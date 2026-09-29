//! Regression tests for the per-step timeouts of the auth handshake and of the
//! pairing exchange.
//!
//! Unlike `tests/auth.rs`, every test here builds its own endpoints (and
//! therefore its own peer certificates) and drives a peer that stalls at a
//! specific point of the exchange, so the only thing that can end the stalled
//! step is the timeout under test. Each stalled step is bounded by a tokio
//! timeout by construction, and the tests add an outer guard so a regression
//! shows up as a failure instead of a hang.

use std::{
   net::SocketAddr,
   sync::{Arc, OnceLock},
   time::Duration,
};

use fsync::p2p::auth::{
   AuthCommands, AuthError, PairingKey, configure_client, configure_server, get_peer_id,
   handle_connecting, handle_incoming, pair_peer,
};
use fsync::p2p::known_peer::add_known_peer;
use quinn::{ConnectionError, Endpoint, TransportConfig, VarInt};
use tokio::task::{self, JoinHandle};

const TEST_SOCKET_ADDR: &str = "127.0.0.1:0"; // use localhost to avoid firewall issues
/// The error code `CloseCode::Timeout` is encoded as on the wire. The enum
/// itself is crate private, so it is spelled out here.
const CLOSE_CODE_TIMEOUT: u32 = 6;
/// How long the code under test is allowed to take. Generous compared to the
/// 5s handshake and 30s pairing timeouts, but short enough that a hung test
/// fails instead of blocking the test run forever.
const TEST_GUARD: Duration = Duration::from_secs(60);

/// Points the config and data directories at a temp directory, once per test
/// binary, so the tests don't touch the real ones. Mirrors `tests/auth.rs`:
/// the dirs have to be redirected before they are first used.
fn setup_data_dir() {
   static ONCE: OnceLock<()> = OnceLock::new();
   ONCE.get_or_init(|| {
      let dir = std::env::temp_dir().join("fsync-p2p-auth-timeout-tests");
      unsafe {
         std::env::set_var("FSYNC_CONFIG_DIR", &dir);
         std::env::set_var("FSYNC_DATA_DIR", &dir);
      }
   });
}

/// Builds an endpoint that serves and dials with the certificate of `name`.
/// The client config is installed as the endpoint's default, so the same
/// endpoint can be used for both roles, as in `tests/auth.rs`.
fn new_endpoint(name: &str, disable_idle_timeout: bool) -> Endpoint {
   setup_data_dir();
   let mut server_config = configure_server(name).expect("failed to configure server crypto");
   let mut client_config = configure_client(name).expect("failed to configure client crypto");
   if disable_idle_timeout {
      // quinn's own idle timer would race the timeouts under test, and under
      // paused time it would fire spuriously on auto-advance.
      server_config.transport_config(transport_config());
      client_config.transport_config(transport_config());
   }
   let mut endpoint = Endpoint::server(
      server_config,
      TEST_SOCKET_ADDR.parse().expect("invalid socket addr"),
   )
   .expect("failed to create endpoint");
   endpoint.set_default_client_config(client_config);
   endpoint
}

fn transport_config() -> Arc<TransportConfig> {
   let mut transport = TransportConfig::default();
   transport.max_idle_timeout(None);
   Arc::new(transport)
}

/// Accepts connections at the transport level and keeps every one of them open
/// without ever opening a stream, so the peer's handshake step stalls.
fn stall_on_connections(endpoint: &Endpoint) -> JoinHandle<()> {
   let endpoint = endpoint.clone();
   task::spawn(async move {
      while let Some(incoming) = endpoint.accept().await {
         task::spawn(async move {
            if let Ok(connection) = incoming.await {
               connection.closed().await;
            }
         });
      }
   })
}

/// Registers `name` as a known peer so the client gets past the known peer
/// check and actually reaches the stalled step.
fn trust_peer(name: &str) {
   let peer_id = get_peer_id(name).expect("failed to get peer id");
   add_known_peer(&peer_id, name).expect("failed to add known peer");
}

fn connect(endpoint: &Endpoint, addr: SocketAddr, server_name: &str) -> quinn::Connecting {
   endpoint
      .connect(addr, server_name)
      .expect("failed to connect")
}

/// `handle_connecting` gives up after 5s when the server completes the QUIC
/// handshake but never answers the `INIT` datagram.
#[tokio::test]
async fn handle_connecting_times_out_when_server_never_responds() {
   const SERVER: &str = "timeout-connecting-server";
   let silent = new_endpoint(SERVER, false);
   let client = new_endpoint("timeout-connecting-client", false);
   let silent_addr = silent.local_addr().expect("failed to get local addr");
   trust_peer(SERVER);
   let _stalled = stall_on_connections(&silent);

   let started = std::time::Instant::now();
   let result = tokio::time::timeout(
      TEST_GUARD,
      handle_connecting(connect(&client, silent_addr, SERVER)),
   )
   .await
   .expect("handle_connecting hung instead of timing out");

   assert!(
      matches!(result, Err(AuthError::HandshakeTimeout)),
      "expected HandshakeTimeout, got {result:?}"
   );
   assert!(
      started.elapsed() >= Duration::from_secs(4),
      "the 5s handshake timeout should not have been cut short, took {:?}",
      started.elapsed()
   );
}

/// `handle_connecting` also gives up after 5s when the server answers with
/// something other than `ACCEPT` and then keeps the connection open forever,
/// instead of waiting on `connection.closed()` indefinitely.
#[tokio::test]
async fn handle_connecting_times_out_when_refusing_server_keeps_connection_open() {
   const SERVER: &str = "timeout-refusing-server";
   let server = new_endpoint(SERVER, false);
   let client = new_endpoint("timeout-refusing-client", false);
   let server_addr = server.local_addr().expect("failed to get local addr");
   trust_peer(SERVER);

   // Reads the `INIT` datagram, refuses it, and then never closes.
   let refusing = task::spawn(async move {
      let incoming = server.accept().await.expect("no incoming connection");
      let connection = incoming.await.expect("connection handshake failed");
      let (mut channel_tx, mut channel_rx) = connection
         .accept_bi()
         .await
         .expect("failed to accept stream");
      let mut mode = [0u8; AuthCommands::INIT.len()];
      channel_rx
         .read_exact(&mut mode)
         .await
         .expect("failed to read mode");
      channel_tx
         .write_all(AuthCommands::REJECT)
         .await
         .expect("failed to reject");
      connection.closed().await
   });

   let started = std::time::Instant::now();
   let result = tokio::time::timeout(
      TEST_GUARD,
      handle_connecting(connect(&client, server_addr, SERVER)),
   )
   .await
   .expect("handle_connecting hung instead of timing out");

   assert!(
      matches!(result, Err(AuthError::HandshakeTimeout)),
      "expected HandshakeTimeout, got {result:?}"
   );
   assert!(
      started.elapsed() >= Duration::from_secs(4),
      "the bounded wait for the peer to close should not have been cut short, took {:?}",
      started.elapsed()
   );

   // The client gives up on the connection itself, with the timeout close code.
   let close_reason = tokio::time::timeout(TEST_GUARD, refusing)
      .await
      .expect("server task hung")
      .expect("server task panicked");
   match close_reason {
      ConnectionError::ApplicationClosed(close_packet) => assert_eq!(
         close_packet.error_code,
         VarInt::from_u32(CLOSE_CODE_TIMEOUT),
         "expected CloseCode::Timeout"
      ),
      other => panic!("expected the client to close the connection, got {other:?}"),
   }
}

/// `handle_incoming` gives up after 5s when the client connects but never
/// opens a stream, closing the connection with `CloseCode::Timeout`.
#[tokio::test]
async fn handle_incoming_times_out_when_client_never_opens_a_stream() {
   const SERVER: &str = "timeout-incoming-server";
   let server = new_endpoint(SERVER, false);
   let client = new_endpoint("timeout-incoming-client", false);
   let server_addr = server.local_addr().expect("failed to get local addr");

   // Accepting and dialing must run concurrently: `server.accept()` only
   // yields an `Incoming` once a client contacts the server.
   let handling = task::spawn(async move {
      let incoming = server.accept().await.expect("no incoming connection");
      handle_incoming(incoming).await
   });
   let connecting = connect(&client, server_addr, SERVER);
   let connection = tokio::time::timeout(TEST_GUARD, connecting)
      .await
      .expect("the client connection hung")
      .expect("connection handshake failed");

   let result = tokio::time::timeout(TEST_GUARD, handling)
      .await
      .expect("handle_incoming hung instead of timing out")
      .expect("handle_incoming task panicked");

   assert!(
      matches!(result, Err(AuthError::HandshakeTimeout)),
      "expected HandshakeTimeout, got {result:?}"
   );

   let close_reason = tokio::time::timeout(TEST_GUARD, connection.closed())
      .await
      .expect("the client never saw the connection close");
   match close_reason {
      ConnectionError::ApplicationClosed(close_packet) => assert_eq!(
         close_packet.error_code,
         VarInt::from_u32(CLOSE_CODE_TIMEOUT),
         "expected CloseCode::Timeout"
      ),
      other => panic!("expected the server to close the connection, got {other:?}"),
   }
}

/// The pairing exchange is human-paced, so `pair_peer` waits 30s for the
/// server's answer instead of the 5s used by the machine steps.
///
/// The 30s is real time here: `#[tokio::test(start_paused = true)]` needs
/// tokio's `test-util` feature, which this crate does not enable. The elapsed
/// time is asserted so the test proves that the pairing timeout, and not one of
/// the 5s machine steps, is what ended the exchange.
#[tokio::test]
async fn pair_peer_times_out_when_server_never_responds() {
   const SERVER: &str = "timeout-pairing-server";
   let silent = new_endpoint(SERVER, true);
   let client = new_endpoint("timeout-pairing-client", true);
   let silent_addr = silent.local_addr().expect("failed to get local addr");
   let _stalled = stall_on_connections(&silent);

   let started = std::time::Instant::now();
   let result = tokio::time::timeout(
      TEST_GUARD,
      // A fixed key: generating one would write the cache file and spawn the
      // key TTL task, and the key is handed to `pair_peer` directly anyway.
      pair_peer(connect(&client, silent_addr, SERVER), || {
         Some(PairingKey::from([42; 32]))
      }),
   )
   .await
   .expect("pair_peer hung instead of timing out");

   let elapsed = started.elapsed();
   assert!(
      matches!(result, Err(AuthError::HandshakeTimeout)),
      "expected HandshakeTimeout, got {result:?}"
   );
   assert!(
      elapsed >= Duration::from_secs(30),
      "the human-paced 30s pairing timeout should be what fired, but the exchange ended after {elapsed:?}"
   );
}

/// The client gives up after five rejected codes instead of exchanging codes
/// with a server that never stops rejecting — the server also caps at five
/// attempts, so there is no point continuing.
#[tokio::test]
async fn pair_peer_gives_up_after_five_rejected_attempts() {
   const SERVER: &str = "rejecting-pairing-server";
   let server = new_endpoint(SERVER, false);
   let client = new_endpoint("rejecting-pairing-client", false);
   let server_addr = server.local_addr().expect("failed to get local addr");

   // Reads the PAIR command, then answers every pairing code with REJECT and
   // never closes; the client must give up on its own after five attempts.
   let rejecting = task::spawn(async move {
      let incoming = server.accept().await.expect("no incoming connection");
      let connection = incoming.await.expect("connection handshake failed");
      let (mut channel_tx, mut channel_rx) = connection
         .accept_bi()
         .await
         .expect("failed to accept stream");
      let mut mode = [0u8; AuthCommands::PAIR.len()];
      channel_rx
         .read_exact(&mut mode)
         .await
         .expect("failed to read PAIR");
      let mut code = [0u8; 64];
      let mut seen = 0usize;
      while seen < 5 {
         if channel_rx.read_exact(&mut code).await.is_err() {
            break; // the client gave up and closed the connection
         }
         seen += 1;
         channel_tx
            .write_all(AuthCommands::REJECT)
            .await
            .expect("failed to write REJECT");
      }
      // Keep the connection open until the client closes it: dropping it here
      // would race the client's last read and fail it with quinn's implicit
      // close (code 0, no reason) instead of letting it reach the cap.
      connection.closed().await;
      seen
   });

   let result = tokio::time::timeout(
      TEST_GUARD,
      pair_peer(connect(&client, server_addr, SERVER), || {
         Some(PairingKey::from([42; 32]))
      }),
   )
   .await
   .expect("pair_peer hung instead of giving up after five attempts");

   assert!(
      matches!(result, Err(AuthError::TooManyPairingAttempts)),
      "expected TooManyPairingAttempts, got {result:?}"
   );

   let codes_seen = tokio::time::timeout(TEST_GUARD, rejecting)
      .await
      .expect("server task hung")
      .expect("server task panicked");
   assert_eq!(
      codes_seen, 5,
      "the client must submit exactly five codes before giving up, saw {codes_seen}"
   );
}
