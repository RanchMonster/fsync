//! Authenticated peer authentication and pairing over QUIC.
//!
//! This module implements the handshake that runs on every QUIC connection
//! accepted by fsync. The transport layer is secured with mutual TLS (mTLS),
//! configured in the [`mtls`] submodule, so the peer's certificate is
//! available during the handshake. This module then decides whether an
//! already-known peer is authenticated directly or whether an unknown peer
//! must go through the pairing exchange described by [`PairMode`].
//!
//! The client announces itself with an `INIT` datagram (known-peer
//! authentication, acknowledged by the server) or with a `PAIR` datagram
//! (a pairing request). The server, driven by [`handle_incoming`], waits up
//! to five seconds for the client's first datagram.
//! [`authenticate_client_side`] and [`initiate_pairing`] are the client entry
//! points; [`pair_peer`] runs the shared pairing exchange over a
//! bidirectional stream once it is established.
use argon2::{Argon2, PasswordVerifier, password_hash::PasswordHashString};
use quinn::{Connection, Incoming, Side};
use rand::random;
use std::{
   fmt::Display,
   fs::File,
   io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
   str::FromStr,
   sync::Arc,
   time::Duration,
};
use tokio::{task, time::timeout};
use x509_parser::nom::AsBytes;
mod mtls;
use super::error::*;
use crate::CONFIG_DIR;
/// Re-exports the mTLS server config builder from the `mtls` submodule.
pub use mtls::configure_server;
use std::io::ErrorKind;

/// A macro to unwrap a `Result`, returning an [`Error::PeerRejected`] with
/// the given message on error.
macro_rules! ok_or_reject {
   ($e:expr,$msg:expr) => {
      match $e {
         Ok(x) => x,
         Err(_) => return Err(Error::PeerRejected($msg.to_string())),
      }
   };
}
/// Unwraps an `Option` value, returning an [`Error::PeerRejected`] with the
/// given message on `None`.
macro_rules! some_or_reject {
   ($e:expr,$msg:expr) => {
      match $e {
         Some(x) => x,
         None => return Err(Error::PeerRejected($msg.to_string())),
      }
   };
}

// I hate handling it like this but rust won't let me do it with a Enum
/// The set of wire-level commands exchanged during the authentication and
/// pairing handshakes.
struct AuthCommands;
impl AuthCommands {
   const INIT: &[u8] = b"INIT";
   const ACKNOWLEDGE: &[u8] = b"ACKNOWLEDGE";
   const HOLD: &[u8] = b"HOLD";
   const REJECT: &[u8] = b"REJECT";
   const ACCEPT: &[u8] = b"ACCEPT";
   const PAIR: &[u8] = b"PAIR";
}
/// A peer identity: the blake3 hash of a peer certificate's public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct KnownPeer([u8; 32]);

impl FromStr for KnownPeer {
   type Err = Error;
   fn from_str(line: &str) -> Result<Self> {
      let key_hash = hex::decode(line)
         .map_err(|_| Error::ParseData("Invalid key hash".into()))?
         .try_into()
         .map_err(|_| Error::ParseData("Invalid key hash length".into()))?;
      Ok(KnownPeer(key_hash))
   }
}
impl Display for KnownPeer {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(f, "{}", hex::encode(self.0))
   }
}
/// Checks whether the given key hash is present in the known peers list
/// stored in `CONFIG_DIR/known_peers`. A missing file is treated as an empty
/// list, so this returns `Ok(false)` rather than an error.
pub fn is_known_peers(key_hash: &[u8; 32]) -> Result<bool> {
   use ErrorKind::NotFound;
   let path = CONFIG_DIR.join("known_peers");
   let file = match std::fs::File::open(&path) {
      Ok(file) => file,
      Err(err) if err.kind() == NotFound => return Ok(false),
      Err(err) => return Err(err.into()),
   };
   for line in BufReader::new(file).lines() {
      let line = line?;
      if line.is_empty() {
         continue;
      }
      let peer = KnownPeer::from_str(&line)?;
      if peer.0 == *key_hash {
         return Ok(true);
      }
   }
   Ok(false)
}
/// Represents the pairing mode of this device: how the server side handles a
/// `PAIR` request from an unknown peer. The `Display` form of the mode is what
/// is announced to the pairing client over the wire. The default is
/// [`PairMode::Relaxed`].
#[derive(Debug)]
pub enum PairMode {
   /// Strict mode: a random key is generated and announced, and the other
   /// device must enter it to complete the pairing.
   Strict,
   /// Relaxed mode: other devices can connect without any confirmation from
   /// this device.
   Relaxed,
   /// Password mode: other devices can connect to this device by providing
   /// the password whose hash is stored in this variant.
   Password(Arc<PasswordHashString>),
   /// Key only mode: pairing is not allowed; users must manually copy the
   /// public key to both devices instead.
   KeyOnly,
   // Add other modes here as needed
}
impl Display for PairMode {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      match self {
         PairMode::Strict => write!(f, "STRICT"),
         PairMode::Relaxed => write!(f, "RELAXED"),
         PairMode::Password(_) => write!(f, "PASSWORD"),
         PairMode::KeyOnly => write!(f, "KEYONLY"),
      }
   }
}
impl Default for PairMode {
   fn default() -> Self {
      // for now, we default to relaxed mode
      Self::Relaxed
   }
}
/// Records the given peer in the known peers list, appending it if it is not
/// already present.
fn add_known_peer(peer: KnownPeer) -> Result<()> {
   if is_known_peers(&peer.0)? {
      return Ok(());
   }
   let mut file = File::options()
      .read(true)
      .append(true)
      .create(true)
      .open(CONFIG_DIR.join("known_peers"))?;
   if file.metadata()?.len() > 0 {
      file.seek(SeekFrom::End(-1))?;
      let mut last_char = [0];
      file.read_exact(&mut last_char)?;
      if last_char[0] != b'\n' {
         file.write_all(b"\n")?;
      }
   }
   writeln!(file, "{}", peer)?;
   Ok(())
}
/// Extracts the blake3 hash of the peer certificate's public key, used to
/// identify the peer in the known peers list.
///
/// # Errors
///
/// Returns [`Error::PeerRejected`] if the connection has no peer identity or
/// the identity is not a valid certificate chain.
fn peer_key_hash(connection: &Connection) -> Result<[u8; 32]> {
   let identity = some_or_reject!(connection.peer_identity(), "no peer identity");

   let tls_handshake_data = ok_or_reject!(
      identity.downcast::<Vec<rustls::pki_types::CertificateDer>>(),
      "peer identity is not a valid certificate(s)"
   );

   let peer_cert = some_or_reject!(
      tls_handshake_data.first(),
      "peer identity is not a valid certificate(s)"
   );

   let (_, x509_cert) = ok_or_reject!(
      x509_parser::parse_x509_certificate(peer_cert),
      "peer identity is not a valid certificate"
   );

   let public_key = x509_cert.public_key().raw;
   Ok(*blake3::hash(public_key).as_bytes())
}
/// Authenticates a peer that claims to be known to us by checking its key
/// hash against the known peers list.
///
/// # Errors
///
/// Returns [`Error::PeerRejected`] if the peer is not a known peer. Errors
/// from the known peers lookup are propagated.
pub async fn authenticate_peer(connection: &mut Connection) -> Result<()> {
   use Error::PeerRejected;
   let peer_id = peer_key_hash(connection)?;
   let is_known = ok_or_reject!(
      task::spawn_blocking(move || is_known_peers(&peer_id)).await,
      "failed to check known peers"
   )?;
   if !is_known {
      return Err(PeerRejected("peer is not a known peer".to_string()));
   }
   Ok(())
}

/// Prompts the user for input on stdin, returning the trimmed line.
///
/// # Errors
///
/// Returns [`Error::Io`] if writing the prompt or reading the input fails.
fn prompt_user(prompt: &str) -> Result<String> {
   use std::io::{stdin, stdout};
   let mut stdout = stdout();
   stdout.write_all(prompt.as_bytes())?;
   stdout.flush()?;
   let mut line = String::new();
   stdin().read_line(&mut line)?;
   Ok(line.trim().to_string())
}

/// Client side of the pairing exchange: reads the pair mode announced by the
/// server and provides the requested credentials, then records the peer as
/// known on a successful exchange.
async fn pair_client_side(connection: &mut Connection) -> Result<()> {
   use Error::PeerRejected;
   let (mut channel_tx, mut channel_rx) = connection.accept_bi().await?;

   let mut mode_len = [0; 1];
   channel_rx.read_exact(&mut mode_len).await?;
   let mut mode_buf = vec![0; mode_len[0] as usize];
   channel_rx.read_exact(&mut mode_buf).await?;
   let mode_str = ok_or_reject!(
      std::str::from_utf8(&mode_buf),
      "pair mode is not valid utf-8"
   );
   match mode_str {
      "RELAXED" => {}

      "PASSWORD" => {
         let password = task::spawn_blocking(|| prompt_user("Password: "))
            .await
            .map_err(|err| PeerRejected(format!("failed to read password: {err}")))??;
         if password.is_empty() {
            return Err(PeerRejected("password must not be empty".to_string()));
         }
         if password.len() > 256 {
            return Err(PeerRejected("password is too long".to_string()));
         }
         channel_tx.write_all(password.as_bytes()).await?;
      }

      "STRICT" => {
         let key_hex = task::spawn_blocking(|| prompt_user("Enter the pairing key: "))
            .await
            .map_err(|err| PeerRejected(format!("failed to read pairing key: {err}")))??;
         let key_hex: String = key_hex.chars().filter(|c| *c != '-').collect();
         let key =
            hex::decode(key_hex).map_err(|_| Error::ParseData("invalid pairing key".into()))?;
         let key: [u8; 8] = key
            .try_into()
            .map_err(|_| Error::ParseData("invalid pairing key".into()))?;
         channel_tx.write_all(&key).await?;
      }

      "KEYONLY" => {}

      other => return Err(Error::ParseData(format!("unknown pair mode: {other}"))),
   }

   let mut stream_buffer = [0; 256]; // more than enough for the pairing response just arbitrarily chose
   stream_buffer.fill(0); // zero out the buffer
   let read = some_or_reject!(
      channel_rx.read(&mut stream_buffer).await?,
      "failed to read pairing response"
   );

   let response = &mut stream_buffer[..read];

   if response == AuthCommands::ACCEPT {
      let peer_id = peer_key_hash(connection)?;
      task::spawn_blocking(move || add_known_peer(KnownPeer(peer_id)))
         .await
         .map_err(|err| PeerRejected(format!("failed to register peer: {err}")))??;
      Ok(())
   } else if response == AuthCommands::REJECT {
      Err(PeerRejected("pairing rejected by peer".to_string()))
   } else {
      Err(Error::ParseData(format!(
         "unexpected pairing response: {}",
         String::from_utf8_lossy(&response)
      )))
   }
}

/// Server side of the pairing exchange: announces the configured pair mode,
/// validates the client's response, and records the peer as known on success.
async fn pair_server_side(connection: &mut Connection, pair_mode: &PairMode) -> Result<()> {
   use Error::PeerRejected;
   use PairMode::*;
   let (mut channel_tx, mut channel_rx) = connection.open_bi().await?;
   let mode = pair_mode.to_string();
   let mode_len = u8::try_from(mode.len()).expect("pair mode string is too long");
   channel_tx.write_all(&[mode_len]).await?;
   channel_tx.write_all(mode.as_bytes()).await?;
   match pair_mode {
      Relaxed => {
         channel_tx.write_all(AuthCommands::ACCEPT).await?;
      }

      KeyOnly => {
         channel_tx.write_all(AuthCommands::REJECT).await?;
         return Err(PeerRejected(
            "Key only mode does not allow pairing".to_string(),
         ));
      }

      Password(password) => {
         let password = password.clone();
         let mut client_password = [0u8; 256]; // any password longer than this is rejected
         let read = channel_rx
            .read(&mut client_password)
            .await?
            .unwrap_or_default();
         if read == 0 {
            return Err(PeerRejected(
               "Password must be at least 1 character long".to_string(),
            ));
         }

         let client_password = client_password[..read].to_vec();
         let verifier = Argon2::default();
         let accept = ok_or_reject!(
            task::spawn_blocking(move || {
               verifier
                  .verify_password(&client_password, &password.password_hash())
                  .is_ok()
            })
            .await,
            "failed to verify password"
         );
         if !accept {
            channel_tx.write_all(AuthCommands::REJECT).await?;
            return Err(PeerRejected("Password rejected".to_string()));
         }
         channel_tx.write_all(AuthCommands::ACCEPT).await?;
      }
      Strict => {
         let random_key = random::<[u8; 8]>();
         let as_hex_string = random_key.map(|byte| format!("{byte:02X}")).join("-");
         tracing::info!("Generated random key for device: {as_hex_string}");
         assert!(
            as_hex_string.len() == 23,
            "Generated key must be 23 characters long when encoded with dashes"
         );
         let mut response_key = [0; 8];
         channel_rx.read_exact(&mut response_key).await?;
         if random_key != response_key {
            channel_tx.write_all(AuthCommands::REJECT).await?;
            return Err(PeerRejected("Key mismatch".to_string()));
         }
         channel_tx.write_all(AuthCommands::ACCEPT).await?;
      }
   }
   let peer_id = peer_key_hash(connection)?;
   task::spawn_blocking(move || add_known_peer(KnownPeer(peer_id)))
      .await
      .map_err(|err| PeerRejected(format!("failed to register peer: {err}")))??;
   Ok(())
}

/// Runs the pairing handshake over an established QUIC connection.
///
/// The exchange is driven by the connection's role: the client side reads the
/// pair mode announced by the server and supplies the requested credentials,
/// while the server side announces its configured [`PairMode`] and validates
/// the client's response. Both sides record the peer in the known peers list
/// when the pairing succeeds.
///
/// # Arguments
///
/// * `connection` - the established QUIC connection to the peer.
/// * `pair_mode` - the mode used on the server side of the exchange. It is
///   required (this function panics if it is `None` on the server side) and
///   is ignored on the client side.
///
/// # Errors
///
/// Returns [`Error::PeerRejected`] when the server rejects the pairing or the
/// client reads a `REJECT` response. Returns [`Error::ParseData`] for an
/// unknown pair mode, an invalid pairing key, or an unexpected response.
pub async fn pair_peer(connection: &mut Connection, pair_mode: Option<&PairMode>) -> Result<()> {
   use Side::{Client, Server};
   match connection.side() {
      Client => pair_client_side(connection).await,
      Server => {
         pair_server_side(
            connection,
            pair_mode.expect("server side pairing requires a pair mode"),
         )
         .await
      }
   }
}
/// Client side of the authenticated handshake: announces that we are a known
/// peer and verifies that the server acknowledges us.
///
/// Sends an `INIT` datagram, checks that this peer is in the known peers
/// list, then waits up to five seconds for the server's `ACKNOWLEDGE`
/// datagram.
///
/// # Errors
///
/// Returns [`Error::PeerRejected`] if the peer is not a known peer or the
/// server does not acknowledge the connection within the timeout.
pub async fn authenticate_client_side(connection: &mut Connection) -> Result<()> {
   use Error::PeerRejected;
   connection
      .send_datagram(AuthCommands::INIT.into())
      .map_err(Error::from)?;
   authenticate_peer(connection).await?;
   match timeout(Duration::from_secs(5), connection.read_datagram()).await {
      Ok(Ok(data)) if data.starts_with(AuthCommands::ACKNOWLEDGE) => Ok(()),
      _ => Err(PeerRejected("peer connection timed out".to_string())),
   }
}
/// Client side of the pairing handshake: announces a pairing request and runs
/// the exchange with the server.
///
/// Sends a `PAIR` datagram, then delegates the rest of the exchange to
/// [`pair_peer`].
///
/// # Errors
///
/// Returns [`Error::PeerRejected`] if the server rejects the pairing, and
/// [`Error::ParseData`] if the server announces an unknown pair mode or sends
/// an unexpected response.
pub async fn initiate_pairing(connection: &mut Connection) -> Result<()> {
   connection
      .send_datagram(AuthCommands::PAIR.into())
      .map_err(Error::from)?;
   pair_peer(connection, None).await
}
/// Server side of the handshake: accepts an incoming QUIC connection and
/// authenticates it.
///
/// Waits up to five seconds for the client's first datagram. A datagram
/// starting with `INIT` triggers known-peer authentication, after which the
/// server replies with `ACKNOWLEDGE` and returns the connection. A datagram
/// starting with `PAIR` runs the pairing exchange in the given [`PairMode`].
/// Any other data is rejected and the connection is closed.
///
/// # Arguments
///
/// * `incoming` - the incoming connection attempt to accept.
/// * `pair_mode` - the pairing mode used to handle `PAIR` requests.
///
/// # Errors
///
/// Returns [`Error::PeerRejected`] if the peer is unknown, the handshake
/// times out, the pairing is rejected, or an invalid command is received. On
/// failure the connection is closed with [`CloseCode::AuthenticationFailure`].
pub async fn handle_incoming(incoming: Incoming, pair_mode: &PairMode) -> Result<Connection> {
   use CloseCode::AuthenticationFailure;
   use Error::PeerRejected;
   let mut connection = incoming.await?;
   let handshake_packet = match timeout(Duration::from_secs(5), connection.read_datagram()).await {
      Ok(Ok(data)) => data,
      Ok(Err(err)) => {
         return Err(err.into());
      }
      Err(_) => {
         connection.close(AuthenticationFailure.into(), b"handshake timed out");
         return Err(PeerRejected("handshake timed out".to_string()));
      }
   };
   if handshake_packet.starts_with(AuthCommands::INIT) {
      match authenticate_peer(&mut connection).await {
         Ok(_) => {
            connection
               .send_datagram(AuthCommands::ACKNOWLEDGE.into())
               .map_err(Error::from)?;
            Ok(connection)
         }
         Err(PeerRejected(reason)) => {
            connection.close(AuthenticationFailure.into(), reason.as_bytes());
            Err(PeerRejected(reason))
         }
         Err(err) => {
            connection.close(AuthenticationFailure.into(), err.to_string().as_bytes());
            Err(PeerRejected(err.to_string()))
         }
      }
   } else if handshake_packet.starts_with(AuthCommands::PAIR) {
      match pair_peer(&mut connection, Some(pair_mode)).await {
         Ok(_) => Ok(connection),
         Err(PeerRejected(reason)) => {
            connection.close(AuthenticationFailure.into(), reason.as_bytes());
            Err(PeerRejected(reason))
         }
         Err(err) => {
            connection.close(AuthenticationFailure.into(), err.to_string().as_bytes());
            Err(PeerRejected(err.to_string()))
         }
      }
   } else {
      connection.close(AuthenticationFailure.into(), b"invalid auth handshake data");
      Err(PeerRejected("invalid auth handshake data".to_string()))
   }
}
#[cfg(test)]
mod tests {
   use super::*;
   use quinn::{Connecting, Incoming};
   use tokio::task::JoinSet;

   const TEST_SOCKET_ADDR: &str = "127.0.0.1:0"; // use localhost to avoid firewall issues

   #[test]
   fn test_known_peer_comparison() {
      let random_key = random::<[u8; 32]>();
      let peer = KnownPeer(random_key);
      let hexed_key = hex::encode(random_key);
      let prased_key = KnownPeer::from_str(&hexed_key).expect("failed to parse known peer");
      assert_eq!(peer, prased_key);
   }

   async fn connecting_peer(connect_attempt: Connecting) {
      let mut connection = connect_attempt.await.expect("failed to connect");
      // send pairing request
      connection
         .send_datagram(AuthCommands::PAIR.into())
         .expect("failed to send pairing request");
      pair_peer(&mut connection, None)
         .await
         .expect("failed to pair peer");
   }

   async fn responding_peer(incoming: Incoming, pair_mode: PairMode) {
      handle_incoming(incoming, &pair_mode)
         .await
         .expect("failed to handle incoming connection");
   }

   #[tokio::test]
   async fn test_pair_peer_relaxed() {
      use quinn::Endpoint;
      // generate key and cert for virtual peers
      let server_config =
         mtls::configure_server("test-peer-server").expect("failed to configure server crypto");
      let client_config =
         mtls::configure_client("test-peer-client").expect("failed to configure client crypto");
      // initialize the quic server
      let server = Endpoint::server(
         server_config,
         TEST_SOCKET_ADDR.parse().expect("invalid socket addr"),
      )
      .expect("failed to create server endpoint");

      // reuse the same endpoint to connect to the host peer
      let local_addr = server.local_addr().expect("failed to get local addr");
      let connection = server
         .connect_with(client_config, local_addr, "test-peer-server")
         .expect("failed to connect to server");
      let mut task_set = JoinSet::new();
      task_set.spawn(connecting_peer(connection));
      task_set.spawn(responding_peer(
         server.accept().await.expect("failed to accept connection"),
         PairMode::Relaxed,
      ));
      task_set.join_all().await;
   }
   // I still need to figure out how to write the other tests
}
