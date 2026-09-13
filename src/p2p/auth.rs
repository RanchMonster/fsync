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
use hex::FromHexError;
use quinn::{Connection, Incoming, RecvStream, Side};
use rand::random;
use std::{
   fmt::Display,
   fs::File,
   io::{BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom, Write},
   str::FromStr,
   sync::Arc,
   time::Duration,
};
use thiserror::Error;
use tokio::{
   task::{self, JoinError},
   time::timeout,
};
use tracing::instrument;
use x509_parser::nom::AsBytes;

use super::error::CloseCode;
use crate::{
   DATA_DIR, asyncify,
   p2p::{
      auth::pairing_key::{PairingKey, load_pairing_key},
      error::QuicError,
   },
};

#[cfg(test)]
pub(crate) static KNOWN_PEERS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub mod mtls;
/// Re-exports the mTLS server and client config builders from the `mtls`
/// submodule.
pub use mtls::{configure_client, configure_server, get_peer_id};

const MAX_PASSWORD_ATTEMPTS: u32 = 5;
const MAX_PASSWORD_LENGTH: usize = 256;

/// Errors that can occur during peer authentication and pairing.
#[derive(Error, Debug)]
pub enum AuthError {
   #[error("no peer identity")]
   NoPeerIdentity,
   #[error("peer identity is not a valid certificate(s)")]
   InvalidPeerIdentity,
   #[error("failed to open known peers file")]
   KnownPeersCheckFailed(#[source] std::io::Error),
   #[error("peer is not a known peer")]
   UnknownPeer,
   #[error("Key mismatch")]
   KeyMismatch,
   #[error("failed to register peer: {0}")]
   FailedToRegisterPeer(#[source] std::io::Error),
   #[error("peer connection timed out")]
   PeerTimeout,
   #[error("handshake timed out")]
   HandshakeTimeout,
   #[error("invalid auth handshake data")]
   InvalidAuthData,
   #[error("invalid pairing key: {0}")]
   InvalidPairingKey(#[source] hex::FromHexError),
   #[error(transparent)]
   Quic(QuicError),
}

/// Simple wrapper to handle for all QUIC errors.
impl<T> From<T> for AuthError
where
   T: Into<QuicError>,
{
   fn from(err: T) -> Self {
      Self::Quic(err.into())
   }
}
/// Define the result type for this module.
type Result<T, E = AuthError> = std::result::Result<T, E>;

// I hate handling it like this but rust won't let me do it with a Enum
/// The set of wire-level commands exchanged during the authentication and
/// pairing handshakes.
pub struct AuthCommands;
impl AuthCommands {
   pub const INIT: &[u8] = b"INIT";
   pub const ACKNOWLEDGE: &[u8] = b"ACKNOWLEDGE";
   pub const HOLD: &[u8] = b"HOLD";
   pub const REJECT: &[u8] = b"REJECT";
   pub const ACCEPT: &[u8] = b"ACCEPT";
   pub const PAIR: &[u8] = b"PAIR";
}

/// A peer identity: the blake3 hash of a peer certificate's public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub struct PeerId(pub [u8; 32]);

impl FromStr for PeerId {
   type Err = hex::FromHexError;
   fn from_str(line: &str) -> std::result::Result<Self, Self::Err> {
      let key_hash = hex::decode(line)?
         .try_into()
         .map_err(|_| hex::FromHexError::InvalidStringLength)?;
      Ok(PeerId(key_hash))
   }
}

impl Display for PeerId {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(f, "{}", hex::encode(self.0))
   }
}

/// Checks whether the given key hash is present in the known peers list
/// stored in `DATA_DIR/known_peers`. A missing file is treated as an empty
/// list, so this returns `false` rather than panicking.
///
/// # Panics
///
/// Panics if the file exists but cannot be opened, or if more than ten
/// lines are empty, unparseable, or unreadable.
pub fn is_known_peer(peer_id: &PeerId) -> Result<bool> {
   use AuthError::KnownPeersCheckFailed;
   use ErrorKind::NotFound;
   let path = DATA_DIR.join("known_peers");
   let file = match File::open(&path) {
      Ok(file) => file,
      Err(err) => {
         if err.kind() == NotFound {
            tracing::warn!(
               known_peers_file =% path.display(),
               error =% err,
               "Know peers file doesn't exist"
            );
            return Ok(false);
         }
         return Err(KnownPeersCheckFailed(err));
      }
   };
   let known_peers_file = BufReader::new(file);

   for line in known_peers_file.lines() {
      let line = line.map_err(KnownPeersCheckFailed)?;

      let stored_peer_id = PeerId::from_str(&line).expect(
         "known peers file is corrupted please remove or reslove the issue and restart the program",
      );

      if stored_peer_id == *peer_id {
         return Ok(true);
      }
   }

   Ok(false)
}

/// Records the given peer in the known peers list, appending it if it is not
/// already present.
fn add_known_peer(peer: PeerId) -> Result<()> {
   use AuthError::KnownPeersCheckFailed;
   if is_known_peer(&peer)? {
      return Ok(());
   }

   let result = (|| {
      let mut file = File::options()
         .read(true)
         .append(true)
         .create(true)
         .open(DATA_DIR.join("known_peers"))?;

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
   })()
   .map_err(KnownPeersCheckFailed);

   result
}

/// Extracts the blake3 hash of the peer certificate's public key, used to
/// identify the peer in the known peers list.
///
/// # Errors
///
/// Returns [`AuthError`] if the connection has no peer identity or the
/// identity is not a valid certificate chain.
#[instrument(skip(connection))]
fn peer_key_hash(connection: &Connection) -> Result<PeerId> {
   use AuthError::{InvalidPeerIdentity, NoPeerIdentity};
   let identity = connection.peer_identity().ok_or(NoPeerIdentity)?;

   let tls_handshake_data = identity
      .downcast::<Vec<rustls::pki_types::CertificateDer>>()
      .map_err(|_| InvalidPeerIdentity)?;

   let peer_cert = tls_handshake_data.first().ok_or(InvalidPeerIdentity)?;

   let (_, x509_cert) =
      x509_parser::parse_x509_certificate(peer_cert).map_err(|_| InvalidPeerIdentity)?;

   let public_key = x509_cert.public_key().raw;
   let public_key_hash = *blake3::hash(public_key).as_bytes();
   Ok(PeerId(public_key_hash))
}

/// Authenticates a peer that claims to be known to us by checking its key
/// hash against the known peers list.
///
/// # Errors
///
/// Returns [`AuthError`] if the peer is not a known peer.
pub async fn authenticate_peer(connection: &mut Connection) -> Result<()> {
   use AuthError::UnknownPeer;
   let peer_id = peer_key_hash(connection)?;
   if asyncify!(is_known_peer, &peer_id)? {
      return Err(UnknownPeer);
   }
   Ok(())
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
/// Returns [`AuthError`] if the peer is not a known peer or the server does
/// not acknowledge the connection within the timeout.
pub async fn authenticate_client_side(connection: &mut Connection) -> Result<()> {
   use AuthError::{InvalidAuthData, PeerTimeout};
   connection.send_datagram(AuthCommands::INIT.into())?;
   authenticate_peer(connection).await?;
   match timeout(Duration::from_secs(5), connection.read_datagram()).await {
      Ok(Ok(data)) => {
         if data.starts_with(AuthCommands::ACKNOWLEDGE) {
            Ok(())
         } else {
            Err(InvalidAuthData)
         }
      }
      _ => Err(PeerTimeout),
   }
}

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
/// Returns [`AuthError`] if the peer is unknown, the handshake times out,
/// the pairing is rejected, or an invalid command is received, and
/// [`QuicError`] for stream or connection failures. On a handshake timeout
/// the connection is closed with [`CloseCode::AuthenticationFailure`].
pub async fn handle_incoming(incoming: Incoming) -> Result<Connection> {
   use CloseCode::AuthenticationFailure;
   let mut connection = incoming.await?;
   let handshake_packet = match timeout(Duration::from_secs(5), connection.read_datagram()).await {
      Ok(Ok(data)) => data,
      Ok(Err(err)) => {
         return Err(err.into());
      }
      Err(_) => {
         let err = HandshakeTimeout;
         connection.close(AuthenticationFailure.into(), err.to_string().as_bytes());
         return Err(err);
      }
   };
   if handshake_packet.starts_with(AuthCommands::INIT) {
      authenticate_peer(&mut connection).await?;
      connection.send_datagram(AuthCommands::ACKNOWLEDGE.into())?;
      Ok(connection)
   } else if handshake_packet.starts_with(AuthCommands::PAIR) {
      pair_peer(&mut connection, Some(pair_mode)).await?;
      Ok(connection)
   } else {
      Err(InvalidAuthData)
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
      let peer = PeerId(random_key);
      let hexed_key = hex::encode(random_key);
      let prased_key = PeerId::from_str(&hexed_key).expect("failed to parse known peer");
      assert_eq!(peer, prased_key);
   }

   #[tokio::test]
   async fn test_is_known_peers_found() {
      let _guard = KNOWN_PEERS_LOCK
         .lock()
         .unwrap_or_else(|poisoned| poisoned.into_inner());
      let known_key = PeerId(random::<[u8; 32]>());
      let other_key = PeerId(random::<[u8; 32]>());
      let path = CONFIG_DIR.join("known_peers");
      let contents = format!(
         "{}\n\n{}\n{}\n",
         other_key, "not-a-valid-hex-line", known_key,
      );
      std::fs::write(&path, contents).expect("failed to write known peers file");
      assert!(
         is_known_peer(&known_key)
            .await
            .expect("Failed to check if peer was known"),
         "Test Peer id {known_key} was not found"
      );
      assert!(
         is_known_peer(&other_key)
            .await
            .expect("Failed to check if peer was known"),
         "Test Peer id {other_key} was not found"
      );
      let bad_peer_id = PeerId(random::<[u8; 32]>());
      // I am dumb but I feel like there should be a better way to say that asset message
      assert!(
         !is_known_peer(&bad_peer_id)
            .await
            .expect("Failed to check if peer was known"),
         "Test Peer id {bad_peer_id} was marked as valid when it should have been marked as invalid"
      );
      let _ = std::fs::remove_file(&path);
   }

   #[tokio::test]
   async fn test_is_known_peers_missing_file() {
      let _guard = KNOWN_PEERS_LOCK
         .lock()
         .unwrap_or_else(|poisoned| poisoned.into_inner());

      let _ = std::fs::remove_file(CONFIG_DIR.join("known_peers"));
      let peer_id = PeerId(random::<[u8; 32]>());

      assert!(
         !is_known_peer(&peer_id)
            .await
            .expect("Failed to check if peer was known"),
         "Test Peer id {peer_id} was marked as valid when it should have been marked as invalid"
      )
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


   #[tokio::test]
   async fn test_pair_peer_relaxed() {
      use quinn::Endpoint;
      let _guard = KNOWN_PEERS_LOCK
         .lock()
         .unwrap_or_else(|poisoned| poisoned.into_inner());
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
      task_set.join_all().await;
   }
   // I still need to figure out how to write the other tests
}
