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
use crate::{CONFIG_DIR, protocol::error::QuicError};

pub mod mtls;
/// Re-exports the mTLS server and client config builders from the `mtls`
/// submodule.
pub use mtls::{configure_client, configure_server};

const MAX_PASSWORD_ATTEMPTS: u32 = 5;
const MAX_PASSWORD_LENGTH: usize = 256;

/// Errors that can occur during peer authentication and pairing.
#[derive(Error, Debug)]
pub enum AuthError {
   #[error("no peer identity")]
   NoPeerIdentity,
   #[error("peer identity is not a valid certificate(s)")]
   InvalidPeerIdentity,
   #[error("failed to check known peers")]
   KnownPeersCheckFailed(#[source] JoinError),
   #[error("peer is not a known peer")]
   UnknownPeer,
   #[error("Received invalid pairing mode from peer")]
   InvalidPairMode,
   #[error("failed to verify password")]
   PasswordVerificationFailure(#[source] JoinError),
   #[error("Key only mode does not allow pairing")]
   PairingNotAllowed,
   #[error("Password must be at least 1 character long")]
   EmptyPassword,
   #[error("Password rejected")]
   PasswordRejected,
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
   #[error("Too many password attempts")]
   TooManyPasswordAttempts,
   #[error("Too many pairing key attempts")]
   TooManyKeyAttempts,
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KnownPeer(pub [u8; 32]);

impl FromStr for KnownPeer {
   type Err = hex::FromHexError;
   fn from_str(line: &str) -> std::result::Result<Self, Self::Err> {
      let key_hash = hex::decode(line)?
         .try_into()
         .map_err(|_| hex::FromHexError::InvalidStringLength)?;
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
/// list, so this returns `false` rather than panicking.
///
/// # Panics
///
/// Panics if the file exists but cannot be opened, or if more than ten
/// lines are empty, unparseable, or unreadable.
#[instrument]
pub fn is_known_peer(key_hash: &[u8; 32]) -> bool {
   use ErrorKind::NotFound;
   let path = CONFIG_DIR.join("known_peers");
   let file = match File::open(&path) {
      Ok(file) => file,
      Err(err) if err.kind() == NotFound => return false,
      Err(err) => {
         panic!("Failed to open known peers file {path:?}: {err}");
      }
   };
   // number of faulty lines in the file breaks after 10
   let known_peers_file = BufReader::new(file);
   let mut bad_line_count = 0;
   for line in known_peers_file.lines() {
      if bad_line_count > 10 {
         panic!("Known peers file {path:?} is corrupted");
      }
      let Ok(line) = line else {
         bad_line_count += 1;
         continue;
      };
      if line.is_empty() {
         bad_line_count += 1;
         continue;
      };
      let Ok(peer) = KnownPeer::from_str(&line) else {
         bad_line_count += 1;
         continue;
      };
      if peer.0 == *key_hash {
         return true;
      }
   }
   false
}

/// Represents the pairing mode of this device: how the server side handles a
/// `PAIR` request from an unknown peer. The `Display` form of the mode is what
/// is announced to the pairing client over the wire. The default is
/// [`PairMode::Relaxed`].
#[derive(Default)]
pub enum PairMode {
   /// Strict mode: a random key is generated and announced, and the other
   /// device must enter it to complete the pairing.
   Strict,
   /// Relaxed mode: other devices can connect without any confirmation from
   /// this device.
   #[default]
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

/// Records the given peer in the known peers list, appending it if it is not
/// already present.
fn add_known_peer(peer: KnownPeer) -> Result<(), std::io::Error> {
   if is_known_peer(&peer.0) {
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
/// Returns [`AuthError`] if the connection has no peer identity or the
/// identity is not a valid certificate chain.
#[instrument(skip(connection))]
fn peer_key_hash(connection: &Connection) -> Result<[u8; 32]> {
   use AuthError::{InvalidPeerIdentity, NoPeerIdentity};
   let identity = connection.peer_identity().ok_or(NoPeerIdentity)?;

   let tls_handshake_data = identity
      .downcast::<Vec<rustls::pki_types::CertificateDer>>()
      .map_err(|_| InvalidPeerIdentity)?;

   let peer_cert = tls_handshake_data.first().ok_or(InvalidPeerIdentity)?;

   let (_, x509_cert) =
      x509_parser::parse_x509_certificate(peer_cert).map_err(|_| InvalidPeerIdentity)?;

   let public_key = x509_cert.public_key().raw;
   Ok(*blake3::hash(public_key).as_bytes())
}

/// Authenticates a peer that claims to be known to us by checking its key
/// hash against the known peers list.
///
/// # Errors
///
/// Returns [`AuthError`] if the peer is not a known peer.
pub async fn authenticate_peer(connection: &mut Connection) -> Result<()> {
   use AuthError::{KnownPeersCheckFailed, UnknownPeer};
   let peer_id = peer_key_hash(connection)?;
   let is_known = task::spawn_blocking(move || is_known_peer(&peer_id))
      .await
      .map_err(KnownPeersCheckFailed)?;
   if !is_known {
      return Err(UnknownPeer);
   }
   Ok(())
}

/// Prompts the user for input on stdin, returning the trimmed line.
///
/// # Errors
///
/// Returns [`std::io::Error`] if writing the prompt or reading the input fails.
async fn prompt_user(prompt: &'static str) -> Result<String, std::io::Error> {
   fn sync_inner(prompt: &str) -> Result<String, std::io::Error> {
      use std::io::{stdin, stdout};
      let mut stdout = stdout();
      stdout.write_all(prompt.as_bytes())?;
      stdout.flush()?;
      let mut line = String::new();
      stdin().read_line(&mut line)?;
      Ok(line.trim().to_string())
   }
   task::spawn_blocking(|| sync_inner(prompt))
      .await
      .expect("Thread unexpectedly panicked")
}

/// Client side of the pairing exchange: reads the pair mode announced by the
/// server and provides the requested credentials. The peer is recorded as
/// known on the server side of the exchange, not here.
///
/// # Errors
///
/// Returns [`AuthError`] if the pairing key or password is rejected, the
/// input is invalid, or the maximum number of attempts is exceeded, and
/// [`QuicError`] if the pairing stream fails.
///
/// # Panics
///
/// Panics if the server announces an unknown pair mode, or if reading input
/// from the user fails.
async fn pair_client_side(connection: &mut Connection) -> Result<()> {
   use AuthError::{
      InvalidPairMode, InvalidPairingKey, TooManyKeyAttempts, TooManyPasswordAttempts,
   };
   assert_eq!(
      AuthCommands::ACCEPT.len(),
      AuthCommands::REJECT.len(),
      "the pairing response must both be the same length"
   );

   async fn accepted(channel_rx: &mut RecvStream) -> Result<bool> {
      let mut response_buf = [0u8; AuthCommands::ACCEPT.len()];
      let Ok(result) = timeout(
         Duration::from_secs(5),
         channel_rx.read_exact(&mut response_buf),
      )
      .await
      else {
         tracing::warn!("Timed out waiting for pairing response");
         return Ok(false);
      };
      result?;
      Ok(response_buf == AuthCommands::ACCEPT)
   }
   /// Helper function to simplify the decoding of the pairing key
   fn decoed_pairing_key(key: &str) -> Result<[u8; 8], FromHexError> {
      let key_hex = hex::decode(key)?
         .try_into()
         .map_err(|_| FromHexError::InvalidStringLength)?;
      Ok(key_hex)
   }
   let (mut channel_tx, mut channel_rx) = connection.accept_bi().await?;

   let mut mode_len = [0; 1];
   channel_rx.read_exact(&mut mode_len).await?;
   let mut mode_buf = vec![0; mode_len[0] as usize];
   channel_rx.read_exact(&mut mode_buf).await?;
   let mode_str = std::str::from_utf8(&mode_buf).map_err(|_| InvalidPairMode)?;
   match mode_str {
      "RELAXED" => {}

      "PASSWORD" => {
         let mut password_attempts = 0;
         loop {
            if password_attempts >= MAX_PASSWORD_ATTEMPTS {
               return Err(TooManyPasswordAttempts);
            }
            let password = prompt_user("Password: ")
               .await
               // I am still expecting this because there are only two reasons this _could_ fail
               // 1. stdin is not readable
               // 2. the read data is not valid utf8/utf16
               .expect("Failed to read password input");
            if password.is_empty() || password.len() > 256 {
               // I am not using tracing here because that is for logging this is for user feedback
               eprintln!("Password must be between 1 and 256 characters long");
               password_attempts += 1;
               continue;
            }
            channel_tx.write_all(password.as_bytes()).await?;
            if accepted(&mut channel_rx).await? {
               break;
            }
            password_attempts += 1;
         }
      }

      "STRICT" => {
         let mut key_attempts = 0;
         loop {
            if key_attempts >= MAX_PASSWORD_ATTEMPTS {
               return Err(TooManyKeyAttempts);
            }
            let key_hex = prompt_user("Enter the pairing key: ")
               .await
               // Same as password prompt
               .expect("Failed to read pairing key input")
               .chars()
               .filter(|c| *c != '-')
               .collect::<String>();
            let key = decoed_pairing_key(&key_hex).map_err(InvalidPairingKey)?;
            channel_tx.write_all(&key).await?;
            if accepted(&mut channel_rx).await? {
               break;
            }
            key_attempts += 1;
         }
      }

      "KEYONLY" => {}

      _ => return Err(InvalidPairMode),
   }

   Ok(())
}

/// Server side of the pairing exchange: announces the configured pair mode,
/// validates the client's response, and records the peer as known on success.
///
/// # Errors
///
/// Returns [`AuthError`] if the pairing is rejected, and [`QuicError`] for
/// stream or connection failures.
async fn pair_server_side(connection: &mut Connection, pair_mode: &PairMode) -> Result<()> {
   use AuthError::{
      EmptyPassword, FailedToRegisterPeer, KeyMismatch, PairingNotAllowed, PasswordRejected,
      PasswordVerificationFailure,
   };
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
         return Err(PairingNotAllowed);
      }

      Password(password) => {
         let password = password.clone();
         let mut client_password = [0u8; 256]; // any password longer than this is rejected
         let read = channel_rx
            .read(&mut client_password)
            .await?
            .unwrap_or_default();
         if read == 0 {
            return Err(EmptyPassword);
         }

         let client_password = client_password[..read].to_vec();
         let verifier = Argon2::default();
         let accept = task::spawn_blocking(move || {
            verifier
               .verify_password(&client_password, &password.password_hash())
               .is_ok()
         })
         .await
         .map_err(PasswordVerificationFailure)?;
         if !accept {
            channel_tx.write_all(AuthCommands::REJECT).await?;
            return Err(PasswordRejected);
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
            return Err(KeyMismatch);
         }
         channel_tx.write_all(AuthCommands::ACCEPT).await?;
      }
   }
   let peer_id = peer_key_hash(connection)?;
   task::spawn_blocking(move || add_known_peer(KnownPeer(peer_id)))
      .await
      .expect("Thread unexpectedly panicked")
      .map_err(FailedToRegisterPeer)?;
   Ok(())
}

/// Runs the pairing handshake over an established QUIC connection.
///
/// The exchange is driven by the connection's role: the client side reads the
/// pair mode announced by the server and supplies the requested credentials,
/// while the server side announces its configured [`PairMode`] and validates
/// the client's response. The server records the peer in the known peers list
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
/// On the server side, returns [`AuthError`] when the pairing is rejected
/// (for example `KeyOnly` mode, a password or key mismatch, or failing to
/// record the peer) and [`QuicError`] for stream or connection failures.
///
/// On the client side the exchange's errors are not propagated; this function
/// always returns `Ok`.
///
/// # Panics
///
/// Panics if the server side is used without a [`PairMode`].
pub async fn pair_peer(connection: &mut Connection, pair_mode: Option<&PairMode>) -> Result<()> {
   use Side::{Client, Server};
   match connection.side() {
      Client => {
         pair_client_side(connection).await;
         Ok(())
      }
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

/// Client side of the pairing handshake: announces a pairing request and runs
/// the exchange with the server.
///
/// Sends a `PAIR` datagram, then delegates the rest of the exchange to
/// [`pair_peer`].
///
/// # Errors
///
/// Returns [`QuicError`] if the `PAIR` datagram cannot be sent, or
/// [`AuthError`] if the pairing exchange fails on the client side.
pub async fn initiate_pairing(connection: &mut Connection) -> Result<()> {
   connection.send_datagram(AuthCommands::PAIR.into())?;
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
/// Returns [`AuthError`] if the peer is unknown, the handshake times out,
/// the pairing is rejected, or an invalid command is received, and
/// [`QuicError`] for stream or connection failures. On a handshake timeout
/// the connection is closed with [`CloseCode::AuthenticationFailure`].
#[instrument(skip(incoming, pair_mode))] // pair_mode doesn't matter here
pub async fn handle_incoming(incoming: Incoming, pair_mode: &PairMode) -> Result<Connection> {
   use AuthError::{HandshakeTimeout, InvalidAuthData};
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
