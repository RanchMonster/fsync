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
use blake3::Hash;
use quinn::{
   Connecting, Connection, ConnectionError, Incoming, ReadError, ReadExactError, StoppedError,
   WriteError,
};
use std::{
   fmt::Display,
   fs::File,
   io::{BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom, Write},
   str::FromStr,
};
use thiserror::Error;
use tracing::instrument;

use super::close_code::CloseCode;
use crate::{
   DATA_DIR, asyncify,
   p2p::{PeerId, auth::pairing_key::load_pairing_key},
};

#[cfg(test)]
pub(crate) static KNOWN_PEERS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub mod mtls;
mod pairing_key;
/// Re-exports the mTLS server and client config builders from the `mtls`
/// submodule.
pub use mtls::{configure_client, configure_server, get_peer_id};
pub use pairing_key::{PairingKey, generate_pairing_key};

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
   #[error("rejected by peer due to {0}")]
   RejectedByPeer(String),
   #[error("invalid auth handshake data")]
   InvalidAuthData,
   #[error("invalid pairing key: {0}")]
   InvalidPairingKey(#[source] hex::FromHexError),
   #[error("no pairing key")]
   NoPairingKey,
   #[error("failed to load pairing key")]
   PairingKeyLoadFailed(#[source] std::io::Error),
   #[error("too many pairing attempts")]
   TooManyPairingAttempts,
   #[error(transparent)]
   WriteError(#[from] WriteError),
   #[error(transparent)]
   ReadError(#[from] ReadError),
   #[error(transparent)]
   ReadExactError(#[from] ReadExactError),
   #[error(transparent)]
   ConnectionError(#[from] ConnectionError),
   #[error(transparent)]
   StoppedError(#[from] StoppedError),
}

/// Define the result type for this module.
type Result<T, E = AuthError> = std::result::Result<T, E>;

// I hate handling it like this but rust won't let me do it with a Enum
/// The set of wire-level commands exchanged during the authentication and
/// pairing handshakes.
pub struct AuthCommands;
impl AuthCommands {
   pub const INIT: &[u8] = b"INIT";
   pub const REJECT: &[u8] = b"REJECT";
   pub const ACCEPT: &[u8] = b"ACCEPT";
   pub const PAIR: &[u8] = b"PAIR";
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
      tracing::debug!("LINE: {line:?}");

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

   (|| {
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
   .map_err(KnownPeersCheckFailed)
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
pub async fn validate_peer(connection: &mut Connection) -> Result<()> {
   use AuthError::UnknownPeer;
   let peer_id = peer_key_hash(connection)?;
   if !asyncify!(is_known_peer, &peer_id)? {
      return Err(UnknownPeer);
   }
   Ok(())
}

fn validate_pair_code(pair_code: PairingKey) -> Result<bool> {
   if let Some(pairing_key) = load_pairing_key()? {
      return Ok(pairing_key == pair_code);
   }
   Ok(false)
}

#[instrument(skip(connecting, get_pairing_key), err)]
pub async fn pair_peer(
   connecting: Connecting, get_pairing_key: impl Fn() -> Option<PairingKey> + Send + Sync,
) -> Result<()> {
   use AuthError::{InvalidAuthData, NoPairingKey, RejectedByPeer};
   use CloseCode::AuthenticationFailure;
   use ConnectionError::ApplicationClosed;

   const _: () = assert!(
      AuthCommands::REJECT.len() == AuthCommands::ACCEPT.len(),
      "Reject and Accept codes must be the same length"
   );

   let connection = connecting.await?;
   let (mut channel_tx, mut channel_rx) = connection.open_bi().await?;
   channel_tx.write_all(AuthCommands::PAIR).await?;

   let mut response_code = [0u8; AuthCommands::ACCEPT.len()];

   tracing::debug!("Response code: {}", String::from_utf8_lossy(&response_code));

   while connection.close_reason().is_none() {
      let pair_code = get_pairing_key().ok_or(NoPairingKey)?;

      tracing::debug!("Attempting pairing with code: {}", pair_code);

      channel_tx
         .write_all(format!("{pair_code}").as_bytes())
         .await?;

      channel_rx.read_exact(&mut response_code).await?;

      if response_code == AuthCommands::ACCEPT {
         let peer_id = peer_key_hash(&connection)?;
         asyncify!(add_known_peer, peer_id)?;

         return Ok(());
      }

      if response_code != AuthCommands::REJECT {
         connection.close(
            AuthenticationFailure.into(),
            InvalidAuthData.to_string().as_bytes(),
         );
         return Err(InvalidAuthData);
      }
   }

   let close_reason = connection
      .close_reason()
      .expect("connection should be closed by now");

   if let ApplicationClosed(close_packet) = &close_reason
      && close_packet.error_code == AuthenticationFailure.into()
   {
      return Err(RejectedByPeer(
         String::from_utf8_lossy(&close_packet.reason).to_string(),
      ));
   }

   Err(close_reason.into())
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
#[instrument(skip(connecting), err)]
pub async fn handle_connecting(connecting: Connecting) -> Result<Connection> {
   use CloseCode::AuthenticationFailure;

   let mut connection = connecting.await?;
   let (mut channel_tx, mut channel_rx) = connection.open_bi().await?;

   channel_tx.write_all(AuthCommands::INIT).await?;

   if let Err(error) = validate_peer(&mut connection).await {
      connection.close(AuthenticationFailure.into(), error.to_string().as_bytes());
      return Err(error);
   }
   let mut response_code = [0u8; AuthCommands::ACCEPT.len()];
   channel_rx.read_exact(&mut response_code).await?;

   if response_code != AuthCommands::ACCEPT {
      return Err(connection.closed().await.into());
   }

   Ok(connection)
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
#[instrument(skip(incoming), err)]
pub async fn handle_incoming(incoming: Incoming) -> Result<Connection> {
   use AuthError::{InvalidAuthData, TooManyPairingAttempts};
   use CloseCode::AuthenticationFailure;
   const _: () = assert!(AuthCommands::INIT.len() == AuthCommands::PAIR.len());

   let mut connection = incoming.await?;
   let (mut channel_tx, mut channel_rx) = connection.accept_bi().await?;
   let mut mode_buf = [0u8; AuthCommands::INIT.len()];
   channel_rx.read_exact(&mut mode_buf).await?;

   tracing::debug!("Mode: {}", String::from_utf8_lossy(&mode_buf));

   if mode_buf == AuthCommands::INIT {
      if let Err(error) = validate_peer(&mut connection).await {
         channel_tx.write_all(AuthCommands::REJECT).await?;
         connection.close(AuthenticationFailure.into(), error.to_string().as_bytes());
         return Err(error);
      }

      channel_tx.write_all(AuthCommands::ACCEPT).await?;
      channel_tx.stopped().await?;
      return Ok(connection);
   }

   if mode_buf != AuthCommands::PAIR {
      let error = InvalidAuthData;
      connection.close(AuthenticationFailure.into(), error.to_string().as_bytes());
      return Err(error);
   }

   let mut connect_attempts = 0;
   let mut hex_encoded_pair_code = [0; 64];

   while connect_attempts < 5 {
      channel_rx.read_exact(&mut hex_encoded_pair_code).await?;

      let pair_code = str::from_utf8(&hex_encoded_pair_code)
         .map_err(|_| InvalidAuthData)?
         .parse::<PairingKey>()
         .map_err(|_| InvalidAuthData)?;

      tracing::debug!("Incoming Pair code: {}", pair_code);

      if let Ok(true) = validate_pair_code(pair_code) {
         let peer_id = peer_key_hash(&connection)?;
         asyncify!(add_known_peer, peer_id)?;

         channel_tx.write_all(AuthCommands::ACCEPT).await?;
         if let Err(error) = channel_tx.stopped().await {
            connection.close(AuthenticationFailure.into(), error.to_string().as_bytes());
         }
         return Ok(connection);
      }
      connect_attempts += 1;
   }
   connection.close(AuthenticationFailure.into(), b"Too many pairing attempts");

   Err(TooManyPairingAttempts)
}
