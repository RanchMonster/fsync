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
use crate::p2p::known_peer::{add_known_peer, get_known_peer};
use quinn::{
   Connecting, Connection, ConnectionError, ConnectionError::ApplicationClosed, Incoming,
   ReadError, ReadExactError, StoppedError, WriteError,
};
use std::{
   fs::File,
   io::{BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom, Write},
   str::FromStr,
   time::Duration,
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
   #[error("handshake timed out")]
   HandshakeTimeout,
   #[error("invalid pairing key: {0}")]
   InvalidPairingKey(#[source] hex::FromHexError),
   #[error("no pairing key")]
   NoPairingKey,
   #[error("failed to load pairing key")]
   PairingKeyLoadFailed(#[source] std::io::Error),
   #[error("too many pairing attempts")]
   TooManyPairingAttempts,
   #[error("Failed to add known peer")]
   AddKnownPeerFailed(#[source] std::io::Error),
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

pub type ValidatedPeer = (Connection, PeerId);
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

/// How long we wait for any single step of the auth handshake before giving
/// up. A peer that connects but never sends data must not be able to hold a
/// task (and a connection slot) indefinitely.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// The pairing exchange is human-paced (the user must read the code off one
/// device and type it into the other), so allow much more time than the
/// machine steps of the handshake. The pairing key itself lives 5 minutes.
const PAIRING_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);

/// How many pairing codes a side exchanges before giving up. Both the server
/// ([`handle_incoming`]) and the client ([`pair_peer`]) enforce this, so a
/// misbehaving peer cannot make us exchange codes forever.
const MAX_PAIRING_ATTEMPTS: usize = 5;

/// The close reason both sides send when they run out of pairing attempts, so a
/// rejecting peer cannot be confused with one that dropped the connection.
const PAIRING_EXHAUSTED_REASON: &[u8] = b"Too many pairing attempts";

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

fn get_peer_cert_name(connection: &Connection) -> Option<String> {
   let identity = connection.peer_identity()?;

   let tls_handshake_data = identity
      .downcast::<Vec<rustls::pki_types::CertificateDer>>()
      .ok()?;
   let peer_cert = tls_handshake_data.first()?;
   let (_, x509_cert) = x509_parser::parse_x509_certificate(peer_cert).ok()?;
   Some(
      x509_cert
         .subject
         .iter_common_name()
         .next()?
         .as_str()
         .ok()?
         .to_string(),
   )
}

/// Authenticates a peer that claims to be known to us by checking its key
/// hash against the known peers list.
///
/// # Errors
///
/// Returns [`AuthError`] if the peer is not a known peer.
async fn validate_peer(_connection: &mut Connection, peer_id: PeerId) -> Result<()> {
   use AuthError::{KnownPeersCheckFailed, UnknownPeer};
   if !asyncify!(get_known_peer, &peer_id)
      .map_err(KnownPeersCheckFailed)?
      .is_some()
   {
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

/// Runs a pre-authentication handshake step under a deadline, closing the
/// connection with [`CloseCode::Timeout`] if the step runs out of time.
///
/// This is the shared core of [`with_handshake_timeout`] and
/// [`with_pairing_timeout`]; it closes the connection because every step it
/// is used for happens *before* the peer is authenticated, so an
/// unresponsive peer must be dropped rather than kept around. It must not be
/// used for anything that happens after a handshake has succeeded.
async fn with_timeout<E, T>(
   connection: &Connection, timeout: Duration,
   fut: impl std::future::Future<Output = std::result::Result<T, E>>,
) -> Result<T>
where
   E: Into<AuthError>,
{
   match tokio::time::timeout(timeout, fut).await {
      Ok(result) => result.map_err(Into::into),
      Err(_) => {
         connection.close(
            CloseCode::Timeout.into(),
            AuthError::HandshakeTimeout.to_string().as_bytes(),
         );
         Err(AuthError::HandshakeTimeout)
      }
   }
}

/// Runs a machine-paced pre-authentication handshake step under
/// [`HANDSHAKE_TIMEOUT`], closing the connection with [`CloseCode::Timeout`]
/// if the step times out.
///
/// Only for steps a peer is expected to answer immediately; anything
/// human-paced must use [`with_pairing_timeout`] instead.
async fn with_handshake_timeout<E, T>(
   connection: &Connection, fut: impl std::future::Future<Output = std::result::Result<T, E>>,
) -> Result<T>
where
   E: Into<AuthError>,
{
   with_timeout(connection, HANDSHAKE_TIMEOUT, fut).await
}

/// Runs a human-paced pre-authentication step under
/// [`PAIRING_ATTEMPT_TIMEOUT`], closing the connection with
/// [`CloseCode::Timeout`] if the step times out.
///
/// Only for the pairing exchange, where the user has to read the code off one
/// device and type it into the other; it still closes the connection because
/// no peer has been authenticated at that point.
async fn with_pairing_timeout<E, T>(
   connection: &Connection, fut: impl std::future::Future<Output = std::result::Result<T, E>>,
) -> Result<T>
where
   E: Into<AuthError>,
{
   with_timeout(connection, PAIRING_ATTEMPT_TIMEOUT, fut).await
}

/// If the peer rejected us, surface the rejection reason even when it only
/// became visible on the stream-error path (a close that lands mid-read is
/// otherwise reported as an opaque connection error). Falls back to
/// `fallback` when the close was not an explicit rejection.
fn surface_rejection(connection: &Connection, fallback: AuthError) -> AuthError {
   use AuthError::RejectedByPeer;

   if let Some(ApplicationClosed(close_packet)) = connection.close_reason()
      && close_packet.error_code == CloseCode::AuthenticationFailure.into()
   {
      return RejectedByPeer(String::from_utf8_lossy(&close_packet.reason).into_owned());
   }
   fallback
}

/// Client side of the pairing exchange: submits pairing codes to a peer that
/// asked to pair with us and accepts the connection once one is accepted.
///
/// Gives up after five rejected pairing codes, whether the peer keeps rejecting
/// them or the connection is closed.
///
/// # Errors
///
/// Returns [`AuthError::TooManyPairingAttempts`] if the peer rejects five
/// codes without closing the connection, [`AuthError::NoPairingKey`] if no
/// pairing key is available, [`AuthError::InvalidAuthData`] if the peer
/// answers with something other than `ACCEPT` or `REJECT`,
/// [`AuthError::RejectedByPeer`] when a rejection from the peer is observed
/// while awaiting a response, [`AuthError::HandshakeTimeout`] if a step of the
/// exchange does not complete in time, and [`AuthError`] for stream and
/// connection failures.
#[instrument(skip(connecting, get_pairing_key), err)]
pub async fn pair_peer(
   connecting: Connecting, get_pairing_key: impl Fn() -> Option<PairingKey> + Send + Sync,
) -> Result<()> {
   use AuthError::{
      AddKnownPeerFailed, InvalidAuthData, NoPairingKey, RejectedByPeer, TooManyPairingAttempts,
   };
   use CloseCode::AuthenticationFailure;

   const _: () = assert!(
      AuthCommands::REJECT.len() == AuthCommands::ACCEPT.len(),
      "Reject and Accept codes must be the same length"
   );

   let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
      .await
      .map_err(|_| AuthError::HandshakeTimeout)??;
   let (mut channel_tx, mut channel_rx) =
      with_handshake_timeout(&connection, connection.open_bi()).await?;
   channel_tx.write_all(AuthCommands::PAIR).await?;

   let mut connect_attempts = 0;
   let mut response_code = [0u8; AuthCommands::ACCEPT.len()];

   tracing::debug!("Response code: {}", String::from_utf8_lossy(&response_code));

   while connect_attempts < MAX_PAIRING_ATTEMPTS && connection.close_reason().is_none() {
      let pair_code = get_pairing_key().ok_or(NoPairingKey)?;

      tracing::debug!("Attempting pairing with code: {}", pair_code);

      channel_tx
         .write_all(format!("{pair_code}").as_bytes())
         .await?;

      if let Err(err) =
         with_pairing_timeout(&connection, channel_rx.read_exact(&mut response_code)).await
      {
         return Err(surface_rejection(&connection, err));
      }

      if response_code == AuthCommands::ACCEPT {
         let peer_id = peer_key_hash(&connection)?;
         let peer_name = get_peer_cert_name(&connection)
            .unwrap_or_else(|| connection.remote_address().to_string());
         asyncify!(add_known_peer, &peer_id, &peer_name).map_err(AddKnownPeerFailed)?;

         return Ok(());
      }

      if response_code != AuthCommands::REJECT {
         connection.close(
            AuthenticationFailure.into(),
            InvalidAuthData.to_string().as_bytes(),
         );
         return Err(InvalidAuthData);
      }
      connect_attempts += 1;
   }

   let Some(close_reason) = connection.close_reason() else {
      // The server never closed (or never told us why): mirror the server's
      // behaviour and give up after the attempt cap.
      connection.close(AuthenticationFailure.into(), PAIRING_EXHAUSTED_REASON);
      return Err(TooManyPairingAttempts);
   };

   if let ApplicationClosed(close_packet) = &close_reason
      && close_packet.error_code == AuthenticationFailure.into()
   {
      return Err(RejectedByPeer(
         String::from_utf8_lossy(&close_packet.reason).into_owned(),
      ));
   }

   Err(close_reason.into())
}

/// Client side of the authenticated handshake: announces that we are a known
/// peer and verifies that the server acknowledges us.
///
/// Sends an `INIT` datagram, checks that this peer is in the known peers
/// list, then waits up to five seconds for the server's `ACKNOWLEDGE`
/// datagram. If the server answers with anything else we wait up to five more
/// seconds for it to close the connection, to surface the reason it gave.
///
/// # Errors
///
/// Returns [`AuthError`] if the peer is not a known peer, or if the server
/// does not acknowledge (and close) the connection within the timeouts.
/// Returns [`AuthError::RejectedByPeer`] with the peer's reason when the
/// server explicitly rejects this connection by closing with an
/// authentication-failure close code, whether that close lands mid-read or
/// after the response has been read.
#[instrument(skip(connecting), err)]
pub async fn handle_connecting(connecting: Connecting) -> Result<ValidatedPeer> {
   use AuthError::{HandshakeTimeout, RejectedByPeer};
   use CloseCode::AuthenticationFailure;

   let mut connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
      .await
      .map_err(|_| HandshakeTimeout)??;
   let (mut channel_tx, mut channel_rx) =
      with_handshake_timeout(&connection, connection.open_bi()).await?;

   channel_tx.write_all(AuthCommands::INIT).await?;
   let peer_id = peer_key_hash(&connection)?;
   if let Err(error) = validate_peer(&mut connection, peer_id).await {
      connection.close(AuthenticationFailure.into(), error.to_string().as_bytes());
      return Err(error);
   }
   let mut response_code = [0u8; AuthCommands::ACCEPT.len()];
   if let Err(err) =
      with_handshake_timeout(&connection, channel_rx.read_exact(&mut response_code)).await
   {
      return Err(surface_rejection(&connection, err));
   }

   if response_code != AuthCommands::ACCEPT {
      // The server refused the handshake: wait (bounded) for it to close so
      // we can surface the reason, but don't let a server that refuses to
      // close pin this task indefinitely.
      return match tokio::time::timeout(HANDSHAKE_TIMEOUT, connection.closed()).await {
         Ok(ApplicationClosed(close_packet))
            if close_packet.error_code == AuthenticationFailure.into() =>
         {
            Err(RejectedByPeer(
               String::from_utf8_lossy(&close_packet.reason).into_owned(),
            ))
         }
         Ok(result) => Err(result.into()),
         Err(_) => {
            connection.close(
               CloseCode::Timeout.into(),
               AuthError::HandshakeTimeout.to_string().as_bytes(),
            );
            Err(AuthError::HandshakeTimeout)
         }
      };
   }

   Ok((connection, peer_id))
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
/// the pairing is rejected, an invalid command is received, or a stream or
/// connection fails. On a handshake timeout the connection is closed with
/// [`CloseCode::Timeout`].
#[instrument(skip(incoming), err)]
pub async fn handle_incoming(incoming: Incoming) -> Result<ValidatedPeer> {
   use AuthError::{AddKnownPeerFailed, HandshakeTimeout, InvalidAuthData, TooManyPairingAttempts};
   use CloseCode::AuthenticationFailure;
   const _: () = assert!(AuthCommands::INIT.len() == AuthCommands::PAIR.len());

   let mut connection = match tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await {
      Ok(Ok(connection)) => connection,
      Ok(Err(err)) => return Err(err.into()),
      Err(_) => return Err(HandshakeTimeout),
   };
   // No connection object exists before `incoming` resolves, so the first
   // timeout above can't close the connection; the rest can.
   let (mut channel_tx, mut channel_rx) =
      with_handshake_timeout(&connection, connection.accept_bi()).await?;
   let mut mode_buf = [0u8; AuthCommands::INIT.len()];
   if let Err(err) = with_handshake_timeout(&connection, channel_rx.read_exact(&mut mode_buf)).await
   {
      return Err(surface_rejection(&connection, err));
   }

   tracing::debug!("Mode: {}", String::from_utf8_lossy(&mode_buf));
   let peer_id = peer_key_hash(&connection)?;
   if mode_buf == AuthCommands::INIT {
      if let Err(error) = validate_peer(&mut connection, peer_id).await {
         // The peer may already be closing; the rejection close packet carries
         // the reason either way, so never let a best-effort REJECT mask the
         // real error.
         let _ = channel_tx.write_all(AuthCommands::REJECT).await;
         connection.close(AuthenticationFailure.into(), error.to_string().as_bytes());
         return Err(error);
      }

      channel_tx.write_all(AuthCommands::ACCEPT).await?;
      // Wait for the client to finish the handshake stream, but don't let a
      // stalled client pin this task: on timeout keep the (now authenticated)
      // connection alive.
      match tokio::time::timeout(HANDSHAKE_TIMEOUT, channel_tx.stopped()).await {
         Ok(result) => {
            if let Err(error) = result {
               tracing::warn!("peer stopped the handshake stream unexpectedly: {error}");
            }
         }
         Err(_) => {
            tracing::debug!("handshake stream was not stopped within the timeout");
         }
      }
      return Ok((connection, peer_id));
   }

   if mode_buf != AuthCommands::PAIR {
      let error = InvalidAuthData;
      connection.close(AuthenticationFailure.into(), error.to_string().as_bytes());
      return Err(error);
   }

   let mut connect_attempts = 0;
   let mut hex_encoded_pair_code = [0; 64];

   while connect_attempts < MAX_PAIRING_ATTEMPTS {
      if let Err(err) = with_pairing_timeout(
         &connection,
         channel_rx.read_exact(&mut hex_encoded_pair_code),
      )
      .await
      {
         return Err(surface_rejection(&connection, err));
      }

      let pair_code = str::from_utf8(&hex_encoded_pair_code)
         .map_err(|_| InvalidAuthData)?
         .parse::<PairingKey>()
         .map_err(|_| InvalidAuthData)?;

      tracing::debug!("Incoming Pair code: {}", pair_code);

      if let Ok(true) = validate_pair_code(pair_code) {
         let peer_id = peer_key_hash(&connection)?;
         let peer_name = get_peer_cert_name(&connection)
            .unwrap_or_else(|| connection.remote_address().to_string());
         asyncify!(add_known_peer, &peer_id, &peer_name).map_err(AddKnownPeerFailed)?;

         channel_tx.write_all(AuthCommands::ACCEPT).await?;
         // Wait for the client to finish the handshake stream, but don't let a
         // stalled client pin this task: on timeout keep the (now
         // authenticated) connection alive.
         match tokio::time::timeout(HANDSHAKE_TIMEOUT, channel_tx.stopped()).await {
            Ok(result) => {
               if let Err(error) = result {
                  tracing::warn!("peer stopped the handshake stream unexpectedly: {error}");
               }
            }
            Err(_) => {
               tracing::debug!("handshake stream was not stopped within the timeout");
            }
         }
         return Ok((connection, peer_id));
      }
      connect_attempts += 1;
   }
   connection.close(AuthenticationFailure.into(), PAIRING_EXHAUSTED_REASON);

   Err(TooManyPairingAttempts)
}
