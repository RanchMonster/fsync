use argon2::{Argon2, PasswordVerifier, password_hash::PasswordHashString};
use quinn::{
   Connection, ConnectionError, ConnectionId, Incoming, Side, VarInt, crypto::rustls::HandshakeData,
};
use rand::random;
use std::{
   collections::{HashMap, HashSet},
   fmt::Display,
   fs::File,
   io::{BufRead, BufReader, Read, Write},
   str::FromStr,
   sync::{Arc, LazyLock},
   time::{Duration, SystemTime},
};
use tokio::{sync::RwLock, time::timeout};
mod mtls;
use super::error::*;
use crate::{CONFIG_DIR, protocol::PROTOCOL_NAME};
pub use mtls::configure_server;
use tokio::task;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// A macro to read a datagram from a connection with a timeout
macro_rules! datagram {
   ($connection:expr) => {
      match timeout(DEFAULT_TIMEOUT, $connection.read_datagram()).await {
         Ok(Ok(datagram)) => Ok(Some(datagram)),
         Ok(Err(err)) => Err(err.into()),
         Err(_) => Ok(None),
      }
   };
   ($connection:expr, $timeout:expr) => {
      match timeout($timeout, $connection.read_datagram()).await {
         Ok(Ok(datagram)) => Ok(Some(datagram)),
         Ok(Err(err)) => Err(err.into()),
         Err(_) => Ok(None),
      }
   };
}
fn get_pair_mode() -> PairMode {
   #[cfg(not(debug_assertions))]
   todo!("implement a config on another branch");
   #[cfg(debug_assertions)]
   PairMode::Relaxed
}
// I hate handling it like this but rust won't let me do it with a Enum
struct AuthCommands;
impl AuthCommands {
   const INIT: &[u8] = b"INIT";
   const AKNOWLEDGE: &[u8] = b"AKNOWLEDGE";
   const HOLD: &[u8] = b"HOLD";
   const REJECT: &[u8] = b"REJECT";
   const ACCEPT: &[u8] = b"ACCEPT";
   const PAIR: &[u8] = b"PAIR";
}
#[derive(Debug, PartialEq, Eq, Hash)]
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
fn is_known_peers(key_hash: &[u8; 32]) -> Result<bool> {
   let path = CONFIG_DIR.join("known_peers");
   let mut lines = BufReader::new(std::fs::File::open(path)?).lines();
   for line in lines {
      let line = line?;
      let peer = KnownPeer::from_str(&line)?;
      return Ok(peer.0 == *key_hash);
   }
   Ok(false)
}
/// Represents the pairing mode of this device
#[derive(Debug)]
pub enum PairMode {
   /// Strict creates a random key that must be entered by the other device
   Strict,
   /// Relaxed allows other devices to connect without any confirmation from this device
   Relaxed,
   /// Password allows other devices to connect to this device with a password
   Password(Arc<PasswordHashString>),
   /// KeyOnly requires users to manually copy the public key to both devices
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
fn add_known_peer(peer: KnownPeer) {
   let mut file = File::options()
      .read(true)
      .append(true)
      .open(CONFIG_DIR.join("known_peers"))
      .expect("Failed to open known peers file");
   if file.metadata().expect("Failed to get metadata").len() > 0 {
      let mut last_char = [0];
      file
         .read_exact(&mut last_char)
         .expect("Failed to read last character");
      if last_char[0] != b'\n' {
         file.write_all(b"\n").expect("Failed to write newline");
      }
   }
   file
      .write_all(&peer.0)
      .expect("Failed to write to known peers file");
}
/// This function is used for authenticating peers who claim to be known to us already
async fn authenticate_peer(connection: &mut Connection) -> Result<()> {
   use Error::PeerRejected;
   let boexed_data = connection
      .peer_identity()
      .ok_or(PeerRejected("no peer identity".to_string()))?;
   let peer_cert = boexed_data
      .downcast_ref::<rustls::pki_types::CertificateDer>()
      .ok_or(PeerRejected(
         "peer identity is not a valid certificate".to_string(),
      ))?;
   let (_, x509_cert) = x509_parser::parse_x509_certificate(peer_cert)
      .map_err(|_| PeerRejected("peer identity is not a valid certificate".to_string()))?;
   let public_key = x509_cert.public_key().raw;
   let peer_id = blake3::hash(public_key);
   let is_known = task::spawn_blocking(move || is_known_peers(peer_id.as_bytes()))
      .await
      .expect("Failed to spawn task")?;
   if !is_known {
      return Err(PeerRejected("peer is not a known peer".to_string()));
   }
   Ok(())
}

async fn pair_client_side(connection: &mut Connection) -> Result<()> {
   use CloseCode::AuthenticationFailure;
   use Error::PeerRejected;
   use PairMode::*;
   let (mut channel_tx, mut channel_rx) = connection.accept_bi().await?;
   todo!("implement pair_client_side");
}
async fn pair_server_side(connection: &mut Connection) -> Result<()> {
   use CloseCode::AuthenticationFailure;
   use Error::PeerRejected;
   use PairMode::*;
   let pair_mode = get_pair_mode();
   let (mut channel_tx, mut channel_rx) = connection.open_bi().await?;
   assert!(
      pair_mode
         .to_string()
         .contains(|c: char| c.is_ascii_uppercase()),
      "Pair mode must be in uppercase"
   );
   channel_tx
      .write_all(pair_mode.to_string().as_bytes())
      .await?;
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
         let mut client_password = [0; 256]; // any password longer than this is rejected
         let read = channel_rx
            .read(&mut client_password)
            .await?
            .unwrap_or_default();
         if read == 0 {
            return Err(PeerRejected(
               "Password must be at least 1 character long".to_string(),
            ));
         }
         let verifier = Argon2::default();
         let accept = task::spawn_blocking(move || {
            verifier
               .verify_password(&client_password, &password.password_hash())
               .is_ok()
         })
         .await
         .expect("Failed to spawn task");
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
         channel_rx.read(&mut response_key).await?;
         if random_key != response_key {
            return Err(PeerRejected("Key mismatch".to_string()));
         }
         channel_tx.write_all(AuthCommands::ACCEPT).await?;
      }
   }
   todo!("implement pair_server_side")
}

pub async fn pair_peer(connection: &mut Connection) -> Result<()> {
   use Side::{Client, Server};
   match connection.side() {
      Client => pair_client_side(connection).await,
      Server => pair_server_side(connection).await,
   }
}
pub async fn handle_incoming(incoming: Incoming) -> Result<Connection> {
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
         Ok(peer) => Ok(connection),
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
      match pair_peer(&mut connection).await {
         Ok(peer) => Ok(connection),
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
