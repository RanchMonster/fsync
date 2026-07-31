use quinn::{
   Connection, ConnectionError, ConnectionId, Incoming, VarInt, crypto::rustls::HandshakeData,
};
use std::{
   collections::{HashMap, HashSet},
   io::{BufRead, BufReader},
   str::FromStr,
   sync::{Arc, LazyLock},
   time::SystemTime,
};
use tokio::sync::RwLock;
mod mtls;
use super::error::*;
use crate::{CONFIG_DIR, protocol::PROTOCOL_NAME};
pub use mtls::configure_server;
use tokio::task;

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

struct KnownPeer {
   name: String,
   key_hash: [u8; 32],
   // store more info here as needed
}
impl FromStr for KnownPeer {
   type Err = Error;
   fn from_str(s: &str) -> Result<Self> {
      let mut fields = s.split_whitespace();
      let name = fields
         .next()
         .ok_or(Error::ParseData("Missing name".into()))?;
      let key_hash = fields
         .next()
         .map(|key_hash| {
            hex::decode(key_hash).map_err(|_| Error::ParseData("Invalid key hash".into()))
         })
         .ok_or(Error::ParseData("Missing key hash".into()))??
         .try_into()
         .map_err(|_| Error::ParseData("Invalid key hash length".into()))?;
      Ok(KnownPeer {
         name: name.into(),
         key_hash,
      })
   }
}
fn is_known_peers(key_hash: &[u8; 32]) -> Result<Option<KnownPeer>> {
   let path = CONFIG_DIR.join("known_peers");
   BufReader::new(std::fs::File::open(path)?)
      .lines()
      .find_map(|line| {
         let result = line.map(|line| KnownPeer::from_str(&line));
         match result {
            Ok(Ok(peer)) if peer.key_hash == *key_hash => Some(peer),
            Ok(Ok(_)) => None, // ignore lines that don't match the key hash
            Ok(Err(err)) => {
               tracing::error!("Failed to parse known peer: {err}");
               None
            }
            Err(err) => {
               tracing::error!("Failed to read line from known peers file: {err}");
               None
            }
         }
      });
   todo!("implement is_known_peers");
}
/// This function is used for authenticating peers who claim to be known to us already
async fn authenticate_peer(connection: &mut Connection) -> Result<KnownPeer> {
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
   match task::spawn_blocking(move || is_known_peers(peer_id.as_bytes()))
      .await
      .expect("Failed to spawn task")?
   {
      Some(peer) => Ok(peer),
      None => Err(PeerRejected("peer is not a known peer".to_string())),
   }
}
async fn pair_peer(connection: &mut Connection) -> Result<KnownPeer> {
   todo!("implement pair_peer");
}
pub async fn handle_incoming(incoming: Incoming) -> Result<(Connection, KnownPeer)> {
   use CloseCode::AuthenticationFailure;
   use Error::PeerRejected;
   let mut connection = incoming.await?;
   let handshake_packet = connection.read_datagram().await?;
   if handshake_packet.is_empty() {
      connection.close(AuthenticationFailure.into(), b"no auth handshake data");
      return Err(PeerRejected(
         "peer did not send auth handshake data".to_string(),
      ));
   }
   if handshake_packet.starts_with(AuthCommands::INIT) {
      match authenticate_peer(&mut connection).await {
         Ok(peer) => Ok((connection, peer)),
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
         Ok(peer) => Ok((connection, peer)),
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
