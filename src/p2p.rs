pub mod auth;
mod close_code;
mod network;
use auth::{configure_client, configure_server, handle_incoming};
use blake3::Hash;
use quinn::{Connection, Endpoint, Incoming};
use std::collections::HashSet;
use std::fmt::Display;
use std::str::FromStr;
use std::sync::LazyLock;
use tokio::sync::RwLock;
use tokio::task::{self};
use tracing::{Instrument, instrument};

use crate::p2p::auth::{handle_connecting, is_known_peer};
use crate::p2p::network::{Network, NetworkError, NetworkMember};
use crate::{Config, asyncify};

const VERSION_NUMBER: &str = env!("CARGO_PKG_VERSION");
pub const HEX_ENCODED_PEER_ID_LENGTH: usize = 64;
pub const PROTOCOL_NAME: &str = concat!("fsync/", env!("PROTOCOL_VERSION"));

/// keeps track of all the peers we are currently connected to we use this to prevent us from
/// connecting to the same peer twice
static CONNECTED_PEERS: LazyLock<RwLock<HashSet<PeerId>>> =
   LazyLock::new(|| RwLock::new(HashSet::new()));

/// A peer identity: the blake3 hash of a peer certificate's public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub struct PeerId(pub [u8; 32]);
impl From<Hash> for PeerId {
   fn from(hash: Hash) -> Self {
      Self(*hash.as_bytes())
   }
}
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
#[instrument(skip(connection))]
fn log_on_disconnect(connection: &Connection, peer_id: PeerId) {
   let connection = connection.clone();
   task::spawn(
      async move {
         connection.closed().await;
         CONNECTED_PEERS.write().await.remove(&peer_id);
         tracing::info!("Peer disconnected");
      }
      .in_current_span(),
   );
}
fn handle_incoming_detached(incoming: Incoming) {
   task::spawn(async move {
      // the error is handled for us via instrumentation on the functions
      // see [tracing::instrument](https://docs.rs/tracing/latest/tracing/attr.instrument.html)
      // for more information
      let Ok((connection, peer_id)) = handle_incoming(incoming).await else {
         return;
      };
      log_on_disconnect(&connection, peer_id);
      #[cfg(not(debug_assertions))]
      compile_error!(
         "There is not current handling for incoming connections this must be implemented for production"
      );
   });
}

#[instrument(err,skip(network,endpoint),fields(network=network.network_name()))]
async fn network_handler<Member: NetworkMember + Send + Sync + 'static, Error: NetworkError>(
   network: &mut impl Network<Member, Error>, endpoint: &Endpoint,
) -> Result<(), Box<dyn std::error::Error>> {
   let connected_peers = CONNECTED_PEERS.read().await;
   let network_members = network
      .list_members()?
      .into_iter()
      .filter(|members| !connected_peers.contains(&members.id()))
      .collect::<Vec<_>>();
   for member in network_members {
      let peer_id = member.id();
      if !asyncify!(is_known_peer, &peer_id)? {
         continue;
      }
      match network.connect(endpoint, member).await {
         Ok(connecting) => {
            let Ok((_connection, peer_id_from_auth)) = handle_connecting(connecting).await else {
               continue;
            };
            if peer_id != peer_id_from_auth {
               // this likely means that someone is up to no good
               tracing::warn!("The peer id doesn't match the public peer id");
            }
            todo!("pass the connection to the sync module");
         }
         Err(err) => {
            tracing::error!("Failed to connect to peer: {err}");
         }
      }
   }

   todo!();
}
pub async fn is_connected(peer_id: &PeerId) -> bool {
   CONNECTED_PEERS.read().await.contains(peer_id)
}

pub async fn start_service(config: &'static Config) -> ! {
   // load args from the config given
   let hostname = config.hostname.clone();

   assert!(!hostname.is_empty(), "Hostname cannot be empty");
   assert!(
      hostname.len() <= 15,
      "Hostname cannot be longer than 15 characters"
   );
   let config_address = &config.address;
   let config_port = config.port;

   // configure the serve and attempt to locate peers on the network that we can talk to
   let server_config = configure_server(&hostname).expect("Failed to configure server");
   let client_config = configure_client(&hostname).expect("Failed to configure client");
   let socket_addr = format!("{config_address}:{config_port}")
      .parse()
      .expect("Invalid address or port");

   let mut endpoint = match Endpoint::server(server_config.clone(), socket_addr) {
      Ok(endpoint) => endpoint,
      Err(err) => {
         panic!("Failed to create service endpoint on {config_address}:{config_port}: {err}")
      }
   };

   // ensure we also set the client config when we attempt to connect to peers we find
   endpoint.set_default_client_config(client_config);

   let local_addr = endpoint.local_addr().expect("Failed to get local address");
   tracing::debug!("Listening on {local_addr}");
   // let mut local_network = LocalNetwork::new(local_addr, peer_id, hostname);

   loop {
      let accept = endpoint.accept().await.expect("Server closed unexpectedly");
      tracing::debug!("Accepted connection {accept:?}");
      handle_incoming_detached(accept);
   }
}
