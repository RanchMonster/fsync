use crate::p2p::network::{Network, NetworkMember};
use crate::p2p::{PeerId, VERSION_NUMBER};

use mdns_sd::{ResolvedService, ScopedIp, ServiceDaemon, ServiceEvent, ServiceInfo};
use quinn::{ConnectError, Connecting, ConnectionError, Endpoint};
use std::collections::HashMap;
use std::str::FromStr;
use std::{collections::HashSet, net::SocketAddr};
use thiserror::Error;
use tokio::{sync::watch, task};
use tracing::instrument;

/// The length of a peer id in hex encoded form.
const PEER_ID_KEY: &str = "peer_id";
const SERVICE_TYPE: &str = "_fsync._udp.local.";
const VERSION_KEY_PROPERTY: &str = "version";
#[derive(Debug, Error)]
pub enum EventError {
   #[error(transparent)]
   Connect(#[from] ConnectError),
   #[error("peer id not found")]
   NoPeerId,
   #[error("Peer version not supported")]
   UnsupportedVersion,
   #[error(transparent)]
   Connection(#[from] ConnectionError),
   #[error("Peer id was not a valid hex string")]
   InvalidPeerId(#[source] hex::FromHexError),
   #[error(
      "fullname must end with service type. We should only be receiving service events for our service type."
   )]
   InvalidFullname,
   #[error("Failed to find a valid connection path for {0}")]
   NoValidConnectionPath(String),
   #[error(transparent)]
   Local(#[from] mdns_sd::Error),
}

/// Container for the relevant information from a service resolved event.
#[derive(Clone)]
pub struct ServiceResolvedInfo {
   hostname: String,
   fullname: String,
   port: u16,
   peer_id: PeerId,
   version: String,
   addresses: HashSet<ScopedIp>,
}
impl NetworkMember for ServiceResolvedInfo {
   fn id(&self) -> PeerId {
      self.peer_id
   }
   fn name(&self) -> &str {
      self.hostname.as_str()
   }
}

/// Simple method to extract the relevant information from a service resolved
/// event.
#[instrument(err)]
fn extract_service_resolved_info(
   info: Box<ResolvedService>,
) -> Result<ServiceResolvedInfo, EventError> {
   use EventError::{InvalidPeerId, NoPeerId, UnsupportedVersion};

   let hostname = info.get_hostname().to_string();
   let fullname = info.get_fullname().to_string();
   let port = info.get_port();

   let peer_id = info
      .txt_properties
      .get("peer_id")
      .map(|v| PeerId::from_str(v.val_str()))
      .ok_or(NoPeerId)?
      .map_err(InvalidPeerId)?;

   let version = info
      .txt_properties
      .get("version")
      .map(|v| v.val_str())
      .ok_or(UnsupportedVersion)?
      .to_string();
   let addresses = info.get_addresses().to_owned();

   Ok(ServiceResolvedInfo {
      hostname,
      fullname,
      port,
      peer_id,
      version,
      addresses,
   })
}

type Result<T, E = EventError> = std::result::Result<T, E>;

const fn is_valid_addr(addr: &ScopedIp) -> bool {
   #[cfg(not(test))]
   return addr.is_ipv4() || addr.is_ipv6() && !addr.is_loopback();
   #[cfg(test)]
   // Easiest way to test is to allow loopback in tests only
   return addr.is_ipv4() || addr.is_ipv6();
}

// Later when we do like path routing, for finding the best/fastest path to a peer, I think we
// should keep this function as the main entry point for that logic.
async fn find_valid_connect_path<I>(
   endpoint: &Endpoint, addresses: I, hostname: &str, port: u16,
) -> Result<Option<Connecting>>
where
   I: IntoIterator<Item = ScopedIp>,
{
   use ConnectError::InvalidRemoteAddress;

   // has to be a closure due to the borrow checker
   let to_socket_addr = |addr: ScopedIp| SocketAddr::new(addr.to_ip_addr(), port);

   let addresses = addresses
      .into_iter()
      .filter(is_valid_addr)
      .map(to_socket_addr);
   for addr in addresses {
      match endpoint.connect(addr, hostname) {
         Ok(connecting) => {
            return Ok(Some(connecting));
         }
         Err(InvalidRemoteAddress(addr)) => {
            tracing::debug!("Invalid remote address {addr:?}");
            continue;
         }
         Err(err) => return Err(err.into()),
      }
   }
   Ok(None)
}

fn create_client_info(
   socket_adrr: SocketAddr, hostname: String, peer_id: PeerId,
) -> Result<ServiceInfo, EventError> {
   assert!(!hostname.is_empty(), "Hostname cannot be empty");
   assert!(
      hostname.len() <= 15,
      "Hostname cannot be longer than 15 characters"
   );
   let peer_id = peer_id.to_string();

   let address = socket_adrr.ip().to_string();
   let port = socket_adrr.port();
   Ok(ServiceInfo::new(
      SERVICE_TYPE,
      &hostname,
      format!("{hostname}.local.").as_str(),
      address,
      port,
      [
         (VERSION_KEY_PROPERTY, VERSION_NUMBER),
         (PEER_ID_KEY, peer_id.as_str()),
      ]
      .as_ref(),
   )?
   .enable_addr_auto())
}

async fn find_other_services(
   event_receiver: mdns_sd::Receiver<ServiceEvent>,
   watch_tx: watch::Sender<HashMap<String, ServiceResolvedInfo>>,
) {
   use ServiceEvent::{ServiceRemoved, ServiceResolved};
   while let Ok(event) = event_receiver.recv_async().await {
      match event {
         ServiceResolved(info) => {
            let Ok(info) = extract_service_resolved_info(info) else {
               continue;
            };
            watch_tx.send_modify(|map| {
               map.insert(info.fullname.clone(), info);
            });
         }
         ServiceRemoved(_, fullname) => {
            watch_tx.send_modify(|map| {
               map.remove(&fullname);
            });
         }
         _ => {}
      }
   }
}

pub struct LocalNetwork {
   service_daemon: ServiceDaemon,
   found_peers: watch::Receiver<HashMap<String, ServiceResolvedInfo>>,
   service_info: ServiceInfo,
}
impl LocalNetwork {
   pub fn new(local_adrr: SocketAddr, peer_id: PeerId, name: &str) -> Result<Self, EventError> {
      let service_daemon = ServiceDaemon::new()?;

      let (found_peers_tx, found_peers) = watch::channel(HashMap::new());

      let service_info = create_client_info(local_adrr, name.to_string(), peer_id)?;

      task::spawn(find_other_services(
         service_daemon.browse(SERVICE_TYPE)?,
         found_peers_tx,
      ));

      Ok(Self {
         service_daemon,
         service_info,
         found_peers,
      })
   }
}
impl Network<ServiceResolvedInfo, EventError> for LocalNetwork {
   fn advertise(&mut self) -> Result<()> {
      self.service_daemon.register(self.service_info.clone())?;
      Ok(())
   }

   fn stop_advertising(&mut self) -> Result<()> {
      self
         .service_daemon
         .unregister(self.service_info.get_fullname())?;
      Ok(())
   }

   async fn connect(&self, endpoint: &Endpoint, member: ServiceResolvedInfo) -> Result<Connecting> {
      use EventError::NoValidConnectionPath;

      let connecting =
         find_valid_connect_path(endpoint, member.addresses, &member.hostname, member.port)
            .await?
            .ok_or(NoValidConnectionPath(member.hostname))?;

      Ok(connecting)
   }

   fn list_members(&self) -> Result<Vec<ServiceResolvedInfo>> {
      Ok(self.found_peers.borrow().values().cloned().collect())
   }

   async fn wait_for_updates(&mut self) -> Result<Vec<ServiceResolvedInfo>> {
      self
         .found_peers
         .changed()
         .await
         .expect("Watcher closed unexpectedly");
      Ok(self.found_peers.borrow().values().cloned().collect())
   }
   fn network_name(&self) -> &str {
      "local"
   }
}
