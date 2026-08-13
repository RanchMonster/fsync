use super::p2p_auth::{authenticate_client_side, is_known_peer};
use super::{SERVICE_TYPE, VERSION_KEY_PROPERTY, VERSION_NUMBER};
use hex::FromHexError;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use quinn::{ConnectError, ConnectionError, Endpoint};
use std::{collections::HashSet, net::SocketAddr};
use thiserror::Error;
use tokio::task;

/// The length of a peer id in hex encoded form.
pub const HEX_ENCODED_PEER_ID_LENGTH: usize = 64;
const PEER_ID_KEY: &str = "peer_id";
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
}

pub async fn handle_event(
   event: &ServiceEvent, endpoint: &Endpoint, discovered_services: &mut HashSet<String>,
) -> std::result::Result<(), EventError> {
   use ConnectError::InvalidRemoteAddress;
   use EventError::{InvalidPeerId, NoPeerId, UnsupportedVersion};
   use ServiceEvent::{ServiceRemoved, ServiceResolved};

   match event {
      ServiceResolved(info) => {
         let hostname = info.get_hostname();
         let fullname = info.get_fullname();
         let port = info.get_port();
         let peer_id = info
            .txt_properties
            .get("peer_id")
            .map(|v| v.val_str())
            .ok_or(NoPeerId)?;
         let version = info
            .txt_properties
            .get("version")
            .map(|v| v.val_str())
            .ok_or(UnsupportedVersion)?;
         if peer_id.len() != HEX_ENCODED_PEER_ID_LENGTH {
            tracing::warn!("peer id is not the correct length {peer_id:?}");
            return Ok(());
         }

         // it should be impossible to break these assertions (do to the mdns standard) unless we
         // use it improperly
         assert!(
            fullname.starts_with(hostname),
            "fullname must start with hostname."
         );
         assert!(
            fullname.ends_with(SERVICE_TYPE),
            "fullname must end with service type. We should only be receiving service events for our service type."
         );
         if discovered_services.contains(fullname) {
            tracing::debug!("Discovered service already connected to {fullname}");
            return Ok(());
         }
         let is_compatible = version == VERSION_NUMBER;

         if !is_compatible {
            Err(UnsupportedVersion)?;
         }

         let is_known = {
            let peer_id: [u8; 32] = hex::decode(peer_id)
               .map_err(InvalidPeerId)?
               .try_into()
               .map_err(|_| InvalidPeerId(FromHexError::InvalidStringLength))?;
            task::spawn_blocking(move || is_known_peer(&peer_id))
               .await
               .expect("Thread unexpectedly panicked")
         };

         if !is_known {
            return Ok(());
         }

         for addr in info.get_addresses() {
            let is_valid = (addr.is_ipv4() || addr.is_ipv6()) && !addr.is_loopback();
            if !is_valid {
               continue;
            }

            let ip_addr = addr.to_ip_addr();
            let socket_addr = SocketAddr::new(ip_addr, port);
            tracing::debug!("Attempting to connect to {socket_addr:?} with peer id {peer_id:?}");

            match endpoint.connect(socket_addr, hostname.clone()) {
               Ok(connection) => {
                  let mut connection = connection.await?;
                  if let Err(error) = authenticate_client_side(&mut connection).await {
                     tracing::error!("Failed to authenticate self to peer: {error:?}");
                  }
                  tracing::debug!("Connected to {fullname}");
                  discovered_services.insert(fullname.to_owned());
               }

               Err(InvalidRemoteAddress(addr)) => {
                  tracing::debug!("Invalid remote address {addr:?}");
                  continue;
               }

               Err(err) => return Err(err.into()),
            }
         }
      }

      ServiceRemoved(service_type, fullname) => {
         assert_eq!(
            service_type, SERVICE_TYPE,
            "We should only be receiving service events for our service type"
         );
         tracing::info!("Service {fullname} no longer advertised");
         discovered_services.remove(fullname);
      }
      _ => {}
   }
   Ok(())
}

pub async fn advertise_local_client(
   socket_adrr: SocketAddr, hostname: String, peer_id: &str,
) -> ServiceDaemon {
   assert_eq!(
      peer_id.len(),
      HEX_ENCODED_PEER_ID_LENGTH,
      "peer id must be the correct length"
   );
   assert!(!hostname.is_empty(), "Hostname cannot be empty");
   assert!(
      hostname.len() <= 15,
      "Hostname cannot be longer than 15 characters"
   );

   let service_daemon = task::spawn_blocking(move || {
      let service_daemon = ServiceDaemon::new().expect("Failed to create mdns daemon");
      // load the address from the environment variable or default to auto assigned
      let address = socket_adrr.ip().to_string();
      let port = socket_adrr.port();
      let service_info = ServiceInfo::new(
         SERVICE_TYPE,
         &hostname,
         format!("{hostname}.local.").as_str(),
         address,
         port,
         [(VERSION_KEY_PROPERTY, VERSION_NUMBER)].as_ref(),
      )?
      .enable_addr_auto();
      service_daemon.register(service_info)?;

      Ok::<_, Box<dyn std::error::Error + Send + Sync>>(service_daemon)
   })
   .await
   .expect("Thread unexpectedly panicked")
   .expect("Failed to create mdns service daemon");

   service_daemon
}
