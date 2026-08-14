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
   #[error(
      "fullname must end with service type. We should only be receiving service events for our service type."
   )]
   InvalidFullname,
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
         // this is asserted on debug and is checked on release
         debug_assert!(
            fullname.ends_with(SERVICE_TYPE),
            "fullname must end with service type. We should only be receiving service events for our service type."
         );

         #[cfg(not(debug_assertions))]
         if !fullname.ends_with(SERVICE_TYPE) {
            return Err(InvalidFullname);
         }

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
            #[cfg(not(test))]
            let is_valid = (addr.is_ipv4() || addr.is_ipv6()) && !addr.is_loopback();

            // easiest way to test is to allow loopback in tests only
            #[cfg(test)]
            let is_valid = (addr.is_ipv4() || addr.is_ipv6());

            if !is_valid {
               continue;
            }

            let ip_addr = addr.to_ip_addr();
            let socket_addr = SocketAddr::new(ip_addr, port);
            tracing::debug!("Attempting to connect to {socket_addr:?} with peer id {peer_id:?}");

            match endpoint.connect(socket_addr, hostname) {
               Ok(connection) => {
                  let mut connection = connection.await?;
                  if let Err(error) = authenticate_client_side(&mut connection).await {
                     tracing::error!("Failed to authenticate self to peer: {error:?}");
                     return Ok(());
                  }
                  tracing::debug!("Connected to {fullname}");
                  discovered_services.insert(fullname.to_owned());
                  return Ok(());
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
   let peer_id = peer_id.to_string();

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
         [
            (VERSION_KEY_PROPERTY, VERSION_NUMBER),
            (PEER_ID_KEY, peer_id.as_str()),
         ]
         .as_ref(),
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

#[cfg(test)]
mod tests {
   use super::*;
   use crate::{
      CONFIG_DIR,
      protocol::p2p_auth::{
         KNOWN_PEERS_LOCK, PairMode, configure_client, configure_server, get_peer_id,
         handle_incoming,
      },
   };
   use std::{
      fs,
      net::{IpAddr, Ipv4Addr},
      time::Duration,
   };
   use tokio::time::timeout;

   /// Restores the previous contents of the known peers file on drop, so tests
   /// never leak state into each other or into real runs.
   struct KnownPeersGuard {
      previous: Option<Vec<u8>>,
   }

   impl KnownPeersGuard {
      fn set(peer_ids: &[&str]) -> Self {
         let path = CONFIG_DIR.join("known_peers");
         let previous = fs::read(&path).ok();
         let contents = peer_ids
            .iter()
            .map(|id| format!("{id}\n"))
            .collect::<String>();
         fs::write(&path, contents).expect("failed to write known peers file");
         Self { previous }
      }
   }

   impl Drop for KnownPeersGuard {
      fn drop(&mut self) {
         let path = CONFIG_DIR.join("known_peers");
         match &self.previous {
            Some(contents) => {
               fs::write(&path, contents).expect("failed to restore known peers file");
            }
            None => {
               let _ = fs::remove_file(&path);
            }
         }
      }
   }

   /// Builds a resolved service event from raw parts, without touching the
   /// network. The host is derived from the instance name with the ".local."
   /// suffix, matching how `advertise_local_client` registers real services.
   fn resolved_event(
      instance: &str, ip: IpAddr, port: u16, peer_id: &str, version: &str,
   ) -> ServiceEvent {
      resolved_event_with_props(
         instance,
         ip,
         port,
         &[("peer_id", peer_id), ("version", version)],
      )
   }

   fn resolved_event_with_props(
      instance: &str, ip: IpAddr, port: u16, props: &[(&str, &str)],
   ) -> ServiceEvent {
      let service_info = ServiceInfo::new(
         SERVICE_TYPE,
         instance,
         format!("{instance}.local.").as_str(),
         ip.to_string().as_str(),
         port,
         props,
      )
      .expect("failed to build service info");
      ServiceEvent::ServiceResolved(Box::new(service_info.as_resolved_service()))
   }

   fn client_endpoint() -> Endpoint {
      Endpoint::client("0.0.0.0:0".parse().expect("invalid addr"))
         .expect("failed to create client endpoint")
   }

   fn random_peer_id() -> String {
      let id: [u8; 32] = rand::random();
      hex::encode(id)
   }

   /// Returns a non-loopback IP for this machine by asking the kernel to pick
   /// a route. No packets are sent; it only resolves the interface.
   fn non_loopback_ip() -> IpAddr {
      let udp = std::net::UdpSocket::bind("0.0.0.0:0").expect("failed to bind udp socket");
      udp.connect("8.8.8.8:80").expect("failed to pick a route");
      let ip = udp.local_addr().expect("failed to get local addr").ip();
      assert!(!ip.is_loopback(), "no non-loopback interface available");
      ip
   }

   #[tokio::test]
   #[should_panic(expected = "Hostname cannot be empty")]
   async fn test_advertise_rejects_empty_hostname() {
      advertise_local_client(
         "0.0.0.0:0".parse().expect("invalid addr"),
         String::new(),
         &"0".repeat(HEX_ENCODED_PEER_ID_LENGTH),
      )
      .await;
   }

   #[tokio::test]
   #[should_panic(expected = "Hostname cannot be longer than 15 characters")]
   async fn test_advertise_rejects_long_hostname() {
      advertise_local_client(
         "0.0.0.0:0".parse().expect("invalid addr"),
         "this-hostname-is-way-too-long".to_string(),
         &"0".repeat(HEX_ENCODED_PEER_ID_LENGTH),
      )
      .await;
   }

   #[tokio::test]
   #[should_panic(expected = "peer id must be the correct length")]
   async fn test_advertise_rejects_bad_peer_id_length() {
      advertise_local_client(
         "0.0.0.0:0".parse().expect("invalid addr"),
         "test-host".to_string(),
         &"0".repeat(HEX_ENCODED_PEER_ID_LENGTH - 1),
      )
      .await;
   }

   #[tokio::test]
   async fn test_advertise_and_browse_self() {
      let server_config = configure_server("test-mdns-adv").expect("failed to configure server");
      let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().expect("invalid addr"))
         .expect("failed to create endpoint");
      let local_addr = endpoint.local_addr().expect("failed to get local addr");

      let hostname = "mdns-adv".to_string();
      let peer_id = get_peer_id("test-mdns-adv").expect("failed to get peer id");
      let daemon = advertise_local_client(local_addr, hostname.clone(), &peer_id).await;
      let browser = daemon
         .browse(SERVICE_TYPE)
         .expect("failed to browse for peers");

      let resolved = timeout(Duration::from_secs(5), async {
         loop {
            match browser.recv_async().await.expect("mdns browser closed") {
               ServiceEvent::ServiceResolved(info) => break *info,
               _ => continue,
            }
         }
      })
      .await
      .expect("timed out waiting for the service to resolve");

      assert_eq!(
         resolved.get_fullname(),
         format!("{hostname}.{SERVICE_TYPE}")
      );
      assert_eq!(resolved.get_hostname(), format!("{hostname}.local."));
      assert_eq!(resolved.get_port(), local_addr.port());
      assert_eq!(
         resolved.get_property_val_str("peer_id"),
         Some(peer_id.as_str())
      );
      assert_eq!(
         resolved.get_property_val_str("version"),
         Some(VERSION_NUMBER)
      );
   }

   #[tokio::test]
   async fn test_resolved_missing_peer_id() {
      let endpoint = client_endpoint();
      let mut discovered = HashSet::new();
      let event = resolved_event_with_props(
         "no-peer-id",
         IpAddr::V4(Ipv4Addr::LOCALHOST),
         1,
         &[("version", VERSION_NUMBER)],
      );
      let result = handle_event(&event, &endpoint, &mut discovered).await;
      assert!(matches!(result, Err(EventError::NoPeerId)));
      assert!(discovered.is_empty());
   }

   #[tokio::test]
   async fn test_resolved_missing_version() {
      let endpoint = client_endpoint();
      let mut discovered = HashSet::new();
      let event = resolved_event_with_props(
         "no-version",
         IpAddr::V4(Ipv4Addr::LOCALHOST),
         1,
         &[("peer_id", &random_peer_id())],
      );
      let result = handle_event(&event, &endpoint, &mut discovered).await;
      assert!(matches!(result, Err(EventError::UnsupportedVersion)));
      assert!(discovered.is_empty());
   }

   #[tokio::test]
   async fn test_resolved_short_peer_id_skipped() {
      let endpoint = client_endpoint();
      let mut discovered = HashSet::new();
      let event = resolved_event(
         "short-id",
         IpAddr::V4(Ipv4Addr::LOCALHOST),
         1,
         "too-short",
         VERSION_NUMBER,
      );
      let result = handle_event(&event, &endpoint, &mut discovered).await;
      assert!(result.is_ok());
      assert!(discovered.is_empty());
   }

   #[tokio::test]
   async fn test_resolved_unsupported_version() {
      let endpoint = client_endpoint();
      let mut discovered = HashSet::new();
      let event = resolved_event(
         "old-version",
         IpAddr::V4(Ipv4Addr::LOCALHOST),
         1,
         &random_peer_id(),
         "999.0.0",
      );
      let result = handle_event(&event, &endpoint, &mut discovered).await;
      assert!(matches!(result, Err(EventError::UnsupportedVersion)));
      assert!(discovered.is_empty());
   }

   #[tokio::test]
   async fn test_resolved_invalid_hex_peer_id() {
      let endpoint = client_endpoint();
      let mut discovered = HashSet::new();
      let event = resolved_event(
         "bad-hex",
         IpAddr::V4(Ipv4Addr::LOCALHOST),
         1,
         &"g".repeat(HEX_ENCODED_PEER_ID_LENGTH),
         VERSION_NUMBER,
      );
      let result = handle_event(&event, &endpoint, &mut discovered).await;
      assert!(matches!(result, Err(EventError::InvalidPeerId(_))));
      assert!(discovered.is_empty());
   }

   #[tokio::test]
   async fn test_resolved_unknown_peer_skipped() {
      let _guard = KNOWN_PEERS_LOCK
         .lock()
         .unwrap_or_else(|poisoned| poisoned.into_inner());
      let _known_peers = KnownPeersGuard::set(&[]);
      let endpoint = client_endpoint();
      let mut discovered = HashSet::new();
      let event = resolved_event(
         "unknown-peer",
         IpAddr::V4(Ipv4Addr::LOCALHOST),
         1,
         &random_peer_id(),
         VERSION_NUMBER,
      );
      let result = handle_event(&event, &endpoint, &mut discovered).await;
      assert!(result.is_ok());
      assert!(discovered.is_empty());
   }

   #[tokio::test]
   async fn test_resolved_duplicate_skipped() {
      let endpoint = client_endpoint();
      let mut discovered = HashSet::new();
      let fullname = "dup._fsync._udp.local.".to_string();
      discovered.insert(fullname.clone());
      let event = resolved_event(
         "dup",
         IpAddr::V4(Ipv4Addr::LOCALHOST),
         1,
         &random_peer_id(),
         VERSION_NUMBER,
      );
      let result = handle_event(&event, &endpoint, &mut discovered).await;
      assert!(result.is_ok());
      assert_eq!(discovered.len(), 1, "duplicate must not be re-added");
      assert!(discovered.contains(&fullname));
   }

   #[tokio::test]
   async fn test_removed_removes_service() {
      let endpoint = client_endpoint();
      let mut discovered = HashSet::new();
      let gone = "gone._fsync._udp.local.".to_string();
      let stays = "stays._fsync._udp.local.".to_string();
      discovered.insert(gone.clone());
      discovered.insert(stays.clone());

      let event = ServiceEvent::ServiceRemoved(SERVICE_TYPE.to_string(), gone.clone());
      let result = handle_event(&event, &endpoint, &mut discovered).await;
      assert!(result.is_ok());
      assert!(
         !discovered.contains(&gone),
         "removed service must be dropped"
      );
      assert!(discovered.contains(&stays), "other services must be kept");
   }

   #[tokio::test]
   #[should_panic(expected = "We should only be receiving service events for our service type")]
   async fn test_removed_wrong_service_type_panics() {
      let endpoint = client_endpoint();
      let mut discovered = HashSet::new();
      let event = ServiceEvent::ServiceRemoved(
         "_other._tcp.local.".to_string(),
         "x._other._tcp.local.".to_string(),
      );
      handle_event(&event, &endpoint, &mut discovered)
         .await
         .unwrap();
   }

   #[tokio::test]
   async fn test_resolved_known_peer_connects() {
      // This exercises the full QUIC path: the server side runs `handle_incoming`
      // and the client side runs `handle_event` against a real endpoint. It is
      // slow (~5s) until the ACKNOWLEDGE bug (github.com/RanchMonster/fsync#16)
      // is fixed, because `authenticate_client_side` times out waiting for an
      // acknowledgement the server never sends.
      let _guard = KNOWN_PEERS_LOCK
         .lock()
         .unwrap_or_else(|poisoned| poisoned.into_inner());
      let server_name = "test-connect-server";
      let client_name = "test-connect-client";
      let server_peer_id = get_peer_id(server_name).expect("failed to get server peer id");
      let client_peer_id = get_peer_id(client_name).expect("failed to get client peer id");
      let _known_peers = KnownPeersGuard::set(&[&server_peer_id, &client_peer_id]);

      let ip = non_loopback_ip();
      let server_config = configure_server(server_name).expect("failed to configure server");
      let server = Endpoint::server(server_config, SocketAddr::new(ip, 0))
         .expect("failed to create server endpoint");
      let local_addr = server.local_addr().expect("failed to get local addr");

      let server_task = tokio::task::spawn(async move {
         let incoming = server.accept().await.expect("no incoming connection");
         handle_incoming(incoming, &PairMode::Relaxed)
            .await
            .expect("failed to handle incoming connection");
      });

      let client_config = configure_client(client_name).expect("failed to configure client");
      let mut endpoint = client_endpoint();
      endpoint.set_default_client_config(client_config);

      let mut discovered = HashSet::new();
      let event = resolved_event(
         server_name,
         ip,
         local_addr.port(),
         &server_peer_id,
         VERSION_NUMBER,
      );

      timeout(
         Duration::from_secs(15),
         handle_event(&event, &endpoint, &mut discovered),
      )
      .await
      .expect("handle_event timed out")
      .expect("handle_event failed");

      assert!(
         discovered.contains(format!("{server_name}.{SERVICE_TYPE}").as_str()),
         "known peer should have been added to discovered services: {discovered:?}"
      );
      server_task.await.expect("server task panicked");
   }
}
