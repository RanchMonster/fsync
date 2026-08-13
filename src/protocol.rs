mod discovery;
mod error;
pub mod p2p_auth;
use discovery::{EventError, advertise_local_client, handle_event};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use p2p_auth::AuthError;
use p2p_auth::{PairMode, authenticate_client_side, configure_server, handle_incoming};
use quinn::{ConnectError, ConnectionError, Endpoint};
use std::{collections::HashSet, net::SocketAddr};
use thiserror::Error;
use tokio::task::{self};

use crate::protocol::p2p_auth::{configure_client, get_peer_id};
pub const SERVICE_TYPE: &str = "_fsync._udp.local.";
const DEFAULT_PORT: u16 = 43127;
pub const VERSION_KEY_PROPERTY: &str = "version";
pub const VERSION_NUMBER: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_NAME: &str = concat!("fsync/", env!("PROTOCOL_VERSION"));

// cleaner then a bunch of arguments
pub struct ServiceConfigArgs {
   pub address: String,
   pub port: u16,
   // this field is required
   pub sync_dirs: Vec<String>,
   pub pair_mode: PairMode,
   pub hostname: String,
   // add more as needed
   // once we have figured out a config and put stuff togother more we will need to add this
   // sync_dirs: todo!("whatever we use to represent sync dirs"),
}
async fn start_service(config_args: ServiceConfigArgs) -> ! {
   // load args from the config given
   let hostname = config_args.hostname.clone();

   assert!(!hostname.is_empty(), "Hostname cannot be empty");
   assert!(
      hostname.len() <= 15,
      "Hostname cannot be longer than 15 characters"
   );
   let config_address = config_args.address;
   let config_port = config_args.port;
   let pair_mode = config_args.pair_mode;

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

   let peer_id = get_peer_id(&hostname).expect("Failed to get peer id");
   tracing::debug!("Advertising {hostname} as ");

   // start the advertisement daemon
   let advertising_daemon = advertise_local_client(local_addr, hostname, &peer_id).await;
   tracing::debug!("Looking for peers");

   let browser = advertising_daemon
      .browse(SERVICE_TYPE)
      .expect("Failed to browse for peers");

   // Define event loop variables
   let mut discovered_peers = HashSet::new();

   // event loop for the service
   loop {
      tokio::select! {
            accept = endpoint.accept() => {
            let incoming = accept.expect("Server closed unexpectedly");
            tracing::debug!("Accepted connection {incoming:?}");
            match handle_incoming(incoming, &pair_mode).await {
                Ok(_connection) => tracing::debug!("Connection accepted, handling is not implemented yet"),
                Err(err) => match err {
                    AuthError::Quic(quic_error) => tracing::error!("Failed to handle connection to {local_addr:?}: {quic_error}"),
                    reason => tracing::warn!("Rejected connection to {local_addr:?}: {reason}"),

                }
            }
         }
         event = browser.recv_async() => {
         let event = event.expect("Unexpectedly closed mdns browser");
      match handle_event(&event, &endpoint, &mut discovered_peers).await{
         Ok(_) => continue,
         Err(err) => tracing::error!("Failed to handle service event: {event:?}: {err}"),

         }
         }
      }
   }
}

async fn advertise_local_client(socket_adrr: SocketAddr, hostname: String) -> ServiceDaemon {
   assert!(!hostname.is_empty(), "Hostname cannot be empty");
   assert!(
      hostname.len() <= 15,
      "Hostname cannot be longer than 15 characters"
   );

   task::spawn_blocking(move || {
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
   .expect("Failed to create mdns service daemon")
}
