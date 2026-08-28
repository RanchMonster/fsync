mod error;
pub mod p2p_auth;
use mdns_sd::{ServiceDaemon, ServiceInfo};
use p2p_auth::AuthError;
use quinn::Endpoint;
use std::net::SocketAddr;
use tokio::task::{self};

pub use crate::protocol::p2p_auth::PairMode;
use crate::{
   Config,
   protocol::p2p_auth::{configure_server, handle_incoming},
};

const SERVICE_TYPE: &str = "_fsync._udp.local.";
const VERSION_KEY_PROPERTY: &str = "version";
const VERSION_NUMBER: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_NAME: &str = concat!("fsync/", env!("PROTOCOL_VERSION"));

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
   let pair_mode = &config.pair_mode;

   // configure the serve and attempt to locate peers on the network that we can talk to
   let server_config = configure_server(&hostname).expect("Failed to configure server");
   let socket_addr = format!("{config_address}:{config_port}")
      .parse()
      .expect("Invalid address or port");
   let endpoint = match Endpoint::server(server_config, socket_addr) {
      Ok(endpoint) => endpoint,
      Err(err) => {
         panic!("Failed to create service endpoint on {config_address}:{config_port}: {err}")
      }
   };
   let local_addr = endpoint.local_addr().expect("Failed to get local address");
   tracing::debug!("Listening on {local_addr}");

   tracing::debug!("Advertising {hostname}");
   // start the advertisement daemon
   let advertising_daemon = advertise_local_client(local_addr, hostname).await;
   tracing::debug!("Looking for peers");
   let browser = advertising_daemon
      .browse(SERVICE_TYPE)
      .expect("Failed to browse for peers");

   // event loop for the service
   'service: loop {
      tokio::select! {
            accept = endpoint.accept() => {
            let incoming = accept.expect("Server closed unexpectedly");
            tracing::debug!("Accepted connection {incoming:?}");
            match handle_incoming(incoming, pair_mode).await {
                Ok(_connection) => tracing::debug!("Connection accepted, handling is not implemented yet"),
                Err(err) => match err {
                    AuthError::Quic(quic_error) => tracing::error!("Failed to handle connection to {local_addr:?}: {quic_error}"),
                    reason => tracing::warn!("Rejected connection to {local_addr:?}: {reason}"),

                }
            }
         }
         _event = browser.recv_async() => {
            todo!("handle events");
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
