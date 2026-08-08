mod error;
mod p2p_auth;
pub use error::{Error, Result};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use quinn::Endpoint;
use std::net::SocketAddr;
use tokio::task::{self};

use crate::protocol::p2p_auth::{PairMode, configure_server, handle_incoming};

const SERVICE_TYPE: &str = "_fsync._udp.local.";
const DEFAULT_PORT: u16 = 43127;
const VERSION_KEY_PROPERTY: &str = "version";
const VERSION_NUMBER: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_NAME: &str = concat!("fsync/", env!("PROTOCOL_VERSION"));

// cleaner then a bunch of arguments
struct ServiceConfigArgs {
   pub address: Option<String>,
   pub port: Option<u16>,
   // this field is required
   pub pair_mode: Option<PairMode>,
   pub hostname: Option<String>,
   // add more as needed
   // once we have figured out a config and put stuff togother more we will need to add this
   // sync_dirs: todo!("whatever we use to represent sync dirs"),
}
async fn start_service(config_args: ServiceConfigArgs) -> Result<()> {
   // load args from the config given
   let hostname = config_args.hostname.unwrap_or_else(|| {
      let mut name = hostname::get()
         .expect("Failed to get hostname")
         .to_string_lossy()
         .to_string();
      if name.len() > 15 {
         tracing::warn!("Hostname is longer than 15 characters, truncating");
         name.truncate(15);
      }
      name
   });
   assert!(!hostname.is_empty(), "Hostname cannot be empty");
   assert!(
      hostname.len() <= 15,
      "Hostname cannot be longer than 15 characters"
   );
   let address = config_args.address.unwrap_or_else(|| "0.0.0.0".to_string());
   let explicit_port = config_args.port;
   let port = explicit_port.unwrap_or(DEFAULT_PORT);
   let pair_mode = config_args.pair_mode.unwrap_or(PairMode::Relaxed);

   // configure the serve and attempt to locate peers on the network that we can talk to
   let server_config = configure_server(&hostname).expect("Failed to configure server");
   let socket_addr = format!("{address}:{port}")
      .parse()
      .expect("Invalid address or port");
   let endpoint = match Endpoint::server(server_config.clone(), socket_addr) {
      Ok(endpoint) => endpoint,
      Err(err) if err.kind() == std::io::ErrorKind::AddrInUse && explicit_port.is_none() => {
         tracing::warn!("Default port {port} is in use, using a random free port instead");
         let fallback_addr = format!("{address}:0")
            .parse()
            .expect("Invalid address or port");
         Endpoint::server(server_config, fallback_addr)
            .expect("Failed to create service endpoint on a random free port")
      }
      Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
         panic!("Port {port} is in use, set a different port: {err}");
      }
      Err(err) => panic!("Failed to create service endpoint on {address}:{port}: {err}"),
   };
   let local_addr = endpoint.local_addr().expect("Failed to get local address");
   tracing::debug!("Listening on {local_addr}");

   tracing::debug!("Advertising {hostname}");
   // start the advertisement daemon
   let advertising_daemon = advertise(local_addr, hostname).await;
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
            match handle_incoming(incoming, &pair_mode).await {
                Ok(_connection) => tracing::debug!("Connection accepted, handling is not implemented yet"),
                Err(err) => match err {
                    Error::Quic(quic_error) => tracing::error!("Failed to handle connection to {local_addr:?}: {quic_error}"),
                    Error::PeerRejected(reason) => tracing::warn!("Rejected connection to {local_addr:?}: {reason}"),
                    error => unreachable!("This error shouldn't be possible
                        if you are seeing this please submit a new issue with the following message:{error:?}"),
                }
            }
         }
         _event = browser.recv_async() => {
            todo!("handle events");
         }
      }
   }
}

async fn advertise(socket_adrr: SocketAddr, hostname: String) -> ServiceDaemon {
   assert!(!hostname.is_empty(), "Hostname cannot be empty");
   assert!(
      hostname.len() <= 15,
      "Hostname cannot be longer than 15 characters"
   );
   let mdns = task::spawn_blocking(move || {
      let mdns = ServiceDaemon::new().expect("Failed to create mdns daemon");
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
      mdns.register(service_info)?;

      Ok::<_, Box<dyn std::error::Error + Send + Sync>>(mdns)
   })
   .await;
   let mdns = mdns
      .expect("Thread unexpectedly panicked")
      .expect("Failed to create mdns daemon");

   mdns
}
