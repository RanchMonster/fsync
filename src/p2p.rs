pub mod auth;
mod close_code;
mod network;
use auth::{configure_client, configure_server, get_peer_id, handle_incoming};
use discovery::{advertise_local_client, handle_event};
use quinn::{Endpoint, Incoming};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::{self};

use crate::Config;

const SERVICE_TYPE: &str = "_fsync._udp.local.";
const VERSION_KEY_PROPERTY: &str = "version";
const VERSION_NUMBER: &str = env!("CARGO_PKG_VERSION");

pub const PROTOCOL_NAME: &str = concat!("fsync/", env!("PROTOCOL_VERSION"));
fn handle_incoming_detached(incoming: Incoming) {
   task::spawn(async move {
      // the error is handled for us via instrumentation on the functions
      // see [tracing::instrument](https://docs.rs/tracing/latest/tracing/attr.instrument.html)
      // for more information
      let Ok(_connection) = handle_incoming(incoming).await else {
         return;
      };
      #[cfg(not(debug_assertions))]
      compile_error!(
         "There is not current handling for incoming connections this must be implemented for production"
      );
   });
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

   loop {
      let accept = endpoint.accept().await.expect("Server closed unexpectedly");
      tracing::debug!("Accepted connection {accept:?}");
      handle_incoming_detached(accept);
   }
}
