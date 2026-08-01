mod error;
mod p2p_auth;
pub use error::{Error, Result};
use mdns_sd::{Receiver, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, ServerConfig};
use rcgen::CertificateParams;
use std::sync::Arc;
use tokio::{
   sync::watch,
   task::{self, JoinHandle},
};
use tracing::instrument;

use crate::keys::get_signing_key;

const SERVICE_TYPE: &str = "_fsync._udp.local.";
const DEFAULT_PORT: u16 = 43127;
const VERSION_KEY_PROPERTY: &str = "version";
const VERSION_NUMBER: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_NAME: &str = concat!("fsync/", env!("PROTOCOL_VERSION"));
fn make_server_config() -> quinn::ServerConfig {
   let keypair = get_signing_key();
   let cert = CertificateParams::new(vec!["fsync".into()])
      .expect("Failed to create certificate params")
      .self_signed(&keypair)
      .expect("Failed to create self signed certificate");

   let rustls_config = rustls::ServerConfig::builder()
      .with_no_client_auth()
      .with_single_cert(vec![cert.der().clone()], keypair.into())
      .expect("Failed to create rustls config");
   let quic_config =
      QuicServerConfig::try_from(rustls_config).expect("Failed to create quic config");

   quinn::ServerConfig::with_crypto(Arc::new(quic_config))
}
async fn start_service() -> Result<()> {
   let service_daemon = advertise().await?;
   let server_config = make_server_config();
   let address = std::env::var("ADDRESS").unwrap_or_else(|_| "0.0.0.0".to_string());
   let port = std::env::var("PORT")
      .ok()
      .and_then(|val| val.parse::<u16>().ok())
      .unwrap_or(DEFAULT_PORT);
   let mut endpoint = Endpoint::server(
      server_config,
      format!("{address}:{port}")
         .parse()
         .expect("Invalid address"),
   )?;
   Ok(())
}
async fn advertise() -> Result<ServiceDaemon> {
   let mdns = task::spawn_blocking(move || {
      let mdns = ServiceDaemon::new().expect("Failed to create mdns daemon");
      let mut hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| {
         hostname::get()
            .expect("Failed to get hostname")
            .to_string_lossy()
            .to_string()
      });
      if !hostname.len() > 15 {
         tracing::warn!("Hostname is too long to advertise and will be truncated to 15 characters");
         hostname.truncate(15);
      }
      // load the address from the environment variable or default to auto assigned
      let address = std::env::var("ADDRESS").unwrap_or_else(|_| "0.0.0.0".to_string());
      let port = std::env::var("PORT")
         .ok()
         .and_then(|val| val.parse::<u16>().ok())
         .unwrap_or(DEFAULT_PORT);
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

      Ok::<_, Error>(mdns)
   })
   .await;
   let mdns = mdns.expect("Thread unexpectedly panicked")?;

   Ok(mdns)
}
