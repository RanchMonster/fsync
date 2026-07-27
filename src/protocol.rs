mod error;
pub use error::{Error, Result};
use mdns_sd::{Receiver, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};
use std::sync::Arc;
use tokio::{
    sync::Mutex,
    task::{self, JoinHandle},
};
use tracing::instrument;

const SERVICE_TYPE: &str = "_fsync._udp.local.";
const DEFAULT_PORT: u16 = 43127;
const VERSION_KEY_PROPERTY: &str = "version";
const VERSION_NUMBER: &str = env!("CARGO_PKG_VERSION");
/// Represents a peer in the network this is mostly like not the actual peer but is a placeholder
/// until I have figure out what I actual need to know about a peer
#[derive(Clone, Debug)]
pub struct Peer {
    version: String,
    addresses: Vec<String>,
    hostname: String,
    port: u16,
}
impl TryFrom<ResolvedService> for Peer {
    type Error = Error;
    #[instrument]
    fn try_from(resolved: ResolvedService) -> Result<Self> {
        let version = resolved
            .txt_properties
            .get(VERSION_KEY_PROPERTY)
            .ok_or(Error::InvalidPeer(resolved.clone()))?
            .val()
            .and_then(|v| std::str::from_utf8(v).ok())
            .unwrap_or_default()
            .to_string();
        let addresses = resolved
            .addresses
            .iter()
            .map(|address| address.to_ip_addr().to_canonical().to_string())
            .collect();
        let hostname = resolved.get_hostname().to_string();
        let port = resolved.port;
        Ok(Peer {
            version,
            addresses,
            hostname,
            port,
        })
    }
}

impl Peer {
    pub fn compatible(&self) -> bool {
        todo!("check if the peer is compatible")
    }

    pub fn version(&self) -> &str {
        &self.version
    }
    /// Find the first valid address
    /// This function is not yet implemented and will require
    /// a custom endpoint for QUIC I will implement this when I get to QUIC
    pub async fn valid_address(&self) -> &str {
        todo!("find the first valid address")
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn is_local(&self) -> bool {
        todo!("check if the peer is local")
    }
}
macro_rules! unwrap_or_create_daemon {
    ($daemon:expr) => {
        match $daemon {
            Some(daemon) => daemon,
            None => ServiceDaemon::new().expect("Failed to create mdns daemon"),
        }
    };
}
pub struct ServiceScanner<'daemon> {
    inner: Receiver<ServiceEvent>,
    daemon: &'daemon ServiceDaemon,
}
impl<'daemon> ServiceScanner<'daemon> {
    pub async fn next_peer(&mut self) -> Option<Peer> {
        use ServiceEvent::*;
        loop {
            let event = self.inner.recv_async().await.ok()?;
            if let ServiceResolved(resolved) = event {
                return (*resolved).try_into().ok();
            }
        }
    }
}
pub struct Service {
    daemon: Option<ServiceDaemon>,
    peers: Arc<Mutex<Vec<Peer>>>,
    join_handle: Option<JoinHandle<()>>,
}
impl Service {
    pub async fn new() -> Self {
        Self {
            daemon: None,
            peers: Arc::new(Mutex::new(Vec::new())),
            join_handle: None,
        }
    }
    pub async fn stop(&mut self) -> Result<()> {
        self.stop_advertising().await?;
        if let Some(join_handle) = self.join_handle.take() {
            join_handle.abort();
        }
        self.peers.lock().await.clear();
        Ok(())
    }
    pub async fn connected(&self) -> Vec<Peer> {
        (*self.peers.lock().await).clone()
    }
    pub async fn start(&mut self) -> Result<()> {
        task::spawn(async move { todo!("start the service") });
        Ok(())
    }
    pub async fn discover_peers(&mut self) -> Result<ServiceScanner> {
        let daemon = self.daemon.take();
        let result = task::spawn_blocking(move || {
            let mdns = unwrap_or_create_daemon!(daemon);
            let receiver = mdns.browse(SERVICE_TYPE)?;
            Ok::<_, Error>((receiver, mdns))
        })
        .await;
        let (receiver, mdns) =
            result.expect("Failed to start peer discovery service state damaged")?;
        self.daemon = Some(mdns);
        let daemon = self.daemon.as_ref().unwrap();
        let scanner = ServiceScanner {
            inner: receiver,
            daemon,
        };
        Ok(scanner)
    }
    pub async fn advertise(&mut self) -> Result<()> {
        let daemon = self.daemon.take();
        let mdns = task::spawn_blocking(move || {
            let mdns = unwrap_or_create_daemon!(daemon);
            let mut hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| {
                hostname::get()
                    .expect("Failed to get hostname")
                    .to_string_lossy()
                    .to_string()
            });
            if !hostname.len() > 15 {
                tracing::warn!(
                    "Hostname is too long to advertise and will be truncated to 15 characters"
                );
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
        self.daemon = Some(mdns);
        Ok(())
    }
    async fn stop_advertising(&mut self) -> Result<()> {
        if let Some(daemon) = &mut self.daemon {
            daemon.unregister(SERVICE_TYPE)?;
        }
        Ok(())
    }
}

// This test case might change in the future after I get QUIC implemented
#[tokio::test]
async fn mmdns_service_testdns_service_test() {
    let mut service = Service::new().await;
    service.advertise().await.unwrap();
    let mut scanner = service.discover_peers().await.unwrap();
    let hostname = hostname::get().unwrap().to_string_lossy().to_string();
    while let Some(peer) = scanner.next_peer().await {
        if peer
            .hostname
            .strip_suffix(".local.")
            .expect("Hostname must end with .local.")
            == hostname
        {
            return;
        }
    }
    panic!("Failed to find self in peer list");
}
