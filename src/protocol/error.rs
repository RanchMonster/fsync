use thiserror::Error;
#[derive(Error, Debug)]
pub enum Error {
   /// Failed to start the service
   #[error("Failed to start the service")]
   ServiceStart,
   /// Failed to stop the service
   #[error("Failed to stop the service gracefully")]
   ServiceStop,
   #[error(
      "Local add and discovery error please ensure you are not running another instance of fsync or that this device is capable of being discovered"
   )]
   Mdns(#[from] mdns_sd::Error),
   /// Peer not found
   #[error("Peer not found")]
   PeerNotFound,
   /// Rejected by a fellow peer
   #[error("Rejected by a fellow peer")]
   PeerRejected,
   /// Malformed peer
   #[error("Invalid peer information")]
   InvalidPeer(mdns_sd::ResolvedService),
   /// Network error
   #[error("Network error")]
   Io(#[from] std::io::Error),
   #[error("QUIC error")]
   Quic(#[from] quinn::ConnectionError),
   #[error("Invalid key hash")]
   InvalidKeyHash,
   #[error("Certificate error: {0}")]
   Rcgen(#[from] rcgen::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
