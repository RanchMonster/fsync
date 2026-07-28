use thiserror::Error;
#[derive(Error, Debug)]
pub enum Error {
   /// Failed to start the service
   #[error("Failed to start the service")]
   ServiceStartError,
   /// Failed to stop the service
   #[error("Failed to stop the service gracefully")]
   ServiceStopError,
   #[error(
      "Local add and discovery error please ensure you are not running another instance of fsync or that this device is capable of being discovered"
   )]
   MdnsErro(#[from] mdns_sd::Error),
   /// Peer not found
   #[error("Peer not found")]
   PeerNotFound,
   /// Rejected by a fellow peer
   #[error("Rejected by a fellow peer")]
   PeerRejected,
   /// Malformed peer
   #[error("Invalid peer information")]
   InvalidPeer(mdns_sd::ResolvedService),
}
pub type Result<T> = std::result::Result<T, Error>;
