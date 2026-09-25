pub mod local;

use quinn::{Connecting, Endpoint};

use crate::p2p::PeerId;

pub trait NetworkMember: Send + Sync + 'static {
   fn id(&self) -> PeerId;
   fn name(&self) -> &str;
}

/// Errors that can occur during a fsync network connection.
pub trait NetworkError: std::error::Error + Send + Sync + 'static {}
impl<T> NetworkError for T where T: std::error::Error + Send + Sync + 'static {}

pub trait Network<Member: NetworkMember, Error: NetworkError>: Send + Sync + 'static {
   fn advertise(&mut self) -> Result<(), Error>;
   fn stop_advertising(&mut self) -> Result<(), Error>;
   async fn connect(&self, endpoint: &Endpoint, member: Member) -> Result<Connecting, Error>;
   fn list_members(&self) -> Result<Vec<Member>, Error>;
   async fn wait_for_updates(&mut self) -> Result<Vec<Member>, Error>;
   fn network_name(&self) -> &str;
}
