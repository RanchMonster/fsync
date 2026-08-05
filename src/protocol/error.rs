use quinn::VarInt;
use thiserror::Error;
macro_rules! impl_from_quinn {
   ($err:ty) => {
      impl From<$err> for Error {
         fn from(err: $err) -> Self {
            Error::Quic(err.into())
         }
      }
   };
}
#[derive(Error, Debug)]
pub enum Error {
   #[error(
      "Local add and discovery error please ensure you are not running another instance of fsync or that this device is capable of being discovered"
   )]
   Mdns(#[from] mdns_sd::Error),
   /// Peer was rejected due to a reason
   #[error("Peer was rejected due to {0}")]
   PeerRejected(String),
   /// Io error
   #[error("IO error")]
   Io(#[from] std::io::Error),
   #[error("QUIC error {0}")]
   Quic(Box<dyn std::error::Error + Send + Sync>),
   #[error("Certificate error: {0}")]
   Rcgen(#[from] rcgen::Error),
   #[error("Parse data error: {0}")]
   ParseData(String),
}
// The fact that quinn has this many error types is a bit of a pain and kind of annoying
// Why do they not implement a Enum or at least a trait for this?
// I will likely be submitting a PR to fix this at some point to quinn
impl_from_quinn!(quinn::ConnectionError);
impl_from_quinn!(quinn::SendDatagramError);
impl_from_quinn!(quinn::ReadError);
impl_from_quinn!(quinn::WriteError);
impl_from_quinn!(quinn::ReadToEndError);
impl_from_quinn!(quinn::ReadExactError);
#[repr(u32)]
pub enum CloseCode {
   InvalidProtocol = 1,
   HandshakeFailure = 2,
   InternalError = 3,
   Shutdown = 4,
   AuthenticationFailure = 5,
   // add more as needed
}
impl Into<VarInt> for CloseCode {
   fn into(self) -> VarInt {
      VarInt::from_u32(self as u32)
   }
}
pub type Result<T> = std::result::Result<T, Error>;
