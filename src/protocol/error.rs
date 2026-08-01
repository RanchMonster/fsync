use quinn::{ConnectionError, ReadError, SendDatagramError, VarInt, WriteError};
use thiserror::Error;
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
impl From<ReadError> for Error {
   fn from(err: quinn::ReadError) -> Self {
      Error::Quic(err.into())
   }
}
impl From<WriteError> for Error {
   fn from(err: quinn::WriteError) -> Self {
      Error::Quic(err.into())
   }
}
impl From<ConnectionError> for Error {
   fn from(err: ConnectionError) -> Self {
      Error::Quic(err.into())
   }
}
impl From<SendDatagramError> for Error {
   fn from(err: SendDatagramError) -> Self {
      Error::Quic(err.into())
   }
}
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
