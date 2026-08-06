use quinn::VarInt;
use thiserror::Error;
#[derive(Error, Debug)]
pub enum QuicError {
   #[error(transparent)]
   Write(#[from] quinn::WriteError),
   #[error(transparent)]
   Read(#[from] quinn::ReadError),
   #[error(transparent)]
   Connection(#[from] quinn::ConnectionError),
   #[error(transparent)]
   ReadExact(#[from] quinn::ReadExactError),
   #[error(transparent)]
   SendDatagram(#[from] quinn::SendDatagramError),
}

#[derive(Error, Debug)]
pub enum Error {
   #[error(transparent)]
   Quic(QuicError),
   #[error("Discovery error {0}")]
   Discovery(String),
   #[error("Peer rejected {0}")]
   PeerRejected(String),
}
impl<T> From<T> for Error
where
   T: Into<QuicError>,
{
   fn from(err: T) -> Self {
      Self::Quic(err.into())
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
pub type Result<T, E = Error> = std::result::Result<T, E>;
