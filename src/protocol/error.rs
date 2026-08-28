use quinn::VarInt;
use thiserror::Error;

/// Errors raised by the QUIC transport layer.
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

/// The reason a connection is closed, encoded as a QUIC application error
/// code.
#[repr(u32)]
pub enum CloseCode {
   InvalidProtocol = 1,
   HandshakeFailure = 2,
   InternalError = 3,
   Shutdown = 4,
   AuthenticationFailure = 5,
   // add more as needed
}
impl From<CloseCode> for VarInt {
   fn from(val: CloseCode) -> Self {
      VarInt::from_u32(val as u32)
   }
}
