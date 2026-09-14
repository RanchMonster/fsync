use quinn::VarInt;
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
