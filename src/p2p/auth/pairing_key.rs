use std::{
   fmt::Display,
   fs::{File, remove_file},
   io::{Read, Write},
   str::FromStr,
   time::Duration,
};

use hex::FromHexError;
use rand::random;
use tokio::{task, time::sleep};

use super::{AuthError, Result};
use crate::CACHE_DIR;
const PAIRING_KEY_TIME_TO_LIVE: Duration = Duration::from_mins(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PairingKey([u8; 32]);
impl Display for PairingKey {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(f, "{}", hex::encode(self.0))
   }
}
impl FromStr for PairingKey {
   type Err = FromHexError;
   fn from_str(line: &str) -> std::result::Result<Self, Self::Err> {
      use FromHexError::InvalidStringLength;
      let key = hex::decode(line)?
         .try_into()
         .map_err(|_| InvalidStringLength)?;
      Ok(PairingKey(key))
   }
}
impl From<[u8; 32]> for PairingKey {
   fn from(key: [u8; 32]) -> Self {
      PairingKey(key)
   }
}

async fn key_ttl_helper_task() {
   sleep(PAIRING_KEY_TIME_TO_LIVE).await;
   task::spawn_blocking(|| {
      let path = CACHE_DIR.join("pairing_key");
      if path.exists() {
         remove_file(path).expect("Failed to remove pairing key file");
      }
   });
}

/// Generates a new pairing key and saves it to the cache directory.
/// Returns [`std::io::Error`] if the key cannot be generated or saved.
/// # Note:
/// This function should only be called in the cli and not was the service is running.
/// ```
/// use fsync::p2p::auth::generate_pairing_key;
/// fn cli_function(){
///     let pairing_key = generate_pairing_key().expect("Failed to generate pairing key");
///     println!("Pairing key: {}", pairing_key);
///     
/// }
pub fn generate_pairing_key() -> Result<PairingKey, std::io::Error> {
   let key = random::<[u8; 32]>();
   let mut file = File::options()
      .create(true)
      .truncate(true)
      .write(true)
      .open(CACHE_DIR.join("pairing_key"))?;
   file.write_all(&key)?;
   tokio::spawn(key_ttl_helper_task());
   Ok(PairingKey(key))
}

/// Loads the pairing key from the cache directory.
/// Returns [`AuthError::PairingKeyLoadFailed`] if the key cannot be loaded.
/// Returns [`None`] if the key does not exist.
/// # Note:
/// This function should be called only by the auth module and should be asyncified.
/// ```no_run
/// async fn validate_pairing_request(given_key: &PairingKey)->Result<(),Box<dyn std::error::Error>> {
///  let pairing_key = asyncify!(load_pairing_key);
///  if let Some(pairing_key) = pairing_key && pairing_key == *given_key {
///     return Ok(());
///  }
///  Err("Invalid pairing key")
///
/// }
pub fn load_pairing_key() -> Result<Option<PairingKey>> {
   use AuthError::PairingKeyLoadFailed;

   let path = CACHE_DIR.join("pairing_key");
   if !path.exists() {
      return Ok(None);
   }

   let mut file = File::open(&path).map_err(PairingKeyLoadFailed)?;
   let mut key = [0; 32];
   file.read_exact(&mut key).map_err(PairingKeyLoadFailed)?;

   Ok(Some(PairingKey(key)))
}
