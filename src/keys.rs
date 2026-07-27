use rcgen::{KeyPair, PKCS_ED25519};
use std::fs::{read_to_string, write};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::CONFIG_DIR;

pub fn get_signing_key() -> KeyPair {
   let private_key_path = CONFIG_DIR.join("key.private");
   if !private_key_path.exists() {
      let key_pair = generate_ed25519_keypair();
      assert!(
         key_pair.algorithm() == &PKCS_ED25519,
         "Key algorithm is not ED25519"
      );
      store_key_pair(&key_pair);
      return key_pair;
   }

   assert!(private_key_path.is_file());

   let file_contents = read_to_string(private_key_path).expect("Failed to read private key file");
   KeyPair::from_pem(&file_contents).expect("Failed to parse private key")
}

/// Generates a key pair for signing and returns the private key.
pub fn generate_ed25519_keypair() -> KeyPair {
   KeyPair::generate_for(&PKCS_ED25519).expect("Failed to generate key pair")
}

pub fn store_key_pair(key_pair: &KeyPair) {
   let private_key_path = CONFIG_DIR.join("key.private");
   let key_pem = key_pair.serialize_pem();
   #[cfg(unix)]
   {
      write(&private_key_path, "").expect("Failed to write private key");
      assert!(&private_key_path.exists());
      &private_key_path
         .metadata()
         .expect("Failed to get metadata")
         .permissions()
         .set_mode(0o600);
   }
   write(private_key_path, key_pem).expect("Failed to write private key");
}

#[cfg(test)]
mod tests {
   use super::*;

   /// Clears key storage from the filesystem.
   pub fn clear_keys() {
      let private_key_path = CONFIG_DIR.join("key.private");
      assert!(private_key_path.exists());
      assert!(private_key_path.is_file());
      std::fs::remove_file(private_key_path).expect("Failed to remove private key");
   }

   #[test]
   fn test_generate_ed25519_keypair() {
      let key_pair = generate_ed25519_keypair();
      assert!(key_pair.algorithm() == &PKCS_ED25519);
   }

   #[test]
   fn test_storage_and_retrieval_of_key_pair() {
      let key_pair = generate_ed25519_keypair();
      store_key_pair(&key_pair);
      let retrieved_key_pair = get_signing_key();
      clear_keys();
      assert_eq!(
         key_pair.public_key_raw(),
         retrieved_key_pair.public_key_raw()
      );
   }

   #[test]
   fn test_clear_key_pair() {
      let key_pair = generate_ed25519_keypair();
      store_key_pair(&key_pair);
      clear_keys();
      let retrieved_key_pair = get_signing_key();
      assert_ne!(
         key_pair.public_key_raw(),
         retrieved_key_pair.public_key_raw()
      );
   }
}
