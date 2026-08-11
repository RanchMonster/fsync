use std::fs::File;
use std::io::{Read, Write};
use std::sync::Arc;

use argon2::password_hash::PasswordHashString;
use serde::Deserialize;

use crate::CONFIG_DIR;
use crate::protocol::{PairMode, ServiceConfigArgs};

const fn default_port() -> u16 {
   43127
}

fn default_pair_mode() -> String {
   "RELAXED".to_string()
}

fn default_address() -> String {
   "0.0.0.0".to_string()
}

fn default_hostname() -> String {
   let mut name = hostname::get()
      .expect("Failed to get hostname")
      .to_string_lossy()
      .to_string();
   if name.len() > 15 {
      tracing::warn!("Hostname is longer than 15 characters, truncating");
      name.truncate(15);
   }
   name
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigIntermediary {
   #[serde(default = "default_port")]
   pub port: u16,
   #[serde(default = "default_address")]
   pub address: String,
   #[serde(default = "default_pair_mode")]
   pub pair_mode: String,
   #[serde(default = "default_hostname")]
   pub hostname: String,

   pub password: Option<String>,
   pub sync_dirs: Vec<String>,
}

pub fn create_config_file() {
   let config_file_path = CONFIG_DIR.join("config.toml");

   assert!(!config_file_path.exists());

   let mut file = File::create(config_file_path).expect("Failed to create config file");

   write_default_config(&mut file);
}

impl Into<ServiceConfigArgs> for ConfigIntermediary {
   fn into(self) -> ServiceConfigArgs {
      let pair_mode = match self.pair_mode.as_str() {
         "STRICT" => PairMode::Strict,
         "RELAXED" => PairMode::Relaxed,
         "PASSWORD" => {
            let password = self
               .password
               .expect("Password is required for password pairing");
            // Accept either a PHC hash string or a plain password.
            let hash = PasswordHashString::new(password.as_str()).unwrap_or_else(|_| {
               let salt = argon2::password_hash::SaltString::generate(&mut rand_core::OsRng);
               let phc = argon2::password_hash::PasswordHasher::hash_password(
                  &argon2::Argon2::default(),
                  password.as_bytes(),
                  &salt,
               )
               .expect("Failed to hash password")
               .to_string();
               PasswordHashString::new(&phc).expect("Failed to create password hash")
            });
            PairMode::Password(Arc::new(hash))
         }
         "KEYONLY" => PairMode::KeyOnly,
         other => panic!("Unknown pair mode: {other}"),
      };

      ServiceConfigArgs {
         address: self.address,
         port: self.port,
         sync_dirs: self.sync_dirs,
         pair_mode: pair_mode,
         hostname: self.hostname,
      }
   }
}

/// Writes the default config to the config file
/// Precondition: Config file exists
fn write_default_config(config_file: &mut File) {
   let default_config = r#"
        # The address to listen on
        address = "0.0.0.0"
        # The port to listen on
        port = 43127
        # The directories to sync (List of strings)
        sync_dirs = []
        # The pairing mode to use (relaxed, strict, password, keyonly)
        pair_mode = "RELAXED"
        # The hostname to advertise
        hostname = "fsync"
        # The password to use for password pairing, only used if pair_mode is password
        # password = 
    "#;

   let result = config_file.write(default_config.as_bytes());

   if let Err(error) = result {
      if error.kind() == std::io::ErrorKind::PermissionDenied {
         eprintln!("You know what you did.");
         std::process::exit(0);
      } else {
         panic!("Failed to write config file: {error}");
      }
   }
}

fn read_config_file() -> ConfigIntermediary {
   let config_file_path = CONFIG_DIR.join("config.toml");

   let mut config_file = File::open(config_file_path).expect("Failed to open config file");

   let mut config_contents = String::new();
   config_file
      .read_to_string(&mut config_contents)
      .expect("Failed to read config file");

   toml::from_str(&config_contents).expect("Failed to read config file")
}

#[cfg(test)]
mod tests {
   use super::*;
   use std::fs;

   #[test]
   fn test_config_file_creation_defaults_and_reading() {
      let config_file_path = CONFIG_DIR.join("config.toml");
      let _ = fs::remove_file(&config_file_path);

      // creation of the config file in the test dir
      assert!(!config_file_path.exists());
      create_config_file();
      assert!(config_file_path.exists());

      // writing of the default config
      let contents = fs::read_to_string(&config_file_path).expect("Failed to read config file");
      assert!(contents.contains("address = \"0.0.0.0\""));
      assert!(contents.contains("port = 43127"));
      assert!(contents.contains("sync_dirs = []"));
      assert!(contents.contains("pair_mode = \"RELAXED\""));
      assert!(contents.contains("hostname = \"fsync\""));

      // reading from the config object
      let config = read_config_file();
      assert_eq!(config.address, "0.0.0.0");
      assert_eq!(config.port, 43127);
      assert_eq!(config.sync_dirs, Vec::<String>::new());
      assert_eq!(config.pair_mode, "RELAXED");
      assert_eq!(config.hostname, "fsync");
      assert_eq!(config.password, None);
   }
}
