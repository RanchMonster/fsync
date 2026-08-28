use std::fs::{self, File};
use std::io::{Read, Write};
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::Arc;

use argon2::password_hash::PasswordHashString;
use serde::{Deserialize, Deserializer};
use thiserror::Error;
use tracing::instrument;

use crate::CONFIG_DIR;
use crate::protocol::{PairMode, ServiceConfigArgs};

#[derive(Error, Debug)]
pub enum ConfigError {
   #[error("Failed to read config data {0}")]
   Io(#[from] std::io::Error),
   #[error("Failed to parse config file {0}")]
   Toml(#[source] toml::de::Error),
}

type Result<T, E = ConfigError> = std::result::Result<T, E>;

const fn default_port() -> u16 {
   43127
}

const fn default_pair_mode() -> PairMode {
   PairMode::Relaxed
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

fn default_workers() -> NonZeroUsize {
   std::thread::available_parallelism().expect("Failed to get the number of available cores")
}

fn load_password_hash() -> Result<String, std::io::Error> {
   let password_file_path = CONFIG_DIR.join("password.hash");
   let mut password_file = File::open(&password_file_path)?;
   let mut password_buffer = String::new();
   password_file
      .read_to_string(&mut password_buffer)
      .expect("Failed to read password file");
   Ok(password_buffer)
}

fn deserialize_pair_mode<'de, D>(deserializer: D) -> Result<PairMode, D::Error>
where
   D: Deserializer<'de>,
{
   let s = String::deserialize(deserializer)?;
   match s.as_str() {
      "STRICT" => Ok(PairMode::Strict),
      "RELAXED" => Ok(PairMode::Relaxed),
      "PASSWORD" => {
         let loaded_password = load_password_hash().map_err(serde::de::Error::custom)?;

         let Ok(decoded_hash) = PasswordHashString::from_str(&loaded_password) else {
            fs::remove_file(CONFIG_DIR.join("password.hash"));
            return Err(serde::de::Error::custom("Password is corrupted"));
         };

         Ok(PairMode::Password(Arc::new(decoded_hash)))
      }
      "KEYONLY" => Ok(PairMode::KeyOnly),
      other => Err(serde::de::Error::custom(format!(
         "Unknown pair mode: {other}"
      ))),
   }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
   #[serde(default = "default_port")]
   pub port: u16,
   #[serde(default = "default_address")]
   pub address: String,
   #[serde(default = "default_pair_mode")]
   #[serde(deserialize_with = "deserialize_pair_mode")]
   pub pair_mode: PairMode,
   #[serde(default = "default_hostname")]
   pub hostname: String,

   pub sync_dirs: Vec<String>,

   #[serde(default = "default_workers")]
   pub workers: NonZeroUsize,
}

pub fn create_config_file() {
   let config_file_path = CONFIG_DIR.join("config.toml");

   assert!(!config_file_path.exists());

   let mut file = File::create(config_file_path).expect("Failed to create config file");

   write_default_config(&mut file);
}

impl Into<ServiceConfigArgs> for Config {
   fn into(self) -> ServiceConfigArgs {
      ServiceConfigArgs {
         address: self.address,
         port: self.port,
         sync_dirs: self.sync_dirs,
         pair_mode: self.pair_mode,
         hostname: self.hostname,
      }
   }
}

/// Writes the default config to the config file
/// Precondition: Config file exists
fn write_default_config(config_file: &mut File) {
   const DEFAULT_CONFIG: &str = r#"
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
    "#;

   let result = config_file.write(DEFAULT_CONFIG.as_bytes());

   if let Err(error) = result {
      if error.kind() == std::io::ErrorKind::PermissionDenied {
         eprintln!("You know what you did.");
         std::process::exit(0);
      } else {
         panic!("Failed to write config file: {error}");
      }
   }
}

#[instrument]
pub fn read_config_file() -> Result<Config> {
   use ConfigError::Toml;
   let config_file_path = CONFIG_DIR.join("config.toml");

   let mut config_file = File::open(config_file_path)?;

   let mut config_contents = String::new();
   config_file
      .read_to_string(&mut config_contents)
      .expect("Failed to read config file");

   let config = toml::from_str(&config_contents).map_err(Toml)?;

   Ok(config)
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
      let config = read_config_file().expect("Failed to read config file");
      assert_eq!(config.address, "0.0.0.0");
      assert_eq!(config.port, 43127);
      assert_eq!(config.sync_dirs, Vec::<String>::new());
      assert_eq!(config.pair_mode, PairMode::Relaxed);
      assert_eq!(config.hostname, "fsync");
   }
}
