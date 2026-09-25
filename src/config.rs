use std::collections::HashMap;
use std::fs::File;
use std::io::{Error as IoError, Read, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::instrument;

use crate::CONFIG_DIR;

const FILE_START_POSITION: u64 = 0;

#[derive(Error, Debug)]
pub enum ConfigError {
   #[error("Failed to read config file {0}")]
   FailedToReadConfig(#[source] IoError),

   #[error("Failed to create config file {0}")]
   FailedToCreateConfig(#[source] IoError),

   #[error("Failed to read password hash file {0}")]
   FailedToReadPasswordHash(#[source] IoError),

   #[error("Stored password is corrupted")]
   PasswordIsCorrupted,

   #[error("Unknown pair mode {0}")]
   UnknownPairMode(String),

   #[error("Failed to parse config file {0}")]
   Toml(#[source] toml::de::Error),
}

type Result<T, E = ConfigError> = std::result::Result<T, E>;

const fn default_port() -> u16 {
   43127
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
   #[serde(default = "default_port")]
   pub port: u16,

   #[serde(default = "default_address")]
   pub address: String,

   #[serde(default = "default_hostname")]
   pub hostname: String,

   pub sync_dirs: HashMap<String, PathBuf>,

   #[serde(default = "default_workers")]
   pub workers: NonZeroUsize,
}
impl Default for Config {
   fn default() -> Self {
      Self {
         port: default_port(),
         address: default_address(),
         hostname: default_hostname(),
         sync_dirs: HashMap::new(),
         workers: default_workers(),
      }
   }
}
impl Config {
   /// Reads the config file from the given directory
   /// # Preconditions:
   /// 1. The config dir must exist
   /// 2. The config dir must be a directory
   /// # Errors
   /// Returns [`ConfigError::FailedToReadConfig`] if the config file cannot be read
   /// Returns [`ConfigError::Toml`] if the config file contents are not valid TOML
   /// Returns [`ConfigError::UnknownPairMode`] if the pair mode is not known
   /// Returns [`ConfigError::PasswordIsCorrupted`] if the pair mode is [`PairMode::Password`] and the password hash file is corrupted
   ///
   /// #Example usage
   /// ```rust
   /// use fsync::Config;
   /// use std::path::{Path, PathBuf};
   /// use std::fs;
   /// fn example() {
   ///  let config_dir = std::env::home_dir().expect("Failed to get home dir").join(".config/fsync");
   ///  
   ///  if !config_dir.exists() {
   ///      fs::create_dir_all(&config_dir).expect("Failed to create config dir");
   ///
   ///  }else if !config_dir.is_dir() {
   ///      fs::remove_dir_all(&config_dir).expect("Failed to remove config dir");
   ///      fs::create_dir_all(&config_dir).expect("Failed to create config dir");
   ///  }
   ///
   ///  let config = Config::load().expect("Failed to load config");
   /// }
   /// ```
   #[instrument]
   pub fn load() -> Result<Self> {
      let config_dir = &(*CONFIG_DIR);
      use ConfigError::{FailedToReadConfig, Toml};

      assert!(config_dir.is_dir(), "Config dir must be a directory");
      assert!(config_dir.exists(), "Config dir must exist");

      let config_file_path = config_dir.join("config.toml");
      let mut config_file = File::open(&config_file_path).map_err(FailedToReadConfig)?;

      let mut config_contents = String::new();
      config_file
         .read_to_string(&mut config_contents)
         .map_err(FailedToReadConfig)?;

      toml::from_str(&config_contents).map_err(Toml)
   }

   /// Creates the default config file in the given directory
   /// # Preconditions
   /// 1. The config dir must exist
   /// 2. The config dir must be a directory
   /// # Errors
   /// Returns [`ConfigError::FailedToCreateConfig`] if the config file cannot be created
   /// # Example usage
   /// ```rust
   /// use fsync::Config;
   /// use std::path::{Path, PathBuf};
   /// use std::fs;
   /// fn example() {
   ///  let config_dir = std::env::home_dir().expect("Failed to get home dir").join(".config/fsync");
   ///
   ///  if !config_dir.exists() {
   ///      fs::create_dir_all(&config_dir).expect("Failed to create config dir");
   ///
   ///  }else if !config_dir.is_dir() {
   ///      fs::remove_dir_all(&config_dir).expect("Failed to remove config dir");
   ///      fs::create_dir_all(&config_dir).expect("Failed to create config dir");
   ///  }
   ///
   ///  Config::create_default_config().expect("Failed to create default config");
   /// }
   /// ```
   #[instrument]
   pub fn create_default_config() -> Result<Self> {
      let config_dir = &(*CONFIG_DIR);
      use ConfigError::FailedToCreateConfig;
      assert!(config_dir.is_dir(), "Config dir must be a directory");
      assert!(config_dir.exists(), "Config dir must exist");

      let config_file_path = config_dir.join("config.toml");
      assert!(!config_file_path.exists(), "Config file already exists");

      let mut config_file = File::create(&config_file_path).map_err(FailedToCreateConfig)?;
      let default_config =
         toml::to_string(&Config::default()).expect("Failed to serialize default config");

      config_file
         .write_all(default_config.as_bytes())
         .map_err(FailedToCreateConfig)?;

      let config = Self::load().expect("Failed to load config we just created");

      Ok(config)
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   

   #[test]
   fn test_default_config_creation_and_reading() {
      let config = Config::create_default_config().expect("Failed to create default config");
      assert_eq!(config.port, 43127);
      assert_eq!(config.address, "0.0.0.0");
      assert_eq!(config.hostname, hostname::get().unwrap().to_string_lossy());
   }
}
