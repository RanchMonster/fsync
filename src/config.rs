use std::collections::HashMap;
use std::fs::File;
use std::io::{Error as IoError, Read, Seek, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use argon2::password_hash::PasswordHashString;
use serde::Deserialize;
use thiserror::Error;
use tracing::instrument;

use crate::CONFIG_DIR;
use crate::protocol::PairMode;

const FILE_START_POSITION: u64 = 0;

const DEFAULT_CONFIG: &str = r#"
        # The address to listen on
        address = "0.0.0.0"
        # The port to listen on
        port = 43127
        # The directories to sync (name -> path)
        sync_dirs = { }
        # The pairing mode to use (relaxed, strict, password, keyonly)
        pair_mode = "RELAXED"
        # The hostname to advertise
        hostname = "fsync"
    "#;
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

fn default_workers() -> NonZeroUsize {
   std::thread::available_parallelism().expect("Failed to get the number of available cores")
}

#[derive(Debug, Deserialize)]
struct ConfigIntermediater {
   #[serde(default = "default_port")]
   port: u16,

   #[serde(default = "default_address")]
   address: String,

   #[serde(default = "default_pair_mode")]
   pair_mode: String,

   #[serde(default = "default_hostname")]
   hostname: String,

   #[serde(default = "default_workers")]
   workers: NonZeroUsize,

   sync_dirs: HashMap<String, PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Config {
   pub port: u16,
   pub address: String,
   pub pair_mode: PairMode,
   pub hostname: String,
   pub sync_dirs: HashMap<String, PathBuf>,
   pub workers: NonZeroUsize,
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

      let ConfigIntermediater {
         port,
         address,
         hostname,
         workers,
         sync_dirs,
         pair_mode,
      } = toml::from_str(&config_contents).map_err(Toml)?;

      let pair_mode = convert_to_pair_mode(&pair_mode, config_dir)?;

      Ok(Config {
         port,
         address,
         pair_mode,
         hostname,
         workers,
         sync_dirs,
      })
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
      config_file
         .write_all(DEFAULT_CONFIG.as_bytes())
         .map_err(FailedToCreateConfig)?;

      let config = Self::load().expect("Failed to load config we just created");

      Ok(config)
   }
}

// --- utility functions ---

fn load_password_hash(password_hash_file: &mut File) -> Result<PasswordHashString> {
   use ConfigError::{FailedToReadPasswordHash, PasswordIsCorrupted};
   // This operation is a slow syscall, also really this like won't ever happen unless we make it
   // happen in the first place
   debug_assert_eq!(
      password_hash_file
         .stream_position()
         .expect("Failed to get password hash file position"),
      FILE_START_POSITION
   );

   let mut password_buffer = String::new();
   password_hash_file
      .read_to_string(&mut password_buffer)
      .map_err(FailedToReadPasswordHash)?;
   // So I wanted to pass the error up the stack but apparently argon2 doesn't implement error correctly or something so we aren't going to log it we can change it later if needed
   PasswordHashString::from_str(password_buffer.trim()).map_err(|_| PasswordIsCorrupted)
}

fn convert_to_pair_mode(pair_mode: &str, config_dir: &Path) -> Result<PairMode, ConfigError> {
   use ConfigError::FailedToReadPasswordHash;

   assert!(!pair_mode.is_empty(), "Pair mode shouldn't be empty");
   assert!(
      pair_mode.is_ascii(),
      "Pair mode should be ascii characters only"
   );

   use ConfigError::UnknownPairMode;
   use PairMode::*;
   match pair_mode {
      "STRICT" => Ok(Strict),
      "RELAXED" => Ok(Relaxed),
      "PASSWORD" => {
         let mut password_hash_file =
            File::open(config_dir.join("password.hash")).map_err(FailedToReadPasswordHash)?;

         let loaded_password = load_password_hash(&mut password_hash_file)?;
         Ok(Password(Arc::new(loaded_password)))
      }
      "KEYONLY" => Ok(KeyOnly),
      other => Err(UnknownPairMode(other.to_string())),
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   use std::fs;
   fn setup_config_dir() -> PathBuf {
      let path = std::env::temp_dir().join("fsync_test_config_dir");
      unsafe { std::env::set_var("FSYNC_CONFIG_DIR", path.clone()) };
      let _ = fs::remove_dir_all(&path); // If the directory exists it will be removed
      path
   }
   #[test]
   fn test_default_config_creation_and_reading() {
      setup_config_dir();
      let config = Config::create_default_config().expect("Failed to create default config");
      assert_eq!(config.port, 43127);
      assert_eq!(config.address, "0.0.0.0");
      assert_eq!(config.pair_mode, PairMode::Relaxed);
      assert_eq!(config.hostname, "fsync");
   }
}
