use std::fs::File;
use std::io::{Read, Write};
use std::sync::{Arc, LazyLock};

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
   pub sync_dirs: Option<Vec<String>>,
}

pub fn create_config_file() {
   let config_file_path = CONFIG_DIR.join("config.talm");

   assert!(!config_file_path.exists());

   let mut file = File::create(config_file_path).expect("Failed to create config file");

   write_default_config(&mut file);
}

impl Into<ServiceConfigArgs> for ConfigIntermediary {
   fn into(self) -> ServiceConfigArgs {
      let pair_mode = match self.pair_mode.as_str() {
         "STRICT" => PairMode::Strict,
         "RELAXED" => PairMode::Relaxed,
         "PASSWORD" => PairMode::Password(Arc::new(
            PasswordHashString::new(
               self
                  .password
                  .expect("Password is required for password pairing")
                  .as_str(),
            )
            .expect("Failed to create password hash"),
         )),
         "KEYONLY" => PairMode::KeyOnly,
         other => panic!("Unknown pair mode: {other}"),
      };

      ServiceConfigArgs {
         address: self.address,
         port: self.port,
         sync_dirs: self.sync_dirs.expect("Sync dirs are required"),
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
        port = 6969
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
   let config_file_path = CONFIG_DIR.join("config.talm");

   let mut config_file = File::open(config_file_path).expect("Failed to open config file");

   let mut config_contents = String::new();
   config_file
      .read_to_string(&mut config_contents)
      .expect("Failed to read config file");

   toml::from_str(&config_contents).expect("Failed to read config file")
}
