use std::fs::File;
use std::io::Write;
use std::sync::Arc;

use argon2::password_hash::PasswordHashString;
use serde::Serialize;

use crate::CONFIG_DIR;
use crate::protocol::{PairMode, ServiceConfigArgs};

const DEFAULT_PORT: u16 = 43127;
const DEFAULT_PAIR_MODE: PairMode = PairMode::Relaxed;
const DEFAULT_ADDRESS: &str = "0.0.0.0";

#[allow(non_snake_case)]
fn GET_DEFAULT_HOSTNAME() -> String {
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

#[derive(Debug, Clone, Serialize)]
pub struct ConfigIntermediary {
   pub address: Option<String>,
   pub port: Option<u16>,
   pub sync_dirs: Option<Vec<String>>,
   pub pair_mode: Option<String>,
   pub hostname: Option<String>,
   pub password: Option<String>,
}

pub fn create_config_file() {
   let config_file_path = CONFIG_DIR.join("config.talm");

   assert!(!config_file_path.exists());

   let mut file = File::create(config_file_path).expect("Failed to create config file");

   write_default_config(&mut file);
}

impl Into<ServiceConfigArgs> for ConfigIntermediary {
   fn into(self) -> ServiceConfigArgs {
      let pair_mode = self.pair_mode.unwrap_or("RELAXED".to_string());
      let pair_mode = match pair_mode.as_str() {
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
         address: self.address.unwrap_or(DEFAULT_ADDRESS.to_string()),
         port: self.port.unwrap_or(DEFAULT_PORT),
         sync_dirs: self.sync_dirs.expect("Sync dirs are required"),
         pair_mode: pair_mode,
         hostname: self.hostname.unwrap_or_else(GET_DEFAULT_HOSTNAME),
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
        password = "password"
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
