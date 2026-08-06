use std::fs::write;

use crate::CONFIG_DIR;

/// Writes the default config to the config file
/// Precondition: Config file exists
fn write_default_config() {
   let default_config = r#"
        # The address to listen on
        address = "0.0.0.0"
        # The port to listen on
        port = 6969
        # The directories to sync (List of strings)
        sync_dirs = []
        # The pairing mode to use (relaxed, strict)
        pair_mode = "relaxed"
        # The hostname to advertise
        hostname = "fsync"
    "#;

   let mut config_file_path = CONFIG_DIR.clone();
   config_file_path.push("config.toml");

   assert!(config_file_path.exists(), "Config file does not exist");

   let result = write(config_file_path, default_config);

   if let Err(error) = result {
      match error.kind() {
         std::io::ErrorKind::PermissionDenied => {
            eprintln!("You know what you did.");
            std::process::exit(0);
         }
         _ => {
            panic!("Failed to write config file: {error}");
         }
      }
   }
}
