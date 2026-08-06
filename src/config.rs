use std::fs::File;
use std::io::Write;

use crate::CONFIG_DIR;

pub fn create_config_file() {
   let config_file_path = CONFIG_DIR.join("config.talm");

   assert!(!config_file_path.exists());

   let mut file = File::create(config_file_path).expect("Failed to create config file");

   write_default_config(&mut file);
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
        # The pairing mode to use (relaxed, strict)
        pair_mode = "relaxed"
        # The hostname to advertise
        hostname = "fsync"
    "#;

   let result = config_file.write(default_config.as_bytes());

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
