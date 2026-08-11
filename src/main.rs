use blake3::Hash;
mod config;
mod fs_watcher;
mod protocol;

#[cfg(test)]
use std::env::temp_dir;
use std::{
   env::temp_dir,
   fs::create_dir_all,
   path::{Path, PathBuf},
   sync::LazyLock,
};

/// The directory where the configuration files are stored.
/// Also handles creating the directory if it doesn't exist.
pub static CONFIG_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
   #[cfg(test)]
   {
      let path = temp_dir().join(".fsync");
      if !path.exists() {
         create_dir_all(&path).expect("Failed to create test config dir.");
      }
      return path;
   }
   #[cfg(not(test))]
   {
      let path = dirs::home_dir().unwrap().join(".fsync");
      if !path.exists() {
         create_dir_all(&path).expect("Failed to create config dir.");
      }
      return path;
   }
});

#[tokio::main]
async fn main() {}

pub async fn hash_file(_path: &Path) -> Result<Hash, std::io::Error> {
   todo!("hash the file")
}
