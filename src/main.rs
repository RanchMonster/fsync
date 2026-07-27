use blake3::Hash;
mod fs_watcher;
mod keys;
mod protocol;

use fs_watcher::WatcherThread;
use std::{
   env::temp_dir,
   fs::create_dir_all,
   path::{Path, PathBuf},
   sync::LazyLock,
};

/// The directory where the configuration files are stored.
/// Also handles creating the directory if it doesn't exist.
pub static CONFIG_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
   if cfg!(test) {
      let path = temp_dir().join(".fsync");
      if !path.exists() {
         create_dir_all(&path).expect("Failed to create test config dir.");
      }
      path
   } else {
      let path = dirs::home_dir().unwrap().join(".fsync");
      if !path.exists() {
         create_dir_all(&path).expect("Failed to create config dir.");
      }
      path
   }
});

#[tokio::main]
async fn main() {}

pub async fn hash_file(path: &Path) -> Result<Hash, std::io::Error> {
   todo!("hash the file")
}
