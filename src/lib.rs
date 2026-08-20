pub mod fs_watcher;
pub mod protocol;
pub mod system_utils;
use blake3::Hash;
use std::{
   fs::create_dir_all,
   path::{Path, PathBuf},
   sync::LazyLock,
};

/// The directory where the configuration files are stored.
/// Also handles creating the directory if it doesn't exist.
///
/// The location can be overridden with the `FSYNC_CONFIG_DIR` environment
/// variable, which tests use to avoid touching the real config directory.
pub static CONFIG_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
   let path = std::env::var_os("FSYNC_CONFIG_DIR")
      .map(PathBuf::from)
      .unwrap_or_else(|| {
         dirs::home_dir()
            .expect("Failed to find home directory")
            .join(".fsync")
      });
   if !path.exists() {
      create_dir_all(&path).expect("Failed to create config dir.");
   }
   path
});

pub async fn hash_file(_path: &Path) -> Result<Hash, std::io::Error> {
   todo!("hash the file")
}
