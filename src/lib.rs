pub mod config;
pub mod fs_watcher;
pub mod protocol;
use std::{fs::create_dir_all, path::PathBuf, sync::LazyLock};
use std::{
   fs::create_dir_all,
   path::{Path, PathBuf},
   sync::LazyLock,
};

pub use crate::config::Config;

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

pub fn start_fsync() -> ! {
   // Leak the config so it lives as long as the process does
   let config = todo!("read config");

   let worker_count = config.workers.get();
   tracing::info!("Using {worker_count} worker threads");

   let rt = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .worker_threads(worker_count)
      .build()
      .expect("Failed to build tokio runtime");
   rt.block_on(protocol::start_service(config));
   unreachable!("Service should not return");
}
