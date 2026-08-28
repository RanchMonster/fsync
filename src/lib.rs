pub mod config;
pub mod fs_watcher;
pub mod protocol;
pub use crate::config::Config;
use std::{fs::create_dir_all, path::PathBuf, sync::LazyLock};

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
   let config = Box::leak(Box::new(Config::load().expect("Failed to load config")));

   let worker_count = config.workers.get();
   tracing::info!("Using {worker_count} worker threads");

   let rt = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .max_blocking_threads(worker_count)
      .thread_name("fsync-worker")
      .build()
      .expect("Failed to build tokio runtime");
   rt.block_on(protocol::start_service(config));

   unreachable!("Service should not return");
}
