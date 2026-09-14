mod config;
pub mod fs_watcher;
pub mod p2p;
pub use crate::config::Config;

use std::{fs::create_dir_all, path::PathBuf, sync::LazyLock};

#[cfg(debug_assertions)]
use std::fs::remove_dir_all;

/// The asyncfiy macro is a convenience macro for wrapping a sync function in a tokio blocing task
/// This is useful for testing and for making the code more readable
#[macro_export]
macro_rules! asyncify {

   ($func:expr) => {{
      tokio::task::spawn_blocking(move || $func)
         .await
         .expect("Thread panicked unexpectedly")
   }};

   ($func:expr, $($arg:expr),*) => {{
      tokio::task::spawn_blocking(move || $func($($arg),*))
         .await
         .expect("Thread panicked unexpectedly")
   }};
}

/// The directory where the configuration files are stored.
/// Also handles creating the directory if it doesn't exist.
///
/// The location can be overridden with the `FSYNC_CONFIG_DIR` environment
/// variable, which tests use to avoid touching the real config directory.
pub static CONFIG_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
   #[cfg(debug_assertions)]
   {
      let process_id = std::process::id();
      let debug_dir = std::env::temp_dir().join(format!("fsync-config-{process_id}"));
      if debug_dir.exists() {
         remove_dir_all(&debug_dir).expect("Failed to remove old config dir.");
      }
      create_dir_all(&debug_dir).expect("Failed to create config dir.");
      return debug_dir;
   }
   #[cfg(not(debug_assertions))]
   {
      let path = dirs::config_local_dir()
         .expect("Failed to find config directory")
         .join("fsync");
      if !path.exists() {
         create_dir_all(&path).expect("Failed to create config dir.");
      }
      path
   }
});

pub static DATA_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
   #[cfg(debug_assertions)]
   {
      let process_id = std::process::id();
      let debug_dir = std::env::temp_dir().join(format!("fsync-data-{process_id}"));
      if debug_dir.exists() {
         remove_dir_all(&debug_dir).expect("Failed to remove old data dir.");
      }
      create_dir_all(&debug_dir).expect("Failed to create data dir.");
      return debug_dir;
   }
   #[cfg(not(debug_assertions))]
   {
      let path = dirs::data_local_dir()
         .expect("Failed to find data directory")
         .join("fsync");
      if !path.exists() {
         create_dir_all(&path).expect("Failed to create data dir.");
      }
      path
   }
});
pub static CACHE_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
   #[cfg(debug_assertions)]
   {
      let process_id = std::process::id();
      let debug_dir = std::env::temp_dir().join(format!("fsync-cache-{process_id}"));
      if debug_dir.exists() {
         remove_dir_all(&debug_dir).expect("Failed to remove old cache dir.");
      }
      create_dir_all(&debug_dir).expect("Failed to create cache dir.");
      return debug_dir;
   }
   #[cfg(not(debug_assertions))]
   {
      let path = dirs::cache_dir()
         .expect("Failed to find cache directory")
         .join("fsync");
      if !path.exists() {
         create_dir_all(&path).expect("Failed to create cache dir.");
      }
      path
   }
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
   rt.block_on(p2p::start_service(config));

   unreachable!("Service should not return");
}
