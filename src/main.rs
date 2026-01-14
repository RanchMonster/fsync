use std::{convert::Infallible, sync::LazyLock};
mod config;
mod server;
#[macro_export]
macro_rules! fatal {
    ($result:expr) => {
        match $result {
            Ok(val) => val,
            Err(err) => {
                log::error!("FATAL: {}", err);
                std::process::exit(1);
            }
        }
    };
}
static DIRS: LazyLock<directories::ProjectDirs> = LazyLock::new(|| {
    fatal!(
        directories::ProjectDirs::from("com", "linuxman", "fsync")
            .ok_or("Failed to get project dirs")
    )
});
#[inline(always)]
pub fn config_dir() -> &'static std::path::Path {
    DIRS.config_dir()
}
#[inline(always)]
pub fn data_dir() -> &'static std::path::Path {
    DIRS.data_dir()
}
#[inline(always)]
pub fn cache_dir() -> &'static std::path::Path {
    DIRS.cache_dir()
}

#[tokio::main]
async fn main() {
    env_logger::try_init_from_env(env_logger::Env::default().default_filter_or("info")).unwrap(); // start logging
}
