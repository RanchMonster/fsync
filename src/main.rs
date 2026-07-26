use std::path::{Path, PathBuf};

use blake3::Hash;
mod fs_watcher;
mod protocol;
use fs_watcher::WatcherThread;
// mod protocol;
#[tokio::main]
async fn main() {}
pub async fn hash_file(path: &Path) -> Result<Hash, std::io::Error> {
    todo!("hash the file")
}
