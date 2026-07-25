use std::path::{Path, PathBuf};

use blake3::Hash;

mod fs_watcher;
use fs_watcher::WatcherThread;
use tokio::fs;
// mod protocol;
#[tokio::main]
async fn main() {}
pub async fn hash_file(path: &Path) -> Result<Hash, std::io::Error> {
    todo!("hash the file")
}
