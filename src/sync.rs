use blake3::Hash;
use std::ffi::OsString;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[derive(Debug, Error)]
pub enum Error {
   #[error(transparent)]
   Io(#[from] std::io::Error),
}

type Result<T, E = Error> = std::result::Result<T, E>;

struct Insertion {
   path: PathBuf,
   position: usize,
   data: Vec<u8>,
}

struct Deletion {
   path: PathBuf,
   position: usize,
   end: usize,
}

struct Rename {
   old_path: PathBuf,
   new_path: PathBuf,
}

/// This enum represents a change for a synced files
enum Event {
   Insert(Insertion),
   Delete(Deletion),
   Rename(Rename),
   Remove(PathBuf),
}

struct SyncEvent {
   changes: Event,
   hash: Hash,
   timestamp: SystemTime,
}

struct Metadata {
   hash: Hash,
   timestamp: SystemTime,
   size: u64,
}

trait FileSystemFile: Read + Write + Seek + Send {
   fn hash(&self) -> Result<Hash>;
   fn metadata(&self) -> Result<Metadata>;
}
trait FileSystem {
   fn open(&self, path: &PathBuf) -> Result<impl FileSystemFile>;
   fn create(&self, path: &PathBuf) -> Result<impl FileSystemFile>;
   fn rename(&self, old_path: &PathBuf, new_path: &PathBuf) -> Result<()>;
   fn remove(&self, path: &PathBuf) -> Result<()>;
   fn list(&self, path: &PathBuf) -> Result<Vec<PathBuf>>;
}
