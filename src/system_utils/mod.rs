#[cfg(not(unix))]
use std::io::{Read, Seek, SeekFrom, Write};

#[cfg(unix)]
use std::os::unix::fs::FileExt;

use std::{
   fs::File,
   io::{ErrorKind, Result},
   ops::{Deref, DerefMut},
   path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

pub struct TempFile {
   path: PathBuf,
   file: File,
}
impl TempFile {
   pub fn new() -> Result<Self> {
      use ErrorKind::AlreadyExists;
      let temp_dir = std::env::temp_dir();

      loop {
         let file_name = hex::encode(rand::random::<[u8; 16]>());
         let path = temp_dir.join(file_name);

         let result = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path);

         match result {
            Ok(file) => return Ok(Self { path, file }),

            Err(err) => {
               if err.kind() == AlreadyExists {
                  continue;
               }

               return Err(err);
            }
         }
      }
   }
   pub fn path(&self) -> &Path {
      &self.path
   }
}
impl Deref for TempFile {
   type Target = File;
   fn deref(&self) -> &Self::Target {
      &self.file
   }
}

impl DerefMut for TempFile {
   fn deref_mut(&mut self) -> &mut Self::Target {
      &mut self.file
   }
}
/// Simple wrapper trait for read/writing to a position in a file
/// on unix systems this is supported natively and is faster than using seek
pub trait ReadWritePostion {
   fn read_pos(&mut self, buf: &mut [u8], pos: u64) -> std::io::Result<usize>;
   fn write_pos(&mut self, buf: &[u8], pos: u64) -> std::io::Result<usize>;
}

#[cfg(unix)]
impl ReadWritePostion for File {
   fn read_pos(&mut self, buf: &mut [u8], pos: u64) -> std::io::Result<usize> {
      self.read_at(buf, pos)
   }
   fn write_pos(&mut self, buf: &[u8], pos: u64) -> std::io::Result<usize> {
      self.write_at(buf, pos)
   }
}

#[cfg(not(unix))]
impl ReadWritePostion for File {
   fn read_pos(&mut self, buf: &mut [u8], pos: u64) -> std::io::Result<usize> {
      let current_pos = self.seek(SeekFrom::Current(0))?;
      self.seek(SeekFrom::Start(pos))?;
      let read = self.read(buf)?;
      self.seek(SeekFrom::Start(current_pos))?;
      Ok(read)
   }
   fn write_pos(&mut self, buf: &[u8], pos: u64) -> std::io::Result<usize> {
      let current_pos = self.seek(SeekFrom::Current(0))?;
      self.seek(SeekFrom::Start(pos))?;
      let written = self.write(buf)?;
      self.seek(SeekFrom::Start(current_pos))?;
      Ok(written)
   }
}

/// Opens a copy-on-write file from the source file.
/// copys the file to a temporary file and returns a handle to the temporary file.
/// Sadly, not all filesystems support copy-on-write cloning. In this case, the
/// function returns a [`std::io::ErrorKind::Unsupported`] error. This is a limitation
/// of the filesystems more than the operating systems themselves but behavior varies between operating systems.
/// # Example
/// ```rust,no_run
/// use fsync::system_utils::open_file_clone;
/// let src = std::env::temp_dir().join("src.txt");
/// let dst = std::env::temp_dir().join("dst.txt");
/// std::fs::write(&src, "Hello World!").expect("Failed to write to source file");
/// open_file_clone(&src).expect("Failed to clone file");
/// let src_contents = std::fs::read(&src).expect("Failed to read source file");
/// let dst_contents = std::fs::read(&dst).expect("Failed to read destination file");
/// assert_eq!(src_contents, dst_contents, "Source and destination files are not the same");
/// ```
pub fn open_file_clone(path: &Path) -> std::io::Result<File> {
   let temp_file = TempFile::new()?;

   #[cfg(target_os = "linux")]
   {
      linux::clone_file_cow(path, &temp_file.path())
   }
   #[cfg(target_os = "macos")]
   {
      macos::clone_file_cow(path, &temp_file.path())
   }
   #[cfg(target_os = "windows")]
   {
      windows::clone_file_cow(path, &temp_file.path())
   }
   #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
   {
      Err(Unsupported.into())
   }
}

#[ignore = "Doesn't work on all filesystems"]
#[test]
fn test_cow_file() {
   let src = std::env::temp_dir().join("src.txt");
   let dst = std::env::temp_dir().join("dst.txt");
   std::fs::write(&src, "Hello World!").expect("Failed to write to source file");
   open_file_clone(&src).expect("Failed to clone file");
   let src_contents = std::fs::read(&src).expect("Failed to read source file");
   let dst_contents = std::fs::read(&dst).expect("Failed to read destination file");
   assert_eq!(
      src_contents, dst_contents,
      "Source and destination files are not the same"
   );
}
