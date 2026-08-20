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
