use std::{fs::File, io::Error, os::fd::AsRawFd, path::Path};

use tracing::instrument;

/// Creates a COW file from the source file.
/// # Arguments
/// * `src` - The source file to clone
/// * `dst` - The destination file to clone to (must be different from `src`)

#[instrument(err)]
pub fn clone_file_cow<P: AsRef<Path> + std::fmt::Debug>(src: P, dst: P) -> std::io::Result<File> {
   assert_ne!(src.as_ref(), dst.as_ref());

   let src_file = File::open(src.as_ref())?;
   let dst_file = File::create(dst.as_ref())?;

   let result = unsafe { libc::ioctl(dst_file.as_raw_fd(), libc::FICLONE, src_file.as_raw_fd()) };

   if result < 0 {
      return Err(Error::last_os_error());
   }
   Ok(dst_file)
}
