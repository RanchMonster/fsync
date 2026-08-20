use std::{ffi::CString, fs::File, io::Error, path::Path};

/// Represents the standard file cloning flags.
const STD_FILE_CLONE: libc::c_int = 0;

unsafe extern "C" {
   unsafe fn clonefile(
      src: *const libc::c_char, dst: *const libc::c_char, flags: libc::c_int,
   ) -> libc::c_int;
}

pub fn clone_file_cow(src: &Path, dst: &Path) -> std::io::Result<File> {
   let c_src = CString::new(src.as_os_str().as_encoded_bytes()).expect("Invalid path");
   let c_dst = CString::new(dst.as_os_str().as_encoded_bytes()).expect("Invalid path");

   let result = unsafe { clonefile(c_src.as_ptr(), c_dst.as_ptr(), STD_FILE_CLONE) };
   if result < 0 {
      return Err(Error::last_os_error());
   }
   let file = File::options()
      .read(true)
      .write(true)
      .open(dst)
      .expect("This should not fail to open the file we just created");
   Ok(file)
}
