use std::{fs::File, io::Error, os::windows::io::AsRawHandle, path::Path};

/// Win32 Constant for "Duplicate File Extents"
const FSCTL_DUPLICATE_EXTENTS_TO_FILE: u32 = 0x00098344;

/// Recreated the precise memory layout Windows expects for an extent swap
#[repr(C)]
struct DuplicateExtentsData {
   file_handle: *mut libc::c_void,
   source_file_offset: i64,
   target_file_offset: i64,
   byte_count: i64,
}

// The Windows API bindings
unsafe extern "system" {
   /// The Windows API function to duplicate an extent of a file
   unsafe fn DeviceIoControl(
      hDevice: *mut libc::c_void, dwIoControlCode: u32, lpInBuffer: *mut DuplicateExtentsData,
      nInBufferSize: u32, lpOutBuffer: *mut libc::c_void, nOutBufferSize: u32,
      lpBytesReturned: *mut u32, lpOverlapped: *mut libc::c_void,
   ) -> i32;

}

pub fn clone_file_cow<P: AsRef<Path> + std::fmt::Debug>(src: P, dst: P) -> std::io::Result<File> {
   assert_ne!(src.as_ref(), dst.as_ref());

   let src_file = File::open(src.as_ref())?;
   let dst_file = File::create(dst.as_ref())?;

   let src_extent_file_size = src_file.metadata()?.len() as i64;

   // The input data for the DeviceIoControl call
   let mut input_data = DuplicateExtentsData {
      file_handle: src_file.as_raw_handle(),
      source_file_offset: 0,
      target_file_offset: 0,
      byte_count: src_extent_file_size,
   };
   let mut bytes_returned = 0;
   let success = unsafe {
      DeviceIoControl(
         dst_file.as_raw_handle(),
         FSCTL_DUPLICATE_EXTENTS_TO_FILE,
         &mut input_data as *mut DuplicateExtentsData,
         std::mem::size_of::<DuplicateExtentsData>() as u32,
         std::ptr::null_mut(),
         0,
         &mut bytes_returned,
         std::ptr::null_mut(),
      )
   };

   if success == 0 {
      return Err(Error::last_os_error());
   }

   Ok(dst_file)
}
