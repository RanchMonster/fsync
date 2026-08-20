use fsync::system_utils::{ReadWritePostion, TempFile, open_file_clone};
use std::io::{Read, Write};

const TEST_DATA: &[u8] = b"Hello World!";
#[test]
fn test_temp_file() {
   let mut temp_file = TempFile::new().expect("Failed to create temp file");
   assert!(temp_file.path().exists(), "Temp file should exist");
   writeln!(*temp_file, "Hello World!").expect("Failed to write to temp file");
}

#[test]
fn test_postion_read_trait() {
   let mut temp_file = TempFile::new().expect("Failed to create temp file");
   temp_file.set_len(1024).expect("Failed to set length");
   temp_file
      .write_pos(TEST_DATA, 500)
      .expect("Failed to write to temp file");
   let mut buf = [0u8; TEST_DATA.len()];
   temp_file
      .read_pos(&mut buf, 500)
      .expect("Failed to read from temp file");
   assert_eq!(TEST_DATA, &buf, "Data should match");
}
