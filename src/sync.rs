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

/// Sanitizes a path into a cross-platform, percent-encoded `PathBuf`.
///
/// Unsafe characters and `%` are encoded as `%XX`. Unpaired UTF-16
/// surrogates on Windows are encoded as `%uXXXX`. Valid UTF-8/Unicode is
/// preserved, and invalid UTF-8 bytes on Unix are encoded byte-by-byte.
///
/// The result is always valid UTF-8, so `path.to_str()` is `Some`.
///
/// # Policy
///
/// Unsafe characters are `%`, control characters, and
/// `< > : " \ | ? *`.
///
/// # Limitations
///
/// This does not handle Windows reserved names (`CON`, `NUL`, ...),
/// trailing spaces or periods, case-insensitive collisions, Unicode
/// normalization, path length limits, or path traversal (`..`).
fn sanitize_path(path: PathBuf) -> PathBuf {
   let mut out: Vec<u8> = Vec::new();

   #[cfg(unix)]
   {
      // Unix filenames are raw bytes, not guaranteed UTF-8.
      let bytes = path.as_os_str().as_bytes();
      let mut i = 0;
      while i < bytes.len() {
         match std::str::from_utf8(&bytes[i..]) {
            Ok(s) => {
               for ch in s.chars() {
                  if is_safe_char(ch) {
                     // Keep safe Unicode as UTF-8 bytes.
                     let mut buf = [0u8; 4];
                     out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                  } else {
                     // Encode each UTF-8 byte of the unsafe character.
                     for &b in ch.encode_utf8(&mut [0u8; 4]).as_bytes() {
                        write!(out, "%{:02X}", b).expect("write is infallible in this context");
                     }
                  }
               }
               break;
            }
            Err(e) => {
               // Preserve valid UTF-8 prefix, encode invalid bytes.
               let valid_up_to = i + e.valid_up_to();

               if valid_up_to > i {
                  let s = std::str::from_utf8(&bytes[i..valid_up_to]).unwrap();
                  for ch in s.chars() {
                     if is_safe_char(ch) {
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                     } else {
                        for &b in ch.encode_utf8(&mut [0u8; 4]).as_bytes() {
                           write!(out, "%{:02X}", b).expect("write is infallible in this context");
                        }
                     }
                  }
                  i = valid_up_to;
               }

               let err_len = e.error_len().unwrap_or(1).min(bytes.len() - i);

               for &b in &bytes[i..i + err_len] {
                  write!(out, "%{:02X}", b).expect("write is infallible in this context");
               }
               i += err_len;
            }
         }
      }
   }

   #[cfg(windows)]
   {
      // Windows filenames are UTF-16; decode and re-encode as UTF-8.
      for res in char::decode_utf16(path.as_os_str().encode_wide()) {
         match res {
            Ok(ch) if is_safe_char(ch) => {
               let mut buf = [0u8; 4];
               out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
            Ok(ch) => {
               for &b in ch.encode_utf8(&mut [0u8; 4]).as_bytes() {
                  write!(out, "%{:02X}", b).expect("write is infallible in this context");
               }
            }
            Err(e) => write!(out, "%u{:04X}", e.unpaired_surrogate())
               .expect("write is infallible in this context"),
         }
      }
   }

   let s = std::str::from_utf8(&out).expect("sanitized path is valid UTF-8");
   PathBuf::from(s)
}

/// Policy knob: characters that are unsafe on either Windows or Unix.
/// `%` is intentionally unsafe so encoded sequences stay unambiguous.
const fn is_safe_char(ch: char) -> bool {
   ch != '%' && !ch.is_control() && !matches!(ch, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*')
}

#[cfg(test)]
mod tests {
   use super::*;
   #[cfg(unix)]
   use std::os::unix::ffi::OsStringExt;
   use std::path::PathBuf;

   #[test]
   fn encodes_windows_invalid_chars() {
      let path = PathBuf::from("a<b>c:d\"e|f?g*h\\i");
      assert_eq!(
         sanitize_path(path),
         PathBuf::from("a%3Cb%3Ec%3Ad%22e%7Cf%3Fg%2Ah%5Ci")
      );
   }

   #[test]
   fn encodes_percent() {
      assert_eq!(sanitize_path(PathBuf::from("a%b")), PathBuf::from("a%25b"));
   }

   #[test]
   fn encodes_control_chars() {
      assert_eq!(
         sanitize_path(PathBuf::from("a\0b\nc")),
         PathBuf::from("a%00b%0Ac")
      );
   }

   #[test]
   fn keeps_unicode() {
      assert_eq!(
         sanitize_path(PathBuf::from("café/日本/🦀")),
         PathBuf::from("café/日本/🦀")
      );
   }

   #[test]
   fn keeps_safe_punctuation() {
      assert_eq!(
         sanitize_path(PathBuf::from("a b.c-d_e")),
         PathBuf::from("a b.c-d_e")
      );
   }

   #[test]
   fn empty_path() {
      assert_eq!(sanitize_path(PathBuf::from("")), PathBuf::from(""));
   }

   #[cfg(unix)]
   #[test]
   fn encodes_invalid_utf8() {
      let path = PathBuf::from(OsString::from_vec(vec![0x61, 0xFF, 0x62]));
      assert_eq!(sanitize_path(path), PathBuf::from("a%FFb"));
   }

   #[cfg(windows)]
   #[test]
   fn encodes_unpaired_surrogate() {
      let path = PathBuf::from(OsString::from_wide(&[0xD800]));
      assert_eq!(sanitize_path(path), PathBuf::from("%uD800"));
   }
}
