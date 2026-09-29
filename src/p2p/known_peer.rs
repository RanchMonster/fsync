use blake3::Hash;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{
   BufRead, BufReader, BufWriter, Error, ErrorKind, Read, Result, Seek, SeekFrom, Write,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::Duration;
use std::{fmt::Display, str::FromStr, sync::RwLock};

use crate::DATA_DIR;

pub const HEX_ENCODED_PEER_ID_LENGTH: usize = 64;
/// Maximum length of a peer name stored in the known peers file (in chars).
const MAX_PEER_NAME_LENGTH: usize = 255;

static KNOWN_PEERS_LOCK: RwLock<()> = RwLock::new(());
/// Where the known peers list is stored. Also handles creating the file if it
/// does not exist yet.
pub fn known_peers_file_path() -> PathBuf {
   DATA_DIR.join("known_peers")
}

fn old_known_peers_file_path() -> PathBuf {
   known_peers_file_path().with_extension("old")
}

/// A peer identity: the blake3 hash of a peer certificate's public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub struct PeerId(pub [u8; 32]);
impl From<Hash> for PeerId {
   fn from(hash: Hash) -> Self {
      Self(*hash.as_bytes())
   }
}
impl FromStr for PeerId {
   type Err = hex::FromHexError;
   fn from_str(line: &str) -> std::result::Result<Self, Self::Err> {
      let key_hash = hex::decode(line)?
         .try_into()
         .map_err(|_| hex::FromHexError::InvalidStringLength)?;
      Ok(PeerId(key_hash))
   }
}

impl Display for PeerId {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(f, "{}", hex::encode(self.0))
   }
}
pub struct PeerInfo {
   pub name: String,
   pub peer_id: PeerId,
}

/// Splits a known-peers line into its first 64 bytes (the hex-encoded id) and
/// the remainder (the name, trimmed). The id does not have to be followed by a
/// tab: any line of at least 64 bytes that is not cut through a multi-byte
/// character at that offset parses, and whatever follows the id — separator or
/// not — is the name. Returns `None` for shorter lines and for lines whose byte
/// 64 falls inside a character, both of which make the line unparseable and a
/// candidate for repair.
fn split_peer_id_and_name(line: &str) -> Option<(&str, &str)> {
   let encoded_peer_id = line.get(..HEX_ENCODED_PEER_ID_LENGTH)?;
   let name = line.get(HEX_ENCODED_PEER_ID_LENGTH..)?.trim();
   Some((encoded_peer_id, name))
}

#[cfg(unix)]
fn harden_known_peers_file_permissions() -> Result<()> {
   use std::os::unix::fs::PermissionsExt;
   let known_peers_file_path = known_peers_file_path();
   let mut permissions = fs::metadata(&known_peers_file_path)?.permissions();
   permissions.set_mode(0o600);
   fs::set_permissions(&known_peers_file_path, permissions)
}

#[cfg(not(unix))]
fn harden_known_peers_file_permissions() -> Result<()> {
   Ok(())
}

/// Creates the known peers file if it is missing, without ever truncating an
/// existing one.
fn ensure_known_peers_file() -> Result<()> {
   match fs::OpenOptions::new()
      .write(true)
      .create_new(true)
      .open(known_peers_file_path())
   {
      Ok(_) => harden_known_peers_file_permissions(),
      Err(err) if err.kind() == ErrorKind::AlreadyExists => Ok(()),
      Err(err) => Err(err),
   }
}

/// Rewrites the file, dropping unparseable and duplicate entries and re-sanitizing
/// names. This scrubs control characters *within* names, but it cannot undo a line
/// split that an older version already committed to disk: an injected entry is
/// indistinguishable from a legitimate one once written. Only the write-path
/// sanitizer prevents that going forward.
fn clean_known_peers_file() -> Result<()> {
   let _write_guard = KNOWN_PEERS_LOCK
      .write()
      .expect("Failed to acquire write lock");
   let old_known_peers_file_path = old_known_peers_file_path();
   let known_peers_file_path = known_peers_file_path();

   fs::rename(&known_peers_file_path, &old_known_peers_file_path)?;

   let old_known_peers_file = BufReader::new(File::open(&old_known_peers_file_path)?);
   let mut new_known_peers_file = BufWriter::new(File::create(&known_peers_file_path)?);

   harden_known_peers_file_permissions()?;
   let mut already_known_peers = HashSet::new();
   for line in old_known_peers_file.lines() {
      let line = line?;
      let Some((peer_id, name)) = split_peer_id_and_name(&line) else {
         continue;
      };
      let Ok(peer_id) = PeerId::from_str(peer_id) else {
         continue;
      };
      if !already_known_peers.insert(peer_id) {
         continue;
      }

      writeln!(
         new_known_peers_file,
         "{}\t{}",
         peer_id,
         sanitize_peer_name(name)
      )?;
   }
   new_known_peers_file.flush()?;

   Ok(())
}

fn lazy_clean_file() -> Result<()> {
   static BAD_FILE_GUARD: AtomicBool = AtomicBool::new(false);
   match BAD_FILE_GUARD.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire) {
      Ok(_) => {
         let result = clean_known_peers_file();
         BAD_FILE_GUARD.store(false, Ordering::Release);
         result
      }

      Err(_) => {
         while BAD_FILE_GUARD.load(Ordering::Acquire) {
            sleep(Duration::from_millis(10));
         }
         Ok(())
      }
   }
}

pub fn get_known_peer(peer_id: &PeerId) -> Result<Option<PeerInfo>> {
   const MAX_ATTEMPTS: usize = 10;
   for _ in 0..MAX_ATTEMPTS {
      ensure_known_peers_file()?;
      let known_peers_file = BufReader::new(File::open(known_peers_file_path())?);

      let read_guard = KNOWN_PEERS_LOCK
         .read()
         .expect("Failed to acquire read lock");

      let mut needs_cleaning = false;
      for line in known_peers_file.lines() {
         let line = line?;
         let Some((peer_id_str, name)) = split_peer_id_and_name(&line) else {
            needs_cleaning = true;
            break;
         };
         let Ok(stored_peer_id) = PeerId::from_str(peer_id_str) else {
            needs_cleaning = true;
            break;
         };

         if stored_peer_id == *peer_id {
            drop(read_guard);
            return Ok(Some(PeerInfo {
               name: sanitize_peer_name(name),
               peer_id: *peer_id,
            }));
         }
      }
      drop(read_guard);

      if !needs_cleaning {
         return Ok(None);
      }
      lazy_clean_file()?;
   }

   Err(Error::new(
      ErrorKind::InvalidData,
      format!("known peers file is still malformed after {MAX_ATTEMPTS} repair attempts"),
   ))
}

/// Sanitizes a peer name for storage in the known peers file.
///
/// Names come from a peer's (self-signed) certificate, so they must not be
/// able to break the one-peer-per-line format of the file: control characters
/// (notably newlines and tabs) are replaced with spaces, whitespace is
/// trimmed, and the length is capped.
fn sanitize_peer_name(name: &str) -> String {
   let mut sanitized =
      String::with_capacity(name.len().min(MAX_PEER_NAME_LENGTH * char::MAX.len_utf8()));
   for c in name.chars().take(MAX_PEER_NAME_LENGTH) {
      if c.is_control() {
         sanitized.push(' ');
      } else {
         sanitized.push(c);
      }
   }
   sanitized.trim().to_string()
}

pub fn add_known_peer(peer_id: &PeerId, name: &str) -> Result<()> {
   use SeekFrom::End;
   let name = sanitize_peer_name(name);
   ensure_known_peers_file()?;

   let mut _write_guard = KNOWN_PEERS_LOCK
      .write()
      .expect("Failed to acquire write lock");

   let mut known_peers_file = File::options()
      .read(true)
      .write(true)
      .open(known_peers_file_path())?;

   if known_peers_file.seek(End(-1)).is_err() {
      writeln!(known_peers_file, "{}\t{}", peer_id, name)?;
      return Ok(());
   }
   let mut last_char_buffer = [0u8; 1];
   known_peers_file.read_exact(&mut last_char_buffer)?;

   if last_char_buffer[0] != b'\n' {
      known_peers_file.write_all(b"\n")?;
   }

   writeln!(known_peers_file, "{}\t{}", peer_id, name)?;
   Ok(())
}

#[cfg(test)]
mod tests {
   use super::*;
   const EMPTY_PEER_ID: PeerId = PeerId([0; 32]);
   const TEST_PEER_NAME: &str = "test";

   #[test]
   fn test_split_peer_id_and_name() {
      let line = format!("{}\t{}", EMPTY_PEER_ID, TEST_PEER_NAME);
      let (peer_id, name) = split_peer_id_and_name(&line).expect("valid line");

      assert_eq!(PeerId::from_str(peer_id).unwrap(), EMPTY_PEER_ID);
      assert_eq!(name, "test");
   }
   #[test]
   fn test_split_peer_id_and_name_empty_name() {
      let line = EMPTY_PEER_ID.to_string();
      let (peer_id, name) = split_peer_id_and_name(&line).expect("valid line");

      assert_eq!(PeerId::from_str(peer_id).unwrap(), EMPTY_PEER_ID);
      assert_eq!(name, "");
   }

   #[test]
   fn test_split_bad_line() {
      assert!(split_peer_id_and_name("bad line").is_none());
   }

   /// Byte 64 falls inside the `é`, so the line must be reported as
   /// unparseable instead of panicking on a `&str` slice.
   #[test]
   fn test_split_line_where_byte_64_is_inside_a_char() {
      let line = format!("{}é{}", "a".repeat(63), "b");
      assert_eq!(line.len(), 66);
      assert!(split_peer_id_and_name(&line).is_none());
   }

   /// Byte 64 landing exactly on a char boundary of a multi-byte name is
   /// still a valid line, and the name must survive intact.
   #[test]
   fn test_split_multibyte_name_at_the_boundary() {
      let line = format!("{}\té", EMPTY_PEER_ID);
      let (peer_id, name) = split_peer_id_and_name(&line).expect("valid line");

      assert_eq!(PeerId::from_str(peer_id).unwrap(), EMPTY_PEER_ID);
      assert_eq!(name, "é");
   }

   #[test]
   fn test_sanitize_peer_name() {
      assert_eq!(sanitize_peer_name("test"), "test");
      assert_eq!(sanitize_peer_name("bad\nname"), "bad name");
      assert_eq!(sanitize_peer_name("bad\tname"), "bad name");
      assert_eq!(sanitize_peer_name("bad\rname"), "bad name");
      assert_eq!(sanitize_peer_name("  trim  "), "trim");
   }

   #[test]
   fn test_sanitize_peer_name_all_control_chars() {
      assert_eq!(sanitize_peer_name("\n\t\r"), "");
   }

   #[test]
   fn test_sanitize_peer_name_truncates() {
      let name = sanitize_peer_name(&"a".repeat(300));
      assert_eq!(name.chars().count(), MAX_PEER_NAME_LENGTH);
   }

   #[test]
   fn test_sanitize_peer_name_nul() {
      assert_eq!(sanitize_peer_name("a\0b"), "a b");
   }

   /// The cap counts chars, not bytes, so multi-byte names are not mangled.
   #[test]
   fn test_sanitize_peer_name_keeps_multibyte_chars() {
      assert_eq!(sanitize_peer_name("日本\n語"), "日本 語");
   }
}
