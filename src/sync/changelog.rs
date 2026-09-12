//! This module contains the changelog for your sync trees.
//!
//! The changelog will store up to the last 30 days of changes or until all known peers have synced.
//!
//! For now, I am storing the changes in a text file which I might change to a database in the
//! future. if I decide I want to do blob storage as well.

use super::Event;
use crate::DATA_DIR;
use parking_lot::RwLock;
use std::{
   fs::{self, File},
   io::{BufRead, BufReader, BufWriter, ErrorKind, Write},
   path::PathBuf,
   sync::LazyLock,
   time::{Duration, SystemTime},
};
use thiserror::Error;

const MAX_TIME_STORED: Duration = Duration::from_hours(24 * 30);

/// The lock used to ensure we don't read and write the changelog at the same time.
static CHANGELOG_LOCK: RwLock<()> = RwLock::new(());
static CHANGELOG_PATH: LazyLock<PathBuf> = LazyLock::new(|| DATA_DIR.join("changelog.jsonl"));

#[derive(Debug, Error)]
pub enum Error {
   #[error(transparent)]
   Io(#[from] std::io::Error),
   #[error(transparent)]
   ParseError(#[from] serde_json::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub fn append_event(event: Event) -> Result<()> {
   let _guard = CHANGELOG_LOCK.write();
   let mut file = File::options()
      .create(true)
      .append(true)
      .open(&*CHANGELOG_PATH)?;
   let event_as_json_string = serde_json::to_string(&event)?;
   writeln!(file, "{}", event_as_json_string)?;
   Ok(())
}

pub fn read_changes_since(since: SystemTime) -> Result<Vec<Event>> {
   let _guard = CHANGELOG_LOCK.read();
   let reader = BufReader::new(File::open(&*CHANGELOG_PATH)?);
   let mut events_since = Vec::new();

   for line in reader.lines() {
      let line = line?;
      let event: Event = serde_json::from_str(&line)?;
      if event.timestamp > since {
         events_since.push(event);
      }
   }

   Ok(events_since)
}

pub fn clear_changelog(since: Option<SystemTime>) -> Result<()> {
   use ErrorKind::CrossesDevices;
   let _guard = CHANGELOG_LOCK.write();

   if !CHANGELOG_PATH.exists() {
      return Ok(());
   }

   let since = since.unwrap_or(SystemTime::now() - MAX_TIME_STORED);

   let temp_file_path = std::env::temp_dir().join("fsync-changelog-temp.jsonl");
   if temp_file_path.exists() {
      std::fs::remove_file(&temp_file_path)?;
   }

   let mut temp_file_writer = BufWriter::new(File::create(&temp_file_path)?);
   let current_file_reader = BufReader::new(File::open(&*CHANGELOG_PATH)?);

   for line in current_file_reader.lines() {
      let line = line?;
      let event: Event = serde_json::from_str(&line)?;
      if event.timestamp > since {
         temp_file_writer.write_all(line.as_bytes())?;
      }
   }

   temp_file_writer.flush()?;
   let Err(error) = fs::rename(&temp_file_path, &*CHANGELOG_PATH) else {
      return Ok(());
   };
   if error.kind() == CrossesDevices {
      fs::copy(&temp_file_path, &*CHANGELOG_PATH)?;
      fs::remove_file(&temp_file_path)?;
   };
   Ok(())
}

#[cfg(test)]
mod tests {
   use super::*;
   use crate::sync::Change;
   #[test]
   fn test_changelog() {
      let event = Event {
         tree: "test".to_string(),
         timestamp: SystemTime::now(),
         changes: vec![Change::Create {
            path: "test".to_string(),
            is_dir: true,
         }],
      };
      append_event(event.clone()).unwrap();
      let events = read_changes_since(SystemTime::now() - MAX_TIME_STORED).unwrap();
      assert_eq!(events.len(), 1);
      assert_eq!(events[0].tree, event.tree);
      assert_eq!(events[0].changes.len(), 1);
      clear_changelog(Some(SystemTime::now())).unwrap();
      let events = read_changes_since(SystemTime::now() - MAX_TIME_STORED).unwrap();
      assert_eq!(events.len(), 0);
   }
}
