use std::{
   path::{Path, PathBuf},
   time::SystemTime,
};

use ignore::gitignore::{Gitignore as IgnoreFile, GitignoreBuilder as IgnoreBuilder};

use async_trait::async_trait;
use blake3::Hash;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub trait SyncError: std::error::Error + Send + Sync {}

#[derive(Error, Debug)]
pub enum FileStreamError {
   #[error("Error reading ignore file")]
   IgnoreFileBuildError(#[from] ignore::Error),
}

impl SyncError for FileStreamError {}

// This represents a change in a sync tree
pub enum Change {
   CreateFile(String),

   CreateDir(String),

   Delete(String),

   Modify {
      target: String,
      size: u64,
      hash: Hash,
   },

   Rename {
      old_path: String,
      new_path: String,
      hash: Hash,
      size: u64,
   },
   // Add more as needed
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
   tree: String,
   timestamp: SystemTime,
}

#[async_trait]
pub trait EventStream<E: SyncError> {
   async fn next(&mut self) -> Option<Result<Event, E>>;
}

/// Helper function to get the ignore file for a given synced location
/// This will look for a .fsyncignore file, then a .ignore file, then a .gitignore file
/// If none of these files exist, an error will be returned
fn get_ingnore_file(synced_location: PathBuf, allow_gitignore: bool) -> Option<IgnoreFile> {
   assert!(synced_location.exists(), "Synced location does not exist");

   fn build_ignore(path: PathBuf) -> Option<IgnoreFile> {
      if !path.exists() {
         return None;
      }

      Some(
         IgnoreBuilder::new(&path)
            .build()
            .unwrap_or_else(|err| panic!("Failed to build ignore file {}: {err}", path.display())),
      )
   }

   build_ignore(synced_location.join(".fsyncignore"))
      .or_else(|| build_ignore(synced_location.join(".ignore")))
      .or_else(|| {
         allow_gitignore
            .then(|| synced_location.join(".gitignore"))
            .and_then(build_ignore)
      })
}
