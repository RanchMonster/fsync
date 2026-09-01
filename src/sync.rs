use std::{
   path::{Path, PathBuf},
   sync::{Arc, RwLock},
   time::SystemTime,
};

use ignore::gitignore::{Gitignore as IgnoreFile, GitignoreBuilder as IgnoreBuilder};

use async_trait::async_trait;
use blake3::Hash;
use notify::{RecommendedWatcher, Watcher};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::broadcast::{self, Receiver, Sender, error::RecvError};

pub trait SyncError: std::error::Error + Send + Sync {}

#[derive(Error, Debug)]
pub enum FileStreamError {
   #[error("Error reading ignore file")]
   IgnoreFileBuildError(#[from] ignore::Error),
   #[error("Notify error")]
   Notify(#[from] notify::Error),
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
fn get_ingnore_file(synced_location: &PathBuf, allow_gitignore: bool) -> Option<IgnoreFile> {
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

/// Returns true if the given path should be ignored
/// Requires the path to be under the ignore file
pub fn should_ignore(path: &Path, ignore_file: &IgnoreFile) -> bool {
   debug_assert!(path.exists(), "Path must exist");

   let parent = ignore_file.path();
   debug_assert!(
      path.starts_with(parent),
      "Path must be under the ignore file"
   );

   assert!(path.is_absolute(), "Path must be absolute");

   let is_dir = path.is_dir();
   ignore_file
      .matched_path_or_any_parents(path, is_dir)
      .is_ignore()
}

/// The deticated file watching entity
pub struct FileSystemWatcher {
   watcher: RecommendedWatcher,
   ignore_files: Arc<RwLock<Vec<IgnoreFile>>>,
   pub receiver: Receiver<Event>,
}

///Abstracted out for readability, handles a notify event and broadcasts it
fn notify_event_handler_builider(
   ignore_files: Arc<RwLock<Vec<IgnoreFile>>>, sender: Sender<Event>,
) -> impl Fn(notify::Result<notify::Event>) {
   move |event: notify::Result<notify::Event>| {
      let Ok(mut event) = event else {
         let error = event.unwrap_err();
         tracing::error!("Failed to handle event due to error {}", error);
         return;
      };
   }
}

impl FileSystemWatcher {
   fn new() -> Self {
      let (sender, receiver) = broadcast::channel(100);

      let ignore_files = Arc::new(RwLock::new(Vec::new()));

      let notify_event_handler = notify_event_handler_builider(Arc::clone(&ignore_files), sender);
      let watcher =
         notify::recommended_watcher(notify_event_handler).expect("Failed to create notify reader");

      Self {
         watcher,
         ignore_files,
         receiver,
      }
   }

   pub fn subscribe(&mut self, synced_location: PathBuf) -> Result<(), FileStreamError> {
      use notify::RecursiveMode::Recursive;

      // TODO: Add config check for allowing gitignore here, or add as argument
      let allow_gitignore = false;
      if let Some(new_ignore_file) = get_ingnore_file(&synced_location, allow_gitignore) {
         self.ignore_files.write().expect().push(new_ignore_file);
      }

      self.watcher.watch(synced_location.as_path(), Recursive)?;

      self.receiver = self.receiver.resubscribe();

      Ok(())
   }
}

#[async_trait]
impl EventStream<FileStreamError> for FileSystemWatcher {
   async fn next(&mut self) -> Option<Result<Event, FileStreamError>> {
      match self.receiver.recv().await {
         Ok(event) => Some(Ok(event)),
         Err(err) => match err {
            RecvError::Closed => {
               panic!("Notify event handler dropped");
            }
            RecvError::Lagged(lost_events) => {
               tracing::error!("Event stream consumer lagging. Lost events: {lost_events}");
               None
            }
         },
      }
   }
}
