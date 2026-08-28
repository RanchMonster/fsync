use std::time::SystemTime;

use blake3::Hash;
use serde::{Deserialize, Serialize};

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
trait SyncError: std::error::Error + Send + Sync {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
   tree: String,
   timestamp: SystemTime,
}

#[async_trait]
trait EventStream<E: SyncError> {
   async fn next(&mut self) -> Result<Option<Event>, E>;
}
