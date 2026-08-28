use fsync::fs_watcher::{IgnoreMap, WatcherThread};
use std::{fs, path::PathBuf};

fn test_dir(name: &str) -> PathBuf {
   let dir = std::env::temp_dir().join(name);
   let _ = fs::remove_dir_all(&dir); // If the directory exists it will be removed
   fs::create_dir(&dir).unwrap();
   dir
}

fn set_file_event_delay() {
   // Don't wait for the event batching delay in the controlled test environment.
   unsafe {
      std::env::set_var("FSYNC_FILE_EVENT_DELAY", "0");
   }
}

#[tokio::test]
async fn test_find_ignores() {
   let search_dir = std::env::current_dir().unwrap();
   let mut ignores = IgnoreMap::new();
   ignores.load(search_dir).await.unwrap();
   assert!(!ignores.is_empty(), "No ignores found");
   assert!(
      ignores.len() == 1,
      "Expected one ignore file only for this test"
   );
}

#[tokio::test]
async fn test_ignore_rules() {
   let search_dir = test_dir("fsync_test_ignore_rules");
   fs::write(search_dir.join(".gitignore"), "/test.txt\n/test_dir").unwrap();
   let mut ignores = IgnoreMap::new();
   ignores.load(search_dir.clone()).await.unwrap();
   assert!(
      !ignores.is_ignore(&search_dir),
      "root directory should not be ignored"
   );
   assert!(
      ignores.is_ignore(&search_dir.join("test.txt")),
      "test.txt should be ignored"
   );
   assert!(
      ignores.is_ignore(&search_dir.join("test_dir")),
      "test_dir should be ignored",
   );
   let _ = fs::remove_dir_all(&search_dir);
}

#[tokio::test]
async fn test_sync_logic() {
   set_file_event_delay();
   let search_dir = test_dir("fsync_test_sync_logic");

   let mut watcher = WatcherThread::init().expect("Failed to initialize watcher");
   let mut sub = watcher
      .subscribe(search_dir.clone())
      .await
      .expect("Failed to subscribe to watcher");
   fs::write(search_dir.join("test.txt"), "Hello World").unwrap();
   if let Ok(events) = sub.recv().await {
      assert!(
         events
            .iter()
            .any(|event| event.paths.contains(&search_dir.join("test.txt"))),
         "test.txt should be created\n{events:?}"
      );
   }
   fs::write(search_dir.join("test.txt"), "Hello World2").unwrap();
   if let Ok(events) = sub.recv().await {
      assert!(
         events
            .iter()
            .any(|event| event.paths.contains(&search_dir.join("test.txt"))),
         "test.txt should be modified\n{events:?}"
      );
   }
   fs::rename(search_dir.join("test.txt"), search_dir.join("test2.txt")).unwrap();
   if let Ok(events) = sub.recv().await {
      assert!(
         events
            .iter()
            .any(|event| event.paths.contains(&search_dir.join("test2.txt")))
      );
   }
   fs::copy(search_dir.join("test2.txt"), search_dir.join("test3.txt")).unwrap();
   if let Ok(events) = sub.recv().await {
      assert!(
         events
            .iter()
            .any(|event| event.paths.contains(&search_dir.join("test3.txt"))),
      );
   }
   fs::remove_file(search_dir.join("test3.txt")).unwrap();
   if let Ok(events) = sub.recv().await {
      assert!(
         events
            .iter()
            .any(|event| event.paths.contains(&search_dir.join("test3.txt"))),
         "test3.txt should be removed\n{events:?}"
      );
   }
   let _ = fs::remove_dir_all(&search_dir);
}
