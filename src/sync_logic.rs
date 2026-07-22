use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, atomic::AtomicU64},
    time::{Duration, Instant},
};

use ignore::gitignore::{Gitignore, GitignoreBuilder};
use notify::{Event, EventHandler, EventKind, RecommendedWatcher, Watcher};
use tokio::{
    runtime::{self, Handle},
    sync::{Mutex, RwLock, mpsc},
    task::{self, JoinHandle, JoinSet},
};
use tracing::instrument;
/// Just a list of all the default ignore files supported by fsync
const DEFAULT_IGNORE_FILES: &[&str] = &[".gitignore", ".ignore", ".fsyncignore"];
const DEFAULT_FILE_EVENT_DELAY: Duration = Duration::from_secs(5); // Default time to wait before alerting the tree to the changes

/// Error type for the local sync handler
#[derive(Debug)]
pub enum LocalSyncError {
    /// Failed to infer the name of the tree
    InferNameError,
    /// IO Error
    Io(std::io::Error),
    /// Notify Error
    Notify(notify::Error),
}

impl std::fmt::Display for LocalSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // this is temporary until I am done implementing the error type
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for LocalSyncError {}
impl From<std::io::Error> for LocalSyncError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}
impl From<notify::Error> for LocalSyncError {
    fn from(err: notify::Error) -> Self {
        Self::Notify(err)
    }
}

/// Result type for the local sync handler
type Result<T> = std::result::Result<T, LocalSyncError>;

// Helper functions for local sync handling

fn find_helper(path: PathBuf, tx: mpsc::Sender<Gitignore>) {
    use std::fs::read_dir;
    let mut builder = None;
    let Ok(files) = read_dir(path.clone()) else {
        tracing::error!(path=%path.display(), "Failed to read directory");
        return;
    };
    for entry in files {
        let Ok(entry) = entry else {
            tracing::error!(path=%path.display(), "Failed to read entry in directory");
            continue;
        };
        let is_dir = {
            let Ok(ftype) = entry.file_type() else {
                tracing::error!(path=%path.display(), "Failed to get file type");
                continue;
            };
            ftype.is_dir()
        };
        if is_dir {
            let tx = tx.clone();
            task::spawn_blocking(move || find_helper(entry.path(), tx));
            continue;
        }
        if let Some(name) = entry.file_name().to_str().map(|name| name.to_string()) {
            let is_ignore_file = DEFAULT_IGNORE_FILES.contains(&name.as_str());
            if is_ignore_file {
                if builder.is_none() {
                    builder = Some(GitignoreBuilder::new(path.clone()));
                }
                builder.as_mut().unwrap().add(path.join(name));
            }
        }
    }
    if let Some(builder) = builder {
        let Ok(built) = builder.build() else {
            tracing::error!(path=%path.display(), "Failed to build gitignore");
            return;
        };
        tx.blocking_send(built).expect("Failed to send gitignore");
    }
}

#[instrument]
pub async fn find_ignores(path: PathBuf) -> Result<Vec<Gitignore>> {
    debug_assert!(path.is_dir(), "All sync trees must start from a directory");
    let (tx, mut rx) = mpsc::channel(100);
    task::spawn_blocking(move || find_helper(path, tx)).await;
    let mut ignore_files = Vec::new();
    while let Some(ignore) = rx.recv().await {
        ignore_files.push(ignore);
    }
    Ok(ignore_files)
}
pub type EventMap = HashMap<PathBuf, EventKind>;
/// Represents a Tree to be synced between two devices
pub struct SyncTree {
    /// The local path of the tree
    local_path: PathBuf,
    /// The name of this tree (defaults to the name of the root file_name of the local path)
    name: String,
    /// All the ignored files for this tree
    ignores: HashMap<PathBuf, Gitignore>,
    /// Watcher for the local tree
    _notify_handle: RecommendedWatcher,
    /// Watch Receiver
    watcher_rx: mpsc::Receiver<Event>,
    /// The amount of time to wait for the file tree to idle before syncing
    file_event_delay: Duration,
    /// Changes to the tree
    changes: HashMap<PathBuf, EventKind>,
}

impl SyncTree {
    fn default_name(local_path: PathBuf) -> Option<String> {
        assert!(
            local_path.is_dir(),
            "All sync trees must start from a directory"
        );
        assert!(local_path.is_absolute(), "Local path must be absolute");
        local_path
            .file_name()
            .map(|name| name.to_str())
            .flatten()
            .map(|name| name.to_string())
    }
    #[instrument]
    pub async fn new(
        local_path: PathBuf,
        name: Option<String>,
        file_event_delay: Option<Duration>,
    ) -> Result<Self> {
        use LocalSyncError::InferNameError;
        use notify::RecursiveMode::Recursive;
        let local_path = local_path.canonicalize()?;
        let file_event_delay = file_event_delay.unwrap_or(DEFAULT_FILE_EVENT_DELAY);
        assert!(
            file_event_delay > Duration::from_secs(0),
            "File event delay must be greater than zero"
        );
        assert!(
            local_path.is_dir(),
            "All sync trees must start from a directory"
        );
        let Some(name) = name.or(Self::default_name(local_path.clone())) else {
            return Err(InferNameError);
        };

        assert!(!name.is_empty(), "Name cannot be empty");
        let mut ignores = HashMap::new();
        let ignore_files = find_ignores(local_path.clone()).await?;
        for ignore_file in ignore_files {
            println!("{}", ignore_file.path().display());
            ignores.insert(ignore_file.path().to_path_buf(), ignore_file);
        }
        let (watcher_tx, watcher_rx) = mpsc::channel(1);
        let mut notify_handle = {
            notify::recommended_watcher(move |event: notify::Result<Event>| match event {
                Ok(event) => {
                    if event.kind.is_modify() || event.kind.is_create() || event.kind.is_remove() {
                        let _ = watcher_tx.blocking_send(event);
                    }
                }
                Err(error) => {
                    tracing::error!("Failed to handle event: {}", error);
                }
            })?
        };
        notify_handle.watch(&local_path, Recursive)?;
        Ok(Self {
            local_path,
            name: name.to_string(),
            ignores,
            _notify_handle: notify_handle,
            watcher_rx,
            file_event_delay,
            changes: HashMap::new(),
        })
    }
    fn is_ignore(&self, path: &PathBuf) -> bool {
        for ancestor in path.ancestors() {
            if !ancestor.starts_with(&self.local_path) {
                continue;
            }
            if let Some(ignore) = self.ignores.get(ancestor) {
                tracing::debug!("Checking ignore rules for: {}", ignore.path().display());
                let path = path.strip_prefix(ancestor).unwrap();
                // println!("found ignore: {}", ignore.path().display());
                let should_ignore = ignore
                    .matched_path_or_any_parents(&path, path.is_dir())
                    .is_ignore();
                if should_ignore {
                    tracing::debug!("Ignoring path: {}", path.display());
                    return true;
                }
            }
        }
        false
    }
    pub async fn next_event(&mut self) -> Option<EventMap> {
        loop {
            tokio::select! {
                Some(event) = self.watcher_rx.recv() => {
                   let kind = event.kind;
                   let is_change = kind.is_modify() || kind.is_create() || kind.is_remove();
                  if is_change {
                     for path in event.paths {
                        assert!(path.starts_with(&self.local_path), "Path must be within the local path instead got {} vs {}", path.display(), self.local_path.display());
                        if self.is_ignore(&path) || path == self.local_path {
                           continue;
                        }
                        self.changes.insert(path.to_path_buf(),kind);
                     }
                  }
                   }
                _ = tokio::time::sleep(self.file_event_delay) => {
                   tracing::debug!("File event delay finished");
                   break;
                }
            }
        }
        let changes = self.changes.clone();
        self.changes.clear();
        Some(changes)
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn update_wait_duration(&mut self, duration: Duration) {
        self.file_event_delay = duration;
    }
}
#[tokio::test]
async fn test_find_ignores() {
    let search_dir = std::env::current_dir().unwrap();
    let ignores = find_ignores(search_dir).await.unwrap();
    assert!(!ignores.is_empty(), "No ignores found");
    assert!(
        ignores.len() == 1,
        "Expected one ignore file only for this test"
    );
}
#[tokio::test]
async fn test_sync_tree() {
    use tokio::{
        fs::{File, remove_file},
        io::AsyncWriteExt,
    };
    let search_dir = std::env::current_dir().unwrap();
    let currnet_dir_name = search_dir.file_name().unwrap().to_str().unwrap();
    let mut tree = SyncTree::new(search_dir.clone(), None, None).await.unwrap();
    assert!(!tree.name().is_empty(), "Name should not be empty");
    assert!(
        tree.name() == currnet_dir_name,
        "Name should be the same as the directory name"
    );
    let mut fd = File::create(search_dir.join("test.txt")).await.unwrap();
    fd.write_all(b"hello world").await.unwrap();
    drop(fd);
    let changes = tree.next_event().await.unwrap();
    assert!(!changes.is_empty(), "No changes found");
    let mut detected_change = false;
    for (path, _) in changes {
        if path.canonicalize().unwrap() == search_dir.join("test.txt").canonicalize().unwrap() {
            detected_change = true;
            break;
        }
    }
    assert!(detected_change, "No change detected");
    remove_file(search_dir.join("test.txt")).await.unwrap();
}
