use ignore::gitignore::{Gitignore, GitignoreBuilder};
use notify::{Event, EventHandler, EventKind, RecommendedWatcher, Watcher};
use std::{
    collections::{HashMap, HashSet},
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::{
    fs::{File, canonicalize},
    sync::{Mutex, MutexGuard, RwLock, broadcast, mpsc},
    task::{self, JoinHandle},
};
use tracing::instrument;
// Macros
macro_rules! deref_impl {
    ($this:ty, $target:ident, $inner:ty) => {
        impl Deref for $this {
            type Target = $inner;
            fn deref(&self) -> &Self::Target {
                &self.$target
            }
        }
        impl DerefMut for $this {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.$target
            }
        }
    };
}

/// Just a list of all the default ignore files supported by fsync
const DEFAULT_IGNORE_FILES: &[&str] = &[".gitignore", ".ignore", ".fsyncignore"];
#[cfg(not(test))]
const FILE_EVENT_DELAY: Duration = Duration::from_secs(5); // Default time to wait before alerting the tree to the changes
#[cfg(test)]
const FILE_EVENT_DELAY: Duration = Duration::from_secs(0); // In tests we don't want to wait for the file events because the it is a controlled environment

/// Error type for the local sync handler
#[derive(Error, Debug)]
pub enum LocalSyncError {
    /// Failed to infer the name of the tree
    #[error("Failed to infer the name of the tree")]
    InferNameError,
    /// IO Error
    #[error("IO Error")]
    Io(#[from] std::io::Error),
    /// Notify Error
    #[error("Notify Error")]
    Notify(#[from] notify::Error),
    #[error("Fs event thread closed")]
    ReceiverClosed,
    #[error("Failed to load ignore file")]
    IgnoreLoadError(#[from] ignore::Error),
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
    task::spawn_blocking(move || find_helper(path, tx))
        .await
        .expect("Paniced while loading ignore files");
    let mut ignore_files = Vec::new();
    while let Some(ignore) = rx.recv().await {
        ignore_files.push(ignore);
    }
    Ok(ignore_files)
}

pub struct WatcherReceiver {
    path: PathBuf,
    rx: broadcast::Receiver<Arc<Event>>,
    event_queue: Vec<Arc<Event>>,
}
impl WatcherReceiver {
    pub async fn recv(&mut self) -> Result<Vec<Arc<Event>>> {
        use LocalSyncError::ReceiverClosed;
        loop {
            tokio::select! {
                  event = self.rx.recv() => {
                     println!("Event: {:?}", event);
                     let event = event.map_err(|_| ReceiverClosed)?;
                     self.event_queue.push(event.clone());
                  }
                  _ = tokio::time::sleep(FILE_EVENT_DELAY) => {
                     if self.event_queue.is_empty() {
                        continue;
                     }
                     return Ok(std::mem::take(&mut self.event_queue));
               }
            }
        }
    }
}
struct IgnoreMap {
    map: HashMap<PathBuf, Gitignore>,
}
impl IgnoreMap {
    fn is_ignore(&self, path: &Path) -> bool {
        assert!(path.is_absolute(), "Path must be absolute");
        for ancestor in path.ancestors() {
            if let Some(ignore) = self.map.get(ancestor) {
                tracing::debug!("Checking ignore rules for: {}", ignore.path().display());
                let path = path
                    .strip_prefix(ancestor)
                    .expect("something went very wrong here");
                let should_ignore = ignore
                    .matched_path_or_any_parents(&path, path.is_dir())
                    .is_ignore();
                if should_ignore {
                    return true;
                }
                continue;
            }
        }
        false
    }
    async fn load(&mut self, path: PathBuf) -> Result<()> {
        let ignores = find_ignores(path).await?;
        self.map.extend(
            ignores
                .into_iter()
                .map(|ignore| (ignore.path().to_path_buf(), ignore)),
        );
        Ok(())
    }
    fn reload(&mut self, path: &Path) -> Result<()> {
        assert!(path.is_absolute(), "Path must be absolute");
        assert!(path.is_file(), "Path must be a file");
        let is_vaild_ignore_file = DEFAULT_IGNORE_FILES.contains(
            &path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .as_ref(),
        );
        assert!(is_vaild_ignore_file, "Path must be a valid ignore file");
        let mut builder =
            GitignoreBuilder::new(path.parent().expect("Path must have a parent it's a file"));
        // Maybe this is contrversial but using a Option for the error is a bit weird
        if let Some(err) = builder.add(path) {
            return Err(LocalSyncError::IgnoreLoadError(err));
        }
        let ignores = builder.build()?;
        self.map.insert(
            path.parent()
                .expect("Path must have a parent it's a file")
                .to_path_buf(),
            ignores,
        );
        Ok(())
    }
    fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}
deref_impl!(IgnoreMap, map, HashMap<PathBuf, Gitignore>);
/// Represents the watcher thread
pub struct WatcherThread {
    watcher: RecommendedWatcher,
    ignores: Arc<Mutex<IgnoreMap>>,
    rx: broadcast::Receiver<Arc<Event>>,
}
impl WatcherThread {
    pub fn init() -> Result<Self> {
        let (tx, rx) = broadcast::channel(100);
        let ignores = Arc::new(Mutex::new(IgnoreMap::new()));
        let watcher = {
            let ignores = ignores.clone();
            notify::recommended_watcher(move |res: notify::Result<Event>| {
                let Ok(mut event) = res else {
                    let error = res.unwrap_err();
                    tracing::error!("Failed to handle event due to error {}", error);
                    return;
                };
                {
                    let mut ignores = ignores.blocking_lock();
                    let mut paths = Vec::with_capacity(event.paths.len()); // Preallocate the vector assuming all paths will not be ignored
                    for path in std::mem::take(&mut event.paths) {
                        let file_name = path.file_name().unwrap_or_default().to_string_lossy();
                        let is_ignore_file = DEFAULT_IGNORE_FILES.contains(&file_name.as_ref());
                        let is_updated = event.kind.is_modify() || event.kind.is_create();
                        if is_ignore_file && is_updated {
                            if let Err(err) = ignores.reload(&path) {
                                tracing::error!(
                                    "Failed to reload ignore file due to error {}",
                                    err
                                );
                            }
                        } else if is_ignore_file && event.kind.is_remove() {
                            assert!(path.is_file(), "Path must be a file {path:?}");
                            ignores.remove(
                                &path
                                    .parent()
                                    .expect("File must have a parent")
                                    .to_path_buf(),
                            );
                        }
                        if ignores.is_ignore(&path) {
                            continue;
                        }
                        paths.push(path);
                    }
                    if paths.is_empty() {
                        return;
                    }
                    event.paths = paths;
                    assert!(event.paths.len() > 0, "Event must have at least one path");
                }
                if event.kind.is_modify() || event.kind.is_create() || event.kind.is_remove() {
                    tx.send(Arc::new(event)).expect("Failed to send event");
                }
            })?
        };
        Ok(Self {
            watcher,
            rx,
            ignores,
        })
    }

    pub async fn subscribe(&mut self, path: PathBuf) -> Result<WatcherReceiver> {
        use notify::RecursiveMode::Recursive;
        assert!(path.is_dir(), "Path must be a directory");
        // I will find a better way to do this check later since if a sub directory has a .gitignore file this is still redundant and wasteful but for now this will do
        {
            let mut ignores = self.ignores.lock().await;
            assert!(!ignores.is_ignore(&path), "Path must not be ignored");
            if !ignores.contains_key(&path) {
                ignores.load(path.clone()).await?;
            }
        }
        self.watcher.watch(&path, Recursive)?;
        let rx = self.rx.resubscribe();
        Ok(WatcherReceiver {
            path,
            rx,
            event_queue: Vec::new(),
        })
    }
}

deref_impl!(WatcherThread, watcher, RecommendedWatcher);

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
    use tokio::fs;
    let search_dir = std::env::temp_dir().join("fsync_test_ignore_rules");
    fs::remove_dir_all(&search_dir).await;
    fs::create_dir(&search_dir).await.unwrap();
    fs::write(&search_dir.join(".gitignore"), "/test.txt\n/test_dir")
        .await
        .unwrap();
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
}
#[tokio::test]
async fn test_sync_logic() {
    use tokio::fs;
    let search_dir = std::env::temp_dir().join("fsync_test_sync_logic");
    fs::remove_dir_all(&search_dir).await;
    fs::create_dir(&search_dir).await.unwrap();

    let mut watcher = WatcherThread::init().expect("Failed to initialize watcher");
    let mut sub = watcher
        .subscribe(search_dir.clone())
        .await
        .expect("Failed to subscribe to watcher");
    fs::write(&search_dir.join("test.txt"), "Hello World")
        .await
        .unwrap();
    if let Ok(events) = sub.recv().await {
        assert!(
            events
                .iter()
                .any(|event| event.paths.contains(&search_dir.join("test.txt"))),
            "test.txt should be created\n{events:?}"
        );
    }
    fs::write(&search_dir.join("test.txt"), "Hello World2")
        .await
        .unwrap();
    if let Ok(events) = sub.recv().await {
        assert!(
            events
                .iter()
                .any(|event| event.paths.contains(&search_dir.join("test.txt"))),
            "test.txt should be modified\n{events:?}"
        );
    }
    fs::rename(&search_dir.join("test.txt"), &search_dir.join("test2.txt"))
        .await
        .unwrap();
    if let Ok(events) = sub.recv().await {
        assert!(
            events
                .iter()
                .any(|event| event.paths.contains(&search_dir.join("test2.txt")))
        );
    }
    fs::copy(&search_dir.join("test2.txt"), &search_dir.join("test3.txt"))
        .await
        .unwrap();
    if let Ok(events) = sub.recv().await {
        assert!(
            events
                .iter()
                .any(|event| event.paths.contains(&search_dir.join("test3.txt"))),
        );
    }
    fs::remove_file(&search_dir.join("test3.txt"))
        .await
        .unwrap();
    if let Ok(events) = sub.recv().await {
        assert!(
            events
                .iter()
                .any(|event| event.paths.contains(&search_dir.join("test3.txt"))),
            "test3.txt should be removed\n{events:?}"
        );
    }
}
