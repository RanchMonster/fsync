use quinn::{Connection, ConnectionError, ConnectionId, Incoming};
use std::{
   collections::{HashMap, HashSet},
   sync::{Arc, LazyLock},
   time::SystemTime,
};
use tokio::sync::RwLock;
mod known_peer;

static SESSIONS: LazyLock<RwLock<HashMap<ConnectionId, SessionInfo>>> =
   LazyLock::new(|| RwLock::new(HashMap::new()));
/// Stores information about the session
struct SessionInfo; // TODO: Implement

pub async fn handle_incoming(incoming: Incoming) {
   todo!("handle incoming connection")
}
