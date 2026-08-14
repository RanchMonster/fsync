use fsync::CONFIG_DIR;
use fsync::protocol::p2p_auth::{
   AuthCommands, KnownPeer, PairMode, configure_client, configure_server, handle_incoming,
   is_known_peer, pair_peer,
};
use quinn::{Connecting, Incoming};
use rand::random;
use std::str::FromStr;
use tokio::task::JoinSet;

const TEST_SOCKET_ADDR: &str = "127.0.0.1:0"; // use localhost to avoid firewall issues
static KNOWN_PEERS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn setup_config_dir() {
   // Point CONFIG_DIR at a temp directory so the tests don't touch the real
   // config directory. Must be called before CONFIG_DIR is first used.
   let dir = std::env::temp_dir().join("fsync-p2p-auth-tests");
   unsafe {
      std::env::set_var("FSYNC_CONFIG_DIR", &dir);
   }
}

#[test]
fn test_known_peer_comparison() {
   let random_key = random::<[u8; 32]>();
   let peer = KnownPeer(random_key);
   let hexed_key = hex::encode(random_key);
   let prased_key = KnownPeer::from_str(&hexed_key).expect("failed to parse known peer");
   assert_eq!(peer, prased_key);
}

#[test]
fn test_is_known_peers_found() {
   setup_config_dir();
   let _guard = KNOWN_PEERS_LOCK
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
   let known_key = random::<[u8; 32]>();
   let other_key = random::<[u8; 32]>();
   let path = CONFIG_DIR.join("known_peers");
   let contents = format!(
      "{}\n\n{}\n{}\n",
      KnownPeer(other_key),
      "not-a-valid-hex-line",
      KnownPeer(known_key)
   );
   std::fs::write(&path, contents).expect("failed to write known peers file");
   assert!(is_known_peer(&known_key));
   assert!(is_known_peer(&other_key));
   assert!(!is_known_peer(&random::<[u8; 32]>()));
   let _ = std::fs::remove_file(&path);
}

#[test]
fn test_is_known_peers_missing_file() {
   setup_config_dir();
   let _guard = KNOWN_PEERS_LOCK
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
   let _ = std::fs::remove_file(CONFIG_DIR.join("known_peers"));
   assert!(!is_known_peer(&random::<[u8; 32]>()));
}

async fn connecting_peer(connect_attempt: Connecting) {
   let mut connection = connect_attempt.await.expect("failed to connect");
   // send pairing request
   connection
      .send_datagram(AuthCommands::PAIR.into())
      .expect("failed to send pairing request");
   pair_peer(&mut connection, None)
      .await
      .expect("failed to pair peer");
}

async fn responding_peer(incoming: Incoming, pair_mode: PairMode) {
   handle_incoming(incoming, &pair_mode)
      .await
      .expect("failed to handle incoming connection");
}

#[tokio::test]
async fn test_pair_peer_relaxed() {
   use quinn::Endpoint;
   setup_config_dir();
   let _guard = KNOWN_PEERS_LOCK
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
   // generate key and cert for virtual peers
   let server_config =
      configure_server("test-peer-server").expect("failed to configure server crypto");
   let client_config =
      configure_client("test-peer-client").expect("failed to configure client crypto");
   // initialize the quic server
   let server = Endpoint::server(
      server_config,
      TEST_SOCKET_ADDR.parse().expect("invalid socket addr"),
   )
   .expect("failed to create server endpoint");

   // reuse the same endpoint to connect to the host peer
   let local_addr = server.local_addr().expect("failed to get local addr");
   let connection = server
      .connect_with(client_config, local_addr, "test-peer-server")
      .expect("failed to connect to server");
   let mut task_set = JoinSet::new();
   task_set.spawn(connecting_peer(connection));
   task_set.spawn(responding_peer(
      server.accept().await.expect("failed to accept connection"),
      PairMode::Relaxed,
   ));
   task_set.join_all().await;
}
