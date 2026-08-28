use fsync::protocol::p2p_auth::{
   AuthCommands, PairMode, configure_client, configure_server, handle_incoming, pair_peer,
};
use quinn::{Connecting, Incoming};
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
