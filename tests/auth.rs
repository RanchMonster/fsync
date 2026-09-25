use std::{
   fs,
   net::SocketAddr,
   str::FromStr,
   sync::{Once, OnceLock},
};

use fsync::{
   DATA_DIR,
   p2p::PeerId,
   p2p::auth::{
      AuthCommands, AuthError, configure_client, configure_server, generate_pairing_key,
      get_peer_id, handle_connecting, handle_incoming, is_known_peer, pair_peer,
   },
};
use quinn::{Connecting, Connection, Endpoint, Incoming};
use tokio::task;

const TEST_SOCKET_ADDR: &str = "127.0.0.1:0"; // use localhost to avoid firewall issues

fn setup() -> &'static Endpoint {
   static ONCE: OnceLock<Endpoint> = OnceLock::new();
   ONCE.get_or_init(|| {
      // Point CONFIG_DIR at a temp directory so the tests don't touch the real
      // config directory. Must be called before CONFIG_DIR is first used.
      let dir = std::env::temp_dir().join("fsync-p2p-auth-tests");
      let items = fs::read_dir(&dir).map(|dir| dir.count()).unwrap_or(0);
      println!("items: {items}");
      unsafe {
         std::env::set_var("FSYNC_CONFIG_DIR", &dir);
         std::env::set_var("FSYNC_DATA_DIR", &dir);
      }
      // generate key and cert for virtual peers
      let server_config =
         configure_server("test-peer-server").expect("failed to configure server crypto");
      let client_config =
         configure_client("test-peer-client").expect("failed to configure client crypto");
      let mut endpoint = quinn::Endpoint::server(
         server_config,
         TEST_SOCKET_ADDR.parse().expect("invalid socket addr"),
      )
      .expect("failed to create server endpoint");
      endpoint.set_default_client_config(client_config);
      endpoint
   })
}

async fn accept_task(endpoint: &'static Endpoint) {
   loop {
      let incoming = endpoint.accept().await.expect("no incoming connection");
      let _ = handle_incoming(incoming).await;
   }
}

async fn pair_task(endpoint: &'static Endpoint, addr: SocketAddr) -> Result<(), AuthError> {
   let pairing_key = generate_pairing_key().expect("failed to generate pairing key");
   let connecting = endpoint
      .connect(addr, "test-peer-client")
      .expect("failed to connect");

   pair_peer(connecting, || Some(pairing_key)).await?;
   Ok(())
}
async fn connect_task(endpoint: &'static Endpoint, addr: SocketAddr) -> Result<(), AuthError> {
   let connecting = endpoint
      .connect(addr, "test-peer-server")
      .expect("failed to connect");
   handle_connecting(connecting).await?;
   Ok(())
}

#[tokio::test]
async fn auth() {
   let endpoint = setup();
   let local_addr = endpoint.local_addr().expect("failed to get local addr");
   {
      let peer_id = get_peer_id("test-peer-client").expect("failed to get peer id");
      println!("data dir: {}", DATA_DIR.display());
      assert!(
         !is_known_peer(&peer_id).expect("failed to check peer id"),
         "peer should not be known at this point"
      );
   }

   // spawn a task to accept connections
   task::spawn(accept_task(endpoint));
   if connect_task(endpoint, local_addr).await.is_ok() {
      panic!("Peer connected without being known");
   }
   pair_task(endpoint, local_addr)
      .await
      .expect("Failed to pair");

   connect_task(endpoint, local_addr)
      .await
      .expect("Failed to reconnect after pairing")
}
