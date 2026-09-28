use std::fs;

use fsync::p2p::known_peer::{PeerId, add_known_peer, get_known_peer, known_peers_file_path};

/// Every test in this binary shares one `known_peers` file, so each test uses
/// its own peer id and only asserts about its own entry. None of these tests
/// truncates or rewrites the file, so they stay independent of each other and of
/// the order they run in.
fn unique_peer_id(byte: u8) -> PeerId {
   PeerId([byte; 32])
}

fn entry_for(peer_id: &PeerId) -> String {
   let contents = fs::read_to_string(known_peers_file_path()).unwrap();
   contents
      .lines()
      .find(|line| line.starts_with(&peer_id.to_string()))
      .unwrap_or_else(|| panic!("no entry found for {peer_id}"))
      .to_string()
}

#[test]
fn add_known_peer_then_get_known_peer_returns_it() {
   let peer_id = unique_peer_id(0x11);
   let name = "add_then_get_peer";

   add_known_peer(&peer_id, name).unwrap();

   let peer_info = get_known_peer(&peer_id)
      .unwrap()
      .expect("peer should be known");
   assert_eq!(peer_info.peer_id, peer_id);
   assert_eq!(peer_info.name, name);
}

#[test]
fn add_known_peer_keeps_previously_added_peers() {
   let first_id = unique_peer_id(0x21);
   let second_id = unique_peer_id(0x22);

   add_known_peer(&first_id, "first_peer").unwrap();
   add_known_peer(&second_id, "second_peer").unwrap();

   assert_eq!(
      get_known_peer(&first_id).unwrap().expect("first").name,
      "first_peer"
   );
   assert_eq!(
      get_known_peer(&second_id).unwrap().expect("second").name,
      "second_peer"
   );
}

#[test]
fn get_known_peer_does_not_modify_the_file() {
   let peer_id = unique_peer_id(0x31);
   add_known_peer(&peer_id, "untouched_peer").unwrap();
   let before = entry_for(&peer_id);

   get_known_peer(&peer_id)
      .unwrap()
      .expect("peer should be known");

   assert_eq!(
      entry_for(&peer_id),
      before,
      "looking a peer up must not rewrite its entry"
   );
}

#[test]
fn get_known_peer_returns_none_for_an_unlisted_peer() {
   let unlisted_id = unique_peer_id(0xff);
   let listed_id = unique_peer_id(0x41);
   add_known_peer(&listed_id, "listed_peer").unwrap();

   assert!(
      get_known_peer(&unlisted_id).unwrap().is_none(),
      "a peer that was never added should be unknown"
   );
   assert!(
      get_known_peer(&listed_id).unwrap().is_some(),
      "adding a peer should not stop it being found"
   );
}
