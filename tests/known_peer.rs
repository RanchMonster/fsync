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

/// A name that tries to inject a second, well-formed entry must not be able to
/// break the one-peer-per-line format: the stored name is neutralized and the
/// smuggled id never becomes a known peer.
#[test]
fn add_known_peer_does_not_allow_injecting_a_second_entry() {
   let real_id = unique_peer_id(0x61);
   let attacker_id = unique_peer_id(0x62);
   let malformed_name = format!("alice\n{}\tattacker", attacker_id);

   add_known_peer(&real_id, &malformed_name).unwrap();

   let peer_info = get_known_peer(&real_id)
      .unwrap()
      .expect("the real peer should be known");
   assert_eq!(peer_info.peer_id, real_id);
   assert_eq!(
      peer_info.name,
      format!("alice {} attacker", attacker_id),
      "a stored name must keep the hostile newline neutralized, got {:?}",
      peer_info.name
   );

   // The file is shared with the other tests in this binary, so this checks the
   // lines belonging to the ids involved rather than the total line count: one
   // line starts with the real id, and none start with the attacker id.
   let contents = fs::read_to_string(known_peers_file_path()).unwrap();
   let real_prefix = real_id.to_string();
   let attacker_prefix = attacker_id.to_string();
   let lines: Vec<&str> = contents.lines().collect();

   assert_eq!(
      lines
         .iter()
         .filter(|line| line.starts_with(&real_prefix))
         .count(),
      1,
      "exactly one line may start with the real id"
   );
   assert!(
      !lines.iter().any(|line| line.starts_with(&attacker_prefix)),
      "no line may start with the attacker id"
   );
   assert!(
      get_known_peer(&attacker_id).unwrap().is_none(),
      "a peer smuggled through a name must not become known"
   );
}
