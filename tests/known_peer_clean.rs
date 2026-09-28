use std::fs;

use fsync::p2p::known_peer::{PeerId, get_known_peer, known_peers_file_path};

/// Repairing the file is a whole-file rewrite, so this behaviour is the only
/// thing in this test binary: every other test in `known_peer.rs` shares the
/// process (and therefore the file) and must not be disturbed by a rewrite.
#[test]
fn get_known_peer_repairs_a_malformed_file() {
   const KNOWN_NAME: &str = "surviving_peer";
   let known_id = PeerId([0x51; 32]);
   let known_entry = format!("{known_id}\t{KNOWN_NAME}");

   fs::write(
      known_peers_file_path(),
      format!("bad line\n{known_entry}\n{known_entry}\n"),
   )
   .unwrap();

   let peer_info = get_known_peer(&known_id)
      .unwrap()
      .expect("a listed peer should still be found in a malformed file");
   assert_eq!(peer_info.peer_id, known_id);
   assert_eq!(peer_info.name, KNOWN_NAME);

   let repaired = fs::read_to_string(known_peers_file_path()).unwrap();
   assert_eq!(
      repaired,
      format!("{known_entry}\n"),
      "the malformed line should be dropped and the duplicate collapsed"
   );

   get_known_peer(&known_id)
      .unwrap()
      .expect("peer should be known");
   assert_eq!(
      fs::read_to_string(known_peers_file_path()).unwrap(),
      repaired,
      "looking a peer up in a clean file must not rewrite it"
   );
}
