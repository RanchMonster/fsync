use std::fs;

use fsync::p2p::known_peer::{PeerId, get_known_peer, known_peers_file_path};

/// These tests all rewrite the whole file, so they must not run concurrently.
/// NOTE: must be bound to a variable — a bare `repair_lock();` drops the guard
/// immediately and serialises nothing.
fn repair_lock() -> std::sync::MutexGuard<'static, ()> {
   static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
   LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Both tests in this binary repair the file, which is a whole-file rewrite, so
/// neither may observe the other's `fs::write`: they serialise on `repair_lock`.
/// Every other test in `known_peer.rs` lives in a separate binary (and therefore
/// a separate process) and is unaffected by these rewrites.
#[test]
fn get_known_peer_repairs_a_malformed_file() {
   let _guard = repair_lock();
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

/// A repair must also scrub control characters out of names that older
/// versions wrote, not just drop malformed lines. The short first line forces
/// the repair; the hostile name sits on a later line so it cannot stop the
/// lookup that triggers it.
#[test]
fn repairing_the_file_sanitizes_hostile_names() {
   let _guard = repair_lock();
   const KNOWN_ID: PeerId = PeerId([0x51; 32]);
   let hostile_id = PeerId([0x52; 32]);
   fs::write(
      known_peers_file_path(),
      format!("bad line\n{KNOWN_ID}\talice\n{hostile_id}\tbob\u{1b}[31m\n"),
   )
   .unwrap();

   get_known_peer(&KNOWN_ID)
      .unwrap()
      .expect("a listed peer should still be found in a malformed file");

   let repaired = fs::read_to_string(known_peers_file_path()).unwrap();
   assert!(
      repaired.lines().all(|line| line
         .split_once('\t')
         .map(|(_, name)| !name.chars().any(char::is_control))
         .unwrap_or(true)),
      "a repair must scrub control characters from stored names, got {:?}",
      repaired
   );
   assert!(
      get_known_peer(&hostile_id).unwrap().is_some(),
      "the hostile entry itself must survive the repair"
   );
}
