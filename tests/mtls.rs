use fsync::CONFIG_DIR;
use fsync::protocol::p2p_auth::mtls::{cache_path, generate_self_signed_cert};
use rustls::pki_types::PrivateKeyDer;
use std::fs;

fn setup_config_dir() {
   // Point CONFIG_DIR at a temp directory so the tests don't touch the real
   // config directory. Must be called before CONFIG_DIR is first used.
   let dir = std::env::temp_dir().join("fsync-mtls-tests");
   unsafe {
      std::env::set_var("FSYNC_CONFIG_DIR", &dir);
   }
}

fn clear_certs(name: &str) {
   let Ok((cert_path, key_path)) = cache_path(name) else {
      return;
   };
   let _ = fs::remove_file(&cert_path);
   let _ = fs::remove_file(&key_path);
}

#[test]
fn test_cache_path() {
   setup_config_dir();
   let (cert_path, key_path) = cache_path("test-node").expect("Failed to get cache path");
   let dir = CONFIG_DIR.join("certs");
   assert_eq!(cert_path, dir.join("test-node.cert.der"));
   assert_eq!(key_path, dir.join("test-node.key.der"));
}

#[test]
fn test_generate_caches_files() {
   setup_config_dir();
   let name = "test-cache-files";
   clear_certs(name);
   let (cert_path, _) = cache_path(name).expect("Failed to get cache path");
   assert!(
      !cert_path.exists(),
      "cache should not exist before generation"
   );

   generate_self_signed_cert(name).expect("Failed to generate cert");
   assert!(
      cert_path.exists(),
      "cert file should exist after generation"
   );
}

#[test]
fn test_cache_preserves_identity() {
   setup_config_dir();
   let name = "test-cache-identity";
   clear_certs(name);

   let (certs_a, key_a) = generate_self_signed_cert(name).expect("Failed to generate cert");
   let (certs_b, key_b) = generate_self_signed_cert(name).expect("Failed to generate cert");

   assert_eq!(
      certs_a[0].as_ref(),
      certs_b[0].as_ref(),
      "cached cert must match"
   );
   match (&key_a, &key_b) {
      (PrivateKeyDer::Pkcs8(a), PrivateKeyDer::Pkcs8(b)) => assert_eq!(
         a.secret_pkcs8_der(),
         b.secret_pkcs8_der(),
         "cached key must match"
      ),
      _ => panic!("unexpected key format"),
   }
}

#[test]
fn test_different_names_different_certs() {
   setup_config_dir();
   clear_certs("test-diff-a");
   clear_certs("test-diff-b");

   let (certs_a, _) = generate_self_signed_cert("test-diff-a").expect("Failed to generate cert");
   let (certs_b, _) = generate_self_signed_cert("test-diff-b").expect("Failed to generate cert");

   assert_ne!(
      certs_a[0].as_ref(),
      certs_b[0].as_ref(),
      "different nodes must have different certs"
   );
}

#[test]
fn test_cache_survives_multiple_calls() {
   setup_config_dir();
   let name = "test-cache-multi";
   clear_certs(name);

   let (certs_first, _) = generate_self_signed_cert(name).expect("Failed to generate cert");
   let (cert_path, _) = cache_path(name).expect("Failed to get cache path");
   fs::remove_file(&cert_path).expect("Failed to remove cache file");

   let (certs_second, _) = generate_self_signed_cert(name).expect("Failed to generate cert");
   assert_ne!(
      certs_first[0].as_ref(),
      certs_second[0].as_ref(),
      "removing the cache should produce a new cert"
   );
}

#[test]
fn test_cache_not_recreated_on_subsequent_calls() {
   setup_config_dir();
   let name = "test-no-recreate";
   clear_certs(name);

   let (cert_path, key_path) = cache_path(name).expect("Failed to get cache path");
   generate_self_signed_cert(name).expect("Failed to generate cert");
   let cert_modified = fs::metadata(&cert_path)
      .expect("Failed to read metadata")
      .modified()
      .expect("Failed to read modified time");
   let key_modified = fs::metadata(&key_path)
      .expect("Failed to read metadata")
      .modified()
      .expect("Failed to read modified time");

   generate_self_signed_cert(name).expect("Failed to generate cert");
   assert_eq!(
      fs::metadata(&cert_path)
         .expect("Failed to read metadata")
         .modified()
         .expect("Failed to read modified time"),
      cert_modified,
      "cache should not be recreated on second call"
   );
   assert_eq!(
      fs::metadata(&key_path)
         .expect("Failed to read metadata")
         .modified()
         .expect("Failed to read modified time"),
      key_modified,
      "cache should not be recreated on second call"
   );
}
