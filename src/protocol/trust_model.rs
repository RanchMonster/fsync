use std::{
   fs::File,
   io::{BufRead, BufReader, Read, Write},
};

use crate::CONFIG_DIR;
use hex::FromHexError;
use rustls::{
   client::danger::{ServerCertVerified, ServerCertVerifier},
   crypto::WebPkiSupportedAlgorithms,
   pki_types::{CertificateDer, ServerName, UnixTime},
};
use tracing::instrument;
fn decode_hex_peer_id(hex_peer_id: &str) -> Result<[u8; 32], hex::FromHexError> {
   let decoded_peer_id = hex::decode(hex_peer_id)?;
   if decoded_peer_id.len() != 32 {
      return Err(FromHexError::InvalidStringLength);
   }
   Ok(decoded_peer_id
      .try_into()
      .expect("Failed to convert to array"))
}

/// Fingerprints a public key as a Hex string of 8 bytes
/// This function is intended for user verification
/// ```no_run
/// # let new_peer_public_key: &[u8] = &[];
/// let human_readable_fingerprint = fingerprint(&new_peer_public_key);
/// println!("Verify the fingerprint of the new device: {human_readable_fingerprint}");
/// print!("Do you want to trust this device? [y/n]: ");
/// let mut input = String::new();
/// std::io::stdin().read_line(&mut input).expect("Failed to read input");
/// if input.trim().to_lowercase() == "y" {
///     // Add the new peer to the trusted list
/// }
/// ```
///
pub fn fingerprint(public_key: &[u8]) -> String {
   let hash = blake3::hash(public_key);
   hash
      .as_bytes()
      .iter()
      .take(8)
      .map(|byte| format!("{byte:02x}"))
      .collect::<String>()
}

#[instrument]
pub fn fetch_known_peer(peer_name: &str) -> Option<[u8; 32]> {
   let path = CONFIG_DIR.join("known_peers");
   assert!(path.exists(), "Known peers file does not exist");
   let file = BufReader::new(File::open(path).expect("Failed to open known peers file"));
   let buffered = BufReader::new(file);

   // I thought about it and found that actually just using a iterator is faster and more memory efficient (I can send you the articles and videos if you want)
   buffered.lines().find_map(|line| {
      let line = line.expect("Failed to read line");
      let mut fields = line.split_whitespace();
      let (Some(name), Some(hex_peer_id)) = (fields.next(), fields.next()) else {
         tracing::warn!("Invalid known peer line: {line}");
         return None;
      };
      let is_valid_name = !name.is_empty()
         && name.len() <= 15
         // I had to type hint for some reason
         && !name.contains(|c: char| c.is_whitespace() || !c.is_ascii_alphanumeric());
      if !is_valid_name {
         tracing::warn!("Invalid known peer name: {name}");
         return None;
      }
      let Ok(decoded_peer_id) = decode_hex_peer_id(hex_peer_id) else {
         tracing::warn!("Invalid known peer ID: {hex_peer_id}");
         return None;
      };
      Some(decoded_peer_id)
   })
}
#[instrument]
pub fn add_known_peer(peer_name: String, peer_id: [u8; 32]) {
   assert!(!peer_name.is_empty(), "Peer name must not be empty");
   assert!(
      peer_name.len() <= 15,
      "Peer name must be at most 15 characters"
   );
   assert!(
      !peer_name.contains(char::is_whitespace),
      "Peer name must not contain whitespace"
   );

   let path = CONFIG_DIR.join("known_peers");
   assert!(path.exists(), "Known peers file does not exist");

   if fetch_known_peer(&peer_name).is_some() {
      tracing::warn!(
         "Peer {peer_name} already known if you are trying to update the peer ID you will need to remove the old peer first"
      );
      return;
   }

   let peer_id = hex::encode(peer_id);
   let mut file = File::options()
      .append(true)
      .open(path)
      .expect("Failed to open known peers file");
   if file.metadata().expect("Failed to get metadata").len() > 0 {
      let mut last_char = [0];
      file
         .read_exact(&mut last_char)
         .expect("Failed to read last character");
      if last_char[0] != b'\n' {
         file.write_all(b"\n").expect("Failed to write newline");
      }
   }
   writeln!(file, "{peer_name} {peer_id}").expect("Failed to write to known peers file");
}
#[derive(Debug)] //switched to derive Debug
pub struct PeerVerifier {
   supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PeerVerifier {
   fn verify_tls12_signature(
      &self, message: &[u8], cert: &CertificateDer<'_>, dss: &rustls::DigitallySignedStruct,
   ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
      rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
   }
   fn verify_tls13_signature(
      &self, message: &[u8], cert: &CertificateDer<'_>, dss: &rustls::DigitallySignedStruct,
   ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
      rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
   }
   fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
      self.supported.supported_schemes()
   }
   #[instrument(skip(end_entity, _intermediates, _ocsp_response))]
   fn verify_server_cert(
      &self, end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>],
      server_name: &ServerName<'_>, _ocsp_response: &[u8], _now: UnixTime,
   ) -> Result<ServerCertVerified, rustls::Error> {
      // Parse certificate
      let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref())
         .map_err(|_| rustls::Error::General("Invalid certificate".into()))?;

      // Extract public key
      let public_key = &cert.public_key().subject_public_key.data;

      // Hash it
      let peer_id = blake3::hash(public_key);
      // substr the name to 15 characters (without cloning the string to avoid allocating)

      let full_name = server_name.to_str();
      let max_name_length = 15.min(full_name.len());
      let peer_name = &full_name[..max_name_length];

      let Some(expected_peer_id) = fetch_known_peer(peer_name) else {
         return Err(rustls::Error::General("Unknown peer".into()));
      };
      if *peer_id.as_bytes() != expected_peer_id {
         return Err(rustls::Error::General("Unknown peer".into()));
      }

      Ok(ServerCertVerified::assertion())
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   use std::fs;

   fn setup() {
      let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
      let path = CONFIG_DIR.join("known_peers");
      if !path.exists() {
         fs::write(&path, "").expect("Failed to create test known_peers file");
      }
   }

   fn cleanup_known_peers() {
      let path = CONFIG_DIR.join("known_peers");
      let _ = fs::remove_file(path);
   }

   fn generate_test_cert() -> (CertificateDer<'static>, [u8; 32]) {
      let rcgen::CertifiedKey { cert, .. } =
         rcgen::generate_simple_self_signed(vec!["test-peer".to_string()]).unwrap();
      let cert_der = cert.der().clone();
      let (_, parsed) = x509_parser::parse_x509_certificate(cert_der.as_ref()).unwrap();
      let public_key = &parsed.public_key().subject_public_key.data;
      let hash = blake3::hash(public_key);
      let peer_id = *hash.as_bytes();
      (cert_der, peer_id)
   }

   #[test]
   fn test_fingerprint() {
      setup();
      let key = [0xAB; 32];
      let fp = fingerprint(&key);
      assert_eq!(fp.len(), 16, "fingerprint should be 16 hex chars");
      assert_eq!(fp, fingerprint(&key), "fingerprint should be deterministic");
      assert_ne!(fp, fingerprint(&[0xCD; 32]));
   }

   #[test]
   fn test_add_and_fetch_round_trip() {
      setup();
      let peer_id = [0x42; 32];
      fs::write(CONFIG_DIR.join("known_peers"), "").unwrap();
      add_known_peer("alice".into(), peer_id);

      let result = fetch_known_peer("alice".into());
      assert!(result.is_some(), "should find alice");
      assert_eq!(result.unwrap(), peer_id);

      assert!(fetch_known_peer("bob".into()).is_none());

      // Malformed lines are skipped, not panicked
      fs::write(
         CONFIG_DIR.join("known_peers"),
         "bad line here\nvalid_peer 0000000000000000000000000000000000000000000000000000000000000000\n",
      )
      .unwrap();
      let result = fetch_known_peer("valid_peer".into());
      assert!(result.is_some());

      cleanup_known_peers();
   }

   #[test]
   fn test_verify_server_cert_accepted() {
      setup();
      let (cert_der, peer_id) = generate_test_cert();
      let verifier = PeerVerifier {
         supported: rustls::crypto::CryptoProvider::get_default()
            .unwrap()
            .signature_verification_algorithms,
      };

      let server_name = ServerName::try_from("test-peer").unwrap();
      let result = verifier.verify_server_cert(&cert_der, &[], &server_name, &[], UnixTime::now());
      assert!(result.is_ok(), "should accept matching peer");
   }

   #[test]
   fn test_verify_server_cert_wrong_peer() {
      setup();
      let (cert_der, _) = generate_test_cert();
      let verifier = PeerVerifier {
         supported: rustls::crypto::CryptoProvider::get_default()
            .unwrap()
            .signature_verification_algorithms,
      };

      let server_name = ServerName::try_from("test-peer").unwrap();
      let result = verifier.verify_server_cert(&cert_der, &[], &server_name, &[], UnixTime::now());
      assert!(result.is_err(), "should reject mismatched peer");
   }
}
