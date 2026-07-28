use std::{
   fs::File,
   io::{BufRead, BufReader},
};

use rustls::{
   client::danger::{ServerCertVerified, ServerCertVerifier},
   crypto::WebPkiSupportedAlgorithms,
   pki_types::{CertificateDer, ServerName, UnixTime},
};
use tracing::instrument;

/// Fingerprints a public key as a Hex string of 8 bytes
/// This function is intended for user verification
/// ```
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
pub fn fetch_known_peer(peer_name: String) -> Option<PeerVerifier> {
   let path = crate::CONFIG_DIR.join("known_peers");
   assert!(path.exists(), "Known peers file does not exist");
   let file = BufReader::new(File::open(path).expect("Failed to open known peers file"));
   for line in file.lines() {
      let line = line.expect("Failed to read line");
      let items = line.split_whitespace().collect::<Vec<&str>>();
      if items.len() != 2 {
         tracing::warn!("Invalid known peer line: {line}");
         continue;
      }
      let name = items[0];
      assert!(name.len() > 0, "Known peer name must not be empty");
      assert!(
         name.len() <= 15,
         "Known peer name must be at most 15 characters"
      );
      if name != peer_name {
         continue;
      }
      let hex_peer_id = items[1];
      let decoded_peer_id = match hex::decode(hex_peer_id) {
         Ok(decoded) => decoded,
         Err(err) => {
            tracing::error!("Failed to decode peer ID line: {line} due to error {err}");
            continue;
         }
      };
      assert!(
         decoded_peer_id.len() == 32,
         "Peer ID must be 32 bytes exactly"
      );
      return Some(PeerVerifier {
         expected_peer_id: decoded_peer_id
            .try_into()
            .expect("Failed to convert to array"),
         supported: rustls::crypto::CryptoProvider::get_default()
            .expect("No default crypto provider installed")
            .signature_verification_algorithms,
      });
   }
   None
}
struct PeerVerifier {
   expected_peer_id: [u8; 32],
   supported: WebPkiSupportedAlgorithms,
}

impl std::fmt::Debug for PeerVerifier {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      f.debug_struct("PeerVerifier")
         .field("expected_peer_id", &hex::encode(self.expected_peer_id))
         .finish()
   }
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
   #[instrument]
   fn verify_server_cert(
      &self, end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>],
      _server_name: &ServerName<'_>, _ocsp_response: &[u8], _now: UnixTime,
   ) -> Result<ServerCertVerified, rustls::Error> {
      // Parse certificate
      let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref())
         .map_err(|_| rustls::Error::General("Invalid certificate".into()))?;

      // Extract public key
      let public_key = &cert.public_key().subject_public_key.data;

      // Hash it
      let peer_id = blake3::hash(public_key);

      if peer_id.as_bytes() != &self.expected_peer_id {
         return Err(rustls::Error::General("Unknown peer".into()));
      }

      Ok(ServerCertVerified::assertion())
   }
}
