//! mTLS configuration for fsync's QUIC connections.
//!
//! This module builds the quinn TLS configs used by fsync's endpoints.
//! Because fsync peers do not have certificates issued by a shared CA, each
//! device generates a self-signed certificate on first use and caches it (and
//! its key) by `name` in `CONFIG_DIR/certs`, giving a device a stable
//! identity across restarts.
//!
//! [`configure_server`] enables client authentication with a verifier that
//! checks the client certificate's signature but not its chain of trust;
//! [`configure_client`] skips server certificate validation entirely. Peer
//! authenticity is instead established by the application-layer handshake in
//! the parent `p2p_auth` module.
use crate::CONFIG_DIR;
use quinn::{
   ClientConfig, ServerConfig,
   crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{fs, path::PathBuf, sync::Arc};
use tracing::instrument;
// So as far as tls goes, I am less concerned with the errors here because in most cases they are
// not things that can be recovered from and I am just going to use tracing and likely panicing
// further up the stack to handle these errors.
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const PROTOCOL_NAME: &str = concat!("fsync", env!("CARGO_PKG_VERSION"));

/// Returns the on-disk paths for the cached certificate and private key for
/// the given name, creating the `CONFIG_DIR/certs` directory (permissioned
/// `0o700` on unix) if it does not exist.
#[instrument]
fn cache_path(name: &str) -> std::io::Result<(PathBuf, PathBuf)> {
   let dir = CONFIG_DIR.join("certs");
   fs::create_dir_all(&dir)?;
   #[cfg(unix)]
   fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
   Ok((
      dir.join(format!("{name}.cert.der")),
      dir.join(format!("{name}.key.der")),
   ))
}

/// Returns a self-signed certificate chain and private key for the given
/// name, generating and caching them on first use.
///
/// If both the cached cert and key files already exist under
/// `CONFIG_DIR/certs`, they are loaded and returned instead of regenerated.
/// Otherwise a new self-signed certificate (with the name as its DNS subject
/// alternative name) is generated, written to disk, and returned.
///
/// # Errors
///
/// Returns a boxed error if the cache files cannot be read or written, or if
/// the certificate or key cannot be generated.
#[instrument]
fn generate_self_signed_cert(
   name: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
   let (cert_path, key_path) = cache_path(name)?;
   if cert_path.exists() && key_path.exists() {
      let cert_bytes = fs::read(&cert_path)?;
      let key_bytes = fs::read(&key_path)?;
      return Ok((
         vec![CertificateDer::from(cert_bytes)],
         PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes)),
      ));
   }

   let mut params = CertificateParams::default();
   params.subject_alt_names = vec![rcgen::SanType::DnsName(name.try_into()?)];

   let key_pair = KeyPair::generate()?;
   let cert = params.self_signed(&key_pair)?;

   let cert_der = CertificateDer::from(cert.der().to_vec());
   let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

   fs::write(&cert_path, cert_der.as_ref())?;
   fs::write(&key_path, key_pair.serialize_der())?;
   // Set the permissions of the key file to 0o600 (rw-------)
   // also I am aware of the potential for a race to read the file before permissions are set but
   // I don't think we need to harden this to that level of security just something to be aware of
   // in the future if I ever want to harden this further (someone else is more then welcome to
   // submit a PR to do this I just don't want to be the one to do it)
   #[cfg(unix)]
   fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
   Ok((vec![cert_der], key_der))
}

/// Verifies a TLS 1.2 handshake signature against the given certificate using
/// the default crypto provider's signature verification algorithms.
fn verify_signature_tls12(
   message: &[u8], cert: &CertificateDer<'_>, dss: &rustls::DigitallySignedStruct,
) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
   let provider =
      rustls::crypto::CryptoProvider::get_default().expect("a default CryptoProvider is installed");
   rustls::crypto::verify_tls12_signature(
      message,
      cert,
      dss,
      &provider.signature_verification_algorithms,
   )
}

/// Verifies a TLS 1.3 handshake signature against the given certificate using
/// the default crypto provider's signature verification algorithms.
fn verify_signature_tls13(
   message: &[u8], cert: &CertificateDer<'_>, dss: &rustls::DigitallySignedStruct,
) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
   let provider =
      rustls::crypto::CryptoProvider::get_default().expect("a default CryptoProvider is installed");
   rustls::crypto::verify_tls13_signature(
      message,
      cert,
      dss,
      &provider.signature_verification_algorithms,
   )
}

/// Server-side certificate verifier that authenticates client certificates.
///
/// Client authentication is offered but not mandatory. The certificate's
/// handshake signature is verified against the supported schemes, but no
/// trust chain is checked (`verify_client_cert` always accepts the
/// certificate). Peer authenticity is established later by the
/// application-layer handshake in the parent `p2p_auth` module.
#[derive(Debug)]
struct SignatureVerifyingClientVerifier;

impl rustls::server::danger::ClientCertVerifier for SignatureVerifyingClientVerifier {
   fn offer_client_auth(&self) -> bool {
      true
   }
   fn client_auth_mandatory(&self) -> bool {
      false
   }
   fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
      &[]
   }
   fn verify_client_cert(
      &self, _end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>],
      _now: rustls::pki_types::UnixTime,
   ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
      Ok(rustls::server::danger::ClientCertVerified::assertion())
   }
   fn verify_tls12_signature(
      &self, message: &[u8], cert: &CertificateDer<'_>, dss: &rustls::DigitallySignedStruct,
   ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
      verify_signature_tls12(message, cert, dss)
   }
   fn verify_tls13_signature(
      &self, message: &[u8], cert: &CertificateDer<'_>, dss: &rustls::DigitallySignedStruct,
   ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
      verify_signature_tls13(message, cert, dss)
   }
   fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
      vec![
         rustls::SignatureScheme::ED25519,
         rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
      ]
   }
}

/// Builds a quinn [`ServerConfig`] for fsync's QUIC server endpoint.
///
/// The server presents a self-signed certificate identified by `name` (see
/// [`generate_self_signed_cert`]) and authenticates clients via
/// [`SignatureVerifyingClientVerifier`]. The ALPN protocol is set to the
/// fsync protocol name.
///
/// # Errors
///
/// Returns a boxed error if the cached certificate and key cannot be read or
/// written, or if certificate generation fails.
#[instrument]
pub fn configure_server(name: &str) -> Result<ServerConfig> {
   let (cert_chain, private_key) = generate_self_signed_cert(name)?;

   let client_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
      Arc::new(SignatureVerifyingClientVerifier);

   let mut server_crypto = rustls::ServerConfig::builder()
      .with_client_cert_verifier(client_verifier)
      .with_single_cert(cert_chain, private_key)
      .expect("Cert and key were generated together; this is infallible");

   server_crypto.alpn_protocols = vec![PROTOCOL_NAME.as_bytes().to_vec()];

   Ok(ServerConfig::with_crypto(Arc::new(
      QuicServerConfig::try_from(server_crypto)
         .expect("Server crypto config is valid; this is infallible"),
   )))
}

/// Builds a quinn [`ClientConfig`] for fsync's QUIC client endpoint.
///
/// The client presents a self-signed certificate identified by `name` (see
/// [`generate_self_signed_cert`]) and skips server certificate validation via
/// `DangerNoVerifier`. The ALPN protocol is set to the fsync protocol name.
///
/// # Errors
///
/// Returns a boxed error if the cached certificate and key cannot be read or
/// written, or if certificate generation fails.
#[instrument]
pub fn configure_client(name: &str) -> Result<ClientConfig> {
   let (cert_chain, private_key) = generate_self_signed_cert(name)?;

   /// Client-side certificate verifier that skips server certificate
   /// validation.
   ///
   /// `verify_server_cert` always accepts the presented certificate; only the
   /// handshake signature is verified. fsync peers use self-signed
   /// certificates with no shared trust root, so authenticity is instead
   /// established by the application-layer handshake in the parent `p2p_auth`
   /// module.
   #[derive(Debug)]
   struct DangerNoVerifier;
   impl rustls::client::danger::ServerCertVerifier for DangerNoVerifier {
      fn verify_server_cert(
         &self, _end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>],
         _server_name: &rustls::pki_types::ServerName<'_>, _ocsp_response: &[u8],
         _now: rustls::pki_types::UnixTime,
      ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
         Ok(rustls::client::danger::ServerCertVerified::assertion())
      }
      fn verify_tls12_signature(
         &self, message: &[u8], cert: &CertificateDer<'_>, dss: &rustls::DigitallySignedStruct,
      ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
      {
         verify_signature_tls12(message, cert, dss)
      }
      fn verify_tls13_signature(
         &self, message: &[u8], cert: &CertificateDer<'_>, dss: &rustls::DigitallySignedStruct,
      ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
      {
         verify_signature_tls13(message, cert, dss)
      }
      fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
         vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
         ]
      }
   }

   let mut client_crypto = rustls::ClientConfig::builder()
      .dangerous()
      .with_custom_certificate_verifier(Arc::new(DangerNoVerifier))
      .with_client_auth_cert(cert_chain, private_key)
      .expect("Cert and key were generated together; this is infallible");

   client_crypto.alpn_protocols = vec![PROTOCOL_NAME.as_bytes().to_vec()];

   Ok(ClientConfig::new(Arc::new(
      QuicClientConfig::try_from(client_crypto)
         .expect("Client crypto config is valid; this is infallible"),
   )))
}

#[cfg(test)]
mod tests {
   use super::*;
   use std::fs;

   fn clear_certs(name: &str) {
      let Ok((cert_path, key_path)) = cache_path(name) else {
         return;
      };
      let _ = fs::remove_file(&cert_path);
      let _ = fs::remove_file(&key_path);
   }

   #[test]
   fn test_cache_path() {
      let (cert_path, key_path) = cache_path("test-node").expect("Failed to get cache path");
      let dir = CONFIG_DIR.join("certs");
      assert_eq!(cert_path, dir.join("test-node.cert.der"));
      assert_eq!(key_path, dir.join("test-node.key.der"));
   }

   #[test]
   fn test_generate_caches_files() {
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
}
