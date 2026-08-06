//! Pinned TLS to a mailbox.
//!
//! Relay certificates are self-signed **by design** (README "Pinned TLS, no
//! CAs"): trust chains to the Stonechat ID, not to a certificate authority.
//! The owner signs the fingerprint with their identity key and the directory
//! publishes it; a client's job is to check that the certificate actually
//! served hashes to the fingerprint it was told to expect.
//!
//! The agent is told once, in its link grant, and stores it. So unlike a phone
//! resolving a stranger through the directory, it never has to decide whether
//! to trust a fingerprint — it only has to refuse anything that is not the one
//! its own primary handed it.
//!
//! Fingerprint = base64(BLAKE2b-256(DER)), matching `relay/src/tls.rs`.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

use crate::util::{b64, blake2b_256, secret_eq};

/// Install the crypto provider once per process. Idempotent: a second call is
/// how `link` followed by `run` in one process would otherwise fail.
pub fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[derive(Debug)]
struct PinnedFingerprint {
    expected_b64: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedFingerprint {
    /// The whole verification. Not "in addition to" the usual chain checks —
    /// *instead of* them: there is no chain, no CA, and no name to match. A
    /// relay's certificate is a bare self-signed leaf, and the fingerprint is
    /// the only thing that says it is ours.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let served = b64(&blake2b_256(end_entity.as_ref()));
        if secret_eq(&served, &self.expected_b64) {
            return Ok(ServerCertVerified::assertion());
        }
        // Named in full on purpose. The overwhelmingly likely cause is that
        // the mailbox was rebuilt and got a new certificate, which is a
        // re-link, not an attack — and an operator reading this at 2am should
        // not have to guess which of the two they are looking at.
        Err(TlsError::General(format!(
            "mailbox certificate does not match the pinned fingerprint \
             (expected {}, served {}). The mailbox may have been rebuilt — \
             re-link the agent. Refusing to connect.",
            self.expected_b64, served
        )))
    }

    /// Signature checking is ordinary; only the identity of the certificate is
    /// unusual. Delegating keeps this out of the business of reimplementing
    /// handshake signature verification.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A rustls client config that accepts exactly one certificate.
pub fn pinned_config(fingerprint_b64: &str) -> Arc<rustls::ClientConfig> {
    install_provider();
    let provider = CryptoProvider::get_default()
        .cloned()
        .expect("provider installed above");
    let verifier = PinnedFingerprint {
        expected_b64: fingerprint_b64.to_string(),
        provider: provider.clone(),
    };
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    // The relay speaks HTTP/1.1; offering h2 to a server that will not use it
    // costs nothing but says something untrue about us.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}
