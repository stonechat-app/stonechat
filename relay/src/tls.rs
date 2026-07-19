//! Self-signed cert, generated once and kept for the mailbox's lifetime.
//! fingerprint = BLAKE2b-256 of the DER certificate (what clients pin).
//!
//! Parity-critical (RUST_PORT.md "TLS"): if PEM files already exist —
//! including ones the Python relay generated via the openssl CLI — they are
//! loaded unchanged, so the pinned fingerprint survives a Python→Rust swap
//! on the same volume. Only a fresh volume generates a new keypair.

use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

type Blake2b256 = Blake2b<U32>;

pub struct Tls {
    pub cert_pem: String,
    pub key_pem: String,
    pub fingerprint_b64: String,
}

pub fn fingerprint_from_cert_pem(cert_pem: &str) -> Result<String, String> {
    let der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .ok_or("no certificate in PEM")?
        .map_err(|e| format!("bad certificate PEM: {e}"))?;
    let mut h = Blake2b256::new();
    h.update(der.as_ref());
    Ok(B64.encode(h.finalize()))
}

impl Tls {
    pub fn load_or_generate(dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let key_file = dir.join("tls_key.pem");
        let cert_file = dir.join("tls_cert.pem");

        let (cert_pem, key_pem) = if key_file.is_file() && cert_file.is_file() {
            (
                std::fs::read_to_string(&cert_file).map_err(|e| e.to_string())?,
                std::fs::read_to_string(&key_file).map_err(|e| e.to_string())?,
            )
        } else {
            let key_pair = rcgen::KeyPair::generate() // ECDSA P-256, like the openssl invocation
                .map_err(|e| e.to_string())?;
            let mut params = rcgen::CertificateParams::default();
            params.distinguished_name = {
                let mut dn = rcgen::DistinguishedName::new();
                dn.push(rcgen::DnType::CommonName, "zeon-mailbox");
                dn
            };
            // openssl used -days 36500; pin explicit far-out bounds instead
            params.not_before = rcgen::date_time_ymd(2020, 1, 1);
            params.not_after = rcgen::date_time_ymd(2126, 1, 1);
            let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
            let cert_pem = cert.pem();
            let key_pem = key_pair.serialize_pem();
            std::fs::write(&cert_file, &cert_pem).map_err(|e| e.to_string())?;
            std::fs::write(&key_file, &key_pem).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| e.to_string())?;
            }
            (cert_pem, key_pem)
        };

        let fingerprint_b64 = fingerprint_from_cert_pem(&cert_pem)?;
        Ok(Self { cert_pem, key_pem, fingerprint_b64 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture was generated with the exact openssl invocation
    /// server/main.py uses; the expected value is what its Python code
    /// (hashlib.blake2b(der, digest_size=32)) reports. If this test fails,
    /// a Rust relay taking over an existing volume would break every
    /// client's pin — do not ship.
    #[test]
    fn fingerprint_matches_python_over_openssl_cert() {
        let pem = include_str!("../tests/fixtures/openssl_cert.pem");
        assert_eq!(
            fingerprint_from_cert_pem(pem).unwrap(),
            "otGmKggjONHxviEOyYtoRpzlTcDhE5wG3z/qEXeG9GQ="
        );
    }

    #[test]
    fn generated_cert_roundtrips_and_persists() {
        let dir = std::env::temp_dir().join(format!("zeon-tls-test-{}", std::process::id()));
        let t1 = Tls::load_or_generate(&dir).unwrap();
        let t2 = Tls::load_or_generate(&dir).unwrap(); // second boot: reuse, same fp
        assert_eq!(t1.fingerprint_b64, t2.fingerprint_b64);
        std::fs::remove_dir_all(&dir).ok();
    }
}
