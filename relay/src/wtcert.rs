//! Short-lived certificates for the browser transport.
//!
//! The mailbox's ordinary TLS certificate is self-signed, on a bare IP, and
//! valid for a century — clients pin its BLAKE2b fingerprint from the
//! directory and refuse CAs outright (PROTOCOL.md "Transport"). A browser
//! cannot do any of that: `fetch` and `WebSocket` simply refuse a self-signed
//! certificate, with no API to accept one.
//!
//! WebTransport's `serverCertificateHashes` is the one exception, and it comes
//! with conditions that are not ours to negotiate:
//!
//! - the certificate must be **ECDSA P-256** (what rcgen generates by default,
//!   and what the long-lived cert already uses);
//! - its validity must be **at most 14 days**;
//! - the pin is **SHA-256 of the DER**, not the BLAKE2b the rest of Stonechat
//!   uses. Two hashes of the same object, for two different audiences.
//!
//! The 14-day cap is the whole design problem. A pin that expires every two
//! weeks is useless if fetching the replacement requires already being
//! connected, so the relay runs *ahead*: it keeps a **schedule** of
//! certificates covering the next several months, each with its window, and
//! serves the whole thing. A client stores the schedule, passes every
//! still-valid hash to `serverCertificateHashes`, and only needs to refresh
//! before its last one lapses — which is months, not days.
//!
//! What the relay cannot do is *vouch* for the schedule: it is the thing being
//! authenticated. The owner's device signs it, exactly as it already signs the
//! long-lived fingerprint, and publishes the signature to the hub. This file
//! generates and serves; it does not claim.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Browsers reject a `serverCertificateHashes` certificate valid for longer
/// than this. Not a preference.
pub const MAX_VALIDITY_DAYS: u32 = 14;

/// How long each certificate in the schedule lives. One day under the cap:
/// the browser compares against *its own* clock, and a certificate minted at
/// exactly 14 days fails for any client whose clock runs slow.
pub const VALIDITY_DAYS: u32 = 13;

/// Certificates are rotated a day before they expire, so there is always a
/// window where both the outgoing and incoming certificate are valid. Without
/// the overlap, a client that connects during the changeover sees a hash it
/// was never told about.
pub const OVERLAP_DAYS: u32 = 1;

/// How far ahead the schedule runs. Twelve certificates at 12 effective days
/// each is about five months — long enough that a client which has been shut
/// in a drawer still holds one valid pin when it wakes.
pub const SCHEDULE_LEN: usize = 12;

/// One certificate and the window it is live for.
pub struct ScheduledCert {
    pub cert_pem: String,
    pub key_pem: String,
    /// SHA-256 of the DER, base64 — what a browser is handed.
    pub sha256_b64: String,
    pub not_before: i64,
    pub not_after: i64,
}

impl ScheduledCert {
    fn to_public(&self) -> Value {
        // Only the hash and the window. The certificate itself is served by
        // the QUIC handshake; publishing the PEM would add nothing and invite
        // someone to treat the schedule as a trust root rather than a pin.
        json!({
            "sha256": self.sha256_b64,
            "not_before": self.not_before,
            "not_after": self.not_after,
        })
    }
}

pub struct CertSchedule {
    dir: PathBuf,
    certs: Vec<ScheduledCert>,
}

fn sha256_b64(der: &[u8]) -> String {
    B64.encode(Sha256::digest(der))
}

fn der_of(cert_pem: &str) -> Result<Vec<u8>, String> {
    let der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .ok_or("no certificate in PEM")?
        .map_err(|e| format!("bad certificate PEM: {e}"))?;
    Ok(der.as_ref().to_vec())
}

fn mint(not_before: i64, not_after: i64) -> Result<ScheduledCert, String> {
    // Enforced rather than merely documented. A certificate a day over the cap
    // is refused by the browser with an error that says nothing useful, and
    // the mistake would only show up in a browser nobody is testing in.
    let days = (not_after - not_before) / DAY;
    if days > MAX_VALIDITY_DAYS as i64 {
        return Err(format!(
            "certificate would be valid for {days} days; browsers cap \
             serverCertificateHashes at {MAX_VALIDITY_DAYS}"
        ));
    }
    // ECDSA P-256 is rcgen's default and is what the browser requires; do not
    // "upgrade" this to Ed25519 without checking the WebTransport spec first.
    let key_pair = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params = rcgen::CertificateParams::new(vec![])
        .map_err(|e| e.to_string())?;
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "stonechat-mailbox-wt");
        dn
    };
    params.not_before = to_rcgen_time(not_before)?;
    params.not_after = to_rcgen_time(not_after)?;
    let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
    let cert_pem = cert.pem();
    let der = der_of(&cert_pem)?;
    Ok(ScheduledCert {
        sha256_b64: sha256_b64(&der),
        cert_pem,
        key_pem: key_pair.serialize_pem(),
        not_before,
        not_after,
    })
}

fn to_rcgen_time(unix: i64) -> Result<time::OffsetDateTime, String> {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .map_err(|e| format!("bad timestamp {unix}: {e}"))
}

const DAY: i64 = 86_400;

impl CertSchedule {
    /// Load the schedule from disk, extending it so it always runs
    /// [`SCHEDULE_LEN`] certificates into the future, and dropping ones that
    /// have fully expired.
    ///
    /// Idempotent and safe to call on every boot: a relay that was off for a
    /// month regenerates the tail rather than starting over, so the pins a
    /// client already holds keep working.
    pub fn load_or_generate(dir: &Path, now: i64) -> Result<Self, String> {
        let dir = dir.join("wt");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let mut certs = Self::read_existing(&dir, now)?;

        // Each certificate takes over OVERLAP_DAYS before the previous one
        // dies, so the live window is VALIDITY_DAYS - OVERLAP_DAYS and there
        // is never an instant with no valid certificate.
        let step = (VALIDITY_DAYS - OVERLAP_DAYS) as i64 * DAY;
        let mut next_start = certs
            .last()
            .map(|c| c.not_after - OVERLAP_DAYS as i64 * DAY)
            .unwrap_or(now - DAY); // a day of slack for a client clock behind ours

        while certs.len() < SCHEDULE_LEN {
            let cert = mint(next_start, next_start + VALIDITY_DAYS as i64 * DAY)?;
            Self::write(&dir, &cert)?;
            next_start += step;
            certs.push(cert);
        }
        certs.sort_by_key(|c| c.not_before);
        Ok(Self { dir, certs })
    }

    fn read_existing(dir: &Path, now: i64) -> Result<Vec<ScheduledCert>, String> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return Ok(out),
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("crt") {
                continue;
            }
            let key_path = path.with_extension("key");
            let (Ok(cert_pem), Ok(key_pem)) = (
                std::fs::read_to_string(&path),
                std::fs::read_to_string(&key_path),
            ) else {
                continue;
            };
            // The window is encoded in the filename: `<not_before>-<not_after>`.
            // Parsing the certificate to recover it would mean pulling in an
            // X.509 parser for a fact we wrote ourselves.
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue };
            let Some((a, b)) = stem.split_once('-') else { continue };
            let (Ok(not_before), Ok(not_after)) = (a.parse::<i64>(), b.parse::<i64>()) else {
                continue;
            };
            if not_after <= now {
                // Fully expired: no client can still be pinning it usefully,
                // and keeping the key around is pure liability.
                let _ = std::fs::remove_file(&path);
                let _ = std::fs::remove_file(&key_path);
                continue;
            }
            let der = der_of(&cert_pem)?;
            out.push(ScheduledCert {
                sha256_b64: sha256_b64(&der),
                cert_pem,
                key_pem,
                not_before,
                not_after,
            });
        }
        out.sort_by_key(|c| c.not_before);
        Ok(out)
    }

    fn write(dir: &Path, cert: &ScheduledCert) -> Result<(), String> {
        let base = dir.join(format!("{}-{}", cert.not_before, cert.not_after));
        std::fs::write(base.with_extension("crt"), &cert.cert_pem)
            .map_err(|e| e.to_string())?;
        let key_path = base.with_extension("key");
        std::fs::write(&key_path, &cert.key_pem).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// The certificate to serve right now: the newest one already in its
    /// window. Newest rather than oldest, so the overlap is spent moving
    /// clients onto the incoming certificate rather than clinging to the
    /// outgoing one.
    pub fn live(&self, now: i64) -> Option<&ScheduledCert> {
        self.certs
            .iter()
            .filter(|c| c.not_before <= now && now < c.not_after)
            .next_back()
    }

    /// Everything a client should pin: every certificate that has not expired,
    /// including ones not yet live. Handing over the future is the point — it
    /// is what makes rotation silent.
    pub fn published(&self, now: i64) -> Value {
        json!({
            "certs": self
                .certs
                .iter()
                .filter(|c| c.not_after > now)
                .map(ScheduledCert::to_public)
                .collect::<Vec<_>>(),
            // So a client can tell "the relay has nothing newer" from "I could
            // not reach the relay", and knows when it must refresh by.
            "refresh_after": self
                .certs
                .iter()
                .filter(|c| c.not_after > now)
                .map(|c| c.not_after)
                .max(),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "stonechat-wtcert-{}-{name}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const NOW: i64 = 1_800_000_000;

    #[test]
    fn minting_over_the_cap_is_refused() {
        // Matched rather than unwrap_err'd: ScheduledCert holds a private
        // key, so it deliberately does not derive Debug — nothing should be
        // able to print one into a log by accident.
        match mint(NOW, NOW + 15 * DAY) {
            Err(e) => assert!(e.contains("browsers cap"), "{e}"),
            Ok(_) => panic!("a 15-day certificate should be refused"),
        }
        assert!(mint(NOW, NOW + 14 * DAY).is_ok());
    }

    #[test]
    fn every_certificate_is_inside_the_browser_cap() {
        // The one hard external constraint. A certificate a day over the cap
        // is refused by the browser with an error that says nothing useful.
        let dir = tmp("cap");
        let s = CertSchedule::load_or_generate(&dir, NOW).unwrap();
        for c in &s.certs {
            let days = (c.not_after - c.not_before) / DAY;
            assert!(
                days <= MAX_VALIDITY_DAYS as i64,
                "certificate valid for {days} days, cap is {MAX_VALIDITY_DAYS}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn there_is_never_a_moment_without_a_live_certificate() {
        // The property rotation exists for. Walk the whole schedule in
        // six-hour steps and assert something is always servable — a gap of
        // even an hour is an outage for every browser session.
        let dir = tmp("gap");
        let s = CertSchedule::load_or_generate(&dir, NOW).unwrap();
        let last = s.certs.last().unwrap().not_after;
        let mut t = NOW;
        while t < last - DAY {
            assert!(s.live(t).is_some(), "no live certificate at t={t}");
            t += DAY / 4;
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_schedule_reaches_months_ahead() {
        // The point of publishing the future: a client only has to refresh
        // before its *last* pin lapses, not before the current one does.
        let dir = tmp("ahead");
        let s = CertSchedule::load_or_generate(&dir, NOW).unwrap();
        let horizon = (s.certs.last().unwrap().not_after - NOW) / DAY;
        assert!(horizon > 90, "only {horizon} days of pins published");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_reboot_keeps_the_pins_clients_already_hold() {
        // If a restart regenerated the schedule, every browser session would
        // be holding hashes for certificates that no longer exist — and the
        // failure looks like an unreachable relay, not a rotation bug.
        let dir = tmp("reboot");
        let first = CertSchedule::load_or_generate(&dir, NOW).unwrap();
        let before: Vec<_> = first.certs.iter().map(|c| c.sha256_b64.clone()).collect();
        drop(first);
        let second = CertSchedule::load_or_generate(&dir, NOW).unwrap();
        let after: Vec<_> = second.certs.iter().map(|c| c.sha256_b64.clone()).collect();
        assert_eq!(before, after);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn time_passing_extends_the_schedule_without_disturbing_it() {
        let dir = tmp("extend");
        let first = CertSchedule::load_or_generate(&dir, NOW).unwrap();
        let live_then = first.live(NOW).unwrap().sha256_b64.clone();
        let still_valid: Vec<_> = first
            .certs
            .iter()
            .filter(|c| c.not_after > NOW + 60 * DAY)
            .map(|c| c.sha256_b64.clone())
            .collect();
        drop(first);

        // Two months later: expired certificates are dropped, the tail is
        // extended, and everything a client could still be pinning survives.
        let later = CertSchedule::load_or_generate(&dir, NOW + 60 * DAY).unwrap();
        let after: Vec<_> = later.certs.iter().map(|c| c.sha256_b64.clone()).collect();
        for hash in &still_valid {
            assert!(after.contains(hash), "a still-valid pin was discarded");
        }
        assert_eq!(later.certs.len(), SCHEDULE_LEN);
        assert!(later.live(NOW + 60 * DAY).is_some());
        assert_ne!(later.live(NOW + 60 * DAY).unwrap().sha256_b64, live_then);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn expired_keys_are_deleted_not_merely_ignored() {
        // A private key nobody can use is a liability with no upside.
        let dir = tmp("shred");
        CertSchedule::load_or_generate(&dir, NOW).unwrap();
        let wt = dir.join("wt");
        let before = std::fs::read_dir(&wt).unwrap().count();
        CertSchedule::load_or_generate(&dir, NOW + 400 * DAY).unwrap();
        let names: Vec<_> = std::fs::read_dir(&wt)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(before > 0);
        for name in &names {
            let stem = name.split('.').next().unwrap();
            let (_, not_after) = stem.split_once('-').unwrap();
            assert!(
                not_after.parse::<i64>().unwrap() > NOW + 400 * DAY,
                "expired key {name} still on disk"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn published_hashes_are_sha256_of_the_der_not_blake2b() {
        // Two hashes of the same object for two audiences: native clients pin
        // BLAKE2b from the directory, browsers are handed SHA-256. Mixing them
        // up produces a pin nothing matches.
        let dir = tmp("hash");
        let s = CertSchedule::load_or_generate(&dir, NOW).unwrap();
        let live = s.live(NOW).unwrap();
        let der = der_of(&live.cert_pem).unwrap();
        assert_eq!(live.sha256_b64, B64.encode(Sha256::digest(&der)));
        assert_ne!(live.sha256_b64, crate::tls::fingerprint_from_cert_pem(&live.cert_pem).unwrap());
        assert_eq!(B64.decode(&live.sha256_b64).unwrap().len(), 32);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn what_is_published_carries_no_private_material() {
        let dir = tmp("public");
        let s = CertSchedule::load_or_generate(&dir, NOW).unwrap();
        let text = s.published(NOW).to_string();
        assert!(!text.contains("PRIVATE"));
        assert!(!text.contains("BEGIN"));
        assert!(text.contains("sha256"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
