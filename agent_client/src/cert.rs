//! Device certificates in their JSON form.
//!
//! `core::devcert` owns the format, the signing bytes and the verification —
//! all this module does is move between that struct and the JSON the wire and
//! the state file use. The signing bytes are deliberately **not** JSON
//! (`core/src/devcert.rs` explains why), so this conversion can never be the
//! thing a signature is computed over.

use serde_json::Value;
use stonechat_core::devcert::{CertStatus, DeviceCert};
use stonechat_core::pqcore::XWING_PUBLIC_BYTES;

use crate::err;
use crate::util::{Result, unb64_n};

pub fn parse(cert: &Value) -> Result<(DeviceCert, [u8; 64])> {
    let stonechat_id = cert
        .get("stonechat_id")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("certificate has no stonechat_id"))?
        .to_string();
    let device_id = cert
        .get("device_id")
        .and_then(Value::as_u64)
        .ok_or_else(|| err!("certificate has no device_id"))? as u32;
    let sig_pub: [u8; 32] = unb64_n(
        cert.get("sig_pub")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("certificate has no sig_pub"))?,
        "certificate sig_pub",
    )?;
    let seal_pub: [u8; XWING_PUBLIC_BYTES] = unb64_n(
        cert.get("seal_pub")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("certificate has no seal_pub"))?,
        "certificate seal_pub",
    )?;
    let not_after = cert
        .get("not_after")
        .and_then(Value::as_u64)
        .ok_or_else(|| err!("certificate has no not_after"))?;
    let sig: [u8; 64] = unb64_n(
        cert.get("sig")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("certificate is unsigned"))?,
        "certificate signature",
    )?;
    Ok((
        DeviceCert {
            stonechat_id,
            device_id,
            sig_pub,
            seal_pub,
            not_after,
        },
        sig,
    ))
}

/// Verify a certificate against the identity key its owner's SC- ID commits
/// to, and against the slot it arrived in.
///
/// `device` is checked because a certificate is otherwise replayable onto
/// another device id — valid, correctly signed, and for someone else. That is
/// exactly the substitution `core`'s test `a_cert_must_not_be_replayable_onto
/// _another_device_id` pins, and the check only means anything if the caller
/// makes it.
pub fn verify(cert: &Value, identity_pub: &[u8; 32], device: Option<u32>) -> Result<DeviceCert> {
    let (parsed, sig) = parse(cert)?;
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    match parsed.verify(identity_pub, &sig, now) {
        CertStatus::Valid => {}
        CertStatus::Expired => {
            return Err(err!(
                "certificate for device {} expired at {} — that device must be \
                 re-certified by its primary before anyone will encrypt to it",
                parsed.device_id,
                parsed.not_after
            ));
        }
        CertStatus::BadSignature => {
            return Err(err!(
                "certificate for device {} is not signed by the identity it \
                 claims — refusing it",
                parsed.device_id
            ));
        }
    }
    if let Some(device) = device
        && parsed.device_id != device
    {
        return Err(err!(
            "certificate names device {} but arrived as device {device}",
            parsed.device_id
        ));
    }
    Ok(parsed)
}

/// The seal key a certificate vouches for — where an envelope to that device
/// must be addressed. Since device certificates, nothing seals to the one
/// identity key in the directory.
pub fn seal_key(cert: &Value) -> Result<[u8; XWING_PUBLIC_BYTES]> {
    Ok(parse(cert)?.0.seal_pub)
}

/// The signing key a certificate vouches for. Prekeys are checked against
/// this, and PQXDH runs against it.
pub fn sig_key(cert: &Value) -> Result<[u8; 32]> {
    Ok(parse(cert)?.0.sig_pub)
}

// There is deliberately no `to_json` here: the agent never mints or re-emits
// a certificate. It holds one, verifies others, and passes its own through
// untouched — having no identity root, it could not sign one anyway.
