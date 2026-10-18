//! The hub: link dead drop and directory.
//!
//! Ordinary TLS here, unlike a mailbox — the hub is a normal host with a
//! normal certificate. What it serves is either opaque (a sealed grant it
//! cannot open) or verified by the caller against something the hub does not
//! control (a directory key must hash to the SC- ID that was asked for, a
//! device manifest must be signed by that key), so nothing in this file
//! trusts the answer it gets.

use serde_json::{Value, json};
use stonechat_core::devices::Manifest;

use crate::util::{Result, hex, status_is_transient, unb64, unb64_n};
use crate::{err, manifest, transient};

pub struct Hub {
    base: String,
    http: reqwest::Client,
}

/// A directory record, after the checks that make it worth having.
pub struct Entry {
    pub stonechat_id: String,
    pub identity_pub: [u8; 32],
    /// `None` when the identity has no running mailbox: it can still be
    /// looked up (for its manifest), just not written to.
    pub mailbox: Option<MailboxAddr>,
    /// The identity's device manifest, verified, as served and parsed.
    /// `None` when the owner has published none.
    pub manifest: Option<(Value, Manifest)>,
}

pub struct MailboxAddr {
    pub address: String,
    /// The mailbox's certificate fingerprint, **signed by the identity key
    /// the SC- ID commits to**. Without that signature it would be the
    /// directory telling us what to trust, which is the one thing pinning
    /// exists to avoid.
    pub tls_fp: String,
}

/// Where to write to a peer: identity key and mailbox, both checked.
#[derive(Clone)]
pub struct Peer {
    pub stonechat_id: String,
    pub identity_pub: [u8; 32],
    pub relay_address: String,
    pub relay_tls_fp: String,
}

impl Entry {
    pub fn peer(&self) -> Result<Peer> {
        let mailbox = self
            .mailbox
            .as_ref()
            .ok_or_else(|| err!("{} has no running mailbox — cannot deliver", self.stonechat_id))?;
        Ok(Peer {
            stonechat_id: self.stonechat_id.clone(),
            identity_pub: self.identity_pub,
            relay_address: mailbox.address.clone(),
            relay_tls_fp: mailbox.tls_fp.clone(),
        })
    }
}

impl Hub {
    pub fn new(base_url: &str) -> Result<Hub> {
        check_scheme(base_url)?;
        crate::pin::install_provider();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Hub {
            base: base_url.trim_end_matches('/').to_string(),
            http,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// Park our public keys under a commitment to them.
    ///
    /// The hub recomputes the commitment and refuses a mismatch, so it cannot
    /// serve keys the scanning phone did not agree to. We check it again on
    /// the other side anyway; its word does not count.
    pub async fn put_link_offer(
        &self,
        commitment: &[u8; 32],
        seal_pub_b64: &str,
        sig_pub_b64: &str,
    ) -> Result<()> {
        let body = json!({
            "key": hex(commitment),
            "offer": {"seal": seal_pub_b64, "sig": sig_pub_b64},
        });
        let r = self
            .http
            .post(format!("{}/v1/link/offer", self.base))
            .json(&body)
            .send()
            .await?;
        expect_ok(r, "park the link offer").await?;
        Ok(())
    }

    /// Collect the grant, if the phone has authorised us yet.
    ///
    /// `Ok(None)` is the ordinary answer — the endpoint 404s until the other
    /// device acts, and this is a poll. It returns and **deletes**, so a
    /// success here is the only one there will be.
    pub async fn take_link_grant(&self, parking_key: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let r = self
            .http
            .get(format!("{}/v1/link/{}", self.base, hex(parking_key)))
            .send()
            .await?;
        if r.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body = expect_ok(r, "collect the link grant").await?;
        let sealed = body
            .get("sealed")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("hub returned a grant with no sealed body"))?;
        Ok(Some(unb64(sealed)?))
    }

    /// Resolve an SC- ID, then verify the answer against the question.
    ///
    /// A Stonechat ID is a commitment to an identity key, so a directory that
    /// swaps the key is caught here rather than trusted. That check is the
    /// entire reason it is safe for the directory to be an untrusted,
    /// unauthenticated lookup. The device manifest, when the record carries
    /// one, is checked under that key too: a directory serving a manifest the
    /// owner did not sign is not serving the owner's record, and the whole
    /// answer is refused.
    pub async fn resolve(&self, stonechat_id: &str) -> Result<Entry> {
        let r = self
            .http
            .get(format!("{}/v1/directory/{stonechat_id}", self.base))
            .send()
            .await?;
        if r.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(err!("{stonechat_id} is unknown to the directory"));
        }
        let body = expect_ok(r, &format!("resolve {stonechat_id}")).await?;
        let pubkey_b64 = body
            .get("pubkey")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("directory entry for {stonechat_id} has no pubkey"))?;
        let identity_pub: [u8; 32] = unb64_n(pubkey_b64, "directory pubkey")?;
        // Against the ID that was asked for, never the one in the answer: a
        // directory returning somebody else's complete record is internally
        // consistent.
        let returned = body
            .get("stonechat_id")
            .and_then(Value::as_str)
            .unwrap_or(stonechat_id);
        if returned != stonechat_id
            || !stonechat_core::ids::pubkey_matches_id(&identity_pub, stonechat_id)
        {
            return Err(err!(
                "directory key does not commit to {stonechat_id} — refusing to use it"
            ));
        }

        let manifest = match body.get("devices").filter(|d| !d.is_null()) {
            None => None,
            Some(raw) => Some((
                raw.clone(),
                manifest::verified(raw, stonechat_id, &identity_pub).ok_or_else(|| {
                    err!("the directory serves a device manifest {stonechat_id} did not sign — refusing the record")
                })?,
            )),
        };

        let mailbox = match body.get("mailbox").filter(|m| !m.is_null()) {
            None => None,
            Some(mailbox) => Some(verified_mailbox(stonechat_id, &identity_pub, mailbox)?),
        };

        Ok(Entry {
            stonechat_id: stonechat_id.to_string(),
            identity_pub,
            mailbox,
            manifest,
        })
    }
}

/// The owner's half of pinned TLS. A fingerprint the owner has not signed is
/// not a fingerprint — it is the directory's opinion, and pinning to it
/// would chain trust to the hub instead of to the identity. Refusing here is
/// the safe failure: it reads as "that mailbox is not vouched for", not as a
/// broken connection later.
fn verified_mailbox(stonechat_id: &str, identity_pub: &[u8; 32], mailbox: &Value) -> Result<MailboxAddr> {
    let address = mailbox
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("{stonechat_id}'s directory entry has no mailbox address"))?;
    let fp_b64 = mailbox
        .get("tls_fp")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("{stonechat_id}'s mailbox publishes no TLS fingerprint"))?;
    let sig_b64 = mailbox
        .get("tls_sig")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("{stonechat_id}'s TLS fingerprint is unsigned — refusing it"))?;
    let sig: [u8; 64] = unb64_n(sig_b64, "TLS fingerprint signature")?;
    if !stonechat_core::primitives::verify_with_context(
        identity_pub,
        stonechat_core::primitives::TLS_SIG_CONTEXT,
        &unb64(fp_b64)?,
        &sig,
    ) {
        return Err(err!(
            "{stonechat_id} did not sign their mailbox's TLS fingerprint — refusing it"
        ));
    }
    Ok(MailboxAddr {
        address: address.to_string(),
        tls_fp: fp_b64.to_string(),
    })
}

/// The hub is reached over ordinary TLS, and only over TLS: a plaintext
/// directory is one anyone on the path can answer for. The one exception is
/// a hub on this machine, which is how the tests run one.
fn check_scheme(url: &str) -> Result<()> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let host = match rest.strip_prefix('[') {
            // A bracketed IPv6 literal, which has colons of its own.
            Some(v6) => v6.split(']').next().unwrap_or(""),
            None => rest.split(['/', ':', '?']).next().unwrap_or(""),
        };
        if matches!(host, "127.0.0.1" | "localhost" | "::1") {
            return Ok(());
        }
        return Err(err!(
            "hub {url} is plain http — the directory must be reached over https (http is \
             allowed only for a hub on this machine)"
        ));
    }
    Err(err!("hub {url} is not an https:// URL"))
}

/// Turn a non-2xx into a sentence that names what was being attempted. The
/// agent's log is the only place anyone sees these. A rate limit or a 5xx is
/// the hub's passing trouble and is reported as such.
async fn expect_ok(r: reqwest::Response, what: &str) -> Result<Value> {
    let status = r.status();
    let text = r.text().await.unwrap_or_default();
    if !status.is_success() {
        let detail: String = text.chars().take(300).collect();
        return Err(if status_is_transient(status) {
            transient!("could not {what} ({status}): {detail}")
        } else {
            err!("could not {what} ({status}): {detail}")
        });
    }
    if text.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&text).map_err(|e| err!("hub returned non-JSON for {what}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::check_scheme;

    #[test]
    fn plain_http_is_for_loopback_only() {
        assert!(check_scheme("https://hub.stonechat.app").is_ok());
        assert!(check_scheme("http://127.0.0.1:8479").is_ok());
        assert!(check_scheme("http://localhost:8000/").is_ok());
        assert!(check_scheme("http://[::1]:8000").is_ok());
        assert!(check_scheme("http://hub.stonechat.app").is_err());
        assert!(check_scheme("http://10.0.0.5:8000").is_err());
        assert!(check_scheme("hub.stonechat.app").is_err());
    }
}
