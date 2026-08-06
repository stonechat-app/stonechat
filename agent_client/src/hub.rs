//! The hub: link dead drop and directory.
//!
//! Ordinary TLS here, unlike a mailbox — the hub is a normal host with a
//! normal certificate. What it serves is either opaque (a sealed grant it
//! cannot open) or verified by the caller against something the hub does not
//! control (a directory key must hash to the SC- ID that was asked for), so
//! nothing in this file trusts the answer it gets.

use serde_json::{Value, json};

use crate::err;
use crate::util::{Result, hex, unb64, unb64_n};

pub struct Hub {
    base: String,
    http: reqwest::Client,
}

/// A directory entry, after the checks that make it worth having.
pub struct Peer {
    pub stonechat_id: String,
    pub identity_pub: [u8; 32],
    pub relay_address: String,
    /// Their mailbox's certificate fingerprint, **signed by the identity key
    /// their SC- ID commits to**. Without that signature it would be the
    /// directory telling us what to trust, which is the one thing pinning
    /// exists to avoid.
    pub relay_tls_fp: String,
}

impl Hub {
    pub fn new(base_url: &str) -> Result<Hub> {
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
    /// unauthenticated lookup.
    pub async fn resolve(&self, stonechat_id: &str) -> Result<Peer> {
        let r = self
            .http
            .get(format!("{}/v1/directory/{stonechat_id}", self.base))
            .send()
            .await?;
        let body = expect_ok(r, &format!("resolve {stonechat_id}")).await?;
        let pubkey_b64 = body
            .get("pubkey")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("directory entry for {stonechat_id} has no pubkey"))?;
        let identity_pub: [u8; 32] = unb64_n(pubkey_b64, "directory pubkey")?;
        let returned = body
            .get("stonechat_id")
            .and_then(Value::as_str)
            .unwrap_or(stonechat_id);
        if !stonechat_core::ids::pubkey_matches_id(&identity_pub, returned) || returned != stonechat_id
        {
            return Err(err!(
                "directory key does not commit to {stonechat_id} — refusing to use it"
            ));
        }
        let server = body
            .get("server")
            .filter(|s| !s.is_null())
            .ok_or_else(|| err!("{stonechat_id} has no running mailbox — cannot deliver"))?;
        let relay_address = server
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("{stonechat_id}'s directory entry has no mailbox address"))?;

        // The owner's half of pinned TLS. A fingerprint the owner has not
        // signed is not a fingerprint — it is the directory's opinion, and
        // pinning to it would chain trust to the hub instead of to the
        // identity. Refusing here is the safe failure: it reads as "that
        // mailbox is not vouched for", not as a broken connection later.
        let fp_b64 = server
            .get("tls_fp")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("{stonechat_id}'s mailbox publishes no TLS fingerprint"))?;
        let sig_b64 = server
            .get("tls_sig")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("{stonechat_id}'s TLS fingerprint is unsigned — refusing it"))?;
        let sig: [u8; 64] = unb64_n(sig_b64, "TLS fingerprint signature")?;
        if !stonechat_core::primitives::verify_with_context(
            &identity_pub,
            stonechat_core::primitives::TLS_SIG_CONTEXT,
            &unb64(fp_b64)?,
            &sig,
        ) {
            return Err(err!(
                "{stonechat_id} did not sign their mailbox's TLS fingerprint — refusing it"
            ));
        }

        Ok(Peer {
            stonechat_id: returned.to_string(),
            identity_pub,
            relay_address: relay_address.to_string(),
            relay_tls_fp: fp_b64.to_string(),
        })
    }
}

/// Turn a non-2xx into a sentence that names what was being attempted. The
/// agent's log is the only place anyone sees these.
async fn expect_ok(r: reqwest::Response, what: &str) -> Result<Value> {
    let status = r.status();
    let text = r.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(err!(
            "could not {what} ({status}): {}",
            text.chars().take(300).collect::<String>()
        ));
    }
    if text.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&text).map_err(|e| err!("hub returned non-JSON for {what}: {e}"))
}
