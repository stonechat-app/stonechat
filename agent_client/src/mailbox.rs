//! A mailbox (relay) client over pinned TLS.
//!
//! Two kinds of mailbox get talked to here and they are not the same thing:
//!
//! - **ours**, where we authenticate with our device token to publish prekeys,
//!   read status and hold the receive socket;
//! - **a peer's**, where we are an anonymous poster to `/inbox` and, when we
//!   need to start a session, a reader of their public prekey bundle.
//!
//! Both are pinned. The fingerprint for ours came from the link grant; a
//! peer's came from the directory and was signed by *their* identity key, so
//! in neither case are we taking a server's word for who it is.

use serde_json::{Value, json};

use crate::err;
use crate::pin::pinned_config;
use crate::util::Result;

pub struct Mailbox {
    address: String,
    http: reqwest::Client,
}

impl Mailbox {
    pub fn new(address: &str, tls_fp: &str) -> Result<Mailbox> {
        let http = reqwest::Client::builder()
            .use_preconfigured_tls((*pinned_config(tls_fp)).clone())
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Mailbox {
            address: address.trim_end_matches('/').to_string(),
            http,
        })
    }

    /// `wss://…/ws?token=…` — the receive socket for our own mailbox.
    pub fn ws_url(&self, device_token: &str) -> String {
        let base = self
            .address
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1);
        format!("{base}/ws?token={device_token}")
    }

    /// Publish this device's prekeys **and the certificate that vouches for
    /// the key which signed them**. One without the other leaves a sender
    /// unable to check either, which is why the relay takes them together.
    pub async fn publish_prekeys(&self, device_token: &str, body: &Value) -> Result<()> {
        let r = self
            .http
            .post(format!("{}/prekeys", self.address))
            .query(&[("token", device_token)])
            .json(body)
            .send()
            .await?;
        expect_ok(r, "publish prekeys").await?;
        Ok(())
    }

    pub async fn status(&self, device_token: &str) -> Result<Value> {
        let r = self
            .http
            .get(format!("{}/status", self.address))
            .query(&[("token", device_token)])
            .send()
            .await?;
        expect_ok(r, "read mailbox status").await
    }

    /// A peer device's prekey bundle.
    ///
    /// **This consumes one of their one-time prekeys**, so it is called once
    /// per peer device and the certificate that comes back is cached. Device 1
    /// is open by design; anything else needs their bundle token, which rides
    /// every envelope they have sent us.
    pub async fn prekey_bundle(&self, device: u32, bundle_token: Option<&str>) -> Result<Value> {
        let mut req = self.http.get(format!("{}/prekeys/bundle", self.address));
        if device != crate::PRIMARY_DEVICE {
            let token = bundle_token
                .ok_or_else(|| err!("device {device}'s bundle needs their bundle token"))?;
            req = req.query(&[("device", device.to_string()), ("token", token.to_string())]);
        }
        expect_ok(req.send().await?, "fetch a prekey bundle").await
    }

    /// Which devices a peer has. Gated by their bundle token, and separate
    /// from fetching a bundle precisely so that *listing* costs no prekeys
    /// (MULTIDEVICE.md "Why the device list is gated").
    pub async fn devices(&self, bundle_token: &str) -> Result<Vec<u32>> {
        let r = self
            .http
            .get(format!("{}/prekeys/devices", self.address))
            .query(&[("token", bundle_token)])
            .send()
            .await?;
        let body = expect_ok(r, "list devices").await?;
        let mut ids: Vec<u32> = body
            .get("devices")
            .and_then(Value::as_array)
            .map(|ds| {
                ds.iter()
                    .filter_map(|d| d.get("device_id").and_then(Value::as_u64))
                    .map(|d| d as u32)
                    .collect()
            })
            .unwrap_or_default();
        ids.sort_unstable();
        Ok(ids)
    }

    /// Hand a sealed envelope to a mailbox. Unauthenticated by design: anyone
    /// may post to anyone's mailbox, and the body is opaque to it.
    pub async fn deliver(&self, envelope: &Value) -> Result<()> {
        let r = self
            .http
            .post(format!("{}/inbox", self.address))
            .json(envelope)
            .send()
            .await?;
        expect_ok(r, "deliver an envelope").await?;
        Ok(())
    }
}

/// How many one-time prekeys a bundle response says are left, when it says.
pub fn opks_remaining(status: &Value) -> Option<u64> {
    status
        .get("prekeys")
        .and_then(|p| p.get("opks"))
        .and_then(Value::as_u64)
}

/// The prekey upload body, assembled where the shapes are documented.
pub fn prekey_upload(
    spk: (u64, &str, &str),
    kspk: (u64, &str, &str),
    opks: Vec<Value>,
    kopks: Vec<Value>,
    cert: &Value,
) -> Value {
    json!({
        "spk": {"id": spk.0, "pub": spk.1, "sig": spk.2},
        "opks": opks,
        "kspk": {"id": kspk.0, "pub": kspk.1, "sig": kspk.2},
        "kopks": kopks,
        "cert": cert,
    })
}

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
    serde_json::from_str(&text).map_err(|e| err!("mailbox returned non-JSON for {what}: {e}"))
}
