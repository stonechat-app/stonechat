//! A mailbox (relay) client over pinned TLS.
//!
//! Two kinds of mailbox get talked to here and they are not the same thing:
//!
//! - **ours**, where we authenticate with our device token to publish prekeys,
//!   read status, fetch shared blobs and hold the receive socket;
//! - **a peer's**, where we are an anonymous poster to `/inbox` and, when we
//!   need to start a session, a reader of their public prekey bundle.
//!
//! Both are pinned. The fingerprint for ours came from the link grant; a
//! peer's came from the directory and was signed by *their* identity key, so
//! in neither case are we taking a server's word for who it is. And both are
//! `https://` only: a mailbox address with any other scheme is refused before
//! a byte is sent, because the pin is checked on the TLS connection and a
//! plaintext connection has nothing to check.

use serde_json::{Value, json};

use crate::pin::pinned_config;
use crate::util::{Result, status_is_transient};
use crate::{err, transient};

pub struct Mailbox {
    address: String,
    http: reqwest::Client,
}

/// A peer's device listing, with the certificates the mailbox serves for
/// each — opaque to it, verified by us.
pub struct DeviceList {
    pub devices_v: Option<u64>,
    pub devices: Vec<(u32, Option<Value>)>,
}

/// What `/inbox` said to a deposit.
pub enum Deposit {
    Accepted { devices_v: Option<u64> },
    /// `410`: that device was revoked, expired, or never existed. Permanent
    /// for that copy; the sender forgets the device and owes it nothing.
    Gone { devices_v: Option<u64> },
}

impl Mailbox {
    pub fn new(address: &str, tls_fp: &str) -> Result<Mailbox> {
        if !address.starts_with("https://") {
            return Err(err!(
                "mailbox address {address} is not https:// — refusing it; the certificate \
                 pin can only be checked on a TLS connection"
            ));
        }
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
        let base = self.address.replacen("https://", "wss://", 1);
        format!("{base}/ws?token={}", crate::util::url_encode(device_token))
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

    /// Which devices a peer has, with the certificate each publishes. Gated
    /// by their bundle token, and separate from fetching a bundle precisely
    /// so that *listing* costs no prekeys.
    pub async fn devices(&self, bundle_token: &str) -> Result<DeviceList> {
        let r = self
            .http
            .get(format!("{}/prekeys/devices", self.address))
            .query(&[("token", bundle_token)])
            .send()
            .await?;
        let body = expect_ok(r, "list devices").await?;
        let mut devices: Vec<(u32, Option<Value>)> = body
            .get("devices")
            .and_then(Value::as_array)
            .map(|ds| {
                ds.iter()
                    .filter_map(|d| {
                        let id = u32::try_from(d.get("device_id")?.as_u64()?).ok()?;
                        (id >= 1).then(|| (id, d.get("cert").filter(|c| !c.is_null()).cloned()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        devices.sort_by_key(|(id, _)| *id);
        Ok(DeviceList {
            devices_v: body.get("devices_v").and_then(Value::as_u64),
            devices,
        })
    }

    /// Hand a sealed envelope to a mailbox. Unauthenticated by design: anyone
    /// may post to anyone's mailbox, and the body is opaque to it.
    pub async fn deliver(&self, envelope: &Value) -> Result<Deposit> {
        let r = self
            .http
            .post(format!("{}/inbox", self.address))
            .json(envelope)
            .send()
            .await?;
        if r.status() == reqwest::StatusCode::GONE {
            let body: Value = r.json().await.unwrap_or(Value::Null);
            return Ok(Deposit::Gone {
                devices_v: body.get("devices_v").and_then(Value::as_u64),
            });
        }
        let body = expect_ok(r, "deliver an envelope").await?;
        Ok(Deposit::Accepted {
            devices_v: body.get("devices_v").and_then(Value::as_u64),
        })
    }

    /// A shared blob on this mailbox, by the per-blob capability its uploader
    /// handed out. `Ok(None)` when the blob is gone — a permanent answer; the
    /// mailbox being unreachable is a transient one.
    pub async fn fetch_blob(&self, blob_id: &str, fetch_token: &str) -> Result<Option<Vec<u8>>> {
        let r = self
            .http
            .get(format!("{}/blob/{blob_id}", self.address))
            .query(&[("token", fetch_token)])
            .send()
            .await?;
        let status = r.status();
        if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(if status_is_transient(status) {
                transient!("could not fetch blob {blob_id} ({status})")
            } else {
                err!("could not fetch blob {blob_id} ({status})")
            });
        }
        Ok(Some(r.bytes().await?.to_vec()))
    }
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
    serde_json::from_str(&text).map_err(|e| err!("mailbox returned non-JSON for {what}: {e}"))
}
