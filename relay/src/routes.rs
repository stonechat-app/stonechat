//! HTTP handlers. Status codes, JSON shapes and error bodies keep the
//! FastAPI-era `{"detail": "<msg>"}` shape inherited from the retired
//! Python relay — the conformance harness (tests/conformance.py) diffs
//! bodies against recorded goldens, so the shape is load-bearing.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha1::Sha1;

use crate::db::{OpkUpload, SpkUpload};
use crate::{blobs, push, AppState, MAX_BLOB_BYTES, MAX_ENVELOPE_BYTES, MAX_KOPKS, MAX_OPKS, MAX_PREKEY_UPLOAD_BYTES, TURN_TTL_S, WIRE_VERSION};

fn detail(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({"detail": msg}))).into_response()
}

fn owner_only(state: &AppState, q: &HashMap<String, String>) -> Result<(), Response> {
    if q.get("token").map(String::as_str) != Some(state.cfg.owner_token.as_str()) {
        return Err(detail(StatusCode::UNAUTHORIZED, "owner only"));
    }
    Ok(())
}

// -- liveness / identity ------------------------------------------------------

/// Unauthenticated liveness only — safe for anyone to poll. Identity, queue
/// depth and prekey inventory live behind the owner token on /status so a
/// stranger who knows this box's address can't map it to its owner or watch
/// its activity. tls_fp stays: it is the certificate hash, already public in
/// the directory and observable from the TLS handshake itself.
pub async fn health(State(state): State<Arc<AppState>>) -> Response {
    Json(json!({"status": "ok", "v": WIRE_VERSION, "tls_fp": state.tls_fp})).into_response()
}

pub async fn status(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(r) = owner_only(&state, &q) {
        return r;
    }
    Json(json!({
        "status": "ok",
        "v": WIRE_VERSION,
        "queued": state.mailbox.depth(),
        "prekeys": state.mailbox.prekey_status(),
    }))
    .into_response()
}

/// Confirm — never reveal — this mailbox's owner. Only an exact 160-bit match
/// returns 200; a stranger scanning addresses learns nothing.
pub async fn owner_check(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let stonechat_id = q.get("stonechat_id").map(String::as_str).unwrap_or("");
    if stonechat_id.is_empty() {
        return detail(StatusCode::BAD_REQUEST, "stonechat_id query parameter required");
    }
    if stonechat_id != state.cfg.owner_id {
        return detail(StatusCode::NOT_FOUND, "not this mailbox's owner");
    }
    Json(json!({"owner_matches": true})).into_response()
}

// -- prekeys ------------------------------------------------------------------

pub async fn upload_prekeys(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    if let Err(r) = owner_only(&state, &q) {
        return r;
    }
    // A full ML-KEM restock is ~55 KB of base64 — prekey uploads get their
    // own cap instead of the envelope one.
    if body.len() > MAX_PREKEY_UPLOAD_BYTES {
        return detail(StatusCode::PAYLOAD_TOO_LARGE, "too large");
    }
    let bad = || {
        detail(
            StatusCode::BAD_REQUEST,
            "expected {spk: {id, pub, sig}, opks: [{id, pub}], kspk: {id, pub, sig}, kopks: [{id, pub}]}",
        )
    };
    let Ok(parsed) = serde_json::from_slice::<Value>(&body) else { return bad() };
    let Some((spk, opks, kspk, kopks)) = parse_prekey_upload(&parsed) else { return bad() };
    state.mailbox.set_prekeys(&spk, &opks, &kspk, &kopks);
    Json(json!({"status": "ok", "prekeys": state.mailbox.prekey_status()})).into_response()
}

fn parse_signed(v: &Value) -> Option<SpkUpload> {
    Some(SpkUpload {
        id: v.get("id")?.as_i64().filter(|_| v["id"].is_i64())?,
        pub_key: v.get("pub")?.as_str()?.to_string(),
        sig: v.get("sig")?.as_str()?.to_string(),
    })
}

fn parse_one_time(body: &Value, field: &str, max: usize) -> Option<Vec<OpkUpload>> {
    let val = body.get(field).unwrap_or(&Value::Array(vec![])).clone();
    let arr = val.as_array()?;
    if arr.len() > max {
        return None;
    }
    let mut out = Vec::with_capacity(arr.len());
    for o in arr {
        out.push(OpkUpload {
            id: o.get("id")?.as_i64().filter(|_| o["id"].is_i64())?,
            pub_key: o.get("pub")?.as_str()?.to_string(),
        });
    }
    Some(out)
}

type PrekeyUpload = (SpkUpload, Vec<OpkUpload>, SpkUpload, Vec<OpkUpload>);

fn parse_prekey_upload(body: &Value) -> Option<PrekeyUpload> {
    let spk = parse_signed(body.get("spk")?)?;
    let kspk = parse_signed(body.get("kspk")?)?;
    let opks = parse_one_time(body, "opks", MAX_OPKS)?;
    let kopks = parse_one_time(body, "kopks", MAX_KOPKS)?;
    Some((spk, opks, kspk, kopks))
}

/// Anyone may start a session (like /inbox). Consumes the returned OPK; a
/// drained pool returns opk=null and senders fall back to 3-DH.
pub async fn prekey_bundle(State(state): State<Arc<AppState>>) -> Response {
    match state.mailbox.take_bundle() {
        Some(bundle) => Json(bundle).into_response(),
        None => detail(StatusCode::NOT_FOUND, "owner has not published prekeys yet"),
    }
}

// -- inbox --------------------------------------------------------------------

/// Shape checks only — the sealed body is opaque by design; sender, type and
/// session header are all inside it.
fn validate_envelope(envelope: &Value) -> Result<(), Response> {
    let err = |msg: &str| Err(detail(StatusCode::BAD_REQUEST, msg));
    let Some(obj) = envelope.as_object() else { return err("missing fields") };
    for field in ["v", "id", "to", "sealed"] {
        if !obj.contains_key(field) {
            return err("missing fields");
        }
    }
    if obj["v"].as_i64() != Some(WIRE_VERSION) {
        return err(&format!("unsupported protocol version (need v{WIRE_VERSION})"));
    }
    if !obj["id"].as_str().is_some_and(|s| !s.is_empty()) {
        return err("bad id");
    }
    if !obj["sealed"].as_str().is_some_and(|s| !s.is_empty()) {
        return err("bad sealed body");
    }
    if let Some(blob_id) = obj.get("blob_id") {
        if !blob_id.is_null() && !blob_id.as_str().is_some_and(blobs::valid_blob_id) {
            return err("bad blob_id");
        }
    }
    // Delivery hints (PROTOCOL.md "Envelope"): all optional, all booleans.
    for hint in ["transient", "push", "ring"] {
        if let Some(v) = obj.get(hint) {
            if !v.is_boolean() {
                return err(&format!("bad {hint} flag"));
            }
        }
    }
    Ok(())
}

pub async fn inbox(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    if body.len() > MAX_ENVELOPE_BYTES {
        return detail(StatusCode::PAYLOAD_TOO_LARGE, "envelope too large");
    }
    let Ok(envelope) = serde_json::from_slice::<Value>(&body) else {
        return detail(StatusCode::BAD_REQUEST, "not json");
    };
    if let Err(r) = validate_envelope(&envelope) {
        return r;
    }
    if envelope["to"].as_str() != Some(state.cfg.owner_id.as_str()) {
        return detail(StatusCode::FORBIDDEN, "not this mailbox's owner");
    }
    let envelope_json = serde_json::to_string(&envelope).unwrap();

    // Transient envelopes (typing indicators) are only worth anything live:
    // never queued, never woken for. If the owner isn't connected they vanish.
    if envelope.get("transient") == Some(&Value::Bool(true)) {
        let delivered = state.link.push(&envelope_json).await;
        return Json(json!({"status": if delivered { "delivered" } else { "dropped" }}))
            .into_response();
    }

    if !state.mailbox.put(&envelope) {
        return detail(StatusCode::SERVICE_UNAVAILABLE, "mailbox full");
    }
    // Best-effort immediate push; the row is only removed when the device acks.
    let delivered_live = state.link.push(&envelope_json).await;
    if envelope.get("push") != Some(&Value::Bool(false)) {
        // push: false (receipts) → deliver on the next connect, don't wake the
        // phone. ring: true (call offers) → always ping, skipping the debounce.
        let ring = envelope.get("ring") == Some(&Value::Bool(true));
        if delivered_live {
            let id = envelope["id"].as_str().unwrap().to_string();
            tokio::spawn(push::ping_gateway_if_unacked(state.clone(), id, ring));
        } else {
            tokio::spawn(push::ping_gateway(state.clone(), ring));
        }
    }
    Json(json!({"status": "queued"})).into_response()
}

// -- push config / TURN -------------------------------------------------------

pub async fn push_config(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    if let Err(r) = owner_only(&state, &q) {
        return r;
    }
    let parsed: Option<Value> = serde_json::from_slice(&body).ok();
    let Some((device_token, platform)) = parsed.as_ref().and_then(|b| {
        Some((b.get("device_token")?.clone(), b.get("platform")?.clone()))
    }) else {
        return detail(StatusCode::BAD_REQUEST, "expected {device_token, platform}");
    };
    let (Some(device_token), Some(platform)) = (device_token.as_str(), platform.as_str()) else {
        return detail(StatusCode::BAD_REQUEST, "bad platform or token");
    };
    if !matches!(platform, "ios" | "android") {
        return detail(StatusCode::BAD_REQUEST, "bad platform or token");
    }
    state.mailbox.set_push_config(device_token, platform);
    Json(json!({"status": "ok"})).into_response()
}

/// Ephemeral credentials for this box's coturn (TURN REST API scheme).
/// Owner-only: the relay carries the owner's call media, nobody else's.
/// The TURN host is the same address the owner reached this server at.
pub async fn turn_credentials(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = owner_only(&state, &q) {
        return r;
    }
    if state.cfg.turn_secret.is_empty() {
        return detail(StatusCode::NOT_FOUND, "no TURN relay on this mailbox");
    }
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + TURN_TTL_S;
    let username = format!("{expiry}:stonechat");
    let mut mac = Hmac::<Sha1>::new_from_slice(state.cfg.turn_secret.as_bytes()).unwrap();
    mac.update(username.as_bytes());
    let credential = B64.encode(mac.finalize().into_bytes());
    let host = host_from_headers(&headers).unwrap_or_default();
    Json(json!({
        "urls": [format!("turn:{host}:{}?transport=udp", state.cfg.turn_port)],
        "username": username,
        "credential": credential,
        "ttl": TURN_TTL_S,
    }))
    .into_response()
}

/// The hostname the client used, port stripped (Python: request.url.hostname).
fn host_from_headers(headers: &HeaderMap) -> Option<String> {
    let host = headers.get(header::HOST)?.to_str().ok()?;
    Some(if let Some(rest) = host.strip_prefix('[') {
        // [v6::addr]:port
        rest.split(']').next().unwrap_or("").to_string()
    } else {
        host.split(':').next().unwrap_or("").to_string()
    })
}

// -- blobs --------------------------------------------------------------------

pub async fn blob_upload(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    if body.is_empty() {
        return detail(StatusCode::BAD_REQUEST, "empty blob");
    }
    if body.len() > MAX_BLOB_BYTES {
        return detail(StatusCode::PAYLOAD_TOO_LARGE, "blob too large");
    }
    match state.blobs.put(&body) {
        Ok(blob_id) => Json(json!({"blob_id": blob_id})).into_response(),
        Err(blobs::PutError::StorageFull) => {
            detail(StatusCode::INSUFFICIENT_STORAGE, "blob storage full")
        }
    }
}

pub async fn blob_download(
    State(state): State<Arc<AppState>>,
    Path(blob_id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(r) = owner_only(&state, &q) {
        return r;
    }
    if !blobs::valid_blob_id(&blob_id) {
        return detail(StatusCode::BAD_REQUEST, "bad blob id");
    }
    match state.blobs.get(&blob_id) {
        Some(data) => (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            data,
        )
            .into_response(),
        None => detail(StatusCode::NOT_FOUND, "no such blob"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    fn err_of(envelope: &str) -> Option<StatusCode> {
        validate_envelope(&v(envelope)).err().map(|r| r.status())
    }

    #[test]
    fn envelope_validation_matrix() {
        let ok = r#"{"v":1,"id":"x","to":"SC-A","sealed":"aGk="}"#;
        assert!(err_of(ok).is_none());
        // missing fields
        assert_eq!(err_of(r#"{"v":1,"id":"x","to":"SC-A"}"#), Some(StatusCode::BAD_REQUEST));
        assert_eq!(err_of(r#"[]"#), Some(StatusCode::BAD_REQUEST));
        // version
        assert_eq!(err_of(r#"{"v":2,"id":"x","to":"a","sealed":"s"}"#), Some(StatusCode::BAD_REQUEST));
        assert_eq!(err_of(r#"{"v":"1","id":"x","to":"a","sealed":"s"}"#), Some(StatusCode::BAD_REQUEST));
        // id / sealed shape
        assert_eq!(err_of(r#"{"v":1,"id":"","to":"a","sealed":"s"}"#), Some(StatusCode::BAD_REQUEST));
        assert_eq!(err_of(r#"{"v":1,"id":7,"to":"a","sealed":"s"}"#), Some(StatusCode::BAD_REQUEST));
        assert_eq!(err_of(r#"{"v":1,"id":"x","to":"a","sealed":""}"#), Some(StatusCode::BAD_REQUEST));
        // blob_id
        assert!(err_of(r#"{"v":1,"id":"x","to":"a","sealed":"s","blob_id":"123e4567-e89b-42d3-a456-426614174000"}"#).is_none());
        assert_eq!(
            err_of(r#"{"v":1,"id":"x","to":"a","sealed":"s","blob_id":"../etc"}"#),
            Some(StatusCode::BAD_REQUEST)
        );
        // hints must be booleans
        assert!(err_of(r#"{"v":1,"id":"x","to":"a","sealed":"s","transient":true,"push":false,"ring":true}"#).is_none());
        assert_eq!(
            err_of(r#"{"v":1,"id":"x","to":"a","sealed":"s","transient":"yes"}"#),
            Some(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn prekey_upload_parsing() {
        let good = v(
            r#"{"spk":{"id":7,"pub":"p","sig":"s"},"opks":[{"id":1,"pub":"a"},{"id":2,"pub":"b"}],
                "kspk":{"id":3,"pub":"kp","sig":"ks"},"kopks":[{"id":9,"pub":"ka"}]}"#,
        );
        let (spk, opks, kspk, kopks) = parse_prekey_upload(&good).unwrap();
        assert_eq!((spk.id, opks.len(), kspk.id, kopks.len()), (7, 2, 3, 1));
        // one-time pools optional; both signed halves required
        assert!(parse_prekey_upload(
            &v(r#"{"spk":{"id":7,"pub":"p","sig":"s"},"kspk":{"id":3,"pub":"kp","sig":"ks"}}"#)
        )
        .is_some());
        assert!(parse_prekey_upload(&v(r#"{"spk":{"id":7,"pub":"p","sig":"s"}}"#)).is_none());
        // float id, missing sig, non-list pools → reject
        assert!(parse_prekey_upload(
            &v(r#"{"spk":{"id":7.5,"pub":"p","sig":"s"},"kspk":{"id":3,"pub":"kp","sig":"ks"}}"#)
        )
        .is_none());
        assert!(parse_prekey_upload(
            &v(r#"{"spk":{"id":7,"pub":"p"},"kspk":{"id":3,"pub":"kp","sig":"ks"}}"#)
        )
        .is_none());
        assert!(parse_prekey_upload(
            &v(r#"{"spk":{"id":7,"pub":"p","sig":"s"},"kspk":{"id":3,"pub":"kp","sig":"ks"},"opks":{}}"#)
        )
        .is_none());
    }

    /// Same recipe as the retired Python relay, recomputed for the
    /// post-rebrand username: b64(HMAC-SHA1("test-turn-secret", "1760000000:stonechat"))
    #[test]
    fn turn_credential_vector() {
        let mut mac = Hmac::<Sha1>::new_from_slice(b"test-turn-secret").unwrap();
        mac.update(b"1760000000:stonechat");
        assert_eq!(B64.encode(mac.finalize().into_bytes()), "LMWqjiuziEnqliLGAALmWl1Ka+E=");
    }

    #[test]
    fn host_header_parsing() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "203.0.113.7:8080".parse().unwrap());
        assert_eq!(host_from_headers(&h).unwrap(), "203.0.113.7");
        h.insert(header::HOST, "example.com".parse().unwrap());
        assert_eq!(host_from_headers(&h).unwrap(), "example.com");
        h.insert(header::HOST, "[::1]:8080".parse().unwrap());
        assert_eq!(host_from_headers(&h).unwrap(), "::1");
    }
}
