//! HTTP handlers. Status codes, JSON shapes and error bodies keep the
//! FastAPI-era `{"detail": "<msg>"}` shape inherited from the retired
//! Python relay — the conformance harness (tests/conformance.py) diffs
//! bodies against recorded goldens, so the shape is load-bearing.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use blake2::Digest;
use base64::Engine;
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha1::Sha1;
use tokio::io::AsyncReadExt;

use crate::db::{OpkUpload, Put, SpkUpload, PRIMARY_DEVICE};
use crate::{blobs, push, AppState, BLOB_CHUNK_BYTES, MAX_BLOB_BYTES, MAX_CERT_BYTES, MAX_ENVELOPE_BYTES, MAX_KOPKS, MAX_OPKS, MAX_PREKEY_UPLOAD_BYTES, TURN_TTL_S, WIRE_VERSION};

fn detail(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({"detail": msg}))).into_response()
}

/// Which device is calling. Any device token authenticates; device 1's token
/// is `STONECHAT_OWNER_TOKEN`, so every existing client keeps working
/// unchanged (MULTIDEVICE.md "Device model"). The 401 body is the historical
/// "owner only" either way — a caller holding no valid token learns nothing
/// about how many devices exist.
///
/// This is authentication, and for a device's *own* things — its socket, its
/// queue, its prekeys, its push registration — it is all that is needed.
/// Managing the mailbox is more than that: see [`auth_primary`].
fn auth_device(state: &AppState, q: &HashMap<String, String>) -> Result<i64, Response> {
    let given = q.get("token").map(String::as_str).unwrap_or("");
    state
        .mailbox
        .device_for_token(given)
        .ok_or_else(|| detail(StatusCode::UNAUTHORIZED, "owner only"))
}

/// The primary, and nobody else. A linked device holds a certificate and a
/// token for its own queue; it does not get to decide which devices the
/// mailbox has, because a stolen one would then decide it too. 401 for no
/// valid token, as everywhere; 403 for a valid token on the wrong device.
fn auth_primary(state: &AppState, q: &HashMap<String, String>) -> Result<(), Response> {
    match auth_device(state, q)? {
        PRIMARY_DEVICE => Ok(()),
        _ => Err(detail(StatusCode::FORBIDDEN, "primary device only")),
    }
}

/// The derived per-mailbox capability that lets an established contact list
/// devices without being able to do anything else here. Not the owner token,
/// and it consumes no prekeys — see MULTIDEVICE.md "Why the device list is
/// gated".
fn bundle_token(owner_token: &str) -> String {
    let mut h = blake2::Blake2b::<blake2::digest::consts::U32>::new();
    h.update(owner_token.as_bytes());
    h.update(b"|stonechat-bundle|");
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn bundle_reader_only(state: &AppState, q: &HashMap<String, String>) -> Result<(), Response> {
    let given = q.get("token").map(String::as_str).unwrap_or("");
    if blobs::secret_eq(given, &bundle_token(&state.cfg.owner_token))
        || state.mailbox.device_for_token(given).is_some()
    {
        return Ok(());
    }
    Err(detail(StatusCode::UNAUTHORIZED, "owner only"))
}

/// Read access to one blob: the owner token, or that blob's derived fetch
/// token. Same 401 body either way — a caller holding neither learns nothing
/// about which of the two it failed.
fn blob_reader_only(
    state: &AppState,
    q: &HashMap<String, String>,
    blob_id: &str,
) -> Result<(), Response> {
    let given = q.get("token").map(String::as_str).unwrap_or("");
    let shared = blobs::secret_eq(given, &blobs::fetch_token(&state.cfg.owner_token, blob_id));
    if shared || state.mailbox.device_for_token(given).is_some() {
        return Ok(());
    }
    Err(detail(StatusCode::UNAUTHORIZED, "owner only"))
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
    let device = match auth_device(&state, &q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    Json(json!({
        "status": "ok",
        "v": WIRE_VERSION,
        "queued": state.mailbox.device_depth(device),
        "prekeys": state.mailbox.prekey_status(device),
        "device_id": device,
        "devices_v": state.mailbox.devices_v(),
        // Handed to every authenticated device, not just device 1: a linked
        // device has to be able to tell its own contacts how to list this
        // mailbox's devices, and it cannot derive the token itself (that
        // needs the owner token, which it deliberately does not hold).
        "bundle_token": bundle_token(&state.cfg.owner_token),
        // Deliberately here and not on /health, which is unauthenticated: an
        // exact build fingerprint handed to anyone who asks tells an attacker
        // precisely which version to target the day a relay bug is published.
        "build": state.build,
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
    let device = match auth_device(&state, &q) {
        Ok(d) => d,
        Err(r) => return r,
    };
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
    // A JSON object on the wire, stored as the text of itself. "Opaque" here
    // means we never look inside — not that we refuse to carry structure;
    // making clients double-encode a JSON object into a JSON string would buy
    // nothing and cost every client a serialization step. Size-capped,
    // because a blob this box cannot read is one it should not store much of.
    let cert = match parsed.get("cert") {
        None | Some(Value::Null) => None,
        Some(Value::Object(_)) => {
            let text = parsed["cert"].to_string();
            if text.len() > MAX_CERT_BYTES {
                return detail(StatusCode::PAYLOAD_TOO_LARGE, "cert too large");
            }
            Some(text)
        }
        Some(_) => return detail(StatusCode::BAD_REQUEST, "bad cert"),
    };
    state.mailbox.set_prekeys(device, &spk, &opks, &kspk, &kopks, cert.as_deref());
    Json(json!({"status": "ok", "prekeys": state.mailbox.prekey_status(device)})).into_response()
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
///
/// Unauthenticated it serves **device 1 only**, in exactly the shape and at
/// exactly the cost it always did — one request, one OPK. `?device=` selects
/// a sibling and requires the bundle token, so no single open call can burn a
/// prekey per device (MULTIDEVICE.md "Why the device list is gated").
pub async fn prekey_bundle(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let device = match q.get("device") {
        None => crate::db::PRIMARY_DEVICE,
        Some(raw) => {
            if let Err(r) = bundle_reader_only(&state, &q) {
                return r;
            }
            match raw.parse::<i64>() {
                Ok(d) => d,
                Err(_) => return detail(StatusCode::BAD_REQUEST, "bad device"),
            }
        }
    };
    match state.mailbox.take_bundle(device) {
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
    // Which device this copy is for. Required, not defaulted: the AEAD's
    // associated data binds this number, so an implicit value would mean
    // sender and receiver having to agree on what "absent" meant.
    let devices_v = state.mailbox.devices_v();
    let device = match envelope
        .get("device")
        .and_then(|v| v.as_i64().filter(|_| v.is_i64()))
    {
        Some(d) => d,
        None => return detail(StatusCode::BAD_REQUEST, "bad device"),
    };
    // A revoked or never-minted device is a permanent failure for this copy,
    // not a retry: 410 carries the current devices_v so the sender re-fetches
    // the bundle and stops encrypting to a device that no longer exists.
    if !state.mailbox.devices().iter().any(|d| d.device_id == device) {
        return (
            StatusCode::GONE,
            Json(json!({"detail": "no such device", "devices_v": devices_v})),
        )
            .into_response();
    }
    let envelope_json = serde_json::to_string(&envelope).unwrap();

    // Transient envelopes (typing indicators) are only worth anything live:
    // never queued, never woken for. If the device isn't connected, or is
    // too far behind to take one more, they vanish.
    if envelope.get("transient") == Some(&Value::Bool(true)) {
        let delivered = state.link.push_transient(device, &envelope_json).await;
        return Json(json!({
            "status": if delivered { "delivered" } else { "dropped" },
            "devices_v": devices_v,
        }))
        .into_response();
    }

    let id = envelope["id"].as_str().unwrap();
    match state.mailbox.put(device, id, &envelope_json) {
        Put::Full => return detail(StatusCode::SERVICE_UNAVAILABLE, "mailbox full"),
        // Already queued: answered exactly as the first delivery was, and
        // otherwise a no-op. Sending it down the socket or pinging the
        // gateway again would let one envelope, replayed, do both forever.
        Put::Duplicate => {
            return Json(json!({"status": "queued", "devices_v": devices_v})).into_response()
        }
        Put::Queued => {}
    }
    // Best-effort immediate delivery: a connected device is woken and reads
    // the row from its queue. The row is only removed when the device acks.
    let delivered_live = state.link.wake(device).await;
    if envelope.get("push") != Some(&Value::Bool(false)) {
        // push: false (receipts) → deliver on the next connect, don't wake the
        // phone. ring: true (call offers) → a shorter grace and debounce.
        let ring = envelope.get("ring") == Some(&Value::Bool(true));
        if delivered_live {
            tokio::spawn(push::ping_gateway_if_unacked(state.clone(), device, id.to_string(), ring));
        } else {
            tokio::spawn(push::ping_gateway(state.clone(), device, ring));
        }
    }
    Json(json!({"status": "queued", "devices_v": devices_v})).into_response()
}

// -- devices (MULTIDEVICE.md "Device model") ----------------------------------

/// List this mailbox's devices. Any device token: a linked desktop should be
/// able to show the same device list the phone shows. Showing is all — what
/// a linked device may *do* to the list is remove itself from it.
pub async fn list_devices(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(r) = auth_device(&state, &q) {
        return r;
    }
    Json(json!({
        "devices_v": state.mailbox.devices_v(),
        "devices": state.mailbox.devices().iter().map(|d| json!({
            "device_id": d.device_id,
            "kind": d.kind,
            "cert": d.cert,
            "created_at": d.created_at,
            "expires_at": d.expires_at,
            "last_seen": d.last_seen,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

/// Mint a device on behalf of the one being linked. The caller supplies the
/// token it is about to seal into the link grant, so the new device's secret
/// is chosen by a device the user already trusts and never transits this
/// handler's response in a form the relay could correlate later — the relay
/// stores only its hash.
///
/// Primary only. A new device is worth nothing without a certificate, and
/// only the primary can sign one; a linked device minting rows could do no
/// good with them and, if stolen, could mint itself a successor with no
/// expiry to outlive its own revocation.
pub async fn mint_device(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    if let Err(r) = auth_primary(&state, &q) {
        return r;
    }
    let parsed: Option<Value> = serde_json::from_slice(&body).ok();
    let Some(token) = parsed
        .as_ref()
        .and_then(|b| b.get("device_token"))
        .and_then(Value::as_str)
        .filter(|t| t.len() >= 32)
    else {
        return detail(
            StatusCode::BAD_REQUEST,
            "expected {device_token} of at least 32 chars",
        );
    };
    if state.mailbox.device_for_token(token).is_some() {
        return detail(StatusCode::CONFLICT, "token already in use");
    }
    let body = parsed.as_ref().unwrap();
    let kind = match body.get("kind").and_then(Value::as_str) {
        None => "linked",
        // "agent" is a headless device: no screen, no user, and typically not
        // on hardware the owner is holding (agent_client/README.md). The relay
        // treats it exactly like any other device — the kind is recorded so
        // the device list can say what it is and the authorising device can
        // pick a certificate lifetime for it.
        Some(k @ ("linked" | "web" | "agent")) => k,
        // "primary" is not mintable: device 1 is whoever holds the owner
        // token, and a second claimant to that role would be a lie.
        Some(_) => return detail(StatusCode::BAD_REQUEST, "bad kind"),
    };
    // A bounded session ends by itself. WEB_CLIENT.md's whole defence is that
    // a browser's authority is short-lived and revocable, so the lifetime is
    // set here, at mint time, by the device doing the authorising.
    let expires_at = match body.get("expires_in_s") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_i64().filter(|s| *s > 0 && *s <= 365 * 24 * 3600) {
            Some(secs) => Some(
                (chrono::Utc::now() + chrono::Duration::seconds(secs))
                    .to_rfc3339_opts(chrono::SecondsFormat::Micros, false),
            ),
            None => return detail(StatusCode::BAD_REQUEST, "bad expires_in_s"),
        },
    };
    let device_id = state.mailbox.add_device(token, kind, expires_at.as_deref());
    Json(json!({
        "device_id": device_id,
        "kind": kind,
        "expires_at": expires_at,
        "devices_v": state.mailbox.devices_v(),
    }))
    .into_response()
}

/// Revoke a device: its queue, prekeys and push registration go, and its
/// socket is cut now rather than at the next reconnect.
///
/// The primary revokes any linked device — a stolen laptop is revoked *from*
/// the phone. A linked device revokes itself and nothing else, which is
/// "sign out"; were it able to revoke its siblings, stealing one device
/// would be enough to evict all the others. Nobody revokes the primary here:
/// its token is the mailbox's own, and the way to retire it is to move the
/// mailbox.
///
/// Honest limit, restated from MULTIDEVICE.md: this is a delivery cut, not a
/// cryptographic excision. The revoked device keeps its device keys and its
/// certificate until that expires, and everything it already received.
pub async fn revoke_device(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let caller = match auth_device(&state, &q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let Ok(device_id) = device_id.parse::<i64>() else {
        return detail(StatusCode::BAD_REQUEST, "bad device");
    };
    // Decided before the device is looked up, so a linked device asking
    // about ids that are not its own learns nothing about which exist.
    if device_id == PRIMARY_DEVICE {
        return detail(StatusCode::FORBIDDEN, "the primary device cannot be revoked");
    }
    if caller != PRIMARY_DEVICE && caller != device_id {
        return detail(StatusCode::FORBIDDEN, "a linked device can revoke only itself");
    }
    let (existed, blob_ids) = state.mailbox.remove_device(device_id);
    if !existed {
        return detail(StatusCode::NOT_FOUND, "no such device");
    }
    // Blobs the dropped envelopes referenced may still be owed to a sibling.
    for blob_id in blob_ids {
        if state.mailbox.blob_refcount(&blob_id) == 0 {
            state.blobs.delete(&blob_id);
        }
    }
    state.link.disconnect(device_id).await;
    Json(json!({"status": "ok", "devices_v": state.mailbox.devices_v()})).into_response()
}

/// Every device's signed prekeys, consuming **no** one-time keys. The free
/// listing half of the bundle split: a sender learns the device set here and
/// then pays exactly one OPK per device it actually needs to X3DH with.
pub async fn prekey_devices(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(r) = bundle_reader_only(&state, &q) {
        return r;
    }
    Json(json!({
        "devices_v": state.mailbox.devices_v(),
        "devices": state.mailbox.device_prekeys(),
    }))
    .into_response()
}

// -- push config / TURN -------------------------------------------------------

pub async fn push_config(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    let device = match auth_device(&state, &q) {
        Ok(d) => d,
        Err(r) => return r,
    };
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
    state.mailbox.set_push_config(device, device_token, platform);
    Json(json!({"status": "ok"})).into_response()
}

/// Ephemeral credentials for this box's coturn (TURN REST API scheme).
/// Any of the owner's devices — a call is answered on whichever one is in
/// hand — and nobody else: the relay carries the owner's call media only.
/// The TURN host is the same address the owner reached this server at.
pub async fn turn_credentials(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = auth_device(&state, &q) {
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

/// Unauthenticated, like `/inbox`: anyone may park ciphertext for this box's
/// owner. `?shared=1` additionally returns the blob's fetch token — the group
/// -media path, where the uploader is the owner and the readers are their
/// fellow members (PROTOCOL.md "Groups").
/// The body streams to disk in chunks and is never held whole: see blobs.rs.
/// Taking `Body` rather than `Bytes` opts out of the router's
/// `DefaultBodyLimit`, which only bounds extractors that buffer — so the
/// MAX_BLOB_BYTES cap is enforced here, per chunk, and a client that lies in
/// Content-Length is cut off at the same byte either way.
pub async fn blob_upload(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    // Cheap pre-checks on a declared length: refuse before streaming rather
    // than after. Both are re-checked against what actually lands.
    if let Some(declared) = content_length(&headers) {
        if declared > MAX_BLOB_BYTES as u64 {
            return detail(StatusCode::PAYLOAD_TOO_LARGE, "blob too large");
        }
        if !state.blobs.has_room(declared) {
            return detail(StatusCode::INSUFFICIENT_STORAGE, "blob storage full");
        }
    }

    let mut incoming = match state.blobs.begin().await {
        Ok(inc) => inc,
        Err(_) => return detail(StatusCode::INSUFFICIENT_STORAGE, "blob storage full"),
    };
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            // Client vanished or the transport failed; Drop takes the partial.
            return detail(StatusCode::BAD_REQUEST, "upload interrupted");
        };
        if incoming.len() + chunk.len() as u64 > MAX_BLOB_BYTES as u64 {
            return detail(StatusCode::PAYLOAD_TOO_LARGE, "blob too large");
        }
        if incoming.write(&chunk).await.is_err() {
            return detail(StatusCode::INSUFFICIENT_STORAGE, "blob storage full");
        }
    }
    if incoming.len() == 0 {
        return detail(StatusCode::BAD_REQUEST, "empty blob");
    }

    let shared = matches!(q.get("shared").map(String::as_str), Some("1" | "true"));
    match state.blobs.commit(incoming).await {
        Ok(blob_id) if shared => {
            let token = blobs::fetch_token(&state.cfg.owner_token, &blob_id);
            Json(json!({"blob_id": blob_id, "fetch_token": token})).into_response()
        }
        Ok(blob_id) => Json(json!({"blob_id": blob_id})).into_response(),
        Err(blobs::PutError::StorageFull) => {
            detail(StatusCode::INSUFFICIENT_STORAGE, "blob storage full")
        }
    }
}

/// Accepts the owner token (the DM path: you fetching your own queued media)
/// or *this blob's* fetch token (the group path: a fellow member fetching the
/// single copy the sender parked here).
pub async fn blob_download(
    State(state): State<Arc<AppState>>,
    Path(blob_id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(r) = blob_reader_only(&state, &q, &blob_id) {
        return r;
    }
    if !blobs::valid_blob_id(&blob_id) {
        return detail(StatusCode::BAD_REQUEST, "bad blob id");
    }
    match state.blobs.open_read(&blob_id).await {
        // Streamed from disk in chunks (blobs.rs): a group of members fetching
        // one video must not cost the mailbox one full copy of it per reader.
        // Content-Length is set explicitly — buffering used to supply it, and
        // clients show upload/download progress with it.
        Some((file, len)) => (
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CONTENT_LENGTH, &len.to_string()[..]),
            ],
            Body::from_stream(file_chunks(file)),
        )
            .into_response(),
        None => detail(StatusCode::NOT_FOUND, "no such blob"),
    }
}

/// A blob file as a chunk stream. Yields at most one read error and then ends,
/// so a mid-read failure truncates the response instead of spinning.
fn file_chunks(
    file: tokio::fs::File,
) -> impl futures_util::Stream<Item = std::io::Result<Bytes>> {
    futures_util::stream::unfold(Some(file), |state| async move {
        let mut file = state?;
        let mut buf = vec![0u8; BLOB_CHUNK_BYTES];
        match file.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok(Bytes::from(buf)), Some(file)))
            }
            Err(e) => Some((Err(e), None)),
        }
    })
}

/// Declared body size, when the client sends one.
fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers.get(header::CONTENT_LENGTH)?.to_str().ok()?.parse().ok()
}

/// Reclaim the space a shared group blob holds once every member has fetched
/// it. Without this a group photo would sit out the full BLOB_TTL against the
/// sender's own storage cap. Idempotent — deleting a blob that is already
/// gone is a success, so a retried cleanup never errors.
///
/// Any device, because any device sends group media and parks the blob here;
/// but a linked device may not delete one a sibling still has queued, which
/// is the only blob whose loss would cost anybody anything.
pub async fn blob_delete(
    State(state): State<Arc<AppState>>,
    Path(blob_id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let caller = match auth_device(&state, &q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    if !blobs::valid_blob_id(&blob_id) {
        return detail(StatusCode::BAD_REQUEST, "bad blob id");
    }
    if caller != PRIMARY_DEVICE && state.mailbox.blob_owed_to_sibling(&blob_id, caller) {
        return detail(StatusCode::FORBIDDEN, "blob is still owed to another device");
    }
    state.blobs.delete(&blob_id);
    Json(json!({"status": "ok"})).into_response()
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

/// The browser transport's certificate schedule.
///
/// Unauthenticated on purpose: every value in it is a hash of a certificate
/// this relay hands to anyone who connects. What makes it *trustworthy* is not
/// this endpoint — it is the owner's signature over the same list, published
/// in the hub directory. A client that takes these hashes without checking
/// that signature has pinned whatever the network told it to.
pub async fn wt_certs(State(state): State<Arc<AppState>>) -> Response {
    match &state.wt_certs {
        Some(schedule) => Json(schedule.published(chrono::Utc::now().timestamp())).into_response(),
        None => (StatusCode::NOT_FOUND, "browser transport disabled").into_response(),
    }
}
