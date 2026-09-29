//! The router, driven in-process: who may call what, and what an anonymous
//! sender can and cannot make the relay do. The recorded corpus in `tests/`
//! pins the wire shapes; this pins the rules.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::link::{self, Close, FrameSink, DRAIN_PAGE, LIVE_FRAMES};
use crate::{blobs, db, limit, AppState, Config};

const OWNER: &str = "SC-TEST-OWNER";
const PRIMARY: &str = "primary-token-0123456789abcdef0123";
const LINKED: &str = "linked-token-0123456789abcdef01234";
const SIBLING: &str = "sibling-token-0123456789abcdef0123";

struct Relay {
    state: Arc<AppState>,
    dir: std::path::PathBuf,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn relay_with(max_queue_bytes: u64, limits: limit::Limits) -> Relay {
    let dir = std::env::temp_dir().join(format!("stonechat-api-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = Arc::new(AppState {
        cfg: Config {
            owner_id: OWNER.into(),
            owner_token: PRIMARY.into(),
            turn_secret: "turn-secret".into(),
            turn_port: 3478,
            push_gateway: String::new(),
            push_key: String::new(),
        },
        mailbox: db::Mailbox::open(":memory:", PRIMARY, max_queue_bytes).unwrap(),
        blobs: blobs::BlobStore::open(&dir.join("blobs")).unwrap(),
        link: link::DeviceLinks::new(),
        tls_fp: String::new(),
        build: String::new(),
        wt_certs: None,
        http: reqwest::Client::new(),
        last_gateway_ping: Mutex::new(HashMap::new()),
        limits,
    });
    Relay { state, dir }
}

/// A mailbox with the primary (1), a linked device (2) and its sibling (3).
fn relay() -> Relay {
    let relay = relay_with(crate::MAX_QUEUE_BYTES, limit::Limits::off());
    assert_eq!(relay.state.mailbox.add_device(LINKED, "linked", None), 2);
    assert_eq!(relay.state.mailbox.add_device(SIBLING, "linked", None), 3);
    relay
}

impl Relay {
    async fn call_from(
        &self,
        peer: Option<&str>,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let body = match body {
            Some(v) => Body::from(serde_json::to_vec(&v).unwrap()),
            None => Body::empty(),
        };
        let mut request = Request::builder().method(method).uri(path).body(body).unwrap();
        if let Some(peer) = peer {
            let addr: SocketAddr = format!("{peer}:4000").parse().unwrap();
            request.extensions_mut().insert(ConnectInfo(addr));
        }
        let response = crate::router(self.state.clone()).oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        self.call_from(None, method, path, body).await
    }

    async fn status_of(&self, method: &str, path: &str, body: Option<Value>) -> u16 {
        self.call(method, path, body).await.0.as_u16()
    }

    async fn park_blob(&self) -> String {
        let request = Request::builder()
            .method("POST")
            .uri("/blob")
            .body(Body::from("ciphertext"))
            .unwrap();
        let response = crate::router(self.state.clone()).oneshot(request).await.unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice::<Value>(&bytes).unwrap()["blob_id"]
            .as_str()
            .unwrap()
            .to_string()
    }
}

fn envelope(id: &str, device: i64) -> Value {
    json!({"v": 1, "id": id, "to": OWNER, "device": device, "sealed": "aGk="})
}

fn prekeys() -> Value {
    json!({"spk": {"id": 1, "pub": "p", "sig": "s"}, "kspk": {"id": 2, "pub": "k", "sig": "ks"}})
}

/// What a connection was sent, in order.
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<String>>>);

impl FrameSink for Recorder {
    async fn text(&mut self, text: String) -> bool {
        let id = serde_json::from_str::<Value>(&text).unwrap()["id"].as_str().unwrap().to_string();
        self.0.lock().unwrap().push(id);
        true
    }
    async fn close(&mut self, (code, _): Close) {
        self.0.lock().unwrap().push(format!("close {code}"));
    }
}

impl Recorder {
    fn ids(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

/// Connect a device the way ws.rs and wt.rs do, recording instead of writing.
async fn connect(relay: &Relay, device: i64) -> (Recorder, tokio::task::JoinHandle<()>) {
    let recorder = Recorder::default();
    let (_, out) = relay.state.link.attach(device).await;
    let queue = relay.state.clone();
    let task = tokio::spawn(link::pump(
        out,
        recorder.clone(),
        move |after| queue.mailbox.page(device, after, DRAIN_PAGE),
        Duration::from_secs(5),
    ));
    (recorder, task)
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

// -- H4: who may manage the mailbox -------------------------------------------

#[tokio::test]
async fn only_the_primary_adds_devices() {
    let r = relay();
    let mint = |token: &str| json!({"device_token": token, "kind": "linked"});
    let fresh = "fresh-token-0123456789abcdef012345";

    assert_eq!(r.status_of("POST", "/devices", Some(mint(fresh))).await, 401);
    assert_eq!(r.status_of("POST", "/devices?token=nope", Some(mint(fresh))).await, 401);

    let (status, body) = r.call("POST", &format!("/devices?token={LINKED}"), Some(mint(fresh))).await;
    assert_eq!(status, 403);
    assert_eq!(body["detail"], "primary device only");
    // Refused before the body is looked at: a linked device learns nothing
    // from a malformed request either.
    assert_eq!(r.status_of("POST", &format!("/devices?token={LINKED}"), Some(json!({}))).await, 403);
    assert!(r.state.mailbox.device_for_token(fresh).is_none());
    assert_eq!(r.state.mailbox.devices().len(), 3);

    let (status, body) = r.call("POST", &format!("/devices?token={PRIMARY}"), Some(mint(fresh))).await;
    assert_eq!(status, 200);
    assert_eq!(body["device_id"], 4);
}

#[tokio::test]
async fn the_revocation_matrix() {
    let r = relay();
    let revoke = |target: i64, token: &str| format!("/devices/{target}?token={token}");

    // Nobody without a token, whatever the target.
    for target in [1, 2, 99] {
        assert_eq!(r.status_of("DELETE", &format!("/devices/{target}"), None).await, 401);
        assert_eq!(r.status_of("DELETE", &revoke(target, "nope"), None).await, 401);
    }

    // The primary cannot be revoked by anyone, itself included.
    for token in [PRIMARY, LINKED] {
        let (status, body) = r.call("DELETE", &revoke(1, token), None).await;
        assert_eq!(status, 403, "{token}");
        assert_eq!(body["detail"], "the primary device cannot be revoked");
    }
    assert_eq!(r.state.mailbox.device_for_token(PRIMARY), Some(1));

    // A linked device cannot revoke a sibling, nor probe for one.
    for target in [3, 99] {
        let (status, body) = r.call("DELETE", &revoke(target, LINKED), None).await;
        assert_eq!(status, 403, "device {target}");
        assert_eq!(body["detail"], "a linked device can revoke only itself");
    }
    assert_eq!(r.state.mailbox.device_for_token(SIBLING), Some(3));

    // It can revoke itself, and is then nobody.
    let before = r.state.mailbox.devices_v();
    let (status, body) = r.call("DELETE", &revoke(2, LINKED), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["devices_v"], before + 1);
    assert_eq!(r.status_of("GET", &format!("/status?token={LINKED}"), None).await, 401);
    assert_eq!(r.status_of("DELETE", &revoke(2, LINKED), None).await, 401);

    // The primary revokes any linked device.
    assert_eq!(r.status_of("DELETE", &revoke(99, PRIMARY), None).await, 404);
    assert_eq!(r.status_of("DELETE", &revoke(3, PRIMARY), None).await, 200);
    assert_eq!(r.state.mailbox.devices().len(), 1);
}

#[tokio::test]
async fn revoking_a_device_closes_its_socket() {
    let r = relay();
    let (seen, task) = connect(&r, 2).await;
    settle().await;
    assert_eq!(r.status_of("DELETE", &format!("/devices/2?token={LINKED}"), None).await, 200);
    tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
    assert_eq!(seen.ids(), [format!("close {}", link::CLOSE_REVOKED)]);
}

#[tokio::test]
async fn a_linked_device_keeps_everything_that_is_its_own() {
    let r = relay();
    for token in [PRIMARY, LINKED] {
        let t = |path: &str| format!("{path}?token={token}");
        let (status, body) = r.call("GET", &t("/status"), None).await;
        assert_eq!(status, 200);
        assert_eq!(body["device_id"], if token == PRIMARY { 1 } else { 2 });
        // A linked device's contacts need this to list the mailbox's
        // devices, and it has no way to derive it.
        assert_eq!(body["bundle_token"].as_str().unwrap().len(), 64, "{token}");
        assert_eq!(r.status_of("POST", &t("/prekeys"), Some(prekeys())).await, 200);
        assert_eq!(
            r.status_of(
                "POST",
                &t("/push-config"),
                Some(json!({"device_token": "t", "platform": "ios"}))
            )
            .await,
            200
        );
        assert_eq!(r.status_of("GET", &t("/devices"), None).await, 200);
        assert_eq!(r.status_of("GET", &t("/turn-credentials"), None).await, 200);
        assert_eq!(r.status_of("GET", &t("/prekeys/devices"), None).await, 200);
    }
    // One device's prekeys are its own: the linked upload left the primary's.
    assert_eq!(r.state.mailbox.prekey_status(1)["spk"], true);
    assert_eq!(r.state.mailbox.prekey_status(3)["spk"], false);

    for path in ["/status", "/devices", "/turn-credentials", "/prekeys/devices"] {
        assert_eq!(r.status_of("GET", path, None).await, 401, "{path}");
    }
    for path in ["/prekeys", "/push-config"] {
        assert_eq!(r.status_of("POST", path, Some(prekeys())).await, 401, "{path}");
    }
}

#[tokio::test]
async fn a_linked_device_cannot_delete_a_blob_a_sibling_is_owed() {
    let r = relay();
    let owed = r.park_blob().await;
    let mut to_sibling = envelope("m-1", 3);
    to_sibling["blob_id"] = json!(owed);
    assert_eq!(r.status_of("POST", "/inbox", Some(to_sibling)).await, 200);

    let delete = |blob: &str, token: &str| format!("/blob/{blob}?token={token}");
    assert_eq!(r.status_of("DELETE", &format!("/blob/{owed}"), None).await, 401);
    let (status, body) = r.call("DELETE", &delete(&owed, LINKED), None).await;
    assert_eq!(status, 403);
    assert_eq!(body["detail"], "blob is still owed to another device");
    assert_eq!(r.status_of("GET", &delete(&owed, SIBLING), None).await, 200);

    // The device that is owed it may; so may anyone once nobody is.
    assert_eq!(r.status_of("DELETE", &delete(&owed, SIBLING), None).await, 200);
    assert_eq!(r.status_of("GET", &delete(&owed, SIBLING), None).await, 404);

    // Group media: parked by the sender, referenced by no queue. The linked
    // device that sent it releases it, as the app does.
    let shared = r.park_blob().await;
    assert_eq!(r.status_of("DELETE", &delete(&shared, LINKED), None).await, 200);

    // The primary manages the mailbox, owed or not.
    let third = r.park_blob().await;
    let mut to_linked = envelope("m-2", 2);
    to_linked["blob_id"] = json!(third);
    assert_eq!(r.status_of("POST", "/inbox", Some(to_linked)).await, 200);
    assert_eq!(r.status_of("DELETE", &delete(&third, PRIMARY), None).await, 200);
}

// -- H5: what an anonymous sender can cost ------------------------------------

#[tokio::test]
async fn a_duplicate_id_is_answered_the_same_and_delivered_once() {
    let r = relay();
    let (seen, task) = connect(&r, 1).await;
    let first = r.call("POST", "/inbox", Some(envelope("e-1", 1))).await;
    settle().await;
    for _ in 0..5 {
        let again = r.call("POST", "/inbox", Some(envelope("e-1", 1))).await;
        assert_eq!(again, first, "a retry must not be told apart from a delivery");
    }
    assert_eq!(first.1["status"], "queued");
    r.call("POST", "/inbox", Some(envelope("e-2", 1))).await;
    settle().await;
    assert_eq!(seen.ids(), ["e-1", "e-2"]);
    assert_eq!(r.state.mailbox.device_depth(1), 2);
    task.abort();
}

#[tokio::test]
async fn a_duplicate_to_an_offline_device_queues_once() {
    let r = relay();
    for _ in 0..3 {
        assert_eq!(r.status_of("POST", "/inbox", Some(envelope("e-1", 1))).await, 200);
    }
    assert_eq!(r.state.mailbox.device_depth(1), 1);
    let (seen, task) = connect(&r, 1).await;
    settle().await;
    assert_eq!(seen.ids(), ["e-1"]);
    task.abort();
}

#[tokio::test]
async fn a_full_queue_drains_in_order_without_being_held_in_memory() {
    let r = relay();
    let total = DRAIN_PAGE * 4 + 3;
    for i in 0..total {
        assert_eq!(r.status_of("POST", "/inbox", Some(envelope(&format!("e-{i:04}"), 1))).await, 200);
    }
    // No read of the queue is ever larger than a page, however deep it is.
    assert_eq!(r.state.mailbox.page(1, 0, DRAIN_PAGE).len(), DRAIN_PAGE);

    let (seen, task) = connect(&r, 1).await;
    settle().await;
    let want: Vec<String> = (0..total).map(|i| format!("e-{i:04}")).collect();
    assert_eq!(seen.ids(), want);

    // Acked rows go; a deposit afterwards still arrives on this connection.
    for id in &want {
        r.state.delete_envelope(1, id);
    }
    r.call("POST", "/inbox", Some(envelope("after", 1))).await;
    settle().await;
    assert_eq!(seen.ids().last().unwrap(), "after");
    assert_eq!(seen.ids().len(), total + 1);
    task.abort();
}

#[tokio::test]
async fn transient_envelopes_are_dropped_once_a_connection_is_behind() {
    let r = relay();
    // Attached, and reading nothing.
    let (_, _out) = r.state.link.attach(1).await;
    let transient = |i: usize| {
        let mut e = envelope(&format!("t-{i}"), 1);
        e["transient"] = json!(true);
        e
    };
    for i in 0..LIVE_FRAMES {
        let (status, body) = r.call("POST", "/inbox", Some(transient(i))).await;
        assert_eq!((status.as_u16(), body["status"].as_str()), (200, Some("delivered")));
    }
    for i in LIVE_FRAMES..LIVE_FRAMES + 50 {
        let (status, body) = r.call("POST", "/inbox", Some(transient(i))).await;
        assert_eq!((status.as_u16(), body["status"].as_str()), (200, Some("dropped")));
    }
    assert_eq!(r.state.mailbox.device_depth(1), 0, "a transient envelope was queued");
    // A real message is not lost to the same backlog: it is in the queue.
    assert_eq!(r.call("POST", "/inbox", Some(envelope("kept", 1))).await.1["status"], "queued");
    assert_eq!(r.state.mailbox.device_depth(1), 1);
}

#[tokio::test]
async fn the_byte_cap_refuses_before_the_row_cap() {
    let one = serde_json::to_string(&envelope("e-0", 1)).unwrap().len() as u64;
    let r = relay_with(one * 3, limit::Limits::off());
    r.state.mailbox.add_device(LINKED, "linked", None);
    for i in 0..3 {
        assert_eq!(r.status_of("POST", "/inbox", Some(envelope(&format!("e-{i}"), 1))).await, 200);
    }
    let (status, body) = r.call("POST", "/inbox", Some(envelope("e-3", 1))).await;
    assert_eq!(status, 503);
    assert_eq!(body["detail"], "mailbox full");
    // Per device, and an ack makes room.
    assert_eq!(r.status_of("POST", "/inbox", Some(envelope("e-3", 2))).await, 200);
    r.state.delete_envelope(1, "e-0");
    assert_eq!(r.status_of("POST", "/inbox", Some(envelope("e-3", 1))).await, 200);
}

#[tokio::test]
async fn deposits_are_rate_limited_per_address_and_in_total() {
    let limits = limit::Limits {
        inbox: limit::Limiter::parse("0.001/3,0.001/5").unwrap(),
        blob: limit::Limiter::parse("0.001/1,0.001/5").unwrap(),
        bundle: limit::Limiter::parse("0.001/2,0.001/5").unwrap(),
    };
    let r = relay_with(crate::MAX_QUEUE_BYTES, limits);
    r.call("POST", &format!("/prekeys?token={PRIMARY}"), Some(prekeys())).await;

    let mut statuses = Vec::new();
    for i in 0..5 {
        let e = Some(envelope(&format!("e-{i}"), 1));
        statuses.push(r.call_from(Some("203.0.113.7"), "POST", "/inbox", e).await.0.as_u16());
    }
    assert_eq!(statuses, [200, 200, 200, 429, 429]);
    let (status, body) =
        r.call_from(Some("203.0.113.7"), "POST", "/inbox", Some(envelope("x", 1))).await;
    assert_eq!(status, 429);
    assert_eq!(body["detail"], "too many requests");
    assert_eq!(r.state.mailbox.device_depth(1), 3, "a refused deposit was stored");

    // Somebody else still gets through, until the ceiling for everybody.
    let e = |id: &str| Some(envelope(id, 1));
    assert_eq!(r.call_from(Some("203.0.113.8"), "POST", "/inbox", e("b-1")).await.0, 200);
    // No address at all (a transport that could not supply one): global only.
    assert_eq!(r.call("POST", "/inbox", e("c-1")).await.0, 200);
    assert_eq!(r.call_from(Some("203.0.113.9"), "POST", "/inbox", e("d-1")).await.0, 429);
    assert_eq!(r.call("POST", "/inbox", e("c-2")).await.0, 429);

    // Each route has its own budget.
    let from = Some("203.0.113.7");
    assert_eq!(r.call_from(from, "GET", "/prekeys/bundle", None).await.0, 200);
    assert_eq!(r.call_from(from, "GET", "/prekeys/bundle", None).await.0, 200);
    assert_eq!(r.call_from(from, "GET", "/prekeys/bundle", None).await.0, 429);
    assert_eq!(r.call_from(from, "POST", "/blob", Some(json!("x"))).await.0, 200);
    assert_eq!(r.call_from(from, "POST", "/blob", Some(json!("x"))).await.0, 429);

    // And nothing the owner does is metered.
    for _ in 0..20 {
        let path = format!("/status?token={PRIMARY}");
        assert_eq!(r.call_from(from, "GET", &path, None).await.0, 200);
    }
}
