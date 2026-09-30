//! Stonechat relay — the program behind a single user's encrypted mailbox.
//!
//! The relay implementation (ported from the retired Python relay;
//! PROTOCOL.md "Mailbox API" is the wire contract). Runs on a VM the user owns.
//! Stores only sealed envelopes addressed to its owner and deletes each one
//! the moment the owner's device acks it. Plaintext never exists here, and
//! neither does sender identity: everything beyond the recipient rides inside
//! an anonymous sealed box only the owner can open (PROTOCOL.md "Envelope").
//! It also serves the owner's PUBLIC prekeys so peers can start
//! forward-secret sessions while the owner is offline.
//!
//! Config (env):
//!     STONECHAT_OWNER_ID     Stonechat ID of the owner (the only valid recipient)
//!     STONECHAT_OWNER_TOKEN  device 1's token: the primary device presents it on
//!                            every authenticated route. Other devices have
//!                            tokens of their own, minted by the primary.
//!     STONECHAT_PORT         listen port (default 8080)
//!     STONECHAT_DB           sqlite path (default ./mailbox.db)
//!     STONECHAT_BLOBS        blob dir (default ./blobs)
//!     STONECHAT_TLS_DIR      where the TLS key/cert live (default: the DB's directory)
//!     STONECHAT_MAX_QUEUE_BYTES  per-device cap on queued envelope bytes (default 64 MiB)
//!     STONECHAT_LIMIT_INBOX / _BLOB / _BUNDLE   deposit rate limits (limit.rs)
//!
//! Transport: everything is served over TLS with a self-signed certificate
//! generated on first boot (or reused from disk — the fingerprint clients pin
//! must survive a Python→Rust swap on the same volume).

#[cfg(test)]
mod api_tests;
mod blobs;
mod db;
mod limit;
mod link;
mod push;
mod routes;
mod tls;
mod wt;
mod wtcert;
mod ws;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;

pub const WIRE_VERSION: i64 = 1;
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
pub const MAX_QUEUE_DEPTH: i64 = 10_000;
/// Default for `STONECHAT_MAX_QUEUE_BYTES`. The row cap alone allows 640 MiB
/// per device; this is what a device's queue may actually weigh. Text
/// envelopes run to a few KB each, so the row cap is still the one a real
/// backlog meets first.
pub const MAX_QUEUE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_BLOB_BYTES: usize = 64 * 1024 * 1024; // videos/documents; mirrored in the app
pub const MAX_TOTAL_BLOB_BYTES: u64 = 1024 * 1024 * 1024;
/// How much of a blob is in memory at once, either direction (blobs.rs).
/// Peak RSS is a function of this and the number of concurrent transfers —
/// never of MAX_BLOB_BYTES, which is the whole point of streaming them.
pub const BLOB_CHUNK_BYTES: usize = 64 * 1024;
pub const BLOB_TTL: Duration = Duration::from_secs(14 * 24 * 3600);
pub const MAX_OPKS: usize = 256;
// ML-KEM-768 one-time prekeys are ~1.6 KB each as base64 (docs/POST_QUANTUM.md);
// prekey uploads get their own body cap so a full restock fits one request.
pub const MAX_KOPKS: usize = 64;
pub const MAX_PREKEY_UPLOAD_BYTES: usize = 256 * 1024;
/// A device certificate is an X-Wing public key (1216 bytes) plus a little
/// framing, base64'd — a few KB. Capped rather than validated: the relay
/// cannot read it (core/src/devcert.rs) and has no business trying.
pub const MAX_CERT_BYTES: usize = 8 * 1024;
pub const PUSH_DEBOUNCE: Duration = Duration::from_secs(5);
/// Call offers ring through the ordinary debounce, not through all of it.
pub const PUSH_DEBOUNCE_RING: Duration = Duration::from_secs(2);
// A socket write succeeding is not delivery: a freshly-backgrounded phone
// keeps its TCP connection open while the suspended app never reads the
// frame. Live delivery only counts once the device acks — envelopes still
// queued after this grace window get a gateway ping like any offline
// delivery. Call offers use the shorter window; ringing can't wait.
pub const PUSH_ACK_GRACE: Duration = Duration::from_secs(10);
pub const PUSH_ACK_GRACE_RING: Duration = Duration::from_secs(2);
pub const TURN_TTL_S: u64 = 6 * 3600;

pub struct Config {
    pub owner_id: String,
    pub owner_token: String,
    pub turn_secret: String,
    pub turn_port: u16,
    pub push_gateway: String,
    pub push_key: String,
}

pub struct AppState {
    pub cfg: Config,
    pub mailbox: db::Mailbox,
    pub blobs: blobs::BlobStore,
    pub link: link::DeviceLinks,
    pub tls_fp: String,
    /// Which binary this process is running: BLAKE2b-256 of its own
    /// executable, first 16 hex characters.
    ///
    /// The relay can be upgraded **in place** — the new binary copied over the
    /// entrypoint and the container restarted — which is what keeps a mailbox's
    /// data alive across a release. That leaves the operator needing to know
    /// whether the swap actually took, and a version baked in at compile time
    /// cannot answer it: it would report the new number whether or not the file
    /// on disk changed. Hashing the file we are executing does.
    pub build: String,
    /// The browser transport's certificate schedule, if it is enabled.
    pub wt_certs: Option<Arc<wtcert::CertSchedule>>,
    pub http: reqwest::Client,
    /// Keyed by (device, ring) — see push::ping_due.
    pub last_gateway_ping: Mutex<HashMap<(i64, bool), Instant>>,
    pub limits: limit::Limits,
}

impl AppState {
    /// Delete one device's copy of an acked envelope, and release its blob if
    /// that was the last copy owed to anyone.
    ///
    /// Refcounted rather than deleted outright: with per-device fan-out the
    /// same `blob_id` is referenced by one envelope per device, and the first
    /// device to ack must not pull the file out from under its siblings
    ///
    /// Blobs with *no* referencing envelope are untouched here — that is the
    /// token-shared mode group media uses, where the ciphertext sits on the
    /// sender's own mailbox and is read by capability token. Those live out
    /// their TTL or die by explicit DELETE.
    pub fn delete_envelope(&self, device: i64, envelope_id: &str) {
        if let Some(blob_id) = self.mailbox.delete(device, envelope_id) {
            if self.mailbox.blob_refcount(&blob_id) == 0 {
                self.blobs.delete(&blob_id);
            }
        }
    }
}

/// BLAKE2b-256 of our own executable, truncated. Empty when it cannot be read
/// — an unreadable binary is not worth refusing to boot over, and an empty
/// build id reads as "unknown" rather than as a wrong answer.
fn own_build_id() -> String {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    let Ok(path) = std::env::current_exe() else {
        return String::new();
    };
    let Ok(bytes) = std::fs::read(path) else {
        return String::new();
    };
    let mut h = Blake2b::<U32>::new();
    h.update(&bytes);
    h.finalize().iter().take(8).map(|b| format!("{b:02x}")).collect()
}

pub fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Every route, once. Both transports serve this router (wt.rs "One router,
/// two transports"), and the tests drive it directly.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(routes::health))
        .route("/status", get(routes::status))
        .route("/owner", get(routes::owner_check))
        .route("/prekeys", post(routes::upload_prekeys))
        .route("/prekeys/bundle", get(routes::prekey_bundle))
        .route("/prekeys/devices", get(routes::prekey_devices))
        .route("/devices", get(routes::list_devices).post(routes::mint_device))
        .route("/devices/{device_id}", axum::routing::delete(routes::revoke_device))
        .route("/inbox", post(routes::inbox))
        .route("/push-config", post(routes::push_config))
        .route("/turn-credentials", get(routes::turn_credentials))
        .route("/blob", post(routes::blob_upload))
        .route(
            "/blob/{blob_id}",
            get(routes::blob_download).delete(routes::blob_delete),
        )
        .route("/ws", get(ws::ws_owner))
        // Public by design: these are hashes of certificates the relay is
        // about to present anyway. The owner's signature over them lives in
        // the hub directory — this endpoint states, it does not vouch.
        .route("/wt/certs", get(routes::wt_certs))
        // Bounds every route that buffers its body into `Bytes` — envelopes,
        // prekeys, certs. Blobs are the one large body and they no longer
        // buffer (routes.rs takes `Body` and streams, which opts out of this
        // layer and enforces MAX_BLOB_BYTES itself), so this can sit just above
        // the largest of the rest instead of at blob size. It was 64 MiB, which
        // meant a junk POST to /inbox could make the relay hold 64 MiB before
        // the handler's own 64 KiB check ever ran.
        .layer(DefaultBodyLimit::max(MAX_PREKEY_UPLOAD_BYTES + 1024))
        // Outermost, so a refused deposit costs a map lookup and nothing else.
        .layer(axum::middleware::from_fn_with_state(state.clone(), limit::guard))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls crypto provider");

    let owner_id = std::env::var("STONECHAT_OWNER_ID").expect("STONECHAT_OWNER_ID is required");
    let owner_token = std::env::var("STONECHAT_OWNER_TOKEN").expect("STONECHAT_OWNER_TOKEN is required");
    let db_path = env_or("STONECHAT_DB", "mailbox.db");
    let blob_dir = PathBuf::from(env_or("STONECHAT_BLOBS", "blobs"));
    let tls_dir = match std::env::var("STONECHAT_TLS_DIR") {
        Ok(d) => PathBuf::from(d),
        Err(_) => Path::new(&db_path)
            .canonicalize()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| {
                // DB not created yet: resolve its parent lexically like Python's
                // Path(DB_PATH).resolve().parent
                let p = std::env::current_dir().unwrap().join(&db_path);
                p.parent().unwrap().to_path_buf()
            }),
    };
    let port: u16 = env_or("STONECHAT_PORT", "8080").parse().expect("bad STONECHAT_PORT");
    // The browser transport is UDP and separate from the TLS listener, so a
    // host that blocks UDP loses browser sessions and nothing else. Set to 0
    // to turn it off entirely.
    let wt_port: u16 = env_or("STONECHAT_WT_PORT", "8443")
        .parse()
        .expect("bad STONECHAT_WT_PORT");

    let max_queue_bytes: u64 = env_or("STONECHAT_MAX_QUEUE_BYTES", &MAX_QUEUE_BYTES.to_string())
        .parse()
        .expect("bad STONECHAT_MAX_QUEUE_BYTES");

    let cfg = Config {
        owner_id,
        owner_token,
        turn_secret: env_or("STONECHAT_TURN_SECRET", ""),
        turn_port: env_or("STONECHAT_TURN_PORT", "3478").parse().expect("bad STONECHAT_TURN_PORT"),
        push_gateway: env_or("STONECHAT_PUSH_GATEWAY", "").trim_end_matches('/').to_string(),
        push_key: env_or("STONECHAT_PUSH_KEY", ""),
    };

    let tls = tls::Tls::load_or_generate(&tls_dir).expect("TLS setup failed");
    // Generated even when the endpoint is off, so turning it on later does not
    // hand every client a schedule they have never seen.
    // The names the browser transport's certificates carry. A certificate with
    // no subjectAltName is refused by browsers outright — CommonName has not
    // been a name for years — and the rejection reads as a pin mismatch, which
    // it is not.
    //
    // The relay cannot discover this itself: in a container it sees a private
    // address, and the address clients dial is the host's. Whoever creates the
    // container knows it, so they pass it. Loopback is always included so a
    // developer running the binary directly needs no configuration.
    let mut wt_sans: Vec<String> = env_or("STONECHAT_WT_ADVERTISE", "")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    for fallback in ["127.0.0.1", "localhost", "::1"] {
        if !wt_sans.iter().any(|s| s == fallback) {
            wt_sans.push(fallback.to_string());
        }
    }
    let wt_certs = if wt_port == 0 {
        None
    } else {
        Some(Arc::new(
            wtcert::CertSchedule::load_or_generate(
                &tls_dir,
                chrono::Utc::now().timestamp(),
                &wt_sans,
            )
            .expect("webtransport certificate schedule"),
        ))
    };
    let state = Arc::new(AppState {
        mailbox: db::Mailbox::open(&db_path, &cfg.owner_token, max_queue_bytes)
            .expect("mailbox db"),
        blobs: blobs::BlobStore::open(&blob_dir).expect("blob store"),
        link: link::DeviceLinks::new(),
        tls_fp: tls.fingerprint_b64.clone(),
        build: own_build_id(),
        wt_certs: wt_certs.clone(),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("http client"),
        last_gateway_ping: Mutex::new(HashMap::new()),
        limits: limit::Limits::from_env().expect("bad rate limit"),
        cfg,
    });

    // Blob GC on a timer instead of inline on every upload; put() still GCs
    // on demand when the cap hits.
    {
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                st.blobs.collect_garbage();
                // A bounded device ends by itself. Revoking rather than just
                // hiding it drops its queue and bumps devices_v, so contacts
                // stop encrypting to a session that is over.
                for device in st.mailbox.expired_devices() {
                    let (_, blob_ids) = st.mailbox.remove_device(device);
                    for blob_id in blob_ids {
                        if st.mailbox.blob_refcount(&blob_id) == 0 {
                            st.blobs.delete(&blob_id);
                        }
                    }
                    st.link.disconnect(device).await;
                    log::info!("device {device} expired and was revoked");
                }
            }
        });
    }

    let app = router(state.clone());

    let o = &state.cfg.owner_id;
    log::info!(
        "mailbox up for owner {}…{}, {} queued",
        &o[..o.len().min(7)],
        &o[o.len().saturating_sub(4)..],
        state.mailbox.depth()
    );

    if let Some(schedule) = wt_certs {
        // Failing to bind UDP must not take the mailbox down with it: native
        // clients do not use this port, and a relay that refuses to start is
        // strictly worse than one without browser sessions.
        // The router is handed over, not rebuilt: every route exists once and
        // both transports run the same code (wt.rs "One router, two
        // transports").
        match wt::serve(state.clone(), schedule, wt_port, app.clone()).await {
            Ok(addr) => log::info!("browser transport on {addr}"),
            Err(e) => log::error!("webtransport disabled: {e}"),
        }
    }

    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
        tls.cert_pem.into_bytes(),
        tls.key_pem.into_bytes(),
    )
    .await
    .expect("rustls config");
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    axum_server::bind_rustls(addr, rustls_config)
        // With the peer address, which is what limit.rs meters by.
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("server");
}
