//! Stonechat routing server — a single user's encrypted mailbox.
//!
//! The relay implementation (ported from the retired Python relay —
//! notes/docs/RUST_PORT.md is the port record; PROTOCOL.md "Routing server API"
//! is the wire contract). Runs on a VM the user owns.
//! Stores only sealed envelopes addressed to its owner and deletes each one
//! the moment the owner's device acks it. Plaintext never exists here, and
//! neither does sender identity: everything beyond the recipient rides inside
//! an anonymous sealed box only the owner can open (PROTOCOL.md "Envelope").
//! It also serves the owner's PUBLIC prekeys so peers can start
//! forward-secret sessions while the owner is offline.
//!
//! Config (env):
//!     STONECHAT_OWNER_ID     Stonechat ID of the owner (the only valid recipient)
//!     STONECHAT_OWNER_TOKEN  shared secret the owner's device presents on /ws
//!     STONECHAT_PORT         listen port (default 8080)
//!     STONECHAT_DB           sqlite path (default ./mailbox.db)
//!     STONECHAT_BLOBS        blob dir (default ./blobs)
//!     STONECHAT_TLS_DIR      where the TLS key/cert live (default: the DB's directory)
//!
//! Transport: everything is served over TLS with a self-signed certificate
//! generated on first boot (or reused from disk — the fingerprint clients pin
//! must survive a Python→Rust swap on the same volume).

mod blobs;
mod db;
mod link;
mod push;
mod routes;
mod tls;
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
pub const MAX_BLOB_BYTES: usize = 64 * 1024 * 1024; // videos/documents; mirrored in the app
pub const MAX_TOTAL_BLOB_BYTES: u64 = 1024 * 1024 * 1024;
pub const BLOB_TTL: Duration = Duration::from_secs(14 * 24 * 3600);
pub const MAX_OPKS: usize = 256;
// ML-KEM-768 one-time prekeys are ~1.6 KB each as base64 (notes/notes/docs/POST_QUANTUM.md, internal);
// prekey uploads get their own body cap so a full restock fits one request.
pub const MAX_KOPKS: usize = 64;
pub const MAX_PREKEY_UPLOAD_BYTES: usize = 256 * 1024;
pub const PUSH_DEBOUNCE: Duration = Duration::from_secs(5);
// A socket write succeeding is not delivery: a freshly-backgrounded phone
// keeps its TCP connection open while the suspended app never reads the
// frame. Live delivery only counts once the device acks — envelopes still
// queued after this grace window get a gateway ping like any offline
// delivery. Call offers use the shorter window; ringing can't wait.
pub const PUSH_ACK_GRACE: Duration = Duration::from_secs(10);
pub const PUSH_ACK_GRACE_RING: Duration = Duration::from_secs(2);
pub const TURN_TTL_S: u64 = 6 * 3600;
/// A parked link grant is a bootstrap secret in flight — short-lived on
/// purpose, and single-use besides (MULTIDEVICE.md "Linking a device").
pub const LINK_TTL: Duration = Duration::from_secs(10 * 60);
pub const MAX_LINK_BYTES: usize = 64 * 1024;
/// Bounded so a mailbox cannot be filled with grants nobody will collect.
pub const MAX_PENDING_LINKS: i64 = 8;

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
    pub http: reqwest::Client,
    pub last_gateway_ping: Mutex<HashMap<i64, Instant>>,
}

impl AppState {
    /// Delete one device's copy of an acked envelope, and release its blob if
    /// that was the last copy owed to anyone.
    ///
    /// Refcounted rather than deleted outright: with per-device fan-out the
    /// same `blob_id` is referenced by one envelope per device, and the first
    /// device to ack must not pull the file out from under its siblings
    /// (MULTIDEVICE.md "Sending: per-device envelopes").
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

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
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

    let cfg = Config {
        owner_id,
        owner_token,
        turn_secret: env_or("STONECHAT_TURN_SECRET", ""),
        turn_port: env_or("STONECHAT_TURN_PORT", "3478").parse().expect("bad STONECHAT_TURN_PORT"),
        push_gateway: env_or("STONECHAT_PUSH_GATEWAY", "").trim_end_matches('/').to_string(),
        push_key: env_or("STONECHAT_PUSH_KEY", ""),
    };

    let tls = tls::Tls::load_or_generate(&tls_dir).expect("TLS setup failed");
    let state = Arc::new(AppState {
        mailbox: db::Mailbox::open(&db_path, &cfg.owner_token).expect("mailbox db"),
        blobs: blobs::BlobStore::open(&blob_dir).expect("blob store"),
        link: link::DeviceLinks::new(),
        tls_fp: tls.fingerprint_b64.clone(),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("http client"),
        last_gateway_ping: Mutex::new(HashMap::new()),
        cfg,
    });

    // Blob GC on a timer instead of inline on every upload (RUST_PORT.md
    // "Permitted improvements"); put() still GCs on demand when the cap hits.
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

    let app = Router::new()
        .route("/health", get(routes::health))
        .route("/status", get(routes::status))
        .route("/owner", get(routes::owner_check))
        .route("/prekeys", post(routes::upload_prekeys))
        .route("/prekeys/bundle", get(routes::prekey_bundle))
        .route("/prekeys/devices", get(routes::prekey_devices))
        .route("/devices", get(routes::list_devices).post(routes::mint_device))
        .route("/devices/{device_id}", axum::routing::delete(routes::revoke_device))
        .route("/link", post(routes::link_put))
        .route("/link/{key}", get(routes::link_take))
        .route("/inbox", post(routes::inbox))
        .route("/push-config", post(routes::push_config))
        .route("/turn-credentials", get(routes::turn_credentials))
        .route("/blob", post(routes::blob_upload))
        .route(
            "/blob/{blob_id}",
            get(routes::blob_download).delete(routes::blob_delete),
        )
        .route("/ws", get(ws::ws_owner))
        .layer(DefaultBodyLimit::max(MAX_BLOB_BYTES + 1024))
        .with_state(state.clone());

    let o = &state.cfg.owner_id;
    log::info!(
        "mailbox up for owner {}…{}, {} queued",
        &o[..o.len().min(7)],
        &o[o.len().saturating_sub(4)..],
        state.mailbox.depth()
    );

    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
        tls.cert_pem.into_bytes(),
        tls.key_pem.into_bytes(),
    )
    .await
    .expect("rustls config");
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    axum_server::bind_rustls(addr, rustls_config)
        .serve(app.into_make_service())
        .await
        .expect("server");
}
