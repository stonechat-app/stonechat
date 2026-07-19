//! At most one live WebSocket to the owner's device.
//!
//! The handler task owns the socket; this holds a sender into its write
//! queue. push() reporting success means "accepted for write" — same promise
//! Python's ws.send_text made, and exactly why the ack-grace window exists
//! (a suspended phone's socket accepts frames it will never read).

use axum::extract::ws::{CloseFrame, Message};
use tokio::sync::{mpsc, Mutex};

struct Conn {
    id: u64,
    tx: mpsc::UnboundedSender<Message>,
}

pub struct OwnerLink {
    conn: Mutex<Option<Conn>>,
    next_id: std::sync::atomic::AtomicU64,
}

impl OwnerLink {
    pub fn new() -> Self {
        Self { conn: Mutex::new(None), next_id: std::sync::atomic::AtomicU64::new(1) }
    }

    /// Register a new owner connection; the previous one (if any) is told to
    /// close with the same code/reason Python used. Returns the connection id
    /// the handler must pass to detach().
    pub async fn attach(&self, tx: mpsc::UnboundedSender<Message>) -> u64 {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let old = self.conn.lock().await.replace(Conn { id, tx });
        if let Some(old) = old {
            let _ = old.tx.send(Message::Close(Some(CloseFrame {
                code: 4000,
                reason: "replaced by newer connection".into(),
            })));
        }
        id
    }

    /// Drop the registration iff it is still this handler's connection
    /// (a replaced connection must not detach its replacement).
    pub async fn detach(&self, id: u64) {
        let mut conn = self.conn.lock().await;
        if conn.as_ref().is_some_and(|c| c.id == id) {
            *conn = None;
        }
    }

    /// Send an already-serialized envelope to the owner if connected.
    pub async fn push(&self, envelope_json: &str) -> bool {
        let conn = self.conn.lock().await;
        match conn.as_ref() {
            Some(c) => c.tx.send(Message::Text(envelope_json.to_string().into())).is_ok(),
            None => false,
        }
    }
}
