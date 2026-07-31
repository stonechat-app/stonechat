//! At most one live WebSocket **per device**.
//!
//! Was one per mailbox: a second connection kicked the first, which is
//! correct for one drainer and fatal for several — two devices sharing one
//! queue would race, and whichever acked first destroyed the envelope for the
//! other (MULTIDEVICE.md "Why the current architecture is single-device").
//! The kick rule survives, scoped down: a second socket for the *same* device
//! still replaces the first, which was never the problem.
//!
//! The handler task owns the socket; this holds a sender into its write
//! queue. push() reporting success means "accepted for write" — same promise
//! Python's ws.send_text made, and exactly why the ack-grace window exists
//! (a suspended phone's socket accepts frames it will never read).

use std::collections::HashMap;

use axum::extract::ws::{CloseFrame, Message};
use tokio::sync::{mpsc, Mutex};

struct Conn {
    id: u64,
    tx: mpsc::UnboundedSender<Message>,
}

pub struct DeviceLinks {
    conns: Mutex<HashMap<i64, Conn>>,
    next_id: std::sync::atomic::AtomicU64,
}

impl DeviceLinks {
    pub fn new() -> Self {
        Self {
            conns: Mutex::new(HashMap::new()),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Register a connection for [device]; that device's previous connection
    /// (if any) is told to close with the same code/reason Python used.
    /// Returns the connection id the handler must pass to detach().
    pub async fn attach(&self, device: i64, tx: mpsc::UnboundedSender<Message>) -> u64 {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let old = self.conns.lock().await.insert(device, Conn { id, tx });
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
    pub async fn detach(&self, device: i64, id: u64) {
        let mut conns = self.conns.lock().await;
        if conns.get(&device).is_some_and(|c| c.id == id) {
            conns.remove(&device);
        }
    }

    /// Send an already-serialized envelope to one device if it is connected.
    pub async fn push(&self, device: i64, envelope_json: &str) -> bool {
        let conns = self.conns.lock().await;
        match conns.get(&device) {
            Some(c) => c
                .tx
                .send(Message::Text(envelope_json.to_string().into()))
                .is_ok(),
            None => false,
        }
    }

    /// Close and forget a device's socket — used by revocation, which must
    /// cut delivery immediately rather than at the next reconnect.
    pub async fn disconnect(&self, device: i64) {
        if let Some(conn) = self.conns.lock().await.remove(&device) {
            let _ = conn.tx.send(Message::Close(Some(CloseFrame {
                code: 4001,
                reason: "device revoked".into(),
            })));
        }
    }
}
