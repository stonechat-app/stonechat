//! Owner WebSocket: drain the queue on connect, delete rows on ack.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::CloseFrame;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;

use crate::link::{self, Close, FrameSink, DRAIN_PAGE, WRITE_TIMEOUT};
use crate::AppState;

/// How long a socket we have closed is given to say so back.
const CLOSE_LINGER: std::time::Duration = std::time::Duration::from_secs(2);

/// The one place the transport-agnostic frame becomes a WebSocket frame.
/// `wt.rs` has the matching two lines for WebTransport.
struct WsSink(SplitSink<WebSocket, Message>);

impl FrameSink for WsSink {
    async fn text(&mut self, text: String) -> bool {
        self.0.send(Message::Text(text.into())).await.is_ok()
    }
    async fn close(&mut self, (code, reason): Close) {
        let frame = CloseFrame { code, reason: reason.into() };
        let _ = self.0.send(Message::Close(Some(frame))).await;
    }
}

pub async fn ws_owner(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    // Any device token authenticates — the token names the device, and that
    // is the queue it drains. Device 1's token is STONECHAT_OWNER_TOKEN, so
    // an un-updated client connects exactly as before.
    let Some(device) = state
        .mailbox
        .device_for_token(q.get("token").map(String::as_str).unwrap_or(""))
    else {
        // Python closes pre-accept, which Starlette turns into a 403
        // handshake denial — same observable behavior as rejecting here.
        return StatusCode::FORBIDDEN.into_response();
    };
    ws.on_upgrade(move |socket| handle(socket, state, device))
}

async fn handle(socket: WebSocket, state: Arc<AppState>, device: i64) {
    let (sink, mut stream) = socket.split();
    let (conn_id, out) = state.link.attach(device).await;
    state.mailbox.touch_device(device);
    log::info!(
        "device {device} connected, draining {} envelopes",
        state.mailbox.device_depth(device)
    );

    // Writer: everything to the socket flows through the pump, so the drain
    // and live pushes serialize exactly like Python's send_lock.
    let queue = state.clone();
    let mut writer = tokio::spawn(link::pump(
        out,
        WsSink(sink),
        move |after| queue.mailbox.page(device, after, DRAIN_PAGE),
        WRITE_TIMEOUT,
    ));

    let acks = state.clone();
    let reader = async move {
        while let Some(Ok(msg)) = stream.next().await {
            match msg {
                Message::Text(text) => {
                    let Ok(ack) = serde_json::from_str::<Value>(&text) else { continue };
                    if let Some(id) = ack.get("ack").and_then(Value::as_str) {
                        // An ack deletes only this device's row; a sibling
                        // still owed the same envelope keeps its copy.
                        acks.delete_envelope(device, id);
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    };
    tokio::pin!(reader);

    // Either half ending ends the connection. The writer ends on its own
    // when the peer stops reading or the device was replaced or revoked, and
    // a socket that outlived its writer would be a connection nothing drains.
    tokio::select! {
        _ = &mut reader => {}
        _ = &mut writer => {
            let _ = tokio::time::timeout(CLOSE_LINGER, &mut reader).await;
        }
    }

    state.link.detach(device, conn_id).await;
    writer.abort();
    log::info!(
        "device {device} disconnected, {} queued",
        state.mailbox.device_depth(device)
    );
}
