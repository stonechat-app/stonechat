//! Owner WebSocket: drain the queue on connect, delete rows on ack.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::sync::mpsc;

use crate::AppState;

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
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let conn_id = state.link.attach(device, tx).await;
    state.mailbox.touch_device(device);
    log::info!(
        "device {device} connected, draining {} envelopes",
        state.mailbox.device_depth(device)
    );

    // Writer: everything to the socket flows through the link's queue, so
    // drain and live pushes serialize exactly like Python's send_lock.
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let closing = matches!(msg, Message::Close(_));
            if sink.send(msg).await.is_err() || closing {
                break;
            }
        }
    });

    for envelope in state.mailbox.all(device) {
        state.link.push(device, &envelope).await;
    }

    while let Some(Ok(msg)) = stream.next().await {
        match msg {
            Message::Text(text) => {
                let Ok(ack) = serde_json::from_str::<Value>(&text) else { continue };
                if let Some(id) = ack.get("ack").and_then(Value::as_str) {
                    // An ack deletes only this device's row; a sibling still
                    // owed the same envelope keeps its copy.
                    state.delete_envelope(device, id);
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    state.link.detach(device, conn_id).await;
    writer.abort();
    log::info!(
        "device {device} disconnected, {} queued",
        state.mailbox.device_depth(device)
    );
}
