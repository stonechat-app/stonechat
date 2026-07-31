//! Push-gateway pings (PROTOCOL.md "Push gateway"). Content-free: only the
//! device token leaves this box. Best-effort — envelopes are safe regardless.

use std::sync::Arc;
use std::time::Instant;

use crate::{AppState, PUSH_ACK_GRACE, PUSH_ACK_GRACE_RING, PUSH_DEBOUNCE};

/// The live socket accepted the frame, but that's only TCP: a suspended app
/// never reads it and never acks. If the envelope hasn't been acked
/// (deleted) after a grace window, treat the owner as offline and wake the
/// device.
pub async fn ping_gateway_if_unacked(
    state: Arc<AppState>,
    device: i64,
    envelope_id: String,
    ring: bool,
) {
    tokio::time::sleep(if ring { PUSH_ACK_GRACE_RING } else { PUSH_ACK_GRACE }).await;
    if state.mailbox.has(device, &envelope_id) {
        ping_gateway(state, device, ring).await;
    }
}

/// The addressed device is offline — ask the push gateway to wake it. Only
/// the device the envelope was routed to is woken: a desktop that registered
/// no token simply drains on next launch, and a sibling phone is not lit up
/// for mail it was never sent (MULTIDEVICE.md "Relay changes").
///
/// ring=true marks a call offer: never debounced, and flagged to the gateway
/// so it can escalate to a VoIP/high-priority push.
pub async fn ping_gateway(state: Arc<AppState>, device: i64, ring: bool) {
    if state.cfg.push_gateway.is_empty() {
        return;
    }
    let Some((device_token, platform)) = state.mailbox.push_config(device) else {
        return;
    };
    {
        // Debounce per device: a burst to one device must not suppress the
        // wake-up another device is owed.
        let mut last = state.last_gateway_ping.lock().unwrap();
        if !ring {
            if let Some(t) = last.get(&device) {
                if t.elapsed() < PUSH_DEBOUNCE {
                    return;
                }
            }
        }
        last.insert(device, Instant::now());
    }
    let mut req = state
        .http
        .post(format!("{}/v1/ping", state.cfg.push_gateway))
        .json(&serde_json::json!({
            "device_token": device_token,
            "platform": platform,
            "ring": ring,
        }));
    if !state.cfg.push_key.is_empty() {
        req = req.header("X-Stonechat-Push-Key", &state.cfg.push_key);
    }
    // warning, not debug: a misconfigured/unreachable gateway looks exactly
    // like "push doesn't work" and must be visible in logs.
    match req.send().await {
        Ok(r) if !r.status().is_success() => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            log::warn!("gateway ping rejected: {} {}", status.as_u16(), &body[..body.len().min(200)]);
        }
        Ok(_) => {}
        Err(e) => log::warn!("gateway ping failed: {e}"),
    }
}
