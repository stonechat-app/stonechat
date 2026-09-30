//! Push-gateway pings (PROTOCOL.md "Push gateway"). Content-free: only the
//! device token leaves this box. Best-effort — envelopes are safe regardless.

use std::sync::Arc;
use std::time::Instant;

use std::collections::HashMap;
use std::time::Duration;

use crate::{AppState, PUSH_ACK_GRACE, PUSH_ACK_GRACE_RING, PUSH_DEBOUNCE, PUSH_DEBOUNCE_RING};

/// Whether a ping is due, recording it if so. Debounced per device — a burst
/// to one device must not suppress the wake-up another is owed — and per
/// kind: a ring is not held back by the message ping that preceded it, only
/// by another ring.
pub fn ping_due(
    last: &mut HashMap<(i64, bool), Instant>,
    device: i64,
    ring: bool,
    now: Instant,
) -> bool {
    let window: Duration = if ring { PUSH_DEBOUNCE_RING } else { PUSH_DEBOUNCE };
    if let Some(t) = last.get(&(device, ring)) {
        if now.saturating_duration_since(*t) < window {
            return false;
        }
    }
    last.insert((device, ring), now);
    true
}

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
/// for mail it was never sent.
///
/// ring=true marks a call offer: debounced on a window short enough that a
/// second call is never swallowed, and flagged to the gateway so it can
/// escalate to a VoIP/high-priority push. It used to skip the debounce, which
/// made `ring` the flag a stranger set to have every envelope wake the phone.
/// push_gateway/main.py does not escalate yet, and still applies its own
/// per-token debounce.
pub async fn ping_gateway(state: Arc<AppState>, device: i64, ring: bool) {
    if state.cfg.push_gateway.is_empty() {
        return;
    }
    let Some((device_token, platform)) = state.mailbox.push_config(device) else {
        return;
    };
    if !ping_due(&mut state.last_gateway_ping.lock().unwrap(), device, ring, Instant::now()) {
        return;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rings_are_debounced_on_their_own_short_window() {
        let mut last = HashMap::new();
        let t0 = Instant::now();
        assert!(ping_due(&mut last, 1, true, t0));
        assert!(!ping_due(&mut last, 1, true, t0 + Duration::from_millis(500)));
        assert!(ping_due(&mut last, 1, true, t0 + PUSH_DEBOUNCE_RING));
        // A message ping a moment ago does not hold a ring back, nor the
        // other way round, and neither holds back another device.
        assert!(ping_due(&mut last, 2, false, t0));
        assert!(ping_due(&mut last, 2, true, t0));
        assert!(!ping_due(&mut last, 2, false, t0 + Duration::from_secs(1)));
        assert!(ping_due(&mut last, 2, false, t0 + PUSH_DEBOUNCE));
        assert!(ping_due(&mut last, 3, false, t0));
    }
}
