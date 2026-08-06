//! The receive loop.
//!
//! Hold the socket, open what arrives, answer what deserves an answer, ack.
//! In that order — the ack is what tells the relay to forget the envelope, so
//! it goes last, after the ratchet advance has been persisted. The app does
//! the same thing for the same reason.
//!
//! **What this agent will and will not do.** It is a device on its owner's
//! identity, not a separate contact, so a reply it sends *is a message from
//! its owner*. It therefore answers ordinary messages and nothing else:
//! accepting a contact request, blocking someone or changing a profile are
//! identity-level acts, and a program that guesses at those on its owner's
//! behalf is a program that eventually guesses wrong.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{Connector, connect_async_tls_with_config};

use crate::hub::Hub;
use crate::mailbox::Mailbox;
use crate::pin::pinned_config;
use crate::proto::{self, Incoming, short};
use crate::state::{self, State};
use crate::util::Result;
use crate::{cert, err, prekeys, replies};

/// Warn this far before the certificate lapses. Matches the app's
/// `certRefreshWindow`: peers begin refetching around then, and it is the last
/// point at which "go and re-link it" is calm advice rather than an outage.
const EXPIRY_WARNING: i64 = 7 * 24 * 3600;

pub async fn run() -> Result<()> {
    let mut st = state::require()?;
    let hub = Hub::new(&st.hub_url)?;

    println!(
        "  {} — device {} of {}",
        if st.display_name.is_empty() {
            "(unnamed)"
        } else {
            &st.display_name
        },
        st.device_id,
        st.stonechat_id
    );
    warn_about_expiry(&st);

    let mailbox = Mailbox::new(&st.relay_address, &st.relay_tls_fp)?;
    let url = mailbox.ws_url(&st.device_token);

    loop {
        match session(&mut st, &hub, &url).await {
            Ok(()) => println!("  socket closed by the mailbox — reconnecting in 3s"),
            Err(e) => eprintln!("  socket dropped ({e}) — reconnecting in 3s"),
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// One connection's worth of work. Returning means reconnect.
async fn session(st: &mut State, hub: &Hub, url: &str) -> Result<()> {
    let connector = Connector::Rustls(pinned_config(&st.relay_tls_fp));
    let (mut ws, _) = connect_async_tls_with_config(url, None, false, Some(connector))
        .await
        .map_err(|e| err!("could not open the receive socket: {e}"))?;
    println!("  connected — waiting for messages (Ctrl-C to stop)");

    // On every reconnect, not just the first: the pool drains as strangers
    // start conversations, and a relay may have been replaced under us.
    match prekeys::top_up(st).await {
        Ok(Some(restocked)) => {
            *st = restocked;
            state::save(st)?;
        }
        Ok(None) => {}
        Err(e) => eprintln!("  ! could not check prekeys: {e}"),
    }

    while let Some(frame) = ws.next().await {
        let raw = match frame? {
            Message::Text(text) => text.to_string(),
            Message::Close(_) => return Ok(()),
            // Ping/pong are handled by the library; anything else is not ours.
            _ => continue,
        };
        let outer: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  ! mailbox sent something that is not an envelope: {e}");
                continue;
            }
        };
        let id = outer
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        if let Err(e) = handle(st, hub, &outer).await {
            // Log and ack anyway. An envelope we cannot open is not going to
            // become openable on redelivery, and refusing to ack it wedges the
            // queue behind it — the one failure mode that takes the agent down
            // permanently rather than for one message.
            eprintln!("  ! could not handle {id}: {e}");
        }
        // Persist before the ack: the ack is what lets the relay forget the
        // envelope, so an advance that is not on disk yet must not be
        // acknowledged.
        state::save(st)?;
        ws.send(Message::text(json!({"ack": id}).to_string()))
            .await?;
    }
    Ok(())
}

async fn handle(st: &mut State, hub: &Hub, outer: &Value) -> Result<()> {
    let incoming = proto::open(st, hub, outer).await?;
    // Opening already advanced the ratchet; persist that much even if what
    // follows fails.
    state::save(st)?;

    match incoming.kind.as_str() {
        "msg" | "media" => reply(st, hub, &incoming).await,
        "contact_request" => {
            // Not ours to answer. Accepting adds a contact to the identity, on
            // every device, on the strength of a program's guess.
            println!(
                "  {} sent a contact request — accept it on the phone",
                short(&incoming.from)
            );
            Ok(())
        }
        other if other.starts_with("sync_") => {
            // Our owner's other devices telling us what they did. Decrypting
            // kept the ratchet current, which was the point; there is nothing
            // for a v1 agent to apply.
            println!("  sync from our own device {}", incoming.from_device);
            Ok(())
        }
        other => {
            // Typing, receipts, reactions, profile updates, calls. Decrypting
            // above kept the ratchet current; nothing to answer.
            println!("  ignoring {other} from {}", short(&incoming.from));
            Ok(())
        }
    }
}

async fn reply(st: &mut State, hub: &Hub, incoming: &Incoming) -> Result<()> {
    let text = incoming
        .payload
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or("<no text>");
    println!(
        "  {} device {}: {text:?}",
        short(&incoming.from),
        incoming.from_device
    );

    tokio::time::sleep(Duration::from_millis(replies::think_time_ms())).await;
    let peer = hub.resolve(&incoming.from).await?;
    let answer = replies::pick();
    let sent = proto::send(
        st,
        &peer,
        "msg",
        &json!({"text": answer}),
        // Whoever spoke to us gets an answer even if the device listing is
        // unavailable — that is the one device we know exists.
        &[incoming.from_device],
    )
    .await?;
    println!("  → {answer:?} (to {sent} device(s))");
    Ok(())
}

fn warn_about_expiry(st: &State) {
    let not_after = st.cert_not_after();
    let now = chrono::Utc::now().timestamp();
    let left = not_after - now;
    if left <= 0 {
        eprintln!(
            "  ! this device's certificate EXPIRED {} days ago. Peers will \
             refuse to encrypt to it. Re-link from the phone.",
            -left / 86_400
        );
    } else if left < EXPIRY_WARNING {
        eprintln!(
            "  ! this device's certificate expires in {} days. Only the primary \
             can renew it, and there is no way to do it from here — re-link \
             before then or this agent goes quiet.",
            left / 86_400
        );
    }
}

/// `status`: what this agent is, without connecting to anything.
pub fn status() -> Result<()> {
    let st = state::require()?;
    let parsed = cert::parse(&st.cert)?.0;
    let left = parsed.not_after as i64 - chrono::Utc::now().timestamp();
    println!("  state       {}", state::state_path().display());
    println!("  owner       {} ({})", st.stonechat_id, st.display_name);
    println!("  device      {} (agent)", st.device_id);
    println!("  mailbox     {}", st.relay_address);
    println!("  pinned fp   {}", st.relay_tls_fp);
    println!(
        "  certificate expires in {} days ({})",
        left / 86_400,
        parsed.not_after
    );
    println!("  prekeys     {} one-time, {} KEM", st.opks.len(), st.kopks.len());
    println!("  sessions    {}", st.sessions.len());
    for key in st.sessions.keys() {
        println!("                {key}");
    }
    Ok(())
}
