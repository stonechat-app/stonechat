//! The receive loop.
//!
//! Hold the socket, open what arrives, apply or answer what deserves it, ack.
//! In that order — the ack is what tells the relay to forget the envelope, so
//! it goes last, after the ratchet advance has been persisted. The app does
//! the same thing for the same reason.
//!
//! **What this agent will and will not do.** It is a device on its owner's
//! identity, not a separate contact, so a reply it sends *is a message from
//! its owner*. It therefore answers ordinary messages from **accepted
//! contacts** and nothing else — it learns who those are from the phone,
//! over `sync_history` and `sync_contact`, and never decides for itself.
//! Accepting a request, blocking someone or changing a profile are
//! identity-level acts, and a program that guesses at those on its owner's
//! behalf is a program that eventually guesses wrong.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{Connector, connect_async_tls_with_config};

use crate::hub::Hub;
use crate::mailbox::Mailbox;
use crate::pin::pinned_config;
use crate::proto::{Agent, Incoming, SendOpts};
use crate::state::{self, State};
use crate::util::{Result, now_ms, short};
use crate::{cert, contacts, err, prekeys, replies, transient};

/// Warn this far before the certificate lapses. The primary renews a linked
/// device's certificate when it has less than half its lifetime left (7 of
/// 14 days), so with under 3 days left the phone has simply not connected,
/// and this is the last point at which "open the app" is calm advice rather
/// than an outage.
const EXPIRY_WARNING: i64 = 3 * 24 * 3600;

/// An envelope whose handling keeps failing transiently is given up on
/// after this many connections: a sender's mailbox that never comes back
/// must not hold the queue behind it forever.
const MAX_TRANSIENT_ATTEMPTS: u32 = 5;

/// Why a connection ended.
enum Closed {
    /// 4001: the phone revoked this device. Nothing more will arrive.
    Revoked,
    /// 4000: another connection authenticated as this device.
    Replaced,
    /// Anything else; reconnect.
    ByMailbox,
}

pub async fn run(show_text: bool) -> Result<()> {
    let st = state::require()?;
    let hub = Hub::new(&st.hub_url)?;
    let url = Mailbox::new(&st.relay_address, &st.relay_tls_fp)?.ws_url(&st.device_token);
    let mut agent = Agent::new(st, hub, show_text);

    println!(
        "  {} — device {} of {}",
        if agent.st.display_name.is_empty() {
            "(unnamed)"
        } else {
            &agent.st.display_name
        },
        agent.st.device_id,
        agent.st.stonechat_id
    );
    println!(
        "  {} accepted contact(s) known{}",
        agent.st.contacts.values().filter(|c| c.status == "accepted").count(),
        if agent.st.contacts.is_empty() {
            " — the phone sends its contacts after linking; until then nobody gets an answer"
        } else {
            ""
        }
    );
    if !show_text {
        println!("  message text is not logged (--show-text to log it)");
    }
    warn_about_expiry(&agent.st);

    let mut attempts: HashMap<String, u32> = HashMap::new();
    let mut backoff = 3u64;
    loop {
        let started = Instant::now();
        match session(&mut agent, &url, &mut attempts).await {
            Ok(Closed::Revoked) => {
                return Err(err!(
                    "this device was revoked from the phone (close code 4001). Nothing more \
                     will arrive; `stonechat-agent forget` removes the local state."
                ));
            }
            Ok(Closed::Replaced) => {
                return Err(err!(
                    "another connection took over this device (close code 4000) — is a second \
                     copy of this agent running against the same state file?"
                ));
            }
            Ok(Closed::ByMailbox) => println!("  socket closed by the mailbox — reconnecting in {backoff}s"),
            Err(e) => eprintln!("  {e} — reconnecting in {backoff}s"),
        }
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        // A connection that held for a while earns a fresh start; one that
        // dropped at once backs off, up to a minute.
        backoff = if started.elapsed() > Duration::from_secs(60) {
            3
        } else {
            (backoff * 2).min(60)
        };
    }
}

/// One connection's worth of work. Returning means reconnect.
async fn session(agent: &mut Agent, url: &str, attempts: &mut HashMap<String, u32>) -> Result<Closed> {
    let connector = Connector::Rustls(pinned_config(&agent.st.relay_tls_fp));
    let (mut ws, _) = connect_async_tls_with_config(url, None, false, Some(connector))
        .await
        .map_err(|e| transient!("could not open the receive socket: {e}"))?;
    println!("  connected — waiting for messages (Ctrl-C to stop)");

    // On every connect, not just the first: signed prekeys rotate weekly,
    // the one-time pools drain as contacts start conversations, the
    // certificate may have been renewed, and the mailbox may have been
    // replaced under us. The upload is the full stock, so all of those
    // converge on what we hold.
    match prekeys::publish(&agent.st).await {
        Ok(next) => {
            agent.st = next;
            agent.save()?;
        }
        Err(e) => eprintln!("  ! could not publish prekeys: {e}"),
    }
    agent.refresh_own_manifest().await;
    warn_about_expiry(&agent.st);

    while let Some(frame) = ws.next().await {
        let raw = match frame? {
            Message::Text(text) => text.to_string(),
            Message::Close(frame) => {
                return Ok(match frame.map(|f| u16::from(f.code)) {
                    Some(4001) => Closed::Revoked,
                    Some(4000) => Closed::Replaced,
                    _ => Closed::ByMailbox,
                });
            }
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
        let Some(id) = outer.get("id").and_then(Value::as_str).map(str::to_string) else {
            eprintln!("  ! mailbox sent an envelope without an id");
            continue;
        };

        match agent.open(&outer).await {
            Ok(incoming) => {
                // Opening committed the ratchet; persist that much before
                // anything that follows can fail.
                agent.save()?;
                attempts.remove(&id);
                if let Err(e) = dispatch(agent, incoming).await {
                    eprintln!("  ! {id}: {e}");
                }
            }
            Err(e) if e.is_transient() => {
                // Nothing was committed, so the envelope can be redelivered
                // whole. Reconnecting is what makes the mailbox do that, in
                // order — but not forever.
                let n = attempts.entry(id.clone()).or_insert(0);
                *n += 1;
                if *n < MAX_TRANSIENT_ATTEMPTS {
                    agent.save()?;
                    return Err(transient!("could not finish {id} ({e}); left queued"));
                }
                eprintln!("  ! dropped {id} after {n} attempts: {e}");
                attempts.remove(&id);
            }
            // Log and ack anyway. An envelope we cannot open is not going to
            // become openable on redelivery, and refusing to ack it wedges
            // the queue behind it — the one failure mode that takes the agent
            // down permanently rather than for one message.
            Err(e) => eprintln!("  ! dropped {id}: {e}"),
        }
        // Persist before the ack: the ack is what lets the relay forget the
        // envelope, so an advance that is not on disk yet must not be
        // acknowledged.
        agent.save()?;
        ws.send(Message::text(json!({"ack": id}).to_string()))
            .await?;
    }
    Ok(Closed::ByMailbox)
}

/// Apply one opened, trusted envelope by type. Errors here are logged by
/// the caller and the envelope is acked regardless: whatever failed, the
/// ratchet has already moved past it.
async fn dispatch(agent: &mut Agent, incoming: Incoming) -> Result<()> {
    let from_self = incoming.from == agent.st.stonechat_id;
    let kind = incoming.kind.as_str();
    let who = short(&incoming.from);

    // Self-sync only ever comes from us. The session already proves the
    // sender is a device the `from` identity certified — so this check, that
    // `from` is *our* identity, is what keeps a peer from writing our
    // contact list.
    if kind.starts_with("sync_") {
        if !from_self {
            println!("  dropped {kind} from {who}: self-sync from someone else's identity");
            return Ok(());
        }
        match kind {
            "sync_cert" => match agent.apply_sync_cert(&incoming.payload) {
                Ok(true) => {
                    agent.save()?;
                    println!(
                        "  certificate renewed by the phone — valid for {} more days",
                        (cert::not_after(&agent.st.cert) as i64 - now_ms() / 1000) / 86_400
                    );
                    // Peers pick the new certificate up from our bundle.
                    match prekeys::publish(&agent.st).await {
                        Ok(next) => {
                            agent.st = next;
                            agent.save()?;
                        }
                        Err(e) => eprintln!("  ! could not republish prekeys: {e} (next connect)"),
                    }
                }
                Ok(false) => println!("  sync_cert: not newer than the certificate held — ignored"),
                Err(e) => eprintln!("  ! sync_cert: {e}"),
            },
            "sync_contact" => match contacts::apply_sync_contact(&mut agent.st, &incoming.payload) {
                Ok(line) => println!("  contacts: {line}"),
                Err(e) => eprintln!("  ! sync_contact: {e}"),
            },
            "sync_block" => match contacts::apply_sync_block(&mut agent.st, &incoming.payload) {
                Ok(line) => println!("  contacts: {line}"),
                Err(e) => eprintln!("  ! sync_block: {e}"),
            },
            "sync_history" => {
                // The blob is on our own mailbox, which we are connected to;
                // a fetch that fails anyway is given a moment, not a
                // redelivery — the ratchet has moved past this envelope.
                let mut tries = 0;
                loop {
                    tries += 1;
                    match agent.apply_sync_history(&incoming.payload).await {
                        Ok(line) => {
                            println!("  {line}");
                            break;
                        }
                        Err(e) if e.is_transient() && tries < 3 => {
                            eprintln!("  ! sync_history: {e} — retrying");
                            tokio::time::sleep(Duration::from_secs(2)).await;
                        }
                        Err(e) => {
                            eprintln!("  ! sync_history: {e}");
                            break;
                        }
                    }
                }
            }
            // sync_sent, sync_read, sync_clear: history we do not keep.
            other => println!("  {other} from our device {} — nothing to apply here", incoming.from_device),
        }
        return Ok(());
    }

    // Blocked senders — contacts or not: decrypted (above) so the ratchet
    // stays current for a later unblock, and otherwise ignored.
    if agent.st.blocked.contains_key(&incoming.from) {
        println!("  ignoring {kind} from blocked {who}");
        return Ok(());
    }

    match kind {
        "msg" | "media" => {
            if !agent.st.is_contact(&incoming.from) {
                // W-A1: a stranger does not get an answer in the owner's name,
                // nor learn that an agent is running.
                println!("  {kind} from {who} — not an accepted contact, not answering");
                return Ok(());
            }
            answer(agent, &incoming).await
        }
        "contact_request" => {
            // Not ours to answer. Accepting adds a contact to the identity, on
            // every device, on the strength of a program's guess.
            println!("  {who} sent a contact request — accept it on the phone");
            Ok(())
        }
        "profile_update" => {
            if let Some(contact) = agent.st.contacts.get_mut(&incoming.from)
                && contact.status == "accepted"
                && let Some(name) = incoming.payload.get("display_name").and_then(Value::as_str)
                && !name.trim().is_empty()
            {
                contact.display_name = name.trim().to_string();
                println!("  {who} is now called {:?}", contact.display_name);
            }
            Ok(())
        }
        other => {
            // Receipts, typing, reactions, edits, calls, groups. Decrypting
            // kept the ratchet current; nothing for this device to do.
            println!("  {other} from {who} — nothing to do");
            Ok(())
        }
    }
}

/// A message from an accepted contact: acknowledge it, answer it, and tell
/// our own other devices what we said so the phone's transcript has no hole.
async fn answer(agent: &mut Agent, incoming: &Incoming) -> Result<()> {
    let who = short(&incoming.from);
    let text = incoming
        .payload
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or("");
    if agent.show_text {
        println!("  {who} device {}: {text:?}", incoming.from_device);
    } else {
        println!(
            "  {} from {who} device {} ({} chars)",
            incoming.kind,
            incoming.from_device,
            text.chars().count()
        );
    }

    // Delivered, as every device that took a copy says. Best-effort.
    if let Err(e) = agent
        .send_to_peer(
            &incoming.from,
            "receipt",
            &json!({"kind": "delivered", "ids": [incoming.id]}),
            &[incoming.from_device],
            SendOpts { no_push: true },
        )
        .await
    {
        eprintln!("  ! could not send a receipt to {who}: {e}");
    }

    tokio::time::sleep(Duration::from_millis(replies::think_time_ms())).await;
    let reply = replies::answer(&incoming.kind, text);
    let payload = json!({"text": reply});
    // Whoever spoke to us gets an answer even if the device listing is
    // unavailable — that is the one device we know exists.
    let sent = agent
        .send_to_peer(&incoming.from, "msg", &payload, &[incoming.from_device], SendOpts::default())
        .await?;
    if agent.show_text {
        println!("  → {reply:?} (to {} device(s))", sent.delivered);
    } else {
        println!("  → replied to {who} (to {} device(s))", sent.delivered);
    }

    // What we said, mirrored to our own other devices (PROTOCOL.md
    // "Self-sync"). Without this the phone's transcript of the conversation
    // would show the contact's messages and none of our answers.
    agent
        .sync_to_siblings(
            "sync_sent",
            &json!({
                "peer": incoming.from,
                "type": "msg",
                "payload": payload,
                "id": sent.id,
                // Milliseconds, unlike the envelope's ISO `sent_at`.
                "sent_at": now_ms(),
            }),
        )
        .await;
    Ok(())
}

fn warn_about_expiry(st: &State) {
    let not_after = st.cert_not_after();
    let now = chrono::Utc::now().timestamp();
    let left = not_after - now;
    if left <= 0 {
        eprintln!(
            "  ! this device's certificate EXPIRED {} days ago. Peers refuse to encrypt to \
             it. The phone renews it only while it is still listed there: open the app, \
             and if the device is gone from Linked devices, `forget` and link again.",
            -left / 86_400
        );
    } else if left < EXPIRY_WARNING {
        eprintln!(
            "  ! this device's certificate expires in {} days. The phone renews it when it \
             connects with under 7 days left and has not — open the app on the phone, or \
             this agent goes quiet.",
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
        "  certificate expires in {} days ({}); the phone renews it while this device is listed",
        left / 86_400,
        parsed.not_after
    );
    println!(
        "  manifest    {}",
        match st.own_manifest_v() {
            0 => "none held — the phone has not published one, or run has not read it yet".to_string(),
            v => format!("version {v}"),
        }
    );
    println!(
        "  contacts    {} accepted, {} pending, {} blocked",
        st.contacts.values().filter(|c| c.status == "accepted").count(),
        st.contacts.values().filter(|c| c.status != "accepted").count(),
        st.blocked.len()
    );
    println!("  prekeys     {} one-time, {} KEM", st.opks.len(), st.kopks.len());
    println!("  sessions    {}", st.sessions.len());
    for key in st.sessions.keys() {
        println!("                {key}");
    }
    Ok(())
}
