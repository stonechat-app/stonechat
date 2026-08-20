//! The browser transport: the owner socket, over WebTransport.
//!
//! Same protocol as `ws.rs` — drain the queue on connect, delete rows on ack,
//! one drainer per device — over a different pipe, because a browser cannot
//! open the pipe `ws.rs` uses. A relay is a self-signed certificate on a bare
//! IP; `fetch` and `WebSocket` refuse that outright and expose no API to
//! accept it (WEB_CLIENT.md blocker 1).
//!
//! WebTransport's `serverCertificateHashes` is the exception, and it is the
//! *same* trust model Stonechat already has — pin the certificate, ignore CAs
//! — with a different hash and a 14-day cap. `wtcert.rs` handles the cap.
//!
//! ## Framing
//!
//! **One bidirectional stream per request.** Each begins with a JSON header
//! line and, if it has one, a body:
//!
//! ```text
//! {"method":"POST","path":"/inbox","len":1234}\n<1234 bytes>
//! ```
//!
//! and the reply comes back the same shape:
//!
//! ```text
//! {"status":200,"headers":{...},"len":56}\n<56 bytes>
//! ```
//!
//! `/ws` is the exception, and it is the HTTP one: the server answers
//! `{"status":101}` and the stream then carries the owner socket —
//! newline-delimited envelopes down, `{"ack": id}` up. Identical payloads to
//! the WebSocket, because the moment the two transports carry different
//! messages there are two protocols to keep correct and only one of them has a
//! conformance corpus.
//!
//! ## One router, two transports
//!
//! Requests are not reimplemented here. The header and body are turned into an
//! `http::Request` and handed to **the same `axum::Router`** the TLS listener
//! serves, so every route — prekeys, bundles, blobs, devices — exists once.
//! An adapter that reimplemented even one of them would be a second relay to
//! keep correct, and the conformance corpus only covers the first.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::http::{Method, Request};
use axum::Router;
use futures_util::StreamExt;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tower::ServiceExt;
use wtransport::endpoint::IncomingSession;
use wtransport::{Endpoint, Identity, ServerConfig};

use crate::link::Frame;
use crate::wtcert::CertSchedule;
use crate::{AppState, MAX_BLOB_BYTES};

/// A request header line longer than this is not a header line.
const MAX_HEADER: usize = 8 * 1024;

/// The largest body this transport will carry, either direction.
///
/// Blob-sized again, because nothing buffers it any more: the request streams
/// from the QUIC stream into the router, and a response with a declared length
/// streams back out. Routes that *do* buffer bound themselves — `/inbox` and
/// the prekey routes take `Bytes`, so the router's own `DefaultBodyLimit`
/// still cuts them off long before this.
const MAX_BODY: usize = MAX_BLOB_BYTES + 1024;

/// What a response may cost in memory when it declares no length.
///
/// A blob download sets Content-Length (routes.rs), so it streams. Everything
/// else here is JSON measured in kilobytes, and buffering those keeps the
/// framing simple — the header line has to state `len` before the body, and
/// for a body of unknown size the only honest way to learn it is to hold it.
const MAX_BUFFERED_RESPONSE: usize = 1024 * 1024;

/// How much of a body moves at once, mirroring the HTTP path's chunk size.
const CHUNK: usize = 64 * 1024;

/// How long a body may stall before the stream is abandoned.
///
/// The header declares a length and the router then waits for that many
/// bytes, so a client that promises 64 MiB and sends none would otherwise pin
/// a task for as long as it kept the stream open — cheap for it, unbounded for
/// us. Generous enough that an ordinary slow upload never trips it: it bounds
/// silence between chunks, not total transfer time.
const BODY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How often to check whether the live certificate has changed. The schedule
/// rotates on the order of days, so this is cheap; it exists so rotation
/// happens without a restart, which is the whole point of pre-signing.
const ROTATE_CHECK: std::time::Duration = std::time::Duration::from_secs(3600);

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

async fn config_for(schedule: &CertSchedule, port: u16) -> Result<ServerConfig, String> {
    let live = schedule
        .live(now())
        .ok_or("no live WebTransport certificate — schedule exhausted")?;
    let stem = format!("{}-{}", live.not_before, live.not_after);
    let identity = Identity::load_pemfiles(
        schedule.dir().join(format!("{stem}.crt")),
        schedule.dir().join(format!("{stem}.key")),
    )
    .await
    .map_err(|e| format!("loading WebTransport identity: {e}"))?;
    Ok(ServerConfig::builder()
        .with_bind_default(port)
        .with_identity(identity)
        // A browser tab that is backgrounded stops being scheduled; without
        // keep-alives the connection is torn down and the queue re-drained on
        // every tab switch.
        .keep_alive_interval(Some(std::time::Duration::from_secs(15)))
        .build())
}

/// Start the WebTransport endpoint. Returns the bound address.
///
/// Runs on its own UDP port beside the TLS listener rather than replacing it:
/// native clients keep the transport they pin today, and a relay whose host
/// blocks UDP degrades to "no browser sessions" rather than "no mailbox".
pub async fn serve(
    state: Arc<AppState>,
    schedule: Arc<CertSchedule>,
    port: u16,
    router: Router,
) -> Result<SocketAddr, String> {
    let endpoint = Arc::new(
        Endpoint::server(config_for(&schedule, port).await?)
            .map_err(|e| format!("binding WebTransport endpoint: {e}"))?,
    );
    let addr = endpoint.local_addr().map_err(|e| e.to_string())?;
    log::info!("webtransport listening on {addr} (udp)");

    // Silent rotation: swap the identity in place when the schedule moves on.
    // Existing connections keep their session — QUIC does not re-handshake —
    // and new ones get the incoming certificate, which clients already hold
    // because the schedule published it months ago.
    {
        let endpoint = Arc::clone(&endpoint);
        let schedule = Arc::clone(&schedule);
        tokio::spawn(async move {
            let mut current = schedule.live(now()).map(|c| c.sha256_b64.clone());
            loop {
                tokio::time::sleep(ROTATE_CHECK).await;
                let live = schedule.live(now()).map(|c| c.sha256_b64.clone());
                if live == current {
                    continue;
                }
                match config_for(&schedule, port).await {
                    Ok(config) => {
                        if let Err(e) = endpoint.reload_config(config, false) {
                            log::error!("webtransport certificate rotation failed: {e}");
                        } else {
                            log::info!("webtransport certificate rotated");
                            current = live;
                        }
                    }
                    Err(e) => log::error!("webtransport rotation: {e}"),
                }
            }
        });
    }

    tokio::spawn(async move {
        loop {
            let incoming = endpoint.accept().await;
            let state = Arc::clone(&state);
            let router = router.clone();
            tokio::spawn(async move {
                if let Err(e) = session(incoming, state, router).await {
                    log::debug!("webtransport session ended: {e}");
                }
            });
        }
    });
    Ok(addr)
}

/// Pull `token` out of a path's query string.
///
/// The token is a bearer secret in a URL, which is the same compromise the
/// WebSocket route makes and no better here — but a WebTransport request
/// carries no headers a client can set, so there is nowhere else to put it
/// yet. Noted in WEB_CLIENT.md's "smaller, fixable items".
fn token_of(path: &str) -> Option<&str> {
    let (_, query) = path.split_once('?')?;
    query.split('&').find_map(|pair| pair.strip_prefix("token="))
}

/// Read one newline-terminated header line, returning it and any bytes of the
/// body that arrived in the same read.
///
/// Capped: a client that never sends a newline must not be able to make the
/// relay buffer without limit, and a header longer than this is not a header.
async fn read_header(
    recv: &mut wtransport::RecvStream,
) -> Result<(String, Vec<u8>), String> {
    let mut buf = vec![0u8; 4096];
    let mut acc = Vec::new();
    loop {
        let Some(n) = recv.read(&mut buf).await.map_err(|e| e.to_string())? else {
            return Err("stream closed before a header arrived".into());
        };
        acc.extend_from_slice(&buf[..n]);
        if let Some(idx) = acc.iter().position(|b| *b == b'\n') {
            let rest = acc.split_off(idx + 1);
            acc.pop(); // the newline
            return Ok((
                String::from_utf8(acc).map_err(|_| "header is not utf-8")?,
                rest,
            ));
        }
        if acc.len() > MAX_HEADER {
            return Err("header line too long".into());
        }
    }
}

/// The request body as a stream the router can consume lazily.
///
/// This is what keeps a 64 MiB upload from costing 64 MiB here: the handler
/// pulls chunks, writes them to disk and drops them (blobs.rs), so the bytes
/// pass through rather than pile up. QUIC's per-stream flow control supplies
/// the backpressure — a slow disk throttles the sender instead of growing a
/// buffer.
///
/// `have` is whatever arrived in the same read as the header. Exactly `len`
/// bytes are yielded; a stream that ends early errors rather than handing the
/// router a short body it would treat as complete.
fn body_stream(recv: wtransport::RecvStream, have: Vec<u8>, len: usize) -> Body {
    struct St {
        recv: wtransport::RecvStream,
        have: Vec<u8>,
        len: usize,
        sent: usize,
    }
    Body::from_stream(futures_util::stream::unfold(
        Some(St { recv, have, len, sent: 0 }),
        |state| async move {
            let mut st = state?;
            if st.sent >= st.len {
                return None;
            }
            // Bytes that came in with the header, before anything else.
            if !st.have.is_empty() {
                let take = st.have.len().min(st.len - st.sent);
                let chunk: Vec<u8> = st.have.drain(..take).collect();
                st.sent += take;
                return Some((Ok(Bytes::from(chunk)), Some(st)));
            }
            let mut buf = vec![0u8; CHUNK];
            match tokio::time::timeout(BODY_IDLE_TIMEOUT, st.recv.read(&mut buf)).await {
                Ok(Ok(Some(n))) if n > 0 => {
                    let take = n.min(st.len - st.sent);
                    buf.truncate(take);
                    st.sent += take;
                    Some((Ok(Bytes::from(buf)), Some(st)))
                }
                Ok(Ok(_)) => Some((
                    Err(std::io::Error::other("stream closed mid-body")),
                    None,
                )),
                Ok(Err(e)) => Some((Err(std::io::Error::other(e.to_string())), None)),
                Err(_) => Some((
                    Err(std::io::Error::other("timed out waiting for body")),
                    None,
                )),
            }
        },
    ))
}

/// Accept a session and serve its streams.
///
/// **Deliberately unauthenticated.** It is tempting to check a device token at
/// CONNECT and let streams inherit it, and that is wrong: most of a relay's
/// surface is open by design. `POST /inbox` takes no token — sealed sender
/// means anyone can post to anyone's mailbox, and a *sender* has no token for
/// the *recipient's* relay. Gating the session would have made delivery
/// impossible for exactly the case this transport exists to serve.
///
/// So each route authenticates itself, exactly as it does over HTTP: `/ws` and
/// `/status` want `?token=`, `/inbox` wants nothing. One router, two
/// transports — including the auth.
async fn session(
    incoming: IncomingSession,
    state: Arc<AppState>,
    router: Router,
) -> Result<(), String> {
    let request = incoming.await.map_err(|e| e.to_string())?;
    let connection = Arc::new(request.accept().await.map_err(|e| e.to_string())?);

    // One stream per request, many in flight.
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(pair) => pair,
            Err(_) => break, // session closed
        };
        let state = Arc::clone(&state);
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(e) = stream(send, recv, state, router).await {
                log::debug!("webtransport stream ended: {e}");
            }
        });
    }
    Ok(())
}

async fn stream(
    mut send: wtransport::SendStream,
    mut recv: wtransport::RecvStream,
    state: Arc<AppState>,
    router: Router,
) -> Result<(), String> {
    let (header, rest) = read_header(&mut recv).await?;
    let req: Value = serde_json::from_str(&header).map_err(|e| e.to_string())?;
    let method = req.get("method").and_then(Value::as_str).unwrap_or("GET");
    let path = req
        .get("path")
        .and_then(Value::as_str)
        .ok_or("request has no path")?
        .to_string();
    let len = req.get("len").and_then(Value::as_u64).unwrap_or(0) as usize;

    // `/ws` is an upgrade, exactly as it is over HTTP: the reply says 101 and
    // the stream then carries the owner socket instead of a response body.
    if path.split('?').next() == Some("/ws") {
        // The socket authenticates itself, from its own query string — the
        // session did not, and must not have.
        let Some(device) = token_of(&path).and_then(|t| state.mailbox.device_for_token(t))
        else {
            send.write_all(b"{\"status\":403,\"headers\":{},\"len\":0}\n")
                .await
                .map_err(|e| e.to_string())?;
            let _ = send.finish().await;
            return Err("bad or missing device token".into());
        };
        send.write_all(b"{\"status\":101}\n")
            .await
            .map_err(|e| e.to_string())?;
        return socket(send, recv, rest, state, device).await;
    }

    // Sanity, not memory: nothing buffers the request any more, so this only
    // refuses a length no route could serve. Answered rather than dropped —
    // an aborted stream is indistinguishable from a network fault, and a
    // client that cannot tell "too big" from "connection died" retries
    // forever.
    if len > MAX_BODY {
        let body = b"{\"detail\":\"body too large for this transport\"}";
        let head = format!(
            "{{\"status\":413,\"headers\":{{\"content-type\":\"application/json\"}},\"len\":{}}}\n",
            body.len()
        );
        send.write_all(head.as_bytes()).await.map_err(|e| e.to_string())?;
        send.write_all(body).await.map_err(|e| e.to_string())?;
        let _ = send.finish().await;
        return Err(format!("request body of {len} bytes exceeds the transport limit"));
    }

    dispatch(router, method, &path, body_stream(recv, rest, len), &mut send).await?;
    send.finish().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Hand a framed request to the same router the TLS listener serves, and frame
/// what comes back.
///
/// This is the whole adapter. Every route — prekeys, bundles, blobs, devices —
/// runs the code it already ran, including its extractors, its body limit and
/// its status codes, so a browser and a phone cannot disagree about what the
/// relay does.
///
/// Writes the reply itself rather than returning it, because a body worth
/// streaming must not be collected first. The framing already allows this: the
/// header line states `len` before the body, and a blob download knows its
/// length from the file (routes.rs sets Content-Length). Responses that
/// declare no length are JSON in the kilobytes and are still buffered — the
/// only honest way to state a length you do not know is to hold the body.
async fn dispatch(
    router: Router,
    method: &str,
    path: &str,
    body: Body,
    send: &mut wtransport::SendStream,
) -> Result<(), String> {
    let request = Request::builder()
        .method(Method::from_bytes(method.as_bytes()).map_err(|_| "bad method")?)
        .uri(path)
        .body(body)
        .map_err(|e| e.to_string())?;

    let response = router
        .oneshot(request)
        .await
        .map_err(|e: std::convert::Infallible| e.to_string())?;
    let status = response.status().as_u16();
    let headers: serde_json::Map<String, Value> = response
        .headers()
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), json!(v))))
        .collect();
    let declared = response
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());

    let head = |len: usize| -> Result<Vec<u8>, String> {
        let mut out = serde_json::to_vec(&json!({
            "status": status, "headers": headers, "len": len,
        }))
        .map_err(|e| e.to_string())?;
        out.push(b'\n');
        Ok(out)
    };

    match declared {
        Some(len) => {
            send.write_all(&head(len)?).await.map_err(|e| e.to_string())?;
            let mut stream = response.into_body().into_data_stream();
            let mut written = 0usize;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| e.to_string())?;
                written += chunk.len();
                send.write_all(&chunk).await.map_err(|e| e.to_string())?;
            }
            // The header already promised `len`; a body that disagrees would
            // desynchronise the client's framing for every later stream.
            if written != len {
                return Err(format!("declared {len} bytes, wrote {written}"));
            }
        }
        None => {
            let bytes = axum::body::to_bytes(response.into_body(), MAX_BUFFERED_RESPONSE)
                .await
                .map_err(|e| e.to_string())?;
            send.write_all(&head(bytes.len())?).await.map_err(|e| e.to_string())?;
            send.write_all(&bytes).await.map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// The owner socket: drain on connect, delete rows on ack. Same messages the
/// WebSocket carries, on a stream instead of a frame sequence.
async fn socket(
    mut send: wtransport::SendStream,
    mut recv: wtransport::RecvStream,
    pending: Vec<u8>,
    state: Arc<AppState>,
    device: i64,
) -> Result<(), String> {
    let (tx, mut rx) = mpsc::unbounded_channel::<Frame>();
    let conn_id = state.link.attach(device, tx).await;
    state.mailbox.touch_device(device);
    log::info!(
        "device {device} draining {} envelopes over webtransport",
        state.mailbox.device_depth(device)
    );

    // Writer, mirroring ws.rs: everything to the client flows through the
    // link's queue, so the drain and live pushes serialize the same way.
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            match frame {
                Frame::Text(text) => {
                    if send.write_all(format!("{text}\n").as_bytes()).await.is_err() {
                        break;
                    }
                }
                Frame::Close { code, reason } => {
                    // The close code is what tells a client "you were replaced"
                    // apart from "you were revoked" — the app shows different
                    // things for those, so it has to survive the transport.
                    let _ = send
                        .write_all(
                            format!("{}\n", json!({"close": code, "reason": reason}))
                                .as_bytes(),
                        )
                        .await;
                    let _ = send.finish().await;
                    break;
                }
            }
        }
    });

    for envelope in state.mailbox.all(device) {
        state.link.push(device, &envelope).await;
    }

    // Reader: newline-delimited acks, starting with anything that arrived
    // alongside the upgrade request.
    let mut buf = vec![0u8; 8192];
    let mut acc = pending;
    loop {
        while let Some(idx) = acc.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = acc.drain(..=idx).collect();
            let Ok(text) = std::str::from_utf8(&line[..line.len() - 1]) else { continue };
            let Ok(ack) = serde_json::from_str::<Value>(text) else { continue };
            if let Some(id) = ack.get("ack").and_then(Value::as_str) {
                // An ack deletes only this device's row; a sibling still owed
                // the same envelope keeps its copy.
                state.delete_envelope(device, id);
            }
        }
        if acc.len() > MAX_HEADER {
            break; // no newline in a sane amount of data is not an ack stream
        }
        match recv.read(&mut buf).await {
            Ok(Some(n)) => acc.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }

    state.link.detach(device, conn_id).await;
    writer.abort();
    log::info!(
        "device {device} disconnected from webtransport, {} queued",
        state.mailbox.device_depth(device)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_token_is_read_from_the_query_string() {
        assert_eq!(token_of("/wt?token=abc"), Some("abc"));
        assert_eq!(token_of("/wt?x=1&token=abc"), Some("abc"));
        assert_eq!(token_of("/wt"), None);
        assert_eq!(token_of("/wt?tokens=abc"), None);
        // A path that merely contains the word is not a token.
        assert_eq!(token_of("/token=abc"), None);
    }
}
