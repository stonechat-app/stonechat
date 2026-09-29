//! The browser transport, end to end, against a real relay process.
//!
//! The unit tests in `wtcert.rs` prove the certificate schedule is well formed.
//! This proves the thing that actually matters: a client holding **only** a
//! SHA-256 from `/wt/certs` — no CA, no system trust store, nothing but the
//! hash — can connect to the mailbox and drain its queue.
//!
//! That is WEB_CLIENT.md blocker 1 in test form. It is a Rust client rather
//! than a browser because there is no browser here, but `serverCertificateHashes`
//! is the same mechanism on both sides: pin the certificate, ignore CAs.
use std::process::{Child, Command};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::Value;
use wtransport::tls::Sha256Digest;
use wtransport::{ClientConfig, Endpoint};

struct Relay {
    child: Child,
    dir: std::path::PathBuf,
    https: String,
    wt_port: u16,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const OWNER: &str = "SC-TEST-OWNER";
const TOKEN: &str = "tok-secret-000000000000000000000";

/// Two free ports: TCP for HTTPS, UDP for QUIC. Bound and dropped, which
/// races in principle and has not in practice — the alternative is teaching
/// the relay to report its ports.
fn free_ports() -> (u16, u16) {
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    (
        tcp.local_addr().unwrap().port(),
        udp.local_addr().unwrap().port(),
    )
}

fn start_relay() -> Relay {
    start_relay_with(&[])
}

fn start_relay_with(env: &[(&str, &str)]) -> Relay {
    let (port, wt_port) = free_ports();
    let dir = std::env::temp_dir().join(format!("stonechat-wt-e2e-{port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_stonechat-relay"))
        .env("STONECHAT_OWNER_ID", OWNER)
        .env("STONECHAT_OWNER_TOKEN", TOKEN)
        .env("STONECHAT_PORT", port.to_string())
        .env("STONECHAT_WT_PORT", wt_port.to_string())
        .env("STONECHAT_DB", dir.join("mailbox.db"))
        .env("STONECHAT_BLOBS", dir.join("blobs"))
        .env("STONECHAT_TLS_DIR", &dir)
        .envs(env.iter().copied())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("relay binary");
    Relay {
        child,
        dir,
        https: format!("https://127.0.0.1:{port}"),
        wt_port,
    }
}

fn http() -> reqwest::Client {
    // The relay's TLS certificate is self-signed and pinned by fingerprint;
    // this test is about the *other* transport, so it skips that check rather
    // than reimplementing it.
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_browser_style_client_drains_its_queue_with_only_a_pinned_hash() {
    let relay = start_relay();
    let http = http();

    // Wait for boot: the schedule is generated on first start, which mints
    // twelve certificates and is not instant.
    let mut certs: Option<Value> = None;
    for _ in 0..100 {
        if let Ok(r) = http.get(format!("{}/wt/certs", relay.https)).send().await {
            if r.status().is_success() {
                certs = Some(r.json().await.unwrap());
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let certs = certs.expect("relay never published a certificate schedule");
    let list = certs["certs"].as_array().unwrap();
    assert!(list.len() >= 2, "schedule should run ahead, got {}", list.len());

    // Everything still valid, exactly as a client would pass it. Passing the
    // whole set is what makes rotation silent: the relay may be serving any
    // of them, and the client does not need to know which.
    let hashes: Vec<Sha256Digest> = list
        .iter()
        .map(|c| {
            let raw = B64.decode(c["sha256"].as_str().unwrap()).unwrap();
            Sha256Digest::new(<[u8; 32]>::try_from(raw.as_slice()).unwrap())
        })
        .collect();

    // Post an envelope over the ordinary HTTP surface, so there is something
    // to drain.
    let envelope = serde_json::json!({
        "v": 1,
        "id": "wt-e2e-1",
        "to": OWNER,
        "device": 1,
        "sealed": B64.encode(b"an opaque box"),
    });
    let posted = http
        .post(format!("{}/inbox", relay.https))
        .json(&envelope)
        .send()
        .await
        .unwrap();
    assert_eq!(posted.status(), 200, "{:?}", posted.text().await);

    // -- the actual question ------------------------------------------------
    let config = ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes(hashes.clone())
        .build();
    let client = Endpoint::client(config).unwrap();
    let conn = client
        .connect(format!(
            "https://127.0.0.1:{}/wt?token={TOKEN}",
            relay.wt_port
        ))
        .await
        .expect("pinned-hash connect should succeed with no CA anywhere");

    let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();

    // `/ws` is an upgrade, exactly as it is over HTTP: the reply says 101 and
    // the stream then carries the owner socket. The token rides on the
    // *request*, not the session — the session is open, because delivery must
    // work for senders who hold no token at all.
    send.write_all(
        format!("{{\"method\":\"GET\",\"path\":\"/ws?token={TOKEN}\",\"len\":0}}\n")
            .as_bytes(),
    )
    .await
    .unwrap();

    let mut buf = vec![0u8; 8192];
    let mut acc = Vec::new();
    let mut lines: Vec<Value> = Vec::new();
    while lines.len() < 2 {
        let n = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut buf))
            .await
            .expect("no envelope drained")
            .unwrap()
            .unwrap();
        acc.extend_from_slice(&buf[..n]);
        while let Some(idx) = acc.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = acc.drain(..=idx).collect();
            lines.push(serde_json::from_slice(&line[..line.len() - 1]).unwrap());
        }
    }
    assert_eq!(lines[0]["status"], 101, "the upgrade must be acknowledged");
    assert_eq!(lines[1]["id"], "wt-e2e-1");
    assert_eq!(lines[1]["sealed"], B64.encode(b"an opaque box"));

    // Ack, and the row is gone — same contract the WebSocket has.
    send.write_all(b"{\"ack\":\"wt-e2e-1\"}\n").await.unwrap();
    let mut depth = -1i64;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let status: Value = http
            .get(format!("{}/status?token={TOKEN}", relay.https))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        depth = status["queued"].as_i64().unwrap_or(-1);
        if depth == 0 {
            break;
        }
    }
    assert_eq!(depth, 0, "ack over webtransport should delete the row");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_hash_is_refused() {
    // The pin has to actually bind. If any certificate were accepted, this
    // transport would be strictly worse than the one it exists to replace.
    let relay = start_relay();
    let http = http();
    for _ in 0..100 {
        if let Ok(r) = http.get(format!("{}/wt/certs", relay.https)).send().await {
            if r.status().is_success() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let config = ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([Sha256Digest::new([0x11; 32])])
        .build();
    let client = Endpoint::client(config).unwrap();
    let attempt = tokio::time::timeout(
        Duration::from_secs(10),
        client.connect(format!(
            "https://127.0.0.1:{}/wt?token={TOKEN}",
            relay.wt_port
        )),
    )
    .await;
    match attempt {
        Ok(Ok(_)) => panic!("a wrong certificate hash was accepted"),
        Ok(Err(_)) | Err(_) => {}
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_can_deliver_without_any_token() {
    // Sealed sender: anyone may post to anyone's mailbox, and a *sender* holds
    // no token for the *recipient's* relay. An earlier version authenticated
    // the session at CONNECT, which made delivery impossible for exactly the
    // case this transport exists to serve — found by writing the client.
    let (relay, http, conn) = start_relay_ready().await;

    let envelope = serde_json::json!({
        "v": 1, "id": "wt-stranger-1", "to": OWNER, "device": 1,
        "sealed": B64.encode(b"from someone with no token"),
    });
    let (head, _) = request(
        &conn, "POST", "/inbox",
        serde_json::to_vec(&envelope).unwrap().as_slice(),
    )
    .await;
    assert_eq!(head["status"], 200, "delivery must not require a token");

    // The open prekey bundle is reachable too — that is how a stranger starts
    // a session in the first place.
    let (head, _) = request(&conn, "GET", "/prekeys/bundle", b"").await;
    assert!(head["status"] == 200 || head["status"] == 404, "{head}");

    // But the owner's own surface still is not.
    let (head, _) = request(&conn, "GET", "/status", b"").await;
    assert_eq!(head["status"], 401, "the owner's status must stay closed");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_device_token_cannot_open_the_socket() {
    let relay = start_relay();
    let http = http();
    let mut certs: Option<Value> = None;
    for _ in 0..100 {
        if let Ok(r) = http.get(format!("{}/wt/certs", relay.https)).send().await {
            if r.status().is_success() {
                certs = Some(r.json().await.unwrap());
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let hashes: Vec<Sha256Digest> = certs.unwrap()["certs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let raw = B64.decode(c["sha256"].as_str().unwrap()).unwrap();
            Sha256Digest::new(<[u8; 32]>::try_from(raw.as_slice()).unwrap())
        })
        .collect();

    let client = Endpoint::client(
        ClientConfig::builder()
            .with_bind_default()
            .with_server_certificate_hashes(hashes)
            .build(),
    )
    .unwrap();

    // A valid certificate pin is not authorisation. The token names the
    // device, and the device names the queue — checked on the `/ws` stream
    // itself, since the session deliberately does not check anything.
    let conn = client
        .connect(format!("https://127.0.0.1:{}/wt", relay.wt_port))
        .await
        .expect("the session itself is open, by design");
    for path in ["/ws?token=nope", "/ws"] {
        let (head, _) = request(&conn, "GET", path, b"").await;
        assert_eq!(head["status"], 403, "socket opened without a token: {path}");
    }
}

/// Start a relay and confirm **both** listeners are live.
///
/// A UDP bind failure is deliberately non-fatal in the relay — a host that
/// blocks UDP should lose browser sessions, not its mailbox — so a port
/// collision between concurrently-running tests shows up as "HTTP works, QUIC
/// times out". Retrying with fresh ports is the fix; the alternative is a
/// flaky suite that looks like a transport bug.
async fn start_relay_ready() -> (Relay, reqwest::Client, wtransport::Connection) {
    let http = http();
    for attempt in 0..5 {
        let relay = start_relay();
        let mut ok = false;
        for _ in 0..100 {
            if let Ok(r) = http.get(format!("{}/wt/certs", relay.https)).send().await {
                if r.status().is_success() {
                    ok = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if ok {
            if let Some(conn) = try_connect(&relay, &http).await {
                return (relay, http, conn);
            }
        }
        eprintln!("relay attempt {attempt} did not come up on both ports; retrying");
    }
    panic!("could not start a relay with both listeners");
}

async fn try_connect(
    relay: &Relay,
    http: &reqwest::Client,
) -> Option<wtransport::Connection> {
    let certs: Value = http
        .get(format!("{}/wt/certs", relay.https))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    let hashes: Vec<Sha256Digest> = certs["certs"]
        .as_array()?
        .iter()
        .map(|c| {
            let raw = B64.decode(c["sha256"].as_str().unwrap()).unwrap();
            Sha256Digest::new(<[u8; 32]>::try_from(raw.as_slice()).unwrap())
        })
        .collect();
    let client = Endpoint::client(
        ClientConfig::builder()
            .with_bind_default()
            .with_server_certificate_hashes(hashes)
            .build(),
    )
    .ok()?;
    tokio::time::timeout(
        Duration::from_secs(5),
        client.connect(format!("https://127.0.0.1:{}/wt", relay.wt_port)),
    )
    .await
    .ok()?
    .ok()
}

/// Connect with pins fetched from `/wt/certs`, the way a browser would.
async fn connect(relay: &Relay, http: &reqwest::Client) -> wtransport::Connection {
    let mut certs: Option<Value> = None;
    for _ in 0..100 {
        if let Ok(r) = http.get(format!("{}/wt/certs", relay.https)).send().await {
            if r.status().is_success() {
                certs = Some(r.json().await.unwrap());
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let hashes: Vec<Sha256Digest> = certs.expect("no schedule")["certs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let raw = B64.decode(c["sha256"].as_str().unwrap()).unwrap();
            Sha256Digest::new(<[u8; 32]>::try_from(raw.as_slice()).unwrap())
        })
        .collect();
    Endpoint::client(
        ClientConfig::builder()
            .with_bind_default()
            .with_server_certificate_hashes(hashes)
            .build(),
    )
    .unwrap()
    .connect(format!("https://127.0.0.1:{}/wt?token={TOKEN}", relay.wt_port))
    .await
    .expect("pinned-hash connect")
}

/// One request on its own stream: header line, body, response, done.
async fn request(
    conn: &wtransport::Connection,
    method: &str,
    path: &str,
    body: &[u8],
) -> (Value, Vec<u8>) {
    let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();
    let header = serde_json::json!({"method": method, "path": path, "len": body.len()});
    send.write_all(format!("{header}\n").as_bytes()).await.unwrap();
    if !body.is_empty() {
        send.write_all(body).await.unwrap();
    }
    send.finish().await.unwrap();

    let mut acc = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    // Read until the header line, then until the declared body length.
    let (head, mut rest) = loop {
        let n = tokio::time::timeout(Duration::from_secs(10), recv.read(&mut buf))
            .await
            .expect("response timed out")
            .unwrap()
            .expect("stream closed before a response");
        acc.extend_from_slice(&buf[..n]);
        if let Some(idx) = acc.iter().position(|b| *b == b'\n') {
            let tail = acc.split_off(idx + 1);
            acc.pop();
            break (
                serde_json::from_slice::<Value>(&acc).expect("response header"),
                tail,
            );
        }
    };
    let len = head["len"].as_u64().unwrap() as usize;
    while rest.len() < len {
        match recv.read(&mut buf).await.unwrap() {
            Some(n) => rest.extend_from_slice(&buf[..n]),
            None => break,
        }
    }
    rest.truncate(len);
    (head, rest)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_http_routes_are_reachable_over_webtransport() {
    // The point of the adapter: these are not reimplemented for the browser.
    // Each request runs the same axum handler the TLS listener serves, with
    // the same extractors, the same body limit and the same status codes — so
    // a browser and a phone cannot disagree about what the relay does.
    let relay = start_relay();
    let http = http();
    let conn = connect(&relay, &http).await;

    // GET with a query string, authenticated by token like every other caller.
    let (head, body) = request(&conn, "GET", &format!("/status?token={TOKEN}"), b"").await;
    assert_eq!(head["status"], 200);
    let status: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["queued"], 0);
    assert_eq!(
        head["headers"]["content-type"], "application/json",
        "response headers must survive the framing"
    );

    // POST with a body.
    let envelope = serde_json::json!({
        "v": 1, "id": "wt-http-1", "to": OWNER, "device": 1,
        "sealed": B64.encode(b"over webtransport"),
    });
    let (head, _) = request(
        &conn, "POST", "/inbox",
        serde_json::to_vec(&envelope).unwrap().as_slice(),
    )
    .await;
    assert_eq!(head["status"], 200, "posting an envelope must work");

    // And it really landed, observed over the *other* transport.
    let queued: Value = http
        .get(format!("{}/status?token={TOKEN}", relay.https))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(queued["queued"], 1, "the two transports share one mailbox");

    // A route's own error handling is the router's, not the adapter's.
    let (head, _) = request(&conn, "GET", "/status?token=wrong", b"").await;
    assert_eq!(head["status"], 401, "auth failures must not become 200s");
    let (head, _) = request(&conn, "GET", "/nope", b"").await;
    assert_eq!(head["status"], 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn binary_bodies_survive_the_framing_in_both_directions() {
    // Blobs are the case the JSON-header framing has to get right: the body is
    // arbitrary bytes, it is large enough to span many reads, and a length
    // mistake would corrupt it silently rather than fail.
    let (relay, http, conn) = start_relay_ready().await;

    // Bytes that would break anything treating the body as text.
    let blob: Vec<u8> = (0..300_000u32).map(|i| (i % 256) as u8).collect();
    let (head, body) = request(
        &conn, "POST", &format!("/blob?token={TOKEN}"), &blob,
    )
    .await;
    assert_eq!(head["status"], 200, "{:?}", String::from_utf8_lossy(&body));
    let blob_id = serde_json::from_slice::<Value>(&body).unwrap()["blob_id"]
        .as_str()
        .unwrap()
        .to_string();

    let (head, got) = request(&conn, "GET", &format!("/blob/{blob_id}?token={TOKEN}"), b"").await;
    assert_eq!(head["status"], 200);
    assert_eq!(got.len(), blob.len(), "length must survive the round trip");
    assert_eq!(got, blob, "bytes must survive the round trip");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_body_is_refused_before_it_is_read() {
    // Bodies stream now, so this ceiling is protocol sanity rather than a
    // memory limit: a length larger than any route could serve is refused
    // from the header alone. The bytes are never read, which is the point —
    // a relay that waited for them would hang instead of answering.
    let (relay, http, conn) = start_relay_ready().await;
    let _ = (&relay, &http);

    let too_big = 65 * 1024 * 1024; // over MAX_BLOB_BYTES, so no route could serve it
    let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();
    let header = serde_json::json!({"method": "POST", "path": "/blob", "len": too_big});
    send.write_all(format!("{header}\n").as_bytes()).await.unwrap();
    // Deliberately send almost nothing after the header: a relay that waited
    // for the body before deciding would hang here instead of answering.
    send.write_all(&[0u8; 64]).await.unwrap();

    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 4096];
    while let Ok(Some(n)) = recv.read(&mut chunk).await {
        buf.extend_from_slice(&chunk[..n]);
        if buf.contains(&b'\n') {
            break;
        }
    }
    let line = buf.split(|b| *b == b'\n').next().unwrap().to_vec();
    let head: Value = serde_json::from_slice(&line).unwrap();
    assert_eq!(head["status"], 413, "an oversized body must be answered, not dropped");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_blob_larger_than_a_buffer_streams_both_ways() {
    // The case media needs and the old 1 MiB ceiling forbade. Several MiB is
    // enough to span many chunks in both directions; the point is not the size
    // but that nothing along the path holds the whole thing, which is what
    // lets a mailbox run under a 48m cgroup cap while carrying a photo.
    let (relay, http, conn) = start_relay_ready().await;
    let _ = (&relay, &http);

    // A pattern that repeats but never aligns to the 64 KiB chunk size, so a
    // dropped, duplicated or misordered chunk cannot cancel out.
    let blob: Vec<u8> = (0..4_000_003u32).map(|i| (i % 251) as u8).collect();

    let (head, body) = request(&conn, "POST", &format!("/blob?token={TOKEN}"), &blob).await;
    assert_eq!(head["status"], 200, "{:?}", String::from_utf8_lossy(&body));
    let blob_id = serde_json::from_slice::<Value>(&body).unwrap()["blob_id"]
        .as_str()
        .unwrap()
        .to_string();

    let (head, got) = request(&conn, "GET", &format!("/blob/{blob_id}?token={TOKEN}"), b"").await;
    assert_eq!(head["status"], 200);
    // The header promises a length before the body streams; a mismatch would
    // desynchronise framing for every later stream on this session.
    assert_eq!(head["len"].as_u64().unwrap() as usize, blob.len());
    assert_eq!(got.len(), blob.len(), "length must survive streaming");
    assert_eq!(got, blob, "bytes must survive streaming");

    // The session is still usable: framing stayed in step through a body far
    // larger than any buffer on the path.
    let (head, _) = request(&conn, "GET", &format!("/status?token={TOKEN}"), b"").await;
    assert_eq!(head["status"], 200, "session unusable after a streamed blob");
}

#[tokio::test(flavor = "multi_thread")]
async fn many_requests_share_one_session() {
    // One stream per request, many in flight: the session is authenticated
    // once at CONNECT and a stream carries no token of its own. If these
    // serialised, a client would be paying a round trip per request for no
    // reason.
    let (relay, http, conn) = start_relay_ready().await;

    let mut tasks = Vec::new();
    for i in 0..12 {
        let conn = conn.clone();
        tasks.push(tokio::spawn(async move {
            let envelope = serde_json::json!({
                "v": 1, "id": format!("wt-many-{i}"), "to": OWNER, "device": 1,
                "sealed": B64.encode(b"x"),
            });
            let (head, _) = request(
                &conn, "POST", "/inbox",
                serde_json::to_vec(&envelope).unwrap().as_slice(),
            )
            .await;
            head["status"].as_u64().unwrap()
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap(), 200);
    }
    let queued: Value = http
        .get(format!("{}/status?token={TOKEN}", relay.https))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(queued["queued"], 12);
}

#[tokio::test(flavor = "multi_thread")]
async fn deposits_are_metered_by_address_on_both_transports() {
    // The router is shared, but the peer address is not: the TLS listener
    // supplies it and the QUIC session has to attach its own. A per-address
    // burst far below the global one tells the two apart — if the address
    // went missing over WebTransport, the third deposit would be accepted.
    let relay = start_relay_with(&[("STONECHAT_LIMIT_INBOX", "0.001/2,0.001/100")]);
    let http = http();
    let conn = connect(&relay, &http).await;

    let post = |i: u32| {
        serde_json::to_vec(&serde_json::json!({
            "v": 1, "id": format!("wt-limit-{i}"), "to": OWNER, "device": 1,
            "sealed": B64.encode(b"x"),
        }))
        .unwrap()
    };
    let mut statuses = Vec::new();
    for i in 0..3 {
        let (head, body) = request(&conn, "POST", "/inbox", &post(i)).await;
        statuses.push(head["status"].as_u64().unwrap());
        if i == 2 {
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["detail"], "too many requests");
            assert_eq!(head["headers"]["retry-after"], "1");
        }
    }
    assert_eq!(statuses, [200, 200, 429]);

    // The same sender over the other transport is the same sender.
    let over_tls = http
        .post(format!("{}/inbox", relay.https))
        .body(post(3))
        .send()
        .await
        .unwrap();
    assert_eq!(over_tls.status(), 429);

    // Nothing else is metered, and nothing refused was stored.
    let status: Value = http
        .get(format!("{}/status?token={TOKEN}", relay.https))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(status["queued"], 2);
}
