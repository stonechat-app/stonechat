//! At most one live WebSocket **per device**.
//!
//! Was one per mailbox: a second connection kicked the first, which is
//! correct for one drainer and fatal for several — two devices sharing one
//! queue would race, and whichever acked first destroyed the envelope for the
//! other (MULTIDEVICE.md "Why the current architecture is single-device").
//! The kick rule survives, scoped down: a second socket for the *same* device
//! still replaces the first, which was never the problem.
//!
//! The handler task owns the socket; this holds what reaches it. Nothing here
//! grows with what senders do. A queued envelope is never handed over at
//! all: the connection is *woken* and reads the row from SQLite itself, a
//! page at a time, as fast as its socket takes them ([`pump`]). Only
//! transient frames, which exist nowhere else, travel in memory, through a
//! bounded channel that drops them when it is full.
//!
//! wake() reporting success means "a drainer is attached" — the promise
//! Python's ws.send_text made was no stronger, and it is exactly why the
//! ack-grace window exists (a suspended phone's socket accepts frames it will
//! never read).
//!
//! **Transport-agnostic since the web client.** This used to speak
//! `axum::extract::ws::Message` directly. A browser cannot open a WebSocket to
//! a relay — self-signed cert on a bare IP, no CA — so the same frames also go
//! over WebTransport (`wt.rs`). Both carry identical bytes; only the pipe
//! differs, and keeping one frame type is what stops the two drifting into two
//! subtly different protocols.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, Mutex, Notify};

/// How many transient frames may wait for one socket. At 64 KiB an envelope
/// this is 2 MiB, and it is the most a connection holds beyond a drain page.
pub const LIVE_FRAMES: usize = 32;
/// How many queued envelopes the drain reads at once: 1 MiB at the most.
pub const DRAIN_PAGE: usize = 16;
/// How long one frame may take to be accepted by the socket. A peer that
/// holds the connection open and reads nothing fills the transport's buffers
/// and then stalls the write; it is disconnected rather than waited on, and
/// the next envelope wakes the device through the push gateway instead.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Close, with the code and reason the WebSocket contract already promised.
/// WebTransport carries them as a final `{"close": code}` line.
pub type Close = (u16, &'static str);

/// The device's socket was replaced by a newer one for the same device.
pub const CLOSE_REPLACED: u16 = 4000;
/// The device was revoked; delivery is cut immediately, not at reconnect.
pub const CLOSE_REVOKED: u16 = 4001;

/// The one place the two transports differ: how a frame becomes bytes.
/// `false` means the peer is gone.
pub trait FrameSink: Send {
    fn text(&mut self, text: String) -> impl Future<Output = bool> + Send;
    fn close(&mut self, close: Close) -> impl Future<Output = ()> + Send;
}

struct Conn {
    id: u64,
    live: mpsc::Sender<String>,
    wake: Arc<Notify>,
    /// Its own channel rather than a frame in `live`: a close must arrive
    /// even when that one is full.
    close: oneshot::Sender<Close>,
}

/// The receiving half of a registration — what [`pump`] runs on.
pub struct Outbound {
    live: mpsc::Receiver<String>,
    wake: Arc<Notify>,
    close: oneshot::Receiver<Close>,
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
    ///
    /// The rule is per device and per *device*, not per transport: a browser
    /// session that connects over WebTransport replaces that same device's
    /// WebSocket, which is right — one drainer per queue, however it arrived.
    pub async fn attach(&self, device: i64) -> (u64, Outbound) {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (live, live_rx) = mpsc::channel(LIVE_FRAMES);
        let (close, close_rx) = oneshot::channel();
        let wake = Arc::new(Notify::new());
        let conn = Conn { id, live, wake: wake.clone(), close };
        let old = self.conns.lock().await.insert(device, conn);
        if let Some(old) = old {
            let _ = old.close.send((CLOSE_REPLACED, "replaced by newer connection"));
        }
        (id, Outbound { live: live_rx, wake, close: close_rx })
    }

    /// Drop the registration iff it is still this handler's connection
    /// (a replaced connection must not detach its replacement).
    pub async fn detach(&self, device: i64, id: u64) {
        let mut conns = self.conns.lock().await;
        if conns.get(&device).is_some_and(|c| c.id == id) {
            conns.remove(&device);
        }
    }

    /// Tell a device's connection that its queue has a new row. `false` if
    /// the device is not connected. The envelope itself stays where it is:
    /// the connection reads it from the queue, in order, when its socket has
    /// room — so a burst of deposits costs a connected device no memory.
    pub async fn wake(&self, device: i64) -> bool {
        match self.conns.lock().await.get(&device) {
            Some(c) => {
                c.wake.notify_one();
                true
            }
            None => false,
        }
    }

    /// Hand a transient envelope to a connected device. It is queued nowhere,
    /// so a device that is absent, or behind by a full channel, never sees
    /// it — which is what transient means.
    pub async fn push_transient(&self, device: i64, envelope_json: &str) -> bool {
        match self.conns.lock().await.get(&device) {
            Some(c) => c.live.try_send(envelope_json.to_string()).is_ok(),
            None => false,
        }
    }

    /// Close and forget a device's socket — used by revocation, which must
    /// cut delivery immediately rather than at the next reconnect.
    pub async fn disconnect(&self, device: i64) {
        if let Some(conn) = self.conns.lock().await.remove(&device) {
            let _ = conn.close.send((CLOSE_REVOKED, "device revoked"));
        }
    }
}

/// Everything one connection writes, for as long as it lives.
///
/// Drains the queue in pages from `page(cursor)`, then sleeps until woken by
/// a deposit, a transient frame or a close. The cursor only ever advances, so
/// an envelope goes down a connection once; a row that arrives mid-drain is
/// simply on a later page. Returns when the peer is gone, stops reading, or
/// was told to close.
pub async fn pump<S: FrameSink>(
    mut out: Outbound,
    mut sink: S,
    page: impl Fn(i64) -> Vec<(i64, String)> + Send,
    write_timeout: Duration,
) {
    async fn write<S: FrameSink>(sink: &mut S, text: String, limit: Duration) -> bool {
        matches!(tokio::time::timeout(limit, sink.text(text)).await, Ok(true))
    }
    async fn close<S: FrameSink>(sink: &mut S, close: Close, limit: Duration) {
        let _ = tokio::time::timeout(limit, sink.close(close)).await;
    }

    let mut cursor = 0i64;
    loop {
        loop {
            let rows = page(cursor);
            if rows.is_empty() {
                break;
            }
            for (seq, body) in rows {
                // Checked per frame: a replaced or revoked connection must
                // not finish a ten-thousand-envelope drain first.
                match out.close.try_recv() {
                    Ok(told) => return close(&mut sink, told, write_timeout).await,
                    Err(oneshot::error::TryRecvError::Closed) => return,
                    Err(oneshot::error::TryRecvError::Empty) => {}
                }
                if !write(&mut sink, body, write_timeout).await {
                    return;
                }
                cursor = seq;
            }
            // A typing indicator is worth nothing by the end of a long drain.
            while let Ok(text) = out.live.try_recv() {
                if !write(&mut sink, text, write_timeout).await {
                    return;
                }
            }
        }
        tokio::select! {
            biased;
            told = &mut out.close => {
                if let Ok(told) = told {
                    close(&mut sink, told, write_timeout).await;
                }
                return;
            }
            // notify_one() leaves a permit when nobody is waiting, so a
            // deposit that lands between the empty page and this line is
            // not lost.
            _ = out.wake.notified() => {}
            text = out.live.recv() => match text {
                Some(text) => {
                    if !write(&mut sink, text, write_timeout).await {
                        return;
                    }
                }
                None => return,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    #[derive(Debug, PartialEq, Clone)]
    enum Sent {
        Text(String),
        Close(u16),
    }

    /// A socket that records what it was given, and can be made to stall.
    #[derive(Clone, Default)]
    struct Probe {
        sent: Arc<StdMutex<Vec<Sent>>>,
        /// Frames accepted before every later write hangs; None never hangs.
        stall_after: Option<usize>,
    }

    impl Probe {
        fn texts(&self) -> Vec<String> {
            self.sent
                .lock()
                .unwrap()
                .iter()
                .filter_map(|s| match s {
                    Sent::Text(t) => Some(t.clone()),
                    Sent::Close(_) => None,
                })
                .collect()
        }
    }

    impl FrameSink for Probe {
        async fn text(&mut self, text: String) -> bool {
            if self.stall_after.is_some_and(|n| self.sent.lock().unwrap().len() >= n) {
                std::future::pending::<()>().await;
            }
            self.sent.lock().unwrap().push(Sent::Text(text));
            true
        }
        async fn close(&mut self, close: Close) {
            self.sent.lock().unwrap().push(Sent::Close(close.0));
        }
    }

    /// A queue the pump can page through: (seq, body), appended by the test.
    #[derive(Clone, Default)]
    struct Queue {
        rows: Arc<StdMutex<Vec<(i64, String)>>>,
        largest_page: Arc<StdMutex<usize>>,
    }

    impl Queue {
        fn add(&self, seq: i64) {
            self.rows.lock().unwrap().push((seq, format!("e-{seq}")));
        }
        fn pager(&self) -> impl Fn(i64) -> Vec<(i64, String)> + Send {
            let q = self.clone();
            move |after| {
                let page: Vec<_> = q
                    .rows
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(seq, _)| *seq > after)
                    .take(DRAIN_PAGE)
                    .cloned()
                    .collect();
                let mut largest = q.largest_page.lock().unwrap();
                *largest = (*largest).max(page.len());
                page
            }
        }
    }

    async fn settle() {
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
    }

    const FAST: Duration = Duration::from_millis(50);

    #[tokio::test]
    async fn the_queue_drains_in_order_a_page_at_a_time() {
        let links = DeviceLinks::new();
        let (queue, probe) = (Queue::default(), Probe::default());
        for seq in 1..=(DRAIN_PAGE as i64 * 3 + 5) {
            queue.add(seq);
        }
        let (_, out) = links.attach(1).await;
        let task = tokio::spawn(pump(out, probe.clone(), queue.pager(), FAST));
        settle().await;
        let got = probe.texts();
        assert_eq!(got.len(), DRAIN_PAGE * 3 + 5);
        assert!(got.windows(2).all(|w| {
            w[0][2..].parse::<i64>().unwrap() < w[1][2..].parse::<i64>().unwrap()
        }));
        assert_eq!(*queue.largest_page.lock().unwrap(), DRAIN_PAGE);
        task.abort();
    }

    #[tokio::test]
    async fn a_deposit_after_the_drain_is_delivered_on_the_same_connection_once() {
        let links = DeviceLinks::new();
        let (queue, probe) = (Queue::default(), Probe::default());
        queue.add(1);
        let (_, out) = links.attach(1).await;
        let task = tokio::spawn(pump(out, probe.clone(), queue.pager(), FAST));
        settle().await;
        queue.add(2);
        assert!(links.wake(1).await);
        settle().await;
        // A second wake with nothing new behind it — what a duplicate
        // deposit would amount to if it woke at all — sends nothing again.
        assert!(links.wake(1).await);
        settle().await;
        assert_eq!(probe.texts(), ["e-1", "e-2"]);
        task.abort();
    }

    #[tokio::test]
    async fn transient_frames_are_dropped_when_the_channel_is_full() {
        let links = DeviceLinks::new();
        // Nothing is pumping, so nothing leaves the channel.
        let (_, _out) = links.attach(1).await;
        for i in 0..LIVE_FRAMES {
            assert!(links.push_transient(1, &format!("t-{i}")).await);
        }
        assert!(!links.push_transient(1, "one too many").await);
        // A durable deposit is unaffected: it was never going in the channel.
        assert!(links.wake(1).await);
        assert!(!links.push_transient(2, "nobody home").await);
        assert!(!links.wake(2).await);
    }

    #[tokio::test]
    async fn an_envelope_deposited_while_the_channel_is_full_still_arrives() {
        let links = DeviceLinks::new();
        let (queue, probe) = (Queue::default(), Probe::default());
        let (_, out) = links.attach(1).await;
        for i in 0..LIVE_FRAMES + 4 {
            links.push_transient(1, &format!("t-{i}")).await;
        }
        queue.add(1);
        links.wake(1).await;
        let task = tokio::spawn(pump(out, probe.clone(), queue.pager(), FAST));
        settle().await;
        let got = probe.texts();
        assert!(got.contains(&"e-1".to_string()));
        assert_eq!(got.len(), LIVE_FRAMES + 1, "the overflow was not dropped");
        task.abort();
    }

    #[tokio::test]
    async fn a_peer_that_stops_reading_is_disconnected() {
        let links = DeviceLinks::new();
        let queue = Queue::default();
        let probe = Probe { stall_after: Some(3), ..Default::default() };
        for seq in 1..=100 {
            queue.add(seq);
        }
        let (_, out) = links.attach(1).await;
        let task = tokio::spawn(pump(out, probe.clone(), queue.pager(), FAST));
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the pump waited on a socket nobody was reading")
            .unwrap();
        assert_eq!(probe.texts().len(), 3);
    }

    #[tokio::test]
    async fn a_close_arrives_past_a_full_channel_and_ends_the_drain() {
        let links = DeviceLinks::new();
        let (queue, probe) = (Queue::default(), Probe::default());
        let (first, out) = links.attach(1).await;
        for i in 0..LIVE_FRAMES {
            links.push_transient(1, &format!("t-{i}")).await;
        }
        let task = tokio::spawn(pump(out, probe.clone(), queue.pager(), FAST));
        let (second, _out2) = links.attach(1).await;
        tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
        assert_eq!(
            probe.sent.lock().unwrap().last(),
            Some(&Sent::Close(CLOSE_REPLACED))
        );
        // The replaced connection's detach must not remove its replacement.
        links.detach(1, first).await;
        assert!(links.wake(1).await);
        links.detach(1, second).await;
        assert!(!links.wake(1).await);
    }

    #[tokio::test]
    async fn revocation_closes_with_its_own_code() {
        let links = DeviceLinks::new();
        let (queue, probe) = (Queue::default(), Probe::default());
        let (_, out) = links.attach(2).await;
        let task = tokio::spawn(pump(out, probe.clone(), queue.pager(), FAST));
        settle().await;
        links.disconnect(2).await;
        tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
        assert_eq!(*probe.sent.lock().unwrap(), [Sent::Close(CLOSE_REVOKED)]);
    }
}
