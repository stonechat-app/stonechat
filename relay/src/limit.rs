//! Deposit rate limits for the routes anyone may call.
//!
//! `/inbox`, `/blob` and `/prekeys/bundle` take no token — sealed sender means
//! a sender has nothing to present — so the only thing that can be metered is
//! where a request came from and how many there are. Each of the three has a
//! token bucket per source address and one for everybody together; a request
//! needs a token from both.
//!
//! This bounds how fast a stranger can fill a queue, spend the blob store or
//! burn one-time prekeys. It is not what keeps the relay's memory bounded:
//! that holds at any rate (link.rs, db.rs).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::AppState;

/// How many source addresses one limiter remembers. At the cap the address
/// idle longest is forgotten — never the whole table, which would hand every
/// throttled sender a full bucket the moment a stranger arrived.
pub const MAX_TRACKED_ADDRESSES: usize = 4096;

/// Defaults, as `per-address rate/burst, global rate/burst` — rates are
/// requests per second. Sized against what one honest sender does to one
/// mailbox, which is the only share of a conversation a mailbox ever sees:
///
/// - `/inbox`: one message is one envelope per recipient device, typing
///   indicators and receipts are envelopes too, and a phone coming back
///   online flushes its whole outbox at once. 200 at once and 20 a second
///   after that is several times a busy sender with five devices to reach.
/// - `/blob`: an album is a few dozen uploads in a row, then nothing.
/// - `/prekeys/bundle`: one per device, once per session. The burst covers a
///   group forming, where every member opens a session in the same minute.
pub const DEFAULT_INBOX: &str = "20/200,100/1000";
pub const DEFAULT_BLOB: &str = "1/60,4/240";
pub const DEFAULT_BUNDLE: &str = "0.5/30,5/300";

#[derive(Clone, Copy, Debug, PartialEq)]
struct Rate {
    per_s: f64,
    burst: f64,
}

struct Bucket {
    tokens: f64,
    /// When this bucket was last asked, allowed or not — so an address that
    /// keeps hammering is never the one idle longest.
    seen: Instant,
}

impl Bucket {
    fn refilled(&self, rate: Rate, now: Instant) -> f64 {
        let idle = now.saturating_duration_since(self.seen).as_secs_f64();
        (self.tokens + idle * rate.per_s).min(rate.burst)
    }
}

struct Buckets {
    global: Bucket,
    addresses: HashMap<IpAddr, Bucket>,
}

pub struct Limiter {
    per_address: Rate,
    global: Rate,
    max_addresses: usize,
    buckets: Mutex<Buckets>,
}

fn parse_rate(spec: &str) -> Result<Rate, String> {
    let bad = || format!("expected rate/burst, got {spec:?}");
    let (per_s, burst) = spec.trim().split_once('/').ok_or_else(bad)?;
    let per_s: f64 = per_s.trim().parse().map_err(|_| bad())?;
    let burst: f64 = burst.trim().parse().map_err(|_| bad())?;
    if !(per_s > 0.0 && per_s.is_finite() && burst >= 1.0 && burst.is_finite()) {
        return Err(bad());
    }
    Ok(Rate { per_s, burst })
}

/// One address per sender, as far as an address can say: an IPv6 host owns
/// its whole /64 and can use a fresh address from it per request.
fn sender(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let prefix = u128::from(v6) & !u128::from(u64::MAX);
                IpAddr::V6(Ipv6Addr::from(prefix))
            }
        },
    }
}

impl Limiter {
    /// `"<per-address>,<global>"`, each `rate/burst`; `"off"` is no limiter.
    pub fn parse(spec: &str) -> Result<Option<Self>, String> {
        if spec.trim() == "off" {
            return Ok(None);
        }
        let (per_address, global) = spec
            .split_once(',')
            .ok_or_else(|| format!("expected per-address,global, got {spec:?}"))?;
        Ok(Some(Self::new(
            parse_rate(per_address)?,
            parse_rate(global)?,
            MAX_TRACKED_ADDRESSES,
        )))
    }

    fn new(per_address: Rate, global: Rate, max_addresses: usize) -> Self {
        Self {
            per_address,
            global,
            max_addresses,
            buckets: Mutex::new(Buckets {
                global: Bucket { tokens: global.burst, seen: Instant::now() },
                addresses: HashMap::new(),
            }),
        }
    }

    /// Spend one request. An address that is over its own limit does not
    /// spend from the global bucket, so one flooder cannot use up everybody
    /// else's share by being refused. `None` is a caller whose address the
    /// transport could not supply: it is held to the global limit alone.
    pub fn allow(&self, ip: Option<IpAddr>, now: Instant) -> bool {
        let mut guard = self.buckets.lock().unwrap();
        let buckets = &mut *guard;

        let global = buckets.global.refilled(self.global, now);
        buckets.global = Bucket { tokens: global, seen: now };

        let Some(ip) = ip.map(sender) else {
            if global < 1.0 {
                return false;
            }
            buckets.global.tokens -= 1.0;
            return true;
        };

        if !buckets.addresses.contains_key(&ip) && buckets.addresses.len() >= self.max_addresses {
            let idle_longest = buckets
                .addresses
                .iter()
                .min_by_key(|(_, b)| b.seen)
                .map(|(ip, _)| *ip);
            if let Some(idle_longest) = idle_longest {
                buckets.addresses.remove(&idle_longest);
            }
        }
        let fresh = Bucket { tokens: self.per_address.burst, seen: now };
        let bucket = buckets.addresses.entry(ip).or_insert(fresh);
        let tokens = bucket.refilled(self.per_address, now);
        *bucket = Bucket { tokens, seen: now };
        if tokens < 1.0 || global < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        buckets.global.tokens -= 1.0;
        true
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.buckets.lock().unwrap().addresses.len()
    }
}

/// The three limiters, by route. `None` is a limit turned off.
pub struct Limits {
    pub inbox: Option<Limiter>,
    pub blob: Option<Limiter>,
    pub bundle: Option<Limiter>,
}

impl Limits {
    /// From `STONECHAT_LIMIT_INBOX`, `_BLOB` and `_BUNDLE`.
    pub fn from_env() -> Result<Self, String> {
        let read = |key: &str, default: &str| {
            Limiter::parse(&crate::env_or(key, default)).map_err(|e| format!("{key}: {e}"))
        };
        Ok(Self {
            inbox: read("STONECHAT_LIMIT_INBOX", DEFAULT_INBOX)?,
            blob: read("STONECHAT_LIMIT_BLOB", DEFAULT_BLOB)?,
            bundle: read("STONECHAT_LIMIT_BUNDLE", DEFAULT_BUNDLE)?,
        })
    }

    #[cfg(test)]
    pub fn off() -> Self {
        Self { inbox: None, blob: None, bundle: None }
    }

    fn for_route(&self, method: &Method, path: &str) -> Option<&Limiter> {
        match (method.as_str(), path) {
            ("POST", "/inbox") => self.inbox.as_ref(),
            ("POST", "/blob") => self.blob.as_ref(),
            ("GET", "/prekeys/bundle") => self.bundle.as_ref(),
            _ => None,
        }
    }
}

/// Router middleware: refuse with 429 before the handler, and before the
/// body, is touched. Both transports pass through it — the TLS listener
/// supplies the peer address itself and wt.rs attaches the QUIC session's.
pub async fn guard(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    if let Some(limiter) = state.limits.for_route(request.method(), request.uri().path()) {
        let ip = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip());
        if !limiter.allow(ip, Instant::now()) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, "1")],
                Json(json!({"detail": "too many requests"})),
            )
                .into_response();
        }
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ip(n: u32) -> Option<IpAddr> {
        Some(IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + n)))
    }

    fn limiter(per_address: &str, global: &str, max_addresses: usize) -> Limiter {
        Limiter::new(
            parse_rate(per_address).unwrap(),
            parse_rate(global).unwrap(),
            max_addresses,
        )
    }

    #[test]
    fn specs_parse_and_junk_is_refused() {
        assert!(Limiter::parse("off").unwrap().is_none());
        let l = Limiter::parse(" 0.5/30 , 5/300 ").unwrap().unwrap();
        assert_eq!(l.per_address, Rate { per_s: 0.5, burst: 30.0 });
        assert_eq!(l.global, Rate { per_s: 5.0, burst: 300.0 });
        for default in [DEFAULT_INBOX, DEFAULT_BLOB, DEFAULT_BUNDLE] {
            assert!(Limiter::parse(default).unwrap().is_some());
        }
        for junk in ["", "20", "20/200", "0/10,1/1", "1/0,1/1", "-1/5,1/1", "a/b,c/d", "nan/1,1/1"] {
            assert!(Limiter::parse(junk).is_err(), "{junk:?} was accepted");
        }
    }

    #[test]
    fn an_address_gets_its_burst_then_its_rate() {
        let l = limiter("2/5", "1000/1000", 16);
        let t0 = Instant::now();
        for _ in 0..5 {
            assert!(l.allow(ip(1), t0));
        }
        assert!(!l.allow(ip(1), t0));
        // Somebody else is unaffected.
        assert!(l.allow(ip(2), t0));
        // Two a second: one second buys two more, not a fresh burst.
        let t1 = t0 + Duration::from_secs(1);
        assert!(l.allow(ip(1), t1));
        assert!(l.allow(ip(1), t1));
        assert!(!l.allow(ip(1), t1));
        // And a long silence buys the burst, never more.
        let t2 = t1 + Duration::from_secs(3600);
        for _ in 0..5 {
            assert!(l.allow(ip(1), t2));
        }
        assert!(!l.allow(ip(1), t2));
    }

    #[test]
    fn the_global_ceiling_holds_across_addresses() {
        let l = limiter("100/100", "1/10", 64);
        let t0 = Instant::now();
        let allowed = (0..40).filter(|n| l.allow(ip(*n), t0)).count();
        assert_eq!(allowed, 10);
        assert!(l.allow(ip(99), t0 + Duration::from_secs(1)));
        assert!(!l.allow(ip(98), t0 + Duration::from_secs(1)));
    }

    #[test]
    fn a_refused_address_does_not_spend_the_global_budget() {
        let l = limiter("1/2", "1/10", 64);
        let t0 = Instant::now();
        for _ in 0..500 {
            l.allow(ip(1), t0);
        }
        let others = (2..20).filter(|n| l.allow(ip(*n), t0)).count();
        assert_eq!(others, 8, "the flooder took more than its own two");
    }

    #[test]
    fn without_an_address_only_the_global_limit_applies() {
        let l = limiter("1/1", "1/3", 64);
        let t0 = Instant::now();
        assert_eq!((0..10).filter(|_| l.allow(None, t0)).count(), 3);
        assert_eq!(l.tracked(), 0);
    }

    #[test]
    fn the_table_is_bounded_and_forgets_the_address_idle_longest() {
        let l = limiter("1/2", "10000/10000", 3);
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        // Address 1 spends its burst and is refused.
        assert!(l.allow(ip(1), at(0)));
        assert!(l.allow(ip(1), at(0)));
        assert!(!l.allow(ip(1), at(0)));
        assert!(l.allow(ip(2), at(1)));
        assert!(l.allow(ip(3), at(2)));
        // It keeps asking, so it is not the one idle longest...
        assert!(!l.allow(ip(1), at(2)) || !l.allow(ip(1), at(2)) || !l.allow(ip(1), at(2)));
        // ...and a newcomer at the cap displaces address 2, not the table.
        assert!(l.allow(ip(4), at(3)));
        assert_eq!(l.tracked(), 3);
        let held: Vec<bool> = {
            let b = l.buckets.lock().unwrap();
            (1..=4).map(|n| b.addresses.contains_key(&ip(n).unwrap())).collect()
        };
        assert_eq!(held, [true, false, true, true]);
        // A flood of strangers never grows it.
        for n in 100..5000 {
            l.allow(ip(n), at(4));
        }
        assert_eq!(l.tracked(), 3);
    }

    #[test]
    fn an_ipv6_sender_is_its_prefix() {
        let l = limiter("1/2", "1000/1000", 64);
        let t0 = Instant::now();
        let v6 = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        assert!(l.allow(v6("2001:db8:1:2::1"), t0));
        assert!(l.allow(v6("2001:db8:1:2:ffff::9"), t0));
        assert!(!l.allow(v6("2001:db8:1:2:abcd::1"), t0));
        assert!(l.allow(v6("2001:db8:1:3::1"), t0));
        // A v4 sender on a dual-stack socket is the same sender.
        assert!(l.allow(v6("::ffff:10.0.0.7"), t0));
        assert!(l.allow(ip(7), t0));
        assert!(!l.allow(ip(7), t0));
    }

    #[test]
    fn only_the_open_deposit_routes_are_limited() {
        let limits = Limits {
            inbox: Limiter::parse(DEFAULT_INBOX).unwrap(),
            blob: Limiter::parse(DEFAULT_BLOB).unwrap(),
            bundle: Limiter::parse(DEFAULT_BUNDLE).unwrap(),
        };
        assert!(limits.for_route(&Method::POST, "/inbox").is_some());
        assert!(limits.for_route(&Method::POST, "/blob").is_some());
        assert!(limits.for_route(&Method::GET, "/prekeys/bundle").is_some());
        for (method, path) in [
            (Method::GET, "/health"),
            (Method::GET, "/status"),
            (Method::GET, "/ws"),
            (Method::GET, "/blob/123e4567-e89b-42d3-a456-426614174000"),
            (Method::POST, "/prekeys"),
            (Method::GET, "/prekeys/devices"),
        ] {
            assert!(limits.for_route(&method, path).is_none(), "{method} {path}");
        }
    }
}
