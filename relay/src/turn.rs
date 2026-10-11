//! The call relay: TURN (RFC 5766) inside the mailbox, for the owner's calls.
//!
//! A call is WebRTC between the two phones, and the mailbox never carries it —
//! except when the networks will not let the phones reach each other (a
//! carrier's NAT, most hotel and office Wi-Fi). Then one side's relay forwards
//! the packets, and that relay is *this process*: no coturn beside it, no
//! shared secret to hand across, nothing to install. The media is DTLS-SRTP
//! keyed between the two phones (PROTOCOL.md "Calls"), so what passes through
//! here is ciphertext, the same as the mail in the queue.
//!
//! The footprint matches the job: one UDP port where the owner's devices
//! knock (`turn_port`; it answers STUN "what is my address" too, so the app
//! needs no third-party STUN server), and ONE relay port beside it
//! (`turn_port + 1`) that exists as an allocation only while a call is up.
//! One owner, one call at a time, so one relay port is enough — a stale
//! allocation left by an app that died mid-call would block the next call,
//! and that is handled where the next call announces itself: minting
//! credentials for a new call (`/turn-credentials`, which the app calls
//! before every call) frees whatever allocation the previous ones held.
//!
//! Credentials are coturn's REST scheme, so the wire format and the app are
//! unchanged from when coturn did this job: `username = "<expiry>:stonechat"`,
//! `credential = base64(HMAC-SHA1(secret, username))`. The secret is this
//! mailbox's own, generated once beside the TLS key.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use turn::auth::{generate_auth_key, AuthHandler};
use turn::relay::RelayAddressGenerator;
use turn::server::config::{ConnConfig, ServerConfig};
use turn::server::Server;
use util::Conn;

pub const REALM: &str = "stonechat";
const USERNAME_SUFFIX: &str = ":stonechat";
/// How long a minted credential works. Long enough for any call; a leaked
/// one buys relaying through this one mailbox until then, nothing else.
pub const TTL: Duration = Duration::from_secs(6 * 3600);
const SECRET_FILE: &str = "turn-secret";

/// The secret the credentials are minted from and checked against. Created
/// on first start next to the TLS key, kept with it: it is part of what
/// makes this mailbox this mailbox, and goes with `/data` in a migration.
pub fn load_or_generate_secret(dir: &Path) -> std::io::Result<String> {
    let path = dir.join(SECRET_FILE);
    match std::fs::read_to_string(&path) {
        Ok(s) if s.trim().len() >= 32 => Ok(s.trim().to_string()),
        _ => {
            let secret: String = {
                let mut bytes = [0u8; 32];
                ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
                    .map_err(|_| std::io::Error::other("no system randomness"))?;
                bytes.iter().map(|b| format!("{b:02x}")).collect()
            };
            std::fs::write(&path, &secret)?;
            Ok(secret)
        }
    }
}

pub fn credential_for(secret: &str, username: &str) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(username.as_bytes());
    B64.encode(mac.finalize().into_bytes())
}

fn now_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// The owner's devices, and nobody else: a username this mailbox minted, not
/// yet expired, with the credential the secret gives it. The TURN server
/// does the integrity check; we hand it the key that check must succeed
/// against, or refuse to.
struct Auth {
    secret: String,
}

impl AuthHandler for Auth {
    fn auth_handle(
        &self,
        username: &str,
        realm: &str,
        _src: SocketAddr,
    ) -> Result<Vec<u8>, turn::Error> {
        let expiry = username
            .strip_suffix(USERNAME_SUFFIX)
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or(turn::Error::ErrNoSuchUser)?;
        if expiry < now_s() {
            return Err(turn::Error::ErrNoSuchUser);
        }
        Ok(generate_auth_key(username, realm, &credential_for(&self.secret, username)))
    }
}

/// The one relay port. Bound fresh for each allocation (the previous one's
/// socket closes with its allocation) and advertised at the address the
/// owner's device reached the mailbox at — in a container that is the host's
/// public address, which the process cannot see on any interface of its
/// own, so it is taken from the credentials request instead.
struct OnePort {
    port: u16,
    advertise: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl RelayAddressGenerator for OnePort {
    fn validate(&self) -> Result<(), turn::Error> {
        if self.port == 0 {
            Err(turn::Error::ErrRelayAddressInvalid)
        } else {
            Ok(())
        }
    }

    async fn allocate_conn(
        &self,
        use_ipv4: bool,
        _requested_port: u16,
    ) -> Result<(Arc<dyn Conn + Send + Sync>, SocketAddr), turn::Error> {
        let host = self.advertise.lock().await.clone();
        let ip = resolve(host.as_deref(), use_ipv4).await?;
        let bind: SocketAddr = if use_ipv4 {
            ([0, 0, 0, 0], self.port).into()
        } else {
            ([0u16; 8], self.port).into()
        };
        let conn = UdpSocket::bind(bind).await.map_err(turn::Error::from)?;
        Ok((Arc::new(conn), SocketAddr::new(ip, self.port)))
    }
}

async fn resolve(host: Option<&str>, use_ipv4: bool) -> Result<IpAddr, turn::Error> {
    let host = match host {
        Some(h) if !h.is_empty() => h,
        _ => return Ok(if use_ipv4 { [127, 0, 0, 1].into() } else { [0u16, 0, 0, 0, 0, 0, 0, 1].into() }),
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let mut addrs = tokio::net::lookup_host((host, 0))
        .await
        .map_err(turn::Error::from)?
        .map(|a| a.ip());
    addrs
        .find(|ip| ip.is_ipv4() == use_ipv4)
        .ok_or(turn::Error::ErrRelayAddressInvalid)
}

pub struct Turn {
    server: Server,
    secret: String,
    pub port: u16,
    advertise: Arc<Mutex<Option<String>>>,
    /// Usernames minted so far whose allocations may still be up. One owner,
    /// one call: the next mint ends them.
    minted: Mutex<Vec<String>>,
}

impl Turn {
    /// Binds the control port and starts answering. `advertise` is the host
    /// the mailbox is dialed at when it is known up front
    /// (`STONECHAT_WT_ADVERTISE`); the credentials request refines it.
    pub async fn start(secret: String, port: u16, advertise: Option<String>) -> Result<Turn, String> {
        let control = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port)))
            .await
            .map_err(|e| format!("binding udp {port}: {e}"))?;
        let advertise = Arc::new(Mutex::new(advertise.filter(|h| !h.is_empty())));
        let server = Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn: Arc::new(control),
                relay_addr_generator: Box::new(OnePort {
                    port: port + 1,
                    advertise: advertise.clone(),
                }),
            }],
            realm: REALM.into(),
            auth_handler: Arc::new(Auth {
                secret: secret.clone(),
            }),
            channel_bind_timeout: Duration::from_secs(600),
            alloc_close_notify: None,
        })
        .await
        .map_err(|e| format!("turn server: {e}"))?;
        Ok(Turn {
            server,
            secret,
            port,
            advertise,
            minted: Mutex::new(Vec::new()),
        })
    }

    /// Credentials for a call that is about to start, at `host` — the name
    /// the device reached the mailbox at, which is where the relay port is
    /// too. Ends the allocations of earlier credentials first: there is one
    /// relay port, and the call that wants it now is the live one.
    pub async fn mint(&self, host: &str) -> (String, String) {
        if !host.is_empty() {
            *self.advertise.lock().await = Some(host.to_string());
        }
        let previous: Vec<String> = std::mem::take(&mut *self.minted.lock().await);
        for name in previous {
            if let Err(e) = self.server.delete_allocations_by_username(name).await {
                log::warn!("turn: ending earlier allocation: {e}");
            }
        }
        let username = format!("{}{USERNAME_SUFFIX}", now_s() + TTL.as_secs());
        let credential = credential_for(&self.secret, &username);
        self.minted.lock().await.push(username.clone());
        (username, credential)
    }

    #[cfg(test)]
    pub async fn allocations(&self) -> usize {
        self.server.get_allocations_info(None).await.map(|m| m.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use turn::client::{Client, ClientConfig};

    /// Two adjacent free UDP ports; the pair is the relay's public shape.
    async fn free_port_pair() -> u16 {
        loop {
            let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let p = a.local_addr().unwrap().port();
            if p < u16::MAX && UdpSocket::bind(("127.0.0.1", p + 1)).await.is_ok() {
                return p;
            }
        }
    }

    async fn client_for(turn: &Turn, username: &str, credential: &str) -> Client {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let c = Client::new(ClientConfig {
            stun_serv_addr: format!("127.0.0.1:{}", turn.port),
            turn_serv_addr: format!("127.0.0.1:{}", turn.port),
            username: username.into(),
            password: credential.into(),
            realm: REALM.into(),
            software: String::new(),
            rto_in_ms: 0,
            conn: Arc::new(sock),
            vnet: None,
        })
        .await
        .unwrap();
        c.listen().await.unwrap();
        c
    }

    #[tokio::test]
    async fn a_call_relays_through_the_one_port_both_ways() {
        let port = free_port_pair().await;
        let turn = Turn::start("secret".repeat(4), port, None).await.unwrap();
        let (user, cred) = turn.mint("127.0.0.1").await;

        // STUN too: the app learns its own address from its mailbox.
        let client = client_for(&turn, &user, &cred).await;
        let seen = client.send_binding_request().await.unwrap();
        assert!(seen.ip().is_loopback());

        let relayed = client.allocate().await.unwrap();
        assert_eq!(relayed.local_addr().unwrap().port(), port + 1);
        assert_eq!(turn.allocations().await, 1);

        // The peer: anyone the client first sends to (that is the permission).
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        relayed.send_to(b"hello peer", peer_addr).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = peer.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello peer");
        assert_eq!(from.port(), port + 1);

        peer.send_to(b"hello back", from).await.unwrap();
        let (n, from) = tokio::time::timeout(Duration::from_secs(3), relayed.recv_from(&mut buf))
            .await
            .expect("relayed data arrives")
            .unwrap();
        assert_eq!(&buf[..n], b"hello back");
        assert_eq!(from, peer_addr);
        client.close().await.unwrap();
    }

    #[tokio::test]
    async fn the_next_call_takes_the_port_from_a_call_that_never_hung_up() {
        let port = free_port_pair().await;
        let turn = Turn::start("secret".repeat(4), port, None).await.unwrap();
        let (user, cred) = turn.mint("127.0.0.1").await;
        let dead = client_for(&turn, &user, &cred).await;
        let _held = dead.allocate().await.unwrap();
        assert_eq!(turn.allocations().await, 1);

        // The app crashed; nobody released that. A new call mints anew.
        let (user2, cred2) = turn.mint("127.0.0.1").await;
        assert_eq!(turn.allocations().await, 0);
        let live = client_for(&turn, &user2, &cred2).await;
        let relayed = live.allocate().await.unwrap();
        assert_eq!(relayed.local_addr().unwrap().port(), port + 1);
        live.close().await.unwrap();
    }

    #[tokio::test]
    async fn only_minted_and_unexpired_credentials_allocate() {
        let port = free_port_pair().await;
        let turn = Turn::start("secret".repeat(4), port, None).await.unwrap();
        let (user, _) = turn.mint("127.0.0.1").await;

        let wrong = client_for(&turn, &user, "not-the-credential").await;
        assert!(wrong.allocate().await.is_err());
        wrong.close().await.unwrap();

        let expired = format!("{}{USERNAME_SUFFIX}", now_s() - 1);
        let stale = client_for(&turn, &expired, &credential_for(&"secret".repeat(4), &expired)).await;
        assert!(stale.allocate().await.is_err());
        stale.close().await.unwrap();
        assert_eq!(turn.allocations().await, 0);
    }

    #[test]
    fn the_secret_is_made_once_and_kept() {
        let dir = std::env::temp_dir().join(format!("stonechat-turn-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = load_or_generate_secret(&dir).unwrap();
        let b = load_or_generate_secret(&dir).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
