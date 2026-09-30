//! The new device's side of linking.
//!
//! The phone shows nothing and scans nothing here: **we** display the code and
//! the phone reads it. That direction is what makes a headless agent possible
//! at all — and since 2026-08-04 the code is a 32-byte commitment rather than
//! the keys themselves, which is why it fits in a terminal over SSH. The old
//! form carried a 1216-byte X-Wing key and ran to ~2360 characters.
//!
//! What arrives is a certificate over keys we generated and never sent
//! anywhere secret, plus addressing. **No identity secret travels**, so an
//! agent on a rented box is bounded by a certificate its owner can revoke,
//! rather than being a copy of their identity.

use std::time::{Duration, Instant};

use serde_json::Value;
use stonechat_core::envelope;

use crate::util::{Result, b64, b64url_nopad, blake2b_256, random, unb64_n};
use crate::{cert, err, hub, qr, state};

/// Domain tag for the offer commitment, mirrored in the hub
/// (`_offer_commitment`), the app (`offerCommitment`) and the web client.
/// Separated so this hash can never be mistaken for the parking key (BLAKE2b
/// over the lookup secret) or a TLS fingerprint (BLAKE2b over a certificate).
const OFFER_CONTEXT: &[u8] = b"stonechat-link-offer";

/// v1 put the keys in the QR; v2 puts a commitment to them.
const OFFER_VERSION: u8 = 2;

/// Grants are deleted after ten minutes whatever happens, so there is no point
/// polling past it — and saying so beats an infinite wait.
const OFFER_TTL: Duration = Duration::from_secs(10 * 60);

pub async fn link(hub_url: &str, no_qr: bool) -> Result<()> {
    if let Some(existing) = state::load()? {
        return Err(err!(
            "this agent is already linked as device {} of {} ({}).\n\
             Revoke it from the phone (Linked devices → the agent → revoke), \
             delete {}, and link again.",
            existing.device_id,
            existing.stonechat_id,
            existing.display_name,
            state::state_path().display()
        ));
    }

    let hub = hub::Hub::new(hub_url)?;

    // Our own keys, generated here and never leaving. `seal` does double duty:
    // it is both what the grant is encapsulated to and what peers will seal
    // envelopes to, which is what binds "the device that opened the grant" to
    // "the device the certificate names".
    let dev_sig_seed = random::<32>();
    let dev_seal_seed = random::<32>();
    let sig_pub = state::sig_public(&dev_sig_seed);
    let seal_pub = state::seal_public(&dev_seal_seed);
    let sig_pub_b64 = b64(&sig_pub);
    let seal_pub_b64 = b64(&seal_pub);

    let mut committed = Vec::with_capacity(OFFER_CONTEXT.len() + seal_pub.len() + sig_pub.len());
    committed.extend_from_slice(OFFER_CONTEXT);
    committed.extend_from_slice(&seal_pub);
    committed.extend_from_slice(&sig_pub);
    let commitment = blake2b_256(&committed);

    // Parked before the code is printed. A code committing to keys nobody can
    // fetch is one that scans and then fails, which is worse than none.
    hub.put_link_offer(&commitment, &seal_pub_b64, &sig_pub_b64)
        .await?;

    // A third, independent secret. The parking key is its hash and not the
    // commitment's: the commitment is on screen, and deriving the parking key
    // from something a passer-by can read would let them destroy the grant
    // with the returns-and-deletes fetch — a shoulder-surf turned into a
    // denial of service.
    let lookup = random::<32>();
    let parking_key = blake2b_256(&lookup);

    let mut code = Vec::with_capacity(65);
    code.push(OFFER_VERSION);
    code.extend_from_slice(&lookup);
    code.extend_from_slice(&commitment);
    let offer = format!("stonechat-link:{}", b64url_nopad(&code));

    println!();
    // The QR is the convenience; the line under it is the guarantee. Printing
    // both is not redundancy for its own sake — a headless box is exactly
    // where the camera path fails (SSH through a multiplexer, a terminal with
    // no Unicode, a window too small) and where the paste path is easiest.
    if qr::wanted(no_qr)
        && let Some(art) = qr::render(&offer)
    {
        println!("{art}");
        println!();
    }
    println!("  {offer}");
    println!();
    println!("  On the phone that holds this identity, open Linked devices:");
    println!("    · \"Link a device\" to scan the code above, or");
    println!("    · \"Paste a code instead\" for the line.");
    println!("  Then choose \"Agent\".");
    println!();
    println!("  Waiting for authorisation (the code is good for 10 minutes)…");

    let started = Instant::now();
    let sealed = loop {
        if let Some(sealed) = hub.take_link_grant(&parking_key).await? {
            break sealed;
        }
        if started.elapsed() > OFFER_TTL {
            return Err(err!(
                "nobody authorised that code within ten minutes; the hub has \
                 dropped it. Run `link` again for a fresh one."
            ));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };

    // The protocol's own hybrid seal, opened with the seal seed the
    // certificate inside is about to vouch for.
    let opened = envelope::unseal(&dev_seal_seed, &sealed).ok_or_else(|| {
        err!(
            "the grant is not sealed to this device's key. Someone else \
             collected a grant for a code that looked like ours, or the hub \
             served the wrong one — either way, link again."
        )
    })?;
    let grant: Value = serde_json::from_slice(&opened)
        .map_err(|e| err!("the grant unsealed but is not valid JSON: {e}"))?;

    let new = adopt(&grant, &dev_sig_seed, &dev_seal_seed, hub.base_url())?;
    state::save(&new)?;

    println!();
    println!("  Linked as device {} of {}", new.device_id, new.stonechat_id);
    println!("  Mailbox: {}", new.relay_address);

    // Prekeys last: until they are up, nobody can start a conversation with
    // this device. Doing it inside `link` means one command leaves a device
    // that actually works, rather than one that exists and cannot be reached.
    let published = crate::prekeys::publish(&new).await?;
    state::save(&published)?;
    println!("  Published prekeys — this device can now be messaged.");
    println!();
    println!("  Next: stonechat-agent run");
    Ok(())
}

/// The three checks, each closing a different substitution.
fn adopt(
    grant: &Value,
    dev_sig_seed: &[u8; 32],
    dev_seal_seed: &[u8; 32],
    fallback_hub: &str,
) -> Result<state::State> {
    let s = |k: &str| -> Result<String> {
        grant
            .get(k)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| err!("grant is missing {k}"))
    };

    let stonechat_id = s("stonechat_id")?;
    let identity_pub_b64 = s("identity_pub")?;
    let identity_pub: [u8; 32] = unb64_n(&identity_pub_b64, "grant identity_pub")?;

    // 1. The identity key must hash to the claimed SC- ID, so a grant that
    //    reached us by any route cannot install a *different* identity under
    //    the name on the phone's screen.
    if !stonechat_core::ids::pubkey_matches_id(&identity_pub, &stonechat_id) {
        return Err(err!(
            "that grant carries an identity key that does not commit to \
             {stonechat_id} — refusing to link"
        ));
    }

    let device_id = grant
        .get("device_id")
        .and_then(Value::as_u64)
        .ok_or_else(|| err!("grant is missing device_id"))? as u32;
    let cert_json = grant
        .get("cert")
        .cloned()
        .ok_or_else(|| err!("grant carries no certificate — there would be nothing to be"))?;

    // 2. The certificate must verify against that identity key, be unexpired,
    //    and name this device and this owner.
    let parsed = cert::verify(&cert_json, &identity_pub, Some(device_id))?;
    if parsed.stonechat_id != stonechat_id {
        return Err(err!(
            "certificate is for {} but the grant claims {stonechat_id}",
            parsed.stonechat_id
        ));
    }

    // 3. The certificate must vouch for **our own** keys. Skipping this is the
    //    interesting failure: we would store a perfectly valid certificate for
    //    someone else's device, publish it with our prekeys, and then be unable
    //    to open a single envelope addressed to us — with no error anywhere.
    if parsed.sig_pub != state::sig_public(dev_sig_seed)
        || parsed.seal_pub != state::seal_public(dev_seal_seed)
    {
        return Err(err!(
            "that certificate is for a different device's keys — refusing to \
             link. Nothing addressed to us would open."
        ));
    }

    Ok(state::State {
        // Deliberately no hub account token: mailbox management and billing
        // stay with the primary, so an agent cannot destroy the mailbox it
        // lives on.
        hub_url: grant
            .get("hub_url")
            .and_then(Value::as_str)
            .unwrap_or(fallback_hub)
            .to_string(),
        stonechat_id,
        display_name: grant
            .get("display_name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        identity_pub_b64,
        cert: cert_json,
        device_id,
        dev_sig_seed_b64: b64(dev_sig_seed),
        dev_seal_seed_b64: b64(dev_seal_seed),
        relay_address: s("relay_address")?,
        relay_tls_fp: s("relay_tls_fp")?,
        device_token: s("device_token")?,
        bundle_token: grant
            .get("bundle_token")
            .and_then(Value::as_str)
            .map(str::to_string),
        spk: None,
        kspk: None,
        opks: Default::default(),
        kopks: Default::default(),
        next_prekey_id: 1,
        sessions: Default::default(),
        peer_certs: Default::default(),
        bundle_tokens: Default::default(),
    })
}
