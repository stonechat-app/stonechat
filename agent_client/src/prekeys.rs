//! Our own prekey pools.
//!
//! Each device maintains its own SPK and OPK pool and signs them with **its
//! own** key; senders check those signatures against the key this device's
//! certificate names, not against the identity. The certificate goes up in the
//! same request, because one without the other leaves a sender unable to check
//! either.
//!
//! The relay has **replace semantics** per device (`db.rs::set_prekeys` drops
//! the pool and reinserts), so a restock uploads the *full remaining stock*,
//! not just the newly minted keys — MULTIDEVICE.md "Prekeys per device". A
//! partial upload silently retires every unused key we had.

use serde_json::{Value, json};
use stonechat_core::pqcore;
use stonechat_core::primitives::{
    KSPK_SIG_CONTEXT, SPK_SIG_CONTEXT, sign_with_context, x25519_pk,
};

use crate::mailbox::{Mailbox, opks_remaining, prekey_upload};
use crate::state::{KemPrekey, Prekey, State};
use crate::util::{Result, b64, random};

/// How many one-time prekeys to keep published. Each is one contact who can
/// start a conversation with forward secrecy from the first message.
const OPK_TARGET: usize = 32;

/// Restock below this. Running out is not fatal — senders fall back to the
/// signed last-resort key — but it is a downgrade, so it should not last.
const OPK_LOW_WATER: u64 = 8;

/// Mint whatever is missing, then publish the whole stock plus our certificate.
pub async fn publish(state: &State) -> Result<State> {
    let mut next = state.clone();
    let sig_seed = next.dev_sig_seed()?;

    if next.spk.is_none() {
        let secret = random::<32>();
        let public = x25519_pk(&secret);
        next.spk = Some(Prekey {
            id: take_id(&mut next),
            secret_b64: b64(&secret),
            public_b64: b64(&public),
        });
    }
    if next.kspk.is_none() {
        let seed = random::<64>();
        let public = pqcore::mlkem_pk_from_seed(&seed);
        next.kspk = Some(KemPrekey {
            id: take_id(&mut next),
            seed_b64: b64(&seed),
            public_b64: b64(&public),
        });
    }
    // Only the secret half is stored: the public one is derivable, and two
    // copies of a key is one chance for them to disagree.
    while next.opks.len() < OPK_TARGET {
        let id = take_id(&mut next);
        next.opks.insert(id, b64(&random::<32>()));
    }
    while next.kopks.len() < OPK_TARGET {
        let seed = random::<64>();
        let id = take_id(&mut next);
        next.kopks.insert(id, b64(&seed));
    }

    let spk = next.spk.clone().expect("minted above");
    let kspk = next.kspk.clone().expect("minted above");
    let spk_sig = sign_with_context(
        &sig_seed,
        SPK_SIG_CONTEXT,
        &crate::util::unb64(&spk.public_b64)?,
    );
    let kspk_sig = sign_with_context(
        &sig_seed,
        KSPK_SIG_CONTEXT,
        &crate::util::unb64(&kspk.public_b64)?,
    );

    let opks = publishable_x25519(&next)?;
    let kopks = publishable_mlkem(&next)?;

    let body = prekey_upload(
        (spk.id, &spk.public_b64, &b64(&spk_sig)),
        (kspk.id, &kspk.public_b64, &b64(&kspk_sig)),
        opks,
        kopks,
        &next.cert,
    );
    let mailbox = Mailbox::new(&next.relay_address, &next.relay_tls_fp)?;
    mailbox.publish_prekeys(&next.device_token, &body).await?;
    Ok(next)
}

/// Restock if the mailbox says we are running low. Returns the new state only
/// when something actually changed, so callers can skip a needless save.
pub async fn top_up(state: &State) -> Result<Option<State>> {
    let mailbox = Mailbox::new(&state.relay_address, &state.relay_tls_fp)?;
    let status = mailbox.status(&state.device_token).await?;
    match opks_remaining(&status) {
        Some(left) if left >= OPK_LOW_WATER => Ok(None),
        // A status we cannot read is not a reason to restock blindly: the
        // upload is ~55 KB and this runs on every reconnect.
        None => Ok(None),
        Some(left) => {
            println!("  one-time prekeys down to {left} — restocking");
            Ok(Some(publish(state).await?))
        }
    }
}

fn take_id(state: &mut State) -> u64 {
    let id = state.next_prekey_id;
    state.next_prekey_id += 1;
    id
}

fn publishable_x25519(state: &State) -> Result<Vec<Value>> {
    state
        .opks
        .iter()
        .map(|(id, secret_b64)| {
            let secret: [u8; 32] = crate::util::unb64_n(secret_b64, "one-time prekey")?;
            Ok(json!({"id": id, "pub": b64(&x25519_pk(&secret))}))
        })
        .collect()
}

fn publishable_mlkem(state: &State) -> Result<Vec<Value>> {
    state
        .kopks
        .iter()
        .map(|(id, seed_b64)| {
            let seed: [u8; 64] = crate::util::unb64_n(seed_b64, "one-time KEM prekey")?;
            Ok(json!({"id": id, "pub": b64(&pqcore::mlkem_pk_from_seed(&seed))}))
        })
        .collect()
}
