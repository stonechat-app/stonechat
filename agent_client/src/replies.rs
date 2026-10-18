//! What the agent says.
//!
//! A fixed set, picked at random. This is the whole of its behaviour for now
//! and it is deliberately dumb: the point of the device is to prove it is a
//! real one — that it links, stays certified, receives, decrypts, ratchets
//! and answers — not to be interesting. Anything cleverer plugs in exactly
//! here: [`answer`] sees the kind of message and its text, and whatever it
//! returns goes out in the owner's name, to an accepted contact, and is
//! mirrored to the owner's other devices.

use crate::util::random;

pub const SENTENCES: &[&str] = &[
    "Interesting — tell me more.",
    "Ha! I was just thinking the same thing.",
    "Message received loud and clear over here.",
    "That's a bold claim. I respect it.",
    "The ratchet turned, the sentence arrived. All is well.",
    "Sure, but have you considered the opposite?",
    "I'd reply something smarter, but I only know ten sentences.",
    "Encrypted, delivered, acknowledged. What a time to be alive.",
    "Noted. Filing that under 'important'.",
    "Say that again and I'll say this again.",
];

/// The reply to one message. `kind` is `msg` or `media`; `text` is the
/// message's text, empty for media.
pub fn answer(_kind: &str, _text: &str) -> String {
    pick().to_string()
}

pub fn pick() -> &'static str {
    let n = u64::from_be_bytes(random::<8>()) as usize;
    SENTENCES[n % SENTENCES.len()]
}

/// How long to wait before answering, in milliseconds — 600–1800ms.
///
/// Not decoration: an instant reply arrives before the sender's own message
/// has finished rendering, which makes the transcript read out of order while
/// you are trying to test the transcript.
pub fn think_time_ms() -> u64 {
    600 + (u64::from_be_bytes(random::<8>()) % 1200)
}
