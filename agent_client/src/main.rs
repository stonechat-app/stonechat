//! Stonechat agent client — a headless device on someone's identity.
//!
//! Not a bot with its own account. It links exactly like a phone or a browser
//! tab does, holds a certificate its owner signed, and speaks the same
//! protocol through `stonechat-core`. What makes it an *agent* is only that
//! nobody is sitting at it: it has no screen, it runs unattended, and it
//! usually lives on a server rather than in a pocket.
//!
//! Read agent_client/README.md before deploying one — in particular the part
//! about what it can see, which is everything addressed to its owner.
//!
//! Usage:
//!     stonechat-agent link [--hub URL]   show a QR + code, wait to be authorised
//!     stonechat-agent run [--show-text]  hold the socket and answer contacts
//!     stonechat-agent status             what this agent is
//!     stonechat-agent forget             delete local state (see the warning)

mod cert;
mod contacts;
mod hub;
mod link;
mod mailbox;
mod manifest;
mod pin;
mod prekeys;
mod proto;
mod qr;
mod replies;
mod run;
mod state;
mod util;

use util::Result;

/// Device 1 — whoever holds the owner token. A bootstrap distinction only;
/// the protocol treats devices uniformly.
pub const PRIMARY_DEVICE: u32 = 1;

const DEFAULT_HUB: &str = "https://hub.stonechat.app";

#[tokio::main]
async fn main() {
    if let Err(e) = dispatch().await {
        // One sentence, on stderr, non-zero exit. This runs under a service
        // manager; the log is the whole interface.
        eprintln!("stonechat-agent: {e}");
        std::process::exit(1);
    }
}

async fn dispatch() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("link") => {
            link::link(&hub_url(&args), args.iter().any(|a| a == "--no-qr")).await
        }
        Some("run") => {
            // Off by default: a container's stdout is kept by the host, and
            // the owner's mail does not belong in it.
            let show_text = args.iter().any(|a| a == "--show-text")
                || std::env::var("STONECHAT_AGENT_SHOW_TEXT").is_ok_and(|v| v == "1");
            run::run(show_text).await
        }
        Some("status") => run::status(),
        Some("forget") => forget(),
        Some("--help" | "-h" | "help") | None => {
            print!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(err!("no such command: {other}\n\n{USAGE}")),
    }
}

/// `--hub URL`, else `$STONECHAT_HUB`, else the production hub.
fn hub_url(args: &[String]) -> String {
    if let Some(i) = args.iter().position(|a| a == "--hub")
        && let Some(url) = args.get(i + 1)
    {
        return url.clone();
    }
    std::env::var("STONECHAT_HUB").unwrap_or_else(|_| DEFAULT_HUB.to_string())
}

/// Drop the local state.
///
/// Deliberately **not** called "unlink", because it does not unlink anything:
/// the device row and its certificate live on the mailbox and in the
/// directory, and only the primary can revoke them. Forgetting the file
/// without revoking leaves a device the owner believes exists, which is worse
/// than either action alone.
fn forget() -> Result<()> {
    let path = state::state_path();
    let existing = state::load()?;
    match existing {
        None => {
            println!("  nothing to forget at {}", path.display());
            Ok(())
        }
        Some(st) => {
            std::fs::remove_file(&path)?;
            println!("  removed {}", path.display());
            println!();
            println!(
                "  This did NOT revoke anything. Device {} is still listed on \
                 the mailbox and peers will still encrypt to it until its \
                 certificate expires.",
                st.device_id
            );
            println!("  Revoke it on the phone: Linked devices → device {} → revoke.", st.device_id);
            Ok(())
        }
    }
}

const USAGE: &str = "\
stonechat-agent — a headless Stonechat device

  link [--hub URL] [--no-qr]
                     Show a link code — as a scannable QR when a terminal is
                     watching, and always as a line you can paste — then wait
                     for the owner's phone to authorise it. Choose \"Agent\"
                     there. --no-qr prints only the line.
  run [--show-text]  Hold the receive socket and answer messages from accepted
                     contacts. --show-text also logs message text, which is
                     otherwise kept out of the log.
  status             Show what this agent is and when its certificate lapses.
  forget             Delete local state. Does NOT revoke — do that on the phone.

Environment:
  STONECHAT_HUB              Hub URL for `link` (default https://hub.stonechat.app)
  STONECHAT_AGENT_STATE      State file (default ~/.stonechat/agent.json)
  STONECHAT_AGENT_SHOW_TEXT  1 is the same as --show-text
";
