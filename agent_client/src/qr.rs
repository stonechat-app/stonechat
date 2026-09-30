//! The link code as a QR the phone's camera can read off a terminal.
//!
//! Worth having even though the code is only 102 characters: scanning is the
//! path the app is built around ("Link a device" opens the camera), and it
//! avoids getting a base64url string through a clipboard, an SSH session and a
//! phone keyboard intact. The plain line is still printed underneath, because
//! a terminal that mangles this — wrong font, tiny window, a multiplexer that
//! eats the escape codes — must not leave you with no way to link.
//!
//! Two rendering decisions matter for whether it actually scans:
//!
//! - **Half blocks.** One character cell is two modules tall, which cancels
//!   the ~2:1 aspect ratio of a terminal cell and leaves the code square.
//!   Rendered one module per cell it comes out twice as tall as it is wide and
//!   most scanners refuse it.
//! - **Forced black-on-white.** Polarity is not negotiable to a lot of phone
//!   cameras, and a terminal's own colours are unknowable — the same output is
//!   dark-on-light in one theme and light-on-dark in another. Setting the
//!   colours explicitly per line makes the result independent of the theme.

use std::io::IsTerminal;

use qrcode::render::unicode;
use qrcode::{EcLevel, QrCode};

/// Black foreground on bright white background, then reset. Applied per line
/// so that nothing after the code inherits it.
const BLACK_ON_WHITE: &str = "\x1b[30;107m";
const RESET: &str = "\x1b[0m";

/// True when a QR is worth printing: a terminal is watching, and the caller
/// has not asked for plain text.
pub fn wanted(suppressed: bool) -> bool {
    !suppressed && std::io::stdout().is_terminal()
}

/// The code as half-block Unicode, indented and colour-forced.
///
/// `None` if the data will not fit a QR at all, which for a 102-character link
/// code should never happen — but a link flow that dies because its decoration
/// failed would be an absurd way to lose.
pub fn render(data: &str) -> Option<String> {
    // Error correction Q, what the link code is designed for. Higher than a
    // URL would need, because this is being photographed off a screen at an
    // angle, in whatever light.
    let code = QrCode::with_error_correction_level(data, EcLevel::Q).ok()?;
    let art = code
        .render::<unicode::Dense1x2>()
        .quiet_zone(true)
        .build();
    Some(
        art.lines()
            .map(|line| format!("  {BLACK_ON_WHITE}{line}{RESET}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic code: version marker + 32-byte lookup + 32-byte commitment,
    /// base64url without padding, behind the scheme. 102 characters.
    fn sample() -> String {
        let body = crate::util::b64url_nopad(&[7u8; 65]);
        format!("stonechat-link:{body}")
    }

    #[test]
    fn a_link_code_renders() {
        let code = sample();
        assert_eq!(code.len(), 102, "the link code is a fixed 102 characters");
        assert!(render(&code).is_some());
    }

    /// Cells actually drawn on screen: escape sequences and the indent are not
    /// width. Measured by removing exactly the strings this module adds,
    /// rather than by filtering control characters — the bytes after `ESC` are
    /// ordinary printable ones and would otherwise be counted.
    fn visible_width(line: &str) -> usize {
        line.replace(BLACK_ON_WHITE, "")
            .replace(RESET, "")
            .strip_prefix("  ")
            .expect("every line is indented")
            .chars()
            .count()
    }

    #[test]
    fn every_line_is_the_same_width() {
        // Ragged lines mean a scanner sees a ragged quiet zone on one side.
        let art = render(&sample()).unwrap();
        let widths: Vec<usize> = art.lines().map(visible_width).collect();
        assert!(
            widths.windows(2).all(|w| w[0] == w[1]),
            "uneven line widths: {widths:?}"
        );
    }

    #[test]
    fn the_code_comes_out_roughly_square() {
        // The reason for half blocks. One module per cell would make this
        // ratio ~0.5, and most scanners refuse a code that far from square.
        let art = render(&sample()).unwrap();
        let rows = art.lines().count();
        let cols = visible_width(art.lines().next().unwrap());
        let ratio = (rows * 2) as f64 / cols as f64;
        assert!(
            (0.9..=1.1).contains(&ratio),
            "expected a square code, got {rows} rows x {cols} cols (ratio {ratio})"
        );
    }

    #[test]
    fn colours_are_forced_and_then_released() {
        // Polarity cannot be left to the terminal's theme, and the colour must
        // not leak onto whatever is printed next.
        let art = render(&sample()).unwrap();
        for line in art.lines() {
            assert!(line.contains(BLACK_ON_WHITE), "line without forced colour");
            assert!(line.ends_with(RESET), "line that does not reset");
        }
    }
}
