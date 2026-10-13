/**
 * The page's Content-Security-Policy, in one place.
 *
 * Its own module so the browser smoke test can serve a page under the
 * **identical** policy without importing — and therefore running — the build.
 * A smoke test with its own relaxed CSP would pass happily while the real page
 * failed to compile WebAssembly, which is exactly what happened on 2026-08-04.
 */
export function csp(extra = '') {
  const connectSrc = ["'self'", 'https:', extra.trim()].filter(Boolean).join(' ');
  return [
    "default-src 'none'",
    // Compiling WASM counts as code generation; without this the core never
    // loads. NOT 'unsafe-eval', which would also re-enable eval() for JS.
    "script-src 'self' 'wasm-unsafe-eval'",
    "style-src 'self'",
    `connect-src ${connectSrc}`,
    // `blob:` is what an attachment renders from: media arrives as ciphertext,
    // is decrypted in the page, and becomes an object URL over bytes that never
    // touched the network in that form. Without it the browser blocks the image
    // it just decrypted and shows a broken icon — the bytes are fine, the
    // policy simply forbids displaying them. Not a loosening toward the
    // network: a blob URL is same-origin and can only name data this page
    // created.
    "img-src 'self' data: blob:",
    // Same, for video and audio elements. `default-src 'none'` means an
    // absent media-src is a *deny*, so a video attachment would fail the same
    // way an image did, and only once someone sent one.
    "media-src blob:",
    "base-uri 'none'",
    "form-action 'none'",
    // No frame-ancestors here: a <meta> policy cannot carry it (browsers
    // ignore it and say so in the console). The server sends it as a
    // header, where it is enforced — the Caddy site block in the main hub's
    // compose file, and whatever a self-hoster puts in front of dist/.
  ].join('; ');
}
