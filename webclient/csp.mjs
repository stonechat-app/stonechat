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
    "img-src 'self' data:",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join('; ');
}
