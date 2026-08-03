/**
 * Build the web client, and produce the thing that justifies it existing.
 *
 * WEB_CLIENT.md's argument, compressed: a web app is re-fetched from its origin
 * on every load, so a coerced origin can serve one targeted user a modified
 * client. Nothing in-page fixes that — "a signature only helps if the verifier
 * lives outside the delivery channel being attacked". What *is* achievable is
 * making the attack detectable:
 *
 *   tiny index.html → SRI-pinned JS → integrity-fetched WASM
 *
 * so the entire attack surface is one small human-readable file, and verifying
 * the served app reduces to checking **one hash** against a published release.
 * That is the whole point of this script. It:
 *
 *   1. bundles the TypeScript to a single file (one file, so one SRI hash —
 *      static `import`s inside a module are not SRI-coverable);
 *   2. hashes the JS, the CSS and the WASM;
 *   3. injects the WASM hash into the bundle, so the client can
 *      `fetch(url, { integrity })` its own core;
 *   4. writes an index.html that pins the other two with `integrity=`;
 *   5. prints the **hash root** — sha256 of index.html — which is what a
 *      transparency log would publish and `curl | shasum` would check.
 *
 * Deliberately absent: a service worker. Service worker scripts cannot carry
 * SRI, so one would put uncoverable code in the delivery path. The client is
 * live-only anyway (no history in a browser), so nothing is lost.
 *
 * ## About `'wasm-unsafe-eval'`
 *
 * Compiling WebAssembly counts as code generation, so a bare `script-src
 * 'self'` blocks `WebAssembly.instantiateStreaming` outright — the core does
 * not load at all. The fix is NOT `'unsafe-eval'`, which would also re-enable
 * `eval()` and `new Function()` for JavaScript and hand a script-injection bug
 * far more than it needs. `'wasm-unsafe-eval'` permits exactly one thing:
 * compiling WASM. Every browser with WebTransport has it (Chrome 97+,
 * Firefox 102+, Safari 16.4+), so it costs no reach either.
 *
 * This is the one policy line that cannot be checked off a browser, and it was
 * found by loading the page.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, rmSync, copyFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, 'dist');
const wasmSource = join(
  here,
  '../core/target/wasm32-unknown-unknown/release/stonechat_core.wasm',
);

/** Subresource Integrity token: the format `integrity=` and `fetch` expect. */
const sri = (buf) => 'sha384-' + createHash('sha384').update(buf).digest('base64');

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

// -- 1. the core -----------------------------------------------------------

let wasm;
try {
  wasm = readFileSync(wasmSource);
} catch {
  console.error(
    `\nstonechat_core.wasm not found at\n  ${wasmSource}\n\n` +
      'Build it first:\n' +
      '  cd ../core && cargo build --release --target wasm32-unknown-unknown\n',
  );
  process.exit(1);
}
copyFileSync(wasmSource, join(dist, 'stonechat_core.wasm'));
const wasmIntegrity = sri(wasm);

// -- 2. the bundle ---------------------------------------------------------

// The WASM hash is compiled *into* the JS, and the JS hash goes into the HTML.
// That ordering is the chain: one file at the root covers everything below it.
const result = await esbuild.build({
  entryPoints: [join(here, 'src/app.ts')],
  bundle: true,
  format: 'esm',
  target: 'es2022',
  platform: 'browser',
  minify: false, // auditability is the product; bytes are not the constraint
  sourcemap: false, // a sourcemap URL is another uncovered fetch
  legalComments: 'none',
  define: {
    __WASM_INTEGRITY__: JSON.stringify(wasmIntegrity),
    __BUILD_VERSION__: JSON.stringify(
      JSON.parse(readFileSync(join(here, 'package.json'), 'utf8')).version,
    ),
  },
  outfile: join(dist, 'app.js'),
  metafile: true,
});

const js = readFileSync(join(dist, 'app.js'));
const css = readFileSync(join(here, 'src/theme.css'));
writeFileSync(join(dist, 'theme.css'), css);

// -- 3. the one human-readable file ---------------------------------------

// Kept deliberately small and free of logic. Everything here should be
// checkable by eye in under a minute — that is the property being bought.
const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self' https:; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'">
<title>Stonechat</title>
<link rel="stylesheet" href="/theme.css" integrity="${sri(css)}">
</head>
<body>
<div id="app" class="app"></div>
<script type="module" src="/app.js" integrity="${sri(js)}"></script>
<noscript>Stonechat needs JavaScript and WebAssembly.</noscript>
</body>
</html>
`;
writeFileSync(join(dist, 'index.html'), html);

// -- 4. the hash root ------------------------------------------------------

const root = createHash('sha256').update(html).digest('hex');
writeFileSync(
  join(dist, 'release.json'),
  JSON.stringify(
    {
      hash_root: root,
      files: {
        'index.html': 'sha256-' + root,
        'app.js': sri(js),
        'theme.css': sri(css),
        'stonechat_core.wasm': wasmIntegrity,
      },
    },
    null,
    2,
  ) + '\n',
);

const kb = (b) => (b.length / 1024).toFixed(1) + ' KB';
console.log('');
console.log(`  index.html            ${kb(Buffer.from(html))}`);
console.log(`  app.js                ${kb(js)}   ${sri(js)}`);
console.log(`  theme.css             ${kb(css)}   ${sri(css)}`);
console.log(`  stonechat_core.wasm   ${kb(wasm)}  ${wasmIntegrity}`);
console.log('');
console.log(`  hash root  ${root}`);
console.log('');
console.log('  Verify a deployment against this:');
console.log("    curl -s https://<origin>/ | shasum -a 256");
console.log('');

if (Buffer.from(html).length > 2048) {
  // Not a hard failure, but the argument weakens as this file grows: "one
  // human-readable file" has to stay readable by an actual human.
  console.warn('  warning: index.html is over 2 KB — keep the root tiny\n');
}
void result;
