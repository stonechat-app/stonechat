/**
 * The browser smoke test.
 *
 * Starts a real relay, a stub hub, and a static server for the built client,
 * then drives headless Chrome at a page served under the **same CSP as the
 * release**. See `entry.ts` for what is asserted and why.
 *
 * Skips (exit 0) when Chrome or the relay binary is absent, so this can live in
 * the default `npm test` without becoming a machine-specific failure. It says
 * which, loudly — a skip that looks like a pass is how a test stops existing.
 *
 * Usage:  node test/smoke/run.mjs
 */
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createSecureContext } from 'node:tls';
import { tmpdir } from 'node:os';
import { dirname, extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';

import { csp } from '../../csp.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '../..');
const RELAY = join(root, '../relay/target/release/stonechat-relay');
const WASM = join(
  root,
  '../core/target/wasm32-unknown-unknown/release/stonechat_core.wasm',
);
const CHROME =
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const OWNER = 'SC-SMOKE-OWNER';
const TOKEN = 'smoke-token-00000000000000000000';

function skip(why) {
  console.log(`SKIPPED: ${why}`);
  process.exit(0);
}

if (!existsSync(RELAY)) {
  skip(`no relay binary at ${RELAY} — build it with: cargo build --release`);
}
if (!existsSync(WASM)) skip('no wasm core — build it for wasm32-unknown-unknown');
if (!existsSync(CHROME)) skip('Google Chrome not installed');

/** A free port, by binding and letting go. Races in principle; hasn't here. */
async function freePort(kind = 'tcp') {
  const { createServer: tcp } = await import('node:net');
  const { createSocket } = await import('node:dgram');
  if (kind === 'udp') {
    const s = createSocket('udp4');
    await new Promise((r) => s.bind(0, '127.0.0.1', r));
    const { port } = s.address();
    await new Promise((r) => s.close(r));
    return port;
  }
  const s = tcp();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const { port } = s.address();
  await new Promise((r) => s.close(r));
  return port;
}

const dir = mkdtempSync(join(tmpdir(), 'stonechat-smoke-'));
const children = [];
const servers = [];
function cleanup() {
  for (const c of children) c.kill();
  for (const s of servers) s.close();
  rmSync(dir, { recursive: true, force: true });
}
process.on('exit', cleanup);

const relayPort = await freePort();
const relayWtPort = await freePort('udp');
const hubPort = await freePort();
const sitePort = await freePort();

// -- the relay -------------------------------------------------------------

children.push(
  spawn(RELAY, [], {
    env: {
      ...process.env,
      STONECHAT_OWNER_ID: OWNER,
      STONECHAT_OWNER_TOKEN: TOKEN,
      STONECHAT_PORT: String(relayPort),
      STONECHAT_WT_PORT: String(relayWtPort),
      // The names its certificates must carry. Omitting this is the bug this
      // test exists to catch.
      STONECHAT_WT_ADVERTISE: '127.0.0.1',
      STONECHAT_DB: join(dir, 'mailbox.db'),
      STONECHAT_BLOBS: join(dir, 'blobs'),
      STONECHAT_TLS_DIR: dir,
    },
    stdio: 'ignore',
  }),
);

/** The relay serves its own certificate; fetch its schedule over plain TLS
 * without verifying, since verifying it is not what is under test here. */
async function relayCerts() {
  const { Agent } = await import('undici').catch(() => ({ Agent: null }));
  void Agent;
  for (let i = 0; i < 100; i++) {
    try {
      const r = await fetch(`https://127.0.0.1:${relayPort}/wt/certs`, {
        // Node 20: per-request TLS options are not exposed through fetch, so
        // the process-wide switch is the only lever. Scoped to this test
        // process, which talks to nothing else.
        dispatcher: undefined,
      });
      if (r.ok) return await r.json();
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('relay never served /wt/certs');
}
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
void createSecureContext;

const schedule = await relayCerts();

// -- a stub hub ------------------------------------------------------------

// Mirrors the real hub's CORS exactly: an origin allowlist and GET+POST. A
// stub that allowed everything would have hidden the CORS bug rather than
// catching it.
const siteOrigin = `http://127.0.0.1:${sitePort}`;
const identity = { pubkey: '', id: OWNER };

const hub = createServer((req, res) => {
  const origin = req.headers.origin;
  if (origin === siteOrigin) {
    res.setHeader('access-control-allow-origin', origin);
    res.setHeader('access-control-allow-methods', 'GET, POST');
    res.setHeader('access-control-allow-headers', 'content-type');
  }
  if (req.method === 'OPTIONS') {
    res.writeHead(204).end();
    return;
  }
  if (req.url?.startsWith('/v1/directory/')) {
    res.setHeader('content-type', 'application/json');
    res.end(
      JSON.stringify({
        stonechat_id: identity.id,
        pubkey: identity.pubkey,
        server: {
          address: `https://127.0.0.1:${relayPort}`,
          wt_address: `127.0.0.1:${relayWtPort}`,
          wt_certs: schedule.certs,
          wt_sig: identity.sig,
        },
      }),
    );
    return;
  }
  res.writeHead(404).end();
});
servers.push(hub);
await new Promise((r) => hub.listen(hubPort, '127.0.0.1', r));

// The owner signs the schedule, exactly as a phone does — `routeFor` refuses
// to pin anything unsigned, so without this the test would fail for the wrong
// reason.
const wasm = readFileSync(WASM);
const { instance } = await WebAssembly.instantiate(
  wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength),
  {},
);
{
  const ex = instance.exports;
  const mem = () => new Uint8Array(ex.memory.buffer);
  const put = (b) => {
    const p = ex.stonechat_alloc(Math.max(b.length, 1));
    mem().set(b, p);
    return p;
  };
  const take = (op, ol) => {
    const v = new DataView(ex.memory.buffer);
    const p = v.getUint32(op, true);
    const n = v.getUint32(ol, true);
    return Buffer.from(mem().slice(p, p + n));
  };
  const seed = Buffer.alloc(32, 7);
  const op = ex.stonechat_alloc(4);
  const ol = ex.stonechat_alloc(4);
  ex.stonechat_identity(put(seed), 0, op, ol);
  const id = JSON.parse(take(op, ol).toString());
  identity.pubkey = id.public;
  identity.id = id.stonechat_id;

  const body = Buffer.from(JSON.stringify({ certs: schedule.certs }));
  const op2 = ex.stonechat_alloc(4);
  const ol2 = ex.stonechat_alloc(4);
  const rc = ex.stonechat_wtcerts_sign(put(body), body.length, put(seed), op2, ol2);
  if (rc !== 0) throw new Error(`wtcerts_sign failed (${rc})`);
  identity.sig = take(op2, ol2).toString();
}

// -- the page --------------------------------------------------------------

const out = join(dir, 'site');
await esbuild.build({
  entryPoints: [join(here, 'entry.ts')],
  bundle: true,
  format: 'esm',
  target: 'es2022',
  platform: 'browser',
  loader: { '.png': 'dataurl' },
  define: {
    __WASM_INTEGRITY__: JSON.stringify(
      'sha384-' + createHash('sha384').update(wasm).digest('base64'),
    ),
    __BUILD_VERSION__: '"smoke"',
  },
  outfile: join(out, 'smoke.js'),
});

const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp(`http://127.0.0.1:${hubPort}`)}">
<title>smoke</title></head><body>
<script type="application/json" id="smoke-config">${JSON.stringify({
  hub: `http://127.0.0.1:${hubPort}`,
  stonechatId: identity.id,
  deviceToken: TOKEN,
})}</script>
<script type="module" src="/smoke.js"></script>
</body></html>`;

const site = createServer((req, res) => {
  const url = (req.url ?? '/').split('?')[0];
  if (url === '/' || url === '/index.html') {
    res.setHeader('content-type', 'text/html');
    res.end(page);
    return;
  }
  const file = url === '/stonechat_core.wasm' ? WASM : join(out, url);
  try {
    const body = readFileSync(file);
    res.setHeader(
      'content-type',
      extname(file) === '.wasm' ? 'application/wasm' : 'text/javascript',
    );
    res.end(body);
  } catch {
    res.writeHead(404).end();
  }
});
servers.push(site);
await new Promise((r) => site.listen(sitePort, '127.0.0.1', r));

// -- drive Chrome ----------------------------------------------------------

const profile = join(dir, 'chrome');
const chrome = spawn(
  CHROME,
  [
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    `--user-data-dir=${profile}`,
    '--enable-logging=stderr',
    '--v=0',
    siteOrigin,
  ],
  { stdio: ['ignore', 'pipe', 'pipe'] },
);
children.push(chrome);

const results = new Map();
let finished;
const done = new Promise((r) => (finished = r));
const deadline = setTimeout(() => finished('timeout'), 60_000);

for (const stream of [chrome.stdout, chrome.stderr]) {
  stream.on('data', (chunk) => {
    for (const line of String(chunk).split('\n')) {
      const m = /SMOKE (\S+) (PASS|FAIL) ?(.*?)(?:", source|$)/.exec(line);
      if (!m) continue;
      const [, name, verdict, detail] = m;
      if (name === 'done') finished(verdict);
      else results.set(name, { ok: verdict === 'PASS', detail });
    }
  });
}

const outcome = await done;
clearTimeout(deadline);

const expected = [
  'core-instantiates',
  'hub-reachable',
  'pins-verify',
  'webtransport-connects',
  'request-round-trips',
];
let failed = outcome === 'timeout' || outcome === 'FAIL';
console.log('');
for (const name of expected) {
  const r = results.get(name);
  if (!r) {
    console.log(`  MISSING  ${name}`);
    failed = true;
  } else {
    console.log(`  ${r.ok ? 'ok  ' : 'FAIL'}     ${name}${r.detail ? '  ' + r.detail : ''}`);
    if (!r.ok) failed = true;
  }
}
console.log('');
if (outcome === 'timeout') console.log('  the page never finished — timed out');
console.log(failed ? 'BROWSER SMOKE FAILED' : 'BROWSER SMOKE PASSED');
process.exit(failed ? 1 : 0);
