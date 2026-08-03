/**
 * Compile the TypeScript tests and run them under `node --test`.
 *
 * The tests import the real `src/` modules rather than a copy, so what is
 * checked is the code that ships. Node 20 cannot import .ts directly, so this
 * bundles first — the same esbuild the release build uses.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, readdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '..', '.test-build');

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

const specs = readdirSync(here)
  .filter((f) => f.endsWith('.test.ts'))
  .map((f) => join(here, f));

await esbuild.build({
  entryPoints: specs,
  bundle: true,
  format: 'esm',
  platform: 'node',
  target: 'node20',
  outdir: out,
  external: ['node:*'],
});

execFileSync(process.execPath, ['--test', out], { stdio: 'inherit' });
