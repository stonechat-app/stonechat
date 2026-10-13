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

// The built specs by name, not the directory: Node 22's `--test` takes
// files and globs, and a directory argument is "Cannot find module".
const built = readdirSync(out)
  .filter((f) => f.endsWith('.js'))
  .map((f) => join(out, f));
execFileSync(process.execPath, ['--test', ...built], { stdio: 'inherit' });
