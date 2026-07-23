#!/usr/bin/env node
/**
 * Client production build wrapper: `tsc -b` then `vite build`.
 *
 * `vite build` is powered by Rolldown's native (Rust/napi) bundler. On Windows,
 * the Rolldown that vite 8.1.5 pins (`rolldown@~1.1.5`) intermittently segfaults
 * in its native worker threads AT PROCESS TEARDOWN — after the bundle AND the PWA
 * service worker have already been written to disk — surfacing as exit code
 * 0xC0000005 (`3221225477`, STATUS_ACCESS_VIOLATION). It is an upstream native
 * crash (vitejs/rolldown-vite#192), unrelated to our sources: the identical
 * commit builds cleanly on the very next run, and rolldown-vite is now archived
 * with no patched release inside vite 8's supported range.
 *
 * This wrapper does NOT relax the build gate:
 *   - a normal success (exit 0) passes with no retry;
 *   - an ordinary build error (`vite` exits 1, or `tsc` fails) fails immediately,
 *     with no retry;
 *   - ONLY the specific native access-violation code triggers exactly ONE clean
 *     re-run of `vite build`, which regenerates the full output — so a green
 *     result always means a genuinely complete build, and a genuinely broken
 *     build (which fails deterministically) still fails on the retry.
 *
 * The crash code is Windows-specific, so on Linux/macOS (including the Docker
 * build) the retry branch is inert and the behaviour is exactly `tsc -b`
 * followed by `vite build`.
 */
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const require = createRequire(import.meta.url);
const projectDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Windows STATUS_ACCESS_VIOLATION (0xC0000005), as reported by Node either
// unsigned (matching cmd.exe/npm) or as its signed 32-bit interpretation.
const NATIVE_CRASH_CODES = new Set([3221225477, -1073741819]);

/** Absolute path to a dependency's bin entry point, workspace-hoist aware. */
function binOf(pkg, relBin) {
  return path.join(path.dirname(require.resolve(`${pkg}/package.json`)), relBin);
}

/** Run a node script synchronously in the client package dir; return its exit code. */
function run(args, label) {
  const result = spawnSync(process.execPath, args, { cwd: projectDir, stdio: 'inherit' });
  if (result.error) {
    console.error(`[client-build] could not spawn ${label}: ${result.error.message}`);
    return 1;
  }
  // status is null only when the child was killed by a POSIX signal; treat as failure.
  return result.status ?? 1;
}

// 1) Type-check + project references. Pure JS (no native addon) — never retried.
const tscStatus = run([binOf('typescript', 'bin/tsc'), '-b'], 'tsc -b');
if (tscStatus !== 0) process.exit(tscStatus);

// 2) Bundle. Retried once, and ONLY on the native access-violation code.
const viteBuild = [binOf('vite', 'bin/vite.js'), 'build'];
let status = run(viteBuild, 'vite build');
if (NATIVE_CRASH_CODES.has(status)) {
  console.warn(
    `[client-build] vite build exited ${status} (STATUS_ACCESS_VIOLATION) — an upstream ` +
      'Rolldown native teardown crash on Windows (vitejs/rolldown-vite#192), not a build ' +
      'error. Re-running vite build once to produce a verified-complete build.',
  );
  status = run(viteBuild, 'vite build (retry)');
}
process.exit(status);
