#!/usr/bin/env node
/**
 * Client production build wrapper: `tsc -b`, then `vite build` for the
 * application, then a SECOND `vite build` for the document sandbox.
 *
 * `vite build` is powered by Rolldown's native (Rust/napi) bundler. On Windows,
 * Rolldown intermittently segfaults in its native worker threads AT PROCESS
 * TEARDOWN — after the bundle AND the PWA service worker have already been
 * written to disk — surfacing as exit code 0xC0000005 (`3221225477`,
 * STATUS_ACCESS_VIOLATION). It is an upstream native crash
 * (vitejs/rolldown-vite#192), unrelated to our sources: the identical commit
 * builds cleanly on the very next run, and rolldown-vite is archived with no
 * patched release inside vite 8's supported range.
 *
 * MEASURED against `rolldown@~1.1.5`, the version vite 8.1.5 pinned. Vite now
 * pins `rolldown@~1.2.4` and the crash has NOT been re-measured against it,
 * because it reproduces only on Windows and only intermittently — so the retry
 * stays. Do not delete it on the strength of a version number: the branch below
 * is inert on Linux and macOS, it costs a passing build nothing, and the way to
 * retire it is a Windows run that stops crashing, not a bump.
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

/**
 * One `vite build`, with the native-crash retry described above.
 *
 * Shared by BOTH builds rather than open-coded twice: the crash is a property of
 * Rolldown's teardown, not of a particular config, so a second build invoked
 * with a bare `spawnSync` would be the one that fails a Windows contributor's
 * push for a reason the first build is already known to survive.
 */
function viteBuild(label, extraArgs = []) {
  const args = [binOf('vite', 'bin/vite.js'), 'build', ...extraArgs];
  const status = run(args, label);
  if (!NATIVE_CRASH_CODES.has(status)) return status;
  console.warn(
    `[client-build] ${label} exited ${status} (STATUS_ACCESS_VIOLATION) — an upstream ` +
      'Rolldown native teardown crash on Windows (vitejs/rolldown-vite#192), not a build ' +
      'error. Re-running once to produce a verified-complete build.',
  );
  return run(args, `${label} (retry)`);
}

// 2) Bundle the application. Retried once, and ONLY on the native crash code.
const appStatus = viteBuild('vite build');
if (appStatus !== 0) process.exit(appStatus);

// 3) Bundle the document sandbox, SECOND and into the same `dist/`.
//
// A separate build rather than a second input, because the app and the sandbox
// share the whole unified/remark substrate and one build would hoist it into a
// chunk belonging to neither asset directory — see vite.config.sandbox.ts.
//
// The ORDER is load-bearing and is pinned by `tests/vite-config.test.ts`
// alongside the `emptyOutDir: false` that makes it survivable. Vite empties an
// `outDir` that lies inside the project root, so a sandbox build with the
// default setting deletes the application that was just built; and running the
// app build second would delete the sandbox instead. The two facts are one
// invariant and must never be separated.
const sandboxStatus = viteBuild('vite build (sandbox)', ['--config', 'vite.config.sandbox.ts']);
process.exit(sandboxStatus);
