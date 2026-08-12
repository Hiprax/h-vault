/**
 * Per-test temporary directories, and a guard that keeps the suite from writing
 * into the repository.
 *
 * A test that writes into the checkout leaves state behind that the NEXT test
 * can read, which is order dependence wearing the costume of a fixture; it also
 * dirties the working tree, and `audit:integrity` scans untracked files, so one
 * stray fixture can fail an unrelated gate. The existing file-writing suites
 * (`integrity-scan`, `ratchet-check`, `selftest`) already do the right thing with
 * `mkdtempSync(tmpdir())`; this module makes it the obvious path AND makes the
 * wrong path fail loudly instead of quietly succeeding.
 *
 * It lives at the repo root, beside `socketEgress.ts` and for the same reason:
 * the allowlist below names paths in EVERY package, so a per-package copy would
 * be three lists that drift, and the tier that copied it last is the one that
 * silently stops guarding. The server tier re-exports it as `tests/tempDir.ts`
 * for the call sites that already name that path.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import fs from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { onTestFinished } from 'vitest';

/** The repository root, derived from this module's own URL, never `process.cwd()`. */
export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

/**
 * Creates a temp directory for the current test and removes it when the test
 * finishes (pass or fail).
 *
 * `onTestFinished` rather than an `afterEach` in the setup file, so the cleanup
 * is scoped to the test that asked for the directory: an `afterEach` sweeping a
 * shared parent is exactly the kind of shared mutable state this phase removes.
 */
export function createTestTempDir(prefix = 'hv-test-'): string {
  const dir = mkdtempSync(path.join(tmpdir(), prefix));
  onTestFinished(() => {
    rmSync(dir, { recursive: true, force: true });
  });
  return dir;
}

/**
 * Paths inside the repository that the RUNNER itself legitimately writes, and
 * which therefore cannot be blocked:
 *
 *   • `node_modules/**` — mongodb-memory-server caches the mongod binary in
 *     `node_modules/.cache/mongodb-binaries`, and several tools keep caches there.
 *   • `packages/*​/coverage/**` — the V8 coverage provider writes its per-worker
 *     `.tmp` payloads from inside the worker process.
 *   • `.testfortress/**` — the JUnit reporter and every gate's report.
 *   • `logs/**` and `packages/*​/logs/**` — the application logger's rotating file
 *     transports, which are NOT silent under `NODE_ENV=test`.
 *
 * That last entry is an allowlist for a real defect rather than an endorsement,
 * and it is written down here because the guard is what found it. Every
 * `createLogger({ moduleName })` call in `packages/server/src` omits
 * `logDirectory`, which @hiprax/logger defaults to `path.resolve(cwd(), 'logs')`,
 * with `includeFile` and `includeGlobalFile` both defaulting to true. Under
 * `npm test -w packages/server` the cwd is the package, so every run appends
 * rotating log files to `packages/server/logs` — measured at ~1.6 MB for one
 * server run and 448 MB accumulated over the project's history. Blocking it here
 * would fail the suite inside production code at import time, and redirecting it
 * needs a production change (a `logDirectory` from config, or `includeFile:
 * !isTest`), which a test-only phase may not make. Recorded as an out-of-scope
 * finding instead; remove this entry when the logger's directory becomes
 * configurable.
 */
const ALLOWED_REPO_WRITES = [
  path.join(REPO_ROOT, 'node_modules'),
  path.join(REPO_ROOT, '.testfortress'),
  path.join(REPO_ROOT, 'logs'),
  path.join(REPO_ROOT, 'packages', 'shared', 'coverage'),
  path.join(REPO_ROOT, 'packages', 'shared', 'logs'),
  path.join(REPO_ROOT, 'packages', 'server', 'coverage'),
  path.join(REPO_ROOT, 'packages', 'server', 'logs'),
  path.join(REPO_ROOT, 'packages', 'client', 'coverage'),
  path.join(REPO_ROOT, 'packages', 'client', 'logs'),
];

/** Thrown when a test tries to write inside the checkout. */
export class RepoWriteBlockedError extends Error {
  override readonly name = 'RepoWriteBlockedError';

  constructor(
    readonly target: string,
    readonly via: string,
  ) {
    super(
      `RepoWriteBlockedError: the test harness blocked a write to "${target}" (via ${via}), ` +
        `which is inside the repository. Use createTestTempDir() from the test harness so the ` +
        `file lands in the OS temp directory and is removed when the test finishes.`,
    );
  }
}

function isBlocked(target: unknown): string | undefined {
  if (typeof target !== 'string' && !(target instanceof URL) && !Buffer.isBuffer(target)) {
    // A numeric file descriptor: the open() that produced it was already checked
    // if it went through a patched entry point, and there is no path to report.
    return undefined;
  }
  const asPath = target instanceof URL ? fileURLToPath(target) : target.toString();
  const resolved = path.resolve(asPath);
  if (!resolved.startsWith(REPO_ROOT + path.sep)) return undefined;
  for (const allowed of ALLOWED_REPO_WRITES) {
    if (resolved === allowed || resolved.startsWith(allowed + path.sep)) return undefined;
  }
  return resolved;
}

let installed = false;

/**
 * Wraps the filesystem write entry points a test would realistically reach.
 *
 * Deliberately NOT a sandbox, and the boundary is worth stating exactly, because
 * a guard trusted for more than it does is worse than no guard:
 *
 *   • It replaces methods ON the `fs` exports object, so it intercepts every
 *     caller that resolves the method at CALL time: `import fs from 'node:fs'`
 *     then `fs.writeFileSync(...)`, `require('fs').mkdirSync(...)`, and any
 *     bundled dependency doing the same. That is the form that found the log-file
 *     writes documented above.
 *   • It does NOT intercept `import { writeFileSync } from 'node:fs'`. Node
 *     snapshots a builtin's named exports when the module namespace is first
 *     created — which happens before any setup file runs — so that binding
 *     already holds the original function and no later assignment can reach it.
 *     Measured, not assumed.
 *
 *   • It covers the four SYNCHRONOUS path-first calls a test reaches for
 *     (`writeFileSync`, `appendFileSync`, `mkdirSync`, `rmSync`) and deliberately
 *     leaves `fs.promises.*` and `createWriteStream` alone. An earlier version
 *     wrapped those too and BROKE THE RUNNER: the v8 coverage provider writes its
 *     per-worker payloads to `coverage/.tmp/coverage-N.json` and reads them back,
 *     and with those wrappers in place the read failed with ENOENT, which killed
 *     the run before the JUnit reporter flushed — leaving a 0-byte
 *     `junit-server.xml` and no `lcov.info`, so `audit:ratchet:full` reported
 *     `tests.count` and every server coverage field as UNMEASURED. A guard that
 *     silently disables the pipeline's own measurements is worth strictly less
 *     than the accidental writes it catches, so it stops at the boundary where it
 *     was observed to interfere. Measured, not assumed.
 *
 * So {@link createTestTempDir} remains the mechanism and this is defense in
 * depth: it catches a whole class of accidental writes with a message naming the
 * fix, and it does not pretend to catch all of them.
 */
export function installRepoWriteGuard(): void {
  if (installed) return;
  installed = true;

  const wrapPathFirst = <T extends (...args: never[]) => unknown>(fn: T, via: string): T => {
    return function guarded(this: unknown, ...args: unknown[]): unknown {
      const blocked = isBlocked(args[0]);
      if (blocked !== undefined) throw new RepoWriteBlockedError(blocked, via);
      return (fn as unknown as (...inner: unknown[]) => unknown).apply(this, args);
    } as unknown as T;
  };

  for (const name of ['writeFileSync', 'appendFileSync', 'mkdirSync', 'rmSync'] as const) {
    const original = fs[name];
    (fs as unknown as Record<string, unknown>)[name] = wrapPathFirst(
      original as unknown as (...args: never[]) => unknown,
      `fs.${name}`,
    );
  }
}
