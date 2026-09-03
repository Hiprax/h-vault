/**
 * The crash probe's PARENT half: spawn a real server process, let it die
 * mid-write, and report how it died.
 *
 * The child (`crashChild.ts`) does the work and kills itself at a chosen
 * persistence-layer call. This side owns three things a test must not have to
 * repeat:
 *
 *   1. THE VERDICT. A probe is only useful if it died where it was told to. A
 *      child that exited cleanly, or that never reached its injection point,
 *      makes every assertion afterwards meaningless — the database would be
 *      showing the result of a COMPLETED request, and a test asserting "nothing
 *      was written" against a request that was never made passes for the wrong
 *      reason. `expectKilled` refuses that outcome loudly.
 *
 *   2. A DEADLINE. A probe whose injection point is never reached would
 *      otherwise hang the suite. Past the deadline the child is killed from
 *      here and reported as a HANG, which is a different failure from a crash
 *      and reads as one.
 *
 *   3. THE ENVIRONMENT. The child inherits this worker's `process.env`, which is
 *      what makes its configuration identical to the parent's — the same JWT
 *      secrets (so a token minted here authenticates there), the same
 *      `NODE_ENV=test` (so rate limiters no-op and no log file is written), the
 *      same timezone and locale pins. `MONGODB_URI` is overridden, and the child
 *      connects explicitly to the URI it is handed anyway; the four `S3_*`
 *      variables are added only for a probe that asked for the storage bridge.
 *
 *   4. THE STORAGE BRIDGE, for the document drills. A probe that passes a
 *      `storage` provider gets an IPC channel, the `S3_*` environment that makes
 *      `storageConfigured` true in the child, and a proxy installed over the
 *      child's memoised provider — so the bucket the child writes to IS the
 *      parent's double, and the parent can assert on what the crash left there.
 *      See `storageBridge.ts`.
 */
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import mongoose from 'mongoose';
import { expect } from 'vitest';
import {
  CRASH_MARKERS,
  type CrashMethod,
  type CrashRequest,
  type CrashScenario,
} from './crashContract.js';
import type { StorageProvider } from '../../src/services/storage/types.js';
import { serveStorageOverIpc } from './storageBridge.js';

/** Resolved from this module's own URL, never `process.cwd()`. */
const here = path.dirname(fileURLToPath(import.meta.url));

/**
 * How long a probe may take before it is a hang rather than a crash.
 *
 * Measured on the reference machine at ~2.5 s end to end, nearly all of it
 * `tsx` transforming the server's module graph. Thirty seconds is far too
 * coarse to fire on a loaded machine and far too tight for a probe that has
 * started waiting on something — a lock it will never get, a transaction whose
 * commit is blocked, a mongod that went away.
 */
const PROBE_DEADLINE_MS = 30_000;

/** SIGKILL's wait-status, and what Node reports as the child's signal. */
const KILL_SIGNAL = 'SIGKILL';

/**
 * The four connection variables a bridged child needs, and only a bridged child.
 *
 * They are what make `storageConfigured` true (so `requireStorage` lets the request
 * through) and what stop `getStorage()` throwing 503 before the bridge can be
 * installed over the provider it returns. The endpoint is deliberately a port
 * nothing listens on: the real `S3Client` this builds is never used, because
 * `crashChild.ts` overwrites every method on the provider before the request runs,
 * and a reachable endpoint would only hide a bridge that failed to install.
 *
 * The bounds are the config schema's own: `min(8)` on the key id, `min(16)` on the
 * secret, and all four set together or `loadConfig` normalises them back to none.
 * `S3_RPC_SECRET` is deliberately absent — the server does not declare it, only the
 * storage container reads it, and setting it here would suggest otherwise.
 */
const STORAGE_ENV = (storage: StorageProvider | undefined): Record<string, string> =>
  storage === undefined
    ? {}
    : {
        S3_ENDPOINT: 'http://127.0.0.1:1',
        S3_BUCKET: 'hvault-crash-drill',
        S3_ACCESS_KEY_ID: 'crashdrillkey',
        S3_SECRET_ACCESS_KEY: 'crash-drill-secret-key-32chars!!',
      };

export interface CrashOutcome {
  /** True when the process was terminated by SIGKILL and never exited on its own. */
  killed: boolean;
  signal: NodeJS.Signals | null;
  exitCode: number | null;
  /** True once the child announced it had armed its injection point. */
  armed: boolean;
  /** True when the request ran to completion — i.e. the probe proved nothing. */
  survived: boolean;
  output: string;
  durationMs: number;
  timedOut: boolean;
}

/**
 * Runs one crashing request against `uri` and returns how the child died.
 *
 * Never throws for a probe that behaved badly: the outcome is data, so a test
 * can assert on it (and `expectKilled` gives every caller the same assertion).
 */
export async function runCrashProbe(options: {
  uri: string;
  scenario: CrashScenario;
  path: string;
  token: string;
  method?: CrashMethod;
  body?: Record<string, unknown>;
  bodyBase64?: string;
  headers?: Record<string, string>;
  /**
   * The parent's storage double, served to the child over IPC.
   *
   * Supplying it does three things at once, and all three are needed together:
   * the child is spawned with an IPC channel, the four `S3_*` variables are put
   * into its environment (so `storageConfigured` is true and `getStorage()` does
   * not throw 503), and every storage call the child makes lands on THIS object —
   * which is how the parent gets to inspect the bucket a killed process left
   * behind. See `storageBridge.ts` for why a bridge rather than a container.
   */
  storage?: StorageProvider;
}): Promise<CrashOutcome> {
  const payload: CrashRequest = {
    uri: options.uri,
    scenario: options.scenario,
    path: options.path,
    token: options.token,
    ...(options.method === undefined ? {} : { method: options.method }),
    ...(options.body === undefined ? {} : { body: options.body }),
    ...(options.bodyBase64 === undefined ? {} : { bodyBase64: options.bodyBase64 }),
    ...(options.headers === undefined ? {} : { headers: options.headers }),
    ...(options.storage === undefined ? {} : { storageBridge: true }),
  };

  const started = Date.now();
  return new Promise<CrashOutcome>((resolve) => {
    const child = spawn(
      process.execPath,
      ['--import', 'tsx', path.join(here, 'crashChild.ts'), JSON.stringify(payload)],
      {
        cwd: path.resolve(here, '..', '..'),
        env: { ...process.env, MONGODB_URI: options.uri, ...STORAGE_ENV(options.storage) },
        // The fourth slot is the storage bridge, and it exists only when a probe
        // asked for one: the five vault scenarios spawn exactly as they always did.
        stdio:
          options.storage === undefined
            ? ['ignore', 'pipe', 'pipe']
            : ['ignore', 'pipe', 'pipe', 'ipc'],
        // Buffers and Dates cross the port unchanged. Errors deliberately do NOT:
        // v8 serialization drops own properties on built-in types, so `statusCode`
        // would vanish — `storageBridge.ts` ships a status code instead.
        ...(options.storage === undefined ? {} : { serialization: 'advanced' as const }),
      },
    );

    const stopServing =
      options.storage === undefined ? () => {} : serveStorageOverIpc(child, options.storage);

    let output = '';
    let timedOut = false;
    // RESOLVE ONCE, and `close` must be the one that wins. A reply written into a
    // channel the SIGKILL just closed raises `ERR_IPC_CHANNEL_CLOSED` on this
    // `ChildProcess`, and the `error` listener below would otherwise report a
    // correct crash as a spawn failure — a red with a message pointing at the
    // wrong thing entirely.
    let settled = false;
    const settle = (outcome: CrashOutcome): void => {
      if (settled) return;
      settled = true;
      stopServing();
      resolve(outcome);
    };
    const collect = (chunk: Buffer): void => {
      output += chunk.toString();
    };
    // Narrowed rather than asserted. Both are `'pipe'` in both stdio shapes above,
    // but the shapes are a UNION now that a bridged probe adds a fourth slot, and
    // TypeScript resolves a union `stdio` to the general `ChildProcess` whose
    // streams are nullable. A `!` here would be an unchecked claim about a value
    // the compiler stopped being able to see; this is the same claim, checked.
    const { stdout, stderr } = child;
    if (!stdout || !stderr) {
      throw new Error('the crash probe was spawned without piped stdout and stderr');
    }
    stdout.on('data', collect);
    stderr.on('data', collect);

    const deadline = setTimeout(() => {
      timedOut = true;
      child.kill(KILL_SIGNAL);
    }, PROBE_DEADLINE_MS);

    // A spawn failure (no `tsx`, no `node`, a permission error) emits `error`
    // and never `close`. Without this listener that is an uncaught exception in
    // the test worker; with it, it is an outcome `expectKilled` can describe —
    // "never armed", with the reason in the transcript.
    child.on('error', (error) => {
      // Only a failure BEFORE the child armed itself is a spawn failure; anything
      // after that is the channel dying with a process that was supposed to die.
      if (output.includes(CRASH_MARKERS.ready)) return;
      clearTimeout(deadline);
      output += `\nthe crash probe could not be spawned: ${error.message}\n`;
      settle({
        killed: false,
        signal: null,
        exitCode: null,
        armed: false,
        survived: false,
        output,
        durationMs: Date.now() - started,
        timedOut: false,
      });
    });

    child.on('close', (exitCode, signal) => {
      clearTimeout(deadline);
      settle({
        // A probe killed by the DEADLINE also arrives here with SIGKILL, so the
        // two are separated explicitly: only a self-inflicted kill counts.
        killed: signal === KILL_SIGNAL && !timedOut,
        signal,
        exitCode,
        armed: output.includes(CRASH_MARKERS.ready),
        survived: output.includes(CRASH_MARKERS.survived),
        output,
        durationMs: Date.now() - started,
        timedOut,
      });
    });
  });
}

/**
 * Aborts the transaction a killed process left open, and reports how many there
 * were.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS NECESSARY, AND WHY IT DOES NOT SOFTEN THE TEST
 * ---------------------------------------------------------------------------
 *
 * A process killed inside a transaction leaves it OPEN on the server. mongod
 * ends it on its own — `transactionLifetimeLimitSeconds`, sixty seconds by
 * default — and until then it holds write locks on every document it touched.
 * That is correct production behaviour and it is also, measured here, a
 * thirty-second hang in `tests/setup.ts`'s per-test truncation, which then fails
 * the run for a reason that has nothing to do with the code.
 *
 * So the drill does deliberately what mongod would do a minute later, and does
 * it AFTER the assertions that describe the window in between. Two things follow
 * and both are worth stating:
 *
 *   • It STRENGTHENS the claim rather than weakening it. Before the reap the
 *     rows are merely invisible (uncommitted); after it they are gone for good,
 *     because an abandoned transaction can only ever abort. A test may assert
 *     either, and this suite asserts both.
 *
 *   • It is targeted, never `killAllSessions`. Only sessions currently running a
 *     transaction are killed — the parent's own connection is doing none — so
 *     this cannot reach into the worker's own work and produce a failure that
 *     looks like a defect in the application.
 */
export async function reapOrphanedTransactions(): Promise<number> {
  const db = mongoose.connection.db;
  if (!db) return 0;
  // The `$currentOp` AGGREGATION, never the legacy `currentOp` command: measured
  // against a real replica set holding an open transaction, the command reports
  // an empty `inprog` (it lists operations, and an abandoned transaction is not
  // running one) while the stage with `idleSessions` reports it. A reaper built
  // on the command silently found nothing and the truncation still hung.
  // `Db.aggregate` on the `admin` database, not `Admin.aggregate` — the latter
  // does not exist, and `$currentOp` is a database-level stage.
  const admin = mongoose.connection.getClient().db('admin');
  const orphans = (await admin
    .aggregate([
      { $currentOp: { allUsers: true, idleSessions: true } },
      { $match: { transaction: { $exists: true } } },
    ])
    .toArray()) as { lsid?: { id: unknown; uid: unknown } }[];

  const sessions = orphans
    .map((op) => op.lsid)
    .filter((lsid): lsid is { id: unknown; uid: unknown } => lsid !== undefined);
  if (sessions.length === 0) return 0;
  await admin.command({ killSessions: sessions.map(({ id, uid }) => ({ id, uid })) });
  return sessions.length;
}

/**
 * Asserts the probe really did crash at its injection point.
 *
 * Every case in the crash suite calls this BEFORE looking at the database.
 * Without it, the most likely way for those tests to break — a byte-exact patch
 * target that a refactor renamed, so the injection never fires — would leave
 * them asserting against a request that completed normally, and several of them
 * would still pass.
 */
export function expectKilled(outcome: CrashOutcome, scenario: CrashScenario): void {
  const detail =
    `${scenario}: exit=${String(outcome.exitCode)} signal=${String(outcome.signal)} ` +
    `armed=${String(outcome.armed)} survived=${String(outcome.survived)}\n${outcome.output.slice(-2000)}`;
  expect(outcome.timedOut, `crash probe HUNG rather than crashed — ${detail}`).toBe(false);
  expect(outcome.armed, `crash probe never armed its injection point — ${detail}`).toBe(true);
  expect(
    outcome.survived,
    `crash probe SURVIVED: the request completed, so nothing below is a claim about a crash — ${detail}`,
  ).toBe(false);
  expect(outcome.killed, `crash probe did not die by ${KILL_SIGNAL} — ${detail}`).toBe(true);
}
