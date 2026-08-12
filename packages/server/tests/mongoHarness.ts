/**
 * Ownership of the suite's mongod instances and of the process-wide mongoose
 * connection.
 *
 * Two defects live here, and both are parallelism/ordering defects rather than
 * bugs in any single test:
 *
 * ── 1. The borrowed connection ──────────────────────────────────────────────
 *
 * Five `describe` blocks need a REPLICA SET, because `supportsTransactions()` is
 * false against a standalone server and the transactional branches of
 * `refresh`, `changePassword`, `cascadeDeleteUser`, `importVault` and
 * `bulkReEncrypt` are unreachable without one. Each of them used to open with
 * `await mongoose.disconnect()`, stand up a `MongoMemoryReplSet`, and
 * `mongoose.connect(replSet.getUri())` — on the process-wide mongoose singleton
 * that `tests/setup.ts` connected to a standalone server — and then close in an
 * `afterAll` that disconnected and stopped the replica set WITHOUT reconnecting.
 *
 * That works only if the swapping block is the last thing in its file, which is
 * why each of the five carried a comment saying so. It is a declared,
 * load-bearing dependence on declaration order, and `sequence.shuffle` reorders
 * blocks WITHIN a file: as soon as a swapping block runs early, every later
 * block in that file talks to a closed client (`MongoNotConnectedError`) and
 * `setup.ts`'s `afterEach` dereferences a `connection.db` that is gone.
 *
 * {@link useReplicaSetConnection} is the fix: the block still borrows the
 * connection, but the borrow is a lifecycle with a matching RETURN — its
 * `afterAll` reconnects to the standalone URI the harness is holding, so the
 * suite is in exactly the state the next block expects, wherever the shuffle
 * puts it.
 *
 * ── 2. The mongod port race ─────────────────────────────────────────────────
 *
 * Vitest runs test files in parallel forks, each creating its own mongod. Left
 * to itself, `mongodb-memory-server` asks `getFreePort()` for a port, and on the
 * FIRST attempt only it honours a preferred port; every later attempt falls back
 * to `listen(0)`, i.e. an OS-assigned ephemeral port. Its ports cache is
 * per-process, so it cannot see the port a sibling fork just took: two forks
 * probe, both see the port free, both hand it to mongod, and the loser dies with
 * `Port "45543" already in use` — taking an unrelated test file down with it.
 *
 * {@link createStandaloneMongo} and {@link createReplicaSet} therefore hand mms a
 * PREFERRED port drawn from a band that belongs to this worker alone
 * ({@link preferredPort}), so two concurrent forks never probe the same number,
 * and retry on a fresh candidate if the residual check-then-bind race is still
 * lost. Nothing here pins the suite to one worker: single-worker mode hides
 * shared state rather than fixing it (Forbidden Action 7).
 */
import { MongoMemoryReplSet, MongoMemoryServer } from 'mongodb-memory-server';
import mongoose from 'mongoose';
import { afterAll, beforeAll } from 'vitest';
import { withEgressAllowed } from './egressGuard.js';

/**
 * First port of the band pool.
 *
 * Chosen BELOW Linux's default ephemeral range (`32768`–`60999`) and far below
 * Windows' (`49152`+), so a harness mongod cannot collide with an OS-assigned
 * client socket — which is the collision class that produced the observed
 * failure. It is also clear of every port this project itself binds (5000 API,
 * 5173 Vite, 8080 stack ingress, 27017 the E2E mongod).
 */
export const PORT_BAND_START = 28_000;

/** Ports reserved per worker. Two mongods per file at once is the realistic peak. */
export const PORTS_PER_WORKER = 64;

/**
 * How many disjoint bands fit between {@link PORT_BAND_START} and the bottom of
 * Linux's ephemeral range (32768). Bands beyond this wrap around; retry then
 * covers the overlap.
 *
 * DERIVED rather than written down, because a hardcoded ceiling is wrong in both
 * directions: too high and a band runs into the ephemeral range, which is the
 * collision class the bands exist to remove; too low and two worker slots more
 * than the ceiling apart share a band, silently reintroducing the intra-run race
 * on a host with many cores. The literal it replaces was 48 against a range that
 * fits 74.
 *
 * Exported so `mongoHarness.test.ts` can assert the ceiling against the real
 * constant: a test that hardcoded a number would stay green if the band start
 * moved.
 */
export const EPHEMERAL_PORT_FLOOR = 32_768;
export const MAX_WORKER_BANDS = Math.floor(
  (EPHEMERAL_PORT_FLOOR - PORT_BAND_START) / PORTS_PER_WORKER,
);

/** Attempts before giving up and letting mms choose freely. */
const PORT_ATTEMPTS = 5;

/** Rotates within this worker's band so two instances in one file differ. */
let bandCursor = 0;

/**
 * This worker's band index.
 *
 * `VITEST_POOL_ID` is the pool SLOT (1..maxWorkers) and is what makes bands
 * disjoint between concurrently-running files. `VITEST_WORKER_ID` counts files
 * and grows without bound, so it is only a fallback — modulo the band count it
 * still spreads, it just no longer guarantees disjointness.
 */
export function workerBandIndex(
  env: NodeJS.ProcessEnv = process.env,
  parentPid: number = process.ppid,
): number {
  const raw = env['VITEST_POOL_ID'] ?? env['VITEST_WORKER_ID'] ?? '1';
  const parsed = Number.parseInt(raw, 10);
  const slot = Number.isInteger(parsed) && parsed > 0 ? parsed - 1 : 0;
  // The parent pid shifts the whole band assignment per VITEST RUN.
  //
  // Within one run every worker shares a parent, so distinct pool slots land on
  // distinct bands — that is a GUARANTEE (the shift is constant, so the mapping
  // stays injective) and it is the property that removes the observed race,
  // because `VITEST_POOL_ID` is a slot in 1..maxWorkers and only one worker holds
  // a slot at a time.
  //
  // Across two CONCURRENT runs — which this repo explicitly supports, see
  // `VITEST_COVERAGE_DIR` in vitest.config.ts — the shift makes a collision
  // UNLIKELY rather than impossible: two runs whose parent pids happen to be
  // congruent modulo the band count land on the same assignment. That residual
  // case degrades to the pre-existing behaviour (mms retries on an OS-assigned
  // port) rather than to a failure, so it is stated honestly here instead of
  // being claimed away.
  const runOffset = Number.isInteger(parentPid) ? Math.abs(parentPid) : 0;
  return (slot + runOffset) % MAX_WORKER_BANDS;
}

/**
 * The next candidate port for this worker. Exported for its own test: a band
 * calculation that quietly returned the same port for every worker would
 * reintroduce the race while looking fixed.
 */
export function preferredPort(attempt: number): number {
  const offset = (bandCursor++ + attempt) % PORTS_PER_WORKER;
  return PORT_BAND_START + workerBandIndex() * PORTS_PER_WORKER + offset;
}

/**
 * mms surfaces a lost bind race as a stdout error naming the port.
 *
 * Exported for its own test: without one, deleting the `if (!isPortCollision(...))
 * throw` guard below — which turns a single clear "mongod binary is missing"
 * failure into five slow identical ones — would break nothing.
 */
export function isPortCollision(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /already in use|EADDRINUSE|address already in use/i.test(message);
}

export async function withPortRetry<T>(create: (port: number) => Promise<T>): Promise<T> {
  let lastError: unknown;

  for (let attempt = 0; attempt < PORT_ATTEMPTS; attempt += 1) {
    try {
      return await create(preferredPort(attempt));
    } catch (error) {
      // Only a port collision is retried. Retrying anything else (a missing
      // binary, a kernel that refuses to start mongod) would turn one clear
      // failure into five slow identical ones.
      if (!isPortCollision(error)) throw error;
      lastError = error;
    }
  }

  throw new Error(
    `Could not start mongod: ${String(PORT_ATTEMPTS)} candidate ports in band ` +
      `${String(PORT_BAND_START + workerBandIndex() * PORTS_PER_WORKER)}+ were all in use. ` +
      `Last error: ${lastError instanceof Error ? lastError.message : String(lastError)}`,
  );
}

/** The standalone mongod every test file gets by default. */
export async function createStandaloneMongo(): Promise<MongoMemoryServer> {
  return withPortRetry((port) => MongoMemoryServer.create({ instance: { port } }));
}

/**
 * A single-node replica set: the only topology where `supportsTransactions()` is
 * true and `session.withTransaction(...)` actually runs.
 *
 * Not exported: {@link useReplicaSetConnection} is the only legitimate caller, and
 * a block that stood one up itself would be back to owning a connection lifecycle
 * by hand. The `withEgressAllowed` wrapper covers the case where THIS is the first
 * mongod of the run (a lazier `setup.ts`, or a file that only uses the helper), so
 * the binary can still be provisioned on a machine that has not cached it.
 */
async function createReplicaSet(): Promise<MongoMemoryReplSet> {
  return withEgressAllowed(() =>
    withPortRetry((port) =>
      MongoMemoryReplSet.create({
        replSet: { count: 1, storageEngine: 'wiredTiger' },
        instanceOpts: [{ port }],
      }),
    ),
  );
}

/**
 * The URI of the standalone server `tests/setup.ts` owns, so a block that
 * borrows the connection knows what to return it to.
 */
let standaloneUri: string | undefined;

/** Called once by `tests/setup.ts` after it starts its server. */
export function setStandaloneUri(uri: string): void {
  standaloneUri = uri;
}

export function getStandaloneUri(): string {
  if (standaloneUri === undefined) {
    throw new Error(
      'The standalone mongod URI is not registered. tests/setup.ts must call ' +
        'setStandaloneUri() in its beforeAll before any block borrows the connection.',
    );
  }
  return standaloneUri;
}

/**
 * Builds every registered model's indexes on the CURRENT connection.
 *
 * `createIndexes()` rather than `init()`: `init()` memoizes on `Model.$init`, so
 * after a connection swap it resolves instantly having built nothing on the new
 * database. Several behaviours under test are enforced BY these indexes and not
 * by application code — `acquireJobLock`'s mutual exclusion is the unique
 * `jobName` index, and the duplicate-folder 409 is the `(userId, searchHash)`
 * partial index — so a block running against an index-less database asserts the
 * wrong thing rather than failing.
 */
export async function buildModelIndexes(): Promise<void> {
  await Promise.all(Object.values(mongoose.models).map((model) => model.createIndexes()));
}

/**
 * Points the process-wide mongoose singleton at a fresh single-node replica set
 * for the enclosing `describe`, and puts it back afterwards.
 *
 * Call it as the first statement of the block. The hooks it registers run before
 * any the block adds afterwards, so a `beforeAll` that asserts
 * `supportsTransactions(...)` — worth keeping, since it is the difference
 * between testing the transactional branch and silently testing the fallback —
 * still sees the swapped connection.
 *
 * The `afterAll` reconnects to {@link getStandaloneUri} unconditionally, even
 * when this block is the last in its file. Making the restore conditional on
 * "is anything left to run" is not possible from inside a hook, and a restore
 * that only happens sometimes is the defect this function exists to remove.
 */
export function useReplicaSetConnection(options: { timeoutMs?: number } = {}): void {
  // Each call site passes the budget it carried before this helper existed
  // (120 s / 90 s / 60 s), so no block silently got a looser one. The default is
  // the largest of them because a single hook can now contain up to
  // `PORT_ATTEMPTS` replica-set starts, and the `afterAll` does strictly more work
  // than the hand-rolled version it replaced (stop, then reconnect).
  const timeoutMs = options.timeoutMs ?? 120_000;
  let replSet: MongoMemoryReplSet | undefined;

  beforeAll(async () => {
    // Keep the standalone server RUNNING (setup.ts owns its lifecycle and stops
    // it in its own afterAll); only the client connection moves.
    if (mongoose.connection.readyState !== 0) {
      await mongoose.disconnect();
    }
    replSet = await createReplicaSet();
    await mongoose.connect(replSet.getUri());
    await buildModelIndexes();
  }, timeoutMs);

  afterAll(async () => {
    try {
      if (mongoose.connection.readyState !== 0) {
        // Swallowed deliberately, and ONLY here: if the disconnect fails the
        // connection is still open against the replica-set URI, and mongoose
        // rejects `connect()` on an active connection with a different string —
        // so an unhandled failure here would replace the real error with a
        // confusing one AND skip the restore. The `readyState` re-check in the
        // `finally` is what decides whether the restore is safe.
        await mongoose.disconnect().catch(() => undefined);
      }
      if (replSet) {
        await replSet.stop();
        replSet = undefined;
      }
    } finally {
      // Return what was borrowed. Without this the next block in the file — and
      // `setup.ts`'s own `afterEach` truncation — runs against a closed client.
      // In a `finally` so a failed stop still restores the connection rather
      // than cascading one teardown error into every remaining test.
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(getStandaloneUri());
      }
    }
  }, timeoutMs);
}
