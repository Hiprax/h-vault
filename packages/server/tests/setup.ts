import type { MongoMemoryServer } from 'mongodb-memory-server';
import mongoose from 'mongoose';
import { beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { applyDeterminismPins, printSeedBannerOnce } from './determinism.js';
import { installEgressGuard, withEgressAllowed } from './egressGuard.js';
import { uninstallTestClock } from './clock.js';
import { applyMongoKernelCompat } from './mongoKernelCompat.js';
import { buildModelIndexes, createStandaloneMongo, setStandaloneUri } from './mongoHarness.js';
import { installRepoWriteGuard } from './tempDir.js';
import { clearLoginThrottle } from '../src/utils/loginThrottle.js';

// Vitest runs every test file in an isolated module graph but shares a single
// `process`. The test harness (Vitest's per-file error handlers,
// mongodb-memory-server's cleanup hooks) therefore registers many
// `uncaughtException`/`unhandledRejection` listeners on `process` across files,
// tripping Node's default 10-listener `MaxListenersExceededWarning`. These
// registrations are intentional and bounded by the number of test files, not a
// product leak, so lift the cap for the test process only (production keeps its
// explicit `process.setMaxListeners(20)` in `server.ts`).
process.setMaxListeners(0);

/**
 * Force `NODE_ENV=test` for the whole suite, before any application module is
 * evaluated.
 *
 * `vitest.config.ts` already pins `test.env.NODE_ENV = 'test'`, and that value
 * DOES win over the developer's root `.env` for every ordinary key. `NODE_ENV`
 * is the one exception: Vite resolves it from the loaded `.env` file as part of
 * mode handling (the "injected env (N) from ../../.env" line at startup), and
 * that resolution lands on `process.env.NODE_ENV` late enough to clobber the
 * pinned value. A developer who runs `npm test` with a root `.env` copied from
 * `.env.example` (which ships `NODE_ENV=development`) therefore boots the whole
 * server suite with `isTest === false`.
 *
 * That is not cosmetic: `authController` gates its progressive login/2FA delay
 * on `!isTest`, so with the flag wrong the delay actually sleeps (up to 5s per
 * failed attempt). The multi-attempt lockout tests fire ~28s of real sleeps and
 * blow their 30s timeouts, turning several auth suites red for a reason wholly
 * unrelated to the code under test.
 *
 * Setting it here is reliable because setup files run AFTER Vite's `.env`
 * injection but BEFORE any test file imports `config/index.js` (this file's own
 * imports never reach it), so `isTest = config.NODE_ENV === 'test'` is evaluated
 * once, correctly, and cached for the worker. It is a plain assignment, not
 * `vi.stubEnv`, because the config module reads `process.env` a single time at
 * load — a per-test stub would be reset and could not influence that read.
 */
process.env.NODE_ENV = 'test';

/**
 * Pin timezone, locale and the seed, in the harness rather than as a shell
 * prefix. Applied here for the same reason as `NODE_ENV` above: after Vite's
 * `.env` injection, before any application module can read a date, a locale or a
 * generator. See `tests/determinism.ts` for why a `TZ=UTC npm test` prefix is
 * not an option in this repository.
 */
applyDeterminismPins();

/**
 * Block outbound network access for the whole suite, and block writes into the
 * checkout. Both are installed at module scope rather than in `beforeAll` so
 * they also cover a test file's import-time code.
 */
installEgressGuard();
installRepoWriteGuard();

/**
 * Name the seed beside the first failure in each file, so any run is
 * reproducible. Registered as a hook rather than as a reporter: a reporter is
 * configuration a contributor can drop without noticing, while this rides along
 * with the setup file every test file already loads.
 */
beforeEach((ctx) => {
  ctx.onTestFailed(() => {
    printSeedBannerOnce();
  });
});

/**
 * SERVER-121912 — let mongod actually start on Linux kernels >= 6.19 (Ubuntu 26.04).
 *
 * MongoDB 8.0 moved TCMalloc to per-CPU caches, and that TCMalloc drives them with
 * restartable sequences in a way that violates the rseq ABI as it changed in that
 * kernel: mongod's startup check aborts. It applies to the production stack
 * (docker-compose.yml pins mongo:8.0) AND here — `mongodb-memory-server` downloads
 * and spawns a REAL mongod, defaulting to the 8.x line — so on a modern host both
 * `npm test` and `npm run test:e2e`, which the project's pre-completion checklist
 * mandates, would die at mongod launch for a reason that looks nothing like the
 * change under test.
 *
 * Handing rseq back to glibc deactivates TCMalloc's per-CPU cache and it starts. The
 * spawned mongod inherits `process.env`, so setting it here is enough. It MERGES
 * rather than overwrites — see mongoKernelCompat.ts for why `??=` was not enough.
 */
applyMongoKernelCompat();

let mongoServer: MongoMemoryServer;

beforeAll(async () => {
  // `withEgressAllowed` covers exactly one thing: mongodb-memory-server fetching
  // the mongod binary on a machine that has not cached it yet. Blocking that
  // would leave a fresh clone unable to run the suite at all.
  // `createStandaloneMongo` hands mms a port from this worker's own band so two
  // parallel forks cannot race for the same one — see tests/mongoHarness.ts.
  mongoServer = await withEgressAllowed(createStandaloneMongo);
  const uri = mongoServer.getUri();
  process.env['MONGODB_URI'] = uri;
  // Registered so a block that borrows the connection for a replica set knows
  // the URI to hand it back to.
  setStandaloneUri(uri);
  await mongoose.connect(uri);

  // Wait for every registered model's indexes to actually exist before any test
  // runs. Mongoose's `autoIndex` kicks the builds off ASYNCHRONOUSLY once the
  // connection opens, so without this a test can execute against a collection
  // whose unique index does not exist yet — and several behaviors under test are
  // enforced BY those indexes, not by application code:
  //
  //   * `acquireJobLock` relies entirely on the E11000 from the unique `jobName`
  //     index. Its filter deliberately does not match a live lock, so the upsert
  //     falls through to an INSERT; with no unique index that insert SUCCEEDS,
  //     creating a second lock document and handing a token to a caller while
  //     another holder is still live (mutual exclusion silently gone).
  //   * Folder's `(userId, searchHash)` unique partial index is what turns a
  //     duplicate folder name into a 409.
  //
  // The race only loses under CPU contention (e.g. the three workspaces running
  // their suites at once), which made it an intermittent failure rather than a
  // reproducible one. Models register when the test file imports them, and hooks
  // run after that module evaluation, so `mongoose.models` is populated here.
  //
  // createIndexes() rather than init(): init() memoizes on `Model.$init`, so it
  // resolves instantly — building nothing — if a file later points mongoose at a
  // DIFFERENT database (as the MongoMemoryReplSet-backed rotation test does).
  // createIndexes() is not memoized and is a cheap no-op when the indexes already
  // exist. It is the same call `runMigrations` uses in production for the same
  // reason. Shared with the replica-set helper, which needs it for the same
  // reason on the connection it swaps in.
  await buildModelIndexes();
});

afterEach(async () => {
  const collections = await mongoose.connection.db!.collections();
  for (const collection of collections) {
    await collection.deleteMany({});
  }

  // Truncating collections resets the DURABLE state; this resets the one piece of
  // PROCESS-LOCAL state a test can leave behind for the next one in its file.
  //
  // `loginThrottle` keeps a module-level `Map` of failed attempts per email,
  // deliberately outside the database (a non-existent email has no row to count
  // against, and the progressive delay must be symmetric or its timing leaks
  // account existence). Fourteen files drive failed logins and only two clear it,
  // which is safe today only because `isTest` skips the actual sleep — so the
  // count is currently unobservable rather than absent. The moment a test asserts
  // on `peekLoginAttempts` outside those two files, or the delay becomes
  // observable, the result would depend on which test ran first. Cleared here so
  // it cannot.
  //
  // Imported statically because `loginThrottle` imports nothing at all: it cannot
  // pull `config/index.js` into this file's graph ahead of the `NODE_ENV`
  // assignment above, which is the hazard that keeps every other production
  // module out of this file.
  clearLoginThrottle();
});

/**
 * The safety net under the test clock.
 *
 * `tests/clock.ts` restores in every place it is used — `withTestClock`'s
 * `finally`, and a describe-scoped `afterEach` beside each bare
 * `installTestClock`. This makes that structural rather than a matter of
 * per-file discipline: a file that installs a fake clock and fails before its own
 * cleanup would otherwise leave the whole WORKER frozen, and every later file in
 * it would then run against an instant that stopped inside a test it has never
 * heard of — an order-dependent failure produced by the very mechanism installed
 * to remove one, and one that `test:flake` would surface as a mystery.
 *
 * `vi.useRealTimers()` is a no-op when no fake clock is installed (asserted in
 * `packages/server/tests/clock.test.ts`), and `sequence.hooks: 'stack'` runs this
 * hook LAST — after every describe-scoped `afterEach` — so a suite that installs
 * its clock in a `beforeEach` is unaffected.
 */
afterEach(() => {
  uninstallTestClock();
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});
