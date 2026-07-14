import { MongoMemoryServer } from 'mongodb-memory-server';
import mongoose from 'mongoose';
import { beforeAll, afterAll, afterEach } from 'vitest';
import { applyMongoKernelCompat } from './mongoKernelCompat.js';

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
  mongoServer = await MongoMemoryServer.create();
  const uri = mongoServer.getUri();
  process.env['MONGODB_URI'] = uri;
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
  // reason.
  await Promise.all(Object.values(mongoose.models).map((model) => model.createIndexes()));
});

afterEach(async () => {
  const collections = await mongoose.connection.db!.collections();
  for (const collection of collections) {
    await collection.deleteMany({});
  }
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});
