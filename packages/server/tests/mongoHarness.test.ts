/**
 * The port-band arithmetic that keeps two parallel forks from racing for the same
 * mongod port, and the connection-return contract that keeps a replica-set block
 * from breaking whichever block the shuffle puts after it.
 *
 * The band logic is asserted directly because it is real arithmetic with a real
 * failure mode: a version that returned the same port for every worker would
 * reintroduce the `Port "45543" already in use` race while looking fixed, and a
 * suite failing that way blames an unrelated test file.
 */
import mongoose from 'mongoose';
import { afterAll, describe, expect, it } from 'vitest';
import { supportsTransactions } from '../src/utils/transactionSupport.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { sampleVaultItem } from './helpers.js';
import {
  EPHEMERAL_PORT_FLOOR,
  MAX_WORKER_BANDS,
  PORTS_PER_WORKER,
  PORT_BAND_START,
  getStandaloneUri,
  isPortCollision,
  preferredPort,
  useReplicaSetConnection,
  withPortRetry,
  workerBandIndex,
} from './mongoHarness.js';

describe('mongoHarness — worker band selection', () => {
  it('maps each pool slot to a distinct band, so two forks never probe one port', () => {
    // `VITEST_POOL_ID` is 1-based; band indexes are 0-based. The parent pid is
    // pinned to 0 so these assertions describe the SLOT mapping rather than this
    // machine's process tree.
    expect(workerBandIndex({ VITEST_POOL_ID: '1' }, 0)).toBe(0);
    expect(workerBandIndex({ VITEST_POOL_ID: '2' }, 0)).toBe(1);
    expect(workerBandIndex({ VITEST_POOL_ID: '7' }, 0)).toBe(6);

    const bands = new Set(
      ['1', '2', '3', '4', '5', '6', '7', '8'].map((id) =>
        workerBandIndex({ VITEST_POOL_ID: id }, 0),
      ),
    );
    expect(bands.size).toBe(8);
  });

  it('shifts the whole assignment per RUN, so two concurrent vitest runs do not collide', () => {
    // Same slot, different parent process: the bands must differ, or two
    // simultaneous runs (which this repo supports — see `VITEST_COVERAGE_DIR` in
    // vitest.config.ts) reproduce exactly the port collision the bands remove.
    expect(workerBandIndex({ VITEST_POOL_ID: '1' }, 100)).not.toBe(
      workerBandIndex({ VITEST_POOL_ID: '1' }, 101),
    );
    // Within ONE run the parent is shared, so distinct slots still land on
    // distinct bands — the property that removes the intra-run race.
    const sameRun = new Set(
      ['1', '2', '3', '4'].map((id) => workerBandIndex({ VITEST_POOL_ID: id }, 4242)),
    );
    expect(sameRun.size).toBe(4);
  });

  it('falls back to the worker id, then to band 0, without ever returning NaN', () => {
    // `VITEST_WORKER_ID` counts FILES and grows without bound, so it is only a
    // fallback: modulo the band count it still spreads.
    expect(workerBandIndex({ VITEST_WORKER_ID: '3' }, 0)).toBe(2);
    expect(workerBandIndex({}, 0)).toBe(0);
    expect(workerBandIndex({ VITEST_POOL_ID: 'not-a-number' }, 0)).toBe(0);
    expect(workerBandIndex({ VITEST_POOL_ID: '0' }, 0)).toBe(0);
    expect(Number.isInteger(workerBandIndex({ VITEST_POOL_ID: '-4' }, 0))).toBe(true);
    expect(workerBandIndex({ VITEST_POOL_ID: '1' }, Number.NaN)).toBe(0);
  });

  it('draws every candidate from this worker’s own band', () => {
    const band = workerBandIndex();
    const low = PORT_BAND_START + band * PORTS_PER_WORKER;
    const high = low + PORTS_PER_WORKER - 1;

    const seen = new Set<number>();
    for (let attempt = 0; attempt < PORTS_PER_WORKER; attempt += 1) {
      const port = preferredPort(attempt);
      expect(port).toBeGreaterThanOrEqual(low);
      expect(port).toBeLessThanOrEqual(high);
      seen.add(port);
    }
    // Successive candidates must actually move: retrying the same port five times
    // would be a retry loop that cannot win a port race.
    expect(seen.size).toBeGreaterThan(1);
  });

  it('keeps the band clear of the OS ephemeral range and of this project’s own ports', () => {
    // Linux hands out 32768–60999 for client sockets and Windows 49152+, which is
    // where the observed collision came from. 5000 (API), 5173 (Vite), 8080 (stack
    // ingress) and 27017 (the E2E mongod) are this repo's own.
    // Derived from the real constants, never from literals: a test that hardcoded
    // the band count or the floor would stay green if either moved, and the whole
    // point of the band is that it sits BELOW the range the OS hands out.
    const highest = PORT_BAND_START + MAX_WORKER_BANDS * PORTS_PER_WORKER;
    expect(PORT_BAND_START).toBeGreaterThan(27017);
    expect(highest).toBeLessThanOrEqual(EPHEMERAL_PORT_FLOOR);
    expect(EPHEMERAL_PORT_FLOOR).toBe(32_768);
    // And the pool is worth having: a single band would make every worker share
    // one range, which is the collision this arithmetic exists to remove.
    expect(MAX_WORKER_BANDS).toBeGreaterThan(1);
  });
});

describe('mongoHarness — the retry policy', () => {
  it('classifies a lost bind race and nothing else as a port collision', () => {
    expect(isPortCollision(new Error('Port "45543" already in use'))).toBe(true);
    expect(isPortCollision(new Error('listen EADDRINUSE: address already in use'))).toBe(true);
    // A missing binary or a kernel that refuses to start mongod must NOT be
    // retried: five slow identical failures hide the one clear message.
    expect(isPortCollision(new Error('spawn ENOENT: mongod not found'))).toBe(false);
    expect(isPortCollision(new Error('Instance failed to start within 10000ms'))).toBe(false);
    expect(isPortCollision('not an error object')).toBe(false);
  });

  it('retries a collision on a DIFFERENT port and succeeds', async () => {
    const tried: number[] = [];
    const result = await withPortRetry((port) => {
      tried.push(port);
      if (tried.length < 3)
        return Promise.reject(new Error(`Port "${String(port)}" already in use`));
      return Promise.resolve('started');
    });

    expect(result).toBe('started');
    expect(tried).toHaveLength(3);
    // A retry loop that handed back the same port could never win the race.
    expect(new Set(tried).size).toBe(3);
  });

  it('rethrows a non-collision error on the FIRST attempt', async () => {
    let attempts = 0;
    await expect(
      withPortRetry(() => {
        attempts += 1;
        return Promise.reject(new Error('spawn ENOENT'));
      }),
    ).rejects.toThrow('spawn ENOENT');
    expect(attempts).toBe(1);
  });

  it('gives up with a message naming the exhausted band', async () => {
    await expect(
      withPortRetry((port) => Promise.reject(new Error(`Port "${String(port)}" already in use`))),
    ).rejects.toThrow(/candidate ports in band \d+\+ were all in use/);
  });
});

describe('mongoHarness — the standalone connection contract', () => {
  it('knows the URI setup.ts is holding, so a borrowed connection can be returned', () => {
    const uri = getStandaloneUri();
    expect(uri).toMatch(/^mongodb:\/\//);
    expect(mongoose.connection.readyState).toBe(1);
  });
});

/**
 * The borrow/return lifecycle itself, asserted rather than assumed.
 *
 * This is the phase's central fix and it needs a test that can fail. The `afterAll`
 * below is registered BEFORE `useReplicaSetConnection()`, and Vitest runs `after*`
 * hooks in reverse registration order, so it runs AFTER the helper's teardown and
 * therefore observes whatever state the helper left behind. Delete the reconnect in
 * `useReplicaSetConnection`'s `afterAll` and this block goes red — which is exactly
 * what every later `describe` in the five real files would experience.
 */
describe('mongoHarness — a borrowed connection is handed back', () => {
  afterAll(async () => {
    // 1. Connected at all (`readyState === 1`), not merely non-null.
    expect(mongoose.connection.readyState).toBe(1);
    // 2. Pointed back at the STANDALONE server, not still at the replica set —
    //    a restore that reconnected to the wrong URI would satisfy (1) alone.
    expect(supportsTransactions(mongoose.connection)).toBe(false);
    // 3. Usable, not just open: a write has to reach a live mongod. This is what
    //    `setup.ts`'s afterEach truncation and every later block actually need.
    const created = await VaultItem.create({
      ...sampleVaultItem(),
      userId: new mongoose.Types.ObjectId(),
    });
    expect(await VaultItem.findById(created._id).lean()).not.toBeNull();
    await VaultItem.deleteOne({ _id: created._id });
  });

  useReplicaSetConnection({ timeoutMs: 120_000 });

  it('runs against the replica set while the block is live', () => {
    // The precondition for the afterAll above to mean anything: the connection
    // really was swapped, so the restore is doing work rather than observing a
    // connection that never moved.
    expect(supportsTransactions(mongoose.connection)).toBe(true);
    expect(mongoose.connection.readyState).toBe(1);
  });
});
