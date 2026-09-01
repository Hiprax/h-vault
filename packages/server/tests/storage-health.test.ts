import { describe, it, expect, vi, beforeEach } from 'vitest';

/**
 * `utils/storageHealth.ts`: the one-shot boot preflight and the in-process gauge
 * `/api/v1/metrics` reports.
 *
 * The four behaviours pinned here are the ones an operator's diagnosis depends on,
 * and each of them is a decision that could plausibly have gone the other way:
 *
 *   * the gauge answers without touching the network, so reading it can never be
 *     the thing that hangs;
 *   * a probe that FAILS is recorded and logged rather than thrown, because
 *     `server.ts` starts it without awaiting and a rejection there becomes an
 *     unhandled rejection the logger's crash coordinator turns into `exit(1)`;
 *   * a probe that SUCCEEDS is recorded too, so `lastProbeOk` distinguishes
 *     "reachable" from "never asked";
 *   * an unconfigured deployment is not probed AT ALL, and its gauge keeps `null`
 *     rather than gaining a `false` for a feature that is merely switched off.
 *
 * Every assertion below is written to be order-independent, because this suite runs
 * with `sequence.shuffle` on: nothing here asserts the module's PRISTINE state (the
 * never-probed gauge is pinned from `health.test.ts`, a different file and therefore
 * a different module registry, through `/api/v1/metrics`). Where a test needs to
 * prove something did not change, it reads the gauge before and after itself.
 */

const { loggerError, loggerInfo, loggerWarn, loggerDebug } = vi.hoisted(() => ({
  loggerError: vi.fn(),
  loggerInfo: vi.fn(),
  loggerWarn: vi.fn(),
  loggerDebug: vi.fn(),
}));

vi.mock('@hiprax/logger', async (importOriginal) => {
  const original = await importOriginal<typeof import('@hiprax/logger')>();
  return {
    ...original,
    createLogger: () => ({
      error: loggerError,
      info: loggerInfo,
      warn: loggerWarn,
      debug: loggerDebug,
    }),
  };
});

/**
 * `storageConfigured` is an `export const` computed once at config load, so a test
 * cannot assign to it. It is republished here as a GETTER over a hoisted flag,
 * which is what lets one file exercise both the configured and the unconfigured
 * deployment: Vite compiles `import { storageConfigured }` into a property read at
 * each use site, so the getter is consulted on every access rather than captured
 * once at import.
 *
 * The whole config module is spread through untouched, deliberately. Re-mocking
 * `config` with `vi.resetModules()` + `vi.doMock` re-evaluates `models/User.ts` and
 * throws `OverwriteModelError`; this replaces one binding without re-evaluating
 * anything.
 */
const { deployment } = vi.hoisted(() => ({ deployment: { storageConfigured: true } }));

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  const mocked: Record<string, unknown> = { ...actual };
  Object.defineProperty(mocked, 'storageConfigured', {
    get: () => deployment.storageConfigured,
    enumerable: true,
    configurable: true,
  });
  return mocked;
});

const { headBucket, storageAccess } = vi.hoisted(() => ({
  headBucket: vi.fn<() => Promise<void>>(),
  storageAccess: { count: 0 },
}));

/**
 * Counts every attempt to OBTAIN a client as well as every probe, because the two
 * failures look different: a preflight that skipped its guard would call
 * `getStorage()` (which throws 503 when unconfigured) before it ever reached
 * `headBucket`, and a test asserting only on `headBucket` would miss it.
 */
vi.mock('../src/services/storage/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/services/storage/index.js')>();
  return {
    ...actual,
    getStorage: () => {
      storageAccess.count += 1;
      return { headBucket } as unknown as ReturnType<typeof actual.getStorage>;
    },
  };
});

import { getStorageHealth, runStoragePreflight } from '../src/utils/storageHealth.js';

beforeEach(() => {
  vi.clearAllMocks();
  storageAccess.count = 0;
  deployment.storageConfigured = true;
  headBucket.mockResolvedValue(undefined);
});

describe('storage health gauge', () => {
  it('reports whether storage is configured without contacting the engine', () => {
    const gauge = getStorageHealth();

    expect(gauge.configured).toBe(true);
    // The negative that matters: reading the gauge is a memory read. If it ever
    // probed, `/api/v1/metrics` would hang for as long as an unreachable bucket
    // takes to time out — which is exactly when an operator is reading it.
    expect(storageAccess.count).toBe(0);
    expect(headBucket).not.toHaveBeenCalled();
  });

  it('follows the unconfigured flag rather than a value captured at import', () => {
    deployment.storageConfigured = false;

    expect(getStorageHealth().configured).toBe(false);
  });
});

describe('runStoragePreflight', () => {
  it('records a successful probe as the last verdict and says so once', async () => {
    const before = Date.now();

    await expect(runStoragePreflight()).resolves.toBe(true);

    const gauge = getStorageHealth();
    expect(gauge.configured).toBe(true);
    expect(gauge.lastProbeOk).toBe(true);
    expect(gauge.lastProbeAt).not.toBeNull();
    expect(Date.parse(gauge.lastProbeAt as string)).toBeGreaterThanOrEqual(before);
    // One-shot: the preflight asks once per call and does not retry around the
    // SDK's own three attempts.
    expect(headBucket).toHaveBeenCalledTimes(1);
    // Nothing loud on the happy path — an error line here would train an operator
    // to ignore the one that matters.
    expect(loggerError).not.toHaveBeenCalled();
  });

  it('records a failed probe, names the reason at error level, and never rejects', async () => {
    headBucket.mockRejectedValue(new Error('connect ECONNREFUSED 10.0.0.9:3900'));

    // `resolves`, not `rejects`, and that is the assertion: `server.ts` starts this
    // without awaiting, so a rejection would surface as an unhandled rejection and
    // the logger's crash coordinator would exit the process — killing a server
    // whose vault is working perfectly because an OPTIONAL feature's bucket is down.
    await expect(runStoragePreflight()).resolves.toBe(false);

    const gauge = getStorageHealth();
    expect(gauge.lastProbeOk).toBe(false);
    expect(gauge.lastProbeAt).not.toBeNull();
    expect(loggerError).toHaveBeenCalledTimes(1);
    const message = String(loggerError.mock.calls[0]?.[0]);
    expect(message).toContain('preflight FAILED');
    // The underlying reason must survive into the log line: in production every
    // 5xx body is redacted to its status text, so this is the only place it exists.
    expect(message).toContain('connect ECONNREFUSED 10.0.0.9:3900');
  });

  it('reports a non-Error rejection without printing "undefined" at an operator', async () => {
    // Nothing obliges a rejected promise to carry an `Error`, and the one line an
    // operator gets for this failure must not be the one that loses the reason.
    headBucket.mockRejectedValue('the engine hung up');

    await expect(runStoragePreflight()).resolves.toBe(false);

    expect(getStorageHealth().lastProbeOk).toBe(false);
    expect(String(loggerError.mock.calls[0]?.[0])).toContain('Unknown error');
  });

  it('does not probe an unconfigured deployment, and leaves the recorded verdict alone', async () => {
    // Establish a known verdict first, so "unchanged" is observable rather than
    // vacuous however the shuffled suite ordered the tests above.
    await runStoragePreflight();
    const recorded = getStorageHealth();
    expect(recorded.lastProbeOk).toBe(true);

    vi.clearAllMocks();
    storageAccess.count = 0;
    deployment.storageConfigured = false;

    await expect(runStoragePreflight()).resolves.toBe(false);

    // The three negatives: no client was built, no request was made, and no verdict
    // was overwritten. A `false` here would tell an operator their bucket is broken
    // when in fact they never configured one.
    expect(storageAccess.count).toBe(0);
    expect(headBucket).not.toHaveBeenCalled();
    expect(loggerError).not.toHaveBeenCalled();
    const gauge = getStorageHealth();
    expect(gauge.configured).toBe(false);
    expect(gauge.lastProbeOk).toBe(true);
    expect(gauge.lastProbeAt).toBe(recorded.lastProbeAt);
  });
});
