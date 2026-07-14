import type net from 'node:net';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  createGracefulShutdown,
  type GracefulShutdownDeps,
} from '../src/utils/gracefulShutdown.js';

/**
 * Phase 5 / T11 — `gracefulShutdown` must be re-entrancy safe.
 *
 * `server.ts` is the process entry point and is coverage-excluded, so the
 * shutdown sequence was extracted into a testable factory. These tests drive
 * the factory directly with injected dependencies (mock logger/server/timers
 * via fake timers) and assert: a double signal runs the sequence exactly once,
 * no stray force-shutdown timer fires `exit(1)` after a clean `exit(0)`, and the
 * job-drain / timeout / error branches behave correctly.
 */

/** Flush the microtask queue without advancing fake timers. */
const flushMicrotasks = async (): Promise<void> => {
  for (let i = 0; i < 20; i++) {
    await Promise.resolve();
  }
};

function makeSocket(): net.Socket {
  return { destroy: vi.fn() } as unknown as net.Socket;
}

interface Harness {
  shutdown: (signal: string) => void;
  logger: { info: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn> };
  serverClose: ReturnType<typeof vi.fn>;
  stop: ReturnType<typeof vi.fn>;
  closeRateLimitStore: ReturnType<typeof vi.fn>;
  closeDatabaseConnection: ReturnType<typeof vi.fn>;
  exit: ReturnType<typeof vi.fn>;
  activeConnections: Set<net.Socket>;
  /** Invoke the callback passed to `server.close`, if it was captured. */
  triggerClose: () => void;
  callServerCloseCallback: boolean;
}

function buildHarness(
  overrides: Partial<GracefulShutdownDeps> & { callServerCloseCallback?: boolean } = {},
): Harness {
  const logger = { info: vi.fn(), warn: vi.fn() };
  const stop = vi.fn();
  const exit = vi.fn();
  const closeRateLimitStore = overrides.closeRateLimitStore ?? vi.fn().mockResolvedValue(undefined);
  const closeDatabaseConnection =
    overrides.closeDatabaseConnection ?? vi.fn().mockResolvedValue(undefined);
  const activeConnections = overrides.activeConnections ?? new Set<net.Socket>();

  const callServerCloseCallback = overrides.callServerCloseCallback ?? true;
  let capturedCb: (() => void) | undefined;
  const serverClose = vi.fn((cb: () => void) => {
    capturedCb = cb;
    if (callServerCloseCallback) cb();
  });

  const shutdown = createGracefulShutdown({
    logger,
    tasks: overrides.tasks ?? [{ stop }, { stop }, null],
    server: overrides.server ?? { close: serverClose },
    activeConnections,
    getRunningJobs: overrides.getRunningJobs ?? (() => []),
    closeRateLimitStore,
    closeDatabaseConnection,
    exit,
    ...(overrides.flushLoggers !== undefined ? { flushLoggers: overrides.flushLoggers } : {}),
    ...(overrides.jobDrainTimeoutMs !== undefined
      ? { jobDrainTimeoutMs: overrides.jobDrainTimeoutMs }
      : {}),
    ...(overrides.forceShutdownTimeoutMs !== undefined
      ? { forceShutdownTimeoutMs: overrides.forceShutdownTimeoutMs }
      : {}),
  });

  return {
    shutdown,
    logger,
    serverClose,
    stop,
    closeRateLimitStore,
    closeDatabaseConnection,
    exit,
    activeConnections,
    triggerClose: () => capturedCb?.(),
    callServerCloseCallback,
  };
}

describe('createGracefulShutdown (T11)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
  });

  it('runs the shutdown sequence once and exits cleanly (no in-flight jobs)', async () => {
    const h = buildHarness();

    h.shutdown('SIGTERM');
    await flushMicrotasks();

    expect(h.serverClose).toHaveBeenCalledTimes(1);
    expect(h.stop).toHaveBeenCalledTimes(2); // two non-null tasks, null skipped
    expect(h.closeRateLimitStore).toHaveBeenCalledTimes(1);
    expect(h.closeDatabaseConnection).toHaveBeenCalledTimes(1);
    expect(h.exit).toHaveBeenCalledTimes(1);
    expect(h.exit).toHaveBeenCalledWith(0);
  });

  it('flushes logger transports before exiting when flushLoggers is provided', async () => {
    const flushLoggers = vi.fn().mockResolvedValue(undefined);
    const h = buildHarness({ flushLoggers });

    h.shutdown('SIGTERM');
    await flushMicrotasks();

    expect(flushLoggers).toHaveBeenCalledTimes(1);
    expect(h.exit).toHaveBeenCalledTimes(1);
    expect(h.exit).toHaveBeenCalledWith(0);
    // The flush must complete before the process exits so final logs persist.
    const flushOrder = flushLoggers.mock.invocationCallOrder[0] ?? Infinity;
    const exitOrder = h.exit.mock.invocationCallOrder[0] ?? -Infinity;
    expect(flushOrder).toBeLessThan(exitOrder);
  });

  it('is a no-op on a second signal and leaves no stray force-shutdown timer', async () => {
    const h = buildHarness();

    h.shutdown('SIGTERM');
    h.shutdown('SIGINT'); // double signal — must be ignored
    await flushMicrotasks();

    expect(h.serverClose).toHaveBeenCalledTimes(1);
    expect(h.stop).toHaveBeenCalledTimes(2);
    expect(h.logger.info).toHaveBeenCalledWith(
      expect.stringContaining('shutdown is already in progress'),
    );
    expect(h.exit).toHaveBeenCalledTimes(1);
    expect(h.exit).toHaveBeenCalledWith(0);

    // The force-shutdown timer must have been cleared on the clean exit; running
    // any remaining timers must NOT produce a stray exit(1).
    await vi.runAllTimersAsync();
    expect(h.exit).toHaveBeenCalledTimes(1);
    expect(h.exit).toHaveBeenCalledWith(0);
  });

  it('awaits in-flight background jobs that complete before the drain timeout', async () => {
    const h = buildHarness({ getRunningJobs: () => [Promise.resolve()] });

    h.shutdown('SIGTERM');
    await flushMicrotasks();

    expect(h.logger.info).toHaveBeenCalledWith(
      expect.stringContaining('in-flight background job(s) completed'),
    );
    expect(h.logger.warn).not.toHaveBeenCalledWith(
      expect.stringContaining('Timed out waiting for in-flight background jobs'),
    );
    expect(h.exit).toHaveBeenCalledTimes(1);
    expect(h.exit).toHaveBeenCalledWith(0);
  });

  it('proceeds after the drain timeout when in-flight jobs never settle', async () => {
    const neverSettles = new Promise<void>(() => {
      /* intentionally never resolves */
    });
    const h = buildHarness({ getRunningJobs: () => [neverSettles], jobDrainTimeoutMs: 10_000 });

    h.shutdown('SIGTERM');
    await vi.advanceTimersByTimeAsync(10_000);
    await flushMicrotasks();

    expect(h.logger.warn).toHaveBeenCalledWith('Timed out waiting for in-flight background jobs');
    expect(h.exit).toHaveBeenCalledTimes(1);
    expect(h.exit).toHaveBeenCalledWith(0);
  });

  it('force-destroys lingering connections and exits(1) when close stalls', async () => {
    const socket = makeSocket();
    const h = buildHarness({
      callServerCloseCallback: false, // server.close never invokes its callback
      activeConnections: new Set<net.Socket>([socket]),
      forceShutdownTimeoutMs: 30_000,
    });

    h.shutdown('SIGTERM');
    await vi.advanceTimersByTimeAsync(30_000);

    expect(socket.destroy).toHaveBeenCalledTimes(1);
    expect(h.logger.warn).toHaveBeenCalledWith('Forcing shutdown after timeout');
    expect(h.exit).toHaveBeenCalledTimes(1);
    expect(h.exit).toHaveBeenCalledWith(1);
  });

  it('exits(1) when a step in the shutdown chain rejects', async () => {
    const h = buildHarness({
      closeDatabaseConnection: vi.fn().mockRejectedValue(new Error('db close failed')),
    });

    h.shutdown('SIGTERM');
    await flushMicrotasks();

    expect(h.logger.warn).toHaveBeenCalledWith(
      expect.stringContaining('Error during graceful shutdown sequence'),
    );
    expect(h.exit).toHaveBeenCalledTimes(1);
    expect(h.exit).toHaveBeenCalledWith(1);
  });

  it('handles a non-Error rejection in the shutdown chain', async () => {
    const h = buildHarness({
      // Reject with a non-Error value to exercise the `Unknown error` fallback.
      closeRateLimitStore: vi.fn().mockRejectedValue('store closed unexpectedly'),
    });

    h.shutdown('SIGTERM');
    await flushMicrotasks();

    expect(h.logger.warn).toHaveBeenCalledWith(
      expect.stringContaining('Error during graceful shutdown sequence: Unknown error'),
    );
    expect(h.exit).toHaveBeenCalledTimes(1);
    expect(h.exit).toHaveBeenCalledWith(1);
  });
});
