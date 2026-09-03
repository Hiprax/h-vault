/**
 * `test:storage` — the harness's own teardown contract, against a real container.
 *
 * `tests/harness/s3Server.ts` states as invariant (e) that the container is removed
 * on EVERY exit path, because its volumes are tmpfs and a leaked one holds RAM until
 * the daemon reaps it. That invariant is the harness's, so nothing in the
 * conformance suite can check it: that file starts an engine, uses it, and stops it
 * once from a single `afterAll` — the one path that was never in doubt.
 *
 * These cases pin the two paths that were, both of them MEASURED rather than
 * imagined. `npm run ci` was leaving two engines running per run (one from `test:e2e`,
 * one from `test:a11y`, both through `e2e/start-server.ts`), on runs that ended green:
 *
 *   1. `e2e/start-server.ts` reaches teardown from two directions at once — Playwright's
 *      SIGTERM, and the dev server's own `exit` handler, which then calls
 *      `process.exit()`. A second `stop()` that resolved on its own instead of joining
 *      the first let that exit run while `docker rm -f` was still in flight.
 *   2. The synchronous `process.on('exit')` hook is the last resort for exactly that
 *      race, so unregistering it BEFORE awaiting the removal — rather than after —
 *      is what turned the race into a leak.
 *
 * Both are invisible to a test that stops an engine once and awaits it.
 *
 * ## Seams
 *
 * None. The engine is the real pinned image in a real container, and the verdict is
 * read from `docker inspect` rather than from the harness's own bookkeeping — a
 * harness that reported its container removed while it was still running is precisely
 * the failure under test.
 */
import { describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { startStorageEngine } from '../../../../tests/harness/s3Server.js';
import { createS3Provider } from '../../src/services/storage/s3Provider.js';

const execFileAsync = promisify(execFile);

/** The engine, ready for the same client the conformance suite uses. */
const startEngine = async () =>
  startStorageEngine({ probe: (connection) => createS3Provider(connection).headBucket() });

/**
 * Whether the daemon still holds a RUNNING container under this id.
 *
 * `docker inspect` exits non-zero on an unknown container, which is what a removed
 * one is, so the throw is the "gone" answer rather than an error to report. Reading
 * `.State.Running` as well as existence matters: `docker rm -f` on a container the
 * harness started with `--rm` both stops and removes it, and a stopped-but-present
 * container would still be a leak of the tmpfs the invariant is about.
 */
async function containerIsRunning(containerId: string): Promise<boolean> {
  try {
    const { stdout } = await execFileAsync('docker', [
      'inspect',
      '-f',
      '{{.State.Running}}',
      containerId,
    ]);
    return stdout.trim() === 'true';
  } catch {
    return false;
  }
}

describe('the storage engine harness removes its container on every exit path', () => {
  it('does not resolve a second stop() until the container has actually been removed', async () => {
    const engine = await startEngine();
    // The subject exists: without this, every assertion below would pass vacuously
    // against an id that never named a running container.
    expect(await containerIsRunning(engine.containerId)).toBe(true);

    // Deliberately NOT awaited. This is the race `e2e/start-server.ts` runs into,
    // and the second caller is the one that goes on to call `process.exit()`.
    const first = engine.stop();
    const second = engine.stop();

    await second;
    expect(await containerIsRunning(engine.containerId)).toBe(false);

    // Neither call reports a failure, and a stop after the removal is still safe:
    // the harness documents `stop` as safe to call twice, and a caller that got a
    // rejection here would log a teardown error after a green run.
    await expect(first).resolves.toBeUndefined();
    await expect(engine.stop()).resolves.toBeUndefined();
  }, 120_000);

  it('keeps its synchronous last-resort exit hook armed until the removal has completed', async () => {
    const hooksBefore = process.listenerCount('exit');

    const engine = await startEngine();
    expect(process.listenerCount('exit')).toBe(hooksBefore + 1);

    // Read SYNCHRONOUSLY after the call: `stop()` runs up to its first await before
    // yielding, so this observes the window in which the removal is in flight. An
    // exit racing this window is covered only while the hook is still registered.
    const stopping = engine.stop();
    expect(process.listenerCount('exit')).toBe(hooksBefore + 1);

    await stopping;
    // And it is not left behind either: a hook per engine would accumulate across a
    // ten-run flake sweep and remove containers that later runs still had ids for.
    expect(process.listenerCount('exit')).toBe(hooksBefore);
    expect(await containerIsRunning(engine.containerId)).toBe(false);
  }, 120_000);
});
