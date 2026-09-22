/**
 * The storage harness's host-port policy: which `docker run` failures are a lost
 * allocation, and what the retry around them may and may not do.
 *
 * This is the sibling of `mongoHarness.test.ts`'s "retry policy" block, and it
 * exists for the same reason: the classification is a real decision with a real
 * failure mode in BOTH directions, and neither direction is visible from a run
 * that happened to succeed.
 *
 * ## Why this file is flat rather than under `tests/storage/`
 *
 * Nothing here starts a container or talks to a daemon, and it must not: the
 * `storage` gate declares `requires: ['docker']`, so a predicate parked beside
 * it would go unmeasured on every machine without one — including the machines
 * most likely to meet the failure it guards. `gate-surface.test.ts` also pins
 * `STORAGE_SUITE` against the files in `tests/storage/` in both directions, so a
 * file there is a registration as well as a test. `mongoHarness.test.ts` is the
 * precedent: flat, globbed, and run on every push.
 *
 * ## Seams
 *
 * None that matter. {@link withHostPortRetry} takes the operation as an
 * argument, which is why it can be driven here with a function that counts its
 * own attempts instead of five containers; the classification is a pure function
 * over the rejection the real call produced, and the rejection below is the
 * VERBATIM one this repository measured, not a paraphrase of it.
 */
import { describe, expect, it } from 'vitest';
import { isHostPortCollision, withHostPortRetry } from '../../../tests/harness/s3Server.js';

/**
 * The rejection `promisify(execFile)` produced when the gate actually failed.
 *
 * Reproduced as the real shape — `Command failed: <argv>` followed by the
 * daemon's own words — because that formatting is a Node convention rather than
 * a contract, and a predicate tuned to a paraphrase of it would pass here and
 * miss the thing it exists for. The endpoint name and the container id are the
 * only parts elided: they are per-run noise, and a 64-character hex literal in a
 * test file is something the secret scanner has to be told to ignore.
 */
const ROOTLESS_COLLISION =
  'Command failed: docker run -d --rm --label hvault-test=storage-harness ' +
  '-p 127.0.0.1:0:3900 dxflrs/garage\n' +
  'docker: Error response from daemon: failed to set up container networking: driver failed ' +
  'programming external connectivity on endpoint <name>: error while calling RootlessKit ' +
  'PortManager.AddPort(): listen tcp4 127.0.0.1:33498: bind: address already in use\n';

/** The same condition as a ROOTFUL daemon reports it, which is its own sentence. */
const ROOTFUL_COLLISION =
  'Command failed: docker run -d --rm -p 127.0.0.1:0:3900 dxflrs/garage\n' +
  'docker: Error response from daemon: driver failed programming external connectivity on ' +
  'endpoint <name>: Bind for 127.0.0.1:33498 failed: port is already allocated\n';

/** An `ExecFileException`-shaped rejection: the streams are their own properties. */
function execFailure(message: string, stderr: string): Error {
  return Object.assign(new Error(message), { stdout: '', stderr, code: 125 });
}

describe('the storage harness classifies a lost host-port allocation', () => {
  it('recognises the rootless spelling this repository measured, verbatim', () => {
    expect(isHostPortCollision(new Error(ROOTLESS_COLLISION))).toBe(true);
  });

  it('recognises the rootful spelling, which shares nothing but the meaning', () => {
    // A predicate narrowed to `RootlessKit` would pass the case above and leave
    // the identical race unhandled on every rootful daemon, silently.
    expect(isHostPortCollision(new Error(ROOTFUL_COLLISION))).toBe(true);
  });

  it('reads the rejection’s own stderr, not only the message Node composed', () => {
    // Node happens to fold stderr into the message today. The stream is the
    // property that is actually specified, so a rejection whose message says
    // nothing must still be classified from it.
    expect(
      isHostPortCollision(
        execFailure(
          'Command failed: docker run',
          'error while calling RootlessKit PortManager.AddPort(): listen tcp4 127.0.0.1:41000: ' +
            'bind: address already in use\n',
        ),
      ),
    ).toBe(true);
  });

  it('refuses every failure that retrying would only repeat', () => {
    // Each of these is a condition five more attempts cannot change, and each
    // would arrive five times over — with the single clear explanation buried —
    // if the predicate widened.
    expect(
      isHostPortCollision(
        new Error(
          'Command failed: docker run\ndocker: Error response from daemon: pull access denied\n',
        ),
      ),
    ).toBe(false);
    expect(
      isHostPortCollision(
        new Error('Cannot connect to the Docker daemon at unix:///var/run/docker.sock.'),
      ),
    ).toBe(false);
    expect(isHostPortCollision(new Error('spawn docker ENOENT'))).toBe(false);
    // The engine refusing its own configuration is not a port problem either.
    expect(isHostPortCollision(new Error('Invalid GARAGE_RPC_SECRET: expected 64 hex'))).toBe(
      false,
    );
    // And a non-Error rejection must be ANSWERED rather than thrown on: this
    // predicate is handed whatever the call rejected with, and a harness that
    // threw while inspecting a failure would replace it with a useless one.
    expect(isHostPortCollision('listen tcp4 127.0.0.1:41000: bind: address already in use')).toBe(
      true,
    );
    expect(isHostPortCollision(undefined)).toBe(false);
    // Deliberately narrower than `mongoHarness.ts`'s predicate, which matches a
    // bare "already in use" because that is what mms prints. A daemon always
    // says `bind: address already in use` or `port is already allocated`, so the
    // looser phrase buys nothing here and would start matching an engine log
    // line that happens to mention a port.
    expect(isHostPortCollision('address already in use')).toBe(false);
    // Error-shaped only: `execFile` rejects with an `Error`, so a bare object
    // carrying a `stderr` is not a rejection this ever sees, and reading one
    // would be a guess dressed as a contract.
    expect(isHostPortCollision({ stderr: 'bind: address already in use' })).toBe(false);
  });
});

describe('the storage harness retries a lost host-port allocation, and only that', () => {
  it('asks for another allocation until one is granted, and returns it', async () => {
    let attempts = 0;
    const result = await withHostPortRetry(() => {
      attempts += 1;
      if (attempts < 3) return Promise.reject(new Error(ROOTLESS_COLLISION));
      return Promise.resolve('container-id');
    });

    expect(result).toBe('container-id');
    // Exactly the attempts that were needed: a loop that kept going after a
    // success would start a second container nothing holds a reference to.
    expect(attempts).toBe(3);
  });

  it('starts the container ONCE when the first allocation is granted', async () => {
    let attempts = 0;
    await expect(
      withHostPortRetry(() => {
        attempts += 1;
        return Promise.resolve('container-id');
      }),
    ).resolves.toBe('container-id');
    expect(attempts).toBe(1);
  });

  it('rethrows anything else on the FIRST attempt, unchanged', async () => {
    let attempts = 0;
    await expect(
      withHostPortRetry(() => {
        attempts += 1;
        return Promise.reject(new Error('Cannot connect to the Docker daemon'));
      }),
    ).rejects.toThrow('Cannot connect to the Docker daemon');
    // The whole point of the classification: one clear failure, not five.
    expect(attempts).toBe(1);
  });

  it('gives up after a bounded number of attempts, naming the last failure', async () => {
    let attempts = 0;
    await expect(
      withHostPortRetry(() => {
        attempts += 1;
        return Promise.reject(new Error(ROOTLESS_COLLISION));
      }),
    ).rejects.toThrow(/host-port allocations in a row were taken/);
    // Bounded, and the bound is asserted rather than assumed: an unbounded loop
    // would hang the gate on a host with nothing free, which reads as a suite
    // that stopped rather than one that failed.
    expect(attempts).toBe(5);

    // And the daemon's own words survive into the give-up message, or the report
    // says only that something was taken and never what said so.
    let thrown: unknown;
    try {
      await withHostPortRetry(() => Promise.reject(new Error(ROOTLESS_COLLISION)));
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect((thrown as Error).message).toContain('RootlessKit PortManager.AddPort()');
  });
});
