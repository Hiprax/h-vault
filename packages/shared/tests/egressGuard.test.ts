/**
 * The socket floor, asserted in the tier that has nothing else.
 *
 * This package patches no HTTP client — it has none — so `net.Socket.prototype.connect`
 * is its whole guard, and it is worth a test precisely because nothing else here
 * would notice if `installSocketEgressGuard()` stopped being called from
 * `tests/setup.ts`.
 */
import net from 'node:net';
import { describe, expect, it } from 'vitest';
import { EgressBlockedError, withEgressAllowed } from './egressGuard.js';

describe('egress guard (shared)', () => {
  it('blocks a TCP connection to a third party in every argument shape', () => {
    // `net.connect` normalizes its arguments into an ARRAY before calling the
    // prototype method, and that is the shape undici — and therefore `fetch` —
    // always uses, so it is the one that matters most.
    expect(() => net.connect({ host: 'api.pwnedpasswords.com', port: 443 })).toThrow(
      EgressBlockedError,
    );
    expect(() => net.connect(443, 'example.com')).toThrow(/example\.com/);
    expect(() => net.connect({ host: 'example.com', port: 80 })).toThrow(
      /must not reach a third party/,
    );
  });

  it('rejects fetch, which reaches the same floor through undici', async () => {
    const failure: unknown = await fetch('https://api.pwnedpasswords.com/range/AAAAA').catch(
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(Error);
    const cause = (failure as { cause?: unknown }).cause;
    expect(cause).toBeInstanceOf(EgressBlockedError);
    expect((cause as EgressBlockedError).host).toBe('api.pwnedpasswords.com');
  });

  it('leaves loopback alone, or it would block a local fixture server', () => {
    const server = net.createServer();
    try {
      expect(() => net.connect({ host: '127.0.0.1', port: 1 }).destroy()).not.toThrow();
      expect(() => net.connect({ host: 'localhost', port: 1 }).destroy()).not.toThrow();
    } finally {
      server.close();
    }
  });

  it('scopes the suspension, so allowing one call does not disable the guard', async () => {
    // `.invalid` is reserved as guaranteed-unresolvable (RFC 2606), so nothing
    // leaves the machine even while the guard is suspended: this asserts only that
    // the connection is no longer REFUSED.
    const allowed = await withEgressAllowed(() => {
      const socket = net.connect({ host: 'blocked.invalid', port: 443 });
      socket.on('error', () => {
        /* an unresolvable host is expected and is not what is asserted */
      });
      socket.destroy();
      return Promise.resolve(true);
    });
    expect(allowed).toBe(true);

    expect(() => net.connect({ host: 'blocked.invalid', port: 443 })).toThrow(EgressBlockedError);
  });
});
