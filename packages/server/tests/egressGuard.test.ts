/**
 * The harness-level egress block, asserted through the clients that would
 * actually be used to leave the machine.
 *
 * Every case here fails if `installEgressGuard()` stops being called from
 * `tests/setup.ts`, or if a patch point is dropped — which is the regression that
 * would let a future suite quietly start talking to `api.pwnedpasswords.com` and
 * make a unit gate depend on a third party's uptime.
 *
 * `api.pwnedpasswords.com` is used as the host on purpose: it is the ONE outbound
 * dependency this codebase really has (`utils/hibp.ts`), so these tests name the
 * thing being prevented rather than an abstract example.
 */
import axios from 'axios';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { EgressBlockedError, withEgressAllowed } from './egressGuard.js';

const HIBP = 'https://api.pwnedpasswords.com/range/AAAAA';

describe('egress guard — outbound requests are blocked', () => {
  it('blocks an axios GET to a third party and names the host', async () => {
    // The real production call shape: this is what `fetchRangeFromHibp` does.
    await expect(axios.get(HIBP)).rejects.toThrow(EgressBlockedError);
    await expect(axios.get(HIBP)).rejects.toThrow(/api\.pwnedpasswords\.com/);
    // The message must point at the fix, not merely refuse.
    await expect(axios.get(HIBP)).rejects.toThrow(/must not reach a third party/);
  });

  it('blocks https.request and http.request directly', () => {
    expect(() => https.request(HIBP)).toThrow(EgressBlockedError);
    expect(() => http.request('http://example.com/')).toThrow(/example\.com/);
    // The options-object form carries the host in a different place; a guard that
    // only understood string URLs would let this one through.
    expect(() =>
      https.request({ hostname: 'api.pwnedpasswords.com', path: '/range/AAAAA' }),
    ).toThrow(EgressBlockedError);
  });

  it('blocks a raw socket, which is what fetch and undici go through', async () => {
    // `net.connect` normalizes its arguments into an ARRAY before calling
    // `Socket.prototype.connect`, and that is the shape undici uses. A guard that
    // only understood the plain options object read no host here, defaulted to
    // "localhost", and allowed every outbound socket while still looking installed.
    expect(() => net.connect({ host: 'api.pwnedpasswords.com', port: 443 })).toThrow(
      EgressBlockedError,
    );
    expect(() => net.connect(443, 'api.pwnedpasswords.com')).toThrow(EgressBlockedError);

    // fetch reaches the same floor, wrapping our error as `cause`.
    const failure: unknown = await fetch(HIBP).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    const cause = (failure as { cause?: unknown }).cause;
    expect(cause).toBeInstanceOf(EgressBlockedError);
    expect((cause as EgressBlockedError).host).toBe('api.pwnedpasswords.com');
  });

  it('carries the host and the patch point on the error, not just in the text', () => {
    let caught: unknown;
    try {
      https.request(HIBP);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(EgressBlockedError);
    expect((caught as EgressBlockedError).host).toBe('api.pwnedpasswords.com');
    expect((caught as EgressBlockedError).via).toBe('https.request');
    expect((caught as EgressBlockedError).name).toBe('EgressBlockedError');
  });
});

describe('egress guard — the local machine stays reachable', () => {
  let server: http.Server;
  let port: number;

  beforeAll(async () => {
    server = http.createServer((_req, res) => {
      res.writeHead(204);
      res.end();
    });
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    port = typeof address === 'object' && address !== null ? address.port : 0;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => {
        resolve();
      });
    });
  });

  it('allows loopback, which is where mongod and the app under supertest live', async () => {
    // A guard that blocked this would take the entire suite down: every
    // integration test drives a real Express app over a local socket, and every
    // model call reaches a real mongod on 127.0.0.1.
    const res = await axios.get(`http://127.0.0.1:${String(port)}/`, {
      validateStatus: () => true,
    });
    expect(res.status).toBe(204);
    await expect(axios.get(`http://localhost:${String(port)}/`)).resolves.toBeDefined();
  });
});

describe('egress guard — the one sanctioned suspension', () => {
  it('allows egress inside withEgressAllowed and re-blocks immediately after', async () => {
    // The single legitimate caller is mongodb-memory-server fetching the mongod
    // binary on a machine that has not cached it. The suspension must be scoped:
    // a leak would silently disable the guard for the rest of the file.
    //
    // The probe host is under `.invalid`, which RFC 2606 reserves as
    // guaranteed-unresolvable, so this test never contacts a third party even
    // while the guard is suspended — it only proves that CONSTRUCTING the request
    // is no longer refused. Blocked, it throws before any lookup; suspended, it
    // proceeds and fails asynchronously with ENOTFOUND, which the error listener
    // absorbs (without it the rejection surfaces as an unhandled exception and
    // Vitest fails the file).
    const probe = 'https://blocked.invalid/range/AAAAA';
    expect(() => https.request(probe)).toThrow(EgressBlockedError);

    const constructed = await withEgressAllowed(() => {
      const request = https.request(probe);
      request.on('error', () => {
        /* an unresolvable host is the expected outcome and not what is asserted */
      });
      request.destroy();
      return Promise.resolve(true);
    });
    expect(constructed).toBe(true);

    expect(() => https.request(probe)).toThrow(EgressBlockedError);
    expect(() => https.request(HIBP)).toThrow(EgressBlockedError);
  });

  it('re-blocks even when the suspended callback throws', async () => {
    await expect(withEgressAllowed(() => Promise.reject(new Error('boom')))).rejects.toThrow(
      'boom',
    );
    expect(() => https.request(HIBP)).toThrow(EgressBlockedError);
  });
});
