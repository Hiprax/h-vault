import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express from 'express';
import request from 'supertest';

// Keep a developer's root `.env` out of the fresh config loads below.
vi.mock('dotenv', () => ({ default: { config: vi.fn() } }));

/**
 * Which interfaces the HTTP server accepts connections on (F-23).
 *
 * `server.listen(port)` with no host binds EVERY interface. Behind the documented
 * PM2 deployment the only intended client is the host Nginx on loopback, so an
 * all-interfaces bind hands anyone who can reach the machine's address a way
 * round the proxy — and with a numeric `TRUST_PROXY`, a way to choose the client
 * address every rate limit and audit row is keyed on. The default is therefore
 * loopback; the containers, which are reached over a bridge network, set
 * `HOST=0.0.0.0` explicitly.
 *
 * These cases load the REAL configuration and open a REAL socket through the same
 * `listenOn` `server.ts` uses, then read the bound address back from the kernel.
 * Port 0 lets the kernel choose a free port.
 */
describe('the HTTP listener address (HOST)', () => {
  const savedHost = process.env['HOST'];
  let server: Server | undefined;

  beforeEach(() => {
    vi.resetModules();
  });

  afterEach(async () => {
    if (savedHost === undefined) Reflect.deleteProperty(process.env, 'HOST');
    else process.env['HOST'] = savedHost;
    const open = server;
    server = undefined;
    if (open?.listening) await new Promise<void>((resolve) => open.close(() => resolve()));
  });

  /** Loads the configuration with `HOST` as given and listens where it says. */
  async function listenWith(host: string | undefined): Promise<AddressInfo> {
    if (host === undefined) Reflect.deleteProperty(process.env, 'HOST');
    else process.env['HOST'] = host;
    const { config } = await import('../src/config/index.js');
    const { listenOn } = await import('../src/utils/listenAddress.js');
    const { createTimedServer } = await import('../src/utils/httpTimeouts.js');
    const app = express();
    app.get('/ping', (_req, res) => {
      res.send('pong');
    });
    const created = createTimedServer(app);
    server = created;
    await new Promise<void>((resolve, reject) => {
      created.once('error', reject);
      listenOn(created, { port: 0, host: config.HOST }, resolve);
    });
    return created.address() as AddressInfo;
  }

  it('binds loopback only by default, and answers there', async () => {
    const address = await listenWith(undefined);

    expect(address.address).toBe('127.0.0.1');
    expect(address.family).toBe('IPv4');
    const res = await request(`http://127.0.0.1:${String(address.port)}`).get('/ping');
    expect(res.text).toBe('pong');
  });

  it('binds loopback when HOST is present but empty, as an unset value', async () => {
    const address = await listenWith('');

    expect(address.address).toBe('127.0.0.1');
  });

  it('binds every IPv4 interface when HOST=0.0.0.0, which is what the containers set', async () => {
    const address = await listenWith('0.0.0.0');

    expect(address.address).toBe('0.0.0.0');
  });

  it('binds IPv6 loopback when HOST=::1 (or is refused by a host with IPv6 disabled)', async () => {
    // Either outcome proves the host reached `listen`: a host booted with
    // `ipv6.disable=1` (which docker/nginx/internal.conf anticipates) refuses the
    // address, while an all-interfaces bind would have succeeded as '::' or
    // '0.0.0.0'.
    const outcome = await listenWith('::1').then(
      (address) => ({ address }),
      (error: NodeJS.ErrnoException) => ({ code: error.code }),
    );

    if ('address' in outcome) {
      expect(outcome.address.address).toBe('::1');
      expect(outcome.address.family).toBe('IPv6');
    } else {
      expect(['EAFNOSUPPORT', 'EADDRNOTAVAIL']).toContain(outcome.code);
    }
  });
});

describe('the boot log names the address the kernel bound (F-23)', () => {
  it('formats an IPv4, an IPv6, a pipe and a server not listening', async () => {
    const { describeBoundAddress } = await import('../src/utils/listenAddress.js');
    expect(describeBoundAddress({ address: '127.0.0.1', family: 'IPv4', port: 5000 })).toBe(
      '127.0.0.1:5000',
    );
    expect(describeBoundAddress({ address: '::', family: 'IPv6', port: 5000 })).toBe('[::]:5000');
    expect(describeBoundAddress('/tmp/hvault.sock')).toBe('/tmp/hvault.sock');
    expect(describeBoundAddress(null)).toBe('no address (not listening)');
  });

  it('reads a real socket: listenOn with HOST=127.0.0.1 reports loopback, never every interface', async () => {
    const { describeBoundAddress, listenOn } = await import('../src/utils/listenAddress.js');
    const { createTimedServer } = await import('../src/utils/httpTimeouts.js');
    const created = createTimedServer(express());
    try {
      await new Promise<void>((resolve, reject) => {
        created.once('error', reject);
        listenOn(created, { port: 0, host: '127.0.0.1' }, resolve);
      });
      const port = (created.address() as AddressInfo).port;
      expect(describeBoundAddress(created.address())).toBe(`127.0.0.1:${String(port)}`);
      // Negative: what an all-interfaces bind would have printed.
      expect(describeBoundAddress(created.address())).not.toMatch(/^\[::\]|^0\.0\.0\.0/);
    } finally {
      await new Promise<void>((resolve) => created.close(() => resolve()));
    }
  });
});
