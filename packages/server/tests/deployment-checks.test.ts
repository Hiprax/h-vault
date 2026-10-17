import { describe, it, expect, vi, beforeEach } from 'vitest';
import express from 'express';
import type { Request, Response } from 'express';
import request from 'supertest';

// Keep a developer's root `.env` out of the fresh module loads below.
vi.mock('dotenv', () => ({ default: { config: vi.fn() } }));

/**
 * The misconfigurations that used to degrade a deployment SILENTLY (F-09).
 *
 *   * Outside `NODE_ENV=production` every rate limiter is a pass-through and the
 *     session cookies drop `Secure`/`Strict`. Nothing said so: an operator who
 *     started a server without the variable ran it with the brakes off.
 *   * With `TRUST_PROXY` unset behind a proxy, every request appears to come from
 *     the proxy, so every client shares ONE rate-limit bucket and every audit row
 *     names the proxy. Nothing said so either.
 *
 * Each is now logged ONCE and reported on `/metrics` (token-gated), never on the
 * public `/health`, which would advertise an instance whose limiters are off.
 *
 * `supertest` connects from 127.0.0.1, which is exactly where a host Nginx on the
 * same machine connects from, so a real request through a real Express app is the
 * misconfigured deployment itself, not a simulation of it.
 */

const warn = vi.fn();
const logger = { warn, info: vi.fn(), error: vi.fn(), debug: vi.fn() };

/** A fresh copy of the module, so its once-only state starts clean. */
async function freshChecks() {
  vi.resetModules();
  return import('../src/utils/deploymentChecks.js');
}

/** An app with Express's own trust-proxy setting and the detector mounted the way `app.ts` mounts it. */
async function appWith(nodeEnv: string, trustProxy: string | number | false) {
  const checks = await freshChecks();
  const app = express();
  if (trustProxy !== false && trustProxy !== 0) app.set('trust proxy', trustProxy);
  app.use(checks.createProxyTrustDetector({ nodeEnv, trustProxy, logger }));
  app.get('/ip', (req: Request, res: Response) => {
    res.json({ ip: req.ip });
  });
  return { app, checks };
}

/** The detector's warnings, told apart from anything else logged. */
function proxyWarnings(): unknown[][] {
  return warn.mock.calls.filter(([message]) => String(message).includes('TRUST_PROXY'));
}

beforeEach(() => {
  warn.mockClear();
});

describe('the non-production start (reportDeploymentMode)', () => {
  it('warns exactly once, naming what is off, when NODE_ENV is development', async () => {
    const checks = await freshChecks();

    checks.reportDeploymentMode('development', logger);
    checks.reportDeploymentMode('development', logger);

    expect(warn).toHaveBeenCalledOnce();
    const [message] = warn.mock.calls[0] as [string];
    expect(message).toContain('NODE_ENV=development');
    expect(message).toMatch(/rate limiting is OFF/);
    expect(message).toMatch(/Secure/);
    expect(message).toMatch(/NODE_ENV=production/);
  });

  it.each(['production', 'test'])('says nothing when NODE_ENV is %s', async (nodeEnv) => {
    const checks = await freshChecks();

    checks.reportDeploymentMode(nodeEnv, logger);

    expect(warn).not.toHaveBeenCalled();
  });
});

describe('a process-wide TLS verification override (reportTlsVerificationOverride)', () => {
  it('warns exactly once when NODE_TLS_REJECT_UNAUTHORIZED=0 turns certificate checks off for every connection', async () => {
    const checks = await freshChecks();

    checks.reportTlsVerificationOverride({ NODE_TLS_REJECT_UNAUTHORIZED: '0' }, logger);
    checks.reportTlsVerificationOverride({ NODE_TLS_REJECT_UNAUTHORIZED: '0' }, logger);

    expect(warn).toHaveBeenCalledOnce();
    const [message] = warn.mock.calls[0] as [string];
    expect(message).toContain('NODE_TLS_REJECT_UNAUTHORIZED=0');
    expect(message).toMatch(/SMTP/);
  });

  it.each([
    ['unset', undefined],
    ['1', '1'],
    ['empty', ''],
  ])('says nothing when it is %s', async (_label, value) => {
    const checks = await freshChecks();

    checks.reportTlsVerificationOverride({ NODE_TLS_REJECT_UNAUTHORIZED: value }, logger);

    expect(warn).not.toHaveBeenCalled();
  });
});

describe('the untrusted-proxy detector (createProxyTrustDetector)', () => {
  it('warns ONCE and raises the gauge when a production server with TRUST_PROXY unset receives X-Forwarded-For from loopback', async () => {
    const { app, checks } = await appWith('production', false);
    expect(checks.proxyMisconfigSuspected()).toBe(false);

    const first = await request(app).get('/ip').set('X-Forwarded-For', '203.0.113.7');
    await request(app).get('/ip').set('X-Forwarded-For', '203.0.113.8');

    // The request itself is served, and what it demonstrates is the harm: the
    // client address is the proxy's, not the one it forwarded.
    expect(first.status).toBe(200);
    expect((first.body as { ip: string }).ip).toMatch(/127\.0\.0\.1$/);
    expect(proxyWarnings()).toHaveLength(1);
    const [message, meta] = proxyWarnings()[0] as [string, Record<string, unknown>];
    expect(message).toMatch(/TRUST_PROXY=loopback/);
    expect(meta).toEqual({ peer: expect.stringMatching(/127\.0\.0\.1$/) as unknown });
    expect(checks.proxyMisconfigSuspected()).toBe(true);
  });

  it('is armed by TRUST_PROXY=0 too, which trusts no proxy exactly as unset does', async () => {
    const { app, checks } = await appWith('production', 0);

    await request(app).get('/ip').set('X-Forwarded-For', '203.0.113.7');

    expect(proxyWarnings()).toHaveLength(1);
    expect(checks.proxyMisconfigSuspected()).toBe(true);
  });

  it('says nothing under TRUST_PROXY=loopback, and the forwarded address is used', async () => {
    const { app, checks } = await appWith('production', 'loopback');

    const res = await request(app).get('/ip').set('X-Forwarded-For', '203.0.113.7');

    expect((res.body as { ip: string }).ip).toBe('203.0.113.7');
    expect(proxyWarnings()).toHaveLength(0);
    expect(checks.proxyMisconfigSuspected()).toBe(false);
  });

  it('says nothing when no X-Forwarded-For arrives (no proxy in front)', async () => {
    const { app, checks } = await appWith('production', false);

    await request(app).get('/ip');

    expect(proxyWarnings()).toHaveLength(0);
    expect(checks.proxyMisconfigSuspected()).toBe(false);
  });

  it.each(['development', 'test'])(
    'is not armed when NODE_ENV is %s (the mode warning covers that start)',
    async (nodeEnv) => {
      const { app, checks } = await appWith(nodeEnv, false);

      await request(app).get('/ip').set('X-Forwarded-For', '203.0.113.7');

      expect(proxyWarnings()).toHaveLength(0);
      expect(checks.proxyMisconfigSuspected()).toBe(false);
    },
  );

  it('ignores X-Forwarded-For from a PUBLIC peer: that is a client lying, not a proxy the operator forgot', async () => {
    const checks = await freshChecks();
    const detector = checks.createProxyTrustDetector({
      nodeEnv: 'production',
      trustProxy: false,
      logger,
    });
    const next = vi.fn();

    detector(
      {
        headers: { 'x-forwarded-for': '10.0.0.1' },
        socket: { remoteAddress: '198.51.100.20' },
      } as unknown as Request,
      {} as Response,
      next,
    );

    expect(next).toHaveBeenCalledOnce();
    expect(proxyWarnings()).toHaveLength(0);
    expect(checks.proxyMisconfigSuspected()).toBe(false);
  });

  it('counts a private-network peer (the Docker bridge) as a proxy too', async () => {
    const checks = await freshChecks();
    const detector = checks.createProxyTrustDetector({
      nodeEnv: 'production',
      trustProxy: false,
      logger,
    });
    const next = vi.fn();

    detector(
      {
        headers: { 'x-forwarded-for': '203.0.113.7' },
        socket: { remoteAddress: '::ffff:172.31.240.3' },
      } as unknown as Request,
      {} as Response,
      next,
    );

    expect(next).toHaveBeenCalledOnce();
    expect(proxyWarnings()).toHaveLength(1);
    expect(checks.proxyMisconfigSuspected()).toBe(true);
  });
});
