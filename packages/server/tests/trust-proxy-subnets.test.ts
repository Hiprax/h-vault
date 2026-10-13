/**
 * What `TRUST_PROXY` trusts, measured through Express's own `trust proxy`.
 *
 * `config/index.ts` hands a named range or a subnet list straight to
 * `app.set('trust proxy', …)`, and Express decides with `proxy-addr`. Since
 * proxy-addr 2.0.8 (GHSA-jqcg-44mw-7w3h) an IPv4 peer is compared as IPv4, and an
 * IPv6 subnet matches it only when it is an IPv4-mapped subnet covering the
 * `::ffff:` marker. Before it, a subnet wide enough to contain the mapped block
 * (`::/1`, or a mapped address written with an IPv4-length prefix such as
 * `::ffff:127.0.0.0/8`) trusted IPv4 peers outside the range it meant, so such a
 * peer could choose the address every rate limit and audit entry is keyed on.
 * These cases pin the trust this deployment relies on, on both sides of that
 * change; ordinary IPv6 subnets were never affected and are pinned as such.
 */
import { describe, it, expect } from 'vitest';
import express from 'express';
import request from 'supertest';

const FORWARDED = '203.0.113.9';

/** The address Express derives for one request from this machine (an IPv4 peer). */
async function clientAddress(trust: string | number | false): Promise<string> {
  const app = express();
  app.set('trust proxy', trust);
  app.get('/ip', (req, res) => {
    res.json({ ip: req.ip });
  });
  const res = await request(app).get('/ip').set('X-Forwarded-For', FORWARDED);
  expect(res.status).toBe(200);
  return (res.body as { ip: string }).ip;
}

/** The peer itself, in whichever spelling the socket reports it. */
const LOOPBACK_PEER = /^(::ffff:)?127\.0\.0\.1$/;

describe('TRUST_PROXY, as Express applies it', () => {
  it('trusts a loopback proxy under the recommended `loopback`, so the forwarded address is used', async () => {
    expect(await clientAddress('loopback')).toBe(FORWARDED);
  });

  it('trusts an IPv4 peer through an IPv4-MAPPED subnet, which spans IPv4 by construction', async () => {
    expect(await clientAddress('::ffff:127.0.0.0/104')).toBe(FORWARDED);
  });

  it('does NOT trust an IPv4 peer through a plain IPv6 subnet (proxy-addr >= 2.0.8)', async () => {
    // `::/1` is half of the IPv6 space and no IPv4 address (proxy-addr refuses a
    // `/0`), yet it contains `::ffff:127.0.0.1`. Trusting an IPv4 peer
    // through it let that peer supply X-Forwarded-For.
    expect(await clientAddress('::/1')).toMatch(LOOPBACK_PEER);
  });

  it('does NOT trust an IPv4 peer through a mapped address with an IPv4-length prefix (the advisory shape)', async () => {
    // `/8` on a mapped address does not reach the `::ffff:` marker, so it is not
    // the IPv4 range `127.0.0.0/8` it looks like; before 2.0.8 it trusted
    // `127.0.0.1` anyway.
    expect(await clientAddress('::ffff:127.0.0.0/8')).toMatch(LOOPBACK_PEER);
  });

  it('never trusted an IPv4 peer through an ordinary IPv6 subnet, before or after the fix', async () => {
    expect(await clientAddress('fc00::/7,fe80::/10')).toMatch(LOOPBACK_PEER);
  });

  it('ignores X-Forwarded-For entirely when no proxy is trusted', async () => {
    expect(await clientAddress(false)).toMatch(LOOPBACK_PEER);
  });
});
