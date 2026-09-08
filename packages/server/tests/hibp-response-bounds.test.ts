/**
 * The HIBP range fetch is the ONLY outbound HTTP call this server makes, and
 * every one of its responses is buffered whole into a string before anything
 * looks at it. These tests hold the bound on that body.
 *
 * They are deliberately NOT written against a hand-rolled rejection. `axios`
 * silently ignores a size limit it was never given (both `maxContentLength` and
 * `maxBodyLength` default to `-1`, and the Node adapter's check is guarded on
 * `> -1`), so a test that mocks the rejection would pass just as happily with
 * the limit deleted from the production call. Instead the spy forwards the
 * REAL config object `fetchRangeFromHibp` built to a REAL axios call against a
 * REAL loopback HTTP server that emits an oversized body. The refusal therefore
 * comes from production configuration on a real socket: deleting
 * `maxContentLength` from `utils/hibp.ts` turns these red.
 *
 * Loopback is exempt from the suite's egress guard (see `tests/egressGuard.ts`),
 * which is what makes this possible without reaching a third party.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, it, expect, vi, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import axios, { type AxiosRequestConfig } from 'axios';
import app from '../src/app.js';
import { HIBP_MAX_RANGE_RESPONSE_BYTES } from '../src/constants/index.js';
import { fetchRangeFromHibp } from '../src/utils/hibp.js';
import { PwnedRangeCache } from '../src/models/PwnedRangeCache.js';
import {
  getRange,
  hibpCache,
  rangeInFlight,
  getHibpCacheBytes,
  resetCacheAccessCount,
} from '../src/controllers/toolsController.js';
import { createTestUser, authHeader, getCsrf as getCsrfBase } from './helpers.js';
import type { TestUser } from './helpers.js';

const API = '/api/v1';

/**
 * A single well-formed range row of exactly `bytes` bytes.
 *
 * One long line rather than many short ones so the body length is exact to the
 * byte — the boundary is what is under test. `stripPaddingRows` keeps any line
 * whose text after the last colon is not `'0'`, so this survives the strip
 * unchanged and the assertion can compare against the body verbatim.
 */
function rangeBodyOfExactly(bytes: number): string {
  return `${'A'.repeat(bytes - 2)}:1`;
}

// ── The loopback upstream ────────────────────────────────────────────

let upstream: http.Server;
let upstreamOrigin: string;
/** Body the next upstream request will receive. Set per test. */
let upstreamBody = '';
/** Requests the upstream actually served — proves the call left the process. */
let upstreamHits = 0;

beforeAll(async () => {
  upstream = http.createServer((_req, res) => {
    upstreamHits += 1;
    // The oversized cases end with the client destroying the socket, which
    // surfaces here as EPIPE/ECONNRESET. That is the expected outcome, not a
    // failure — but an unhandled 'error' on a response would take the worker
    // down with it.
    res.on('error', () => undefined);

    // No `Content-Length`: Node falls back to chunked transfer encoding, so the
    // limit is exercised the way it must actually hold — incrementally, on the
    // response stream — rather than by a header the upstream could simply lie
    // about or omit.
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    const CHUNK = 64 * 1024;
    for (let offset = 0; offset < upstreamBody.length; offset += CHUNK) {
      res.write(upstreamBody.slice(offset, offset + CHUNK));
    }
    res.end();
  });
  await new Promise<void>((resolve) => {
    upstream.listen(0, '127.0.0.1', resolve);
  });
  const address = upstream.address() as AddressInfo;
  upstreamOrigin = `http://127.0.0.1:${String(address.port)}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    upstream.close((err) => {
      if (err) reject(err);
      else resolve();
    });
  });
});

/**
 * Redirect the outbound HIBP call to the loopback upstream while forwarding the
 * production config object VERBATIM. The URL is the only thing substituted;
 * every option `fetchRangeFromHibp` chose — including the size limits under
 * test — is the one axios actually runs with.
 */
function interceptToUpstream(): void {
  const realGet = axios.get.bind(axios);
  vi.spyOn(axios, 'get').mockImplementation(((url: string, cfg?: AxiosRequestConfig) => {
    const prefix = url.slice(url.lastIndexOf('/') + 1);
    return realGet<string>(`${upstreamOrigin}/range/${prefix}`, cfg);
  }) as typeof axios.get);
}

describe('HIBP range response size bound', () => {
  beforeEach(() => {
    upstreamHits = 0;
    hibpCache.clear();
    rangeInFlight.clear();
    resetCacheAccessCount();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    hibpCache.clear();
    rangeInFlight.clear();
    resetCacheAccessCount();
  });

  // ── The wiring ─────────────────────────────────────────────────────

  it('passes the named ceiling as BOTH maxContentLength and maxBodyLength', async () => {
    const getSpy = vi.spyOn(axios, 'get').mockResolvedValue({ data: 'REAL:5' });

    await fetchRangeFromHibp('5BAA6');

    const config = getSpy.mock.calls[0]?.[1];
    // `maxBodyLength` bounds the REQUEST body, which this GET does not send, so
    // it does no work today. Asserted so the intent cannot be quietly dropped as
    // "dead config" — axios enforces it itself, so it already covers any future
    // caller that gives this helper a body.
    expect(config?.maxContentLength).toBe(HIBP_MAX_RANGE_RESPONSE_BYTES);
    expect(config?.maxBodyLength).toBe(HIBP_MAX_RANGE_RESPONSE_BYTES);
    // The SSRF hardening the bound sits beside must survive the change.
    expect(config?.maxRedirects).toBe(0);
    expect(config?.timeout).toBe(10_000);
  });

  it('leaves the ceiling finite and positive, so axios actually enforces it', () => {
    // axios treats any value <= -1 as "no limit" (the check is guarded on
    // `> -1`), so a bound accidentally set to -1 or 0 would read as configured
    // while enforcing nothing.
    expect(HIBP_MAX_RANGE_RESPONSE_BYTES).toBeGreaterThan(0);
    expect(Number.isSafeInteger(HIBP_MAX_RANGE_RESPONSE_BYTES)).toBe(true);
  });

  // ── The boundary, against a real socket ────────────────────────────

  it('accepts a body of EXACTLY the ceiling', async () => {
    upstreamBody = rangeBodyOfExactly(HIBP_MAX_RANGE_RESPONSE_BYTES);
    expect(Buffer.byteLength(upstreamBody, 'utf8')).toBe(HIBP_MAX_RANGE_RESPONSE_BYTES);
    interceptToUpstream();

    await expect(fetchRangeFromHibp('AAAAA')).resolves.toBe(upstreamBody);
    expect(upstreamHits).toBe(1);
  });

  it('refuses a body ONE byte over the ceiling, naming maxContentLength', async () => {
    upstreamBody = rangeBodyOfExactly(HIBP_MAX_RANGE_RESPONSE_BYTES + 1);
    expect(Buffer.byteLength(upstreamBody, 'utf8')).toBe(HIBP_MAX_RANGE_RESPONSE_BYTES + 1);
    interceptToUpstream();

    // Not merely "it threw": the specific refusal, so a timeout, a socket reset
    // or an assertion inside the test itself cannot be mistaken for the bound
    // holding.
    await expect(fetchRangeFromHibp('BBBBB')).rejects.toMatchObject({
      code: 'ERR_BAD_RESPONSE',
      message: `maxContentLength size of ${String(HIBP_MAX_RANGE_RESPONSE_BYTES)} exceeded`,
    });
    expect(upstreamHits).toBe(1);
  });

  it('scales the refusal to the CEILING, not to how large the reply was', async () => {
    // A body four times the ceiling. Deliberately NOT asserted by counting bytes
    // the upstream managed to write: that was tried and measured, and on
    // loopback the sending side gets ~92% of a 4 MiB body into socket buffers
    // before the abort lands, which is both a 7.8% margin (a flake waiting to
    // happen) and a measurement of kernel buffering rather than of the client's
    // memory. What IS observable, and is the actual property, is that the
    // refusal names the CEILING rather than the body size — the count crossed
    // 1 MiB and stopped there — and that no response object ever reaches the
    // caller, so none of the body was handed over as data.
    upstreamBody = rangeBodyOfExactly(HIBP_MAX_RANGE_RESPONSE_BYTES * 4);
    interceptToUpstream();

    const err: unknown = await fetchRangeFromHibp('CCCCC').then(
      () => null,
      (e: unknown) => e,
    );

    expect(err).toMatchObject({
      code: 'ERR_BAD_RESPONSE',
      message: `maxContentLength size of ${String(HIBP_MAX_RANGE_RESPONSE_BYTES)} exceeded`,
    });
    // The negative: no body was delivered to the caller, at any size.
    expect((err as { response?: unknown }).response).toBeUndefined();
    expect(upstreamHits).toBe(1);
  });
});

// ── The stored copy ──────────────────────────────────────────────────

/**
 * `PwnedRangeCache.range` carries a `maxlength` matching the fetch ceiling.
 *
 * Be exact about what that is worth, because both production write sites
 * deliberately omit `runValidators` (`toolsController.getRange`'s upsert and
 * `breachSeed`'s `bulkWrite`, each with the reason written beside it: Mongoose's
 * `required` check rejects `''`, and an EMPTY range is legitimate — a prefix
 * whose every row was count-0 padding). The BINDING bound is therefore
 * `maxContentLength` on the fetch; this one is the backstop that catches a
 * future write site, and it is asserted on both surfaces where a validator can
 * actually run.
 */
describe('PwnedRangeCache.range length bound', () => {
  it('rejects a document whose range exceeds the fetch ceiling', async () => {
    await expect(
      PwnedRangeCache.create({
        prefix: 'FEDCB',
        range: 'x'.repeat(HIBP_MAX_RANGE_RESPONSE_BYTES + 1),
        source: 'hibp',
        fetchedAt: new Date(),
      }),
    ).rejects.toThrow(/range/i);

    // Refused, not truncated: a silently trimmed range would be a corrupted
    // breach corpus reported as a clean one.
    await expect(PwnedRangeCache.findOne({ prefix: 'FEDCB' }).lean()).resolves.toBeNull();
  });

  it('rejects an oversized range on an update that opts into validators', async () => {
    await expect(
      PwnedRangeCache.updateOne(
        { prefix: 'FEDCC' },
        { $set: { range: 'x'.repeat(HIBP_MAX_RANGE_RESPONSE_BYTES + 1), source: 'hibp' } },
        { upsert: true, runValidators: true },
      ),
    ).rejects.toThrow(/range/i);

    await expect(PwnedRangeCache.findOne({ prefix: 'FEDCC' }).lean()).resolves.toBeNull();
  });

  it('still stores a range at exactly the ceiling', async () => {
    await PwnedRangeCache.create({
      prefix: 'FEDCA',
      range: 'y'.repeat(HIBP_MAX_RANGE_RESPONSE_BYTES),
      source: 'hibp',
      fetchedAt: new Date(),
    });
    const doc = await PwnedRangeCache.findOne({ prefix: 'FEDCA' }).lean();
    expect(doc?.range).toHaveLength(HIBP_MAX_RANGE_RESPONSE_BYTES);
  });

  it('still caches a prefix whose every row was padding, through getRange itself', async () => {
    // Driven through the real code path, NOT by re-issuing the upsert inline: a
    // test that rewrites the production write proves only that Mongoose works.
    // A prefix with zero real breached suffixes strips to the empty string, and
    // caching it is what stops it re-hitting HIBP for ever — which is precisely
    // why that upsert runs no validators. Adding `runValidators: true` there
    // alongside the new `maxlength` makes the upsert reject on `required`, the
    // catch finds no stale row, and `getRange` throws: red on both assertions.
    hibpCache.clear();
    rangeInFlight.clear();
    vi.spyOn(axios, 'get').mockResolvedValue({
      data: `${'A'.repeat(35)}:0\r\n${'B'.repeat(35)}:0`,
    });

    await expect(getRange('FEDC9')).resolves.toBe('');
    await expect(PwnedRangeCache.findOne({ prefix: 'FEDC9' }).lean()).resolves.toMatchObject({
      range: '',
      source: 'hibp',
    });

    vi.restoreAllMocks();
    hibpCache.clear();
    rangeInFlight.clear();
  });
});

// ── What the refusal does to the caches and to the answer ────────────

describe('an oversized HIBP response is refused safely', () => {
  let user: TestUser;
  let agent: request.Agent;

  beforeEach(async () => {
    upstreamHits = 0;
    hibpCache.clear();
    rangeInFlight.clear();
    resetCacheAccessCount();
    await PwnedRangeCache.deleteMany({});
    user = await createTestUser();
    agent = request(app);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    hibpCache.clear();
    rangeInFlight.clear();
    resetCacheAccessCount();
  });

  it('propagates from getRange and writes NOTHING to L1 or L2', async () => {
    upstreamBody = rangeBodyOfExactly(HIBP_MAX_RANGE_RESPONSE_BYTES + 1);
    interceptToUpstream();
    const bytesBefore = getHibpCacheBytes();

    await expect(getRange('DDDDD')).rejects.toMatchObject({ code: 'ERR_BAD_RESPONSE' });

    // L1: no entry, and the running byte total is not left desynchronised —
    // an entry accounted for but never stored (or the reverse) would silently
    // shrink or inflate the cache budget for every later range.
    expect(hibpCache.has('DDDDD')).toBe(false);
    expect(getHibpCacheBytes()).toBe(bytesBefore);
    // L2: no persisted row, so the oversized body cannot be replayed from disk
    // on the next boot.
    await expect(PwnedRangeCache.findOne({ prefix: 'DDDDD' }).lean()).resolves.toBeNull();
    // The coalescing map drained, so the failure is not memoised for later callers.
    expect(rangeInFlight.size).toBe(0);
  });

  it('cannot overwrite or corrupt a stale L2 entry it fails to refresh', async () => {
    // The documented resilience path: a failed refresh serves the stale row
    // rather than reporting the prefix unchecked, because the corpus is
    // additive so stale-real still reports every breach it already knew. What
    // must NOT happen is the oversized body replacing that row, or landing in
    // L1 where it would be served as fresh for an hour.
    const stale = 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD:3';
    await PwnedRangeCache.create({
      prefix: 'CAFE1',
      range: stale,
      source: 'hibp',
      fetchedAt: new Date(Date.now() - 400 * 86_400_000),
    });
    upstreamBody = rangeBodyOfExactly(HIBP_MAX_RANGE_RESPONSE_BYTES + 1);
    interceptToUpstream();

    await expect(getRange('CAFE1')).resolves.toBe(stale);
    expect(upstreamHits).toBe(1);
    await expect(PwnedRangeCache.findOne({ prefix: 'CAFE1' }).lean()).resolves.toMatchObject({
      range: stale,
    });
    // Deliberately not written to L1 either, so the next request retries L3
    // instead of serving stale data for the full L1 TTL.
    expect(hibpCache.has('CAFE1')).toBe(false);
  });

  it('does not poison a subsequent good fetch for the same prefix', async () => {
    upstreamBody = rangeBodyOfExactly(HIBP_MAX_RANGE_RESPONSE_BYTES + 1);
    interceptToUpstream();
    await expect(getRange('EDCBA')).rejects.toMatchObject({ code: 'ERR_BAD_RESPONSE' });

    upstreamBody = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:9\r\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:0';
    await expect(getRange('EDCBA')).resolves.toBe('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:9');
    expect(upstreamHits).toBe(2);
    await expect(PwnedRangeCache.findOne({ prefix: 'EDCBA' }).lean()).resolves.toMatchObject({
      range: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:9',
    });
  });

  it('surfaces as a 5xx on the single endpoint — never a 200 carrying "not breached"', async () => {
    upstreamBody = rangeBodyOfExactly(HIBP_MAX_RANGE_RESPONSE_BYTES + 1);
    interceptToUpstream();
    const { token, cookie } = await getCsrfBase(agent);

    const res = await agent
      .post(`${API}/tools/check-password-breach`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', token)
      .set('Cookie', cookie)
      .send({ hashPrefix: 'ABCDE' });

    // 502, not 500, and measured rather than assumed: `handleCommonErrors`
    // switches on `err.name`, and a REAL `AxiosError` carrying no `response`
    // maps to "Error communicating with an external service" / 502. (The
    // neighbouring HIBP failure tests in `tools.test.ts` assert 500 because
    // their mocks are plain `Error`s wearing an `isAxiosError` property, so they
    // fall through to the default branch — those never exercise this mapping.)
    expect(res.status).toBe(502);
    expect(res.body.success).toBe(false);
    // THE NEGATIVE THAT MATTERS, asserted independently of which 5xx it is: a
    // 200 with an empty `data` reads to the client as "this password appears in
    // no breach", which is the one answer a failed lookup must never produce.
    expect(res.status).toBeGreaterThanOrEqual(500);
    expect(res.status).not.toBe(200);
    expect(res.body.data).toBeUndefined();
    // And nothing of the oversized body is echoed back to the caller.
    expect(JSON.stringify(res.body)).not.toContain('AAAAAAAAAA');
  });

  it('surfaces in errors[] on the batch endpoint — the prefix is absent from data', async () => {
    upstreamBody = rangeBodyOfExactly(HIBP_MAX_RANGE_RESPONSE_BYTES + 1);
    interceptToUpstream();
    const { token, cookie } = await getCsrfBase(agent);

    const res = await agent
      .post(`${API}/tools/check-password-breach/batch`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', token)
      .set('Cookie', cookie)
      .send({ hashPrefixes: ['ABCDE'] });

    expect(res.status).toBe(200);
    expect(res.body.errors).toEqual(['ABCDE']);
    // THE NEGATIVE THAT MATTERS. The prefix must be ABSENT from `data`, not
    // present-and-empty: the client reads a present key as a completed check.
    expect(Object.keys(res.body.data as Record<string, string>)).not.toContain('ABCDE');
    expect((res.body.data as Record<string, string>).ABCDE).toBeUndefined();
    expect(res.body.data).toEqual({});
  });

  it('reports only the oversized prefix, still answering the good ones in the same batch', async () => {
    // The bound must not turn one anomalous upstream response into a batch-wide
    // outage: a mixed batch answers what it can and names what it could not.
    await PwnedRangeCache.create({
      prefix: 'BEEF1',
      range: 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:4',
      source: 'seed',
      fetchedAt: new Date(),
    });
    upstreamBody = rangeBodyOfExactly(HIBP_MAX_RANGE_RESPONSE_BYTES + 1);
    interceptToUpstream();
    const { token, cookie } = await getCsrfBase(agent);

    const res = await agent
      .post(`${API}/tools/check-password-breach/batch`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', token)
      .set('Cookie', cookie)
      .send({ hashPrefixes: ['BEEF1', 'ABCDE'] });

    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({ BEEF1: 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:4' });
    expect(res.body.errors).toEqual(['ABCDE']);
  });
});
