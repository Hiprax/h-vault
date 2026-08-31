/**
 * The three document limiters are sized from the operator's own configuration,
 * not from a number somebody liked.
 *
 * ## The failure these budgets exist to prevent
 *
 * A part upload is not one request. One 100 MB document is thirteen of them, a
 * user may run {@link MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER} transfers at once,
 * and a dropped socket mid-transfer is ordinary enough that a client retries. A
 * budget that ignores any of those three factors does not refuse an abusive
 * caller; it refuses a legitimate transfer PARTWAY THROUGH, leaving the bytes it
 * had already accepted sitting in the bucket until the garbage collector finds
 * them. That is the same hazard `breach-batch-budget.test.ts` was written for, and
 * the derivation below is the same shape: the NEED is computed here from the
 * shared constants and the live configuration, and the shipped budget must cover
 * it.
 *
 * Nothing here restates a literal from `rateLimiter.ts`. The two numbers that ARE
 * pinned as literals — the 120 floor and the doubling for reads — are checked
 * through the exported pure function at a size cap this deployment is not
 * configured with, which is the only way to reach the floor branch at all.
 */
import { describe, it, expect } from 'vitest';
import {
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER,
} from '@hvault/shared';
import { config } from '../src/config/index.js';
import {
  DOCUMENT_PART_RATE_LIMIT_MAX,
  DOCUMENT_RATE_LIMIT_WINDOW_MS,
  DOCUMENT_READ_RATE_LIMIT_MAX,
  DOCUMENT_UPLOAD_RATE_LIMIT_MAX,
  documentPartBudgetFor,
  documentPartLimiter,
  documentReadLimiter,
  documentUploadLimiter,
} from '../src/middleware/rateLimiter.js';

const BYTES_PER_MB = 1024 * 1024;

/** Parts one worst-case transfer costs under THIS deployment's configured cap. */
const partsPerTransfer = Math.ceil(
  (config.MAX_DOCUMENT_SIZE_MB * BYTES_PER_MB) / DOCUMENT_PLAINTEXT_CHUNK_BYTES,
);

describe('documentPartLimiter budget', () => {
  it('covers three concurrent worst-case transfers within a single window', () => {
    // The floor with no retries at all: a user running the maximum number of
    // maximum-sized transfers must be able to deliver every part once. A budget
    // below this 429s a transfer the server itself told the client to start.
    const withoutRetries = partsPerTransfer * MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER;
    expect(withoutRetries).toBeGreaterThan(0);
    expect(DOCUMENT_PART_RATE_LIMIT_MAX).toBeGreaterThanOrEqual(withoutRetries);
  });

  it('still covers them when every part is retried', () => {
    // A part is the one request in this feature a client retries as a matter of
    // course. Doubling the need is the weakest honest statement of that, and the
    // shipped budget allows more; what must never hold is a budget that only
    // covers the first delivery of every part.
    const withOneRetryEach = partsPerTransfer * MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER * 2;
    expect(DOCUMENT_PART_RATE_LIMIT_MAX).toBeGreaterThanOrEqual(withOneRetryEach);
  });

  it('derives from the configured cap rather than from a fixed number', () => {
    // The property the derivation exists for: raise the operator's size cap and
    // the budget must rise with it, or the largest document the operator allows
    // is the one that cannot be uploaded. Checked through the exported function
    // at TWO caps, so a constant masquerading as a derivation fails here.
    const small = documentPartBudgetFor(DOCUMENT_PLAINTEXT_CHUNK_BYTES * 20);
    const large = documentPartBudgetFor(DOCUMENT_PLAINTEXT_CHUNK_BYTES * 200);
    expect(large).toBeGreaterThan(small);
    expect(large).toBe(200 * MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER * 4);
  });

  it('floors a tiny configured cap at the same budget a default deployment gets', () => {
    // At `MAX_DOCUMENT_SIZE_MB=1` the derivation yields 1 x 3 x 4 = 12 requests
    // per fifteen minutes, which would throttle a small-cap deployment into
    // uselessness. The floor is the branch no test could otherwise reach, because
    // this suite runs at the default cap.
    expect(documentPartBudgetFor(1 * BYTES_PER_MB)).toBe(120);
    expect(documentPartBudgetFor(0)).toBe(120);
  });
});

describe('documentReadLimiter budget', () => {
  it('is the part budget doubled, because a download is one request per segment', () => {
    // A user reads more than they write and a whole-file download costs one
    // request per segment, so the read budget must be at least as generous as
    // the write one. Stated as the relationship rather than as a number.
    expect(DOCUMENT_READ_RATE_LIMIT_MAX).toBe(DOCUMENT_PART_RATE_LIMIT_MAX * 2);
    expect(DOCUMENT_READ_RATE_LIMIT_MAX).toBeGreaterThanOrEqual(
      partsPerTransfer * MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER * 2,
    );
  });

  it('never falls below 240, the doubled floor', () => {
    expect(documentPartBudgetFor(1 * BYTES_PER_MB) * 2).toBe(240);
  });
});

describe('documentUploadLimiter budget', () => {
  it('covers more complete transfers than a user can have open at once', () => {
    // Init, complete and abort are three requests per transfer no matter how big
    // the file is, so this one is flat — but it still has to be comfortably above
    // the concurrency the server itself permits.
    const requestsPerTransfer = 3;
    expect(Math.floor(DOCUMENT_UPLOAD_RATE_LIMIT_MAX / requestsPerTransfer)).toBeGreaterThanOrEqual(
      MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER * 10,
    );
  });
});

describe('the three limiters are three limiters', () => {
  it('exports a distinct middleware per limiter', () => {
    // `tests/support/routeTable.ts` reads the limiter column by FUNCTION
    // IDENTITY through a `Map` keyed by the function. Three exports sharing one
    // object collapse that map to one entry, every document route then reports
    // one arbitrary limiter name, and the column stops being a check. Hoisting
    // `noopIfNonProduction()` out of the three call sites is exactly how that
    // would happen.
    const distinct = new Set([documentUploadLimiter, documentPartLimiter, documentReadLimiter]);
    expect(distinct.size).toBe(3);
  });

  it('spends every budget over the same fifteen-minute window', () => {
    expect(DOCUMENT_RATE_LIMIT_WINDOW_MS).toBe(15 * 60 * 1000);
  });
});
