/**
 * breachBatchLimiter sizing.
 *
 * The batch breach endpoint checks up to HIBP_BATCH_MAX_PREFIXES prefixes per
 * request, so a full scan of the worst-case vault — every item holding a distinct
 * password, hence a distinct 5-char prefix — costs
 * `ceil(MAX_ITEMS_PER_USER / HIBP_BATCH_MAX_PREFIXES)` requests. The limiter MUST
 * allow at least that many in one window, or a legitimate scan is 429'd part-way
 * and the unchecked passwords are reported as unchecked instead of safe — a
 * partial result, never a false "no breaches". Derived from the real shared
 * constants so a change to any of them fails here rather than silently
 * reintroducing the hazard.
 */
import { describe, it, expect } from 'vitest';
import { MAX_ITEMS_PER_USER, HIBP_BATCH_MAX_PREFIXES } from '@hvault/shared';
import { BREACH_BATCH_RATE_LIMIT_MAX } from '../src/middleware/rateLimiter.js';

describe('breachBatchLimiter budget', () => {
  it('covers a full-vault scan of an all-distinct vault within a single window', () => {
    const worstCaseBatches = Math.ceil(MAX_ITEMS_PER_USER / HIBP_BATCH_MAX_PREFIXES);
    expect(BREACH_BATCH_RATE_LIMIT_MAX).toBeGreaterThanOrEqual(worstCaseBatches);
  });
});
