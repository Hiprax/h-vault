import { describe, it, expect } from 'vitest';

import { createStorageBreaker } from '../src/utils/storageBreaker.js';

/**
 * `utils/storageBreaker.ts` — the circuit breaker shared by every bulk walk over
 * object storage (the hourly collector's three sweeps, the empty-trash request,
 * and the nightly auto-purge).
 *
 * ## Why it is worth a file of its own
 *
 * The three call sites each pin the breaker's EFFECT — how many deletes are
 * attempted before a walk gives up, and that the rows past that point are left
 * untouched. What none of them can see is the boundary itself, because a walk
 * only ever observes "stopped at five". A threshold moved by one is a change to
 * how long an outage holds a fifteen-minute lock or a user's request open, and it
 * would be invisible to every one of those tests until it was moved by enough to
 * change a count they happen to assert.
 *
 * So this file walks the counter one call at a time across `n-1`, `n` and `n+1`,
 * and pins the two properties the call sites depend on and cannot state: that a
 * success resets the consecutive run while the TOTAL keeps climbing, and that two
 * breakers share nothing.
 *
 * The threshold is restated as a literal rather than imported. The module keeps
 * its own constant private precisely so that a test cannot agree with it by
 * construction — a test that read the number would pass on any value it was
 * given, which is the one thing a boundary test must not do.
 */
const BREAKER_THRESHOLD = 5;

describe('createStorageBreaker', () => {
  it('opens closed: a fresh breaker has refused nothing and counted nothing', () => {
    const breaker = createStorageBreaker();

    expect(breaker.isRefusing()).toBe(false);
    expect(breaker.failures).toBe(0);
  });

  it('holds at one failure below the threshold and trips exactly on it', () => {
    const breaker = createStorageBreaker();

    for (let attempt = 1; attempt < BREAKER_THRESHOLD; attempt += 1) {
      breaker.recordFailure();
      // `n-1`: four refusals in a row is a bad patch of keys, not a dead engine,
      // and a walk that stopped here would strand rows for no reason.
      expect(breaker.isRefusing(), `it must not trip on failure ${String(attempt)}`).toBe(false);
    }

    breaker.recordFailure();
    expect(breaker.isRefusing(), 'it must trip on the threshold itself').toBe(true);
    expect(breaker.failures).toBe(BREAKER_THRESHOLD);
  });

  it('stays tripped once it has tripped', () => {
    // `n+1`. Nothing in the callers clears a breaker mid-walk, and if anything
    // ever did, a walk would resume against the same dead engine it just gave up
    // on — so the latch is the property, not an accident of the arithmetic.
    const breaker = createStorageBreaker();
    for (let attempt = 0; attempt < BREAKER_THRESHOLD + 1; attempt += 1) breaker.recordFailure();

    expect(breaker.isRefusing()).toBe(true);
    expect(breaker.failures).toBe(BREAKER_THRESHOLD + 1);
  });

  it('never trips on failures that are separated by a success, while still counting them all', () => {
    // The whole reason the counter is CONSECUTIVE. A walk over an account with
    // individually unreachable keys scattered through it must finish and report
    // every one of them; only an engine that is refusing everything stops it.
    const breaker = createStorageBreaker();

    for (let round = 0; round < BREAKER_THRESHOLD * 2; round += 1) {
      breaker.recordFailure();
      breaker.recordSuccess();
      expect(breaker.isRefusing(), `it must not trip in round ${String(round)}`).toBe(false);
    }

    // The total is the number that reaches the response body and the log line, so
    // a reset that cleared it too would under-report an outage as a clean run.
    expect(breaker.failures).toBe(BREAKER_THRESHOLD * 2);
  });

  it('is reset by a success on the very last call before it would have tripped', () => {
    const breaker = createStorageBreaker();
    for (let attempt = 0; attempt < BREAKER_THRESHOLD - 1; attempt += 1) breaker.recordFailure();

    breaker.recordSuccess();
    breaker.recordFailure();

    // Five failures recorded, but the run was broken, so the walk continues.
    expect(breaker.isRefusing()).toBe(false);
    expect(breaker.failures).toBe(BREAKER_THRESHOLD);
  });

  it('gives every walk its own counter, sharing nothing between them', () => {
    // The defect this refuses is a module-level counter, which is what the
    // extracted code looked like before it was a factory: the collector runs
    // hourly for the lifetime of the process, so a shared counter would leave the
    // SECOND run starting already tripped after one bad hour, and would let a
    // user's empty-trash request trip the nightly cron's breaker.
    const first = createStorageBreaker();
    const second = createStorageBreaker();

    for (let attempt = 0; attempt < BREAKER_THRESHOLD; attempt += 1) first.recordFailure();

    expect(first.isRefusing()).toBe(true);
    expect(second.isRefusing(), 'a second walk must start closed').toBe(false);
    expect(second.failures).toBe(0);
  });

  it('does not let a caller write to the failure total it reports', () => {
    // `failures` is the number that goes into a response body and an audit row.
    // It is a getter over a closed-over count for that reason: a plain mutable
    // field would let a caller "correct" it and report a walk it did not do.
    const breaker = createStorageBreaker();
    breaker.recordFailure();

    expect(() => {
      (breaker as { failures: number }).failures = 0;
    }).toThrow(TypeError);
    expect(breaker.failures).toBe(1);
  });
});
