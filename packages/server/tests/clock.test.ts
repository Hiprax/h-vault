/**
 * The test clock's own contract.
 *
 * This seam is harness code, and harness code that is wrong is worse than absent:
 * a clock that fails to hand itself back leaves every LATER file in that worker
 * running against an instant that stopped somewhere inside a test it has never
 * heard of — an order-dependent failure produced by the very mechanism installed
 * to remove one. So the properties asserted here are the ones whose absence would
 * be invisible until a shuffled run in some other file went red.
 */
import { afterEach, describe, expect, it } from 'vitest';
import {
  FROZEN_INSTANT_ISO,
  FROZEN_INSTANT_MS,
  advanceClockBy,
  installTestClock,
  setClockTo,
  uninstallTestClock,
  withTestClock,
} from './clock.js';

afterEach(() => {
  // Belt and braces: a test below that fails BEFORE its own restore must not take
  // the rest of this file with it.
  uninstallTestClock();
});

describe('the test clock', () => {
  it('freezes where it already is, so a second process cannot drift from it', () => {
    const before = Date.now();
    installTestClock();
    const frozen = Date.now();

    // The default installs at the real "now" rather than jumping to a fixed
    // instant, and that is what keeps mongod's clock — which this worker cannot
    // freeze — within milliseconds of the one under test.
    expect(frozen).toBeGreaterThanOrEqual(before);
    expect(frozen - before).toBeLessThan(1_000);

    // Frozen means frozen: reading it repeatedly must not advance it. This is the
    // property the whole seam exists for, and it is what makes "the server must
    // see a strictly later second" a decision rather than a race.
    expect(Date.now()).toBe(frozen);
    expect(new Date().getTime()).toBe(frozen);
  });

  it('installs at an explicit instant when one is given', () => {
    installTestClock({ at: FROZEN_INSTANT_MS });
    expect(Date.now()).toBe(FROZEN_INSTANT_MS);
    expect(new Date().toISOString()).toBe(FROZEN_INSTANT_ISO);
  });

  it('keeps the pinned instant clear of both TOTP step boundaries', () => {
    // Not decoration: the pinned instant is documented as usable for a 30-second
    // TOTP step, and a code generated within 3 seconds of a boundary can be a
    // different step by the time the server validates it. If someone re-pins this
    // constant to a rounder-looking value, this is what says no.
    const intoStep = FROZEN_INSTANT_MS % 30_000;
    expect(intoStep).toBeGreaterThanOrEqual(3_000);
    expect(intoStep).toBeLessThanOrEqual(27_000);
  });

  it('advances only when told to, and by exactly the amount asked for', () => {
    installTestClock({ at: FROZEN_INSTANT_MS });
    advanceClockBy(1_100);
    expect(Date.now()).toBe(FROZEN_INSTANT_MS + 1_100);
    advanceClockBy(0);
    expect(Date.now()).toBe(FROZEN_INSTANT_MS + 1_100);
    setClockTo(FROZEN_INSTANT_MS + 60_000);
    expect(Date.now()).toBe(FROZEN_INSTANT_MS + 60_000);
  });

  it('refuses to wind backwards, naming what to do instead', () => {
    installTestClock({ at: FROZEN_INSTANT_MS });
    // A negative advance is always a mistake and it is a silent one: a token
    // minted "later" would end up dated before its issuer, and the resulting 401
    // would be attributed to the code under test.
    expect(() => {
      advanceClockBy(-1);
    }).toThrow(/non-negative/);
    expect(() => {
      advanceClockBy(Number.NaN);
    }).toThrow(/non-negative/);
    expect(() => {
      advanceClockBy(Number.POSITIVE_INFINITY);
    }).toThrow(/non-negative/);
    // And the clock is untouched by the refusal.
    expect(Date.now()).toBe(FROZEN_INSTANT_MS);
  });

  it('leaves real timers running, so real I/O still settles', async () => {
    // The reason the default is `toFake: ['Date']`. A bare `vi.useFakeTimers()`
    // also fakes `setTimeout`, and in a suite that awaits a supertest round trip
    // or a mongoose query that means the await never settles — a hang rather than
    // a failure, which is the worst thing a harness can do.
    installTestClock();
    const frozen = Date.now();
    await new Promise((resolve) => setTimeout(resolve, 5));
    // The promise resolved (a faked timer would never have fired) and the clock
    // did not move while it did.
    expect(Date.now()).toBe(frozen);
  });

  it('restores the real clock after the body, and after a body that throws', async () => {
    const realBefore = Date.now();
    await withTestClock({ at: FROZEN_INSTANT_MS }, () => {
      expect(Date.now()).toBe(FROZEN_INSTANT_MS);
    });
    expect(Date.now()).toBeGreaterThanOrEqual(realBefore);
    expect(Date.now()).not.toBe(FROZEN_INSTANT_MS);

    // The half that matters. Without the `finally`, a failing assertion inside the
    // body would leave this worker frozen for every file after it.
    await expect(
      withTestClock({ at: FROZEN_INSTANT_MS }, () => {
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
    expect(Date.now()).not.toBe(FROZEN_INSTANT_MS);
    expect(Date.now()).toBeGreaterThanOrEqual(realBefore);
  });

  it('returns the body’s value, so a caller can drive a request through it', async () => {
    const result = await withTestClock({ at: FROZEN_INSTANT_MS }, () => {
      advanceClockBy(2_000);
      return Date.now();
    });
    expect(result).toBe(FROZEN_INSTANT_MS + 2_000);
  });

  it('fakes the timer functions too when asked, and only then', () => {
    let fired = false;
    installTestClock({ at: FROZEN_INSTANT_MS, timers: 'all' });
    setTimeout(() => {
      fired = true;
    }, 10);
    // Under `timers: 'all'` the callback is queued and NOT run by the event loop,
    // so moving the wall clock past its deadline must not fire it — which is what
    // lets a test model a suspended machine (the clock jumped, no task ran).
    advanceClockBy(1_000);
    expect(fired).toBe(false);
  });

  it('is safe to uninstall when none was installed', () => {
    // Called unconditionally from an `afterEach`, including on a test that never
    // installed one.
    expect(() => {
      uninstallTestClock();
    }).not.toThrow();
  });
});
