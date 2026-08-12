/**
 * `classifyStrength` and `formatCrackTime`, as properties.
 *
 * These two turn an entropy figure into the two things a user reads about a
 * generated password: a band ("Strong") and a duration ("3 thousand years"). Both
 * are pure functions of a number that the generator can push a long way — 128
 * characters over an 88-character pool is ~827 bits — so the interesting failures
 * are not wrong labels but broken arithmetic:
 *
 *   - a NON-MONOTONIC mapping, where adding a character to a password makes the
 *     UI report LESS strength or a SHORTER crack time. That is worse than a wrong
 *     number: it tells the user the opposite of the truth about a choice they are
 *     making right now.
 *   - `Infinity` or `NaN` reaching the DOM. `2 ** (bits - 1)` overflows a double
 *     at ~1025 bits, which is why the implementation works in log10 space; a
 *     regression to the naive form renders "Infinity years" or "NaN years".
 *
 * `formatCrackTime` returns a STRING, so monotonicity needs an ordering over its
 * output. `durationRank` below is that ordering, and it is a specification of the
 * output GRAMMAR rather than a copy of the computation: it knows the unit words
 * and their sequence, not how many guesses a bit is worth. A value it cannot
 * parse fails the property, which makes "the formatter grew a new output shape
 * nobody ordered" a test failure rather than a silent hole.
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  OFFLINE_GPU_GUESSES_PER_SEC,
  STRENGTH_LABELS,
  classifyStrength,
  formatCrackTime,
  passwordEntropyBits,
} from '../../src/utils/passwordEntropy';
import { PROPERTY_RUNS, propertyBanner, propertyRun } from '../../../../tests/harness/property.js';

/** The unit words `formatCrackTime` can emit, in increasing order of duration. */
const UNIT_ORDER = ['second', 'minute', 'hour', 'day', 'month', 'year'] as const;
/** The scale words `humanizeYears` can emit, in increasing order. */
const SCALE_ORDER = ['thousand', 'million', 'billion', 'trillion'] as const;

/**
 * A comparable rank for one of `formatCrackTime`'s outputs: `[tier, magnitude]`,
 * compared lexicographically.
 *
 * Returns `null` for anything outside the documented grammar, which the
 * properties below treat as a failure.
 */
function durationRank(text: string): [number, number] | null {
  if (text === 'less than a second') return [0, 0];
  if (text === 'forever') return [Number.MAX_SAFE_INTEGER, 0];

  const plain = text.replace(/,/g, '');

  const scientific = /^~(\d+(?:\.\d+)?) x 10\^(\d+) years$/.exec(plain);
  if (scientific) {
    // Ordered by exponent first, mantissa second — the mantissa is always in
    // [1, 10), so exponent + mantissa/10 is a faithful single number.
    return [
      1 + UNIT_ORDER.length + SCALE_ORDER.length,
      Number(scientific[2]) + Number(scientific[1]) / 10,
    ];
  }

  const scaled = /^(\d+(?:\.\d+)?) (thousand|million|billion|trillion) years$/.exec(plain);
  if (scaled) {
    const index = SCALE_ORDER.indexOf(scaled[2] as (typeof SCALE_ORDER)[number]);
    return [1 + UNIT_ORDER.length + index, Number(scaled[1])];
  }

  const counted = /^(\d+(?:\.\d+)?) (second|minute|hour|day|month|year)s?$/.exec(plain);
  if (counted) {
    const index = UNIT_ORDER.indexOf(counted[2] as (typeof UNIT_ORDER)[number]);
    return [1 + index, Number(counted[1])];
  }

  return null;
}

function rankOrFail(text: string): [number, number] {
  const rank = durationRank(text);
  expect(
    rank,
    `${propertyBanner()} — formatCrackTime emitted an unparseable form: ${text}`,
  ).not.toBeNull();
  return rank ?? [0, 0];
}

const compareRank = (a: [number, number], b: [number, number]): number =>
  a[0] === b[0] ? a[1] - b[1] : a[0] - b[0];

/** The band edges `classifyStrength` documents, plus the unit boundaries of the formatter. */
const BOUNDARIES = [0, 1, 40, 64, 80, 112, 827, 1_024, 1_025];

/**
 * Bits a real generator can produce, plus the extremes that break naive maths,
 * plus a dense neighbourhood around every band edge.
 *
 * The neighbourhood arm is load-bearing for the monotonicity properties. Two
 * independent draws from a 0-1024 range almost never straddle a 24-bit-wide band,
 * so a swapped pair of thresholds went UNDETECTED by an earlier version of this
 * generator (measured: the mutation was caught only by the composed property at
 * the bottom of the file). Sampling within ±1 of each edge, and comparing a
 * SORTED sample rather than a pair, is what makes the claim testable.
 */
const bitsArbitrary = fc.oneof(
  fc.double({ min: 0, max: 1_024, noNaN: true }),
  fc.double({ min: 0, max: 4_096, noNaN: true }),
  fc.constantFrom(...BOUNDARIES, 39.999, 63.999, 79.999, 111.999, 10_000),
  fc
    .tuple(fc.constantFrom(...BOUNDARIES), fc.double({ min: -1, max: 1, noNaN: true }))
    .map(([edge, delta]) => Math.max(0, edge + delta)),
);

describe('the duration ordering this file compares against', () => {
  it('orders the documented output grammar, and refuses anything else', () => {
    // The oracle is pinned before it is relied on: an ordering that got the unit
    // sequence wrong would make every monotonicity assertion below vacuous.
    const ascending = [
      'less than a second',
      '1 second',
      '59 seconds',
      '1 minute',
      '2 hours',
      '3 days',
      '4 months',
      '5 years',
      '999 years',
      '1 thousand years',
      '2.5 million years',
      '1 billion years',
      '999 trillion years',
      '~1.5 x 10^16 years',
      '~9.9 x 10^99 years',
      'forever',
    ];
    for (let index = 1; index < ascending.length; index++) {
      const previous = rankOrFail(ascending[index - 1]!);
      const current = rankOrFail(ascending[index]!);
      expect(
        compareRank(previous, current),
        `${ascending[index - 1]!} < ${ascending[index]!}`,
      ).toBeLessThan(0);
    }
    expect(durationRank('a fortnight')).toBeNull();
    expect(durationRank('')).toBeNull();
  });
});

describe('classifyStrength', () => {
  it('never decreases as entropy increases', () => {
    // A SORTED SAMPLE rather than a pair: every adjacent step is checked, so one
    // run examines up to nine transitions instead of one, and a swapped pair of
    // thresholds cannot survive by being narrower than the gap between two random
    // draws.
    fc.assert(
      fc.property(fc.array(bitsArbitrary, { minLength: 2, maxLength: 10 }), (sample) => {
        const ascending = [...sample].sort((a, b) => a - b);
        for (let index = 1; index < ascending.length; index++) {
          const lower = ascending[index - 1]!;
          const upper = ascending[index]!;
          expect(
            classifyStrength(lower).level,
            `${propertyBanner()} — ${String(lower)} bits banded above ${String(upper)} bits`,
          ).toBeLessThanOrEqual(classifyStrength(upper).level);
        }
      }),
      propertyRun(),
    );
  });

  it('always returns one of the five declared labels, matching its own level', () => {
    fc.assert(
      fc.property(bitsArbitrary, (bits) => {
        const { level, label } = classifyStrength(bits);
        expect(STRENGTH_LABELS, propertyBanner()).toContain(label);
        expect(label, propertyBanner()).toBe(STRENGTH_LABELS[level]);
        expect(Number.isInteger(level), propertyBanner()).toBe(true);
      }),
      propertyRun(),
    );
  });

  it('bands a non-finite figure as the WEAKEST, never the strongest', () => {
    // Fail-safe direction, and it is the one that matters: a `NaN` from a broken
    // charset calculation must never be presented as "Very Strong".
    for (const bits of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      const { level, label } = classifyStrength(bits);
      // Infinity is genuinely stronger than any threshold, so only NaN and -Inf
      // are required to land at 0; +Infinity must simply not be NaN-banded.
      if (Number.isNaN(bits) || bits === Number.NEGATIVE_INFINITY) {
        expect(level, `bits=${String(bits)}`).toBe(0);
        expect(label, `bits=${String(bits)}`).toBe('Very Weak');
      } else {
        expect(level, `bits=${String(bits)}`).toBe(0);
      }
    }
  });
});

describe('formatCrackTime', () => {
  it('never emits Infinity, NaN or an exponent artifact, for any input', () => {
    fc.assert(
      fc.property(
        fc.oneof(bitsArbitrary, fc.constantFrom(Number.NaN, Number.POSITIVE_INFINITY, -1, -1e9)),
        (bits) => {
          const text = formatCrackTime(bits);
          expect(text, propertyBanner()).toBeTypeOf('string');
          expect(text.length, propertyBanner()).toBeGreaterThan(0);
          expect(text, propertyBanner()).not.toMatch(/Infinity|NaN|undefined|e\+\d/);
        },
      ),
      propertyRun(),
    );
  });

  it('emits only forms the documented grammar covers', () => {
    fc.assert(
      fc.property(bitsArbitrary, (bits) => {
        rankOrFail(formatCrackTime(bits));
      }),
      propertyRun(),
    );
  });

  it('never decreases as entropy increases, at a fixed attacker rate', () => {
    fc.assert(
      fc.property(fc.array(bitsArbitrary, { minLength: 2, maxLength: 10 }), (sample) => {
        const ascending = [...sample].sort((a, b) => a - b);
        for (let index = 1; index < ascending.length; index++) {
          const low = ascending[index - 1]!;
          const high = ascending[index]!;
          expect(
            compareRank(rankOrFail(formatCrackTime(low)), rankOrFail(formatCrackTime(high))),
            `${propertyBanner()} — ${String(low)} bits reported "${formatCrackTime(low)}" but ${String(high)} bits reported "${formatCrackTime(high)}"`,
          ).toBeLessThanOrEqual(0);
        }
      }),
      propertyRun(),
    );
  });

  it('never increases as the attacker gets faster', () => {
    // The other axis of the same claim. A rate that appears with the wrong sign
    // in the log-space subtraction would pass every fixed-rate assertion above.
    fc.assert(
      fc.property(
        bitsArbitrary,
        fc.double({ min: 1, max: 1e18, noNaN: true }),
        fc.double({ min: 1, max: 1e18, noNaN: true }),
        (bits, rateA, rateB) => {
          const [slow, fast] = rateA <= rateB ? [rateA, rateB] : [rateB, rateA];
          const slowRank = rankOrFail(formatCrackTime(bits, slow));
          const fastRank = rankOrFail(formatCrackTime(bits, fast));
          expect(compareRank(fastRank, slowRank), propertyBanner()).toBeLessThanOrEqual(0);
        },
      ),
      propertyRun({ numRuns: Math.ceil(PROPERTY_RUNS / 2) }),
    );
  });

  it('answers "forever" only for an attacker who cannot guess at all', () => {
    fc.assert(
      fc.property(
        bitsArbitrary,
        fc.constantFrom(0, -1, Number.NaN, Number.POSITIVE_INFINITY),
        (bits, rate) => {
          const text = formatCrackTime(bits, rate);
          if (bits > 0) {
            expect(text, propertyBanner()).toBe('forever');
          }
        },
      ),
      propertyRun({ numRuns: 40 }),
    );
  });

  it('agrees with the entropy the generator would report for the same options', () => {
    // The two functions are used together on one screen: `passwordEntropyBits`
    // feeds both, so a length/pool pair must produce a band and a duration that
    // move together. Ties them into one property rather than testing each in a
    // vacuum.
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 128 }),
        fc.integer({ min: 2, max: 88 }),
        fc.integer({ min: 1, max: 128 }),
        (length, poolSize, extra) => {
          const shorter = passwordEntropyBits(length, poolSize);
          const longer = passwordEntropyBits(length + extra, poolSize);
          expect(longer, propertyBanner()).toBeGreaterThanOrEqual(shorter);
          expect(classifyStrength(longer).level, propertyBanner()).toBeGreaterThanOrEqual(
            classifyStrength(shorter).level,
          );
          expect(
            compareRank(
              rankOrFail(formatCrackTime(shorter, OFFLINE_GPU_GUESSES_PER_SEC)),
              rankOrFail(formatCrackTime(longer, OFFLINE_GPU_GUESSES_PER_SEC)),
            ),
            propertyBanner(),
          ).toBeLessThanOrEqual(0);
        },
      ),
      propertyRun(),
    );
  });
});
