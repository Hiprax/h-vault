import { describe, it, expect } from 'vitest';
import {
  buildSpec,
  countValidPasswords,
  unrankPassword,
  type GeneratorSpec,
} from '../src/lib/passwordGenerator';

/**
 * The uniformity proof.
 *
 * A statistical test of a random generator can only fail to reject; it is also
 * flaky by construction, which this repository forbids. Unranking makes a much
 * stronger test possible: the map from `[0, W)` to valid passwords is claimed to
 * be a BIJECTION, so enumerate every valid password by brute force, unrank every
 * index, and assert the two collections are equal as SETS and equal in SIZE.
 * Nothing random is involved and the result is total rather than probabilistic.
 *
 * It is also the best mutation defence in this module: any off-by-one in the
 * recurrence, the deficit flooring, the block arithmetic or the character
 * indexing changes `W` or breaks the bijection, and one of these assertions
 * catches it.
 */

/** Every string of `length` over the pool that meets every class minimum. */
function enumerateValid(spec: GeneratorSpec): string[] {
  const pool = spec.classes.map((cls) => cls.alphabet).join('');
  const valid: string[] = [];

  const walk = (prefix: string): void => {
    if (prefix.length === spec.length) {
      const meets = spec.classes.every((cls) => {
        const count = [...prefix].filter((char) => cls.alphabet.includes(char)).length;
        return count >= cls.minimum;
      });
      if (meets) valid.push(prefix);
      return;
    }
    for (const char of pool) walk(prefix + char);
  };

  walk('');
  return valid;
}

/**
 * Small specs built by hand rather than through `buildSpec`, so the proof covers
 * shapes the real character classes cannot produce (a two-character alphabet, a
 * class with no minimum beside one with a high minimum).
 */
const SPECS: { readonly name: string; readonly spec: GeneratorSpec }[] = [
  {
    name: 'three classes, one of each required',
    spec: {
      length: 5,
      classes: [
        { alphabet: 'ab', minimum: 1 },
        { alphabet: 'cd', minimum: 1 },
        { alphabet: 'e', minimum: 1 },
      ],
    },
  },
  {
    name: 'no minimums at all, which must reduce to plain base-N counting',
    spec: {
      length: 4,
      classes: [
        { alphabet: 'ab', minimum: 0 },
        { alphabet: 'cd', minimum: 0 },
      ],
    },
  },
  {
    name: 'asymmetric minimums over unequal alphabets',
    spec: {
      length: 4,
      classes: [
        { alphabet: 'abc', minimum: 2 },
        { alphabet: 'de', minimum: 1 },
      ],
    },
  },
  {
    name: 'a middle class carrying the only requirement',
    spec: {
      length: 4,
      classes: [
        { alphabet: 'ab', minimum: 0 },
        { alphabet: 'cd', minimum: 2 },
        { alphabet: 'ef', minimum: 0 },
      ],
    },
  },
  {
    name: 'every position spoken for by a minimum',
    spec: {
      length: 3,
      classes: [
        { alphabet: 'ab', minimum: 2 },
        { alphabet: 'cd', minimum: 1 },
      ],
    },
  },
];

describe.each(SPECS)('unranking is a bijection: $name', ({ spec }) => {
  const expected = enumerateValid(spec);
  const total = countValidPasswords(spec);

  it('counts exactly what brute force enumerates', () => {
    expect(total).toBe(BigInt(expected.length));
    expect(expected.length).toBeGreaterThan(0);
  });

  it('produces every valid password exactly once, and nothing else', () => {
    const produced: string[] = [];
    for (let index = 0n; index < total; index += 1n) {
      produced.push(unrankPassword(index, spec));
    }

    // Injective: no index maps onto another index's password.
    expect(new Set(produced).size).toBe(produced.length);
    // Surjective onto the valid set, and reaching nothing outside it.
    expect([...produced].sort()).toEqual([...expected].sort());
  });

  it('refuses an index outside the range rather than wrapping', () => {
    expect(() => unrankPassword(-1n, spec)).toThrow(RangeError);
    expect(() => unrankPassword(total, spec)).toThrow(RangeError);
  });
});

describe('the unconstrained case reduces to the old arithmetic exactly', () => {
  it('counts pool^length when nothing is required', () => {
    const spec: GeneratorSpec = {
      length: 6,
      classes: [
        { alphabet: 'abcde', minimum: 0 },
        { alphabet: 'fgh', minimum: 0 },
      ],
    };
    expect(countValidPasswords(spec)).toBe(8n ** 6n);
  });

  it('counts pool^length for the real default policy with its minimums removed', () => {
    const spec = buildSpec({
      length: 20,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true,
      excludeAmbiguous: false,
      minUppercase: 0,
      minLowercase: 0,
      minNumbers: 0,
      minSymbols: 0,
    });
    expect(countValidPasswords(spec)).toBe(88n ** 20n);
  });

  it('counts strictly fewer passwords once a minimum is imposed', () => {
    const base = {
      length: 20,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true,
      excludeAmbiguous: false,
      minUppercase: 0,
      minLowercase: 0,
      minNumbers: 0,
      minSymbols: 0,
    };
    const unconstrained = countValidPasswords(buildSpec(base));
    const constrained = countValidPasswords(buildSpec({ ...base, minNumbers: 1 }));
    expect(constrained).toBeLessThan(unconstrained);
    // And it is exactly the complement: every password with no digit at all.
    expect(unconstrained - constrained).toBe(78n ** 20n);
  });
});
