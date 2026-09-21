import { describe, it, expect } from 'vitest';
import {
  MAX_PASSWORD_CLASS_MINIMUM,
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
} from '@hvault/shared';
import {
  PasswordGeneratorError,
  assertDisjointClasses,
  buildSpec,
  cellAt,
  charAt,
  countValidPasswords,
  generatePassphrase,
  generatePassword,
  passwordEntropyBitsForOptions,
  unrankPassword,
  type PasswordGenOptionsLike,
} from '../src/lib/passwordGenerator';
import { DIGITS, LOWER, SYMBOLS, UPPER, buildCharset } from '../src/utils/passwordEntropy';

const BASE: PasswordGenOptionsLike = {
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

const countOf = (value: string, alphabet: string): number =>
  [...value].filter((char) => alphabet.includes(char)).length;

describe('buildSpec', () => {
  it('keeps the classes in the order buildCharset concatenates them', () => {
    const spec = buildSpec(BASE);
    expect(spec.classes.map((cls) => cls.alphabet)).toEqual([UPPER, LOWER, DIGITS, SYMBOLS]);
  });

  it('drops a disabled class entirely, which is what makes its minimum inert', () => {
    const spec = buildSpec({ ...BASE, numbers: false, minNumbers: 5 });
    expect(spec.classes).toHaveLength(3);
    expect(spec.classes.some((cls) => cls.alphabet === DIGITS)).toBe(false);
  });

  it('clamps a minimum no wire bound has ever rejected', () => {
    // Nothing narrows on the wire, deliberately, so the generator is where an
    // out-of-range stored value is repaired.
    const spec = buildSpec({ ...BASE, minNumbers: 60 });
    const digits = spec.classes.find((cls) => cls.alphabet === DIGITS);
    expect(digits?.minimum).toBe(MAX_PASSWORD_CLASS_MINIMUM);
  });

  it('clamps a length outside the supported range', () => {
    expect(buildSpec({ ...BASE, length: 1 }).length).toBe(MIN_PASSWORD_LENGTH);
    expect(buildSpec({ ...BASE, length: 9999 }).length).toBe(MAX_PASSWORD_LENGTH);
  });

  it('refuses a policy with no character class', () => {
    expect(() =>
      buildSpec({ ...BASE, uppercase: false, lowercase: false, numbers: false, symbols: false }),
    ).toThrow(PasswordGeneratorError);
  });

  it('refuses a password too short to hold everything it requires', () => {
    // Four classes at the cap need 20 characters; 8 is the shortest allowed.
    const error = (() => {
      try {
        buildSpec({
          ...BASE,
          length: 8,
          minUppercase: 5,
          minLowercase: 5,
          minNumbers: 5,
          minSymbols: 5,
        });
        return null;
      } catch (thrown) {
        return thrown as PasswordGeneratorError;
      }
    })();
    expect(error?.reason).toBe('length-too-short');
  });

  it('leaves every real class non-empty after the ambiguous-character exclusion', () => {
    // The counting assumes every enabled class can contribute a character. The
    // excluded set is 'lI1O0', which takes two characters from the digits and
    // one each from the two letter classes, so none of them can empty. Adding a
    // character to AMBIGUOUS that empties a class would turn this red.
    for (const cls of buildSpec({ ...BASE, excludeAmbiguous: true }).classes) {
      expect(cls.alphabet.length).toBeGreaterThan(0);
    }
  });

  it('agrees with buildCharset about the size of the pool', () => {
    for (const excludeAmbiguous of [false, true]) {
      const options = { ...BASE, excludeAmbiguous };
      const spec = buildSpec(options);
      const pooled = spec.classes.reduce((sum, cls) => sum + cls.alphabet.length, 0);
      expect(pooled).toBe(buildCharset(options).length);
    }
  });
});

describe('assertDisjointClasses', () => {
  it('accepts the real classes, which are disjoint', () => {
    const spec = buildSpec(BASE);
    const pool = spec.classes.reduce((sum, cls) => sum + cls.alphabet.length, 0);
    expect(() => assertDisjointClasses(spec.classes, pool)).not.toThrow();
  });

  it('refuses two classes that share a character', () => {
    // The precondition the whole counting rests on. A symbol that is also a
    // letter would make the count over-report, the sampling non-uniform and the
    // reported entropy an over-statement, with nothing else noticing.
    expect(() =>
      assertDisjointClasses(
        [
          { alphabet: 'abc', minimum: 0 },
          { alphabet: 'cde', minimum: 0 },
        ],
        6,
      ),
    ).toThrow(/overlap/);
  });

  it('refuses a class that repeats a character within itself', () => {
    expect(() => assertDisjointClasses([{ alphabet: 'aab', minimum: 0 }], 3)).toThrow(/overlap/);
  });

  it('refuses a partition that disagrees with the shared pool builder', () => {
    // The two modules have to describe the same pool; a divergence between them
    // would be invisible in every other test.
    expect(() => assertDisjointClasses([{ alphabet: 'abc', minimum: 0 }], 4)).toThrow(/overlap/);
  });
});

describe('cellAt and charAt', () => {
  it('reads a present cell and treats an absent one as no count', () => {
    expect(cellAt([3n, 4n], 1)).toBe(4n);
    expect(cellAt([3n], 7)).toBe(0n);
  });

  it('reads a character and refuses an index outside the alphabet', () => {
    expect(charAt('abc', 2)).toBe('c');
    expect(() => charAt('abc', 3)).toThrow(RangeError);
  });
});

describe('unrankPassword, golden values', () => {
  // These pin the class order, the deficit flooring and the character indexing
  // all at once: any one of the three changing moves the string.
  it('maps index 0 to the first password the ordering defines', () => {
    const spec = buildSpec({ ...BASE, minNumbers: 1, minSymbols: 1 });
    expect(unrankPassword(0n, spec)).toBe('AAAAAAAAAAAAAAAAAA0!');
  });

  it('maps index 0 to an all-uppercase password when nothing is required', () => {
    const spec = buildSpec(BASE);
    expect(unrankPassword(0n, spec)).toBe('A'.repeat(20));
  });

  it('maps the last index to the last password the ordering defines', () => {
    const spec = buildSpec(BASE);
    const last = countValidPasswords(spec) - 1n;
    expect(unrankPassword(last, spec)).toBe('?'.repeat(20));
  });
});

describe('generatePassword', () => {
  it('honours every class minimum, on every draw', () => {
    const options: PasswordGenOptionsLike = {
      ...BASE,
      length: 16,
      minUppercase: 2,
      minLowercase: 1,
      minNumbers: 3,
      minSymbols: 2,
    };
    for (let i = 0; i < 100; i += 1) {
      const password = generatePassword(options);
      expect(password).toHaveLength(16);
      expect(countOf(password, UPPER)).toBeGreaterThanOrEqual(2);
      expect(countOf(password, LOWER)).toBeGreaterThanOrEqual(1);
      expect(countOf(password, DIGITS)).toBeGreaterThanOrEqual(3);
      expect(countOf(password, SYMBOLS)).toBeGreaterThanOrEqual(2);
    }
  });

  it('draws only from the selected pool', () => {
    const options = { ...BASE, symbols: false, excludeAmbiguous: true };
    const pool = buildCharset(options);
    for (let i = 0; i < 50; i += 1) {
      for (const char of generatePassword(options)) expect(pool).toContain(char);
    }
  });

  it('produces different passwords across calls', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 50; i += 1) seen.add(generatePassword(BASE));
    expect(seen.size).toBeGreaterThan(45);
  });

  it('still generates when a single class is selected', () => {
    const password = generatePassword({
      ...BASE,
      uppercase: false,
      lowercase: false,
      symbols: false,
      minNumbers: 4,
    });
    expect(password).toMatch(/^[0-9]{20}$/);
  });
});

describe('passwordEntropyBitsForOptions', () => {
  it('matches the pool-based figure exactly when nothing is required', () => {
    const bits = passwordEntropyBitsForOptions(BASE);
    expect(bits).toBeCloseTo(20 * Math.log2(88), 9);
  });

  it('reports strictly fewer bits once a minimum is imposed, and says so honestly', () => {
    const unconstrained = passwordEntropyBitsForOptions(BASE);
    const constrained = passwordEntropyBitsForOptions({ ...BASE, minNumbers: 1, minSymbols: 1 });
    expect(constrained).toBeLessThan(unconstrained);
    // The measured cost of the shipped default, which the UI states out loud.
    expect(unconstrained - constrained).toBeCloseTo(0.1368, 3);
  });

  it('never rises when a minimum rises', () => {
    let previous = Number.POSITIVE_INFINITY;
    for (let minimum = 0; minimum <= MAX_PASSWORD_CLASS_MINIMUM; minimum += 1) {
      const bits = passwordEntropyBitsForOptions({ ...BASE, minNumbers: minimum });
      expect(bits).toBeLessThanOrEqual(previous);
      previous = bits;
    }
  });

  it('can fall far enough to move the strength band, at an extreme policy', () => {
    // Requiring 5 of 8 characters from one class is a large real loss, and the
    // meter has to be able to show it rather than quoting the unconstrained pool.
    const bits = passwordEntropyBitsForOptions({ ...BASE, length: 8, minSymbols: 5 });
    expect(bits).toBeLessThan(8 * Math.log2(88));
  });
});

describe('generatePassphrase', () => {
  const words = ['alpha', 'bravo', 'charlie', 'delta'] as const;

  it('joins the requested number of words with the separator', () => {
    const phrase = generatePassphrase(4, '-', words);
    expect(phrase.split('-')).toHaveLength(4);
    for (const word of phrase.split('-')) expect(words).toContain(word);
  });

  it('refuses a non-positive word count', () => {
    expect(() => generatePassphrase(0, '-', words)).toThrow(RangeError);
    expect(() => generatePassphrase(1.5, '-', words)).toThrow(RangeError);
  });

  it('never emits a word that is not in the list', () => {
    // The defect this replaces: an index miss produced the literal string
    // 'word', silently, with the reported entropy unchanged.
    for (let i = 0; i < 50; i += 1) {
      for (const word of generatePassphrase(6, ' ', words).split(' ')) {
        expect(words).toContain(word);
      }
    }
  });
});
