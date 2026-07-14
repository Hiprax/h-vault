import { describe, it, expect } from 'vitest';
import {
  UPPER,
  LOWER,
  DIGITS,
  SYMBOLS,
  AMBIGUOUS,
  buildCharset,
  getEffectiveCharsetSize,
  passwordEntropyBits,
  passphraseEntropyBits,
  classifyStrength,
  formatCrackTime,
  STRENGTH_LABELS,
  OFFLINE_GPU_GUESSES_PER_SEC,
  OFFLINE_GPU_RATE_LABEL,
  type PasswordCharsetOptions,
} from '../src/utils/passwordEntropy';

// A base options object with everything off; individual tests flip what they need.
const OFF: PasswordCharsetOptions = {
  uppercase: false,
  lowercase: false,
  numbers: false,
  symbols: false,
  excludeAmbiguous: false,
};

function opts(partial: Partial<PasswordCharsetOptions>): PasswordCharsetOptions {
  return { ...OFF, ...partial };
}

describe('passwordEntropy — character sets', () => {
  it('has the expected canonical set sizes (single source of truth)', () => {
    expect(UPPER.length).toBe(26);
    expect(LOWER.length).toBe(26);
    expect(DIGITS.length).toBe(10);
    expect(SYMBOLS.length).toBe(26);
    expect(AMBIGUOUS).toBe('lI1O0');
    // No accidental duplicate characters within any set.
    for (const set of [UPPER, LOWER, DIGITS, SYMBOLS]) {
      expect(new Set(set).size).toBe(set.length);
    }
  });
});

describe('buildCharset / getEffectiveCharsetSize — each checkbox individually', () => {
  it('uppercase only → 26', () => {
    expect(getEffectiveCharsetSize(opts({ uppercase: true }))).toBe(26);
    expect(buildCharset(opts({ uppercase: true }))).toBe(UPPER);
  });

  it('lowercase only → 26', () => {
    expect(getEffectiveCharsetSize(opts({ lowercase: true }))).toBe(26);
  });

  it('numbers only → 10', () => {
    expect(getEffectiveCharsetSize(opts({ numbers: true }))).toBe(10);
  });

  it('symbols only → 26', () => {
    expect(getEffectiveCharsetSize(opts({ symbols: true }))).toBe(26);
  });

  it('all four classes → 88', () => {
    expect(
      getEffectiveCharsetSize(
        opts({ uppercase: true, lowercase: true, numbers: true, symbols: true }),
      ),
    ).toBe(88);
  });
});

describe('buildCharset — exclude ambiguous', () => {
  it('all classes minus ambiguous → 83, and none of l I 1 O 0 remain', () => {
    const set = buildCharset(
      opts({
        uppercase: true,
        lowercase: true,
        numbers: true,
        symbols: true,
        excludeAmbiguous: true,
      }),
    );
    expect(set.length).toBe(83); // 88 - 5
    for (const ch of AMBIGUOUS) {
      expect(set).not.toContain(ch);
    }
  });

  it('exclude ambiguous is class-specific: lowercase→25, uppercase→24, digits→8, symbols→26', () => {
    // lowercase loses only 'l'
    expect(getEffectiveCharsetSize(opts({ lowercase: true, excludeAmbiguous: true }))).toBe(25);
    // uppercase loses 'I' and 'O'
    expect(getEffectiveCharsetSize(opts({ uppercase: true, excludeAmbiguous: true }))).toBe(24);
    // digits lose '1' and '0'
    expect(getEffectiveCharsetSize(opts({ numbers: true, excludeAmbiguous: true }))).toBe(8);
    // symbols contain no ambiguous chars
    expect(getEffectiveCharsetSize(opts({ symbols: true, excludeAmbiguous: true }))).toBe(26);
  });
});

describe('buildCharset — empty selection fallback', () => {
  it('no class selected falls back to lowercase (26) so generation never divides by 0', () => {
    expect(buildCharset(OFF)).toBe(LOWER);
    expect(getEffectiveCharsetSize(OFF)).toBe(26);
  });

  it('no class + excludeAmbiguous still falls back to lowercase (matches generator behaviour)', () => {
    expect(getEffectiveCharsetSize(opts({ excludeAmbiguous: true }))).toBe(26);
  });
});

describe('passwordEntropyBits', () => {
  it('computes length * log2(charsetSize)', () => {
    expect(passwordEntropyBits(20, 88)).toBeCloseTo(20 * Math.log2(88), 10);
    expect(passwordEntropyBits(8, 88)).toBeCloseTo(51.6754, 3);
    expect(passwordEntropyBits(10, 2)).toBe(10); // log2(2) === 1
  });

  it('is monotonic in length and in charset size', () => {
    expect(passwordEntropyBits(21, 88)).toBeGreaterThan(passwordEntropyBits(20, 88));
    expect(passwordEntropyBits(20, 94)).toBeGreaterThan(passwordEntropyBits(20, 88));
  });

  it('returns 0 for degenerate inputs (length<=0, charset<=1, non-finite)', () => {
    expect(passwordEntropyBits(0, 88)).toBe(0);
    expect(passwordEntropyBits(-5, 88)).toBe(0);
    expect(passwordEntropyBits(20, 1)).toBe(0);
    expect(passwordEntropyBits(20, 0)).toBe(0);
    expect(passwordEntropyBits(Number.NaN, 88)).toBe(0);
    expect(passwordEntropyBits(20, Number.POSITIVE_INFINITY)).toBe(0);
  });
});

describe('passphraseEntropyBits', () => {
  it('computes wordCount * log2(wordlistSize); 2048-word list = 11 bits/word', () => {
    expect(passphraseEntropyBits(1, 2048)).toBe(11);
    expect(passphraseEntropyBits(5, 2048)).toBe(55);
    expect(passphraseEntropyBits(12, 2048)).toBe(132);
  });

  it('returns 0 for degenerate inputs', () => {
    expect(passphraseEntropyBits(0, 2048)).toBe(0);
    expect(passphraseEntropyBits(5, 1)).toBe(0);
    expect(passphraseEntropyBits(Number.NaN, 2048)).toBe(0);
  });
});

describe('classifyStrength — band boundaries', () => {
  it('maps bits to the correct 5-level band at each boundary', () => {
    // Very Weak: < 40
    expect(classifyStrength(0)).toEqual({ level: 0, label: 'Very Weak' });
    expect(classifyStrength(39.999)).toEqual({ level: 0, label: 'Very Weak' });
    // Weak: 40..63
    expect(classifyStrength(40)).toEqual({ level: 1, label: 'Weak' });
    expect(classifyStrength(63.999)).toEqual({ level: 1, label: 'Weak' });
    // Fair: 64..79
    expect(classifyStrength(64)).toEqual({ level: 2, label: 'Fair' });
    expect(classifyStrength(79.999)).toEqual({ level: 2, label: 'Fair' });
    // Strong: 80..111
    expect(classifyStrength(80)).toEqual({ level: 3, label: 'Strong' });
    expect(classifyStrength(111.999)).toEqual({ level: 3, label: 'Strong' });
    // Very Strong: >= 112
    expect(classifyStrength(112)).toEqual({ level: 4, label: 'Very Strong' });
    expect(classifyStrength(1000)).toEqual({ level: 4, label: 'Very Strong' });
  });

  it('treats non-finite / negative entropy as Very Weak', () => {
    expect(classifyStrength(Number.NaN).level).toBe(0);
    expect(classifyStrength(-10).level).toBe(0);
  });

  it('label matches STRENGTH_LABELS[level] for every band', () => {
    for (const bits of [10, 50, 70, 90, 200]) {
      const { level, label } = classifyStrength(bits);
      expect(label).toBe(STRENGTH_LABELS[level]);
    }
  });
});

describe('formatCrackTime — headline offline-GPU rate', () => {
  it('exports the conservative attacker constants', () => {
    expect(OFFLINE_GPU_GUESSES_PER_SEC).toBe(1e11);
    expect(typeof OFFLINE_GPU_RATE_LABEL).toBe('string');
  });

  it('produces an honest humanized ladder at 1e11 guesses/s', () => {
    // Values hand-verified: average guesses = 2^(bits-1), seconds = guesses / 1e11.
    expect(formatCrackTime(20)).toBe('less than a second');
    expect(formatCrackTime(40)).toBe('5 seconds');
    expect(formatCrackTime(45)).toBe('3 minutes');
    expect(formatCrackTime(50)).toBe('2 hours');
    expect(formatCrackTime(55)).toBe('2 days'); // a default 5-word passphrase (55 bits)
    expect(formatCrackTime(60)).toBe('2 months');
    expect(formatCrackTime(80)).toMatch(/thousand years$/);
    expect(formatCrackTime(128)).toMatch(/^~\d\.\d x 10\^19 years$/);
  });

  it('is non-decreasing in bits (crack time never shrinks as entropy grows)', () => {
    // Compare via the internal seconds proxy: reconstruct ordering by category rank.
    const rank = (s: string): number => {
      if (s === 'less than a second') return 0;
      if (/second/.test(s)) return 1;
      if (/minute/.test(s)) return 2;
      if (/hour/.test(s)) return 3;
      if (/\bday/.test(s)) return 4;
      if (/month/.test(s)) return 5;
      if (/thousand years|^\d+ years|million|billion|trillion/.test(s)) return 6;
      return 7; // scientific years
    };
    let prev = -1;
    for (let bits = 10; bits <= 900; bits += 10) {
      const r = rank(formatCrackTime(bits));
      expect(r).toBeGreaterThanOrEqual(prev);
      prev = r;
    }
  });

  it('never overflows to Infinity/NaN across the whole range', () => {
    // The generator's realistic maximum: 128 chars over the full 88-char pool ≈ 827 bits.
    const huge = passwordEntropyBits(128, 88);
    const out = formatCrackTime(huge);
    expect(out).not.toMatch(/Infinity|NaN|undefined/);
    expect(out).toMatch(/years$/);
    // The sweep past ~1025 bits is the real overflow guard: a naive 2**(bits-1) becomes
    // Infinity there, but the log-space implementation must stay finite up to 2000 bits.
    for (let bits = 1; bits <= 2000; bits += 7) {
      expect(formatCrackTime(bits)).not.toMatch(/Infinity|NaN|undefined/);
    }
  });

  it('handles degenerate inputs safely', () => {
    expect(formatCrackTime(0)).toBe('less than a second');
    expect(formatCrackTime(-5)).toBe('less than a second');
    expect(formatCrackTime(Number.NaN)).toBe('less than a second');
    expect(formatCrackTime(50, 0)).toBe('forever');
    expect(formatCrackTime(50, -1)).toBe('forever');
    expect(formatCrackTime(50, Number.POSITIVE_INFINITY)).toBe('forever');
  });

  it('a faster attacker yields a strictly shorter time (rate relationship is not inverted)', () => {
    // Map a humanized duration onto an ordinal tier so we can compare across the
    // different output formats (minutes/hours/days/months/years). Higher = longer.
    const tierRank = (label: string): number => {
      if (label.includes('year')) return 6;
      if (label.includes('month')) return 5;
      if (label.includes('day')) return 4;
      if (label.includes('hour')) return 3;
      if (label.includes('minute')) return 2;
      if (label.includes('second')) return 1;
      return 0;
    };

    // At 45 bits the correct implementation steps DOWN exactly one tier as the
    // attacker gets 100x faster: months → days → hours → minutes. A regression
    // that inverted the rate relationship (`+ log10(rate)` instead of `-`) would
    // push every rate into the 'years' band, making the sequence non-decreasing.
    const rates = [1e6, 1e8, 1e9, 1e10]; // strictly increasing attacker speed
    const ranks = rates.map((r) => tierRank(formatCrackTime(45, r)));

    for (let i = 1; i < ranks.length; i++) {
      expect(ranks[i]).toBeLessThan(ranks[i - 1]!);
    }

    // The headline extremes are still both astronomically large 'years' strings.
    expect(formatCrackTime(100, 1e4)).toMatch(/years$/);
    expect(formatCrackTime(100, 1e12)).toMatch(/years$/);
  });
});

describe('end-to-end sanity — realistic generator settings', () => {
  it('default 20-char full charset ≈ 129 bits → Very Strong', () => {
    const bits = passwordEntropyBits(
      20,
      getEffectiveCharsetSize(
        opts({
          uppercase: true,
          lowercase: true,
          numbers: true,
          symbols: true,
        }),
      ),
    );
    expect(Math.round(bits)).toBe(129);
    expect(classifyStrength(bits).label).toBe('Very Strong');
  });

  it('8-char full charset ≈ 52 bits → Weak (honest, not "Very Strong")', () => {
    const bits = passwordEntropyBits(8, 88);
    expect(Math.round(bits)).toBe(52);
    expect(classifyStrength(bits).label).toBe('Weak');
  });

  it('5-word passphrase = 55 bits → Weak; 12-word = 132 bits → Very Strong', () => {
    expect(classifyStrength(passphraseEntropyBits(5, 2048)).label).toBe('Weak');
    expect(classifyStrength(passphraseEntropyBits(12, 2048)).label).toBe('Very Strong');
  });
});
