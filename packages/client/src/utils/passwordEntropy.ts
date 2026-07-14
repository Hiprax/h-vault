/**
 * Exact, information-theoretic strength metrics for RANDOMLY GENERATED passwords
 * and passphrases.
 *
 * For a uniform-random generator the keyspace is known exactly, so the honest metric
 * is Shannon entropy: bits = length * log2(poolSize). This module is the single
 * source of truth for the character sets, the entropy math, the strength banding, and
 * the crack-time estimate. It is deliberately free of React and of zxcvbn so it can be
 * unit-tested in isolation and reused by the generator component.
 *
 * Why not zxcvbn here? zxcvbn is a heuristic estimator tuned for HUMAN-chosen
 * passwords. On a known-uniform-random string it (a) saturates its 0..4 score once
 * guesses >= 1e10 (~33 bits), so it cannot tell a 33-bit password from a 256-bit one;
 * (b) uses a fixed brute-force cardinality of 10 rather than the real charset; and
 * (c) can be skewed lower by coincidental dictionary/sequence substrings that do not
 * actually reduce the security of a uniform-random secret. zxcvbn remains the correct
 * tool for the human-chosen master password (Register / Reset / Settings / Vault
 * Health) — just not for generated output.
 */

export interface PasswordCharsetOptions {
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}

// ---------------------------------------------------------------------------
// Character sets — the single source of truth shared with the generator.
// ---------------------------------------------------------------------------

export const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
export const LOWER = 'abcdefghijklmnopqrstuvwxyz';
export const DIGITS = '0123456789';
export const SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?';
export const AMBIGUOUS = 'lI1O0';

/**
 * Build the exact character pool the generator draws from for the given options. The
 * generator MUST call this same function so the displayed entropy is computed from the
 * identical pool (no drift). When no class is selected we fall back to lowercase so
 * generation can never draw from an empty pool — and the entropy is then honestly
 * reported for that lowercase pool.
 */
export function buildCharset(options: PasswordCharsetOptions): string {
  let charset = '';
  if (options.uppercase) charset += UPPER;
  if (options.lowercase) charset += LOWER;
  if (options.numbers) charset += DIGITS;
  if (options.symbols) charset += SYMBOLS;

  if (options.excludeAmbiguous) {
    charset = charset
      .split('')
      .filter((c) => !AMBIGUOUS.includes(c))
      .join('');
  }

  if (charset.length === 0) {
    charset = LOWER; // fallback — mirrors generatePassword so entropy matches reality
  }
  return charset;
}

/** Size of the effective character pool the generator would draw from. */
export function getEffectiveCharsetSize(options: PasswordCharsetOptions): number {
  return buildCharset(options).length;
}

/**
 * Shannon entropy (bits) of a uniform-random password of `length` characters drawn
 * from a pool of `charsetSize` symbols: length * log2(charsetSize). A pool of size
 * <= 1 (or non-positive length) carries no entropy.
 */
export function passwordEntropyBits(length: number, charsetSize: number): number {
  if (!Number.isFinite(length) || !Number.isFinite(charsetSize)) return 0;
  if (length <= 0 || charsetSize <= 1) return 0;
  return length * Math.log2(charsetSize);
}

/**
 * Shannon entropy (bits) of a passphrase of `wordCount` words, each chosen uniformly
 * from a list of `wordlistSize` words: wordCount * log2(wordlistSize). The separator
 * is user-chosen (fixed, not random) and therefore contributes 0 bits.
 */
export function passphraseEntropyBits(wordCount: number, wordlistSize: number): number {
  if (!Number.isFinite(wordCount) || !Number.isFinite(wordlistSize)) return 0;
  if (wordCount <= 0 || wordlistSize <= 1) return 0;
  return wordCount * Math.log2(wordlistSize);
}

// ---------------------------------------------------------------------------
// Strength banding
// ---------------------------------------------------------------------------

export const STRENGTH_LABELS = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'] as const;
export type StrengthLevel = 0 | 1 | 2 | 3 | 4;
export type StrengthLabel = (typeof STRENGTH_LABELS)[number];

/**
 * Map exact entropy (bits) to a 5-level strength band. These thresholds are an
 * engineering calibration (not a verbatim standard): they combine the widely-used
 * online-vs-offline attack dividers (~40 bits to resist online guessing; ~64 bits as a
 * common floor for resisting offline fast-hash attacks) with NIST SP 800-131A Rev 2's
 * 112-bit "minimum acceptable security strength" (through 2030) as the top-band anchor.
 * For a UNIFORM-random generator the nominal entropy IS the true guessing resistance,
 * so these bands are directly meaningful (unlike for human-chosen passwords, where the
 * nominal charset entropy over-states resistance and a heuristic like zxcvbn is needed).
 *
 *   < 40   Very Weak   — falls to an offline attack in seconds
 *   40-63  Weak        — survives online throttling, not fast-hash offline
 *   64-79  Fair        — resists slow hashing indefinitely; years vs one GPU fast-hash
 *   80-111 Strong      — vast time vs one GPU fast-hash, but below the crypto floor
 *   >= 112 Very Strong — meets NIST's minimum cryptographic security strength
 */
export function classifyStrength(bits: number): { level: StrengthLevel; label: StrengthLabel } {
  let level: StrengthLevel;
  if (!Number.isFinite(bits) || bits < 40) level = 0;
  else if (bits < 64) level = 1;
  else if (bits < 80) level = 2;
  else if (bits < 112) level = 3;
  else level = 4;
  return { level, label: STRENGTH_LABELS[level] };
}

// ---------------------------------------------------------------------------
// Crack-time estimate (honest, overflow-proof)
// ---------------------------------------------------------------------------

/**
 * Headline attacker model: a single high-end consumer GPU cracking a fast, unsalted
 * hash (an RTX 4090 computes ~1.6x10^11 MD5/s; hashcat v6.2.6 benchmark). This is a
 * deliberately CONSERVATIVE (attacker-favouring) figure so the crack time we show can
 * never over-state safety — the opposite of zxcvbn's mild 1e4/s default display.
 */
export const OFFLINE_GPU_GUESSES_PER_SEC = 1e11;

/** Human-readable form of the headline rate, for labelling the UI. */
export const OFFLINE_GPU_RATE_LABEL = '~10¹¹ guesses/s';

const LOG10_2 = Math.log10(2);
const LOG10_MINUTE = Math.log10(60);
const LOG10_HOUR = Math.log10(3600);
const LOG10_DAY = Math.log10(86_400);
const LOG10_MONTH = Math.log10(2_629_800); // 1/12 of a Julian year, in seconds
const LOG10_YEAR = Math.log10(31_557_600); // Julian year in seconds

/** Format a small count (>= 1, exact integer range) with a pluralized unit. */
function countWithUnit(value: number, unit: string): string {
  const rounded = Math.max(1, Math.round(value));
  return `${rounded.toLocaleString('en-US')} ${unit}${rounded === 1 ? '' : 's'}`;
}

/** Format a value in [1, 1000) with ~2-3 significant figures (no false precision). */
function significant(value: number): string {
  if (value >= 100) return String(Math.round(value));
  if (value >= 10) return String(Math.round(value * 10) / 10);
  return String(Math.round(value * 100) / 100);
}

/** Humanize a duration expressed as log10(years). */
function humanizeYears(log10Years: number): string {
  if (log10Years < 3) {
    // < 1000 years — a plain integer count reads naturally.
    return countWithUnit(10 ** log10Years, 'year');
  }
  if (log10Years < 15) {
    // Word-scaled with a couple of significant figures. The attacker rate is only an
    // order-of-magnitude estimate, so we deliberately avoid 15-digit exact year counts.
    const scales: { log: number; name: string }[] = [
      { log: 12, name: 'trillion' },
      { log: 9, name: 'billion' },
      { log: 6, name: 'million' },
      { log: 3, name: 'thousand' },
    ];
    for (const s of scales) {
      if (log10Years >= s.log) {
        return `${significant(10 ** (log10Years - s.log))} ${s.name} years`;
      }
    }
  }
  // Beyond ~10^15 years, present in scientific notation: ~m x 10^N years.
  const n = Math.floor(log10Years);
  const mantissa = 10 ** (log10Years - n);
  return `~${mantissa.toFixed(1)} x 10^${n} years`;
}

/**
 * Humanized AVERAGE time to crack a uniform-random secret of `bits` entropy at
 * `guessesPerSecond`. Uses the expected number of guesses, 2^(bits-1), and computes
 * ENTIRELY in log10 space. A naive `2 ** (bits - 1)` overflows a JS float to Infinity
 * once bits >= ~1025; the generator's own maximum is only ~827 bits (128 chars over the
 * 88-char pool), which is in range, but the log-space form stays finite for ANY input
 * (verified past 2000 bits in the tests) and never builds a huge intermediate — 10**x is
 * only ever materialized inside a branch where x is provably small.
 *
 * The average vs full-keyspace choice is a single bit (factor of 2) and never moves a
 * band; average is used because it is the true expectation for a uniform secret.
 */
export function formatCrackTime(
  bits: number,
  guessesPerSecond: number = OFFLINE_GPU_GUESSES_PER_SEC,
): string {
  if (!Number.isFinite(bits) || bits <= 0) return 'less than a second';
  if (!Number.isFinite(guessesPerSecond) || guessesPerSecond <= 0) return 'forever';

  const log10Guesses = (bits - 1) * LOG10_2; // average = 2^(bits-1)
  const log10Seconds = log10Guesses - Math.log10(guessesPerSecond);

  if (log10Seconds < 0) return 'less than a second';
  if (log10Seconds < LOG10_MINUTE) return countWithUnit(10 ** log10Seconds, 'second');
  if (log10Seconds < LOG10_HOUR)
    return countWithUnit(10 ** (log10Seconds - LOG10_MINUTE), 'minute');
  if (log10Seconds < LOG10_DAY) return countWithUnit(10 ** (log10Seconds - LOG10_HOUR), 'hour');
  if (log10Seconds < LOG10_MONTH) return countWithUnit(10 ** (log10Seconds - LOG10_DAY), 'day');
  if (log10Seconds < LOG10_YEAR) return countWithUnit(10 ** (log10Seconds - LOG10_MONTH), 'month');

  return humanizeYears(log10Seconds - LOG10_YEAR);
}
