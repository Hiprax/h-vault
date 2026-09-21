import {
  MAX_PASSWORD_CLASS_MINIMUM,
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
} from '@hvault/shared';
import { pickUniform, randomBigIntBelow } from './secureRandom';
import {
  AMBIGUOUS,
  DIGITS,
  LOWER,
  SYMBOLS,
  UPPER,
  buildCharset,
  passwordEntropyBitsFromCount,
  type PasswordCharsetOptions,
} from '../utils/passwordEntropy';

/**
 * Password generation that samples UNIFORMLY over the set of passwords a policy
 * actually allows, and reports the entropy of that set exactly.
 *
 * ---------------------------------------------------------------------------
 * WHY NOT THE TWO OBVIOUS DESIGNS
 * ---------------------------------------------------------------------------
 *
 * The generator this replaces drew each position independently from the merged
 * pool and honoured no minimum at all, so a 20-character password over the full
 * 88-character pool contained no digit about 8.9 per cent of the time.
 *
 * The two usual fixes are both wrong in ways that do not announce themselves:
 *
 *  - GENERATE THEN PATCH: overwrite a position with a digit when none turned up.
 *    That concentrates probability on strings with exactly one digit and, worse,
 *    on the positions the patch favours.
 *  - FORCE-PLACE THEN SHUFFLE: draw the required characters first, fill the
 *    rest, then shuffle. Positions come out uniform, but the CLASS COUNTS do
 *    not: strings with exactly the minimum are over-represented.
 *
 * Neither is catastrophic, and neither can state its own entropy, which is the
 * disqualifying part for a strength meter that promises never to overstate.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS DOES INSTEAD
 * ---------------------------------------------------------------------------
 *
 * Count the valid passwords, draw one uniform integer below that count, and
 * UNRANK it. `W(r, d)` is the number of valid suffixes of length `r` given the
 * still-outstanding per-class deficits `d`:
 *
 *     W(0, d) = 1 if every deficit is 0, else 0
 *     W(r, d) = sum over classes c of size(c) * W(r - 1, decrement(d, c))
 *
 * with the decrement floored at zero, because a class that has met its minimum
 * imposes nothing further. The map from `[0, W)` to valid passwords is a
 * BIJECTION, which is the whole point: uniformity is then provable by exhaustive
 * enumeration over small parameters rather than argued from a statistical test
 * that can only ever fail to reject. `tests/passwordGeneratorExhaustive.test.ts`
 * is that proof.
 *
 * The entropy is `log2(W)`, exactly, and with every minimum at zero `W` reduces
 * to `pool^length` identically, so the unconstrained figure is unchanged.
 *
 * ---------------------------------------------------------------------------
 * THE PRECONDITION THE WHOLE DECOMPOSITION RESTS ON
 * ---------------------------------------------------------------------------
 *
 * "The character at this position belongs to exactly one class" is only true
 * while the four alphabets are pairwise DISJOINT. They are today, and nothing
 * enforced it, so {@link buildSpec} does: add a symbol that is also a letter and
 * the count silently over-counts, the sampling stops being uniform, and the
 * reported entropy becomes an overstatement. That is exactly the class of defect
 * this module exists to make impossible.
 */

export type PasswordGeneratorFailure = 'no-class-enabled' | 'length-too-short' | 'classes-overlap';

export class PasswordGeneratorError extends Error {
  readonly reason: PasswordGeneratorFailure;

  constructor(reason: PasswordGeneratorFailure, message: string) {
    super(message);
    this.name = 'PasswordGeneratorError';
    this.reason = reason;
  }
}

/** One enabled character class, with the bound the policy puts on it. */
export interface PasswordClass {
  readonly alphabet: string;
  readonly minimum: number;
}

export interface GeneratorSpec {
  readonly length: number;
  /** Enabled classes only, in the order `buildCharset` concatenates them. */
  readonly classes: readonly PasswordClass[];
}

export interface PasswordGenOptionsLike extends PasswordCharsetOptions {
  length: number;
  minUppercase: number;
  minLowercase: number;
  minNumbers: number;
  minSymbols: number;
}

/**
 * Read one counting cell.
 *
 * The `?? 0n` is meaning, not defensive padding: a state with no recorded count
 * contributes nothing to the sum. It is exported so both of its arms can be
 * exercised directly, because every line here has to be covered by a test that
 * could fail, and the out-of-range arm is unreachable through the public API.
 */
export function cellAt(cells: readonly bigint[], index: number): bigint {
  return cells[index] ?? 0n;
}

/** Read one character, refusing an index outside the alphabet. */
export function charAt(alphabet: string, index: number): string {
  const char = alphabet[index];
  if (char === undefined) {
    throw new RangeError('passwordGenerator: character index out of range');
  }
  return char;
}

function clampLength(value: number): number {
  if (!Number.isFinite(value)) return MIN_PASSWORD_LENGTH;
  return Math.min(MAX_PASSWORD_LENGTH, Math.max(MIN_PASSWORD_LENGTH, Math.round(value)));
}

function clampMinimum(value: number): number {
  if (!Number.isFinite(value) || value < 0) return 0;
  return Math.min(MAX_PASSWORD_CLASS_MINIMUM, Math.round(value));
}

function withoutAmbiguous(chars: string, exclude: boolean): string {
  if (!exclude) return chars;
  let kept = '';
  for (const char of chars) {
    if (!AMBIGUOUS.includes(char)) kept += char;
  }
  return kept;
}

/**
 * Refuse a class list whose alphabets are not pairwise disjoint.
 *
 * Exported so it can be driven directly, because the real four alphabets cannot
 * violate it and an unreachable guard is one nobody can prove still works. The
 * precondition it defends is the one the whole decomposition rests on: "the
 * character at this position belongs to exactly one class" is only true while
 * the alphabets are disjoint, and adding a symbol that is also a letter would
 * make the count over-report, the sampling non-uniform and the reported entropy
 * an over-statement, all silently.
 */
export function assertDisjointClasses(
  classes: readonly PasswordClass[],
  expectedPoolSize: number,
): void {
  const pool = classes.map((cls) => cls.alphabet).join('');
  if (new Set(pool).size !== pool.length || pool.length !== expectedPoolSize) {
    throw new PasswordGeneratorError(
      'classes-overlap',
      'The character classes overlap, so a password cannot be counted correctly.',
    );
  }
}

/**
 * Turn user-facing options into the shape the counter and the unranker need.
 *
 * Clamps before it judges, so a stored policy from before a bound existed is
 * repaired rather than refused. Throws only for a policy that cannot produce a
 * password at all.
 */
export function buildSpec(options: PasswordGenOptionsLike): GeneratorSpec {
  const exclude = options.excludeAmbiguous;
  const candidates = [
    {
      enabled: options.uppercase,
      alphabet: withoutAmbiguous(UPPER, exclude),
      minimum: options.minUppercase,
    },
    {
      enabled: options.lowercase,
      alphabet: withoutAmbiguous(LOWER, exclude),
      minimum: options.minLowercase,
    },
    {
      enabled: options.numbers,
      alphabet: withoutAmbiguous(DIGITS, exclude),
      minimum: options.minNumbers,
    },
    {
      enabled: options.symbols,
      alphabet: withoutAmbiguous(SYMBOLS, exclude),
      minimum: options.minSymbols,
    },
  ];

  const classes: PasswordClass[] = [];
  for (const candidate of candidates) {
    if (!candidate.enabled) continue;
    classes.push({ alphabet: candidate.alphabet, minimum: clampMinimum(candidate.minimum) });
  }

  if (classes.length === 0) {
    throw new PasswordGeneratorError(
      'no-class-enabled',
      'Select at least one character type to generate a password.',
    );
  }

  assertDisjointClasses(classes, buildCharset(options).length);

  const length = clampLength(options.length);
  const required = classes.reduce((sum, cls) => sum + cls.minimum, 0);
  if (length < required) {
    throw new PasswordGeneratorError(
      'length-too-short',
      'The password is too short to hold every required character.',
    );
  }

  return { length, classes };
}

interface CountTable {
  /** Flat `(length + 1) * states` grid of counts, indexed `r * states + state`. */
  readonly cells: readonly bigint[];
  readonly states: number;
  /** `decrements[state * classCount + c]` is `state` with class `c` satisfied once more. */
  readonly decrements: Int32Array;
  readonly initialState: number;
  readonly length: number;
}

const tableCache = new Map<string, CountTable>();

function cacheKey(spec: GeneratorSpec): string {
  return spec.classes
    .map((cls) => `${String(cls.alphabet.length)}:${String(cls.minimum)}`)
    .join('|');
}

function buildTable(spec: GeneratorSpec): CountTable {
  const classCount = spec.classes.length;

  // Mixed radix over the per-class deficits, each digit in `[0, minimum]`.
  const strides: number[] = [];
  let states = 1;
  for (const cls of spec.classes) {
    strides.push(states);
    states *= cls.minimum + 1;
  }

  // An Int32Array so the reads below need no presence check: a typed array is
  // indexed as `number`, where a plain array would be `number | undefined`.
  const decrements = new Int32Array(states * classCount);
  let initialState = 0;
  for (const [classIndex, cls] of spec.classes.entries()) {
    const stride = strides[classIndex] ?? 1;
    initialState += cls.minimum * stride;
    for (let state = 0; state < states; state += 1) {
      const digit = Math.floor(state / stride) % (cls.minimum + 1);
      decrements[state * classCount + classIndex] = digit > 0 ? state - stride : state;
    }
  }

  const sizes = spec.classes.map((cls) => BigInt(cls.alphabet.length));
  const cells = new Array<bigint>((spec.length + 1) * states).fill(0n);
  // W(0, d) is 1 only for the all-satisfied state, which is index 0.
  cells[0] = 1n;

  for (let remaining = 1; remaining <= spec.length; remaining += 1) {
    const rowBase = remaining * states;
    const prevBase = rowBase - states;
    for (let state = 0; state < states; state += 1) {
      let total = 0n;
      for (const [classIndex, size] of sizes.entries()) {
        const next = decrements[state * classCount + classIndex] ?? 0;
        const sub = cellAt(cells, prevBase + next);
        if (sub !== 0n) total += size * sub;
      }
      cells[rowBase + state] = total;
    }
  }

  return { cells, states, decrements, initialState, length: spec.length };
}

function tableFor(spec: GeneratorSpec): CountTable {
  const key = cacheKey(spec);
  const cached = tableCache.get(key);
  // A table built for a longer password already contains every shorter one, so
  // dragging the length slider never rebuilds.
  if (cached && cached.length >= spec.length) return cached;
  const table = buildTable(spec);
  tableCache.set(key, table);
  return table;
}

/** How many distinct passwords satisfy this policy. Exact. */
export function countValidPasswords(spec: GeneratorSpec): bigint {
  const table = tableFor(spec);
  return cellAt(table.cells, spec.length * table.states + table.initialState);
}

/**
 * The `index`-th valid password, in the order the counting defines.
 *
 * Total over `[0, countValidPasswords(spec))` and injective, which is what makes
 * a uniform draw over that range a uniform draw over the passwords.
 */
export function unrankPassword(index: bigint, spec: GeneratorSpec): string {
  const table = tableFor(spec);
  const total = cellAt(table.cells, spec.length * table.states + table.initialState);
  if (index < 0n || index >= total) {
    throw new RangeError('unrankPassword: index outside the valid range');
  }

  const classCount = spec.classes.length;
  let rest = index;
  let state = table.initialState;
  const out: string[] = [];

  for (let position = 0; position < spec.length; position += 1) {
    const remaining = spec.length - position;
    const prevBase = (remaining - 1) * table.states;
    for (const [classIndex, cls] of spec.classes.entries()) {
      const next = table.decrements[state * classCount + classIndex] ?? 0;
      const sub = cellAt(table.cells, prevBase + next);
      if (sub === 0n) continue;
      const block = BigInt(cls.alphabet.length) * sub;
      if (rest < block) {
        out.push(charAt(cls.alphabet, Number(rest / sub)));
        rest %= sub;
        state = next;
        break;
      }
      rest -= block;
    }
  }

  return out.join('');
}

/** A uniformly random password satisfying `options`. */
export function generatePassword(options: PasswordGenOptionsLike): string {
  const spec = buildSpec(options);
  const total = countValidPasswords(spec);
  return unrankPassword(randomBigIntBelow(total), spec);
}

/** The exact entropy of {@link generatePassword} under these options, in bits. */
export function passwordEntropyBitsForOptions(options: PasswordGenOptionsLike): number {
  return passwordEntropyBitsFromCount(countValidPasswords(buildSpec(options)));
}

/**
 * A passphrase of `wordCount` words drawn uniformly, with replacement.
 *
 * With replacement is correct and is what the `wordCount * log2(listSize)`
 * entropy claim assumes; drawing without replacement would lower it. The draw
 * goes through `pickUniform`, whose index guard THROWS, replacing a `?? 'word'`
 * fallback that could put a literal constant into a passphrase while leaving the
 * reported entropy untouched.
 */
export function generatePassphrase(
  wordCount: number,
  separator: string,
  words: readonly string[],
): string {
  if (!Number.isSafeInteger(wordCount) || wordCount < 1) {
    throw new RangeError('generatePassphrase needs a positive word count');
  }
  const chosen: string[] = [];
  for (let i = 0; i < wordCount; i += 1) chosen.push(pickUniform(words));
  return chosen.join(separator);
}
