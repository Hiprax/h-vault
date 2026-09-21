/**
 * Parsing and building of TOTP/HOTP values, dependency-free and synchronous.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS MODULE EXISTS, AND WHY IT IMPORTS NOTHING
 * ---------------------------------------------------------------------------
 *
 * A login item's `data.totp` is a free-form bounded string, and the application
 * writes TWO different shapes into it. The item form stores whatever the user
 * typed, usually a bare base32 secret; every third-party import parser stores a
 * full `otpauth://` URI verbatim; and `toOtpauthUri` in
 * `services/export/portableItem.ts` EMITS a URI on every export. So an export
 * followed by a re-import turns a secret into a URI, and both shapes have to
 * render. This module is the ONE place that knows how to read either.
 *
 * It deliberately imports nothing. `otpauth` is a lazy-only dependency that the
 * bundle policy keeps out of every eager chunk (pinned by
 * `tests/vite-config.test.ts`), and it is needed only to GENERATE a code, never
 * to understand a stored value. Keeping the parse synchronous and dependency
 * free is also what lets a component decide what to render before it has
 * awaited anything, and what would let this run inside the document sandbox,
 * whose Rollup graph must never pull an HTTP client in behind a shared import.
 *
 * ---------------------------------------------------------------------------
 * THE BASE32 LENGTH RULE, WHICH IS A TIGHTENING AND NOT A RELAXATION
 * ---------------------------------------------------------------------------
 *
 * The rule this replaces demanded `length % 8 === 0`, which rejected the
 * 26-character (16-byte) secret most services issue. The correct rule is that a
 * whole number of bytes, encoded five bits at a time, can only produce a length
 * whose residue mod 8 is one of {0, 2, 4, 5, 7}: a group of 8 characters is 5
 * bytes, and the legal partial groups are 2 characters (1 byte), 4 (2 bytes),
 * 5 (3 bytes) and 7 (4 bytes). Residues 1, 3 and 6 encode no whole byte count
 * and are malformed.
 *
 * Simply DELETING the length check would be worse than the bug it fixes.
 * `otpauth`'s decoder consumes five bits at a time and silently discards a
 * trailing partial group, so a mistyped secret would produce plausible,
 * confidently wrong codes forever, with nothing to indicate it. The same
 * reasoning is why {@link parseTotpValue} reports an unsupported algorithm or
 * digit count as a FAILURE rather than falling back to the defaults: a wrong
 * code that looks right is the worst outcome this feature can produce.
 */

/** The values the `otpauth://` specification defines as defaults. */
export const TOTP_DEFAULTS = {
  algorithm: 'SHA1',
  digits: 6,
  period: 30,
} as const;

/** The hash algorithms both this application and `otpauth` can generate. */
const SUPPORTED_ALGORITHMS = ['SHA1', 'SHA256', 'SHA512'] as const;

export type TotpAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number];

/** Digit counts worth generating. The specification names 6 and 8; 7 occurs. */
const SUPPORTED_DIGITS = [6, 7, 8];

/**
 * Residues mod 8 that a whole number of bytes can produce in base32.
 * See the header: 1, 3 and 6 encode no whole byte count.
 */
const DECODABLE_BASE32_RESIDUES = new Set([0, 2, 4, 5, 7]);

const BASE32_ALPHABET = /^[A-Z2-7]+$/;

/** A stored TOTP value, understood. */
export interface ParsedTotp {
  /**
   * `hotp` parses successfully on purpose. A counter-based code cannot be
   * generated from a stored value alone, but the caller has to be able to SAY
   * so; treating it as a parse failure would render "invalid secret" for a
   * value that is perfectly valid and merely unsupported here.
   */
  readonly type: 'totp' | 'hotp';
  /** Normalised: uppercase, no padding, no separators. */
  readonly secret: string;
  readonly issuer: string;
  readonly account: string;
  readonly algorithm: TotpAlgorithm;
  readonly digits: number;
  /** Seconds. Meaningless for `hotp`, where it is left at the default. */
  readonly period: number;
  /** A decimal string for `hotp`, so a 64-bit counter survives; else `null`. */
  readonly counter: string | null;
}

export type TotpParseFailure =
  | 'empty'
  | 'invalid-base32'
  | 'invalid-uri'
  | 'missing-secret'
  | 'unsupported-algorithm'
  | 'unsupported-digits'
  | 'unsupported-period';

export type TotpParseResult =
  | { readonly ok: true; readonly value: ParsedTotp }
  | { readonly ok: false; readonly reason: TotpParseFailure };

/** Strip the separators people paste, drop padding, and uppercase. */
export function normaliseBase32(value: string): string {
  return value
    .replace(/[\s-]+/g, '')
    .replace(/=+$/, '')
    .toUpperCase();
}

/**
 * Is this a base32 string that decodes to a whole number of bytes?
 *
 * Takes an ALREADY-normalised value; see {@link normaliseBase32}.
 */
export function isDecodableBase32(normalised: string): boolean {
  if (normalised.length === 0) return false;
  if (!BASE32_ALPHABET.test(normalised)) return false;
  return DECODABLE_BASE32_RESIDUES.has(normalised.length % 8);
}

function isTotpAlgorithm(value: string): value is TotpAlgorithm {
  return (SUPPORTED_ALGORITHMS as readonly string[]).includes(value);
}

/** A positive integer, or `null`. Rejects `1.5`, `-1`, `1e3`, `''` and `NaN`. */
function positiveInteger(raw: string | null): number | null {
  if (raw === null || !/^\d+$/.test(raw)) return null;
  const parsed = Number(raw);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

/**
 * Split an `otpauth://` label into its issuer prefix and account name.
 *
 * The specification writes the label as `accountname` or
 * `issuer (":" / "%3A") *"%20" accountname`, says neither part may contain a
 * colon, and allows spaces after the separator. So: split on the FIRST colon
 * only, and trim the leading spaces off what follows.
 */
function splitLabel(label: string): { issuer: string; account: string } {
  const colon = label.indexOf(':');
  if (colon === -1) return { issuer: '', account: label.trim() };
  return {
    issuer: label.slice(0, colon).trim(),
    account: label
      .slice(colon + 1)
      .replace(/^ +/, '')
      .trim(),
  };
}

function parseOtpauthUri(raw: string): TotpParseResult {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: 'invalid-uri' };
  }

  // A non-special scheme keeps its host verbatim rather than lowercasing it,
  // so `otpauth://TOTP/...` has to be folded here.
  const type = url.hostname.toLowerCase();
  if (type !== 'totp' && type !== 'hotp') return { ok: false, reason: 'invalid-uri' };

  const secretParam = url.searchParams.get('secret');
  if (secretParam === null || secretParam.trim().length === 0) {
    return { ok: false, reason: 'missing-secret' };
  }
  const secret = normaliseBase32(secretParam);
  if (!isDecodableBase32(secret)) return { ok: false, reason: 'invalid-base32' };

  let label: string;
  try {
    label = decodeURIComponent(url.pathname.replace(/^\//, ''));
  } catch {
    return { ok: false, reason: 'invalid-uri' };
  }
  const fromLabel = splitLabel(label);

  // The specification says the two "should be equal" and names no winner when
  // they disagree. Newer implementations use the parameter, so it wins, and the
  // label prefix is the fallback for the many URIs that carry no parameter.
  const issuerParam = url.searchParams.get('issuer');
  const issuer = issuerParam !== null && issuerParam.length > 0 ? issuerParam : fromLabel.issuer;

  const algorithmRaw = url.searchParams.get('algorithm');
  let algorithm: TotpAlgorithm = TOTP_DEFAULTS.algorithm;
  if (algorithmRaw !== null && algorithmRaw.length > 0) {
    const upper = algorithmRaw.toUpperCase();
    if (!isTotpAlgorithm(upper)) return { ok: false, reason: 'unsupported-algorithm' };
    algorithm = upper;
  }

  const digitsRaw = url.searchParams.get('digits');
  let digits: number = TOTP_DEFAULTS.digits;
  if (digitsRaw !== null && digitsRaw.length > 0) {
    const parsed = positiveInteger(digitsRaw);
    if (parsed === null || !SUPPORTED_DIGITS.includes(parsed)) {
      return { ok: false, reason: 'unsupported-digits' };
    }
    digits = parsed;
  }

  const periodRaw = url.searchParams.get('period');
  let period: number = TOTP_DEFAULTS.period;
  if (periodRaw !== null && periodRaw.length > 0) {
    const parsed = positiveInteger(periodRaw);
    if (parsed === null) return { ok: false, reason: 'unsupported-period' };
    period = parsed;
  }

  const counterRaw = url.searchParams.get('counter');
  const counter =
    type === 'hotp' && counterRaw !== null && /^\d+$/.test(counterRaw) ? counterRaw : null;

  return {
    ok: true,
    value: { type, secret, issuer, account: fromLabel.account, algorithm, digits, period, counter },
  };
}

/**
 * Understand a stored `data.totp` value, in either shape it can hold.
 *
 * A bare secret is assumed to be a TOTP on the specification's defaults, which
 * is what the item form has always meant by it.
 */
export function parseTotpValue(raw: string): TotpParseResult {
  const trimmed = raw.trim();
  if (trimmed.length === 0) return { ok: false, reason: 'empty' };

  if (/^otpauth:\/\//i.test(trimmed)) return parseOtpauthUri(trimmed);

  const secret = normaliseBase32(trimmed);
  if (!isDecodableBase32(secret)) return { ok: false, reason: 'invalid-base32' };

  return {
    ok: true,
    value: {
      type: 'totp',
      secret,
      issuer: '',
      account: '',
      algorithm: TOTP_DEFAULTS.algorithm,
      digits: TOTP_DEFAULTS.digits,
      period: TOTP_DEFAULTS.period,
      counter: null,
    },
  };
}

/** A sentence naming what went wrong, for a user rather than a log. */
export function describeTotpFailure(reason: TotpParseFailure): string {
  switch (reason) {
    case 'empty':
      return 'No TOTP secret is set';
    case 'invalid-base32':
      return 'Invalid TOTP secret (not valid base32)';
    case 'invalid-uri':
      return 'Invalid TOTP link (not a usable otpauth:// URI)';
    case 'missing-secret':
      return 'This TOTP link carries no secret';
    case 'unsupported-algorithm':
      return 'This TOTP uses a hash algorithm this app cannot generate';
    case 'unsupported-digits':
      return 'This TOTP asks for a code length this app cannot generate';
    case 'unsupported-period':
      return 'This TOTP has an unusable time step';
  }
}

const BASE32_ALPHABET_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * RFC 4648 base32, unpadded.
 *
 * Unpadded because the `otpauth://` specification says the padding "is not
 * required and should be omitted", and because a trailing `=` in a query string
 * is one more thing for a relaying tool to mangle.
 */
export function encodeBase32(bytes: Uint8Array): string {
  let buffer = 0;
  let bits = 0;
  let out = '';
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET_CHARS.charAt((buffer >>> (bits - 5)) & 31);
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET_CHARS.charAt((buffer << (5 - bits)) & 31);
  return out;
}

/**
 * The inverse of {@link encodeBase32}.
 *
 * Needed because a single `otpauth://` code arrives as base32 while everything
 * downstream holds keys as BYTES, which is what makes them zeroable. Throws
 * rather than skipping an unknown character: a silently shortened key generates
 * confidently wrong codes.
 */
export function decodeBase32(value: string): Uint8Array {
  const normalised = normaliseBase32(value);
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of normalised) {
    const index = BASE32_ALPHABET_CHARS.indexOf(char);
    if (index < 0) throw new RangeError('decodeBase32: not a base32 character');
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

export interface OtpauthUriInput {
  readonly type: 'totp' | 'hotp';
  /** Already base32, uppercase, unpadded. */
  readonly secret: string;
  readonly issuer: string;
  readonly account: string;
  readonly algorithm: TotpAlgorithm;
  readonly digits: number;
  readonly period: number;
  readonly counter: string | null;
}

export interface BuiltOtpauthUri {
  readonly uri: string;
  /** True when the label had to be shortened to fit. */
  readonly truncated: boolean;
}

function composeUri(input: OtpauthUriInput, issuer: string, account: string): string {
  const label = issuer.length > 0 ? `${issuer}:${account}` : account;
  const params = new URLSearchParams();
  params.set('secret', input.secret);
  if (issuer.length > 0) params.set('issuer', issuer);
  params.set('algorithm', input.algorithm);
  params.set('digits', String(input.digits));
  if (input.type === 'hotp') {
    params.set('counter', input.counter ?? '0');
  } else {
    params.set('period', String(input.period));
  }
  return `otpauth://${input.type}/${encodeURIComponent(label)}?${params.toString()}`;
}

/**
 * Build a canonical `otpauth://` URI that is guaranteed to FIT.
 *
 * ---------------------------------------------------------------------------
 * WHY THE LENGTH BOUND IS LOAD-BEARING
 * ---------------------------------------------------------------------------
 *
 * A login item's `data.totp` is capped at `MAX_LOGIN_TOTP_LENGTH`, and that cap
 * is checked on every DECRYPT as well as on write. So an over-long value does
 * not merely fail to save: if one ever reached storage it would fail validation
 * every time the item was opened, stamping the whole item as undecodable and
 * dropping it into a read-only state the user cannot edit their way out of.
 * A long issuer plus a 128-byte secret gets there.
 *
 * The label is shortened until it fits and the SECRET IS NEVER TOUCHED, because
 * a truncated secret is a key that silently generates wrong codes, which is the
 * failure this whole module is arranged to avoid. `null` means even the bare
 * secret does not fit, and the caller must refuse the entry rather than store
 * something shorter.
 */
export function buildOtpauthUri(input: OtpauthUriInput, maxLength: number): BuiltOtpauthUri | null {
  let issuer = input.issuer;
  let account = input.account;

  for (;;) {
    const uri = composeUri(input, issuer, account);
    if (uri.length <= maxLength) {
      return { uri, truncated: issuer !== input.issuer || account !== input.account };
    }
    if (account.length > 0) {
      account = account.slice(0, -1);
      continue;
    }
    if (issuer.length > 0) {
      issuer = issuer.slice(0, -1);
      continue;
    }
    return null;
  }
}
