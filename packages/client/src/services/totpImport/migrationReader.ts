/**
 * A bounded reader for Google Authenticator's export payload.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS HAND-WRITTEN
 * ---------------------------------------------------------------------------
 *
 * The payload is a protobuf message, and a protobuf library would be a runtime
 * dependency parsing attacker-influenceable bytes in the origin that holds the
 * unlocked vault key. The subset actually needed is one flat message containing
 * one repeated submessage, which is a few dozen lines of varint and
 * length-delimited reading. Writing it here means every bound is visible, every
 * rejection is deliberate, and the whole thing sits inside this project's own
 * coverage, mutation and fuzz gates rather than behind a version range.
 *
 * The schema is not published by Google. It is reconstructed identically by
 * several independent implementations, and this reader agrees with them on every
 * field number, wire type and enum value:
 *
 *     MigrationPayload { repeated OtpParameters otp_parameters = 1;
 *                        int32 version = 2; int32 batch_size = 3;
 *                        int32 batch_index = 4; int32 batch_id = 5 }
 *     OtpParameters    { bytes secret = 1; string name = 2; string issuer = 3;
 *                        Algorithm algorithm = 4; DigitCount digits = 5;
 *                        OtpType type = 6; int64 counter = 7 }
 *
 * ---------------------------------------------------------------------------
 * FIVE RULES THAT ARE NOT NEGOTIABLE
 * ---------------------------------------------------------------------------
 *
 *  1. AN UNKNOWN ENUM VALUE REJECTS THE ENTRY; IT NEVER FALLS BACK. Defaulting
 *     an unrecognised algorithm to SHA1 would produce a code that looks right
 *     and never matches the service, for ever, with nothing to indicate it. Zero
 *     is the one exception, because protobuf's implicit default genuinely means
 *     SHA1 / six digits / TOTP here, which is what every other implementation
 *     reads it as.
 *  2. GROUPS (WIRE TYPES 3 AND 4) REJECT THE WHOLE MESSAGE. Skipping a group
 *     correctly means matching nested end-group tags, which is the unbounded
 *     recursion this reader is designed not to contain. Google Authenticator
 *     never emits one, so refusing is free.
 *  3. EVERY LOOP ITERATION MUST STRICTLY ADVANCE THE CURSOR, asserted in code.
 *     That is what makes termination a property of the structure rather than of
 *     each branch being right, and it is pinned by a fuzz property.
 *  4. NO ERROR CARRIES ANY PART OF THE INPUT. Every message is a fixed string.
 *     The payload is made of secret keys, and an error is the easiest way for
 *     one to reach a log, a toast or a bug report. A fuzz property asserts that
 *     no thrown message contains any eight-character run of the input.
 *  5. A DUPLICATE SCALAR REJECTS THE ENTRY. Protobuf says last-one-wins; this
 *     reader does not, because Google Authenticator never emits duplicates and a
 *     repeated `secret` is the classic shape of a parser-differential attack,
 *     where two readers of the same bytes disagree about what they say.
 */

/** The longest `otpauth-migration://` URI this will consider. */
export const MAX_MIGRATION_URI_LENGTH = 16_384;
/** A QR code cannot carry more than 2953 bytes in byte mode; this is generous. */
export const MAX_MIGRATION_PAYLOAD_BYTES = 4096;
/** Google Authenticator puts about ten accounts in a code. */
export const MAX_OTP_PARAMETERS = 64;
/** Anti-spin: a payload made of thousands of empty unknown fields stops here. */
const MAX_FIELDS_PER_MESSAGE = 256;
/** A 64-bit varint is at most ten bytes. An eleventh is malformed. */
const MAX_VARINT_BYTES = 10;
const MIN_SECRET_BYTES = 1;
/** 128 bytes bounds the base32 form at 205 characters. */
export const MAX_SECRET_BYTES = 128;
const MAX_LABEL_BYTES = 512;
const MAX_LABEL_LENGTH = 256;
/** A crafted payload must not be able to render "part 1 of 4294967295". */
export const MAX_BATCH_SIZE = 32;

export type MigrationParseCode =
  | 'too-large'
  | 'malformed'
  | 'unsupported-field'
  | 'no-entries'
  | 'too-many-entries'
  | 'bad-secret'
  | 'bad-enum'
  | 'bad-batch';

/** Every failure this reader can produce. The message never quotes the input. */
export class MigrationParseError extends Error {
  readonly code: MigrationParseCode;

  constructor(code: MigrationParseCode, message: string) {
    super(message);
    this.name = 'MigrationParseError';
    this.code = code;
  }
}

const MALFORMED = (): MigrationParseError =>
  new MigrationParseError('malformed', 'That code is not a readable Google Authenticator export.');

type MigrationAlgorithm = 'SHA1' | 'SHA256' | 'SHA512' | 'MD5';

export interface MigrationEntry {
  readonly type: 'totp' | 'hotp';
  /** Raw bytes, never a string: the caller owns zeroing it. */
  readonly secret: Uint8Array;
  readonly name: string;
  readonly issuer: string;
  readonly algorithm: MigrationAlgorithm;
  readonly digits: 6 | 8;
  /** A decimal string for `hotp`, so a 64-bit counter survives intact. */
  readonly counter: string | null;
}

export interface MigrationPayload {
  readonly entries: readonly MigrationEntry[];
  readonly version: number;
  readonly batchSize: number;
  readonly batchIndex: number;
  readonly batchId: number;
}

/** Enum tables as `Map`s, which keeps `security/detect-object-injection` quiet. */
const ALGORITHMS = new Map<number, MigrationAlgorithm>([
  [0, 'SHA1'],
  [1, 'SHA1'],
  [2, 'SHA256'],
  [3, 'SHA512'],
  [4, 'MD5'],
]);
const DIGIT_COUNTS = new Map<number, 6 | 8>([
  [0, 6],
  [1, 6],
  [2, 8],
]);
const OTP_TYPES = new Map<number, 'totp' | 'hotp'>([
  [0, 'totp'],
  [1, 'hotp'],
  [2, 'totp'],
]);

/**
 * A cursor over the payload.
 *
 * `DataView` rather than direct indexing: under `noUncheckedIndexedAccess` a
 * `Uint8Array` read is `number | undefined`, which would put a presence check on
 * every byte, while `getUint8` is typed `number` and throws `RangeError` past
 * the end. One catch at the top turns that into one rejection.
 */
class Cursor {
  private readonly view: DataView;
  offset = 0;

  constructor(private readonly bytes: Uint8Array) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  get done(): boolean {
    return this.offset >= this.bytes.byteLength;
  }

  get remaining(): number {
    return this.bytes.byteLength - this.offset;
  }

  byte(): number {
    const value = this.view.getUint8(this.offset);
    this.offset += 1;
    return value;
  }

  /** A varint as a `bigint`, so a 64-bit counter is never rounded. */
  varint(): bigint {
    let value = 0n;
    let shift = 0n;
    for (let read = 0; read < MAX_VARINT_BYTES; read += 1) {
      const byte = this.byte();
      value |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) return value;
      shift += 7n;
    }
    // An eleventh continuation byte cannot describe a 64-bit value.
    throw MALFORMED();
  }

  slice(length: number): Uint8Array {
    if (length < 0 || length > this.remaining) throw MALFORMED();
    const out = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }
}

function toSafeInt(value: bigint): number {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) throw MALFORMED();
  return Number(value);
}

/** Skip one field this reader does not model, or refuse if it cannot be skipped. */
function skipField(cursor: Cursor, wireType: number): void {
  switch (wireType) {
    case 0:
      cursor.varint();
      return;
    case 1:
      cursor.slice(8);
      return;
    case 2:
      cursor.slice(toSafeInt(cursor.varint()));
      return;
    case 5:
      cursor.slice(4);
      return;
    default:
      // Wire types 3 and 4 are start-group and end-group; 6 and 7 do not exist.
      // See rule 2 in the header for why this refuses rather than skips.
      throw new MigrationParseError(
        'unsupported-field',
        'That export uses a field type this app does not read.',
      );
  }
}

/**
 * Walk one message, handing each field's number and wire type to `visit`.
 *
 * Both messages this reader understands are walked by this one function, and
 * that is deliberate rather than tidiness: the loop carries three invariants
 * that must never be allowed to differ between them.
 *
 *  1. The field cap, which is what bounds the work a crafted payload can ask
 *     for on a message whose own length says nothing about how many fields it
 *     holds.
 *  2. The tag decode. A wrong shift or mask here does not fail, it silently
 *     reads a different field than the one on the wire.
 *  3. STRUCTURAL TERMINATION: every iteration must strictly advance the cursor.
 *     This is what makes the walk finite whatever `visit` did, including a
 *     `skipField` over an unknown field, and it holds without either caller
 *     having to remember it. A second copy of this loop would be a second place
 *     for that one line to be dropped, and dropping it is a hang rather than a
 *     wrong answer, so there is exactly one copy.
 *
 * `visit` reads whatever the field's payload is and leaves the cursor after it;
 * anything it throws travels out unchanged.
 */
function eachField(cursor: Cursor, visit: (fieldNumber: number, wireType: number) => void): void {
  let fields = 0;
  while (!cursor.done) {
    if ((fields += 1) > MAX_FIELDS_PER_MESSAGE) throw MALFORMED();
    const before = cursor.offset;
    const tag = toSafeInt(cursor.varint());
    visit(tag >>> 3, tag & 0x07);
    if (cursor.offset <= before) throw MALFORMED();
  }
}

const utf8 = new TextDecoder('utf-8', { fatal: false });

/**
 * Codepoint ranges removed from a label before anyone reads it.
 *
 * Written as NUMBERS rather than as a regular expression over the characters
 * themselves, for two reasons. A literal range would put real bidirectional
 * control characters into this source file, which is precisely the trojan-source
 * shape the repository's own lint rule exists to catch, and it would be a source
 * file nobody could review safely. And the intent reads better as a table.
 *
 *   - C0 and C1 controls, which have no business in a label at all.
 *   - Bidirectional overrides, embeddings and isolates. These REORDER rendered
 *     text, so an entry could be made to display an issuer it does not have,
 *     directly above the account a person is about to attach its key to. That is
 *     the highest-value spoof available against this feature and it is the one
 *     most often missed.
 *   - Zero-width characters and the byte-order mark, which make two entries look
 *     identical while being different.
 */
const STRIPPED_CODEPOINT_RANGES: readonly (readonly [number, number])[] = [
  [0x0000, 0x001f],
  [0x007f, 0x009f],
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2066, 0x2069],
  [0xfeff, 0xfeff],
];

function isStripped(codePoint: number): boolean {
  return STRIPPED_CODEPOINT_RANGES.some(([low, high]) => codePoint >= low && codePoint <= high);
}

/** Decode a label, then remove what a label must never carry. */
function decodeLabel(bytes: Uint8Array): string {
  if (bytes.byteLength > MAX_LABEL_BYTES) throw MALFORMED();
  let cleaned = '';
  for (const char of utf8.decode(bytes)) {
    if (!isStripped(char.codePointAt(0) ?? 0)) cleaned += char;
  }
  return cleaned.normalize('NFC').trim().slice(0, MAX_LABEL_LENGTH);
}

/**
 * Separate the issuer from the account name.
 *
 * Google Authenticator writes the label the way the `otpauth://` specification
 * does, as `Issuer:Account`, and it ALSO fills the separate issuer field. So the
 * name arrives carrying a prefix that is already known, and showing it verbatim
 * puts "Acme:alice@example.com" under a heading that already says "Acme".
 *
 * Two cases, and both occur:
 *   - the issuer field is set and the name repeats it as a prefix, which is
 *     stripped;
 *   - the issuer field is empty and the name carries it, which is split out on
 *     the FIRST colon, since neither part may contain one.
 */
function splitLabel(name: string, issuer: string): { issuer: string; account: string } {
  if (issuer.length > 0) {
    const prefix = `${issuer}:`;
    return name.startsWith(prefix)
      ? { issuer, account: name.slice(prefix.length).replace(/^ +/, '') }
      : { issuer, account: name };
  }
  const colon = name.indexOf(':');
  if (colon === -1) return { issuer: '', account: name };
  return {
    issuer: name.slice(0, colon).trim(),
    account: name.slice(colon + 1).replace(/^ +/, ''),
  };
}

/**
 * The fields of one `OtpParameters`, as they arrive.
 *
 * One record rather than seven locals because the walk fills them from inside a
 * callback, and `null` is what "this field has not been seen" means: every
 * branch below refuses a second sighting, which is rule 5.
 */
interface OtpFields {
  secret: Uint8Array | null;
  name: string | null;
  issuer: string | null;
  algorithm: MigrationAlgorithm | null;
  digits: 6 | 8 | null;
  type: 'totp' | 'hotp' | null;
  counter: string | null;
}

function readOtpParameters(bytes: Uint8Array): MigrationEntry {
  const cursor = new Cursor(bytes);
  const read: OtpFields = {
    secret: null,
    name: null,
    issuer: null,
    algorithm: null,
    digits: null,
    type: null,
    counter: null,
  };

  // A duplicate of a field this reader models is refused; see rule 5.
  eachField(cursor, (fieldNumber, wireType) => {
    switch (fieldNumber) {
      case 1: {
        if (wireType !== 2 || read.secret !== null) throw MALFORMED();
        read.secret = cursor.slice(toSafeInt(cursor.varint()));
        break;
      }
      case 2: {
        if (wireType !== 2 || read.name !== null) throw MALFORMED();
        read.name = decodeLabel(cursor.slice(toSafeInt(cursor.varint())));
        break;
      }
      case 3: {
        if (wireType !== 2 || read.issuer !== null) throw MALFORMED();
        read.issuer = decodeLabel(cursor.slice(toSafeInt(cursor.varint())));
        break;
      }
      case 4: {
        if (wireType !== 0 || read.algorithm !== null) throw MALFORMED();
        const resolved = ALGORITHMS.get(toSafeInt(cursor.varint()));
        if (resolved === undefined) {
          throw new MigrationParseError('bad-enum', 'That export uses an unknown hash algorithm.');
        }
        read.algorithm = resolved;
        break;
      }
      case 5: {
        if (wireType !== 0 || read.digits !== null) throw MALFORMED();
        const resolved = DIGIT_COUNTS.get(toSafeInt(cursor.varint()));
        if (resolved === undefined) {
          throw new MigrationParseError('bad-enum', 'That export uses an unknown code length.');
        }
        read.digits = resolved;
        break;
      }
      case 6: {
        if (wireType !== 0 || read.type !== null) throw MALFORMED();
        const resolved = OTP_TYPES.get(toSafeInt(cursor.varint()));
        if (resolved === undefined) {
          throw new MigrationParseError('bad-enum', 'That export uses an unknown code type.');
        }
        read.type = resolved;
        break;
      }
      case 7: {
        if (wireType !== 0 || read.counter !== null) throw MALFORMED();
        // Kept as a decimal string: `Number` would round a large counter, and a
        // rounded counter generates codes that never match.
        read.counter = cursor.varint().toString(10);
        break;
      }
      default:
        skipField(cursor, wireType);
        break;
    }
  });

  const secret = read.secret;
  if (secret === null || secret.byteLength < MIN_SECRET_BYTES) {
    throw new MigrationParseError('bad-secret', 'One of those accounts has no secret key.');
  }
  if (secret.byteLength > MAX_SECRET_BYTES) {
    throw new MigrationParseError('bad-secret', 'One of those accounts has an oversized key.');
  }

  const split = splitLabel(read.name ?? '', read.issuer ?? '');

  return {
    type: read.type ?? 'totp',
    // Copied out of the payload so the caller owns a buffer it can zero without
    // reaching into a slice of somebody else's array.
    secret: Uint8Array.from(secret),
    name: split.account,
    issuer: split.issuer,
    algorithm: read.algorithm ?? 'SHA1',
    digits: read.digits ?? 6,
    counter: read.type === 'hotp' ? read.counter : null,
  };
}

/** Read a decoded `MigrationPayload`, or throw a {@link MigrationParseError}. */
export function readMigrationPayload(bytes: Uint8Array): MigrationPayload {
  if (bytes.byteLength > MAX_MIGRATION_PAYLOAD_BYTES) {
    throw new MigrationParseError('too-large', 'That export is larger than this app will read.');
  }

  const cursor = new Cursor(bytes);
  const entries: MigrationEntry[] = [];
  let version = 0;
  let batchSize = 0;
  let batchIndex = 0;
  let batchId = 0;

  try {
    eachField(cursor, (fieldNumber, wireType) => {
      switch (fieldNumber) {
        case 1: {
          if (wireType !== 2) throw MALFORMED();
          if (entries.length >= MAX_OTP_PARAMETERS) {
            throw new MigrationParseError(
              'too-many-entries',
              'That export holds more accounts than this app will read at once.',
            );
          }
          entries.push(readOtpParameters(cursor.slice(toSafeInt(cursor.varint()))));
          break;
        }
        case 2:
          if (wireType !== 0) throw MALFORMED();
          version = toSafeInt(cursor.varint());
          break;
        case 3:
          if (wireType !== 0) throw MALFORMED();
          batchSize = toSafeInt(cursor.varint());
          break;
        case 4:
          if (wireType !== 0) throw MALFORMED();
          batchIndex = toSafeInt(cursor.varint());
          break;
        case 5:
          if (wireType !== 0) throw MALFORMED();
          batchId = toSafeInt(cursor.varint());
          break;
        default:
          skipField(cursor, wireType);
          break;
      }
    });
  } catch (error) {
    // `DataView` throws `RangeError` past the end of the buffer; that is a
    // truncated payload, which is the ordinary outcome of a partial scan.
    if (error instanceof RangeError) throw MALFORMED();
    throw error;
  }

  if (entries.length === 0) {
    throw new MigrationParseError('no-entries', 'That code carries no accounts.');
  }
  // `batch_size` is absent on a single-code export, so zero means one part.
  const size = batchSize === 0 ? 1 : batchSize;
  if (size > MAX_BATCH_SIZE || batchIndex >= size) {
    throw new MigrationParseError('bad-batch', 'That export describes an unusable set of codes.');
  }

  return { entries, version, batchSize: size, batchIndex, batchId };
}
