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
 * SEVEN RULES THAT ARE NOT NEGOTIABLE
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
 *  6. A TAG IS A 32-BIT VALUE, AND FIELD NUMBER 0 DOES NOT EXIST. Protobuf
 *     encodes a tag as a uint32 varint, so field numbers run from 1 to 2^29 - 1.
 *     A varint can be wider than that, and readers do not agree on what a wider
 *     tag means: one that keeps its low 32 bits reads tag 2^32 + 10 as field 1,
 *     `otp_parameters`, while one that does not sees a field number the format
 *     does not allow. That is rule 5's differential again, and this reader
 *     refuses. Field 0 is what any tag below 8 decodes to,
 *     and no encoder emits it. The implementation-reserved range 19000-19999 is
 *     NOT refused: it is reserved from .proto DECLARATIONS, so on the wire it is
 *     an unknown field like any other, and it is skipped like one.
 *  7. A NUMBER IS READ ONLY IN A SPELLING EVERY READER AGREES ON. A varint can
 *     spell a small value in more bytes than it needs, and readers split three
 *     ways over that: protobufjs 7.x reads five bytes of a 32-bit value and then
 *     skips five more without looking at them, landing inside the next field;
 *     Google's C++ reader refuses a tag or a length longer than five bytes; Go
 *     reads the value. So a TAG and a LENGTH PREFIX are a `uint32` in at most five
 *     bytes, and a longer spelling is refused. An `int32` field (the payload's
 *     four numbers and the three enums) is read in exactly the two spellings
 *     protobuf writes: a non-negative value in at most five bytes, or a NEGATIVE
 *     one sign-extended to ten, which is how a negative `batch_id` arrives. Any
 *     other spelling (a value from 2^31 up in five bytes, or ten bytes that are
 *     not a sign extension) is refused too: no encoder writes one, and what every
 *     reader keeps of it, its low 32 bits, is not the number the bytes spell. The
 *     int64 `counter`, and an unknown varint being skipped, keep the full ten
 *     bytes: every reader measures those alike.
 */

/** The longest `otpauth-migration://` URI this will consider. */
export const MAX_MIGRATION_URI_LENGTH = 16_384;
/** A QR code cannot carry more than 2953 bytes in byte mode; this is generous. */
export const MAX_MIGRATION_PAYLOAD_BYTES = 4096;
/** Google Authenticator puts about ten accounts in a code. */
export const MAX_OTP_PARAMETERS = 64;
/** Anti-spin: a payload made of thousands of empty unknown fields stops here. */
const MAX_FIELDS_PER_MESSAGE = 256;
/**
 * A 64-bit varint is at most ten bytes. An eleventh is malformed, and so is a
 * tenth carrying more than bit 63: ten bytes hold seventy bits, and the six
 * above 64 are refused rather than kept, since one reader keeps them, another
 * wraps them away and a third refuses.
 */
const MAX_VARINT_BYTES = 10;
/** The most the tenth byte of a 64-bit varint may hold: bit 63, and nothing above. */
const MAX_FINAL_VARINT_BYTE = 0x01;
/**
 * The largest `uint32`, and so the largest tag protobuf can express: field
 * 2^29 - 1, wire type 7. Anything above it is refused; see rule 6.
 */
const MAX_UINT32 = 2n ** 32n - 1n;
/** The widest spelling of a tag, a length or a non-negative `int32`; see rule 7. */
const MAX_UINT32_VARINT_BYTES = 5;
/** The largest `int32`. */
const MAX_INT32 = 2n ** 31n - 1n;
/** The smallest `int32`, -2^31, as the 64-bit sign extension protobuf writes it. */
const MIN_SIGN_EXTENDED_INT32 = 2n ** 64n - 2n ** 31n;
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
  /**
   * Identifies the export a code belongs to, and is compared, never counted. A
   * random `int32` in Google Authenticator's exports, so it can be NEGATIVE.
   */
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
    return this.spelledVarint().value;
  }

  /**
   * A `uint32`: a TAG or a LENGTH PREFIX. At most five bytes, and no more than
   * 32 bits; see rule 7 in the header for why a longer spelling is refused
   * rather than read.
   */
  uint32(): bigint {
    const { value, width } = this.spelledVarint();
    if (width > MAX_UINT32_VARINT_BYTES || value > MAX_UINT32) throw MALFORMED();
    return value;
  }

  /** A length prefix, as the number of bytes {@link slice} should take. */
  length(): number {
    return Number(this.uint32());
  }

  /**
   * An `int32`, in one of the two spellings protobuf writes: a non-negative
   * value in at most five bytes, or a NEGATIVE one sign-extended to 64 bits,
   * which is always ten. Anything else is a number no `int32` can be; see rule 7.
   */
  int32(): number {
    const { value, width } = this.spelledVarint();
    if (value <= MAX_INT32 && width <= MAX_UINT32_VARINT_BYTES) return Number(value);
    // A value this large has bit 63 set, so its spelling is necessarily ten bytes.
    if (value >= MIN_SIGN_EXTENDED_INT32) return Number(BigInt.asIntN(64, value));
    throw MALFORMED();
  }

  /** A varint, and how many bytes spelled it. */
  private spelledVarint(): { value: bigint; width: number } {
    let value = 0n;
    let shift = 0n;
    for (let read = 1; read < MAX_VARINT_BYTES; read += 1) {
      const byte = this.byte();
      value |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) return { value, width: read };
      shift += 7n;
    }
    // The tenth byte may carry bit 63 and nothing else. That also refuses a
    // continuation bit here, since an eleventh byte cannot describe 64 bits.
    const last = this.byte();
    if (last > MAX_FINAL_VARINT_BYTE) throw MALFORMED();
    return { value: value | (BigInt(last) << shift), width: MAX_VARINT_BYTES };
  }

  slice(length: number): Uint8Array {
    if (length < 0 || length > this.remaining) throw MALFORMED();
    const out = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }
}

/** A count or an index, which an export can only mean as zero or more. */
function nonNegative(value: number): number {
  if (value < 0) throw MALFORMED();
  return value;
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
      cursor.slice(cursor.length());
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
 *     reads a different field than the one on the wire. So the tag is bounded
 *     to 32 bits and split with `bigint` shifts, never with `>>>` and `&` on a
 *     `number`: those coerce to 32 bits FIRST, which is precisely how tag
 *     2^32 + 10 used to be read as field 1 (rule 6). Field 0 is refused here too,
 *     so neither message can meet it.
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
    const tag = cursor.uint32();
    const fieldNumber = Number(tag >> 3n);
    if (fieldNumber === 0) throw MALFORMED();
    visit(fieldNumber, Number(tag & 0x07n));
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
        read.secret = cursor.slice(cursor.length());
        break;
      }
      case 2: {
        if (wireType !== 2 || read.name !== null) throw MALFORMED();
        read.name = decodeLabel(cursor.slice(cursor.length()));
        break;
      }
      case 3: {
        if (wireType !== 2 || read.issuer !== null) throw MALFORMED();
        read.issuer = decodeLabel(cursor.slice(cursor.length()));
        break;
      }
      case 4: {
        if (wireType !== 0 || read.algorithm !== null) throw MALFORMED();
        const resolved = ALGORITHMS.get(cursor.int32());
        if (resolved === undefined) {
          throw new MigrationParseError('bad-enum', 'That export uses an unknown hash algorithm.');
        }
        read.algorithm = resolved;
        break;
      }
      case 5: {
        if (wireType !== 0 || read.digits !== null) throw MALFORMED();
        const resolved = DIGIT_COUNTS.get(cursor.int32());
        if (resolved === undefined) {
          throw new MigrationParseError('bad-enum', 'That export uses an unknown code length.');
        }
        read.digits = resolved;
        break;
      }
      case 6: {
        if (wireType !== 0 || read.type !== null) throw MALFORMED();
        const resolved = OTP_TYPES.get(cursor.int32());
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
          entries.push(readOtpParameters(cursor.slice(cursor.length())));
          break;
        }
        case 2:
          if (wireType !== 0) throw MALFORMED();
          version = nonNegative(cursor.int32());
          break;
        case 3:
          if (wireType !== 0) throw MALFORMED();
          batchSize = nonNegative(cursor.int32());
          break;
        case 4:
          if (wireType !== 0) throw MALFORMED();
          batchIndex = nonNegative(cursor.int32());
          break;
        case 5:
          if (wireType !== 0) throw MALFORMED();
          // The one field that may be negative: a random `int32` identifier.
          batchId = cursor.int32();
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
