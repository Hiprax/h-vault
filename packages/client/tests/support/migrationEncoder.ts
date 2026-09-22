/**
 * A test-only encoder for Google Authenticator's export payload.
 *
 * The reader is the thing under test, so its inputs cannot come from the reader.
 * This builds the wire format independently, from the schema rather than from
 * the reader's code, which is what makes a round-trip test meaningful instead of
 * circular. It is also the only way to construct the shapes that matter most:
 * a truncated message, an unknown field, a group tag, an eleven-byte varint.
 */

export interface EncodableEntry {
  secret?: Uint8Array | undefined;
  name?: string | undefined;
  issuer?: string | undefined;
  /** Raw enum value, so a test can encode one the reader must reject. */
  algorithm?: number | undefined;
  digits?: number | undefined;
  type?: number | undefined;
  counter?: bigint | undefined;
}

export interface EncodablePayload {
  entries: EncodableEntry[];
  version?: number | undefined;
  batchSize?: number | undefined;
  batchIndex?: number | undefined;
  batchId?: number | undefined;
}

export function varint(value: number | bigint): number[] {
  let remaining = BigInt(value);
  if (remaining < 0n) throw new Error('varint: negative');
  const out: number[] = [];
  do {
    const byte = Number(remaining & 0x7fn);
    remaining >>= 7n;
    out.push(remaining > 0n ? byte | 0x80 : byte);
  } while (remaining > 0n);
  return out;
}

/**
 * A tag for ANY field number, as the raw varint of `(fieldNumber << 3) | wireType`
 * computed in `bigint`.
 *
 * The shapes this exists for are the ones a real encoder can never produce: a
 * field number of zero, one above protobuf's 2^29 - 1 ceiling, or one so large
 * its tag no longer fits in 32 bits. JavaScript's `<<` and `|` work on 32-bit
 * integers, so computing such a tag with them quietly yields a DIFFERENT, small
 * tag, which is exactly the aliasing a test here has to be able to express.
 */
export function bigTag(fieldNumber: bigint, wireType: number): number[] {
  if (fieldNumber < 0n) throw new Error('bigTag: negative field number');
  if (!Number.isInteger(wireType) || wireType < 0 || wireType > 7) {
    throw new Error('bigTag: a wire type is three bits');
  }
  return varint((fieldNumber << 3n) | BigInt(wireType));
}

/** The tag of an ordinary field. Exact for every field number, via {@link bigTag}. */
export function tag(fieldNumber: number, wireType: number): number[] {
  return bigTag(BigInt(fieldNumber), wireType);
}

function lengthDelimited(fieldNumber: number, bytes: ArrayLike<number>): number[] {
  return [...tag(fieldNumber, 2), ...varint(bytes.length), ...Array.from(bytes)];
}

function utf8(value: string): number[] {
  return [...new TextEncoder().encode(value)];
}

export function encodeEntry(entry: EncodableEntry): number[] {
  const out: number[] = [];
  if (entry.secret !== undefined) out.push(...lengthDelimited(1, entry.secret));
  if (entry.name !== undefined) out.push(...lengthDelimited(2, utf8(entry.name)));
  if (entry.issuer !== undefined) out.push(...lengthDelimited(3, utf8(entry.issuer)));
  if (entry.algorithm !== undefined) out.push(...tag(4, 0), ...varint(entry.algorithm));
  if (entry.digits !== undefined) out.push(...tag(5, 0), ...varint(entry.digits));
  if (entry.type !== undefined) out.push(...tag(6, 0), ...varint(entry.type));
  if (entry.counter !== undefined) out.push(...tag(7, 0), ...varint(entry.counter));
  return out;
}

export function encodePayload(payload: EncodablePayload): Uint8Array {
  const out: number[] = [];
  for (const entry of payload.entries) out.push(...lengthDelimited(1, encodeEntry(entry)));
  if (payload.version !== undefined) out.push(...tag(2, 0), ...varint(payload.version));
  if (payload.batchSize !== undefined) out.push(...tag(3, 0), ...varint(payload.batchSize));
  if (payload.batchIndex !== undefined) out.push(...tag(4, 0), ...varint(payload.batchIndex));
  if (payload.batchId !== undefined) out.push(...tag(5, 0), ...varint(payload.batchId));
  return Uint8Array.from(out);
}

export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** The URI Google Authenticator shows, with `data` percent-encoded as it does. */
export function encodeMigrationUri(payload: EncodablePayload): string {
  return `otpauth-migration://offline?data=${encodeURIComponent(toBase64(encodePayload(payload)))}`;
}

/**
 * The same URI with a literal `+` left unencoded in `data`.
 *
 * This is the shape that breaks a reader using `URLSearchParams`, which decodes
 * `+` as a space. `batchId` is nudged until the base64 happens to contain one,
 * so the test fixture is derived rather than hand-copied.
 */
export function encodeMigrationUriWithLiteralPlus(payload: EncodablePayload): string {
  for (let batchId = 0; batchId < 500; batchId += 1) {
    const base64 = toBase64(encodePayload({ ...payload, batchId }));
    if (base64.includes('+')) return `otpauth-migration://offline?data=${base64}`;
  }
  throw new Error('could not build a payload whose base64 contains "+"');
}

/** A 16-byte secret, deterministic so a failure reproduces. */
export function sampleSecret(seed = 1): Uint8Array {
  return Uint8Array.from({ length: 16 }, (_, i) => (seed * 31 + i * 17) & 0xff);
}
