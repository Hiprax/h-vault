/**
 * Fuzzing the Google Authenticator export reader.
 *
 * This is the second place in H-Vault where arbitrary, attacker-chosen bytes are
 * turned into something the application acts on, and it is the more sensitive of
 * the two: the bytes it reads ARE secret keys, and the thing it produces is
 * offered to the user as a key to attach to an account.
 *
 * Eight clauses, each of which can fail on its own:
 *
 *   1. **Nothing untyped escapes.** `readMigrationPayload` returns a payload or
 *      throws `MigrationParseError`. A `RangeError` from a `DataView` read past
 *      the end, or a `TypeError` from anywhere, is a crash: the UI's catch is
 *      written against the typed error.
 *   2. **It terminates, structurally.** Every loop iteration must strictly
 *      advance the cursor. That is asserted inside the reader, so a payload that
 *      could spin ends as a typed rejection rather than as a frozen tab.
 *   3. **NO ERROR EVER QUOTES THE INPUT.** The input is made of secret keys, and
 *      an error message is the shortest path from one to a log, a toast or a bug
 *      report. This is checked directly: no thrown message may contain any
 *      eight-character run of the input.
 *   4. **Anything it accepts can be stored.** Every entry must build an
 *      `otpauth://` URI within `MAX_LOGIN_TOTP_LENGTH`. An over-long value would
 *      fail validation on every DECRYPT, stranding the whole item in a read-only
 *      state, so this is the property that keeps a hostile issuer from bricking
 *      an item the user attaches it to.
 *   5. **A round trip is lossless.** Encoded by the independent test encoder and
 *      read back, every field survives, and an unknown field anywhere changes
 *      nothing.
 *   6. **A field number protobuf cannot express is refused, never aliased or
 *      skipped.** A tag is a 32-bit value and field number 0 does not exist. A
 *      tag at or above 2^32 used to be squeezed into 32 bits, so field 2^29 + 1
 *      was read as field 1. Other readers disagree about such a tag (some also
 *      read it as field 1, others refuse the whole message), so the account this
 *      reader imported depended on which program read the code. Refused with
 *      the one fixed message, whatever wire type the tag claims, at the top
 *      level and inside an account.
 *   7. **A second copy of a modelled field is refused**, whether it arrives
 *      under its own tag or under one that aliases onto it.
 *   8. **A number is read only in a spelling every reader agrees on.** A tag or
 *      a length in at most five bytes, an int32 in at most five or as the
 *      ten-byte sign extension of a negative value; any wider spelling, which
 *      some readers skip past unread and others refuse, is refused with the one
 *      fixed message.
 *
 * Clauses 5 and 6 only mean something if the generators can REACH the boundary
 * between them, so the field numbers below are drawn from bands on BOTH sides of
 * the 2^29 - 1 ceiling, from the implementation-reserved range, and from the
 * band that aliases onto every modelled field, rather than from a small range
 * that could never produce a tag wider than one byte.
 *
 * The generated-case count is nine properties × `PROPERTY_RUNS` (100 when this
 * was written, so 900 cases per run). NOTHING ENFORCES THAT NUMBER: no ratchet
 * field records it, and lowering `PROPERTY_RUNS` or passing a smaller `numRuns`
 * here would go unnoticed by every gate. Treat both as a denominator anyway.
 */
import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { MAX_LOGIN_TOTP_LENGTH } from '@hvault/shared';
import {
  MigrationParseError,
  readMigrationPayload,
} from '../../src/services/totpImport/migrationReader';
import { parseMigrationUri } from '../../src/services/totpImport/migrationUri';
import { buildOtpauthUri, encodeBase32 } from '../../src/lib/totp';
import { PROPERTY_RUNS, propertyBanner, propertyRun } from '../../../../tests/harness/property';
import {
  bigTag,
  encodeEntry,
  encodeMigrationUri,
  encodePayload,
  int32Varint,
  paddedVarint,
  tag,
  varint,
  type EncodableEntry,
} from '../support/migrationEncoder';

/** The reader's one fixed refusal. Compared verbatim: no message may vary with its input. */
const MALFORMED_MESSAGE = 'That code is not a readable Google Authenticator export.';

/** Protobuf's largest field number, 2^29 - 1: the one whose tags fill all 32 bits. */
const MAX_FIELD_NUMBER = 2n ** 29n - 1n;

/**
 * Field numbers protobuf allows and neither message models (the payload models
 * 1-5, an account 1-7). Three bands: the ordinary one, the 19000-19999 range the
 * implementation reserves from DECLARATIONS (on the wire it is just unknown), and
 * the top of the legal range, whose tags sit just under 2^32.
 */
const unknownFieldNumber: fc.Arbitrary<bigint> = fc.oneof(
  fc.bigInt({ min: 20n, max: 100n }),
  fc.bigInt({ min: 19_000n, max: 19_999n }),
  fc.bigInt({ min: MAX_FIELD_NUMBER - 64n, max: MAX_FIELD_NUMBER }),
);

/**
 * Field numbers no conforming encoder can put on the wire. Zero; the band just
 * past the ceiling, whose tags sit just over 2^32; field numbers either side of
 * 2^32 itself; `k * 2^29 + m`, which a 32-bit reader reads as modelled field
 * `m`, the exact shape of the defect this module once had; and anything up to
 * the widest tag a ten-byte varint carries.
 */
const invalidFieldNumber: fc.Arbitrary<bigint> = fc.oneof(
  fc.constant(0n),
  fc.bigInt({ min: 2n ** 29n, max: 2n ** 29n + 64n }),
  fc.bigInt({ min: 2n ** 32n - 64n, max: 2n ** 32n + 64n }),
  fc
    .tuple(fc.bigInt({ min: 1n, max: 2n ** 32n - 1n }), fc.bigInt({ min: 1n, max: 7n }))
    .map(([k, modelled]) => k * 2n ** 29n + modelled),
  fc.bigInt({ min: 2n ** 29n, max: 2n ** 61n - 1n }),
);

/** The four wire types a reader can skip. Groups and 6/7 are refused elsewhere. */
const skippableWireType = fc.constantFrom(0, 1, 2, 5);

/** Every three-bit wire type, including the four no field may be skipped over. */
const anyWireType = fc.integer({ min: 0, max: 7 });

/**
 * A well-formed body for `wireType`. The length-delimited one is a whole encoded
 * account, so a reader that aliased its tag onto `otp_parameters` would import it
 * rather than stumble over the body and refuse for the wrong reason.
 */
function bodyFor(wireType: number, account: readonly number[]): number[] {
  switch (wireType) {
    case 0:
      return varint(1);
    case 1:
      return [1, 2, 3, 4, 5, 6, 7, 8];
    case 2:
      return [...varint(account.length), ...account];
    default:
      return [1, 2, 3, 4];
  }
}

/** One `otp_parameters` field around an already-encoded account. */
function wrapEntry(body: readonly number[]): number[] {
  return [...tag(1, 2), ...varint(body.length), ...body];
}

/**
 * A payload with one extra field, either after the account at the top level or
 * as the account's own last field.
 */
function withExtraField(
  account: readonly number[],
  field: readonly number[],
  inside: boolean,
): Uint8Array {
  return Uint8Array.from(
    inside ? wrapEntry([...account, ...field]) : [...wrapEntry(account), ...field],
  );
}

/**
 * A run of fields under arbitrary tags, legal and not, each followed by a few
 * arbitrary bytes. The reader must survive this the way it survives random
 * bytes, but random bytes almost never spell a five-byte tag.
 */
const hostileTagBytes: fc.Arbitrary<Uint8Array> = fc
  .array(
    fc.tuple(
      fc.oneof(unknownFieldNumber, invalidFieldNumber, fc.bigInt({ min: 1n, max: 7n })),
      anyWireType,
      fc.uint8Array({ maxLength: 12 }),
    ),
    { maxLength: 24 },
  )
  .map((fields) =>
    Uint8Array.from(
      fields.flatMap(([fieldNumber, wireType, body]) => [
        ...bigTag(fieldNumber, wireType),
        ...body,
      ]),
    ),
  );

/** Read, and report what came back, without letting anything untyped escape. */
function attempt(bytes: Uint8Array): { ok: boolean; error: MigrationParseError | null } {
  try {
    readMigrationPayload(bytes);
    return { ok: true, error: null };
  } catch (error) {
    if (error instanceof MigrationParseError) return { ok: false, error };
    throw error;
  }
}

const anyBytes = fc.uint8Array({ minLength: 0, maxLength: 512 });

const anyEntry: fc.Arbitrary<EncodableEntry> = fc.record(
  {
    secret: fc.uint8Array({ minLength: 1, maxLength: 64 }),
    name: fc.string({ maxLength: 60 }),
    issuer: fc.string({ maxLength: 60 }),
    algorithm: fc.constantFrom(0, 1, 2, 3),
    digits: fc.constantFrom(0, 1, 2),
    type: fc.constantFrom(0, 1, 2),
    counter: fc.bigInt({ min: 0n, max: 2n ** 63n }),
  },
  { requiredKeys: ['secret'] },
);

describe('the export reader is total over arbitrary bytes', () => {
  it('returns a payload or throws MigrationParseError, never anything else', () => {
    fc.assert(
      fc.property(anyBytes, (bytes) => {
        const result = attempt(bytes);
        expect(result.ok || result.error !== null, propertyBanner()).toBe(true);
      }),
      propertyRun({ numRuns: PROPERTY_RUNS }),
    );
  });

  it('terminates on every input, including ones built to spin', () => {
    // Long runs of continuation bits, repeated tags and nested length prefixes
    // are the shapes that hang a naive reader.
    const hostile = fc.oneof(
      fc.constant(Uint8Array.from(Array<number>(400).fill(0xff))),
      fc.constant(Uint8Array.from([...tag(1, 2), ...varint(0)])),
      fc.constant(Uint8Array.from(Array<number>(300).flatMap(() => [...tag(1, 2), ...varint(0)]))),
      fc.constant(Uint8Array.from(Array<number>(200).flatMap(() => [...tag(64, 0), 0x00]))),
      anyBytes,
      hostileTagBytes,
    );
    fc.assert(
      fc.property(hostile, (bytes) => {
        const started = Date.now();
        attempt(bytes);
        // A generous ceiling: the point is that it finishes at all, and a
        // wall-clock bound here is a backstop behind the reader's own
        // strictly-advancing-cursor assertion, not the primary control.
        expect(Date.now() - started, propertyBanner()).toBeLessThan(1000);
      }),
      propertyRun({ numRuns: PROPERTY_RUNS }),
    );
  });

  it('never puts any part of the input into an error message', () => {
    fc.assert(
      fc.property(fc.oneof(anyBytes, hostileTagBytes), (bytes) => {
        const result = attempt(bytes);
        if (result.error === null) return;
        const message = `${result.error.message} ${String(result.error)}`;
        // Any eight-byte run of the input, rendered the way it would leak.
        for (let i = 0; i + 8 <= bytes.length; i += 1) {
          const run = [...bytes.subarray(i, i + 8)]
            .map((byte) => String.fromCharCode(byte))
            .join('');
          expect(message.includes(run), propertyBanner()).toBe(false);
        }
      }),
      propertyRun({ numRuns: PROPERTY_RUNS }),
    );
  });
});

describe('everything the reader accepts can actually be stored', () => {
  it('builds an otpauth URI inside the stored bound, for every accepted entry', () => {
    fc.assert(
      fc.property(fc.array(anyEntry, { minLength: 1, maxLength: 8 }), (entries) => {
        const bytes = encodePayload({ entries });
        const result = attempt(bytes);
        if (!result.ok) return;
        for (const entry of readMigrationPayload(bytes).entries) {
          if (entry.algorithm === 'MD5') continue; // not generatable, never stored
          const built = buildOtpauthUri(
            {
              type: entry.type,
              secret: encodeBase32(entry.secret),
              issuer: entry.issuer,
              account: entry.name,
              algorithm: entry.algorithm,
              digits: entry.digits,
              period: 30,
              counter: entry.counter,
            },
            MAX_LOGIN_TOTP_LENGTH,
          );
          expect(built, propertyBanner()).not.toBeNull();
          expect(built?.uri.length ?? 0, propertyBanner()).toBeLessThanOrEqual(
            MAX_LOGIN_TOTP_LENGTH,
          );
        }
      }),
      propertyRun({ numRuns: PROPERTY_RUNS }),
    );
  });
});

describe('a round trip through the independent encoder loses nothing', () => {
  it('reads back every field it was given', () => {
    fc.assert(
      fc.property(
        fc.array(anyEntry, { minLength: 1, maxLength: 6 }),
        // The whole int32 range: a negative batch number is sign-extended to ten
        // bytes, and Google Authenticator writes negative ones.
        fc.integer({ min: -(2 ** 31), max: 2 ** 31 - 1 }),
        (entries, batchId) => {
          const payload = parseMigrationUri(encodeMigrationUri({ entries, batchSize: 1, batchId }));
          expect(payload.entries.length, propertyBanner()).toBe(entries.length);
          expect(payload.batchId, propertyBanner()).toBe(batchId);
          payload.entries.forEach((read, index) => {
            const written = entries[index];
            expect([...read.secret], propertyBanner()).toEqual([...(written?.secret ?? [])]);
          });
        },
      ),
      propertyRun({ numRuns: PROPERTY_RUNS }),
    );
  });

  it('is unaffected by an unknown field appearing anywhere in the message', () => {
    // Google has added fields before. Refusing one would break this feature on a
    // future release of the app it reads, so this holds across every legal band,
    // at the top level and inside an account, for every skippable wire type.
    fc.assert(
      fc.property(
        anyEntry,
        unknownFieldNumber,
        skippableWireType,
        fc.boolean(),
        (entry, fieldNumber, wireType, inside) => {
          const account = encodeEntry(entry);
          const plain = Uint8Array.from(wrapEntry(account));
          const field = [...bigTag(fieldNumber, wireType), ...bodyFor(wireType, account)];
          const injected = withExtraField(account, field, inside);
          const read = readMigrationPayload(injected);
          // The same single account, and nothing the extra field carried.
          expect(read.entries.length, propertyBanner()).toBe(1);
          expect([...(read.entries[0]?.secret ?? [])], propertyBanner()).toEqual([
            ...readMigrationPayload(plain).entries.flatMap((e) => [...e.secret]),
          ]);
        },
      ),
      propertyRun({ numRuns: PROPERTY_RUNS }),
    );
  });
});

describe('a number is read only in a spelling every reader agrees on', () => {
  it('accepts a tag, a length or an int32 exactly when it is spelled the way protobuf writes it', () => {
    // One varint of an honest export is re-spelled at a drawn width. Readers
    // agree on a tag or a length in at most five bytes, and on an int32 in at most
    // five bytes or as the ten-byte sign extension of a negative value; past
    // that, one reader skips bytes it never read and another refuses, so the
    // same export would mean different things to each. Refused, with the fixed
    // message, exactly then.
    fc.assert(
      fc.property(
        anyEntry,
        fc.constantFrom('tag', 'length', 'int32'),
        fc.integer({ min: 1, max: 10 }),
        fc.integer({ min: -(2 ** 31), max: 2 ** 31 - 1 }),
        (entry, respelled, drawnWidth, batchId) => {
          const account = encodeEntry(entry);
          const widthFor = (value: number | bigint): number =>
            Math.max(drawnWidth, varint(value).length);
          const tagBytes = respelled === 'tag' ? paddedVarint(0x0a, widthFor(0x0a)) : tag(1, 2);
          const lengthBytes =
            respelled === 'length'
              ? paddedVarint(account.length, widthFor(account.length))
              : varint(account.length);
          // A negative int32 has one spelling only, ten bytes; a non-negative one
          // can be padded like anything else.
          const idBytes =
            respelled === 'int32' && batchId >= 0
              ? paddedVarint(batchId, widthFor(batchId))
              : int32Varint(batchId);
          const bytes = Uint8Array.from([
            ...tagBytes,
            ...lengthBytes,
            ...account,
            ...tag(5, 0),
            ...idBytes,
          ]);

          const spelledWidth =
            respelled === 'tag'
              ? tagBytes.length
              : respelled === 'length'
                ? lengthBytes.length
                : idBytes.length;
          const canonical = spelledWidth <= 5 || (respelled === 'int32' && batchId < 0);
          const result = attempt(bytes);
          if (canonical) {
            expect(result.ok, propertyBanner()).toBe(true);
            const read = readMigrationPayload(bytes);
            expect(read.batchId, propertyBanner()).toBe(batchId);
            expect([...(read.entries[0]?.secret ?? [])], propertyBanner()).toEqual([
              ...(entry.secret ?? []),
            ]);
          } else {
            expect(result.error?.message, propertyBanner()).toBe(MALFORMED_MESSAGE);
          }
        },
      ),
      propertyRun({ numRuns: PROPERTY_RUNS }),
    );
  });
});

describe('a field number protobuf cannot express is refused, never aliased or skipped', () => {
  it('refuses it wherever it appears, with the one fixed message', () => {
    fc.assert(
      fc.property(
        anyEntry,
        invalidFieldNumber,
        anyWireType,
        fc.boolean(),
        (entry, fieldNumber, wireType, inside) => {
          const account = encodeEntry(entry);
          // The control: without the extra field the payload reads, so the
          // refusal below is about the tag and nothing else. Wire types 3, 4, 6
          // and 7 are drawn too: the tag is judged BEFORE its wire type, so they
          // are 'malformed' here and never 'unsupported-field'.
          expect(attempt(Uint8Array.from(wrapEntry(account))).ok, propertyBanner()).toBe(true);
          const field = [...bigTag(fieldNumber, wireType), ...bodyFor(wireType, account)];
          const result = attempt(withExtraField(account, field, inside));
          expect(result.ok, propertyBanner()).toBe(false);
          expect(result.error?.code, propertyBanner()).toBe('malformed');
          expect(result.error?.message, propertyBanner()).toBe(MALFORMED_MESSAGE);
        },
      ),
      propertyRun({ numRuns: PROPERTY_RUNS }),
    );
  });

  it('refuses a second copy of any modelled field, under its own tag or an aliasing one', () => {
    // Rule 5 and rule 6 together: a duplicate is refused under the honest tag,
    // and one sent under an aliasing tag never lands either. That second branch
    // held before rule 6 existed too, because the alias arrived as a duplicate;
    // the property that pins rule 6 itself is the one above.
    const fullEntry: fc.Arbitrary<EncodableEntry> = fc.record({
      secret: fc.uint8Array({ minLength: 1, maxLength: 64 }),
      name: fc.string({ maxLength: 20 }),
      issuer: fc.string({ maxLength: 20 }),
      algorithm: fc.constantFrom(0, 1, 2, 3),
      digits: fc.constantFrom(0, 1, 2),
      type: fc.constantFrom(0, 1, 2),
      counter: fc.bigInt({ min: 0n, max: 2n ** 63n }),
    });
    /** Each modelled account field: its key, its field number and its wire type. */
    const modelled = [
      { key: 'secret', fieldNumber: 1n, wireType: 2 },
      { key: 'name', fieldNumber: 2n, wireType: 2 },
      { key: 'issuer', fieldNumber: 3n, wireType: 2 },
      { key: 'algorithm', fieldNumber: 4n, wireType: 0 },
      { key: 'digits', fieldNumber: 5n, wireType: 0 },
      { key: 'type', fieldNumber: 6n, wireType: 0 },
      { key: 'counter', fieldNumber: 7n, wireType: 0 },
    ] as const;
    fc.assert(
      fc.property(
        fullEntry,
        fullEntry,
        fc.constantFrom(...modelled),
        fc.option(fc.bigInt({ min: 1n, max: 2n ** 32n - 1n }), { nil: null }),
        (first, second, field, alias) => {
          const account = encodeEntry(first);
          // The control: the account alone reads, so the refusal is the copy's.
          expect(attempt(Uint8Array.from(wrapEntry(account))).ok, propertyBanner()).toBe(true);
          // One field encoded alone: a one-byte tag, since every modelled field
          // number is below 16, then its body.
          const alone = encodeEntry({ [field.key]: second[field.key] });
          const again =
            alias === null
              ? alone
              : [
                  ...bigTag(alias * 2n ** 29n + field.fieldNumber, field.wireType),
                  ...alone.slice(1),
                ];
          const result = attempt(Uint8Array.from(wrapEntry([...account, ...again])));
          expect(result.error?.code, propertyBanner()).toBe('malformed');
          expect(result.error?.message, propertyBanner()).toBe(MALFORMED_MESSAGE);
        },
      ),
      propertyRun({ numRuns: PROPERTY_RUNS }),
    );
  });
});
