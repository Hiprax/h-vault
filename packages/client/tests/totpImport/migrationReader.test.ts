import { describe, it, expect } from 'vitest';
import {
  MAX_BATCH_SIZE,
  MAX_OTP_PARAMETERS,
  MAX_SECRET_BYTES,
  MigrationParseError,
  readMigrationPayload,
} from '../../src/services/totpImport/migrationReader';
import {
  bigTag,
  encodeEntry,
  encodePayload,
  int32Varint,
  paddedVarint,
  sampleSecret,
  tag,
  varint,
} from '../support/migrationEncoder';

/**
 * Every rejection here is a decision recorded in the reader's header, and each
 * test names the bad outcome it prevents rather than merely the branch it takes.
 */

function reasonFor(bytes: Uint8Array): string {
  try {
    readMigrationPayload(bytes);
  } catch (error) {
    if (error instanceof MigrationParseError) return error.code;
    return `unexpected:${String(error)}`;
  }
  return 'no-error';
}

describe('readMigrationPayload, the happy path', () => {
  it('reads an account with every field set', () => {
    const secret = sampleSecret();
    const payload = readMigrationPayload(
      encodePayload({
        entries: [
          {
            secret,
            name: 'GitHub:alice@example.com',
            issuer: 'GitHub',
            algorithm: 2,
            digits: 2,
            type: 2,
          },
        ],
        version: 1,
        batchSize: 1,
        batchIndex: 0,
        batchId: 4242,
      }),
    );

    expect(payload.entries).toHaveLength(1);
    const [entry] = payload.entries;
    expect(entry?.algorithm).toBe('SHA256');
    expect(entry?.digits).toBe(8);
    expect(entry?.type).toBe('totp');
    expect(entry?.issuer).toBe('GitHub');
    expect([...(entry?.secret ?? [])]).toEqual([...secret]);
    expect(payload.batchId).toBe(4242);
  });

  it('reads protobuf implicit defaults the way every other implementation does', () => {
    // Zero is genuinely "unspecified" on the wire, and Google Authenticator
    // means SHA1 / six digits / TOTP by it. This is the ONE place a missing
    // value is filled in rather than refused.
    const payload = readMigrationPayload(encodePayload({ entries: [{ secret: sampleSecret() }] }));
    const [entry] = payload.entries;
    expect(entry?.algorithm).toBe('SHA1');
    expect(entry?.digits).toBe(6);
    expect(entry?.type).toBe('totp');
    expect(entry?.counter).toBeNull();
  });

  it('treats an absent batch size as a single-code export', () => {
    // Without this a one-code export could never complete, because the batch
    // collector would be waiting for part 0 of 0.
    const payload = readMigrationPayload(encodePayload({ entries: [{ secret: sampleSecret() }] }));
    expect(payload.batchSize).toBe(1);
    expect(payload.batchIndex).toBe(0);
  });

  it('keeps a 64-bit counter exactly, as a string', () => {
    // `Number` would round this, and a rounded counter generates codes that
    // never match for the rest of the account's life.
    const counter = 18_446_744_073_709_551_615n;
    const payload = readMigrationPayload(
      encodePayload({ entries: [{ secret: sampleSecret(), type: 1, counter }] }),
    );
    expect(payload.entries[0]?.counter).toBe('18446744073709551615');
    expect(payload.entries[0]?.type).toBe('hotp');
  });

  it('ignores a counter on a time-based entry, where it has no meaning', () => {
    const payload = readMigrationPayload(
      encodePayload({ entries: [{ secret: sampleSecret(), type: 2, counter: 9n }] }),
    );
    expect(payload.entries[0]?.counter).toBeNull();
  });

  it('skips a field number it does not model, so a future export still reads', () => {
    const entry = encodeEntry({ secret: sampleSecret() });
    const withUnknown = Uint8Array.from([
      ...tag(1, 2),
      ...varint(entry.length),
      ...entry,
      // Field 64, length-delimited, four bytes of anything.
      ...tag(64, 2),
      ...varint(4),
      1,
      2,
      3,
      4,
      // Field 65, varint.
      ...tag(65, 0),
      ...varint(9999),
    ]);
    expect(readMigrationPayload(withUnknown).entries).toHaveLength(1);
  });

  it('skips an unknown field inside an account, not only at the top level', () => {
    // Google has added fields before, and an entry is where a new one would most
    // likely appear.
    const entry = [
      ...encodeEntry({ secret: sampleSecret() }),
      ...tag(40, 0),
      ...varint(7),
      ...tag(41, 2),
      ...varint(2),
      9,
      9,
    ];
    const bytes = Uint8Array.from([...tag(1, 2), ...varint(entry.length), ...entry]);
    expect(readMigrationPayload(bytes).entries).toHaveLength(1);
  });
});

describe('readMigrationPayload, refusals', () => {
  it('refuses an unknown algorithm rather than falling back to SHA1', () => {
    // Falling back is the dangerous failure: every code would look right and
    // none would work, with nothing to say why.
    expect(reasonFor(encodePayload({ entries: [{ secret: sampleSecret(), algorithm: 99 }] }))).toBe(
      'bad-enum',
    );
  });

  it('refuses an unknown code length rather than assuming six', () => {
    expect(reasonFor(encodePayload({ entries: [{ secret: sampleSecret(), digits: 9 }] }))).toBe(
      'bad-enum',
    );
  });

  it('refuses an unknown code type', () => {
    expect(reasonFor(encodePayload({ entries: [{ secret: sampleSecret(), type: 7 }] }))).toBe(
      'bad-enum',
    );
  });

  it('refuses an entry with no secret, and one with an empty secret', () => {
    expect(reasonFor(encodePayload({ entries: [{ name: 'a' }] }))).toBe('bad-secret');
    expect(reasonFor(encodePayload({ entries: [{ secret: new Uint8Array(0) }] }))).toBe(
      'bad-secret',
    );
  });

  it('refuses an oversized secret', () => {
    const huge = new Uint8Array(MAX_SECRET_BYTES + 1).fill(7);
    expect(reasonFor(encodePayload({ entries: [{ secret: huge }] }))).toBe('bad-secret');
  });

  it('refuses a payload carrying no accounts at all', () => {
    expect(reasonFor(encodePayload({ entries: [], batchSize: 1 }))).toBe('no-entries');
  });

  it('refuses more accounts than it will read at once', () => {
    const entries = Array.from({ length: MAX_OTP_PARAMETERS + 1 }, (_, i) => ({
      secret: sampleSecret(i + 1),
    }));
    expect(reasonFor(encodePayload({ entries }))).toBe('too-many-entries');
  });

  it('refuses a group tag outright instead of trying to skip it', () => {
    // Skipping a group correctly means matching nested end-group tags, which is
    // the unbounded recursion this reader is built not to contain.
    const bytes = Uint8Array.from([...tag(9, 3), ...tag(9, 4)]);
    expect(reasonFor(bytes)).toBe('unsupported-field');
  });

  it('refuses a wire type that does not exist', () => {
    expect(reasonFor(Uint8Array.from([...tag(9, 6)]))).toBe('unsupported-field');
  });

  it('refuses an over-long varint', () => {
    const eleven = Uint8Array.from([...tag(2, 0), ...Array<number>(11).fill(0xff)]);
    expect(reasonFor(eleven)).toBe('malformed');
  });

  it.each([0x02, 0x7f])(
    'refuses a ten-byte varint whose last byte is %i, wider than 64 bits, instead of keeping the excess',
    (last) => {
      // Ten bytes carry seventy bits, and only the lowest of the tenth byte's
      // seven belongs to a 64-bit value. Kept, the rest made a counter no 64-bit
      // reader could hold: one reader refuses it and another wraps it modulo
      // 2^64, which is two readers disagreeing about the same account's key
      // state. 0x02 is the first value past the boundary the next test accepts.
      const overflow = [...Array<number>(9).fill(0xff), last];
      const body = [...encodeEntry({ secret: sampleSecret(), type: 1 }), ...tag(7, 0), ...overflow];
      const bytes = Uint8Array.from([...tag(1, 2), ...varint(body.length), ...body]);
      expect(reasonFor(bytes)).toBe('malformed');
    },
  );

  it('still reads the widest 64-bit varint, whose tenth byte is 1', () => {
    // The boundary on the other side: 2^64 - 1 is ten bytes ending in 0x01.
    expect(varint(2n ** 64n - 1n).at(-1)).toBe(0x01);
    const payload = readMigrationPayload(
      encodePayload({ entries: [{ secret: sampleSecret(), type: 1, counter: 2n ** 64n - 1n }] }),
    );
    expect(payload.entries[0]?.counter).toBe('18446744073709551615');
  });

  it('refuses a length that runs past the end of the message', () => {
    const bytes = Uint8Array.from([...tag(1, 2), ...varint(200), 1, 2, 3]);
    expect(reasonFor(bytes)).toBe('malformed');
  });

  it('refuses a truncated message rather than returning what it managed to read', () => {
    const full = encodePayload({ entries: [{ secret: sampleSecret(), name: 'abc' }] });
    for (let cut = 1; cut < full.length; cut += 1) {
      const reason = reasonFor(full.subarray(0, cut));
      // Either it refuses, or it legitimately read a shorter but complete
      // message. What it must never do is throw something that is not ours.
      expect(reason.startsWith('unexpected:')).toBe(false);
    }
  });

  it('refuses a duplicate scalar, which is the shape of a parser-differential attack', () => {
    // Protobuf says last-one-wins. Google Authenticator never emits duplicates,
    // so two `secret` fields means two readers could disagree about which key
    // this entry has.
    const doubled = [
      ...encodeEntry({ secret: sampleSecret(1) }),
      ...encodeEntry({ secret: sampleSecret(2) }),
    ];
    const bytes = Uint8Array.from([...tag(1, 2), ...varint(doubled.length), ...doubled]);
    expect(reasonFor(bytes)).toBe('malformed');
  });

  it('refuses a batch larger than it will display', () => {
    const entries = [{ secret: sampleSecret() }];
    expect(reasonFor(encodePayload({ entries, batchSize: MAX_BATCH_SIZE + 1 }))).toBe('bad-batch');
  });

  it('refuses a part index outside its own batch', () => {
    const entries = [{ secret: sampleSecret() }];
    expect(reasonFor(encodePayload({ entries, batchSize: 2, batchIndex: 5 }))).toBe('bad-batch');
  });

  it('refuses a payload larger than it will read', () => {
    expect(reasonFor(new Uint8Array(5000))).toBe('too-large');
  });
});

describe('every modelled field is pinned to its wire type and to one occurrence', () => {
  /** An entry whose field `number` is encoded with the WRONG wire type. */
  function entryWithWireType(fieldNumber: number, wireType: number): Uint8Array {
    const body = [
      ...encodeEntry({ secret: sampleSecret() }),
      ...tag(fieldNumber, wireType),
      // A varint body, which is wrong for a length-delimited field and right for
      // the ones that expect a varint, so each case is the mismatch it names.
      ...varint(1),
    ];
    return Uint8Array.from([...tag(1, 2), ...varint(body.length), ...body]);
  }

  it.each([
    ['name', 2, 0],
    ['issuer', 3, 0],
    ['algorithm', 4, 2],
    ['digits', 5, 2],
    ['type', 6, 2],
    ['counter', 7, 2],
  ])('refuses %s carrying the wrong wire type', (_label, fieldNumber, wireType) => {
    // A field encoded as something other than its declared type is a message
    // this reader did not produce and cannot vouch for.
    expect(reasonFor(entryWithWireType(fieldNumber, wireType))).toBe('malformed');
  });

  it.each([
    ['name', { secret: sampleSecret(), name: 'a' }, { name: 'b' }],
    ['issuer', { secret: sampleSecret(), issuer: 'a' }, { issuer: 'b' }],
    ['algorithm', { secret: sampleSecret(), algorithm: 1 }, { algorithm: 2 }],
    ['digits', { secret: sampleSecret(), digits: 1 }, { digits: 2 }],
    ['type', { secret: sampleSecret(), type: 2 }, { type: 1 }],
    ['counter', { secret: sampleSecret(), type: 1, counter: 1n }, { counter: 2n }],
  ])('refuses a duplicated %s', (_label, first, second) => {
    // Protobuf says last-one-wins. This does not: Google Authenticator never
    // emits a duplicate, so two of anything is the shape of a message crafted so
    // that two readers disagree about what it says.
    const body = [...encodeEntry(first), ...encodeEntry(second)];
    const bytes = Uint8Array.from([...tag(1, 2), ...varint(body.length), ...body]);
    expect(reasonFor(bytes)).toBe('malformed');
  });

  it('refuses a label longer than it will decode', () => {
    expect(
      reasonFor(encodePayload({ entries: [{ secret: sampleSecret(), name: 'x'.repeat(600) }] })),
    ).toBe('malformed');
  });

  it('refuses a message padded out with more fields than it will read', () => {
    // Anti-spin: a payload made of thousands of empty unknown fields would
    // otherwise be read to the end, however long that took.
    const filler: number[] = [];
    for (let i = 0; i < 300; i += 1) filler.push(...tag(90, 0), ...varint(1));
    expect(reasonFor(Uint8Array.from(filler))).toBe('malformed');
  });

  it('refuses an account padded out the same way', () => {
    const body: number[] = [...encodeEntry({ secret: sampleSecret() })];
    for (let i = 0; i < 300; i += 1) body.push(...tag(90, 0), ...varint(1));
    const bytes = Uint8Array.from([...tag(1, 2), ...varint(body.length), ...body]);
    expect(reasonFor(bytes)).toBe('malformed');
  });

  it('refuses a length too large to be a safe integer', () => {
    // A ten-byte varint is legal on the wire and cannot be a length this reader
    // could act on. 2^64 - 1, the widest value a 64-bit varint carries, so the
    // refusal is the safe-integer bound's rather than the varint's own.
    const huge = Uint8Array.from([...tag(1, 2), ...Array<number>(9).fill(0xff), 0x01]);
    expect(reasonFor(huge)).toBe('malformed');
  });
});

describe('a tag is a 32-bit value, and field number 0 does not exist', () => {
  /**
   * The one fixed sentence every malformed payload gets. Asserted verbatim, not
   * merely by code: rule 4 of the reader's header is that no error carries any
   * part of the input, and an assertion on the code alone would still pass if a
   * refusal here started quoting the tag it refused.
   */
  const MALFORMED_MESSAGE = 'That code is not a readable Google Authenticator export.';

  /** Protobuf's largest field number, 2^29 - 1: the one whose tags fill 32 bits. */
  const MAX_FIELD_NUMBER = 2n ** 29n - 1n;

  /**
   * Field 2^29 + 1 on the wire, whose tag is 2^32 + ((1 << 3) | 2). A reader
   * that takes the low 32 bits of the tag sees field 1, `otp_parameters`; the
   * field on the wire is one no conforming reader models.
   */
  const ALIASES_FIELD_ONE = 2n ** 29n + 1n;

  function refusal(bytes: Uint8Array): { code: string; message: string } {
    try {
      readMigrationPayload(bytes);
    } catch (error) {
      if (error instanceof MigrationParseError) return { code: error.code, message: error.message };
      return { code: `unexpected:${String(error)}`, message: '' };
    }
    return { code: 'no-error', message: '' };
  }

  function wrapEntry(body: readonly number[]): number[] {
    return [...tag(1, 2), ...varint(body.length), ...body];
  }

  const honestEntry = encodeEntry({ secret: sampleSecret(1), name: 'honest' });
  const hiddenEntry = encodeEntry({ secret: sampleSecret(2), name: 'hidden' });

  it('the fixtures below are well formed, so each refusal is about its tag alone', () => {
    // The control for every case in this block: the same bytes under an honest
    // tag read cleanly. Without it, a refusal could be blamed on the body.
    const payload = readMigrationPayload(
      Uint8Array.from([...wrapEntry(honestEntry), ...wrapEntry(hiddenEntry)]),
    );
    expect(payload.entries.map((entry) => entry.name)).toEqual(['honest', 'hidden']);
  });

  it('refuses a top-level tag above 2^32 instead of reading it as otp_parameters', () => {
    const bytes = Uint8Array.from([
      ...bigTag(ALIASES_FIELD_ONE, 2),
      ...varint(hiddenEntry.length),
      ...hiddenEntry,
    ]);
    // A reader that skipped it would say 'no-entries'; one that aliased it
    // would import the account. Only a refusal of the whole payload is right.
    expect(refusal(bytes)).toEqual({ code: 'malformed', message: MALFORMED_MESSAGE });
  });

  it('refuses the aliased entry even behind an honest one, so nothing is imported', () => {
    // The shape an attack would take: a payload that looks ordinary to every
    // reader except one, which also sees the hidden account.
    const bytes = Uint8Array.from([
      ...wrapEntry(honestEntry),
      ...bigTag(ALIASES_FIELD_ONE, 2),
      ...varint(hiddenEntry.length),
      ...hiddenEntry,
    ]);
    expect(refusal(bytes)).toEqual({ code: 'malformed', message: MALFORMED_MESSAGE });
  });

  it('refuses the same aliasing inside an account, where it would supply the secret', () => {
    // Field 2^29 + 1 inside OtpParameters aliases onto field 1, `secret`.
    const secret = sampleSecret(3);
    const body = [
      ...bigTag(ALIASES_FIELD_ONE, 2),
      ...varint(secret.length),
      ...secret,
      ...tag(2, 2),
      ...varint(1),
      0x61,
    ];
    expect(refusal(Uint8Array.from(wrapEntry(body)))).toEqual({
      code: 'malformed',
      message: MALFORMED_MESSAGE,
    });
  });

  it.each([
    ['length-delimited', 2, [...varint(3), 1, 2, 3]],
    ['varint', 0, varint(7)],
  ])('refuses field number 0 (%s) at the top level', (_label, wireType, body) => {
    // Protobuf reserves field 0: no encoder emits it, so a message carrying one
    // was not written by anything this reader should trust.
    const bytes = Uint8Array.from([...wrapEntry(honestEntry), ...tag(0, wireType), ...body]);
    expect(refusal(bytes)).toEqual({ code: 'malformed', message: MALFORMED_MESSAGE });
  });

  it.each([
    ['length-delimited', 2, [...varint(3), 1, 2, 3]],
    ['varint', 0, varint(7)],
  ])('refuses field number 0 (%s) inside an account', (_label, wireType, body) => {
    const entry = [...honestEntry, ...tag(0, wireType), ...body];
    expect(refusal(Uint8Array.from(wrapEntry(entry)))).toEqual({
      code: 'malformed',
      message: MALFORMED_MESSAGE,
    });
  });

  it.each([
    ['field 2^29, whose varint tag is exactly 2^32', 2n ** 29n, 0],
    ['field 2^32 + 1', 2n ** 32n + 1n, 2],
    ['a tag just above the largest safe integer', 2n ** 50n, 0],
    ['a tag near 2^64, the largest a ten-byte varint carries here', 2n ** 61n - 1n, 0],
  ])('refuses %s', (_label, fieldNumber, wireType) => {
    // A length-delimited body is a whole account, so a reader that aliased the
    // tag onto field 1 would import it rather than stumble over the body.
    const body = wireType === 2 ? [...varint(hiddenEntry.length), ...hiddenEntry] : varint(1);
    const bytes = Uint8Array.from([
      ...wrapEntry(honestEntry),
      ...bigTag(fieldNumber, wireType),
      ...body,
    ]);
    expect(refusal(bytes)).toEqual({ code: 'malformed', message: MALFORMED_MESSAGE });
  });

  it.each([
    ['length-delimited', 2, [...varint(2), 9, 9]],
    ['varint', 0, varint(1)],
    ['fixed 32-bit', 5, [1, 2, 3, 4]],
  ])('still skips the largest legal field number (%s), which fills all 32 bits', (_l, w, body) => {
    // The boundary itself: 2^29 - 1 is a field protobuf allows, so refusing it
    // would refuse an export that is merely newer than this reader.
    const bytes = Uint8Array.from([
      ...wrapEntry(honestEntry),
      ...bigTag(MAX_FIELD_NUMBER, w),
      ...body,
    ]);
    const payload = readMigrationPayload(bytes);
    expect(payload.entries.map((entry) => entry.name)).toEqual(['honest']);
  });

  it('lets the largest 32-bit tag through the bound, to be judged on its wire type', () => {
    // 0xFFFFFFFF is field 2^29 - 1 with wire type 7. It must pass the tag bound
    // and be refused for the wire type, which does not exist: a bound one lower
    // would call it malformed instead, and would refuse legal tags beside it.
    const bytes = Uint8Array.from([...wrapEntry(honestEntry), ...bigTag(MAX_FIELD_NUMBER, 7)]);
    expect(varint(0xffff_ffff)).toEqual(bigTag(MAX_FIELD_NUMBER, 7));
    expect(reasonFor(bytes)).toBe('unsupported-field');
  });

  it.each([19_000n, 19_500n, 19_999n])(
    'skips field %s from the implementation-reserved range like any unknown field',
    (fieldNumber) => {
      // 19,000-19,999 are reserved for DECLARATIONS: a .proto file may not use
      // them. On the wire they are unknown fields, which every reader skips, so
      // there is no disagreement between readers to refuse.
      const entry = [...honestEntry, ...tag(Number(fieldNumber), 0), ...varint(5)];
      const bytes = Uint8Array.from([
        ...wrapEntry(entry),
        ...tag(Number(fieldNumber), 2),
        ...varint(2),
        9,
        9,
      ]);
      const payload = readMigrationPayload(bytes);
      expect(payload.entries.map((read) => read.name)).toEqual(['honest']);
      expect([...(payload.entries[0]?.secret ?? [])]).toEqual([...sampleSecret(1)]);
    },
  );
});

describe('how many bytes a number may be spelled in', () => {
  /**
   * A varint can spell a small number in more bytes than it needs, and readers
   * do not agree on what that means: protobufjs 7.x reads five bytes of a 32-bit
   * value and then skips five more WITHOUT LOOKING at them, Google's C++ reader
   * refuses a tag or a length longer than five bytes, and Go reads the value.
   * The same export would therefore be three different messages to three
   * readers, which is the differential rules 5 and 6 of the reader exist to
   * refuse. Five bytes is the widest spelling all of them agree on.
   */
  const MALFORMED_MESSAGE = 'That code is not a readable Google Authenticator export.';

  function malformedMessageFor(bytes: Uint8Array): string {
    try {
      readMigrationPayload(bytes);
    } catch (error) {
      if (error instanceof MigrationParseError && error.code === 'malformed') return error.message;
      return `unexpected:${String(error)}`;
    }
    return 'no-error';
  }

  const entryBody = encodeEntry({ secret: sampleSecret(3), name: 'padded', type: 2 });

  /** One entry, with its tag and its length prefix spelled as the caller says. */
  function entryWith(tagBytes: number[], lengthBytes: number[]): Uint8Array {
    return Uint8Array.from([...tagBytes, ...lengthBytes, ...entryBody]);
  }

  const entryTag = tag(1, 2);

  it('reads a tag spelled in five bytes, the widest spelling every reader agrees on', () => {
    const bytes = entryWith(paddedVarint(0x0a, 5), varint(entryBody.length));
    expect(readMigrationPayload(bytes).entries.map((read) => read.name)).toEqual(['padded']);
  });

  it('refuses a tag spelled in six bytes, which protobufjs 7 reads as a different message', () => {
    const bytes = entryWith(paddedVarint(0x0a, 6), varint(entryBody.length));
    expect(malformedMessageFor(bytes)).toBe(MALFORMED_MESSAGE);
  });

  it('refuses a tag spelled in ten bytes, the longest a varint can be', () => {
    const bytes = entryWith(paddedVarint(0x0a, 10), varint(entryBody.length));
    expect(malformedMessageFor(bytes)).toBe(MALFORMED_MESSAGE);
  });

  it('reads a length prefix spelled in five bytes', () => {
    const bytes = entryWith(entryTag, paddedVarint(entryBody.length, 5));
    expect(readMigrationPayload(bytes).entries.map((read) => read.name)).toEqual(['padded']);
  });

  it('refuses a length prefix spelled in six bytes, top-level or inside an account', () => {
    expect(malformedMessageFor(entryWith(entryTag, paddedVarint(entryBody.length, 6)))).toBe(
      MALFORMED_MESSAGE,
    );
    // The same rule for a length INSIDE `OtpParameters`: the secret's.
    const secret = sampleSecret(4);
    const inner = [...tag(1, 2), ...paddedVarint(secret.length, 6), ...secret];
    const outer = Uint8Array.from([...entryTag, ...varint(inner.length), ...inner]);
    expect(malformedMessageFor(outer)).toBe(MALFORMED_MESSAGE);
  });

  it('refuses a length prefix spelled in six bytes on a field it would otherwise skip', () => {
    const bytes = Uint8Array.from([
      ...entryTag,
      ...varint(entryBody.length),
      ...entryBody,
      ...tag(40, 2),
      ...paddedVarint(1, 6),
      9,
    ]);
    expect(malformedMessageFor(bytes)).toBe(MALFORMED_MESSAGE);
  });

  it('reads an enum spelled in five bytes and refuses one spelled in six', () => {
    const withDigits = (spelled: number[]): Uint8Array => {
      const inner = [...encodeEntry({ secret: sampleSecret(5) }), ...tag(5, 0), ...spelled];
      return Uint8Array.from([...entryTag, ...varint(inner.length), ...inner]);
    };
    expect(readMigrationPayload(withDigits(paddedVarint(2, 5))).entries[0]?.digits).toBe(8);
    expect(malformedMessageFor(withDigits(paddedVarint(2, 6)))).toBe(MALFORMED_MESSAGE);
  });

  it('still skips an unknown varint field of any width, which every reader measures alike', () => {
    const bytes = Uint8Array.from([
      ...entryTag,
      ...varint(entryBody.length),
      ...entryBody,
      ...tag(40, 0),
      ...paddedVarint(1, 10),
    ]);
    expect(readMigrationPayload(bytes).entries.map((read) => read.name)).toEqual(['padded']);
  });
});

describe('int32 fields are read as protobuf writes them', () => {
  /**
   * `version`, `batch_size`, `batch_index`, `batch_id` and the three enums are
   * `int32`. Protobuf writes a negative `int32` sign-extended to 64 bits, which
   * is always ten bytes, and Google Authenticator's `batch_id` is a random
   * `int32` that can be negative: an export observed in the wild carried
   * `0xfffffffff40ff6f2`. Read as an unsigned number, that is far past any safe
   * integer, and the whole export used to be refused.
   */
  const MALFORMED_MESSAGE = 'That code is not a readable Google Authenticator export.';
  const entry = { secret: sampleSecret(6), name: 'batch', type: 2 };

  function payloadWithBatchId(spelled: number[]): Uint8Array {
    const body = encodeEntry(entry);
    return Uint8Array.from([
      ...tag(1, 2),
      ...varint(body.length),
      ...body,
      ...tag(3, 0),
      ...varint(2),
      ...tag(5, 0),
      ...spelled,
    ]);
  }

  it('reads a negative batch_id exactly as a real multi-code export carries it', () => {
    const observed = 0xfffffffff40ff6f2n;
    const payload = readMigrationPayload(payloadWithBatchId(varint(observed)));
    expect(payload.batchId).toBe(-200_280_334);
    expect(payload.batchSize).toBe(2);
    expect(payload.entries.map((read) => read.name)).toEqual(['batch']);
  });

  it('reads both int32 extremes, and the encoder spells the negative one in ten bytes', () => {
    expect(int32Varint(-(2 ** 31))).toHaveLength(10);
    const lowest = readMigrationPayload(encodePayload({ entries: [entry], batchId: -(2 ** 31) }));
    expect(lowest.batchId).toBe(-(2 ** 31));
    const highest = readMigrationPayload(encodePayload({ entries: [entry], batchId: 2 ** 31 - 1 }));
    expect(highest.batchId).toBe(2 ** 31 - 1);
  });

  it('refuses a value no int32 can be: wider than 31 bits and not a sign extension', () => {
    // 2^31 in five bytes, 2^40, and a ten-byte value whose top bits are not all
    // ones. Readers truncate each of these to 32 bits and disagree with anyone
    // who does not, so none of them is an int32 this reader will guess at.
    // 2^64 - 2^31 - 1 is the value just below the smallest sign-extended int32.
    for (const spelled of [
      varint(2n ** 31n),
      varint(2n ** 40n),
      varint(2n ** 63n),
      varint(2n ** 64n - 2n ** 31n - 1n),
    ]) {
      expect(malformedMessageOf(payloadWithBatchId(spelled))).toBe(MALFORMED_MESSAGE);
    }
  });

  it('refuses a non-negative int32 spelled in more than five bytes', () => {
    expect(malformedMessageOf(payloadWithBatchId(paddedVarint(7, 6)))).toBe(MALFORMED_MESSAGE);
    expect(readMigrationPayload(payloadWithBatchId(paddedVarint(7, 5))).batchId).toBe(7);
  });

  it('refuses a negative version, batch size or batch index, which no export can mean', () => {
    for (const payload of [
      { entries: [entry], version: -1 },
      { entries: [entry], batchSize: -1 },
      { entries: [entry], batchIndex: -1 },
    ]) {
      expect(malformedMessageOf(encodePayload(payload))).toBe(MALFORMED_MESSAGE);
    }
  });

  it('refuses a negative enum as an unknown one, never as a fallback', () => {
    expect(reasonFor(encodePayload({ entries: [{ ...entry, algorithm: -1 }] }))).toBe('bad-enum');
    expect(reasonFor(encodePayload({ entries: [{ ...entry, digits: -2 }] }))).toBe('bad-enum');
  });

  function malformedMessageOf(bytes: Uint8Array): string {
    try {
      readMigrationPayload(bytes);
    } catch (error) {
      if (error instanceof MigrationParseError && error.code === 'malformed') return error.message;
      return `unexpected:${String(error)}`;
    }
    return 'no-error';
  }
});

describe('label handling', () => {
  it('does not repeat the issuer inside the account name', () => {
    // Google Authenticator fills BOTH the issuer field and the label prefix, so
    // showing the name verbatim puts "Acme:alice" under a heading saying "Acme".
    const payload = readMigrationPayload(
      encodePayload({
        entries: [{ secret: sampleSecret(), issuer: 'Acme', name: 'Acme:alice@example.com' }],
      }),
    );
    expect(payload.entries[0]?.issuer).toBe('Acme');
    expect(payload.entries[0]?.name).toBe('alice@example.com');
  });

  it('recovers the issuer from the label when the field is empty', () => {
    const payload = readMigrationPayload(
      encodePayload({ entries: [{ secret: sampleSecret(), name: 'Globex: bob@example.com' }] }),
    );
    expect(payload.entries[0]?.issuer).toBe('Globex');
    expect(payload.entries[0]?.name).toBe('bob@example.com');
  });

  it('leaves a name that merely contains the issuer elsewhere alone', () => {
    const payload = readMigrationPayload(
      encodePayload({ entries: [{ secret: sampleSecret(), issuer: 'Acme', name: 'not-Acme:x' }] }),
    );
    expect(payload.entries[0]?.name).toBe('not-Acme:x');
  });

  it('strips bidirectional overrides, which could make an entry display a false issuer', () => {
    const payload = readMigrationPayload(
      encodePayload({
        entries: [{ secret: sampleSecret(), issuer: 'Ac\u202Eme', name: 'a\u200Bb' }],
      }),
    );
    expect(payload.entries[0]?.issuer).toBe('Acme');
    expect(payload.entries[0]?.name).toBe('ab');
  });

  it('survives a label that is not valid UTF-8 rather than losing the account', () => {
    const bytes = Uint8Array.from([
      ...tag(1, 2),
      ...varint(20),
      ...encodeEntry({ secret: sampleSecret() }).slice(0, 20),
    ]);
    // The point is only that a bad byte never throws something foreign.
    expect(reasonFor(bytes).startsWith('unexpected:')).toBe(false);
  });
});
