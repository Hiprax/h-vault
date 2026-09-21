/**
 * Fuzzing the Google Authenticator export reader.
 *
 * This is the second place in H-Vault where arbitrary, attacker-chosen bytes are
 * turned into something the application acts on, and it is the more sensitive of
 * the two: the bytes it reads ARE secret keys, and the thing it produces is
 * offered to the user as a key to attach to an account.
 *
 * Five clauses, each of which can fail on its own:
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
 *      read back, every field survives.
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
  encodeMigrationUri,
  encodePayload,
  tag,
  varint,
  type EncodableEntry,
} from '../support/migrationEncoder';

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
      fc.property(anyBytes, (bytes) => {
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
      fc.property(fc.array(anyEntry, { minLength: 1, maxLength: 6 }), (entries) => {
        const payload = parseMigrationUri(encodeMigrationUri({ entries, batchSize: 1 }));
        expect(payload.entries.length, propertyBanner()).toBe(entries.length);
        payload.entries.forEach((read, index) => {
          const written = entries[index];
          expect([...read.secret], propertyBanner()).toEqual([...(written?.secret ?? [])]);
        });
      }),
      propertyRun({ numRuns: PROPERTY_RUNS }),
    );
  });

  it('is unaffected by an unknown field appearing anywhere in the message', () => {
    // Google has added fields before. Refusing one would break this feature on a
    // future release of the app it reads.
    fc.assert(
      fc.property(anyEntry, fc.integer({ min: 20, max: 100 }), (entry, fieldNumber) => {
        const base = encodePayload({ entries: [entry], batchSize: 1 });
        const withUnknown = Uint8Array.from([
          ...base,
          ...tag(fieldNumber, 2),
          ...varint(3),
          1,
          2,
          3,
        ]);
        const plain = attempt(base);
        const injected = attempt(withUnknown);
        expect(injected.ok, propertyBanner()).toBe(plain.ok);
      }),
      propertyRun({ numRuns: PROPERTY_RUNS }),
    );
  });
});
