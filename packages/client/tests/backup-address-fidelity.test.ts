// @vitest-environment node
import { describe, it, expect, beforeAll } from 'vitest';
import { identityDataSchema, cardDataSchema } from '@hvault/shared';
import { CryptoService } from '../src/services/crypto/cryptoService';

/**
 * Field-level retention for an address's second street line and an identity's
 * delivery notes across an encrypt/decrypt cycle, under the REAL Web Crypto and the
 * REAL shared schemas.
 *
 * Scope, stated precisely, because it is easy to overclaim here. This file drives
 * `CryptoService` and the shared schemas directly. It therefore pins:
 *
 * - that a schema-parsed blob carrying both fields survives serialization,
 *   encryption, decryption and re-encryption under a DIFFERENT key byte-identically,
 *   so a cross-account restore or a post-rotation restore cannot mangle it;
 * - that a blob written by an older build (neither key present) still parses, with
 *   the defaults filling both fields in;
 * - that the card schema strips the identity-only field before it is ever serialized,
 *   so it cannot reach ciphertext at all.
 *
 * It does NOT pin the production restore LOOP, because it does not call it: the
 * sequence below mirrors `BackupSettingsPage`'s decrypt-to-string then
 * re-encrypt-that-string rather than invoking it. A re-parse introduced into the real
 * loop would not fail anything here. The guard for the loop itself is the interaction
 * test at `coverage-backup-settings.test.tsx` ("re-encrypts a restored row without
 * altering one byte of its plaintext"), which drives the real page and asserts on the
 * exact argument handed to `encryptData`; the end-to-end guard is
 * `e2e/address-fields.spec.ts`, which deletes the live values before restoring so they
 * can only come back out of the downloaded file.
 *
 * Why it exists at all: `coverage-backup-settings.test.tsx` MOCKS `cryptoService`, and
 * `e2e/backup-restore.spec.ts` seeds placeholder ciphertext, so neither exercises real
 * crypto over real schema output.
 */

let crypto: CryptoService;
let keyA: CryptoKey;
let keyB: CryptoKey;

async function freshVaultKey(): Promise<CryptoKey> {
  return globalThis.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
}

beforeAll(async () => {
  crypto = new CryptoService();
  keyA = await freshVaultKey();
  keyB = await freshVaultKey();
});

/** An identity carrying both new fields, exactly as the item form would build it. */
const IDENTITY = {
  firstName: 'Ada',
  lastName: 'Lovelace',
  address: {
    street: '1 Main St',
    street2: 'Flat 2, Building C',
    city: 'London',
    state: '',
    zip: 'E1 6AN',
    country: 'UK',
    deliveryNotes: 'Ring twice, then leave with the concierge.\nGate code 1234.',
  },
} as const;

/**
 * A card whose billing address DOES carry a `deliveryNotes` key, so the assertion
 * that it is absent after the round trip is a real one. A fixture without the key
 * would make that assertion trivially true and prove nothing about the strip.
 */
const CARD = {
  cardholderName: 'Ada Lovelace',
  number: '4111111111111111',
  expMonth: '12',
  expYear: '2030',
  cvv: '123',
  billingAddress: {
    street: '1 Main St',
    street2: 'Suite 100',
    city: 'London',
    state: '',
    zip: 'E1 6AN',
    country: 'UK',
    deliveryNotes: 'leave with the doorman',
  },
} as const;

describe('backup fidelity: the new address fields survive a cross-key restore', () => {
  it('re-encrypts an identity blob under a new key without altering one byte', async () => {
    // The item as it is stored: schema output, serialized, encrypted under key A.
    const stored = JSON.stringify(identityDataSchema.parse(IDENTITY));
    const atRest = await crypto.encryptData(stored, keyA);

    // The restore path, verbatim: decrypt to a STRING, then re-encrypt that string.
    // No JSON.parse, no schema, no field walk.
    const recovered = await crypto.decryptData(atRest.encrypted, atRest.iv, atRest.tag, keyA);
    expect(recovered).toBe(stored);
    const reEncrypted = await crypto.encryptData(recovered, keyB);

    // A genuinely different ciphertext under a different key...
    expect(reEncrypted.encrypted).not.toBe(atRest.encrypted);

    // ...that still decrypts to the identical plaintext.
    const final = await crypto.decryptData(
      reEncrypted.encrypted,
      reEncrypted.iv,
      reEncrypted.tag,
      keyB,
    );
    expect(final).toBe(stored);

    // And the fields are still there after the round trip, through the real schema.
    const parsed = identityDataSchema.parse(JSON.parse(final));
    expect(parsed.address?.street2).toBe('Flat 2, Building C');
    expect(parsed.address?.deliveryNotes).toBe(
      'Ring twice, then leave with the concierge.\nGate code 1234.',
    );
    // Newlines survive intact: delivery instructions are naturally multi-line.
    expect(parsed.address?.deliveryNotes).toContain('\n');
  });

  it("re-encrypts a card's billing address under a new key without altering one byte", async () => {
    const stored = JSON.stringify(cardDataSchema.parse(CARD));
    // The identity-only field never even reaches the ciphertext: the schema strips it
    // before serialization, so it is absent from the string that gets encrypted.
    expect(stored).not.toContain('deliveryNotes');
    expect(stored).not.toContain('doorman');
    const atRest = await crypto.encryptData(stored, keyA);
    const recovered = await crypto.decryptData(atRest.encrypted, atRest.iv, atRest.tag, keyA);
    const reEncrypted = await crypto.encryptData(recovered, keyB);
    const final = await crypto.decryptData(
      reEncrypted.encrypted,
      reEncrypted.iv,
      reEncrypted.tag,
      keyB,
    );

    expect(final).toBe(stored);
    const parsed = cardDataSchema.parse(JSON.parse(final));
    expect(parsed.billingAddress?.street2).toBe('Suite 100');
    // The card must not acquire an identity-only field anywhere along the way.
    expect(parsed.billingAddress).not.toHaveProperty('deliveryNotes');
  });

  it('carries the fields through a blob an older build encrypted', async () => {
    // A row written before these fields existed has neither key. A restore must not
    // fail on it, and the schema's defaults are what make the recovered item usable.
    const legacy = JSON.stringify({
      firstName: 'Ada',
      lastName: 'Lovelace',
      address: { street: '1 Main St', city: 'London', state: '', zip: 'E1', country: 'UK' },
    });
    const atRest = await crypto.encryptData(legacy, keyA);
    const recovered = await crypto.decryptData(atRest.encrypted, atRest.iv, atRest.tag, keyA);
    expect(recovered).toBe(legacy);

    const parsed = identityDataSchema.parse(JSON.parse(recovered));
    expect(parsed.address?.street2).toBe('');
    expect(parsed.address?.deliveryNotes).toBe('');
    expect(parsed.address?.street).toBe('1 Main St');
  });

  // A fourth case asserting that an "unknown future field" also survives was removed
  // deliberately. It could only ever have restated a property of AES-GCM and
  // JSON.stringify, and its comment claimed it would catch a re-parse creeping into
  // the restore loop, which it could not: this file does not call that loop. The
  // interaction test in coverage-backup-settings.test.tsx is what guards it.
});
