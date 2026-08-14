// @vitest-environment node
import { describe, it, expect, beforeAll } from 'vitest';
import { vaultItemDataSchemas, cardDataSchema, identityDataSchema } from '@hvault/shared';
import { buildImportOperations } from '../../src/services/import';
import {
  buildLogin,
  buildNote,
  clampAddress,
  makeItem,
} from '../../src/services/import/itemBuilders';

/**
 * Phase 3 (fidelity-clamp): a single over-long field must be clamped to the
 * shared schema bound and its overflow preserved in the item's notes, rather
 * than failing `vaultItemDataSchemas` and discarding the WHOLE item — password
 * included — at the encryption step (`buildImportOperations`).
 */

let vaultKey: CryptoKey;

beforeAll(async () => {
  vaultKey = await globalThis.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
});

/** Parse against the schema, run the transformed OUTPUT back through it, and
 * assert both succeed — proving the item is valid both at encrypt time (raw
 * input) and at decrypt time (the stored, transformed value). */
function assertRoundTrips(
  itemType: 'login' | 'card' | 'identity' | 'note' | 'secret',
  data: unknown,
): void {
  const schema = vaultItemDataSchemas[itemType];
  const first = schema.safeParse(data);
  expect(first.success).toBe(true);
  if (first.success) {
    expect(schema.safeParse(first.data).success).toBe(true);
  }
}

describe('import fidelity clamp — logins', () => {
  it('imports a login with a 3000-char scheme-less URL, preserving the full URL in notes', async () => {
    const fullUrl = `${'a'.repeat(3000)}.example.com`;
    const item = buildLogin({ username: 'octocat', password: 'pw', urls: [fullUrl] });

    const uris = item.data.uris as { uri: string }[];
    expect(uris).toHaveLength(1);
    // Clamped so that, after the schema prepends `https://`, the stored value is
    // still ≤ 2048 (2048 - 'https://'.length = 2040 on the raw scheme-less input).
    expect(uris[0]!.uri.length).toBe(2040);
    // The full original URL is recoverable from the notes.
    expect(String(item.data.notes)).toContain(fullUrl);

    // Valid at both encrypt time (raw) and decrypt time (transformed → 2048).
    assertRoundTrips('login', item.data);
    const parsed = vaultItemDataSchemas.login.parse(item.data) as { uris: { uri: string }[] };
    expect(parsed.uris[0]!.uri.length).toBe(2048);

    // And it is NOT skipped by the real encrypt/validate step.
    const { inserts: items, failedCount: skipped } = await buildImportOperations({
      inserts: [item],
      updates: [],
      vaultKey,
    });
    expect(skipped).toBe(0);
    expect(items).toHaveLength(1);
  });

  it('imports a login with an explicit-scheme over-long URL, clamped to 2048 flat', () => {
    const fullUrl = `https://${'a'.repeat(3000)}`;
    const item = buildLogin({ username: 'u', password: 'p', urls: [fullUrl] });
    const uris = item.data.uris as { uri: string }[];
    expect(uris[0]!.uri.length).toBe(2048);
    expect(String(item.data.notes)).toContain(fullUrl);
    assertRoundTrips('login', item.data);
  });

  it('imports a login with a >500-char username, clamped with the full value preserved in notes', async () => {
    const fullUsername = 'u'.repeat(600);
    const item = buildLogin({ username: fullUsername, password: 'pw' });

    expect((item.data.username as string).length).toBe(500);
    expect(String(item.data.notes)).toContain(fullUsername);
    assertRoundTrips('login', item.data);

    const { failedCount: skipped } = await buildImportOperations({
      inserts: [item],
      updates: [],
      vaultKey,
    });
    expect(skipped).toBe(0);
  });

  it('clamps an over-long password but NEVER copies it into notes', () => {
    const longPassword = 'p'.repeat(12_000);
    const item = buildLogin({ username: 'u', password: longPassword, notes: 'hello' });

    expect((item.data.password as string).length).toBe(10_000);
    // The password must not leak into the free-text notes under any label.
    expect(String(item.data.notes ?? '')).not.toContain('p'.repeat(10_001));
    expect(item.data.notes).toBe('hello');
    assertRoundTrips('login', item.data);
  });

  it('imports a login with 150 custom fields, keeping 100 and summarizing the rest in notes', async () => {
    const customFields = Array.from({ length: 150 }, (_, i) => ({
      name: `field${String(i)}`,
      value: `value${String(i)}`,
      type: 0,
    }));
    const item = buildLogin({ username: 'u', password: 'p', customFields });

    const fields = item.data.customFields as { name: string; value: string }[];
    expect(fields).toHaveLength(100);
    expect(String(item.data.notes)).toContain('50 additional custom field(s) not imported');
    // A dropped field's data is still recoverable in the summary.
    expect(String(item.data.notes)).toContain('field149: value149');
    assertRoundTrips('login', item.data);

    const { failedCount: skipped } = await buildImportOperations({
      inserts: [item],
      updates: [],
      vaultKey,
    });
    expect(skipped).toBe(0);
  });

  it('clamps an over-long custom-field value and preserves the remainder in notes', () => {
    const bigValue = 'x'.repeat(60_000);
    const item = buildLogin({
      username: 'u',
      password: 'p',
      customFields: [{ name: 'blob', value: bigValue }],
    });
    const fields = item.data.customFields as { name: string; value: string }[];
    expect(fields[0]!.value.length).toBe(50_000);
    expect(String(item.data.notes)).toContain('Custom field "blob" was truncated');
    assertRoundTrips('login', item.data);
  });

  it('skips a custom field with an empty name without dropping the item', () => {
    const item = buildLogin({
      username: 'u',
      password: 'p',
      customFields: [
        { name: '   ', value: 'ignored' },
        { name: 'kept', value: 'v' },
      ],
    });
    const fields = item.data.customFields as { name: string }[];
    expect(fields).toHaveLength(1);
    expect(fields[0]!.name).toBe('kept');
    assertRoundTrips('login', item.data);
  });
});

describe('import fidelity clamp — cards, identities and notes', () => {
  it('clamps an over-long identity notes field instead of discarding the identity', () => {
    const item = makeItem('identity', 'Jane', {
      firstName: 'Jane',
      notes: 'n'.repeat(60_000),
    });
    expect((item.data.notes as string).length).toBe(50_000);
    assertRoundTrips('identity', item.data);
  });

  it('clamps and caps identity custom fields, folding overflow into notes', () => {
    const customFields = Array.from({ length: 120 }, (_, i) => ({
      name: `f${String(i)}`,
      value: `v${String(i)}`,
      type: 'text',
    }));
    const item = makeItem('identity', 'Jane', { firstName: 'Jane', customFields });
    const fields = item.data.customFields as unknown[];
    expect(fields).toHaveLength(100);
    expect(String(item.data.notes)).toContain('20 additional custom field(s) not imported');
    assertRoundTrips('identity', item.data);
  });

  it('drops non-object and empty-name custom-field entries on a pre-shaped item', () => {
    const item = makeItem('identity', 'Jane', {
      firstName: 'Jane',
      customFields: [null, 'str', { name: '', value: 'x' }, { name: 'real', value: 'y' }],
    });
    const fields = item.data.customFields as { name: string }[];
    expect(fields).toHaveLength(1);
    expect(fields[0]!.name).toBe('real');
    assertRoundTrips('identity', item.data);
  });

  it('removes the customFields key entirely when every entry is invalid', () => {
    const item = makeItem('identity', 'Jane', {
      firstName: 'Jane',
      customFields: [null, { name: '   ', value: 'x' }],
    });
    expect(item.data.customFields).toBeUndefined();
    assertRoundTrips('identity', item.data);
  });

  it('drops a custom field whose name is not a string rather than coercing it', () => {
    // `{ name: 123 }` is what a hand-edited or machine-generated export produces.
    // Coercing it (`String(rec.name)`) would invent a field called "123" that the
    // user never wrote; the entry is dropped instead, and the item survives.
    const item = makeItem('identity', 'Jane', {
      firstName: 'Jane',
      customFields: [
        { name: 123, value: 'x' },
        { name: 'real', value: 'y' },
      ],
    });
    const fields = item.data.customFields as { name: string }[];
    expect(fields).toHaveLength(1);
    expect(fields[0]!.name).toBe('real');
    assertRoundTrips('identity', item.data);
  });

  it('empties a custom-field value that is neither a string nor a number, keeping the field', () => {
    // `customFieldSchema.value` is a string, so a boolean or an object reaching it
    // fails `vaultItemDataSchemas` and `validateImportItems` discards the WHOLE
    // item — every other field with it. The value is emptied instead: the field's
    // NAME is what the user recognises, and a coerced "true" or "[object Object]"
    // would be a value the source file never contained.
    const item = makeItem('identity', 'Jane', {
      firstName: 'Jane',
      customFields: [
        { name: 'consented', value: true },
        { name: 'meta', value: { nested: 1 } },
        { name: 'count', value: 42 },
        { name: 'plain', value: 'text' },
      ],
    });
    const fields = item.data.customFields as { name: string; value: string }[];
    expect(fields.map((field) => [field.name, field.value])).toEqual([
      ['consented', ''],
      ['meta', ''],
      // A number IS coerced — it is a lossless rendering of the source value,
      // which a boolean and an object are not.
      ['count', '42'],
      ['plain', 'text'],
    ]);
    assertRoundTrips('identity', item.data);
  });

  it('clamps an over-long secure-note content to the schema bound', () => {
    const item = buildNote({ name: 'Big', content: 'z'.repeat(60_000) });
    expect((item.data.content as string).length).toBe(50_000);
    assertRoundTrips('note', item.data);
  });

  it('clamps an over-long identity address instead of discarding the identity', async () => {
    const item = makeItem('identity', 'Jane', {
      firstName: 'Jane',
      address: {
        street: 'a'.repeat(700),
        street2: 'b'.repeat(700),
        city: 'c'.repeat(300),
        state: 'd'.repeat(300),
        zip: 'e'.repeat(40),
        country: 'f'.repeat(200),
      },
    });
    const address = item.data.address as Record<string, string>;
    expect(address.street).toHaveLength(500);
    expect(address.street2).toHaveLength(500);
    expect(address.city).toHaveLength(200);
    expect(address.state).toHaveLength(200);
    expect(address.zip).toHaveLength(20);
    expect(address.country).toHaveLength(100);
    // Nothing is silently dropped: each trimmed tail is recoverable from the notes.
    expect(String(item.data.notes)).toContain('Street address truncated');
    expect(String(item.data.notes)).toContain('Street address line 2 truncated');
    expect(String(item.data.notes)).toContain('ZIP truncated');
    assertRoundTrips('identity', item.data);

    // The point of the clamp: the item SURVIVES the real encrypt-and-validate step
    // rather than being discarded wholesale (name, passport and all) at validation.
    const { inserts, failedCount } = await buildImportOperations({
      inserts: [item],
      updates: [],
      vaultKey,
    });
    expect(failedCount).toBe(0);
    expect(inserts).toHaveLength(1);
  });

  it('clamps an over-long card billing address at the same choke point', () => {
    // No importer builds a card billing address today (Bitwarden cards have no address
    // field), but the clamp covers both keys so a parser added later is bounded without
    // having to opt in.
    const item = makeItem('card', 'Visa', {
      cardholderName: 'Jane',
      number: '4111111111111111',
      billingAddress: { street: 'a'.repeat(700), zip: 'e'.repeat(40) },
    });
    const billing = item.data.billingAddress as Record<string, string>;
    expect(billing.street).toHaveLength(500);
    expect(billing.zip).toHaveLength(20);
    // Absent fields are filled with '', matching the shared schema's own defaults.
    expect(billing.street2).toBe('');
    assertRoundTrips('card', item.data);
  });

  it('bounds a scalar by the table for the item type it was given, not by its key name', () => {
    // `clampNotesAndFields` takes the item TYPE as a parameter and looks the bounds
    // up per type, because a key name alone does not identify a field: `number` on
    // a card is a PAN bounded at 30, and on anything else it is an ordinary value
    // this module has no business truncating. A note also exercises the empty-table
    // path, since only `card` and `identity` declare scalar bounds at all.
    //
    // Red the moment the lookup stops being per type — a fall back to another
    // type's list, or a key-keyed table — because `number` would come back
    // truncated to 30 with a "Card number truncated" line invented in `notes`.
    const number = '9'.repeat(120);
    const card = makeItem('card', 'Visa', { number });
    expect(card.data.number).toHaveLength(30);
    expect(String(card.data.notes)).toContain('Card number truncated');

    const note = makeItem('note', 'Recovery kit', {
      content: 'keep me',
      number,
      cvv: '9'.repeat(9),
    });
    expect(note.data.number).toBe(number);
    expect(note.data.cvv).toHaveLength(9);
    expect(note.data.content).toBe('keep me');
    expect(note.data.notes).toBeUndefined();
  });

  it('leaves a within-bounds address untouched and adds no notes', () => {
    const item = makeItem('identity', 'Jane', {
      firstName: 'Jane',
      address: { street: '1 Main St', street2: 'Flat 2', city: 'London' },
    });
    expect(item.data.address).toEqual({
      street: '1 Main St',
      street2: 'Flat 2',
      city: 'London',
      state: '',
      zip: '',
      country: '',
    });
    expect(item.data.notes).toBeUndefined();
    assertRoundTrips('identity', item.data);
  });

  it('leaves a non-object address value alone rather than reshaping it', () => {
    // Defensive arm: a parser handing over a string or an array must not be silently
    // rewritten into an empty address, which would look like real data.
    const item = makeItem('identity', 'Jane', { firstName: 'Jane', address: 'nonsense' });
    expect(item.data.address).toBe('nonsense');
  });
});

// ---------------------------------------------------------------------------
// clampAddress, exercised directly.
//
// The `deliveryNotes` arm is unreachable through any parser (no source format has
// such a column), which is exactly why the helper is exported: the alternative is
// an untested arm that only wakes up the day a format gains one.
// ---------------------------------------------------------------------------

describe('clampAddress', () => {
  it('fills every base field, defaulting the ones the caller omitted', () => {
    const { address, overflow } = clampAddress({ street: '1 Main St' });
    expect(address).toEqual({
      street: '1 Main St',
      street2: '',
      city: '',
      state: '',
      zip: '',
      country: '',
    });
    expect(overflow).toEqual([]);
  });

  it('reports the truncated tail so the caller can preserve it', () => {
    const { address, overflow } = clampAddress({ street2: `${'x'.repeat(500)}TAIL` });
    expect(address.street2).toHaveLength(500);
    expect(overflow).toHaveLength(1);
    expect(overflow[0]).toContain('Street address line 2 truncated');
    expect(overflow[0]).toContain('TAIL');
  });

  it('produces an address the shared schemas accept for BOTH item types', () => {
    // The whole contract in one assertion: whatever this returns must survive
    // read-back, or the item it belongs to degrades to the undecodable notice.
    const huge = 'z'.repeat(9_999);
    const { address } = clampAddress({
      street: huge,
      street2: huge,
      city: huge,
      state: huge,
      zip: huge,
      country: huge,
      deliveryNotes: huge,
    });
    expect(identityDataSchema.safeParse({ address }).success).toBe(true);
    expect(cardDataSchema.safeParse({ billingAddress: address }).success).toBe(true);
  });

  it('clamps delivery notes when given them but never invents the key', () => {
    const withNotes = clampAddress({ deliveryNotes: 'n'.repeat(1_200) });
    expect(withNotes.address.deliveryNotes).toHaveLength(1_000);
    // "Delivery notes truncated", not "... was truncated": the labels are field
    // names and two of them are plural, so the copular form was ungrammatical.
    expect(withNotes.overflow[0]).toContain('Delivery notes truncated');
    expect(withNotes.overflow[0]).not.toContain('notes was truncated');

    const without = clampAddress({ street: '1 Main St' });
    expect(without.address).not.toHaveProperty('deliveryNotes');
  });
});

// ---------------------------------------------------------------------------
// Backup codes
//
// Recovery codes sit on the PASSWORD side of the "may this be copied into notes"
// line, not the custom-field side: `notes` is written verbatim into the Chrome CSV
// `note` column, so folding an over-cap code in would leak it into the very export
// whose loss note promises the codes are absent.
// ---------------------------------------------------------------------------

describe('backup codes on import', () => {
  it('keeps the codes, de-duplicated and in order', () => {
    const item = buildLogin({
      username: 'u',
      password: 'p',
      backupCodes: ['aaaa-1111', 'bbbb-2222', 'aaaa-1111'],
    });
    expect(item.data.backupCodes).toEqual(['aaaa-1111', 'bbbb-2222']);
    assertRoundTrips('login', item.data);
  });

  it('trims each code and drops blank and nullish entries', () => {
    const item = buildLogin({
      username: 'u',
      password: 'p',
      backupCodes: ['  aaaa-1111  ', '', '   ', null, undefined, 'bbbb-2222'],
    });
    expect(item.data.backupCodes).toEqual(['aaaa-1111', 'bbbb-2222']);
  });

  it('omits the key entirely when there are no codes', () => {
    const item = buildLogin({ username: 'u', password: 'p' });
    expect('backupCodes' in item.data).toBe(false);
    assertRoundTrips('login', item.data);
  });

  it('clamps an over-long code to the schema bound rather than sinking the item', () => {
    const item = buildLogin({ username: 'u', password: 'p', backupCodes: ['c'.repeat(400)] });
    expect((item.data.backupCodes as string[])[0]).toHaveLength(128);
    assertRoundTrips('login', item.data);
  });

  it('keeps 50 codes, counts the rest, and never writes their values into notes', () => {
    const many = Array.from({ length: 60 }, (_, i) => `code-${i}`);
    const item = buildLogin({ username: 'u', password: 'p', backupCodes: many });
    expect(item.data.backupCodes).toHaveLength(50);
    const notes = String(item.data.notes ?? '');
    expect(notes).toContain('10 additional backup code(s) not imported.');
    // A COUNT, never the values.
    expect(notes).not.toContain('code-55');
    assertRoundTrips('login', item.data);
  });

  it('survives encryption at the maximum on every bound', async () => {
    // The guard against a permanently read-only item: the largest login the importer
    // can build must still validate and seal.
    const item = buildLogin({
      username: 'u'.repeat(500),
      password: 'p'.repeat(10_000),
      backupCodes: Array.from({ length: 50 }, () => 'c'.repeat(128)),
    });
    assertRoundTrips('login', item.data);
    const { inserts, failedCount: skipped } = await buildImportOperations({
      inserts: [item],
      updates: [],
      vaultKey,
    });
    expect(skipped).toBe(0);
    expect(inserts).toHaveLength(1);
  });
});
