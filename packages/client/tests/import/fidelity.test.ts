// @vitest-environment node
import { describe, it, expect, beforeAll } from 'vitest';
import { vaultItemDataSchemas } from '@hvault/shared';
import { buildEncryptedImportItems } from '../../src/services/import';
import { buildLogin, buildNote, makeItem } from '../../src/services/import/itemBuilders';

/**
 * Phase 3 (fidelity-clamp): a single over-long field must be clamped to the
 * shared schema bound and its overflow preserved in the item's notes, rather
 * than failing `vaultItemDataSchemas` and discarding the WHOLE item — password
 * included — at the encryption step (`buildEncryptedImportItems`).
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
    const { items, skipped } = await buildEncryptedImportItems([item], vaultKey);
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

    const { skipped } = await buildEncryptedImportItems([item], vaultKey);
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

    const { skipped } = await buildEncryptedImportItems([item], vaultKey);
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

  it('clamps an over-long secure-note content to the schema bound', () => {
    const item = buildNote({ name: 'Big', content: 'z'.repeat(60_000) });
    expect((item.data.content as string).length).toBe(50_000);
    assertRoundTrips('note', item.data);
  });
});
