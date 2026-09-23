import { describe, it, expect, beforeAll } from 'vitest';
import { PASSWORD_HISTORY_MAX } from '@hvault/shared';
import type { IPasswordHistoryEntry } from '@hvault/shared';
import { cryptoService } from '../src/services/crypto/cryptoService';
import { buildPasswordHistoryPayload } from '../src/services/crypto/passwordHistory';
import { decryptVaultField } from '../src/services/crypto/vaultField';

/** The row the history belongs to: a realistic ObjectId, as every row id is. */
const ROW_ID = '507f1f77bcf86cd799439011';
/** Another row of the same vault, which the entry must NOT open under. */
const OTHER_ROW_ID = '507f1f77bcf86cd799439012';

/**
 * Unit coverage for the shared password-history builder. It uses the REAL
 * Web Crypto vault key (node's webcrypto is installed in tests/setup.ts), so the
 * encrypted old password round-trips back to plaintext — proving the payload
 * actually preserves the previous password rather than merely looking shaped.
 */
describe('buildPasswordHistoryPayload', () => {
  let vaultKey: CryptoKey;

  beforeAll(async () => {
    const rawVk = await cryptoService.generateVaultKey();
    vaultKey = await cryptoService.importVaultKey(rawVk);
  });

  const entry = (encryptedPassword: string): IPasswordHistoryEntry => ({
    encryptedPassword,
    iv: 'iv',
    tag: 'tag',
    changedAt: '2024-01-01T00:00:00.000Z',
  });

  it('returns undefined when the password is unchanged', async () => {
    const payload = await buildPasswordHistoryPayload({
      existingRawHistory: [],
      oldPassword: 'same',
      newPassword: 'same',
      rowId: ROW_ID,
      vaultKey,
    });
    expect(payload).toBeUndefined();
  });

  it('returns undefined when there is no old password', async () => {
    expect(
      await buildPasswordHistoryPayload({
        existingRawHistory: undefined,
        oldPassword: '',
        newPassword: 'new',
        rowId: ROW_ID,
        vaultKey,
      }),
    ).toBeUndefined();
    expect(
      await buildPasswordHistoryPayload({
        existingRawHistory: undefined,
        oldPassword: undefined,
        newPassword: 'new',
        rowId: ROW_ID,
        vaultKey,
      }),
    ).toBeUndefined();
  });

  it('returns undefined when the new password is not a string', async () => {
    const payload = await buildPasswordHistoryPayload({
      existingRawHistory: [],
      oldPassword: 'old',
      newPassword: undefined,
      rowId: ROW_ID,
      vaultKey,
    });
    expect(payload).toBeUndefined();
  });

  it('prepends the OLD password (recoverable) when it changes', async () => {
    const payload = await buildPasswordHistoryPayload({
      existingRawHistory: [],
      oldPassword: 'the-old-secret',
      newPassword: 'the-new-secret',
      rowId: ROW_ID,
      vaultKey,
    });

    expect(payload).toBeDefined();
    expect(payload).toHaveLength(1);
    const first = payload![0]!;
    // Sealed in format v2: the marker is on the IV.
    expect(first.iv.startsWith('v2:')).toBe(true);
    // The stored entry decrypts back to the OLD password, never the new one,
    // when opened as THIS row's password history.
    const recovered = await decryptVaultField(
      { encrypted: first.encryptedPassword, iv: first.iv, tag: first.tag },
      { role: 'item.password-history', rowId: ROW_ID },
      vaultKey,
    );
    expect(recovered).toBe('the-old-secret');
    expect(typeof first.changedAt).toBe('string');
  });

  it('binds the retained password to its own row and role, so it opens nowhere else', async () => {
    // The point of passing `rowId`: an entry moved onto another item's history,
    // or into another field of the same row, fails its tag check instead of
    // being read there as that item's previous password.
    const payload = await buildPasswordHistoryPayload({
      existingRawHistory: [],
      oldPassword: 'the-old-secret',
      newPassword: 'the-new-secret',
      rowId: ROW_ID,
      vaultKey,
    });
    const first = payload![0]!;
    const field = { encrypted: first.encryptedPassword, iv: first.iv, tag: first.tag };

    await expect(
      decryptVaultField(field, { role: 'item.password-history', rowId: OTHER_ROW_ID }, vaultKey),
    ).rejects.toThrow();
    await expect(
      decryptVaultField(field, { role: 'item.name', rowId: ROW_ID }, vaultKey),
    ).rejects.toThrow();
    // Nor does it open as an unbound v1 field with the marker stripped.
    await expect(
      cryptoService.decryptData(first.encryptedPassword, first.iv.slice(3), first.tag, vaultKey),
    ).rejects.toThrow();
  });

  it('refuses a row id that is not an ObjectId before sealing anything', async () => {
    await expect(
      buildPasswordHistoryPayload({
        existingRawHistory: [],
        oldPassword: 'the-old-secret',
        newPassword: 'the-new-secret',
        rowId: 'not-an-object-id',
        vaultKey,
      }),
    ).rejects.toThrow('A vault field is bound to an ObjectId row id');
  });

  it('prepends before existing history and preserves prior entries verbatim', async () => {
    const existingRawHistory = [entry('prev-1'), entry('prev-2')];
    const payload = await buildPasswordHistoryPayload({
      existingRawHistory,
      oldPassword: 'current',
      newPassword: 'next',
      rowId: ROW_ID,
      vaultKey,
    });

    expect(payload).toHaveLength(3);
    // Newest first, then the previous entries unchanged and in order.
    expect(payload![1]).toEqual(entry('prev-1'));
    expect(payload![2]).toEqual(entry('prev-2'));
  });

  it('caps the history at PASSWORD_HISTORY_MAX, dropping the oldest', async () => {
    const existingRawHistory = Array.from({ length: PASSWORD_HISTORY_MAX }, (_, i) =>
      entry(`prev-${i}`),
    );
    const payload = await buildPasswordHistoryPayload({
      existingRawHistory,
      oldPassword: 'current',
      newPassword: 'next',
      rowId: ROW_ID,
      vaultKey,
    });

    expect(payload).toHaveLength(PASSWORD_HISTORY_MAX);
    // The oldest entry (prev-9) is pushed off the end by the newly prepended one.
    expect(payload!.map((e) => e.encryptedPassword)).not.toContain(
      `prev-${PASSWORD_HISTORY_MAX - 1}`,
    );
    expect(payload![payload!.length - 1]).toEqual(entry(`prev-${PASSWORD_HISTORY_MAX - 2}`));
  });

  it('does not copy extraneous keys off existing history entries', async () => {
    const dirty = {
      ...entry('prev'),
      _polluted: 'x',
    } as unknown as IPasswordHistoryEntry;
    const payload = await buildPasswordHistoryPayload({
      existingRawHistory: [dirty],
      oldPassword: 'current',
      newPassword: 'next',
      rowId: ROW_ID,
      vaultKey,
    });
    expect(payload![1]).toEqual(entry('prev'));
    expect(payload![1]).not.toHaveProperty('_polluted');
  });
});
