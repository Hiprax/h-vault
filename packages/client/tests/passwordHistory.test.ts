import { describe, it, expect, beforeAll } from 'vitest';
import { PASSWORD_HISTORY_MAX } from '@hvault/shared';
import type { IPasswordHistoryEntry } from '@hvault/shared';
import { cryptoService } from '../src/services/crypto/cryptoService';
import { buildPasswordHistoryPayload } from '../src/services/crypto/passwordHistory';

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
        vaultKey,
      }),
    ).toBeUndefined();
    expect(
      await buildPasswordHistoryPayload({
        existingRawHistory: undefined,
        oldPassword: undefined,
        newPassword: 'new',
        vaultKey,
      }),
    ).toBeUndefined();
  });

  it('returns undefined when the new password is not a string', async () => {
    const payload = await buildPasswordHistoryPayload({
      existingRawHistory: [],
      oldPassword: 'old',
      newPassword: undefined,
      vaultKey,
    });
    expect(payload).toBeUndefined();
  });

  it('prepends the OLD password (recoverable) when it changes', async () => {
    const payload = await buildPasswordHistoryPayload({
      existingRawHistory: [],
      oldPassword: 'the-old-secret',
      newPassword: 'the-new-secret',
      vaultKey,
    });

    expect(payload).toBeDefined();
    expect(payload).toHaveLength(1);
    const first = payload![0]!;
    // The stored entry decrypts back to the OLD password, never the new one.
    const recovered = await cryptoService.decryptData(
      first.encryptedPassword,
      first.iv,
      first.tag,
      vaultKey,
    );
    expect(recovered).toBe('the-old-secret');
    expect(typeof first.changedAt).toBe('string');
  });

  it('prepends before existing history and preserves prior entries verbatim', async () => {
    const existingRawHistory = [entry('prev-1'), entry('prev-2')];
    const payload = await buildPasswordHistoryPayload({
      existingRawHistory,
      oldPassword: 'current',
      newPassword: 'next',
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
      vaultKey,
    });
    expect(payload![1]).toEqual(entry('prev'));
    expect(payload![1]).not.toHaveProperty('_polluted');
  });
});
