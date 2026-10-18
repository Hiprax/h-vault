/**
 * Opening the copy of a vault key that the account's backup holds.
 *
 * After a master password reset that copy may be the only key left that opens
 * what the reset stranded, so every way the attempt can end is named, and none of
 * them leaves key bytes behind. Real WebCrypto throughout: a wrapper built with the
 * app's own primitives, opened with the backup password, compared with the live
 * key before any import.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { IBackupSettings } from '@hvault/shared';
import { cryptoService } from '../src/services/crypto/cryptoService';
import {
  completeBwkWrapper,
  hasBackupKeyCopy,
  openBackupKeyCopy,
  sameBwkWrapper,
  unwrapBwk,
} from '../src/services/crypto/backupKeyCopy';

const BACKUP_PASSWORD = 'correct horse battery staple';

function vaultKey(fill: number): Promise<CryptoKey> {
  return cryptoService.importVaultKey(new Uint8Array(32).fill(fill).buffer);
}

/**
 * The backup block an account stores: a BWK sealed under the backup password, and
 * `copyOf` sealed under that BWK (or under `copyUnder`, to model a replaced copy).
 */
async function accountBackup(copyOf: CryptoKey, copyUnder?: ArrayBuffer): Promise<IBackupSettings> {
  const salt = cryptoService.generateSalt();
  const bwkSalt = cryptoService.arrayBufferToBase64(salt);
  const bek = await cryptoService.deriveBEK(BACKUP_PASSWORD, salt);
  const bwk = cryptoService.generateBWK();
  const sealedBwk = await cryptoService.encryptBWK(bwk, bek);
  const copy = await cryptoService.encryptVaultKeyWithBWK(copyOf, copyUnder ?? bwk);
  return {
    enabled: true,
    scheduleHour: 3,
    isConfigured: true,
    encryptedBWK: sealedBwk.encrypted,
    bwkIv: sealedBwk.iv,
    bwkTag: sealedBwk.tag,
    bwkSalt,
    bwkEncryptedVaultKey: copy.encrypted,
    bwkVaultKeyIv: copy.iv,
    bwkVaultKeyTag: copy.tag,
  };
}

/** Whether every byte of `buffer` is zero (a detached buffer counts as cleared). */
function zeroed(buffer: ArrayBuffer): boolean {
  return new Uint8Array(buffer).every((byte) => byte === 0);
}

let live: CryptoKey;
let earlier: CryptoKey;
let backupOfEarlier: IBackupSettings;

beforeAll(async () => {
  live = await vaultKey(0x11);
  earlier = await vaultKey(0x22);
  backupOfEarlier = await accountBackup(earlier);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('openBackupKeyCopy', () => {
  it('opens the copy of an earlier key as a key that opens what that key sealed', async () => {
    const sealed = await cryptoService.encryptData('stranded entry', earlier);

    const outcome = await openBackupKeyCopy(backupOfEarlier, BACKUP_PASSWORD, live);

    expect(outcome.kind).toBe('opened');
    const key = (outcome as { key: CryptoKey }).key;
    expect(await cryptoService.decryptData(sealed.encrypted, sealed.iv, sealed.tag, key)).toBe(
      'stranded entry',
    );
    // Never the live key itself under another name.
    expect(key).not.toBe(live);
  });

  it('zeroes the raw backup wrapping key and the raw copy once the key is imported', async () => {
    const decryptBwk = vi.spyOn(cryptoService, 'decryptBWK');
    const decryptCopy = vi.spyOn(cryptoService, 'decryptVaultKeyWithBWK');

    await openBackupKeyCopy(backupOfEarlier, BACKUP_PASSWORD, live);

    const rawBwk = await (decryptBwk.mock.results[0]!.value as Promise<ArrayBuffer>);
    const rawCopy = await (decryptCopy.mock.results[0]!.value as Promise<ArrayBuffer>);
    expect(zeroed(rawBwk)).toBe(true);
    expect(zeroed(rawCopy)).toBe(true);
  });

  it('says the copy is the live key, importing nothing, when it is', async () => {
    const backupOfLive = await accountBackup(live);
    const importKey = vi.spyOn(cryptoService, 'importVaultKey');
    const decryptCopy = vi.spyOn(cryptoService, 'decryptVaultKeyWithBWK');

    expect(await openBackupKeyCopy(backupOfLive, BACKUP_PASSWORD, live)).toEqual({
      kind: 'same-as-live',
    });
    expect(importKey).not.toHaveBeenCalled();
    const rawCopy = await (decryptCopy.mock.results[0]!.value as Promise<ArrayBuffer>);
    expect(zeroed(rawCopy)).toBe(true);
  });

  it('says the backup password is wrong, opening nothing further', async () => {
    const decryptCopy = vi.spyOn(cryptoService, 'decryptVaultKeyWithBWK');

    expect(await openBackupKeyCopy(backupOfEarlier, 'not the backup password', live)).toEqual({
      kind: 'wrong-password',
    });
    expect(decryptCopy).not.toHaveBeenCalled();
  });

  it('says the copy cannot be opened when the wrapping key opens but the copy does not', async () => {
    const replaced = await accountBackup(earlier, cryptoService.generateBWK());
    const decryptBwk = vi.spyOn(cryptoService, 'decryptBWK');
    const importKey = vi.spyOn(cryptoService, 'importVaultKey');

    expect(await openBackupKeyCopy(replaced, BACKUP_PASSWORD, live)).toEqual({
      kind: 'unopenable',
    });
    expect(importKey).not.toHaveBeenCalled();
    const rawBwk = await (decryptBwk.mock.results[0]!.value as Promise<ArrayBuffer>);
    expect(zeroed(rawBwk)).toBe(true);
  });

  it('says no copy is stored, deriving nothing, when no backup wrapping key is stored either', async () => {
    const derive = vi.spyOn(cryptoService, 'deriveBEK');
    const { bwkSalt: _salt, ...noSalt } = backupOfEarlier;

    for (const backup of [undefined, noSalt] as (IBackupSettings | undefined)[]) {
      expect(await openBackupKeyCopy(backup, BACKUP_PASSWORD, live)).toEqual({ kind: 'absent' });
    }
    expect(derive).not.toHaveBeenCalled();
  });

  it('judges the backup password even when no copy is stored, zeroing the wrapping key it opened', async () => {
    const { bwkVaultKeyTag: _tag, ...noCopy } = backupOfEarlier;
    const decryptBwk = vi.spyOn(cryptoService, 'decryptBWK');
    const decryptCopy = vi.spyOn(cryptoService, 'decryptVaultKeyWithBWK');

    expect(await openBackupKeyCopy(noCopy, 'not the backup password', live)).toEqual({
      kind: 'wrong-password',
    });
    expect(await openBackupKeyCopy(noCopy, BACKUP_PASSWORD, live)).toEqual({ kind: 'absent' });

    // The second unwrap is the right password's; the first one refused.
    expect(decryptBwk).toHaveBeenCalledTimes(2);
    const rawBwk = await (decryptBwk.mock.results[1]!.value as Promise<ArrayBuffer>);
    expect(zeroed(rawBwk)).toBe(true);
    expect(decryptCopy).not.toHaveBeenCalled();
  });
});

describe('hasBackupKeyCopy', () => {
  it('is true only for a complete wrapping key AND a complete copy', () => {
    expect(hasBackupKeyCopy(backupOfEarlier)).toBe(true);
    expect(hasBackupKeyCopy(undefined)).toBe(false);
    for (const field of [
      'encryptedBWK',
      'bwkIv',
      'bwkTag',
      'bwkSalt',
      'bwkEncryptedVaultKey',
      'bwkVaultKeyIv',
      'bwkVaultKeyTag',
    ] as const) {
      expect(hasBackupKeyCopy({ ...backupOfEarlier, [field]: '' })).toBe(false);
    }
  });
});

describe('the backup wrapping key helpers', () => {
  it('builds a wrapper only from all four fields, and compares wrappers field by field', () => {
    const wrapper = completeBwkWrapper(backupOfEarlier);
    expect(wrapper).toEqual({
      encryptedBWK: backupOfEarlier.encryptedBWK,
      bwkIv: backupOfEarlier.bwkIv,
      bwkTag: backupOfEarlier.bwkTag,
      bwkSalt: backupOfEarlier.bwkSalt,
    });
    expect(completeBwkWrapper({ ...backupOfEarlier, bwkTag: '' })).toBeNull();
    expect(completeBwkWrapper(undefined)).toBeNull();
    expect(sameBwkWrapper(wrapper!, { ...wrapper! })).toBe(true);
    expect(sameBwkWrapper(wrapper!, { ...wrapper!, bwkSalt: 'other' })).toBe(false);
  });

  it('answers null for a password that does not open the wrapper, and rethrows a failed derivation', async () => {
    const wrapper = completeBwkWrapper(backupOfEarlier)!;
    expect(await unwrapBwk(wrapper, 'wrong')).toBeNull();

    vi.spyOn(cryptoService, 'deriveBEK').mockRejectedValueOnce(new Error('derive refused'));
    await expect(unwrapBwk(wrapper, BACKUP_PASSWORD)).rejects.toThrow('derive refused');
  });
});
