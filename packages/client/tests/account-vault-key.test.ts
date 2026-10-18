/**
 * `holdsAccountVaultKey`: does the key this session holds equal the one the
 * account's wrapper opens to?
 *
 * The one question both the re-seal's same-key proof and a session checking a
 * superseded key ask, answered with real crypto: open the wrapper with the master
 * key, compare the bytes in constant time, and clear the plaintext key bytes on
 * every path.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { cryptoService } from '../src/services/crypto/cryptoService';
import { holdsAccountVaultKey } from '../src/services/crypto/accountVaultKey';

async function freshMek(): Promise<CryptoKey> {
  return globalThis.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
}

async function freshVaultKey(): Promise<CryptoKey> {
  return cryptoService.importVaultKey(cryptoService.generateVaultKey());
}

async function wrap(key: CryptoKey, mek: CryptoKey) {
  return cryptoService.encryptVaultKey(key, mek);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('holdsAccountVaultKey', () => {
  it('answers true for the very key the wrapper holds', async () => {
    const mek = await freshMek();
    const key = await freshVaultKey();

    expect(await holdsAccountVaultKey(key, await wrap(key, mek), mek)).toBe(true);
  });

  it('answers false for any other key, such as the one a rotation replaced', async () => {
    const mek = await freshMek();
    const held = await freshVaultKey();

    expect(await holdsAccountVaultKey(held, await wrap(await freshVaultKey(), mek), mek)).toBe(
      false,
    );
  });

  it('throws when the master key cannot open the wrapper, rather than answering either way', async () => {
    const key = await freshVaultKey();
    const wrapper = await wrap(key, await freshMek());

    await expect(holdsAccountVaultKey(key, wrapper, await freshMek())).rejects.toThrow(
      'Failed to decrypt vault key',
    );
  });

  it('zeroes the opened key bytes once compared, whichever way the answer goes', async () => {
    // The exact buffers the wrapper was opened into, so the assertion is about
    // THIS function's plaintext and not the copy the comparison exports and clears.
    const opened: ArrayBuffer[] = [];
    const realDecrypt = cryptoService.decryptVaultKey.bind(cryptoService);
    vi.spyOn(cryptoService, 'decryptVaultKey').mockImplementation(async (...args) => {
      const raw = await realDecrypt(...args);
      opened.push(raw);
      return raw;
    });
    const clearKey = vi.spyOn(cryptoService, 'clearKey');
    const mek = await freshMek();
    const key = await freshVaultKey();

    await holdsAccountVaultKey(key, await wrap(key, mek), mek);
    await holdsAccountVaultKey(key, await wrap(await freshVaultKey(), mek), mek);

    expect(opened).toHaveLength(2);
    for (const raw of opened) {
      expect(clearKey).toHaveBeenCalledWith(raw);
      expect(new Uint8Array(raw).every((byte) => byte === 0)).toBe(true);
    }
  });
});
