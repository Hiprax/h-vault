/**
 * The master-password proof a settings card sends: the auth hash derived from the
 * typed password and the account's address, with BOTH derived keys zeroed before
 * it is handed back, and nothing else derived or kept.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn(),
    getAuthHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn(),
  },
}));

import { proveMasterPassword } from '../../src/lib/masterPasswordProof';
import { cryptoService } from '../../src/services/crypto/cryptoService';

const AUTH_KEY = new ArrayBuffer(32);
const MEK = {} as CryptoKey;

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(cryptoService.deriveKeys).mockResolvedValue({
    masterEncryptionKey: MEK,
    authKey: AUTH_KEY,
  } as never);
  vi.mocked(cryptoService.getAuthHash).mockReturnValue('proof-hash');
});

describe('proveMasterPassword', () => {
  it('derives from the password with the address as salt, returns the auth hash, then zeroes the auth key and releases the master key', async () => {
    await expect(proveMasterPassword('my master password', 'owner@example.org')).resolves.toBe(
      'proof-hash',
    );
    expect(cryptoService.deriveKeys).toHaveBeenCalledWith(
      'my master password',
      'owner@example.org',
    );
    expect(cryptoService.getAuthHash).toHaveBeenCalledWith(AUTH_KEY);
    expect(cryptoService.clearKey).toHaveBeenCalledWith(AUTH_KEY);
    expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(MEK);
    // The hash is read from the auth key's bytes, so it must be taken BEFORE they
    // are zeroed: the other order would send the hash of 32 zero bytes.
    const hashed = vi.mocked(cryptoService.getAuthHash).mock.invocationCallOrder[0]!;
    const zeroed = vi.mocked(cryptoService.clearKey).mock.invocationCallOrder[0]!;
    expect(hashed).toBeLessThan(zeroed);
  });

  it('hands back nothing when the derivation fails', async () => {
    vi.mocked(cryptoService.deriveKeys).mockRejectedValueOnce(new Error('no Web Crypto'));
    await expect(proveMasterPassword('pw', 'owner@example.org')).rejects.toThrow('no Web Crypto');
    expect(cryptoService.getAuthHash).not.toHaveBeenCalled();
  });
});
