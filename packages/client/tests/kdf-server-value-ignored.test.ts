/**
 * The client derives the master key with its OWN iteration count, never the
 * server's.
 *
 * Every sign-in response and every profile read carries a `kdfIterations`
 * field, and `authStore` stores it and persists it. It is a record of what the
 * account was registered with, nothing more: if the client ever derived with
 * it, a hostile or compromised server could answer `1` and have every unlock
 * run a single PBKDF2 round, turning the next captured auth hash into an
 * offline guess per password rather than 600,000 hashes per guess. Ignoring it
 * is therefore a security property, and this pins it on the path that consumes
 * the persisted value directly: `unlock`, which re-derives the MEK from the
 * master password with no server call at all.
 *
 * Real `authStore`, real `cryptoService`, real Web Crypto. What is mocked is the
 * encrypted session storage, which persists nothing in a unit run.
 */
import { describe, it, expect, vi, beforeEach, afterEach, type MockInstance } from 'vitest';
import { KDF_ITERATIONS } from '@hvault/shared';

vi.hoisted(() => {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    configurable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
});

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
  isStorageDegraded: vi.fn().mockReturnValue(false),
}));

import { useAuthStore } from '../src/stores/authStore';
import { cryptoService } from '../src/services/crypto/cryptoService';

const PASSWORD = 'correct horse battery staple';
const EMAIL = 'kdf.owner@example.test';

let deriveBits: MockInstance<SubtleCrypto['deriveBits']>;

beforeEach(async () => {
  // The wrapped vault key the session persisted, sealed under the MEK the
  // client's own derivation produces.
  const { masterEncryptionKey } = await cryptoService.deriveKeys(PASSWORD, EMAIL);
  const vaultKey = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
  const encryptedVaultKeyData = await cryptoService.encryptVaultKey(vaultKey, masterEncryptionKey);

  useAuthStore.setState({
    user: { userId: 'u1', email: EMAIL },
    isAuthenticated: true,
    isLocked: true,
    vaultKey: null,
    mek: null,
    encryptedVaultKeyData,
    // What a hostile server would answer.
    kdfIterations: 1,
  } as never);

  deriveBits = vi.spyOn(globalThis.crypto.subtle, 'deriveBits');
});

afterEach(() => {
  deriveBits.mockRestore();
});

describe('unlock with a server-supplied kdfIterations of 1', () => {
  it('derives with KDF_ITERATIONS and unlocks the vault', async () => {
    await useAuthStore.getState().unlock(PASSWORD);

    const iterations = deriveBits.mock.calls.map(([params]) => (params as Pbkdf2Params).iterations);
    // The MEK round at the client's own count, then the one-round auth-key hash.
    expect(iterations).toEqual([KDF_ITERATIONS, 1]);
    expect(iterations[0]).toBe(600_000);

    const state = useAuthStore.getState();
    expect(state.vaultKey).not.toBeNull();
    expect(state.mek).not.toBeNull();
    // The recorded value is left as it is: stored, never acted on.
    expect(state.kdfIterations).toBe(1);
  });

  it('refuses a wrong password rather than accepting a cheaper derivation', async () => {
    await expect(useAuthStore.getState().unlock('not the password')).rejects.toThrow(
      /Failed to decrypt vault key/,
    );

    expect(deriveBits.mock.calls.map(([params]) => (params as Pbkdf2Params).iterations)[0]).toBe(
      KDF_ITERATIONS,
    );
    expect(useAuthStore.getState().vaultKey).toBeNull();
    expect(useAuthStore.getState().mek).toBeNull();
  });
});
