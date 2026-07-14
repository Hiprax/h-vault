/**
 * Tests for the encryptedStorage Zustand StateStorage adapter.
 *
 * Verifies AES-256-GCM encryption/decryption of persisted state,
 * degraded-mode fallback, buffer validation, and key lifecycle.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock the logger to suppress console output during tests
vi.mock('../src/lib/logger', () => ({
  logger: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
    debug: vi.fn(),
  },
}));

// ---------------------------------------------------------------------------
// Module-level state helpers
// ---------------------------------------------------------------------------

const SESSION_KEY_NAME = 'hvault_storage_key';
const STORAGE_DEGRADED_KEY = '__hv_storage_degraded';

/**
 * Clear the module cache so each test gets a fresh encryptedStorage with
 * no cached CryptoKey from a previous test.
 */
async function freshImport() {
  vi.resetModules();
  const mod = await import('../src/stores/encryptedStorage');
  return mod;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('encryptedStorage', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  // -------------------------------------------------------------------------
  // getItem
  // -------------------------------------------------------------------------

  it('getItem returns null for missing keys', async () => {
    const { encryptedStorage } = await freshImport();
    const result = await encryptedStorage.getItem('nonexistent');
    expect(result).toBeNull();
  });

  // -------------------------------------------------------------------------
  // setItem + getItem round-trip
  // -------------------------------------------------------------------------

  it('setItem + getItem round-trips data correctly', async () => {
    const { encryptedStorage } = await freshImport();
    const testData = JSON.stringify({
      state: { isAuthenticated: true, user: { email: 'test@example.com' } },
    });

    await encryptedStorage.setItem('test-store', testData);
    const result = await encryptedStorage.getItem('test-store');

    expect(result).toBe(testData);
  });

  it('round-trips complex nested data', async () => {
    const { encryptedStorage } = await freshImport();
    const testData = JSON.stringify({
      state: {
        isAuthenticated: true,
        user: { userId: '123', email: 'test@example.com' },
        encryptedVaultKeyData: { encrypted: 'abc', iv: 'def', tag: 'ghi' },
        kdfIterations: 600000,
      },
      version: 0,
    });

    await encryptedStorage.setItem('auth-store', testData);
    const result = await encryptedStorage.getItem('auth-store');

    expect(result).toBe(testData);
  });

  // -------------------------------------------------------------------------
  // Data in localStorage is encrypted (not plaintext)
  // -------------------------------------------------------------------------

  it('stores encrypted data in localStorage, not plaintext', async () => {
    const { encryptedStorage } = await freshImport();
    const secretValue = 'super-secret-vault-data-12345';
    const testData = JSON.stringify({ state: { secret: secretValue } });

    await encryptedStorage.setItem('encrypted-test', testData);

    const rawStored = localStorage.getItem('encrypted-test');
    expect(rawStored).not.toBeNull();
    // Raw stored value must not contain the plaintext
    expect(rawStored).not.toContain(secretValue);
    expect(rawStored).not.toContain('super-secret');
    // It should be a base64 string
    expect(rawStored).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });

  // -------------------------------------------------------------------------
  // Corrupted localStorage data
  // -------------------------------------------------------------------------

  it('returns null and removes entry for corrupted localStorage data', async () => {
    const { encryptedStorage } = await freshImport();

    // Write valid data first to create a session key
    await encryptedStorage.setItem('my-store', '"hello"');

    // Now corrupt the localStorage entry
    localStorage.setItem('my-store', 'not-valid-base64!!!');

    const result = await encryptedStorage.getItem('my-store');
    expect(result).toBeNull();
    expect(localStorage.getItem('my-store')).toBeNull();
  });

  it('returns null and removes entry when data was encrypted with a different key', async () => {
    const { encryptedStorage } = await freshImport();

    // Write data with current session key
    await encryptedStorage.setItem('my-store', '"original"');

    // Simulate browser restart: clear session key and get a fresh module
    sessionStorage.clear();
    const { encryptedStorage: freshStorage } = await freshImport();

    // getItem should fail to decrypt (different key) and return null
    const result = await freshStorage.getItem('my-store');
    expect(result).toBeNull();
    // Stale entry should be removed
    expect(localStorage.getItem('my-store')).toBeNull();
  });

  // -------------------------------------------------------------------------
  // Buffer validation: rejects data shorter than 13 bytes
  // -------------------------------------------------------------------------

  it('rejects base64 data shorter than 13 bytes (12-byte IV + 1 byte min)', async () => {
    const { encryptedStorage } = await freshImport();

    // Trigger key creation first
    await encryptedStorage.setItem('init', '"x"');

    // Create a valid base64 string that decodes to < 13 bytes (e.g. 10 bytes)
    const shortData = new Uint8Array(10);
    crypto.getRandomValues(shortData);
    let binary = '';
    for (const byte of shortData) {
      binary += String.fromCharCode(byte);
    }
    localStorage.setItem('short-data', btoa(binary));

    const result = await encryptedStorage.getItem('short-data');
    expect(result).toBeNull();
    // Corrupted entry should be removed
    expect(localStorage.getItem('short-data')).toBeNull();
  });

  it('accepts base64 data of exactly 13 bytes (clears the < 13 length guard)', async () => {
    const { encryptedStorage } = await freshImport();
    // Same module graph as the freshly-imported storage, so this is the exact
    // (mocked) logger instance getItem calls.
    const { logger } = await import('../src/lib/logger');

    // Trigger key creation first.
    await encryptedStorage.setItem('init', '"x"');
    vi.mocked(logger.error).mockClear();

    // Exactly 13 bytes: 12-byte IV + 1 byte — the smallest input the `< 13`
    // guard admits. Random bytes are not a valid AES-GCM container, so decrypt
    // fails and getItem returns null; the point is that it reaches the DECRYPT
    // path, NOT the too-short path. Raising the floor (e.g. `< 14`) would divert
    // this 13-byte input to the too-short branch and fire the 'Corrupted...' log.
    const thirteen = new Uint8Array(13);
    crypto.getRandomValues(thirteen);
    let binary = '';
    for (const byte of thirteen) {
      binary += String.fromCharCode(byte);
    }
    localStorage.setItem('boundary-13', btoa(binary));

    const result = await encryptedStorage.getItem('boundary-13');

    // The too-short branch is the ONLY caller of this log line, so its absence
    // proves 13 bytes cleared the length guard.
    expect(logger.error).not.toHaveBeenCalledWith('Corrupted encrypted storage data');
    expect(result).toBeNull();
    expect(localStorage.getItem('boundary-13')).toBeNull();

    // A normal round-trip (well above the guard) still works end to end.
    await encryptedStorage.setItem('valid', '"hi"');
    expect(await encryptedStorage.getItem('valid')).toBe('"hi"');
  });

  // -------------------------------------------------------------------------
  // removeItem
  // -------------------------------------------------------------------------

  it('removeItem clears the entry from localStorage', async () => {
    const { encryptedStorage } = await freshImport();

    await encryptedStorage.setItem('to-remove', '"data"');
    expect(localStorage.getItem('to-remove')).not.toBeNull();

    encryptedStorage.removeItem('to-remove');
    expect(localStorage.getItem('to-remove')).toBeNull();
  });

  // -------------------------------------------------------------------------
  // Degraded mode
  // -------------------------------------------------------------------------

  describe('degraded mode (Web Crypto unavailable)', () => {
    it('strips sensitive data when crypto is unavailable', async () => {
      // Temporarily remove Web Crypto API
      const originalSubtle = crypto.subtle;
      Object.defineProperty(crypto, 'subtle', { value: undefined, configurable: true });

      try {
        const { encryptedStorage } = await freshImport();

        const sensitiveState = JSON.stringify({
          state: {
            isAuthenticated: true,
            accessToken: 'secret-token',
            vaultKey: 'secret-key',
            mek: 'master-key',
            user: { email: 'user@test.com' },
            encryptedVaultKeyData: { encrypted: 'xxx' },
          },
          version: 0,
        });

        await encryptedStorage.setItem('auth-store', sensitiveState);

        // Check what was stored in localStorage
        const stored = localStorage.getItem('auth-store');
        expect(stored).not.toBeNull();
        const parsed = JSON.parse(stored!);

        // Only isAuthenticated should survive
        expect(parsed.state.isAuthenticated).toBe(true);
        expect(parsed.state.accessToken).toBeUndefined();
        expect(parsed.state.vaultKey).toBeUndefined();
        expect(parsed.state.mek).toBeUndefined();
        expect(parsed.state.user).toBeUndefined();
        expect(parsed.state.encryptedVaultKeyData).toBeUndefined();

        // Degraded flag should be set
        expect(localStorage.getItem(STORAGE_DEGRADED_KEY)).toBe('true');
      } finally {
        Object.defineProperty(crypto, 'subtle', { value: originalSubtle, configurable: true });
      }
    });

    it('getItem returns null when session key is missing and crypto fails', async () => {
      // Temporarily remove Web Crypto API
      const originalSubtle = crypto.subtle;
      Object.defineProperty(crypto, 'subtle', { value: undefined, configurable: true });

      try {
        const { encryptedStorage } = await freshImport();

        // Put some data directly in localStorage
        localStorage.setItem('some-key', 'some-value');

        const result = await encryptedStorage.getItem('some-key');
        expect(result).toBeNull();
      } finally {
        Object.defineProperty(crypto, 'subtle', { value: originalSubtle, configurable: true });
      }
    });
  });

  // -------------------------------------------------------------------------
  // isStorageDegraded
  // -------------------------------------------------------------------------

  it('isStorageDegraded returns false normally', async () => {
    const { isStorageDegraded } = await freshImport();
    expect(isStorageDegraded()).toBe(false);
  });

  it('isStorageDegraded returns true when degraded flag is set', async () => {
    localStorage.setItem(STORAGE_DEGRADED_KEY, 'true');
    const { isStorageDegraded } = await freshImport();
    expect(isStorageDegraded()).toBe(true);
  });

  it('setItem clears degraded flag when encryption succeeds', async () => {
    const { encryptedStorage, isStorageDegraded } = await freshImport();

    // Set degraded flag manually
    localStorage.setItem(STORAGE_DEGRADED_KEY, 'true');
    expect(isStorageDegraded()).toBe(true);

    // Successful setItem should clear it
    await encryptedStorage.setItem('store', '"data"');
    expect(isStorageDegraded()).toBe(false);
  });

  // -------------------------------------------------------------------------
  // Session key caching
  // -------------------------------------------------------------------------

  it('reuses cached key across multiple operations', async () => {
    const { encryptedStorage } = await freshImport();

    // Write and read multiple items — all should work with the same key
    await encryptedStorage.setItem('key1', '"value1"');
    await encryptedStorage.setItem('key2', '"value2"');

    expect(await encryptedStorage.getItem('key1')).toBe('"value1"');
    expect(await encryptedStorage.getItem('key2')).toBe('"value2"');

    // Session key should be stored
    expect(sessionStorage.getItem(SESSION_KEY_NAME)).not.toBeNull();
  });

  it('generates a new session key on first use', async () => {
    const { encryptedStorage } = await freshImport();

    expect(sessionStorage.getItem(SESSION_KEY_NAME)).toBeNull();

    await encryptedStorage.setItem('trigger', '"init"');

    expect(sessionStorage.getItem(SESSION_KEY_NAME)).not.toBeNull();
    // Should be a valid base64 string
    const key = sessionStorage.getItem(SESSION_KEY_NAME)!;
    expect(key).toMatch(/^[A-Za-z0-9+/]+=*$/);
    // AES-256 key = 32 bytes => base64 = 44 chars
    expect(atob(key).length).toBe(32);
  });
});
