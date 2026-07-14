/**
 * Encrypted Local Storage adapter for Zustand persist middleware.
 *
 * Encrypts persisted state with AES-256-GCM before writing to localStorage.
 * The encryption key is generated once per browser session and stored in
 * sessionStorage, so it is automatically cleared when the tab/window closes.
 *
 * This ensures that persisted Zustand state (e.g. user metadata, encrypted
 * vault key data) cannot be read by someone with access to the localStorage
 * database on disk, unless the browser session is still active.
 *
 * If the session key is missing (browser was restarted), getItem returns null
 * and the stale encrypted data is removed from localStorage. The app will
 * treat this as a fresh session and redirect to login.
 */

import type { StateStorage } from 'zustand/middleware';
import { logger } from '../lib/logger.js';

const SESSION_KEY_NAME = 'hvault_storage_key';
const STORAGE_DEGRADED_KEY = '__hv_storage_degraded';

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

/** Cached CryptoKey to avoid re-importing on every getItem/setItem call. */
let cachedKey: CryptoKey | null = null;
/** The raw base64 string the cached key was imported from (for staleness check). */
let cachedKeyRaw: string | null = null;

/**
 * Retrieve the AES-256-GCM encryption key from sessionStorage, or generate
 * a new one if this is the first call in the current browser session.
 *
 * The imported CryptoKey is cached in a module-scoped variable so that
 * subsequent calls skip the `crypto.subtle.importKey` round-trip when the
 * underlying raw key in sessionStorage hasn't changed.
 *
 * Returns `null` only if the Web Crypto API is unavailable.
 */
async function getOrCreateKey(): Promise<CryptoKey | null> {
  try {
    const stored = sessionStorage.getItem(SESSION_KEY_NAME);

    // Return cached key if the raw material hasn't changed
    if (stored && stored === cachedKeyRaw && cachedKey) {
      return cachedKey;
    }

    if (stored) {
      const raw = Uint8Array.from(atob(stored), (c) => c.charCodeAt(0));
      // Re-imported as non-extractable: once the key is loaded from
      // sessionStorage there is no need to export it again, so we lock
      // it down to reduce the in-memory attack surface.
      const imported = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, [
        'encrypt',
        'decrypt',
      ]);
      cachedKey = imported;
      cachedKeyRaw = stored;
      return imported;
    }

    // Generate a new 256-bit key.
    //
    // SECURITY TRADE-OFF: extractable is set to `true` intentionally.
    //
    // The key must be extractable so that its raw material can be serialised
    // to sessionStorage (via `exportKey`) and re-imported when needed.
    // Without extractability the key could not survive page reloads within
    // the same browser session, which would force a re-login on every
    // navigation.
    //
    // Risk: if an attacker gains DOM access (e.g. via XSS), they could call
    // `crypto.subtle.exportKey('raw', key)` to obtain the raw key material.
    // However, DOM access already grants the ability to read sessionStorage
    // directly (where the base64-encoded key is stored), so extractability
    // does not meaningfully widen the attack surface.
    //
    // A non-extractable key was considered but rejected because:
    //   1. The key material must persist in sessionStorage across page loads.
    //   2. `crypto.subtle.exportKey` requires `extractable: true`.
    //   3. IndexedDB-based persistence (which can store non-extractable
    //      CryptoKey objects) does not auto-clear on session end, defeating
    //      the purpose of session-scoped encryption.
    //
    // Mitigation: the key is scoped to sessionStorage, which is automatically
    // cleared when the browser tab/window closes, limiting the exposure
    // window to the lifetime of the active session.
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable — see security trade-off note above
      ['encrypt', 'decrypt'],
    );
    const exported = await crypto.subtle.exportKey('raw', key);
    const exportedBytes = new Uint8Array(exported);
    let keyBinary = '';
    for (const byte of exportedBytes) {
      keyBinary += String.fromCharCode(byte);
    }
    const newKeyBase64 = btoa(keyBinary);
    sessionStorage.setItem(SESSION_KEY_NAME, newKeyBase64);
    cachedKey = key;
    cachedKeyRaw = newKeyBase64;
    return key;
  } catch {
    // Web Crypto API unavailable (e.g. non-secure context) -- fall through
    cachedKey = null;
    cachedKeyRaw = null;
    return null;
  }
}

// ---------------------------------------------------------------------------
// Degraded-mode helper
// ---------------------------------------------------------------------------

/**
 * In degraded mode (Web Crypto unavailable), strip ALL sensitive data from the
 * persisted state. Only the bare minimum (`isAuthenticated`) is kept so the app
 * can decide whether to show the login screen. Everything else (user email,
 * kdfIterations, encryptedVaultKeyData, etc.) is removed to avoid leaking
 * sensitive information in plaintext localStorage.
 */
function stripSensitiveState(value: string): string {
  try {
    const parsed: unknown = JSON.parse(value);
    if (typeof parsed === 'object' && parsed !== null && 'state' in parsed) {
      const obj = parsed as Record<string, unknown>;
      const state = obj.state as Record<string, unknown> | undefined;
      if (state) {
        const safeState: Record<string, unknown> = {
          isAuthenticated: state.isAuthenticated === true,
        };
        return JSON.stringify({ ...obj, state: safeState });
      }
    }
  } catch {
    // Not JSON or malformed — return empty state to avoid leaking data
    return JSON.stringify({ state: { isAuthenticated: false } });
  }
  return value;
}

// ---------------------------------------------------------------------------
// Zustand StateStorage implementation (async)
// ---------------------------------------------------------------------------

/**
 * A Zustand `StateStorage` adapter that transparently encrypts values with
 * AES-256-GCM before writing to localStorage and decrypts on read.
 *
 * Zustand's persist middleware supports async `getItem` / `setItem`, so
 * returning Promises is fully supported.
 */
export const encryptedStorage: StateStorage = {
  getItem: async (name: string): Promise<string | null> => {
    const stored = localStorage.getItem(name);
    if (!stored) return null;

    try {
      const key = await getOrCreateKey();
      if (!key) return null;

      const combined = Uint8Array.from(atob(stored), (c) => c.charCodeAt(0));
      if (combined.length < 13) {
        // 12 bytes IV + at least 1 byte ciphertext required
        logger.error('Corrupted encrypted storage data');
        localStorage.removeItem(name);
        return null;
      }
      const iv = combined.slice(0, 12);
      const ciphertext = combined.slice(12);
      const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
      return new TextDecoder().decode(decrypted);
    } catch {
      // Decryption failed -- the session key was rotated (browser restarted)
      // or the data is corrupt. Remove the stale entry so the app starts
      // fresh.
      localStorage.removeItem(name);
      return null;
    }
  },

  setItem: async (name: string, value: string): Promise<void> => {
    try {
      const key = await getOrCreateKey();
      if (!key) {
        // Web Crypto unavailable — store only the absolute minimum needed
        // (isAuthenticated boolean) to avoid leaking sensitive data in plaintext.
        localStorage.setItem(name, stripSensitiveState(value));
        localStorage.setItem(STORAGE_DEGRADED_KEY, 'true');
        return;
      }

      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(value);
      const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

      // Combine IV (12 bytes) + ciphertext and base64-encode the result
      const combined = new Uint8Array(iv.length + new Uint8Array(ciphertext).length);
      combined.set(iv);
      combined.set(new Uint8Array(ciphertext), iv.length);

      let binary = '';
      for (const byte of combined) {
        binary += String.fromCharCode(byte);
      }
      localStorage.setItem(name, btoa(binary));
      // Encrypted storage is working — clear degraded flag if it was set
      localStorage.removeItem(STORAGE_DEGRADED_KEY);
    } catch {
      // Encryption failed — store only the absolute minimum needed
      localStorage.setItem(name, stripSensitiveState(value));
      localStorage.setItem(STORAGE_DEGRADED_KEY, 'true');
    }
  },

  removeItem: (name: string): void => {
    localStorage.removeItem(name);
  },
};

/**
 * Returns true when the encrypted storage adapter has fallen back to
 * unencrypted localStorage (e.g. because the Web Crypto API is unavailable
 * in a non-HTTPS context).
 */
export function isStorageDegraded(): boolean {
  return localStorage.getItem(STORAGE_DEGRADED_KEY) === 'true';
}
