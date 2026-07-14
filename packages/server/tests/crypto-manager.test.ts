import { describe, it, expect } from 'vitest';
import { CryptoManager } from '@hiprax/crypto';
import { cryptoManager, ValidationBypassCryptoManager } from '../src/utils/cryptoManager.js';

// Config-secret key used for 2FA-secret encryption in tests (mirrors the test
// SESSION_SECRET). Server config secrets are not user passwords, hence the
// validatePassword override.
const KEY = 'TestSessionSecret4Testing!!12345';
const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

// Genuine v0 (pre-1.0, pre-HPCR-header) sync ciphertext captured from
// @hiprax/crypto@0.9.5 BEFORE the 1.4.4 upgrade. Existing 2FA secrets encrypted
// under the old version must remain decryptable (legacyMode 'auto'), or users
// with 2FA enabled would be locked out after the upgrade.
const V0_CIPHERTEXT =
  'M5ZlRV3Pl6OemwO3CyO2r6YLjQQflilTnEG1N0OLBI2xgQBRll6jsOGpOQ-ircXtjjmBYfcLfwk8KFiVvfJ1Zwyl605PEXO02Xsoao-EDbSTum_uxBN1X_lx_Go';

describe('shared cryptoManager', () => {
  it('has validatePassword overridden to always return true', () => {
    // The override allows server-side config secrets (which don't follow
    // user-password complexity rules) to be used as encryption keys.
    expect(cryptoManager.validatePassword('simple')).toBe(true);
  });

  it('accepts any string as a valid password (override)', () => {
    // Even trivially simple strings pass because the override always returns true.
    expect(cryptoManager.validatePassword('')).toBe(true);
    expect(cryptoManager.validatePassword('a')).toBe(true);
    expect(cryptoManager.validatePassword('no-uppercase-or-special')).toBe(true);
  });

  it('is a real CryptoManager (subclass) instance', () => {
    // Verify it's the real CryptoManager subclass, not a mock. Uses
    // toBeInstanceOf rather than constructor.name since the instance is now a
    // ValidationBypassCryptoManager.
    expect(cryptoManager).toBeInstanceOf(CryptoManager);
    expect(cryptoManager).toBeInstanceOf(ValidationBypassCryptoManager);
  });

  it('round-trips a fresh (v1) 2FA-secret ciphertext', () => {
    const cipher = cryptoManager.encryptTextSync(SECRET, KEY);
    expect(cryptoManager.decryptTextSync(cipher, KEY)).toBe(SECRET);
  });

  it('decrypts a legacy v0 ciphertext produced by @hiprax/crypto 0.9.5', () => {
    // legacyMode defaults to 'auto', so pre-1.0 v0 sync ciphertexts stay
    // decryptable — no 2FA lockout on upgrade.
    expect(cryptoManager.decryptTextSync(V0_CIPHERTEXT, KEY)).toBe(SECRET);
  });
});
