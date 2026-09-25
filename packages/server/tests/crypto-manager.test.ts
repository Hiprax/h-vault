import { describe, it, expect } from 'vitest';
import { CryptoError, CryptoManager } from '@hiprax/crypto';
import {
  cryptoManager,
  TWO_FACTOR_SECRET_PBKDF2_ITERATIONS,
  ValidationBypassCryptoManager,
} from '../src/utils/cryptoManager.js';

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

  it('seals under a weak key through encryptTextSync, which the base class refuses', () => {
    // The override is only worth anything if encryptTextSync still consults it.
    // `KEY` passes the package's own password rule, so the round-trip above never
    // reaches the bypass; a weak key does. The base class must refuse it (else the
    // pair proves nothing) and the subclass must seal AND recover it.
    let refusal: unknown;
    try {
      new CryptoManager().encryptTextSync(SECRET, 'simple');
    } catch (err) {
      refusal = err;
    }
    expect(refusal).toBeInstanceOf(CryptoError);
    expect((refusal as CryptoError).code).toBe('WEAK_PASSWORD');

    const cipher = cryptoManager.encryptTextSync(SECRET, 'simple');
    expect(cipher).not.toContain(SECRET);
    expect(cryptoManager.decryptTextSync(cipher, 'simple')).toBe(SECRET);
  });

  it('configures no decrypt KDF floor', () => {
    // A floor binds headerless input too, and a v0 ciphertext decrypts at the
    // fallback count (100,000 by default), so ANY `minPbkdf2Iterations` above that
    // refuses every pre-1.0 2FA secret: the lockout the v0 golden above exists to
    // prevent. This pins the configuration, next to the ciphertext it would break.
    expect(cryptoManager.getDecryptKdfLimits()).toMatchObject({
      minWork: 0,
      minPbkdf2Iterations: 0,
    });
  });

  it('shows why: a floored twin refuses the v0 golden before deriving anything', () => {
    // Same class, same write cost, one added floor. The refusal is the HEADERLESS
    // one, raised before any key derivation: until 1.9.0 a floor never reached v0
    // input at all. (A v1 row written at 10,000 would be refused by this floor too,
    // on its header, which is why no floor above the write count is ever safe.)
    const floored = new ValidationBypassCryptoManager({
      pbkdf2Iterations: TWO_FACTOR_SECRET_PBKDF2_ITERATIONS,
      decryptKdfLimits: { minPbkdf2Iterations: 600_000 },
    });
    let refusal: unknown;
    try {
      floored.decryptTextSync(V0_CIPHERTEXT, KEY);
    } catch (err) {
      refusal = err;
    }
    expect(refusal).toBeInstanceOf(CryptoError);
    expect((refusal as CryptoError).code).toBe('FALLBACK_KDF_COST_BELOW_DECRYPT_MINIMUM');
    // The production instance, which carries no floor, still reads it.
    expect(cryptoManager.decryptTextSync(V0_CIPHERTEXT, KEY)).toBe(SECRET);
  });
});
