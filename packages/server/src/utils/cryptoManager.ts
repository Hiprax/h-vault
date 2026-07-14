import { CryptoManager } from '@hiprax/crypto';

/**
 * CryptoManager subclass that bypasses the user-password complexity check.
 *
 * The `twoFactorEncryptionKey` is a server-side configuration secret, not a
 * user-facing password, so the default CryptoManager complexity rules
 * (uppercase, lowercase, digit, special char) are inappropriate for it.
 * Overriding `validatePassword` to always return `true` is the type-safe way to
 * opt out: `encryptTextSync` calls `this.validatePassword(finalPassword)`
 * internally (the sync decrypt path does not), and the constructor's
 * `skipPasswordValidation` option only guards the optional `defaultPassphrase` —
 * not the per-call key — so a subclass override is required rather than that flag.
 *
 * `legacyMode` is left at its default (`'auto'`), so 2FA secrets encrypted by
 * earlier releases (pre-1.0 v0 wire format) remain decryptable.
 */
export class ValidationBypassCryptoManager extends CryptoManager {
  public override validatePassword(_password: string): boolean {
    return true;
  }
}

/**
 * Shared CryptoManager instance used across controllers for 2FA TOTP-secret
 * encryption/decryption. A single instance keeps the bypass behavior consistent
 * everywhere it is consumed.
 */
export const cryptoManager = new ValidationBypassCryptoManager();
