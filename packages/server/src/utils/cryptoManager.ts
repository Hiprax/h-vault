import { CryptoManager } from '@hiprax/crypto';

/**
 * PBKDF2 iteration count for every 2FA secret this server WRITES.
 *
 * The library's default is 600,000, the OWASP figure for a USER PASSWORD, and
 * `encryptTextSync`/`decryptTextSync` run it through `crypto.pbkdf2Sync` on the
 * event loop: measured at ~300 ms per call with the loop fully blocked, and
 * `login2fa` decrypts before it checks the code, so every wrong code bought a
 * third of a second of a stalled worker. The key here is not a password. It is
 * `TWO_FACTOR_ENCRYPTION_KEY` (or `SESSION_SECRET`), a configuration secret the
 * config schema holds to at least 32 characters and the deployment guide says to
 * generate randomly, so a large work factor protects nothing an attacker could
 * guess. 10,000 costs ~5 ms, is ten times NIST SP 800-132's floor, and keeps a
 * margin should an operator choose a weaker secret than advised.
 *
 * READING IS UNAFFECTED, which is what makes lowering this safe. A v1 ciphertext
 * carries its own count in its header and decrypts at that count, so every
 * secret stored at 600,000 keeps decrypting (and keeps costing 600,000 until the
 * user next enrols); a pre-1.0 v0 ciphertext has no header and decrypts at
 * `legacyPbkdf2Iterations`, which is left at the library default for exactly
 * that reason.
 *
 * Two things NOT to do in its place. Do not switch to the async
 * `encryptText`/`decryptText`: those are the Argon2id lineage, each decrypt path
 * asserts the KDF id it expects, and under the default `legacyMode: 'auto'` the
 * resulting mismatch is swallowed by the v0 retry and surfaces as a generic
 * `DECRYPTION_FAILED`, so every stored 2FA secret would become unreadable with
 * an error that looks like a wrong key. And never configure a
 * `decryptKdfLimits` minimum on this manager. `minPbkdf2Iterations` is the one
 * that binds this PBKDF2 path (`minWork` is Argon2id-only and inert here today,
 * and is banned anyway so the rule stays one rule): above this count it refuses
 * every secret written with it, and since 1.9.0 it also binds headerless v0
 * input, which decrypts at `legacyPbkdf2Iterations` (100,000), so a floor above
 * that locks out every account still holding a v0 secret. Raising `legacyPbkdf2Iterations` to meet
 * the floor does not rescue them: it changes the derived key, and the v0 row
 * then fails its tag instead. `crypto-manager.test.ts` pins both floors at 0.
 */
export const TWO_FACTOR_SECRET_PBKDF2_ITERATIONS = 10_000;

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
 * encryption/decryption. A single instance keeps the bypass behavior, and the
 * write-side iteration count, consistent everywhere it is consumed. Only
 * `pbkdf2Iterations` is set: see `TWO_FACTOR_SECRET_PBKDF2_ITERATIONS` for why
 * nothing else may be.
 */
export const cryptoManager = new ValidationBypassCryptoManager({
  pbkdf2Iterations: TWO_FACTOR_SECRET_PBKDF2_ITERATIONS,
});
