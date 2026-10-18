import { cryptoService } from '../services/crypto/cryptoService';
import { holdsAccountVaultKey, type WrappedVaultKey } from '../services/crypto/accountVaultKey';

/**
 * The proof of the master password a sensitive request carries: the auth hash,
 * derived in the browser from the password and the account's address (the salt).
 * The auth key is zeroed once the hash is taken (never before: the hash is read
 * from those bytes), and the master-encryption key is released; it is
 * non-extractable, so `clearCryptoKey` has no raw copy of it to zero. The one place a settings
 * card turns a typed master password into that proof; the password itself never
 * leaves the browser.
 */
export async function proveMasterPassword(password: string, email: string): Promise<string> {
  const { masterEncryptionKey, authKey } = await cryptoService.deriveKeys(password, email);
  const authHash = cryptoService.getAuthHash(authKey);
  cryptoService.clearKey(authKey);
  await cryptoService.clearCryptoKey(masterEncryptionKey);
  return authHash;
}

/**
 * {@link proveMasterPassword}, checked in the browser first: the proof only when
 * the key derived from `password` opens `wrapper` onto `heldKey`, the vault key this
 * session holds, and `null` when it does not.
 *
 * A typo is therefore refused here, before any request: it spends none of the
 * account's master-password budget (a few attempts per quarter hour, shared by every
 * re-authenticating request) and does not meet the 401 handler, which would refresh
 * the session and send the same wrong proof a second time. The derived keys are
 * released on every way out.
 */
export async function proveMasterPasswordForHeldKey(
  password: string,
  email: string,
  heldKey: CryptoKey,
  wrapper: WrappedVaultKey,
): Promise<string | null> {
  const { masterEncryptionKey, authKey } = await cryptoService.deriveKeys(password, email);
  try {
    let opens: boolean;
    try {
      opens = await holdsAccountVaultKey(heldKey, wrapper, masterEncryptionKey);
    } catch {
      opens = false;
    }
    return opens ? cryptoService.getAuthHash(authKey) : null;
  } finally {
    cryptoService.clearKey(authKey);
    await cryptoService.clearCryptoKey(masterEncryptionKey);
  }
}
