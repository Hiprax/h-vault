import { cryptoService } from '../services/crypto/cryptoService';

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
