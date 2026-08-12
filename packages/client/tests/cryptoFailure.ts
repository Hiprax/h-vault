/**
 * Shared assertions for the two ways this codebase reports a failed decryption.
 *
 * A bare `rejects.toThrow()` accepts ANY rejection, including a `TypeError`
 * raised by a typo in the test itself, so it cannot distinguish "the ciphertext
 * failed authentication" from "the test called a function that does not exist".
 * These helpers pin the exact failure instead, and they pin the property that
 * matters most about it: every failure mode reports the SAME thing, so nothing
 * in the error tells an attacker WHICH input they got wrong.
 */
import { expect } from 'vitest';

/**
 * The single message `CryptoService.decryptVaultKey` reports for every failure
 * mode. The service catches WebCrypto's `OperationError` and replaces it with
 * this fixed text, so a wrong master password and corrupted stored key material
 * are indistinguishable to the caller.
 */
const VAULT_KEY_DECRYPT_FAILURE =
  'Failed to decrypt vault key. The master password may be incorrect or the vault key data is corrupted.';

/** Await a promise that must reject, and hand back the rejection reason. */
async function rejectionOf(promise: Promise<unknown>, what: string): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error(`expected ${what} to reject, but it resolved`);
    },
    (error: unknown) => error,
  );
}

/**
 * Assert an AES-GCM authentication failure: WebCrypto's spec-defined
 * `OperationError`, surfaced unwrapped. Used for every path that does NOT
 * translate the error — `decryptData`, `decryptBWK`, `decryptVaultKeyWithBWK`
 * and raw `subtle.decrypt` calls.
 */
export async function expectGcmAuthFailure(promise: Promise<unknown>): Promise<DOMException> {
  const rejection = await rejectionOf(promise, 'the decryption');

  // Matched by constructor NAME rather than with `instanceof DOMException`:
  // under jsdom the global `DOMException` is jsdom's own class, while the
  // rejection comes from Node's WebCrypto, so `instanceof` is false there even
  // though both are DOMExceptions. The `name` is the part the spec fixes.
  expect(rejection).toBeInstanceOf(Error);
  const domError = rejection as DOMException;
  expect(domError.constructor.name).toBe('DOMException');
  expect(domError.name).toBe('OperationError');
  return domError;
}

/**
 * Assert the wrapped failure `decryptVaultKey` reports: a plain `Error` (never
 * a `DOMException`) carrying {@link VAULT_KEY_DECRYPT_FAILURE} verbatim.
 */
export async function expectVaultKeyDecryptFailure(promise: Promise<unknown>): Promise<Error> {
  const rejection = await rejectionOf(promise, 'the vault-key decryption');

  expect(rejection).toBeInstanceOf(Error);
  const error = rejection as Error;
  expect(error.name).toBe('Error');
  expect(error.message).toBe(VAULT_KEY_DECRYPT_FAILURE);
  return error;
}
