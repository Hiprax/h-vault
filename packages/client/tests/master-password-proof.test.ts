/**
 * The master-password proof, checked in the browser before anything is sent.
 *
 * A wrong password must come back as `null` with no proof at all, so the caller
 * sends nothing: the server's master-password budget is a few attempts per quarter
 * hour, shared by every re-authenticating request, and a refused proof also meets
 * the 401 handler, which would replay it. Real key derivation throughout.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { cryptoService } from '../src/services/crypto/cryptoService';
import type { WrappedVaultKey } from '../src/services/crypto/accountVaultKey';
import { proveMasterPassword, proveMasterPasswordForHeldKey } from '../src/lib/masterPasswordProof';

const EMAIL = 'ada@example.com';
const PASSWORD = 'Master-Password-1!';

let heldKey: CryptoKey;
let wrapper: WrappedVaultKey;

beforeAll(async () => {
  heldKey = await cryptoService.importVaultKey(new Uint8Array(32).fill(0x11).buffer);
  const { masterEncryptionKey } = await cryptoService.deriveKeys(PASSWORD, EMAIL);
  wrapper = await cryptoService.encryptVaultKey(heldKey, masterEncryptionKey);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('proveMasterPasswordForHeldKey', () => {
  it('returns the same proof the server checks when the password opens the wrapper onto the held key', async () => {
    const proof = await proveMasterPasswordForHeldKey(PASSWORD, EMAIL, heldKey, wrapper);

    expect(proof).toBe(await proveMasterPassword(PASSWORD, EMAIL));
    expect(proof).toMatch(/\S/);
  });

  it('returns no proof for a wrong password, releasing what it derived', async () => {
    const derive = vi.spyOn(cryptoService, 'deriveKeys');
    const clearCryptoKey = vi.spyOn(cryptoService, 'clearCryptoKey');
    const hash = vi.spyOn(cryptoService, 'getAuthHash');

    expect(await proveMasterPasswordForHeldKey('Not-The-Password', EMAIL, heldKey, wrapper)).toBe(
      null,
    );
    // No proof was even computed for the wrong password…
    expect(hash).not.toHaveBeenCalled();
    // …and both derived keys were released: the auth key's bytes zeroed, the
    // master key handed to `clearCryptoKey`.
    const derived = await (derive.mock.results[0]!.value as ReturnType<typeof derive>);
    expect(new Uint8Array(derived.authKey).every((byte) => byte === 0)).toBe(true);
    expect(clearCryptoKey).toHaveBeenCalledWith(derived.masterEncryptionKey);
  });

  it('returns no proof when the wrapper opens onto a DIFFERENT key than the one held', async () => {
    const other = await cryptoService.importVaultKey(new Uint8Array(32).fill(0x22).buffer);

    expect(await proveMasterPasswordForHeldKey(PASSWORD, EMAIL, other, wrapper)).toBeNull();
  });

  it('releases the derived keys after a proof too, and only once the hash is taken', async () => {
    const order: string[] = [];
    vi.spyOn(cryptoService, 'getAuthHash').mockImplementation(() => {
      order.push('hash');
      return 'proof';
    });
    vi.spyOn(cryptoService, 'clearKey').mockImplementation(() => {
      order.push('clearKey');
    });
    const clearCryptoKey = vi.spyOn(cryptoService, 'clearCryptoKey');

    expect(await proveMasterPasswordForHeldKey(PASSWORD, EMAIL, heldKey, wrapper)).toBe('proof');

    // The auth key is zeroed last: zeroing it first would hash zeros.
    expect(order.at(-1)).toBe('clearKey');
    expect(order.indexOf('hash')).toBeLessThan(order.lastIndexOf('clearKey'));
    expect(clearCryptoKey).toHaveBeenCalledTimes(1);
  });
});
