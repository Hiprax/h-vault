/**
 * The search hash, under its own subkey of the vault key.
 *
 * An item's `searchHash` used to be HMAC-SHA256 keyed with the raw vault key,
 * exported on every item write to do it: one key doing AES-GCM and HMAC at once,
 * and its bytes on the JavaScript heap once per save. It is now keyed with
 * `HKDF-SHA256(ikm = vault key, salt = empty, info = "hvault/item/search/v1")`,
 * derived once per vault key into a non-extractable HMAC key.
 *
 * The vectors below were computed OUTSIDE this code (Node's `hkdfSync` and
 * `createHmac` over key bytes 0x40..0x5f), so a change to the label, the salt, the
 * normalisation or the key size is a visible edit here rather than every stored
 * hash quietly changing meaning.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cryptoService } from '../src/services/crypto/cryptoService';

const KEY_BYTES = Uint8Array.from({ length: 32 }, (_, i) => 0x40 + i);

async function vaultKey(): Promise<CryptoKey> {
  return cryptoService.importVaultKey(KEY_BYTES.slice().buffer);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('generateSearchHash', () => {
  it.each([
    ['Bank', '1cbabaf6fdf238d16ef57788d88732b07ad9d399cb78852550e990d799bfb60e'],
    ['  My Login  ', 'd51d4ed8d790ef181f0ce9aee5fea75106f48af3ce709ad2b5b530bee7cb0c4e'],
    ['GitHub', '85b6756fbe4ffbe60cbab4656b1307eb8854857372fe4a838d30c8500b0e28e5'],
  ])('hashes %j to the committed HKDF-subkey vector', async (name, expected) => {
    expect(await cryptoService.generateSearchHash(name, await vaultKey())).toBe(expected);
  });

  it('is no longer the HMAC under the raw vault key', async () => {
    // The raw-key vector for "Bank", computed the same independent way. Equality
    // would mean the subkey is not being used at all.
    expect(await cryptoService.generateSearchHash('Bank', await vaultKey())).not.toBe(
      'efcea17f2e6ea7bdaf5e793c2e4d3e8f715664baea375ef5e5f0c345c8d507a2',
    );
  });

  it('exports the vault key once per key, however many names it hashes', async () => {
    const key = await vaultKey();
    const exportKey = vi.spyOn(crypto.subtle, 'exportKey');

    await Promise.all([
      cryptoService.generateSearchHash('a', key),
      cryptoService.generateSearchHash('b', key),
    ]);
    await cryptoService.generateSearchHash('c', key);

    // Concurrent first calls share one derivation, and later calls reuse it.
    expect(exportKey).toHaveBeenCalledTimes(1);
    // A different vault key (a rotation) gets its own subkey.
    await cryptoService.generateSearchHash('a', await vaultKey());
    expect(exportKey).toHaveBeenCalledTimes(2);
  });

  it('derives a NON-extractable HMAC key, so the subkey never exists as readable bytes', async () => {
    const deriveKey = vi.spyOn(crypto.subtle, 'deriveKey');

    await cryptoService.generateSearchHash('x', await vaultKey());

    expect(deriveKey).toHaveBeenCalledTimes(1);
    const [algorithm, , derivedType, extractable, usages] = deriveKey.mock.calls[0]!;
    expect(algorithm).toMatchObject({ name: 'HKDF', hash: 'SHA-256' });
    const { info } = algorithm as HkdfParams;
    expect(new TextDecoder().decode(info as Uint8Array)).toBe('hvault/item/search/v1');
    expect(derivedType).toEqual({ name: 'HMAC', hash: 'SHA-256', length: 256 });
    expect(extractable).toBe(false);
    expect(usages).toEqual(['sign']);
    const derived = await deriveKey.mock.results[0]!.value;
    await expect(crypto.subtle.exportKey('raw', derived as CryptoKey)).rejects.toThrow();
  });

  it('zeroes the raw copy it exported for the derivation', async () => {
    const clearKey = vi.spyOn(cryptoService, 'clearKey');
    await cryptoService.generateSearchHash('x', await vaultKey());
    expect(clearKey).toHaveBeenCalledTimes(1);
    expect(new Uint8Array(clearKey.mock.calls[0]![0])).toEqual(new Uint8Array(32));
  });

  it('forgets a failed derivation, so the next hash retries rather than failing for ever', async () => {
    const key = await vaultKey();
    const exportKey = vi
      .spyOn(crypto.subtle, 'exportKey')
      .mockRejectedValueOnce(new DOMException('transient', 'OperationError'));

    await expect(cryptoService.generateSearchHash('Bank', key)).rejects.toThrow('transient');
    expect(await cryptoService.generateSearchHash('Bank', key)).toBe(
      '1cbabaf6fdf238d16ef57788d88732b07ad9d399cb78852550e990d799bfb60e',
    );
    expect(exportKey).toHaveBeenCalledTimes(2);
  });
});
