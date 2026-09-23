/**
 * `vaultField`: the binding's validation, and the dual-read dispatch.
 *
 * The committed vectors pin the bytes; the store suite proves the read path
 * refuses relocated fields. This file pins the two things neither of those can
 * see: that a binding refuses every input that would make the layout ambiguous
 * or non-canonical, and that an UNMARKED field goes down the v1 path untouched,
 * never validating a binding it does not need.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ItemType } from '@hvault/shared';
import {
  decryptVaultField,
  isBoundField,
  vaultFieldAad,
  type VaultFieldBinding,
} from '../src/services/crypto/vaultField';
import { cryptoService } from '../src/services/crypto/cryptoService';
import { AEAD_REFUSAL, expectRefusal } from './documentCryptoHarness';
import { freshVaultKey, sealV2, specAad } from './support/vaultFieldSealer';

const ROW = '66c0f1a2b3c4d5e6f7a8b9c0';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('vaultFieldAad', () => {
  it.each<[VaultFieldBinding, string]>([
    [{ role: 'item.name', rowId: ROW }, `hvault/vault-field/v2|item.name|${ROW}`],
    [
      { role: 'item.data', rowId: ROW, itemType: 'card' },
      `hvault/vault-field/v2|item.data|card|${ROW}`,
    ],
    [
      { role: 'item.password-history', rowId: ROW },
      `hvault/vault-field/v2|item.password-history|${ROW}`,
    ],
    [{ role: 'folder.name', rowId: ROW }, `hvault/vault-field/v2|folder.name|${ROW}`],
  ])('spells %o as its specification says', (binding, expected) => {
    expect(new TextDecoder().decode(vaultFieldAad(binding))).toBe(expected);
  });

  it('gives an id in upper case the bytes of the same id in lower case', () => {
    expect(vaultFieldAad({ role: 'item.name', rowId: ROW.toUpperCase() })).toEqual(
      vaultFieldAad({ role: 'item.name', rowId: ROW }),
    );
  });

  it.each([
    ['empty', ''],
    ['23 hex characters (n-1)', ROW.slice(1)],
    ['25 hex characters (n+1)', `${ROW}0`],
    ['a non-hex character', `${ROW.slice(0, 23)}g`],
    ['a separator', `${ROW.slice(0, 23)}|`],
    ['surrounding whitespace', ` ${ROW}`],
  ])('refuses a row id that is %s', (_label, rowId) => {
    for (const role of ['item.name', 'item.password-history', 'folder.name'] as const) {
      expect(() => vaultFieldAad({ role, rowId }), role).toThrow(
        'A vault field is bound to an ObjectId row id',
      );
    }
    expect(() => vaultFieldAad({ role: 'item.data', rowId, itemType: 'login' })).toThrow(
      'A vault field is bound to an ObjectId row id',
    );
  });

  it.each(['', 'Login', 'login|x', 'toString'])('refuses the item type %j', (itemType) => {
    expect(() =>
      vaultFieldAad({ role: 'item.data', rowId: ROW, itemType: itemType as ItemType }),
    ).toThrow('A vault item’s data is bound to a known item type');
  });
});

describe('isBoundField', () => {
  it.each([
    ['a marked IV', 'v2:ICEiIyQlJicoKSor', true],
    ['a v1 IV', 'ICEiIyQlJicoKSor', false],
    ['the marker after whitespace', ' v2:ICEiIyQlJicoKSor', false],
    ['the marker in upper case', 'V2:ICEiIyQlJicoKSor', false],
    ['the marker without its colon', 'v2ICEiIyQlJicoKSor', false],
    ['an empty string', '', false],
  ])('reads %s as %s', (_label, iv, expected) => {
    expect(isBoundField(iv)).toBe(expected);
  });
});

describe('decryptVaultField', () => {
  it('opens an unmarked field through decryptData with exactly the v1 arguments', async () => {
    const key = await freshVaultKey();
    const v1 = await cryptoService.encryptData('legacy', key);
    const decryptData = vi.spyOn(cryptoService, 'decryptData');
    const decryptDataWithAad = vi.spyOn(cryptoService, 'decryptDataWithAad');

    // A binding no v2 field could use: an unmarked field must not examine it.
    const opened = await decryptVaultField(
      v1,
      { role: 'item.name', rowId: 'not an id at all' },
      key,
    );

    expect(opened).toBe('legacy');
    expect(decryptData).toHaveBeenCalledTimes(1);
    expect(decryptData.mock.calls[0]).toEqual([v1.encrypted, v1.iv, v1.tag, key]);
    expect(decryptDataWithAad).not.toHaveBeenCalled();
  });

  it('opens a marked field with the helper’s additional data and never the v1 path', async () => {
    const key = await freshVaultKey();
    const sealed = await sealV2(key, 'bound', specAad('item.name', ROW));
    const decryptData = vi.spyOn(cryptoService, 'decryptData');
    const decryptDataWithAad = vi.spyOn(cryptoService, 'decryptDataWithAad');

    expect(await decryptVaultField(sealed, { role: 'item.name', rowId: ROW }, key)).toBe('bound');

    expect(decryptData).not.toHaveBeenCalled();
    expect(decryptDataWithAad).toHaveBeenCalledTimes(1);
    const [encrypted, iv, tag, passedKey, aad] = decryptDataWithAad.mock.calls[0]!;
    expect([encrypted, iv, tag]).toEqual([sealed.encrypted, sealed.iv.slice(3), sealed.tag]);
    expect(passedKey).toBe(key);
    expect(new TextDecoder().decode(aad)).toBe(specAad('item.name', ROW));
  });

  it('rejects, rather than throwing synchronously, when a marked field’s binding is invalid', async () => {
    const key = await freshVaultKey();
    const sealed = await sealV2(key, 'bound', specAad('item.name', ROW));
    const decryptDataWithAad = vi.spyOn(cryptoService, 'decryptDataWithAad');

    // A promise that rejects is what every caller's per-row handling catches.
    const pending = decryptVaultField(sealed, { role: 'item.name', rowId: 'bad' }, key);
    await expect(pending).rejects.toThrow('A vault field is bound to an ObjectId row id');
    expect(decryptDataWithAad).not.toHaveBeenCalled();
  });

  it('refuses a bound field with its marker removed, by authentication, not by parsing', async () => {
    const key = await freshVaultKey();
    const sealed = await sealV2(key, 'bound', specAad('item.name', ROW));

    await expectRefusal(
      () =>
        decryptVaultField(
          { ...sealed, iv: sealed.iv.slice(3) },
          { role: 'item.name', rowId: ROW },
          key,
        ),
      AEAD_REFUSAL,
    );
  });

  it('refuses a bound field under another key, as v1 does', async () => {
    const sealed = await sealV2(await freshVaultKey(), 'bound', specAad('item.name', ROW));
    const otherKey = await freshVaultKey();

    await expectRefusal(
      () => decryptVaultField(sealed, { role: 'item.name', rowId: ROW }, otherKey),
      AEAD_REFUSAL,
    );
  });
});
