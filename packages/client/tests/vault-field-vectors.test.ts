/**
 * The committed known-answer vectors for vault-field ciphertext format v2.
 *
 * Every other suite proves the binding is self-consistent, or consistent with a
 * restatement of the format. Neither can pin a format: rename a role, reorder the
 * item type and the row id, or change the separator, and a self-consistent
 * implementation keeps passing while every bound field already stored stops
 * opening. The server holds only ciphertext, so nothing could ever re-frame it.
 *
 * So these values are FROZEN, exactly like `document-crypto-vectors.test.ts`. They
 * were computed from the written format (the comment above
 * `VAULT_FIELD_AAD_PREFIX` in `@hvault/shared`) by a standalone script that
 * shares no code with the module under test, then reproduced by it. They may only
 * change alongside a new version label inside `VAULT_FIELD_AAD_PREFIX` and a path
 * that can still read this one. A red test here is never something to re-record.
 *
 * What they pin:
 *   - the exact additional-data bytes of each of the four roles, including the
 *     prefix, every separator, and where the item type sits for `item.data`;
 *   - that the marker is on the IV and the IV under it is the plain 12 bytes;
 *   - that the ciphertext is the v1 layout (tag in its own field, 16 bytes), so
 *     the binding lives in the tag and nowhere else: under one key and IV a v1
 *     and a v2 seal of the same plaintext share their ciphertext bytes exactly.
 */
import { describe, expect, it } from 'vitest';
import { VAULT_FIELD_ROLES } from '@hvault/shared';
import {
  decryptVaultField,
  vaultFieldAad,
  type VaultFieldBinding,
} from '../src/services/crypto/vaultField';
import { AEAD_REFUSAL, expectRefusal, fromHex, toBase64 } from './documentCryptoHarness';

/** The vault key of every vector: bytes 0x40..0x5f. */
const VECTOR_KEY_BYTES = fromHex(
  '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
);
/** The IV of every vector: bytes 0x20..0x2b. Shared on purpose; see the header. */
const VECTOR_IV = 'ICEiIyQlJicoKSor';

const ITEM_ID = '66c0f1a2b3c4d5e6f7a8b9c0';
const FOLDER_ID = '66c0f1a2b3c4d5e6f7a8b9c1';

interface Vector {
  binding: VaultFieldBinding;
  aadHex: string;
  plaintext: string;
  encrypted: string;
  tag: string;
}

const VECTORS: readonly Vector[] = [
  {
    binding: { role: 'item.name', rowId: ITEM_ID },
    // "hvault/vault-field/v2|item.name|66c0f1a2b3c4d5e6f7a8b9c0"
    aadHex:
      '687661756c742f7661756c742d6669656c642f76327c6974656d2e6e616d657c363663306631613262336334643565366637613862396330',
    plaintext: 'Bank',
    encrypted: 'd4qtiw==',
    tag: 'jMLhDsKXUGcpzaGZR02fRg==',
  },
  {
    binding: { role: 'item.data', rowId: ITEM_ID, itemType: 'login' },
    // "hvault/vault-field/v2|item.data|login|66c0f1a2b3c4d5e6f7a8b9c0"
    aadHex:
      '687661756c742f7661756c742d6669656c642f76327c6974656d2e646174617c6c6f67696e7c363663306631613262336334643565366637613862396330',
    plaintext: '{"username":"alice","password":"hunter2"}',
    encrypted: 'Tsm2k3oGPngZUB7WHBUy+vDDzmRjBGLK8h+RWsWc8vc0T1LzUvzv4cE=',
    tag: 'AFNkCS+X/VgZozlwOIDZ0Q==',
  },
  {
    binding: { role: 'item.password-history', rowId: ITEM_ID },
    // "hvault/vault-field/v2|item.password-history|66c0f1a2b3c4d5e6f7a8b9c0"
    aadHex:
      '687661756c742f7661756c742d6669656c642f76327c6974656d2e70617373776f72642d686973746f72797c363663306631613262336334643565366637613862396330',
    plaintext: 'old-password',
    encrypted: 'WoenzW8VI2oDWk6I',
    tag: 'mJrGhL3M5zRpjS8FokqP9w==',
  },
  {
    binding: { role: 'folder.name', rowId: FOLDER_ID },
    // "hvault/vault-field/v2|folder.name|66c0f1a2b3c4d5e6f7a8b9c1"
    aadHex:
      '687661756c742f7661756c742d6669656c642f76327c666f6c6465722e6e616d657c363663306631613262336334643565366637613862396331',
    plaintext: 'Finance',
    encrypted: 'c4KtgXEXNQ==',
    tag: '8KA66eg8U27LuaeU7AetCA==',
  },
];

/** The FORMAT-V1 seal of the first vector's plaintext under the same key and IV. */
const V1_BANK = { encrypted: 'd4qtiw==', tag: '6D01q9HKRd1lFnTMaW4jdQ==' };

function vectorKey(): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey('raw', VECTOR_KEY_BYTES, 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ]);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function stored(vector: Vector) {
  return { encrypted: vector.encrypted, iv: `v2:${VECTOR_IV}`, tag: vector.tag };
}

describe('the committed vault-field v2 vectors', () => {
  it('covers every role exactly once', () => {
    // Against the shared list, so a role added there without a vector fails here.
    expect(VECTORS.map((v) => v.binding.role)).toEqual([...VAULT_FIELD_ROLES]);
  });

  it.each(VECTORS.map((v) => [v.binding.role, v] as const))(
    'builds the committed additional data for %s',
    (_role, vector) => {
      expect(toHex(vaultFieldAad(vector.binding))).toBe(vector.aadHex);
    },
  );

  it.each(VECTORS.map((v) => [v.binding.role, v] as const))(
    'opens the committed %s triple to its exact plaintext',
    async (_role, vector) => {
      expect(await decryptVaultField(stored(vector), vector.binding, await vectorKey())).toBe(
        vector.plaintext,
      );
    },
  );

  it.each(VECTORS.map((v) => [v.binding.role, v] as const))(
    'seals %s to the committed ciphertext and tag under the helper’s additional data',
    async (_role, vector) => {
      // The seal direction, driven through SubtleCrypto with the helper's bytes:
      // this is the half Phase-26's writer must reproduce, pinned before it exists.
      const sealed = new Uint8Array(
        await globalThis.crypto.subtle.encrypt(
          {
            name: 'AES-GCM',
            iv: fromHex('202122232425262728292a2b'),
            additionalData: vaultFieldAad(vector.binding),
            tagLength: 128,
          },
          await vectorKey(),
          new TextEncoder().encode(vector.plaintext),
        ),
      );
      expect(toBase64(sealed.slice(0, -16))).toBe(vector.encrypted);
      expect(toBase64(sealed.slice(-16))).toBe(vector.tag);
    },
  );

  it('carries the binding in the tag alone: the v1 seal shares the ciphertext bytes', async () => {
    const [bankName] = VECTORS;
    // The committed v1 triple is what a v1 seal produces today, with no additional
    // data at all, so this pins the v1 call shape as well as the vector.
    const v1Sealed = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: fromHex('202122232425262728292a2b'), tagLength: 128 },
        await vectorKey(),
        new TextEncoder().encode(bankName!.plaintext),
      ),
    );
    expect(toBase64(v1Sealed.slice(0, -16))).toBe(V1_BANK.encrypted);
    expect(toBase64(v1Sealed.slice(-16))).toBe(V1_BANK.tag);
    expect(V1_BANK.encrypted).toBe(bankName!.encrypted);
    expect(V1_BANK.tag).not.toBe(bankName!.tag);
    // And the v1 triple opens as v1, i.e. with no marker on its IV.
    expect(
      await decryptVaultField(
        { ...V1_BANK, iv: VECTOR_IV },
        { role: 'item.name', rowId: ITEM_ID },
        await vectorKey(),
      ),
    ).toBe('Bank');
  });

  it('refuses the v1 triple once a marker claims it is bound', async () => {
    const key = await vectorKey();
    await expectRefusal(
      () =>
        decryptVaultField(
          { ...V1_BANK, iv: `v2:${VECTOR_IV}` },
          { role: 'item.name', rowId: ITEM_ID },
          key,
        ),
      AEAD_REFUSAL,
    );
  });

  it.each<[string, VaultFieldBinding]>([
    ['another row', { role: 'item.data', rowId: FOLDER_ID, itemType: 'login' }],
    ['another item type', { role: 'item.data', rowId: ITEM_ID, itemType: 'note' }],
    ['the name slot', { role: 'item.name', rowId: ITEM_ID }],
    ['the history slot', { role: 'item.password-history', rowId: ITEM_ID }],
  ])('refuses the committed item.data triple read as %s', async (_label, binding) => {
    const key = await vectorKey();
    await expectRefusal(() => decryptVaultField(stored(VECTORS[1]!), binding, key), AEAD_REFUSAL);
  });
});
