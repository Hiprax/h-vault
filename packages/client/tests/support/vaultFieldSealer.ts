/**
 * A format-v2 vault-field SEALER, for tests only.
 *
 * Nothing in the application writes format v2 yet: this release reads it and
 * keeps writing v1, so that a vault can be read by the build that will later
 * start writing it. The suites that prove the read path therefore need a way to
 * produce a bound field, and this is it.
 *
 * It restates the format from its WRITTEN specification (the comment above
 * `VAULT_FIELD_AAD_PREFIX` in `@hvault/shared`) with string literals, and it
 * deliberately does not call `vaultFieldAad`. A sealer built on the module under
 * test would agree with that module by construction, so a wrong separator, a
 * missing item type or a swapped id would round-trip happily and every test here
 * would stay green over a format nothing else can read. The committed vector file
 * pins the same bytes from a third, standalone derivation.
 */
import type { ItemType } from '@hvault/shared';

/** The four fields a binding can name, spelled as the format spells them. */
type SealedRole = 'item.name' | 'item.data' | 'item.password-history' | 'folder.name';

/** The additional-data string, written out from the specification. */
export function specAad(role: SealedRole, rowId: string, itemType?: ItemType): string {
  if (role === 'item.data') {
    if (itemType === undefined) throw new Error('item.data is bound to an item type');
    return `hvault/vault-field/v2|item.data|${itemType}|${rowId}`;
  }
  return `hvault/vault-field/v2|${role}|${rowId}`;
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** A stored triple, exactly as a server would hand it back. */
export interface StoredTriple {
  encrypted: string;
  iv: string;
  tag: string;
}

/**
 * Seal `plaintext` as a v2 field under `key`, bound to `aad`.
 *
 * `aad` is a raw string so a test can seal under a binding that is WRONG on
 * purpose, which is how the relocation cases build a row that looks stored.
 */
export async function sealV2(
  key: CryptoKey,
  plaintext: string,
  aad: string,
): Promise<StoredTriple> {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const sealed = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(aad), tagLength: 128 },
      key,
      new TextEncoder().encode(plaintext),
    ),
  );
  return {
    encrypted: toBase64(sealed.slice(0, -16)),
    iv: `v2:${toBase64(iv)}`,
    tag: toBase64(sealed.slice(-16)),
  };
}

/** A fresh AES-256-GCM key, extractable like the real vault key. */
export async function freshVaultKey(): Promise<CryptoKey> {
  return globalThis.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
}
