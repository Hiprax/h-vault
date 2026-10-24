/**
 * The full backup's integrity signature.
 *
 * HMAC-SHA256 over the manifest's canonical JSON, under a key derived from the
 * backup wrapping key (BWK) with HKDF and a label of its own,
 * `hvault-full-backup-hmac-v1`. The label is not the vault backup's
 * (`hvault-backup-hmac-v1`, `cryptoService.computeBackupHmac`), so a vault backup's
 * signature can never verify a full backup's manifest, nor the other way round; and
 * there is NO fallback to the raw BWK, because this format never had one.
 *
 * The key is derived straight into a non-extractable HMAC key, so the subkey's bytes
 * never exist in script memory. Lives outside `cryptoService` on purpose: that
 * module is in the initial payload, which has no room, and only the lazily loaded
 * full-backup code uses this.
 */

const FULL_BACKUP_HMAC_INFO = 'hvault-full-backup-hmac-v1';

/** A signature as the manifest carries it: 32 bytes, lower-case hex. */
const SIGNATURE_PATTERN = /^[0-9a-f]{64}$/;

/** The HMAC key for one use, derived from the raw BWK. */
async function deriveMacKey(bwk: ArrayBuffer, usage: 'sign' | 'verify'): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', bwk, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(FULL_BACKUP_HMAC_INFO),
    },
    base,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    [usage],
  );
}

/**
 * The signing key, derived once at the start of a full backup so the raw BWK can be
 * zeroed at once rather than held for the whole run.
 */
export function deriveFullBackupSigningKey(bwk: ArrayBuffer): Promise<CryptoKey> {
  return deriveMacKey(bwk, 'sign');
}

/** Sign `canonicalJson`, answering the lower-case hex signature. */
export async function signFullBackupManifest(
  canonicalJson: string,
  key: CryptoKey,
): Promise<string> {
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(canonicalJson));
  return Array.from(new Uint8Array(signature), (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}

/**
 * Whether `signature` is this BWK's signature over `canonicalJson`.
 *
 * The shape `resolveBackupSignature` injects. A malformed signature is a plain
 * `false`, never a throw; the comparison is SubtleCrypto's, in constant time.
 */
export async function verifyFullBackupManifest(
  canonicalJson: string,
  signature: string,
  bwk: ArrayBuffer,
): Promise<boolean> {
  if (!SIGNATURE_PATTERN.test(signature)) return false;
  const bytes = Uint8Array.from({ length: 32 }, (_, index) =>
    parseInt(signature.slice(index * 2, index * 2 + 2), 16),
  );
  return crypto.subtle.verify(
    'HMAC',
    await deriveMacKey(bwk, 'verify'),
    bytes,
    new TextEncoder().encode(canonicalJson),
  );
}
