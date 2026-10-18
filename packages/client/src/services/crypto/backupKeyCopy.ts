/**
 * The backup wrapping key (BWK), and the copy of a vault key sealed under it.
 *
 * An account with encrypted backups stores, beside its master-key wrapper, a BWK
 * sealed under a key derived from the backup password, and a copy of a vault key
 * sealed under that BWK (`settings.backup.bwkEncryptedVaultKey`). A master password
 * reset replaces the vault key and leaves this copy alone, so after a reset it may be
 * the only copy of the PREVIOUS key: the one that still opens every entry the reset
 * left unreadable. Recovery opens it here, with the backup password, and only ever
 * the ACCOUNT's copy (a backup file carries its own BWK, and the two have different
 * jobs: see `BackupSettingsPage`'s restore).
 */
import type { IBackupSettings } from '@hvault/shared';
import { cryptoService } from './cryptoService';

/**
 * The four fields that make a backup-wrapping-key wrapper usable.
 *
 * The same shape arrives from two places (the account's `settings.backup` and the
 * `backupEncryption` block inside a backup file), so the completeness test lives
 * here once rather than at each call site, where copies drift apart.
 */
export interface BwkWrapper {
  encryptedBWK: string;
  bwkIv: string;
  bwkTag: string;
  bwkSalt: string;
}

export function completeBwkWrapper(block: Partial<BwkWrapper> | undefined): BwkWrapper | null {
  if (!block?.encryptedBWK || !block.bwkIv || !block.bwkTag || !block.bwkSalt) return null;
  return {
    encryptedBWK: block.encryptedBWK,
    bwkIv: block.bwkIv,
    bwkTag: block.bwkTag,
    bwkSalt: block.bwkSalt,
  };
}

/** Whether two wrappers name the same key, so it is derived once and not twice. */
export function sameBwkWrapper(a: BwkWrapper, b: BwkWrapper): boolean {
  return (
    a.encryptedBWK === b.encryptedBWK &&
    a.bwkIv === b.bwkIv &&
    a.bwkTag === b.bwkTag &&
    a.bwkSalt === b.bwkSalt
  );
}

/**
 * Unwrap one backup wrapping key, or `null` when this password does not open THIS
 * wrapper.
 *
 * `null` rather than a throw, because a caller may try more than one wrapper and a
 * password that opens none is the only thing that means "incorrect backup
 * password". A failure to DERIVE, by contrast, still propagates: that is Web Crypto
 * refusing, or a hostile file's unparseable salt, and reporting either as a wrong
 * password would be a lie.
 *
 * The salt and the derived key are zeroed here on every exit; the unwrapped key
 * belongs to the caller, which zeroes it in its own `finally`.
 */
export async function unwrapBwk(
  wrapper: BwkWrapper,
  password: string,
): Promise<ArrayBuffer | null> {
  const salt = cryptoService.base64ToArrayBuffer(wrapper.bwkSalt);
  let bek: CryptoKey | undefined;
  try {
    bek = await cryptoService.deriveBEK(password, salt);
    try {
      return await cryptoService.decryptBWK(
        wrapper.encryptedBWK,
        wrapper.bwkIv,
        wrapper.bwkTag,
        bek,
      );
    } catch {
      return null;
    }
  } finally {
    cryptoService.clearKey(salt);
    if (bek) await cryptoService.clearCryptoKey(bek);
  }
}

/** Whether the account stores a complete copy of a vault key under its BWK. */
export function hasBackupKeyCopy(backup: IBackupSettings | undefined): boolean {
  return (
    completeBwkWrapper(backup) !== null &&
    Boolean(backup?.bwkEncryptedVaultKey) &&
    Boolean(backup?.bwkVaultKeyIv) &&
    Boolean(backup?.bwkVaultKeyTag)
  );
}

/** What opening the account's backup copy of a vault key came to. */
export type BackupKeyCopyOutcome =
  | { kind: 'opened'; key: CryptoKey }
  | { kind: 'absent' | 'wrong-password' | 'unopenable' | 'same-as-live' };

/**
 * Opens the vault key the account's backup holds a copy of, with the backup
 * password, as a key DIFFERENT from `liveKey`, or says why not:
 *
 * - `absent`: no complete copy is stored (when a BWK is stored, only once the password
 *   has been proved to open it);
 * - `wrong-password`: the password does not open the account's BWK, copy or not;
 * - `unopenable`: the BWK opens but the copy does not (damaged or replaced);
 * - `same-as-live`: the copy is the key the account already uses, so it can open
 *   nothing the live key cannot.
 *
 * The comparison is constant-time and runs on the raw bytes BEFORE any key is
 * imported; the raw BWK and the raw copy are zeroed on every way out. The caller
 * owns the key it gets back.
 */
export async function openBackupKeyCopy(
  backup: IBackupSettings | undefined,
  password: string,
  liveKey: CryptoKey,
): Promise<BackupKeyCopyOutcome> {
  const wrapper = completeBwkWrapper(backup);
  const sealed =
    backup?.bwkEncryptedVaultKey && backup.bwkVaultKeyIv && backup.bwkVaultKeyTag
      ? {
          encrypted: backup.bwkEncryptedVaultKey,
          iv: backup.bwkVaultKeyIv,
          tag: backup.bwkVaultKeyTag,
        }
      : null;
  if (wrapper === null) return { kind: 'absent' };

  // The password is judged even when no copy is stored: a caller about to re-wrap
  // with it must learn now that it is wrong, not after it has committed.
  const rawBwk = await unwrapBwk(wrapper, password);
  if (rawBwk === null) return { kind: 'wrong-password' };
  if (sealed === null) {
    cryptoService.clearKey(rawBwk);
    return { kind: 'absent' };
  }
  let rawCopy: ArrayBuffer;
  try {
    rawCopy = await cryptoService.decryptVaultKeyWithBWK(
      sealed.encrypted,
      sealed.iv,
      sealed.tag,
      rawBwk,
    );
  } catch {
    return { kind: 'unopenable' };
  } finally {
    cryptoService.clearKey(rawBwk);
  }
  try {
    if (await cryptoService.vaultKeyEqualsRaw(liveKey, rawCopy)) return { kind: 'same-as-live' };
    return { kind: 'opened', key: await cryptoService.importVaultKey(rawCopy) };
  } finally {
    cryptoService.clearKey(rawCopy);
  }
}
