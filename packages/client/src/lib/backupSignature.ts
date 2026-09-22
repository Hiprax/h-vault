/**
 * Whether a backup file may be restored, and on whose authority.
 *
 * A downloaded backup carries an `integrity` field: an HMAC-SHA256 over the rest
 * of the file, computed under an HKDF subkey of the backup wrapping key (BWK).
 * Restore has always checked it when it was there. Two things made that check
 * weaker than `SECURITY.md` said it was, and this module is the one place the
 * verdict is now decided.
 *
 * 1. **An absent signature used to be a warning notice and nothing else**, so a
 *    file with its `integrity` field simply deleted restored exactly as a signed
 *    one did. A notice the user does not have to answer is not a control.
 * 2. **The key the signature was checked against could come out of the file
 *    itself.** Restore unwraps a BWK before it can verify anything, and it used
 *    to prefer the `backupEncryption` block carried *inside* the file over the
 *    account's own stored wrapper. Anyone handing you a file plus "its" backup
 *    password therefore supplied both the message and the key that authenticates
 *    it, and the verification proved only that the file agreed with itself.
 *
 * So the verdict turns on one fact and one fact only: **which key verified the
 * signature**. A signature that verifies under key material the account already
 * held is evidence. A signature that verifies only under the key the file
 * carried is self-certification. No signature at all is no evidence.
 *
 * It is a pure function on purpose. The restore handler is a 300-line async flow
 * with a dozen exits, and this decision is the one that must be exhaustible: the
 * whole input domain is six combinations, and the test for it enumerates all six
 * rather than sampling the ones the UI happens to produce.
 *
 * The user-facing sentences deliberately live at the call site, keyed on the
 * discriminant, for the reason the offline-cache banner gives: copy read off a
 * message string is copy that drifts, and a verdict is not a sentence.
 */

/**
 * Which unwrapped backup wrapping key a signature was checked against.
 *
 * `'account'` is the account's own `settings.backup` block, which reached the
 * browser over an authenticated session and which the file cannot influence.
 * `'file'` is the `backupEncryption` block carried inside the backup itself —
 * legitimate for a cross-account restore, or for a backup taken before the
 * backup password was changed, and in both of those cases the only way in. It is
 * still key material the file supplied, so a signature checked against it
 * certifies nothing about where the file came from.
 *
 * Both are unwrapped wherever the restore password opens them, because the two
 * jobs downstream want different ones: the signature wants the account's, and
 * the file's own BWK-wrapped vault key can only ever be opened by the file's.
 */
export type BackupHmacKeySource = 'account' | 'file';

/** One unwrapped BWK, and where it came from. */
export interface BackupHmacKey {
  readonly source: BackupHmacKeySource;
  readonly bwk: ArrayBuffer;
}

export interface BackupSignatureFacts {
  /** The file carried an `integrity` field of the expected type. */
  readonly signaturePresent: boolean;
  /**
   * Which available key verified the signature, or `null` when none did — either
   * because none was tried or because every one of them disagreed. Never read
   * when `signaturePresent` is false, which is what stops a caller that forgot to
   * reset a stale value from buying a pass.
   */
  readonly verifiedUnder: BackupHmacKeySource | null;
}

export type BackupSignatureVerdict =
  /** Signed, and verified under key material the file did not supply. */
  | { readonly kind: 'verified' }
  /**
   * A signature is present and no key available here agrees with it. That is
   * either tampering or a file signed under a different backup password than the
   * one entered, and nothing here can tell those two apart — so the call site's
   * wording must not assert the first.
   */
  | { readonly kind: 'refused'; readonly reason: 'signature_mismatch' }
  /**
   * Restorable, but only on an explicit answer from the user.
   * `unsigned` — the file carries no signature at all.
   * `self_signed` — it carries one, and it could only be checked against the key
   * the file itself supplied.
   */
  | { readonly kind: 'unconfirmed'; readonly reason: 'unsigned' | 'self_signed' };

/**
 * The single decision point: may these bytes be restored, and does the user have
 * to say so first?
 *
 * The order of the tests is the invariant. An absent signature is answered before
 * `verifiedUnder` is ever read, and `'account'` is the only value that yields
 * `verified`, so exactly one of the six inputs restores without an answer.
 */
export function classifyBackupSignature(facts: BackupSignatureFacts): BackupSignatureVerdict {
  if (!facts.signaturePresent) return { kind: 'unconfirmed', reason: 'unsigned' };
  if (facts.verifiedUnder === 'account') return { kind: 'verified' };
  if (facts.verifiedUnder === 'file') return { kind: 'unconfirmed', reason: 'self_signed' };
  return { kind: 'refused', reason: 'signature_mismatch' };
}

/**
 * Try the signature against each key in turn, and classify what happened.
 *
 * `keys` is in PREFERENCE ORDER and the caller puts the account's first: the
 * first key that verifies is the one the verdict is built from, so an account key
 * that agrees short-circuits before the file's key is ever consulted. That
 * ordering IS the control, which is why the test asserts it rather than assuming
 * it — a file key tried first would verify a hostile file and report `verified`.
 *
 * The verifier is injected rather than imported so that the ordering and the
 * verdict can be tested as one unit without mocking a crypto module, and so this
 * file stays free of Web Crypto. The real call site passes
 * `cryptoService.verifyBackupHmac`, whose own HKDF-subkey-then-legacy-raw-BWK
 * fallback is orthogonal to this one: it tries two derivations of the SAME BWK,
 * while this tries different BWKs.
 *
 * A verifier that rejects counts as a disagreement for that key and the next key
 * is still tried, because a malformed wrapper must not be able to turn a refusal
 * into an unhandled failure the caller reports as something else entirely.
 */
export async function resolveBackupSignature(
  signature: string | null,
  canonicalJson: string,
  keys: readonly BackupHmacKey[],
  verify: (data: string, hmac: string, bwk: ArrayBuffer) => Promise<boolean>,
): Promise<BackupSignatureVerdict> {
  if (signature === null) {
    return classifyBackupSignature({ signaturePresent: false, verifiedUnder: null });
  }

  for (const key of keys) {
    let agreed = false;
    try {
      agreed = await verify(canonicalJson, signature, key.bwk);
    } catch {
      agreed = false;
    }
    if (agreed) {
      return classifyBackupSignature({ signaturePresent: true, verifiedUnder: key.source });
    }
  }

  return classifyBackupSignature({ signaturePresent: true, verifiedUnder: null });
}
