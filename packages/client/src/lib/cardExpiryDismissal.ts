/**
 * Whether this browser hid the vault page's card expiry reminder, and for WHICH
 * set of cards.
 *
 * Remembered per FINGERPRINT: a hash of the account plus every warned card's id
 * and status. Hiding the reminder for "card A expiring" does not hide it for
 * "card A expired", nor for a second card that starts expiring later, nor for
 * another account signing in on the same browser, because each of those changes
 * the fingerprint and the stored value then simply stops matching.
 *
 * Only the 32-bit hash is stored, never an id, a name or a date: local storage
 * outlives the session and is readable by anything running in the origin, while
 * the vault's contents are meant to exist in clear only in memory. A hash this
 * short cannot be turned back into the ids it was built from, and a collision
 * costs no more than a reminder that stays hidden.
 *
 * A per-browser convenience, exactly like `updateNoticeDismissal.ts`: storage
 * that is blocked or full means the reminder comes back, never an error.
 */
import type { CardExpiryStatus } from './cardExpiry';

const DISMISSED_CARD_EXPIRY_KEY = 'hvault_dismissed_card_expiry';

/** FNV-1a, 32-bit, over the UTF-8 bytes of `text`, as eight lower-case hex digits. */
function fnv1a32(text: string): string {
  let hash = 0x811c9dc5;
  for (const byte of new TextEncoder().encode(text)) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

/**
 * The fingerprint of one account's warned cards. The pairs are SORTED first, so
 * the order the vault happens to list its items in never changes the value.
 */
export function cardExpiryFingerprint(
  userId: string,
  entries: readonly { id: string; status: CardExpiryStatus }[],
): string {
  const pairs = entries.map((entry) => `${entry.id}:${entry.status}`).sort();
  return fnv1a32(`${userId}\n${pairs.join('\n')}`);
}

export function isCardExpiryReminderDismissed(fingerprint: string): boolean {
  try {
    return localStorage.getItem(DISMISSED_CARD_EXPIRY_KEY) === fingerprint;
  } catch {
    return false;
  }
}

export function dismissCardExpiryReminder(fingerprint: string): void {
  try {
    localStorage.setItem(DISMISSED_CARD_EXPIRY_KEY, fingerprint);
  } catch {
    return;
  }
}
