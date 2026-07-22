import type { ItemType } from '@hvault/shared';
import { firstUri, normalizeHost } from '../services/import/identity';
import { isUndecodableData } from './vaultData';

/**
 * Presentation helpers for a DECRYPTED vault item.
 *
 * A vault list row used to render the item NAME and nothing else, which is
 * exactly why ten imported `accounts.google.com` logins looked identical: an
 * export without a title derives every name from the URL host. The subtitle is
 * the second, distinguishing line — the value that actually tells two rows
 * apart.
 */

/**
 * The masked prefix a card subtitle carries: four U+2022 bullets, the same
 * character `VaultItemDetail` masks a card number with, then the last four
 * digits.
 */
const CARD_MASK = '••••';

/**
 * A card number shorter than this gets no subtitle at all.
 *
 * `number` is the one field a subtitle draws on that the detail view MASKS
 * behind a reveal control, so the list must never show most of it. Four digits
 * or fewer would be shown whole; at five, four of five digits is an 80% reveal.
 * Eight keeps the reveal at half or less, and costs nothing real: a payment card
 * number is 12-19 digits, so every actual card still gets its `•••• 1234`.
 */
const MIN_CARD_DIGITS = 8;

/** The decrypted fields a subtitle is derived from. */
export interface SubtitleItem {
  itemType: ItemType;
  /** Decrypted, schema-transformed item data. */
  data: Record<string, unknown>;
}

/**
 * A short secondary label that distinguishes an item from others with the same
 * name, or `''` when the type has nothing meaningful to show.
 *
 * | Type | Subtitle |
 * | --- | --- |
 * | `login` | the username, else the host of its first URI |
 * | `card` | `•••• <last four digits>` |
 * | `identity` | the full name, else the email address |
 * | `note`, `secret` | none |
 *
 * Two rules are load-bearing:
 *
 * 1. **No secret ever appears here.** A password, CVV, SSN, TOTP seed or secret
 *    value is never part of a subtitle — the list is the one vault surface that
 *    renders many items at once, in front of whoever can see the screen, with
 *    no reveal control to opt into.
 * 2. **An undecodable item gets no subtitle.** When decrypted data fails schema
 *    validation `vaultStore` keeps a placeholder in `data` (see
 *    {@link isUndecodableData}), so any label derived from it would describe the
 *    placeholder rather than the item.
 *
 * The login fallback reuses the importer's `firstUri` + `normalizeHost`, so the
 * host a user reads is the same one the import resolver matches on.
 */
export function getItemSubtitle(item: SubtitleItem): string {
  const { data } = item;
  if (isUndecodableData(data)) return '';

  switch (item.itemType) {
    case 'login':
      return loginSubtitle(data);
    case 'card':
      return cardSubtitle(data);
    case 'identity':
      return identitySubtitle(data);
    case 'note':
    case 'secret':
      return '';
  }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

function loginSubtitle(data: Record<string, unknown>): string {
  const username = trimmedString(data.username);
  if (username) return username;
  // No username to tell accounts apart — fall back to the site itself, which at
  // least separates a login from a same-named item on another host.
  return normalizeHost(firstUri(data));
}

function cardSubtitle(data: Record<string, unknown>): string {
  // Card numbers are commonly stored with spaces or dashes; count digits only so
  // "4111 1111 1111 1111" and "4111111111111111" mask identically.
  const digits = trimmedString(data.number).replace(/\D/g, '');
  if (digits.length < MIN_CARD_DIGITS) return '';
  return `${CARD_MASK} ${digits.slice(-4)}`;
}

function identitySubtitle(data: Record<string, unknown>): string {
  const fullName = [trimmedString(data.firstName), trimmedString(data.lastName)]
    .filter(Boolean)
    .join(' ');
  if (fullName) return fullName;
  return trimmedString(data.email);
}

function trimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}
