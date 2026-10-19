/**
 * Card expiry: the ONE definition of when a stored payment card stops being
 * valid, and of every sentence the app says about it.
 *
 * Evaluated only in the browser, from the decrypted `expMonth`/`expYear`. The
 * server never learns an expiry date, so no reminder can be mailed and nothing
 * here may ever be sent anywhere: it reads two strings and the local clock.
 *
 * ## The rule
 *
 * A card is valid THROUGH the last day of its expiry month, in local time (a
 * card printed `03/24` is still good on 31 March 2024 and refused on 1 April).
 * It is "expiring" when 60 days or fewer remain, the same two-month window
 * 1Password's Watchtower uses, and "expired" from the first day after its month.
 *
 * ## What is read, and what is refused
 *
 * Stored values come from the item form, from every import format and from old
 * saves, so the reader is lenient about SHAPE and strict about MEANING: a month
 * is `1`-`12` with or without one leading zero, a year is four digits, or two
 * digits meaning `20YY`. Anything else (empty, `00`, `13`, a three-digit year,
 * stray characters) is "no expiry known" (`null`), never a guess, so a card with
 * a junk value is simply not warned about rather than warned about wrongly.
 *
 * ## Why day differences are rounded
 *
 * Both ends of a difference are LOCAL midnights, and a local day is 23 or 25
 * hours long across a daylight-saving change. Dividing by 24 hours and
 * truncating would make a card due in 10 days read as due in 9 for the week
 * after the clocks go forward; rounding absorbs the hour exactly, because the
 * error is never more than one hour in 24.
 *
 * ## Why the month names are a static array
 *
 * The sentences are tested as exact strings, and `Intl.DateTimeFormat` output
 * depends on the runtime's ICU data and locale. English month names from a fixed
 * table make every sentence the same on every machine, and the app's copy is
 * English throughout.
 */

import { isUndecodableData } from './vaultData';

/** How many days ahead a card counts as expiring soon (two months, inclusive). */
export const CARD_EXPIRY_SOON_DAYS = 60;

export type CardExpiryStatus = 'expired' | 'expiring' | 'valid';

/** A calendar month, `1` for January. Narrower than `number` so a lookup by it is total. */
type CardMonth = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12;

export interface CardExpiry {
  status: CardExpiryStatus;
  /** The expiry month, `1`-`12`. */
  month: CardMonth;
  /** The four-digit expiry year (a stored `27` reads as `2027`). */
  year: number;
  /** Local midnight at the START of the last day the card is valid. */
  lastValidDay: Date;
  /**
   * Whole days from today's local midnight to {@link lastValidDay}: `0` on the
   * last valid day, `1` the day before, negative once expired.
   */
  daysLeft: number;
}

const DAY_MS = 86_400_000;

/**
 * `1`-`12`, optionally with ONE leading zero. `00`, `013` and `+3` are refused:
 * a month written any other way is not one the form or an import produced.
 */
const MONTH_PATTERN = /^(?:0?[1-9]|1[0-2])$/;

/** Two or four ASCII digits (`\d` without the `u` flag never matches other scripts' digits). */
const YEAR_PATTERN = /^(?:\d{2}|\d{4})$/;

const MONTH_NAMES: Record<CardMonth, string> = {
  1: 'January',
  2: 'February',
  3: 'March',
  4: 'April',
  5: 'May',
  6: 'June',
  7: 'July',
  8: 'August',
  9: 'September',
  10: 'October',
  11: 'November',
  12: 'December',
};

/**
 * The month a stored value names, or `null`. `typeof`, not `=== undefined`: the
 * caller reads a decrypted record, and a value of the wrong type there must read
 * as "unknown" rather than throw on `.trim()`.
 */
function parseMonth(raw: string | undefined): CardMonth | null {
  if (typeof raw !== 'string') return null;
  const text = raw.trim();
  if (!MONTH_PATTERN.test(text)) return null;
  // The pattern admits exactly the strings for 1-12, so the number is one.
  return Number(text) as CardMonth;
}

/**
 * The four-digit year a stored value names, or `null`.
 *
 * A two-digit year is `20YY`: cards are issued for a few years ahead, so no
 * stored two-digit year means the 1900s. A four-digit year below 1000 (`0999`)
 * is refused, which also keeps `new Date(year, ...)` away from its legacy rule
 * of reading years 0-99 as 1900-1999.
 */
function parseYear(raw: string | undefined): number | null {
  if (typeof raw !== 'string') return null;
  const text = raw.trim();
  if (!YEAR_PATTERN.test(text)) return null;
  const value = Number(text);
  if (text.length === 2) return 2000 + value;
  return value >= 1000 ? value : null;
}

/** Local midnight of the calendar day `now` falls on. */
function startOfLocalDay(now: Date): Date {
  return new Date(now.getFullYear(), now.getMonth(), now.getDate());
}

/**
 * Reads a card's expiry from its stored month and year, as of `now`.
 *
 * Returns `null` when either part is missing or not a month/year this module
 * recognises (see the module note): the caller shows nothing rather than a
 * warning built on a guess.
 */
export function readCardExpiry(
  expMonth: string | undefined,
  expYear: string | undefined,
  now: Date = new Date(),
): CardExpiry | null {
  const month = parseMonth(expMonth);
  const year = parseYear(expYear);
  if (month === null || year === null) return null;
  // Day 0 of the FOLLOWING month is the last day of this one; `month` is
  // 1-based, which is exactly the 0-based index of the month after it.
  // December (12) rolls into January of the next year and back, by design.
  const lastValidDay = new Date(year, month, 0);
  const daysLeft = Math.round((lastValidDay.getTime() - startOfLocalDay(now).getTime()) / DAY_MS);
  const status: CardExpiryStatus =
    daysLeft < 0 ? 'expired' : daysLeft <= CARD_EXPIRY_SOON_DAYS ? 'expiring' : 'valid';
  return { status, month, year, lastValidDay, daysLeft };
}

/**
 * The expiry as the item view shows it: `MM/YYYY` when both parts are
 * recognised, otherwise whatever non-empty parts are stored joined by `/` (a
 * month with no year shows just the month, never a dangling `/`), and `''`
 * when nothing is stored.
 */
export function formatCardExpiry(
  expMonth: string | undefined,
  expYear: string | undefined,
): string {
  const month = parseMonth(expMonth);
  const year = parseYear(expYear);
  if (month !== null && year !== null) {
    return `${String(month).padStart(2, '0')}/${String(year)}`;
  }
  return [expMonth, expYear]
    .map((part) => (typeof part === 'string' ? part.trim() : ''))
    .filter((part) => part !== '')
    .join('/');
}

/** `March 2024`. */
function monthYearLabel(expiry: CardExpiry): string {
  return `${MONTH_NAMES[expiry.month]} ${String(expiry.year)}`;
}

/**
 * The card's status as a predicate, lower-case, for a sentence that already
 * names the card: `expired at the end of March 2024`, `expires today`,
 * `expires tomorrow`, `expires in 12 days`.
 */
export function cardExpiryPhrase(expiry: CardExpiry): string {
  if (expiry.status === 'expired') return `expired at the end of ${monthYearLabel(expiry)}`;
  if (expiry.daysLeft === 0) return 'expires today';
  if (expiry.daysLeft === 1) return 'expires tomorrow';
  return `expires in ${String(expiry.daysLeft)} days`;
}

/**
 * The item view's two sentences: a headline and the date it rests on.
 *
 * A card that has not expired gets the same shape whatever its status, so the
 * text never claims a window the status does not: "expires in N days" is true
 * of a valid card as well, and whether to show it at all is the caller's call.
 */
export function describeCardExpiry(expiry: CardExpiry): { headline: string; detail: string } {
  const through = monthYearLabel(expiry);
  if (expiry.status === 'expired') {
    return { headline: 'This card has expired', detail: `It was valid through ${through}.` };
  }
  return {
    headline: `This card ${cardExpiryPhrase(expiry)}`,
    detail: `It is valid through the end of ${through}.`,
  };
}

/**
 * The editor's one-line hint under the expiry inputs. An expired card can still
 * be saved (people keep old cards for their records), and the hint says so, so
 * it never reads as a validation error.
 */
export function cardExpiryHint(expiry: CardExpiry): string {
  const phrase = cardExpiryPhrase(expiry);
  if (expiry.status === 'expired') return `This card ${phrase}. You can still save it.`;
  return `This card ${phrase}, at the end of ${monthYearLabel(expiry)}.`;
}

/** The parts of a vault item {@link readItemCardExpiry} reads. */
export interface CardExpiryItem {
  itemType: string;
  data: Record<string, unknown>;
  deletedAt?: string | undefined;
}

/**
 * The expiry of a vault ITEM, for the places that warn about one: a card outside
 * the trash whose payload decoded. Everything else is `null`. A trashed card is
 * not one the user still carries, and an undecodable one holds a placeholder
 * rather than its real month and year (`isUndecodableData`). One definition, so
 * the vault list and the vault reminder can never disagree about which cards they
 * warn about.
 */
export function readItemCardExpiry(
  item: CardExpiryItem,
  now: Date = new Date(),
): CardExpiry | null {
  if (item.itemType !== 'card' || item.deletedAt || isUndecodableData(item.data)) return null;
  const { expMonth, expYear } = item.data;
  return readCardExpiry(
    typeof expMonth === 'string' ? expMonth : undefined,
    typeof expYear === 'string' ? expYear : undefined,
    now,
  );
}
