/**
 * The pure rules behind the item editor (`VaultItemForm`), kept out of the
 * component so each one is unit-tested (and mutation-tested) directly rather than
 * only through a rendered form.
 *
 * Two ideas run through all of them:
 *
 *  - **A card must be storable as it is printed.** Real cards fail rules a typical
 *    checkout form applies: a Maestro number can be 12 digits, and some brands carry
 *    no Luhn check digit at all. The editor therefore REFUSES only what cannot be a
 *    card number and WARNS about what is merely suspicious.
 *  - **An untouched value never blocks a save.** Every stored entry was accepted by
 *    some earlier version, and imports store values verbatim. A rule added or
 *    tightened later must not stop someone renaming an entry because of a field they
 *    never touched, so each blocking rule passes a control whose text still equals
 *    the value the form opened with ({@link isUntouched}).
 */

import { MAX_CARD_NUMBER_LENGTH } from '@hvault/shared';

/** Digits a card number may have: 12 (some Maestro cards) to 19 (ISO/IEC 7812). */
const MIN_CARD_NUMBER_DIGITS = 12;
const MAX_CARD_NUMBER_DIGITS = 19;

/**
 * The card-number control's `maxLength`: every digit the vault can store plus the
 * group spaces the control inserts between them. Long enough that typing or pasting
 * a number past 19 digits reaches the "12 to 19 digits" message instead of being
 * silently cut short by the browser.
 */
export const CARD_NUMBER_INPUT_MAX_LENGTH =
  MAX_CARD_NUMBER_LENGTH + Math.floor((MAX_CARD_NUMBER_LENGTH - 1) / 4);

/** A month the editor accepts: `1`-`12`, with or without one leading zero. */
export const CARD_MONTH_PATTERN = /^(0?[1-9]|1[0-2])$/;

/** A year the editor accepts: four digits, or two that mean `20YY`. */
export const CARD_YEAR_PATTERN = /^(\d{2}|\d{4})$/;

/** A card verification code: three or four digits. */
export const CARD_CVV_PATTERN = /^\d{3,4}$/;

/** The digits of a card number, with the spaces and dashes people write it with removed. */
export function cardNumberDigits(value: string): string {
  return value.replace(/[\s-]/g, '');
}

/**
 * Group a card number's digits in fours for display.
 *
 * Keeps every digit the vault can store (`MAX_CARD_NUMBER_LENGTH`), not the first
 * 19: cutting there silently changed a pasted or imported 20-digit number into a
 * different, valid-looking one. The 12-19 digit rule now reports the length instead.
 */
export function formatCardNumber(value: string): string {
  const digits = value.replace(/\D/g, '').slice(0, MAX_CARD_NUMBER_LENGTH);
  const groups: string[] = [];
  for (let i = 0; i < digits.length; i += 4) {
    groups.push(digits.slice(i, i + 4));
  }
  return groups.join(' ');
}

/**
 * Whether a STORED card number can be shown grouped without changing what it says:
 * nothing but digits, spaces and dashes, and a length the editor accepts. Anything
 * else (an imported value with letters, or more than 19 digits) is shown exactly as
 * stored, so that saving an unrelated edit writes it back byte for byte.
 */
export function isCleanCardNumber(stored: string): boolean {
  if (!/^[\d\s-]+$/.test(stored)) return false;
  const length = cardNumberDigits(stored).length;
  return length >= MIN_CARD_NUMBER_DIGITS && length <= MAX_CARD_NUMBER_DIGITS;
}

/** True when `digits` is a whole card number by length: 12 to 19 digits and nothing else. */
export function isCardNumberLength(digits: string): boolean {
  return (
    /^\d+$/.test(digits) &&
    digits.length >= MIN_CARD_NUMBER_DIGITS &&
    digits.length <= MAX_CARD_NUMBER_DIGITS
  );
}

/**
 * The Luhn (mod 10) checksum. A failure is a WARNING, never a refusal: most card
 * brands carry the check digit, but not all of them do, and a vault has to store the
 * card the person actually holds.
 */
export function isValidLuhn(digits: string): boolean {
  if (!/^\d+$/.test(digits)) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = Number(digits[i]);
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}

/** A two-digit year means `20YY`; anything else is returned unchanged. */
export function expandCardYear(value: string): string {
  return /^\d{2}$/.test(value) ? `20${value}` : value;
}

/**
 * Whether a control still holds exactly the value the form opened with. `initial`
 * is `null` while CREATING, which is never untouched: every rule applies to a new
 * entry.
 */
export function isUntouched(
  initial: Readonly<Record<string, unknown>> | null,
  key: string,
  value: unknown,
): boolean {
  return initial !== null && Object.hasOwn(initial, key) && initial[key] === value;
}

/** UTF-8 length of `value`, which is what an item name's ciphertext is as long as. */
export function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

/** The parts of a custom-field row the emptiness rules look at. */
export interface CustomFieldRowLike {
  name: string;
  value: string;
  type: string;
}

/**
 * Whether a custom-field row holds something worth keeping: a non-blank text or
 * hidden value, or a boolean switched on. A boolean that is off is the same as an
 * untouched row, so a nameless one is dropped rather than refused.
 */
export function customFieldHasContent(row: CustomFieldRowLike): boolean {
  return row.type === 'boolean' ? row.value === 'true' : row.value.trim() !== '';
}

/**
 * Whether the form should re-check a field that depends on the one just edited (the
 * expiry month and year, a secret's date and time). Only when the partner already
 * shows an error, has been visited, or a save was attempted: re-checking it any
 * earlier would put an error on a field the person has not reached yet, and not
 * re-checking it at all would leave an error standing after the person fixed its
 * cause.
 */
export function shouldRecheckPartner(state: {
  hasError: boolean;
  isTouched: boolean;
  isSubmitted: boolean;
}): boolean {
  return state.hasError || state.isTouched || state.isSubmitted;
}

/**
 * How many controls hold an error, for the summary above the Save button.
 *
 * Walks react-hook-form's error tree: a leaf is an object carrying a string
 * `message`; arrays (custom-field and URI rows) and nested objects are walked; the
 * `ref` of a leaf (a DOM node) is never entered.
 */
export function countFieldErrors(errors: unknown): number {
  if (errors === null || typeof errors !== 'object') return 0;
  if (Array.isArray(errors)) {
    return errors.reduce<number>((total, entry) => total + countFieldErrors(entry), 0);
  }
  const record = errors as Record<string, unknown>;
  if (typeof record.message === 'string') return 1;
  let total = 0;
  for (const [key, entry] of Object.entries(record)) {
    if (key !== 'ref') total += countFieldErrors(entry);
  }
  return total;
}
