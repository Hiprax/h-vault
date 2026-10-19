/**
 * `lib/itemFormRules.ts`: the pure rules behind the item editor, pinned at their
 * boundaries. The rendered form is covered by `components/VaultItemForm.rules.test.tsx`;
 * here each rule is checked on its own, one value either side of every edge.
 */
import { describe, expect, it } from 'vitest';
import { MAX_CARD_NUMBER_LENGTH } from '@hvault/shared';
import {
  CARD_CVV_PATTERN,
  CARD_MONTH_PATTERN,
  CARD_NUMBER_INPUT_MAX_LENGTH,
  CARD_YEAR_PATTERN,
  cardNumberDigits,
  countFieldErrors,
  customFieldHasContent,
  expandCardYear,
  formatCardNumber,
  isCardNumberLength,
  isCleanCardNumber,
  isUntouched,
  isValidLuhn,
  shouldRecheckPartner,
  utf8ByteLength,
} from '../../src/lib/itemFormRules';

describe('card number length', () => {
  it.each([
    ['11 digits', '1'.repeat(11), false],
    ['12 digits (some Maestro cards)', '1'.repeat(12), true],
    ['19 digits', '1'.repeat(19), true],
    ['20 digits', '1'.repeat(20), false],
    ['nothing', '', false],
    ['digits with a space', '4111 1111 1111', false],
    ['digits with a letter', '41111111111a', false],
  ])('%s: %s', (_label, digits, accepted) => {
    expect(isCardNumberLength(digits)).toBe(accepted);
  });
});

describe('cardNumberDigits', () => {
  it('removes the spaces and dashes a number is written with, and nothing else', () => {
    expect(cardNumberDigits('4111-1111 1111\t1111')).toBe('4111111111111111');
    expect(cardNumberDigits('4111 old')).toBe('4111old');
  });
});

describe('formatCardNumber', () => {
  it('groups the digits in fours', () => {
    expect(formatCardNumber('4111111111111111')).toBe('4111 1111 1111 1111');
    expect(formatCardNumber('4111-1111')).toBe('4111 1111');
  });

  it('keeps a 20th digit instead of cutting the number to 19', () => {
    expect(formatCardNumber('12345678901234567890')).toBe('1234 5678 9012 3456 7890');
  });

  it('keeps every digit the vault can store, and fits the control that shows them', () => {
    const longest = formatCardNumber('7'.repeat(MAX_CARD_NUMBER_LENGTH));
    expect(longest.replace(/ /g, '')).toHaveLength(MAX_CARD_NUMBER_LENGTH);
    expect(longest).toHaveLength(CARD_NUMBER_INPUT_MAX_LENGTH);
    // One digit more than the vault can hold is the one that is not kept.
    expect(formatCardNumber('7'.repeat(MAX_CARD_NUMBER_LENGTH + 1))).toBe(longest);
  });
});

describe('isCleanCardNumber', () => {
  it.each([
    ['a plain number', '4111111111111111', true],
    ['a spaced number', '4111 1111 1111 1111', true],
    ['a dashed number', '4111-1111-1111-1111', true],
    ['12 digits', '1'.repeat(12), true],
    ['11 digits', '1'.repeat(11), false],
    ['19 digits', '1'.repeat(19), true],
    ['20 digits', '1'.repeat(20), false],
    ['trailing text', '4111111111111111 old', false],
    ['nothing', '', false],
  ])('%s', (_label, stored, clean) => {
    expect(isCleanCardNumber(stored)).toBe(clean);
  });
});

describe('isValidLuhn', () => {
  it.each([
    ['a valid 16-digit number', '4111111111111111', true],
    ['the same number with its last digit changed', '4111111111111112', false],
    ['a valid 19-digit number', '4111111111111111110', true],
    ['the textbook valid example', '79927398713', true],
    ['the textbook example, last digit changed', '79927398710', false],
    ['nothing', '', false],
    ['a number with a space', '4111 1111 1111 1111', false],
  ])('%s', (_label, digits, valid) => {
    expect(isValidLuhn(digits)).toBe(valid);
  });
});

describe('expiry month', () => {
  it.each(['1', '01', '9', '09', '10', '12'])('accepts %s', (month) => {
    expect(CARD_MONTH_PATTERN.test(month)).toBe(true);
  });

  it.each(['0', '00', '13', '001', '1 ', ' 1', '', 'a'])('refuses "%s"', (month) => {
    expect(CARD_MONTH_PATTERN.test(month)).toBe(false);
  });
});

describe('expiry year', () => {
  it.each(['29', '2029'])('accepts %s', (year) => {
    expect(CARD_YEAR_PATTERN.test(year)).toBe(true);
  });

  it.each(['2', '202', '20290', '', '20a9'])('refuses "%s"', (year) => {
    expect(CARD_YEAR_PATTERN.test(year)).toBe(false);
  });

  it.each([
    ['29', '2029'],
    ['2029', '2029'],
    ['2', '2'],
    ['', ''],
    ['ab', 'ab'],
  ])('expands %s to %s', (year, expanded) => {
    expect(expandCardYear(year)).toBe(expanded);
  });
});

describe('CVV', () => {
  it.each([
    ['123', true],
    ['1234', true],
    ['12', false],
    ['12345', false],
    ['12a', false],
    ['', false],
  ])('%s', (cvv, accepted) => {
    expect(CARD_CVV_PATTERN.test(cvv)).toBe(accepted);
  });
});

describe('isUntouched', () => {
  it('is never true while creating', () => {
    expect(isUntouched(null, 'name', '')).toBe(false);
  });

  it('is true only for a key the form opened with, still at that exact value', () => {
    const initial = { name: 'Bank', number: '' };
    expect(isUntouched(initial, 'name', 'Bank')).toBe(true);
    expect(isUntouched(initial, 'number', '')).toBe(true);
    expect(isUntouched(initial, 'name', 'Bank ')).toBe(false);
    expect(isUntouched(initial, 'cvv', undefined)).toBe(false);
    // An inherited property is not a value the form opened with.
    expect(isUntouched(initial, 'toString', Object.prototype.toString)).toBe(false);
  });
});

describe('utf8ByteLength', () => {
  it.each([
    ['', 0],
    ['abc', 3],
    ['é', 2],
    ['€', 3],
    ['\u{1F600}', 4],
  ])('"%s" is %i bytes', (value, bytes) => {
    expect(utf8ByteLength(value)).toBe(bytes);
  });
});

describe('customFieldHasContent', () => {
  it.each([
    ['blank text', { name: '', value: '   ', type: 'text' }, false],
    ['text', { name: '', value: 'x', type: 'text' }, true],
    ['a hidden value', { name: '', value: ' x ', type: 'hidden' }, true],
    ['a blank hidden value', { name: '', value: '', type: 'hidden' }, false],
    ['a boolean switched on', { name: '', value: 'true', type: 'boolean' }, true],
    ['a boolean switched off', { name: '', value: 'false', type: 'boolean' }, false],
    ['a boolean never set', { name: '', value: '', type: 'boolean' }, false],
  ])('%s', (_label, row, hasContent) => {
    expect(customFieldHasContent(row)).toBe(hasContent);
  });
});

describe('shouldRecheckPartner', () => {
  it('re-checks a partner that shows an error, was visited, or after a save attempt', () => {
    const none = { hasError: false, isTouched: false, isSubmitted: false };
    expect(shouldRecheckPartner(none)).toBe(false);
    expect(shouldRecheckPartner({ ...none, hasError: true })).toBe(true);
    expect(shouldRecheckPartner({ ...none, isTouched: true })).toBe(true);
    expect(shouldRecheckPartner({ ...none, isSubmitted: true })).toBe(true);
  });
});

describe('countFieldErrors', () => {
  it('counts nothing in an empty or missing error tree', () => {
    expect(countFieldErrors(undefined)).toBe(0);
    expect(countFieldErrors(null)).toBe(0);
    expect(countFieldErrors({})).toBe(0);
  });

  it('counts each leaf once, through rows and nested objects', () => {
    expect(
      countFieldErrors({
        name: { message: 'Name is required' },
        customFields: [
          { name: { message: 'Give this field a name, or remove it' } },
          undefined,
          { name: { message: 'a' }, value: { message: 'b' } },
        ],
        address: { city: { message: 'c' } },
      }),
    ).toBe(5);
  });

  it('never enters a leaf or its DOM reference, and ignores a non-string message', () => {
    expect(countFieldErrors({ a: { message: 'x', ref: { message: 'inner' } } })).toBe(1);
    expect(countFieldErrors({ ref: { message: 'y' }, b: { message: 'z' } })).toBe(1);
    expect(countFieldErrors({ a: { message: 5 } })).toBe(0);
  });
});
