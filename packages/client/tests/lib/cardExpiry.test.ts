/**
 * `lib/cardExpiry.ts`: when a stored card stops being valid, and every sentence
 * the app says about it.
 *
 * Every `now` is built with the LOCAL `Date` constructor and passed in, never
 * read from the machine: the rule is "valid through the last day of the month,
 * in local time", so a test that built its instants in UTC would be asserting a
 * different rule in every zone but one. The DST cases are written to hold in any
 * zone, and are the ones that tell `Math.round` from a truncating division when
 * this file runs in a zone with transitions (`HVAULT_TZ=America/New_York`).
 */
import { describe, expect, it } from 'vitest';
import {
  CARD_EXPIRY_SOON_DAYS,
  cardExpiryHint,
  cardExpiryPhrase,
  describeCardExpiry,
  formatCardExpiry,
  readCardExpiry,
  type CardExpiry,
} from '../../src/lib/cardExpiry';

/** Reads an expiry that must exist; the failure names what did not parse. */
function expiryOf(month: string, year: string, now: Date): CardExpiry {
  const expiry = readCardExpiry(month, year, now);
  if (expiry === null) throw new Error(`expected ${month}/${year} to parse`);
  return expiry;
}

/** The local calendar date a `Date` falls on, as `[year, monthIndex, day]`. */
function localDay(date: Date): [number, number, number] {
  return [date.getFullYear(), date.getMonth(), date.getDate()];
}

describe('readCardExpiry: the last valid day', () => {
  it('is valid through the whole last day of its month, and expiring with 0 days left', () => {
    for (const now of [
      new Date(2026, 2, 31, 0, 0, 0, 0),
      new Date(2026, 2, 31, 15, 30),
      new Date(2026, 2, 31, 23, 59, 59, 999),
    ]) {
      const expiry = expiryOf('03', '2026', now);
      expect(expiry).toEqual({
        status: 'expiring',
        month: 3,
        year: 2026,
        lastValidDay: new Date(2026, 2, 31),
        daysLeft: 0,
      });
    }
  });

  it('is expired from the first moment of the following day, with a negative count', () => {
    const expiry = expiryOf('3', '2026', new Date(2026, 3, 1, 0, 0, 0, 0));
    expect(expiry.status).toBe('expired');
    expect(expiry.daysLeft).toBe(-1);
    // The month is still the stored one; expiry never shifts the month it names.
    expect(expiry.month).toBe(3);
    expect(localDay(expiry.lastValidDay)).toEqual([2026, 2, 31]);
  });

  it('counts years-old expiry as expired by the full number of days', () => {
    const expiry = expiryOf('01', '2020', new Date(2021, 0, 31));
    expect(expiry.status).toBe('expired');
    expect(expiry.daysLeft).toBe(-366); // 2020 was a leap year: 31 Jan 2020 to 31 Jan 2021.
  });

  it('starts the last valid day at local midnight', () => {
    const { lastValidDay } = expiryOf('7', '2027', new Date(2027, 0, 1));
    expect(localDay(lastValidDay)).toEqual([2027, 6, 31]);
    expect([
      lastValidDay.getHours(),
      lastValidDay.getMinutes(),
      lastValidDay.getSeconds(),
      lastValidDay.getMilliseconds(),
    ]).toEqual([0, 0, 0, 0]);
  });
});

describe('readCardExpiry: the expiring window', () => {
  it(`is expiring with exactly ${String(CARD_EXPIRY_SOON_DAYS)} days left`, () => {
    // 1 April to 31 May 2026: 30 days to 1 May, 30 more to 31 May.
    const expiry = expiryOf('05', '2026', new Date(2026, 3, 1, 9));
    expect(expiry.daysLeft).toBe(60);
    expect(expiry.status).toBe('expiring');
  });

  it(`is still valid with ${String(CARD_EXPIRY_SOON_DAYS + 1)} days left`, () => {
    const expiry = expiryOf('05', '2026', new Date(2026, 2, 31, 9));
    expect(expiry.daysLeft).toBe(61);
    expect(expiry.status).toBe('valid');
  });

  it('keeps the window at two months', () => {
    expect(CARD_EXPIRY_SOON_DAYS).toBe(60);
  });
});

describe('readCardExpiry: calendar edges', () => {
  it('rolls December into the next January and back', () => {
    const lastDay = expiryOf('12', '2026', new Date(2026, 11, 31, 12));
    expect(localDay(lastDay.lastValidDay)).toEqual([2026, 11, 31]);
    expect(lastDay.status).toBe('expiring');
    expect(lastDay.daysLeft).toBe(0);
    expect(lastDay.year).toBe(2026);

    const nextYear = expiryOf('12', '2026', new Date(2027, 0, 1));
    expect(nextYear.status).toBe('expired');
    expect(nextYear.daysLeft).toBe(-1);
  });

  it('ends February on the 29th in a leap year and the 28th otherwise', () => {
    const now = new Date(1999, 0, 1);
    expect(localDay(expiryOf('2', '2028', now).lastValidDay)).toEqual([2028, 1, 29]);
    expect(localDay(expiryOf('2', '2027', now).lastValidDay)).toEqual([2027, 1, 28]);
    // The century rules: 2000 was a leap year, 2100 will not be.
    expect(localDay(expiryOf('2', '2000', now).lastValidDay)).toEqual([2000, 1, 29]);
    expect(localDay(expiryOf('2', '2100', now).lastValidDay)).toEqual([2100, 1, 28]);
  });

  it('is still valid on 29 February of a leap year and expired on 1 March', () => {
    expect(expiryOf('02', '2028', new Date(2028, 1, 29, 18)).status).toBe('expiring');
    expect(expiryOf('02', '2028', new Date(2028, 2, 1)).status).toBe('expired');
  });

  it('counts whole calendar days across a spring-forward change', () => {
    // 1 March to 31 March 2026 contains the North American spring change
    // (8 March), so that span is an hour short of 30 x 24 h there; a truncating
    // division would report 29.
    expect(expiryOf('03', '2026', new Date(2026, 2, 1)).daysLeft).toBe(30);
    // And the European change (29 March) sits inside this one.
    expect(expiryOf('04', '2026', new Date(2026, 2, 28)).daysLeft).toBe(33);
  });

  it('counts whole calendar days across a fall-back change', () => {
    // 1 to 30 November 2026 contains the North American fall change (1 November),
    // so the span is an hour LONG there; a rounding-up division would report 30.
    expect(expiryOf('11', '2026', new Date(2026, 10, 1)).daysLeft).toBe(29);
    expect(expiryOf('10', '2026', new Date(2026, 9, 24)).daysLeft).toBe(7);
  });
});

describe('readCardExpiry: what it reads', () => {
  const now = new Date(2026, 0, 15);

  it('reads a month with or without one leading zero, and every month of the year', () => {
    for (let month = 1; month <= 12; month += 1) {
      const bare = expiryOf(String(month), '2030', now);
      const padded = expiryOf(String(month).padStart(2, '0'), '2030', now);
      expect(bare.month).toBe(month);
      expect(padded).toEqual(bare);
      expect(bare.lastValidDay.getMonth()).toBe(month - 1);
    }
  });

  it('reads a two-digit year as 20YY, and agrees with the four-digit spelling', () => {
    expect(expiryOf('6', '27', now)).toEqual(expiryOf('06', '2027', now));
    expect(expiryOf('6', '27', now).year).toBe(2027);
    expect(expiryOf('6', '00', now).year).toBe(2000);
    expect(expiryOf('6', '99', now).year).toBe(2099);
  });

  it('ignores surrounding whitespace', () => {
    expect(expiryOf(' 3 ', '\t2027\n', now)).toEqual(expiryOf('3', '2027', now));
  });

  it('accepts the smallest four-digit year it allows', () => {
    const expiry = expiryOf('1', '1000', now);
    expect(expiry.year).toBe(1000);
    expect(localDay(expiry.lastValidDay)).toEqual([1000, 0, 31]);
    expect(expiry.status).toBe('expired');
  });

  it.each([
    ['00', 'a zero month'],
    ['0', 'a bare zero'],
    ['13', 'a thirteenth month'],
    ['003', 'two leading zeros'],
    ['+3', 'a sign'],
    ['3.0', 'a decimal'],
    ['1 2', 'inner whitespace'],
    ['ab', 'letters'],
    ['', 'an empty value'],
    ['   ', 'only whitespace'],
    ['٣', 'a non-ASCII digit'],
  ])('refuses the month %j (%s)', (month) => {
    expect(readCardExpiry(month, '2027', now)).toBeNull();
  });

  it.each([
    ['202', 'three digits'],
    ['20271', 'five digits'],
    ['7', 'one digit'],
    ['0999', 'a four-digit year below 1000'],
    ['0000', 'year zero'],
    ['20 27', 'inner whitespace'],
    ['ab', 'letters'],
    ['', 'an empty value'],
    ['２０２７', 'full-width digits'],
  ])('refuses the year %j (%s)', (year) => {
    expect(readCardExpiry('3', year, now)).toBeNull();
  });

  it('returns null when either part is missing', () => {
    expect(readCardExpiry(undefined, '2027', now)).toBeNull();
    expect(readCardExpiry('3', undefined, now)).toBeNull();
    expect(readCardExpiry(undefined, undefined, now)).toBeNull();
  });

  it('reads a value of the wrong type as unknown rather than throwing', () => {
    // The caller reads a decrypted record; a malformed one must not take the
    // vault page down with a TypeError from `.trim()`.
    const month = 3 as unknown as string;
    const year = 2027 as unknown as string;
    expect(readCardExpiry(month, '2027', now)).toBeNull();
    expect(readCardExpiry('3', year, now)).toBeNull();
  });

  it('judges against the current clock when no instant is given', () => {
    // A card that expired long ago and one valid for decades are the same
    // verdict on any machine, whatever today is.
    expect(readCardExpiry('1', '2001')?.status).toBe('expired');
    expect(readCardExpiry('12', '2999')?.status).toBe('valid');
  });
});

describe('formatCardExpiry', () => {
  it('shows MM/YYYY when both parts are recognised', () => {
    expect(formatCardExpiry('3', '2027')).toBe('03/2027');
    expect(formatCardExpiry('03', '27')).toBe('03/2027');
    expect(formatCardExpiry(' 12 ', ' 2030 ')).toBe('12/2030');
    expect(formatCardExpiry('10', '00')).toBe('10/2000');
  });

  it('shows the stored parts as they are when either is not recognised', () => {
    expect(formatCardExpiry('13', '2027')).toBe('13/2027');
    expect(formatCardExpiry('ab', ' 27 ')).toBe('ab/27');
    expect(formatCardExpiry('3', '202')).toBe('3/202');
  });

  it('never shows a dangling slash for a missing part', () => {
    expect(formatCardExpiry('3', '')).toBe('3');
    expect(formatCardExpiry('', '2027')).toBe('2027');
    expect(formatCardExpiry(' 3 ', undefined)).toBe('3');
    expect(formatCardExpiry(undefined, '2027')).toBe('2027');
    expect(formatCardExpiry('   ', '2027')).toBe('2027');
  });

  it('is empty when nothing is stored', () => {
    expect(formatCardExpiry('', '')).toBe('');
    expect(formatCardExpiry(undefined, undefined)).toBe('');
    expect(formatCardExpiry(' ', '\t')).toBe('');
    expect(formatCardExpiry(3 as unknown as string, undefined)).toBe('');
  });
});

describe('the sentences', () => {
  const now = new Date(2026, 9, 31, 10);

  it('describes an expired card by the month it was valid through', () => {
    const expiry = expiryOf('3', '2024', now);
    expect(describeCardExpiry(expiry)).toEqual({
      headline: 'This card has expired',
      detail: 'It was valid through March 2024.',
    });
    expect(cardExpiryPhrase(expiry)).toBe('expired at the end of March 2024');
    expect(cardExpiryHint(expiry)).toBe(
      'This card expired at the end of March 2024. You can still save it.',
    );
  });

  it('says "today" on the last valid day', () => {
    const expiry = expiryOf('10', '2026', now);
    expect(expiry.daysLeft).toBe(0);
    expect(describeCardExpiry(expiry)).toEqual({
      headline: 'This card expires today',
      detail: 'It is valid through the end of October 2026.',
    });
    expect(cardExpiryPhrase(expiry)).toBe('expires today');
    expect(cardExpiryHint(expiry)).toBe('This card expires today, at the end of October 2026.');
  });

  it('says "tomorrow" the day before', () => {
    const expiry = expiryOf('10', '2026', new Date(2026, 9, 30));
    expect(expiry.daysLeft).toBe(1);
    expect(describeCardExpiry(expiry).headline).toBe('This card expires tomorrow');
    expect(cardExpiryPhrase(expiry)).toBe('expires tomorrow');
    expect(cardExpiryHint(expiry)).toBe('This card expires tomorrow, at the end of October 2026.');
  });

  it('counts the days otherwise', () => {
    // 31 October to 30 November 2026.
    const expiry = expiryOf('11', '2026', now);
    expect(expiry.daysLeft).toBe(30);
    expect(describeCardExpiry(expiry)).toEqual({
      headline: 'This card expires in 30 days',
      detail: 'It is valid through the end of November 2026.',
    });
    expect(cardExpiryPhrase(expiry)).toBe('expires in 30 days');
    expect(cardExpiryHint(expiry)).toBe(
      'This card expires in 30 days, at the end of November 2026.',
    );
  });

  it('describes a valid card in the same shape, never as expired', () => {
    const expiry = expiryOf('12', '2027', now);
    expect(expiry.status).toBe('valid');
    expect(describeCardExpiry(expiry)).toEqual({
      headline: `This card expires in ${String(expiry.daysLeft)} days`,
      detail: 'It is valid through the end of December 2027.',
    });
  });

  it('names every month in English, from January to December', () => {
    const names = Array.from({ length: 12 }, (_, index) =>
      describeCardExpiry(expiryOf(String(index + 1), '2001', now)).detail.replace(
        /^It was valid through (\w+) 2001\.$/,
        '$1',
      ),
    );
    expect(names).toEqual([
      'January',
      'February',
      'March',
      'April',
      'May',
      'June',
      'July',
      'August',
      'September',
      'October',
      'November',
      'December',
    ]);
  });

  it('never produces the bare word "Expiry", which the item view uses as a field label', () => {
    const samples = [
      expiryOf('3', '2024', now),
      expiryOf('10', '2026', now),
      expiryOf('10', '2026', new Date(2026, 9, 30)),
      expiryOf('11', '2026', now),
      expiryOf('12', '2027', now),
    ];
    const outputs = samples.flatMap((expiry) => {
      const { headline, detail } = describeCardExpiry(expiry);
      return [headline, detail, cardExpiryPhrase(expiry), cardExpiryHint(expiry)];
    });
    expect(outputs).toHaveLength(20);
    for (const text of outputs) {
      expect(text).not.toMatch(/\bExpiry\b/);
    }
    expect(formatCardExpiry('Expiry', '')).toBe('Expiry'); // Raw text is shown as stored...
    expect(formatCardExpiry('3', '2027')).not.toMatch(/Expiry/); // ...but never invented.
  });
});
