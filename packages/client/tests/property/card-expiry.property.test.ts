/**
 * `readCardExpiry` and `formatCardExpiry`, as properties over every month of a
 * century and any instant around it.
 *
 * The day count is checked by CALENDAR arithmetic, never by dividing
 * milliseconds again: `new Date(y, m, d + daysLeft)` lets the `Date` constructor
 * normalise the overflow day by day, so it lands on the last valid day exactly
 * when `daysLeft` is the number of local calendar days between them, whatever
 * the zone's transitions did to the hours in between. That is the property that
 * fails for a truncating division in a zone with daylight saving, and it is
 * meaningful in UTC as well (where it pins month lengths and leap years).
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  CARD_EXPIRY_SOON_DAYS,
  formatCardExpiry,
  readCardExpiry,
  type CardExpiry,
} from '../../src/lib/cardExpiry';
import { propertyBanner, propertyRun } from '../../../../tests/harness/property.js';

const monthArbitrary = fc.integer({ min: 1, max: 12 });
const yearArbitrary = fc.integer({ min: 2000, max: 2099 });

/** Any instant from a year before the earliest expiry to a year after the latest. */
const nowArbitrary = fc
  .integer({ min: new Date(1999, 0, 1).getTime(), max: new Date(2101, 0, 1).getTime() })
  .map((ms) => new Date(ms));

/** One spelling of a month: bare (`3`) or zero-padded (`03`). */
function spellMonth(month: number, padded: boolean): string {
  return padded ? String(month).padStart(2, '0') : String(month);
}

/** One spelling of a 2000-2099 year: four digits or the last two. */
function spellYear(year: number, short: boolean): string {
  return short ? String(year).slice(2) : String(year);
}

function read(month: string, year: string, now: Date): CardExpiry {
  const expiry = readCardExpiry(month, year, now);
  if (expiry === null) throw new Error(`${month}/${year} did not parse. ${propertyBanner()}`);
  return expiry;
}

describe('readCardExpiry as a property', () => {
  it('ends every month on its last local day, at midnight', () => {
    fc.assert(
      fc.property(monthArbitrary, yearArbitrary, nowArbitrary, (month, year, now) => {
        const {
          lastValidDay,
          month: readMonth,
          year: readYear,
        } = read(String(month), String(year), now);
        expect([readMonth, readYear], propertyBanner()).toEqual([month, year]);
        expect(
          [lastValidDay.getFullYear(), lastValidDay.getMonth(), lastValidDay.getHours()],
          propertyBanner(),
        ).toEqual([year, month - 1, 0]);
        // The next calendar day is the first of another month.
        const next = new Date(year, month - 1, lastValidDay.getDate() + 1);
        expect(next.getDate(), propertyBanner()).toBe(1);
        expect(next.getMonth(), propertyBanner()).toBe(month % 12);
      }),
      propertyRun(),
    );
  });

  it('counts daysLeft in whole local calendar days from today', () => {
    fc.assert(
      fc.property(monthArbitrary, yearArbitrary, nowArbitrary, (month, year, now) => {
        const { lastValidDay, daysLeft } = read(String(month), String(year), now);
        expect(Number.isInteger(daysLeft), propertyBanner()).toBe(true);
        const landed = new Date(now.getFullYear(), now.getMonth(), now.getDate() + daysLeft);
        expect(landed.getTime(), propertyBanner()).toBe(lastValidDay.getTime());
      }),
      propertyRun(),
    );
  });

  it('loses exactly one day of validity per calendar day', () => {
    fc.assert(
      fc.property(monthArbitrary, yearArbitrary, nowArbitrary, (month, year, now) => {
        const tomorrow = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1, 12);
        const today = read(String(month), String(year), now);
        const next = read(String(month), String(year), tomorrow);
        expect(next.daysLeft, propertyBanner()).toBe(today.daysLeft - 1);
      }),
      propertyRun(),
    );
  });

  it('derives the status from daysLeft and nothing else', () => {
    fc.assert(
      fc.property(monthArbitrary, yearArbitrary, nowArbitrary, (month, year, now) => {
        const { status, daysLeft } = read(String(month), String(year), now);
        const expected =
          daysLeft < 0 ? 'expired' : daysLeft <= CARD_EXPIRY_SOON_DAYS ? 'expiring' : 'valid';
        expect(status, propertyBanner()).toBe(expected);
      }),
      propertyRun(),
    );
  });

  it('reads every spelling of the same month and year the same way', () => {
    fc.assert(
      fc.property(
        monthArbitrary,
        yearArbitrary,
        nowArbitrary,
        fc.boolean(),
        fc.boolean(),
        (month, year, now, padded, short) => {
          const canonical = read(String(month), String(year), now);
          const spelled = read(spellMonth(month, padded), spellYear(year, short), now);
          expect(spelled, propertyBanner()).toEqual(canonical);
        },
      ),
      propertyRun(),
    );
  });

  it('formats to MM/YYYY, which reads back as the same expiry', () => {
    fc.assert(
      fc.property(
        monthArbitrary,
        yearArbitrary,
        nowArbitrary,
        fc.boolean(),
        fc.boolean(),
        (month, year, now, padded, short) => {
          const monthText = spellMonth(month, padded);
          const yearText = spellYear(year, short);
          const formatted = formatCardExpiry(monthText, yearText);
          expect(formatted, propertyBanner()).toMatch(/^(0[1-9]|1[0-2])\/20\d{2}$/);
          const [formattedMonth = '', formattedYear = ''] = formatted.split('/');
          expect(read(formattedMonth, formattedYear, now), propertyBanner()).toEqual(
            read(monthText, yearText, now),
          );
        },
      ),
      propertyRun(),
    );
  });
});
