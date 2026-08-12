/**
 * `combineExpiry`, as a property — including the case that only exists in a
 * DST-observing timezone.
 *
 * A secret's `expiresAt` is an ABSOLUTE INSTANT edited through two LOCAL-time
 * controls. `getDefaultValues` renders the stored instant into a `YYYY-MM-DD` and
 * an `HH:MM`, and `combineExpiry` turns the pair back into a value to store. The
 * contract that matters is the round trip: if the user touched NEITHER control,
 * the stored string must come back BYTE-IDENTICAL. Not "the same instant" —
 * identical, because
 *
 *   - a date-only value must not be silently promoted to a datetime,
 *   - sub-minute precision the controls cannot express must survive a save, and
 *   - the import content hash is computed over the stored string, so any rewrite
 *     of an untouched item makes a re-import of the same file insert a duplicate
 *     instead of matching.
 *
 * `combineExpiry` decides "untouched" by comparing the CONTROL STRINGS with what
 * the stored instant renders as, rather than by comparing instants, and the
 * reason is written into the production comment: during the repeated hour of a
 * fall-back DST transition, TWO distinct instants render to the SAME date and
 * time pair. An instant comparison can be satisfied by at most one of them, so
 * the other fell through to the rebuild branch and was rewritten an hour earlier.
 *
 * That branch is UNREACHABLE in UTC — it has no transitions — which is why this
 * file is part of the `test:property` gate's second leg
 * (`HVAULT_TZ=America/New_York`) and not only of the UTC suite. Under UTC the
 * properties below still hold; they simply cannot distinguish the string
 * comparison from an instant comparison, and the two ambiguous-hour tests say so
 * by asserting the ambiguity exists before relying on it.
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  combineExpiry,
  localDateValue,
  localTimeValue,
} from '../../src/components/vault/VaultItemForm';
import { secretDataSchema } from '@hvault/shared';
import { PROPERTY_RUNS, propertyBanner, propertyRun } from '../../../../tests/harness/property.js';

/**
 * The zone this run is pinned to, read from the environment the harness set.
 *
 * Used only to LABEL the two ambiguous-hour tests, never to decide whether to
 * assert: each of them proves the ambiguity it needs from `Date` itself, so it is
 * a real test in every zone rather than a conditional skip in most of them.
 */
const RUNNING_IN = process.env['TZ'] ?? 'unset';

/** An instant somewhere in a plausible expiry range, at whole-second precision. */
const instantArbitrary = fc
  .integer({ min: Date.UTC(1971, 0, 1) / 1000, max: Date.UTC(2099, 11, 31) / 1000 })
  .map((seconds) => new Date(seconds * 1000));

/** The two control values `getDefaultValues` would render for an instant. */
function controlsFor(instant: Date): { date: string; time: string } {
  return { date: localDateValue(instant), time: localTimeValue(instant) };
}

/**
 * Local midnight on a date, as an ISO instant — what `combineExpiry` produces
 * when the time control is empty.
 */
function localMidnightIso(date: string): string {
  const [year, month, day] = date.split('-').map(Number) as [number, number, number];
  const local = new Date(0);
  local.setFullYear(year, month - 1, day);
  local.setHours(0, 0, 0, 0);
  return local.toISOString();
}

describe('combineExpiry — an untouched pair of controls', () => {
  it('returns the stored string byte-identically for any stored instant', () => {
    fc.assert(
      fc.property(instantArbitrary, (instant) => {
        const stored = instant.toISOString();
        const { date, time } = controlsFor(instant);

        expect(combineExpiry(date, time, stored), propertyBanner()).toBe(stored);
      }),
      propertyRun(),
    );
  });

  it('returns a DATE-ONLY stored value unchanged, without promoting it to a datetime', () => {
    // `new Date('2026-11-01')` is parsed as UTC midnight, so in a zone behind UTC
    // the rendered controls name the PREVIOUS local day — and the stored value
    // must still come back as the date-only string it was. A rebuild would emit a
    // full ISO instant here, which is a different value with a different content
    // hash and a different meaning to `formatRemainingTime`.
    fc.assert(
      fc.property(instantArbitrary, (instant) => {
        const stored = instant.toISOString().slice(0, 10);
        const asStored = new Date(stored);
        const { date, time } = controlsFor(asStored);

        expect(combineExpiry(date, time, stored), propertyBanner()).toBe(stored);
      }),
      propertyRun(),
    );
  });

  it('preserves sub-minute precision the controls cannot express', () => {
    // The controls render `HH:MM`; the stored value may carry seconds and
    // milliseconds. An untouched save must not truncate them, which is only true
    // while the "unchanged" test is a string comparison over what the controls
    // render rather than a comparison of instants at minute resolution.
    fc.assert(
      fc.property(
        instantArbitrary,
        fc.integer({ min: 1, max: 59 }),
        fc.integer({ min: 1, max: 999 }),
        (instant, seconds, millis) => {
          const precise = new Date(instant);
          precise.setSeconds(seconds, millis);
          const stored = precise.toISOString();
          const { date, time } = controlsFor(precise);

          expect(combineExpiry(date, time, stored), propertyBanner()).toBe(stored);
        },
      ),
      propertyRun(),
    );
  });

  it('keeps whatever it returns acceptable to secretDataSchema', () => {
    // The value goes straight into the encrypted blob, where `secretDataSchema`'s
    // three refines meet it again on the next decrypt. A shape they reject is the
    // undecodable-item class, so the two are asserted together rather than
    // separately.
    fc.assert(
      fc.property(instantArbitrary, fc.boolean(), (instant, storedIsDateOnly) => {
        const stored = storedIsDateOnly
          ? instant.toISOString().slice(0, 10)
          : instant.toISOString();
        const { date, time } = controlsFor(new Date(stored));
        const combined = combineExpiry(date, time, stored);

        expect(combined, propertyBanner()).toBeDefined();
        expect(
          secretDataSchema.safeParse({ expiresAt: combined }).success,
          `${propertyBanner()} — combineExpiry produced ${String(combined)}, which its own schema rejects`,
        ).toBe(true);
      }),
      propertyRun(),
    );
  });
});

describe('combineExpiry — a control the user did move', () => {
  it('rebuilds from the controls whenever either one differs from the stored value', () => {
    fc.assert(
      fc.property(instantArbitrary, fc.integer({ min: 1, max: 3_000 }), (instant, minutes) => {
        const stored = instant.toISOString();
        const moved = new Date(instant.getTime() + minutes * 60_000);
        const { date, time } = controlsFor(moved);
        // Only meaningful while the moved instant renders to a DIFFERENT pair; a
        // 1-minute step always does, but a DST jump can map two different instants
        // to the same pair, and in that case "untouched" is the correct answer.
        fc.pre(date !== localDateValue(instant) || time !== localTimeValue(instant));

        const combined = combineExpiry(date, time, stored);
        expect(combined, propertyBanner()).not.toBe(stored);
        // The rebuild is LOCAL time at minute resolution: exactly the pair of
        // control values, seconds and milliseconds zeroed.
        const rebuilt = new Date(combined ?? '');
        expect(localDateValue(rebuilt), propertyBanner()).toBe(date);
        expect(localTimeValue(rebuilt), propertyBanner()).toBe(time);
        expect(rebuilt.getSeconds(), propertyBanner()).toBe(0);
        expect(rebuilt.getMilliseconds(), propertyBanner()).toBe(0);
      }),
      propertyRun(),
    );
  });

  it('treats an empty time control as LOCAL midnight, never as UTC midnight', () => {
    fc.assert(
      fc.property(instantArbitrary, (instant) => {
        const date = localDateValue(instant);
        const combined = combineExpiry(date, '', 'not-the-stored-value');

        expect(combined, propertyBanner()).toBe(localMidnightIso(date));
        expect(localDateValue(new Date(combined ?? '')), propertyBanner()).toBe(date);
        expect(localTimeValue(new Date(combined ?? '')), propertyBanner()).toBe('00:00');
      }),
      propertyRun({ numRuns: Math.ceil(PROPERTY_RUNS / 2) }),
    );
  });

  it('returns undefined for a date control that is empty or malformed', () => {
    // `undefined` is what `omitUndefined` drops, i.e. "no expiry". The four-digit
    // year bound is the reachable case: Chrome's date picker accepts year 275760,
    // and the form refuses such a value inline rather than letting it reach here.
    fc.assert(
      fc.property(
        fc.constantFrom('', '2026', '2026-1-1', '275760-09-13', 'nope', '2026-01-01T00:00'),
        (date) => {
          expect(combineExpiry(date, '09:30', ''), propertyBanner()).toBeUndefined();
        },
      ),
      propertyRun({ numRuns: 12 }),
    );
  });
});

describe('combineExpiry — the fall-back DST repeated hour', () => {
  /**
   * The two instants that share one local wall-clock reading in
   * America/New_York's 2026 fall-back transition: DST ends at 02:00 EDT on
   * November 1, so 01:30 local happens twice — once at 05:30Z (UTC-4) and again
   * at 06:30Z (UTC-5).
   */
  const FIRST_PASS = '2026-11-01T05:30:00.000Z';
  const SECOND_PASS = '2026-11-01T06:30:00.000Z';

  it(`round-trips BOTH instants of an ambiguous local hour verbatim (TZ=${RUNNING_IN})`, () => {
    const first = new Date(FIRST_PASS);
    const second = new Date(SECOND_PASS);

    // The ambiguity is PROVEN from `Date` rather than assumed, so this test is
    // meaningful in every zone: under a DST-observing zone the two instants render
    // identically and the assertion below is the real thing; under UTC they render
    // an hour apart and it degrades to two ordinary round-trips. Either way it
    // fails if `combineExpiry` stops returning the stored string.
    const ambiguous =
      localDateValue(first) === localDateValue(second) &&
      localTimeValue(first) === localTimeValue(second);
    expect(first.getTime()).not.toBe(second.getTime());

    for (const stored of [FIRST_PASS, SECOND_PASS]) {
      const instant = new Date(stored);
      const { date, time } = controlsFor(instant);
      expect(
        combineExpiry(date, time, stored),
        `ambiguous=${String(ambiguous)} TZ=${RUNNING_IN} — an untouched save rewrote ${stored}`,
      ).toBe(stored);
    }

    // In a DST-observing zone, the pair of control values is genuinely shared:
    // stated as its own assertion so the DST leg of the gate is provably doing
    // something the UTC leg cannot.
    if (RUNNING_IN === 'America/New_York') {
      expect(ambiguous).toBe(true);
      expect(controlsFor(first)).toEqual(controlsFor(second));
    }
  });

  it('rewrites neither instant of any ambiguous hour it can find in the year', () => {
    // Every hour of every DST transition in a 20-year window, rather than one
    // hand-picked date: a zone whose transition rules change (they do — Congress
    // has legislated on this twice) would otherwise silently stop being tested.
    fc.assert(
      fc.property(fc.integer({ min: 2000, max: 2040 }), (year) => {
        const pairs = ambiguousInstantsIn(year);
        for (const [first, second] of pairs) {
          for (const instant of [first, second]) {
            const stored = instant.toISOString();
            const { date, time } = controlsFor(instant);
            expect(
              combineExpiry(date, time, stored),
              `${propertyBanner()} — ${stored} was rewritten (${date} ${time}, TZ=${RUNNING_IN})`,
            ).toBe(stored);
          }
        }
        // Under a DST-observing zone there is at least one such hour per year;
        // under UTC there are none, and the loop above is vacuous. Asserted so the
        // difference is visible in the report rather than hidden.
        if (RUNNING_IN === 'America/New_York') {
          expect(pairs.length, propertyBanner()).toBeGreaterThan(0);
        }
      }),
      propertyRun({ numRuns: 20 }),
    );
  });
});

/**
 * Every pair of distinct instants in `year` that render to the SAME local date
 * and time — i.e. the repeated minutes of a fall-back transition.
 *
 * Found by scanning at 30-minute resolution and comparing each candidate with the
 * instant one hour later, which is the shape every fall-back transition takes.
 * Deliberately derived from the runtime's own zone data rather than hard-coded:
 * that is what makes it correct in UTC (it finds nothing) and in a zone whose
 * rules differ from the United States'.
 */
function ambiguousInstantsIn(year: number): [Date, Date][] {
  const HALF_HOUR = 30 * 60_000;
  const HOUR = 60 * 60_000;
  const start = Date.UTC(year, 0, 1);
  const end = Date.UTC(year + 1, 0, 1);
  const found: [Date, Date][] = [];

  for (let time = start; time < end; time += HALF_HOUR) {
    const first = new Date(time);
    const later = new Date(time + HOUR);
    if (
      localDateValue(first) === localDateValue(later) &&
      localTimeValue(first) === localTimeValue(later)
    ) {
      found.push([first, later]);
    }
  }
  return found;
}
