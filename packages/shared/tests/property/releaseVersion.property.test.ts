/**
 * The release-version comparator, as PROPERTIES.
 *
 * `compareReleaseVersions` decides whether a user has seen a release's notes and
 * whether GitHub has a newer release than this server. Both decisions need it to
 * be a TOTAL ORDER over every version the parser accepts: reflexive, antisymmetric,
 * transitive, and in agreement with comparing the numeric parts left to right. A
 * comparator that disagreed with itself on some pair would make "newer than" depend
 * on which operand came first, and a watermark could move backwards.
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { compareReleaseVersions, parseReleaseVersion } from '../../src/utils/releaseVersion.js';
import { propertyBanner, propertyRun } from '../../../../tests/harness/property.js';

/** A version part, biased towards the edges: 0, single digits, and the six-digit cap. */
const part = fc.oneof(
  fc.constantFrom(0, 1, 9, 10, 99, 100, 999999),
  fc.integer({ min: 0, max: 999999 }),
);
const parts = fc.tuple(part, part, part);
const version = parts.map(([major, minor, patch]) => `${major}.${minor}.${patch}`);

function tupleOrder(a: readonly number[], b: readonly number[]): number {
  for (let i = 0; i < a.length; i += 1) {
    const difference = (a[i] ?? 0) - (b[i] ?? 0);
    if (difference !== 0) return Math.sign(difference);
  }
  return 0;
}

describe('release version order (property)', () => {
  it('round-trips every generated version through the parser', () => {
    fc.assert(
      fc.property(parts, ([major, minor, patch]) => {
        expect(parseReleaseVersion(`${major}.${minor}.${patch}`), propertyBanner()).toEqual([
          major,
          minor,
          patch,
        ]);
      }),
      propertyRun(),
    );
  });

  it('agrees with comparing the numeric parts left to right', () => {
    fc.assert(
      fc.property(parts, parts, (a, b) => {
        expect(compareReleaseVersions(a.join('.'), b.join('.')), propertyBanner()).toBe(
          tupleOrder(a, b),
        );
      }),
      propertyRun(),
    );
  });

  it('is reflexive and antisymmetric', () => {
    fc.assert(
      fc.property(version, version, (a, b) => {
        expect(compareReleaseVersions(a, a), propertyBanner()).toBe(0);
        expect(compareReleaseVersions(a, b), propertyBanner()).toBe(
          -compareReleaseVersions(b, a) || 0,
        );
      }),
      propertyRun(),
    );
  });

  it('is transitive', () => {
    fc.assert(
      fc.property(version, version, version, (a, b, c) => {
        const [low, mid, high] = [a, b, c].sort(compareReleaseVersions);
        expect(compareReleaseVersions(low!, high!) <= 0, propertyBanner()).toBe(true);
        expect(compareReleaseVersions(low!, mid!) <= 0, propertyBanner()).toBe(true);
        expect(compareReleaseVersions(mid!, high!) <= 0, propertyBanner()).toBe(true);
      }),
      propertyRun(),
    );
  });
});
