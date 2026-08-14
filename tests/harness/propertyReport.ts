/**
 * Where each leg of the `test:property` gate writes its JUnit report.
 *
 * The gate runs SIX vitest invocations: one per package, twice over — once in
 * `UTC` and once in `America/New_York` (see `DST_TZ` in `./determinism.ts` for
 * why the second zone is not optional). Each leg therefore needs its OWN report
 * name, and the reason is the one `vitest.security.config.ts` records: a run
 * that writes another run's report overwrites evidence, and a gate whose
 * evidence is the LAST leg's is a gate that has quietly stopped covering the
 * other five.
 *
 * Kept in its own module, importing nothing but the zone, so a vitest CONFIG can
 * use it without pulling fast-check into config-load time.
 */
import { DST_TZ, PINNED_TZ, RUN_TZ } from './determinism.js';

/** The workspaces that carry a property suite. */
export const PROPERTY_PACKAGES = ['shared', 'server', 'client'] as const;

export type PropertyPackage = (typeof PROPERTY_PACKAGES)[number];

/**
 * The short name for a zone, used in a report file name.
 *
 * A zone identifier contains a `/` and is therefore not a legal path segment, so
 * it is mapped rather than interpolated — `junit-property-shared-America/New_York.xml`
 * would land in a directory that does not exist and the gate would report a
 * missing report instead of a failing property.
 */
export function zoneSuffix(zone: string = RUN_TZ): string {
  return zone === DST_TZ ? 'dst' : 'utc';
}

/** The JUnit report name for one leg: package × zone. */
export function propertyJunitReport(pkg: PropertyPackage, zone: string = RUN_TZ): string {
  return `junit-property-${pkg}-${zoneSuffix(zone)}.xml`;
}

/**
 * Every report name the gate must produce, in the order the gate runs them.
 *
 * `gate-surface.test.ts` compares this against what `.testfortress/verify.json`
 * declares for `test:property`, in BOTH directions: a leg that stops writing its
 * report and a declared report no leg writes are the same defect seen from two
 * sides, and only comparing both catches either.
 */
export function allPropertyJunitReports(): string[] {
  // Zone-major, matching the gate's own loop: all three packages in UTC, then
  // all three in the DST zone.
  return [PINNED_TZ, DST_TZ].flatMap((zone) =>
    PROPERTY_PACKAGES.map((pkg) => propertyJunitReport(pkg, zone)),
  );
}
