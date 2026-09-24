/**
 * Reading a Stryker report as EVIDENCE, and holding it to a recorded floor.
 *
 * Two gates read Stryker reports: `test:mutation`, the campaign over the whole
 * declared scope, and `test:mutation:diff`, the per-change leg over the lines a
 * change touched. They must agree on what a score IS, so the definition lives
 * here once rather than in each of them:
 *
 *  a. THE SCORE IS COMPUTED FROM THE PER-MUTANT STATUSES, never taken from a
 *     headline the report states about itself. Killed and Timeout count as
 *     detected (a suite that hangs on a mutation has noticed it); Survived and
 *     NoCoverage count against; every other status — `Ignored` above all — is
 *     excluded from BOTH halves, because it is a mutant a configuration chose
 *     not to test. That exclusion is why the denominator (`totalMutants`) is a
 *     ratcheted field in its own right: shrinking what gets tested shows up as a
 *     smaller denominator even when the percentage rises.
 *
 *  b. A FLOOR IS FOUR CHECKS, NOT ONE. A score over less code is not the same
 *     score, so a unit (one leg, or the merged campaign) regresses when a file
 *     it used to mutate is no longer mutated, when it tests fewer mutants, when
 *     its score falls, or when one of its core modules falls or stops being
 *     measured at all. Each is reported separately, because each asks for a
 *     different remedy.
 *
 *  c. NOTHING HERE READS THE FILESYSTEM OR EXITS. The gates own the process
 *     boundary; this module is pure so the arithmetic that decides a verdict can
 *     be driven directly by a test instead of through a Stryker run that takes
 *     minutes at best.
 */
import { moduleKey } from './mutation-scope.mjs';

/** Statuses that count as a kill, and the ones that count against the suite. */
export const KILLED_STATUSES = new Set(['Killed', 'Timeout']);
export const ALIVE_STATUSES = new Set(['Survived', 'NoCoverage']);

/** A percentage to two places; `0` over an empty denominator, never `NaN`. */
export const pct = (killed, total) => (total > 0 ? +((killed / total) * 100).toFixed(2) : 0);

/**
 * @typedef {{ killed: number, total: number, ignored: number }} FileStats
 * @typedef {{ file: string, line: number, mutator: string, replacement: string, status: string }} Survivor
 * @typedef {{ perFile: Map<string, FileStats>, byStatus: Record<string, number>, alive: Survivor[] }} Tally
 */

/** @returns {Tally} an empty tally to accumulate one or more reports into */
export const createTally = () => ({ perFile: new Map(), byStatus: {}, alive: [] });

/**
 * Adds one Stryker `mutation-testing-report-schema` document to a tally.
 *
 * @param {{ files?: Record<string, { mutants?: { status: string, mutatorName?: string, replacement?: unknown, location?: { start?: { line?: number } } }[] }> }} report
 * @param {Tally} [tally]
 * @param {{ ignoredIsAlive?: boolean }} [options] `ignoredIsAlive` counts an
 *   `Ignored` mutant AGAINST the suite instead of leaving it out. The per-change
 *   leg sets it: there, the only way to get an `Ignored` mutant is a directive
 *   comment on the very lines the change touched, and a change must not be able
 *   to excuse its own mutants by writing one.
 * @returns {Tally}
 */
export function tallyReport(report, tally = createTally(), { ignoredIsAlive = false } = {}) {
  for (const [file, entry] of Object.entries(report.files ?? {})) {
    const stats = tally.perFile.get(file) ?? { killed: 0, total: 0, ignored: 0 };
    for (const mutant of entry.mutants ?? []) {
      tally.byStatus[mutant.status] = (tally.byStatus[mutant.status] ?? 0) + 1;
      if (KILLED_STATUSES.has(mutant.status)) {
        stats.killed++;
        stats.total++;
      } else if (
        ALIVE_STATUSES.has(mutant.status) ||
        (ignoredIsAlive && mutant.status === 'Ignored')
      ) {
        stats.total++;
        tally.alive.push({
          file,
          line: mutant.location?.start?.line ?? 0,
          mutator: String(mutant.mutatorName ?? ''),
          replacement: String(mutant.replacement ?? '').slice(0, 120),
          status: mutant.status,
        });
      } else {
        stats.ignored++;
      }
    }
    tally.perFile.set(file, stats);
  }
  return tally;
}

/**
 * The four numbers a floor is made of, for one tally.
 *
 * Core modules are PATH PREFIXES over the measured file set, so a new file
 * inside one joins it automatically; a module with no mutants in this tally is
 * absent rather than 0, because "not measured here" and "measured and nothing
 * was killed" are different claims.
 *
 * @param {Tally} tally
 * @param {readonly string[]} coreModules
 */
export function summariseTally(tally, coreModules) {
  let killed = 0;
  let total = 0;
  for (const stats of tally.perFile.values()) {
    killed += stats.killed;
    total += stats.total;
  }
  /** @type {Record<string, number>} */
  const modules = {};
  for (const modulePath of coreModules) {
    let moduleKilled = 0;
    let moduleTotal = 0;
    for (const [file, stats] of tally.perFile) {
      if (file.startsWith(modulePath)) {
        moduleKilled += stats.killed;
        moduleTotal += stats.total;
      }
    }
    if (moduleTotal > 0) modules[moduleKey(modulePath)] = pct(moduleKilled, moduleTotal);
  }
  return {
    overall: pct(killed, total),
    killed,
    totalMutants: total,
    filesMutated: [...tally.perFile.keys()].sort(),
    modules,
  };
}

/**
 * The per-file statuses in the shape `ratchet-check.mjs` reads.
 *
 * The ratchet RECOMPUTES the score from these rather than trusting the headline
 * a report states, so they are what the second reader of the evidence checks
 * the first against. The order within a file carries no meaning.
 *
 * @param {Tally} tally
 */
export function evidenceFiles(tally) {
  return Object.fromEntries(
    [...tally.perFile.keys()].sort().map((file) => {
      const stats = /** @type {FileStats} */ (tally.perFile.get(file));
      return [
        file,
        {
          mutants: [
            ...Array.from({ length: stats.killed }, () => ({ status: 'Killed' })),
            ...Array.from({ length: stats.total - stats.killed }, () => ({ status: 'Survived' })),
            ...Array.from({ length: stats.ignored }, () => ({ status: 'Ignored' })),
          ],
        },
      ];
    }),
  );
}

/** Every survivor, sorted so the list reads as a triage queue and diffs cleanly. */
export const sortedSurvivors = (tally) =>
  [...tally.alive].sort(
    (a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.mutator.localeCompare(b.mutator),
  );

/**
 * Has a floor been recorded for this unit at all? The two load-bearing fields,
 * and nothing weaker: a unit carrying a score without its measured file set would
 * be a floor whose scope-narrowing defence is off.
 *
 * @param {{ overall?: unknown, filesMutated?: unknown } | undefined} recorded
 */
export const isBanked = (recorded) =>
  typeof recorded?.overall === 'number' && Array.isArray(recorded?.filesMutated);

/**
 * (b) The ways a measured unit falls short of its recorded floor.
 *
 * @param {string} label who is speaking, e.g. `shared` or `merged`
 * @param {{ overall?: number, totalMutants?: number, filesMutated?: string[], modules?: Record<string, number> }} recorded
 * @param {{ overall: number, totalMutants: number, filesMutated: string[], modules: Record<string, number> }} measured
 * @returns {string[]} one line per failure; empty when the floor holds
 */
export function floorFailures(label, recorded, measured) {
  const failures = [];
  const lost = (recorded.filesMutated ?? []).filter(
    (file) => !measured.filesMutated.includes(file),
  );
  if (lost.length > 0) {
    failures.push(
      `${label}: scope narrowed: ${String(lost.length)} file(s) are no longer mutated, e.g. ${lost.slice(0, 3).join(', ')}`,
    );
  }
  if (typeof recorded.totalMutants === 'number' && measured.totalMutants < recorded.totalMutants) {
    failures.push(
      `${label}: denominator shrank: ${String(measured.totalMutants)} mutants tested, baseline ${String(recorded.totalMutants)}`,
    );
  }
  if (typeof recorded.overall === 'number' && measured.overall < recorded.overall) {
    failures.push(
      `${label}: overall ${String(measured.overall)}% is below the recorded ${String(recorded.overall)}%`,
    );
  }
  for (const [key, want] of Object.entries(recorded.modules ?? {})) {
    const got = measured.modules[key];
    if (got === undefined) {
      failures.push(`${label}: core module ${key} was not measured at all`);
    } else if (got < want) {
      failures.push(
        `${label}: core module ${key}: ${String(got)}% is below the recorded ${String(want)}%`,
      );
    }
  }
  return failures;
}
