#!/usr/bin/env node
/**
 * Lint gate — ESLint, exactly as `npm run lint` runs it, plus a SARIF report.
 *
 * Why this exists rather than `eslint . -f sarif -o report.sarif`: `-o` sends
 * the formatted output to the FILE INSTEAD OF the terminal, so a failing lint
 * gate would print nothing at all and the developer would have to open a report
 * to find out what broke. ESLint cannot write two formats in one run from the
 * CLI, and running it twice doubles a 30-second gate. Driving the Node API
 * instead lints once and renders that single result twice: `stylish` to the
 * terminal, SARIF to `.testfortress/reports/eslint.sarif`.
 *
 * The gate is `--max-warnings=0`, spelled out: any error OR any warning fails.
 * Warnings were invisible on the hosted runner (`eslint .` exits 0 on them);
 * running locally they are cheap enough to forbid outright, and the count is
 * what `warnings.lint` in the ratchet's baseline is measured from.
 */
import { ESLint } from 'eslint';
import { repoRoot } from './lib/proc.mjs';
import { ensureReportDir, writeJsonReport, reportPath } from './lib/reports.mjs';
import { toSarif, countLevels } from './lib/sarif.mjs';
import { color, symbol } from './lib/ui.mjs';
import path from 'node:path';

const REPORT = 'eslint.sarif';

ensureReportDir();

/**
 * No `concurrency`, and no `cache`. Both were considered because this is the
 * largest gate in the fast tier; both are recorded here because a negative
 * result nobody wrote down is a negative result the next person pays for again.
 *
 * `concurrency: 'auto'` (ESLint 10.7.0) was measured on the reference machine —
 * four cores, shared with unrelated work, which is the machine this project's
 * budgets are already stated against — on 2026-09-06, over eight interleaved
 * pairs of whole-repository runs:
 *
 *   * wall clock 4-4. Every difference was within 22 %, in both directions, and
 *     which way a pair fell tracked how many cores happened to be free.
 *   * total CPU 65.7 s -> 90.4 s (+37.5 %) and peak RSS 2.34 GB -> 3.28 GB
 *     (+0.95 GB), in EVERY run, at every load. That asymmetry is the whole
 *     finding: the cost is unconditional and the benefit is not.
 *
 * The mechanism is `projectService: true` in `eslint.config.mjs`. A worker gets
 * its own `ConfigLoader`, so the flat config is evaluated once per thread and
 * each thread builds its own TypeScript program over the same three packages.
 * `'auto'` caps the pool at `os.availableParallelism() >> 1` — two threads on
 * four cores — so a second full program is paid for up front to halve the
 * per-thread file count, and it only pays back when two cores are genuinely
 * idle. That is the wrong way round for the tier this gate dominates: T0
 * measures 1m 18s on an idle machine and fits its 90 s budget, and 1m 19s to
 * 2m 44s on a busy one and does not. Concurrency turns spare CPU into wall
 * clock precisely when there is spare CPU, i.e. when the tier already fits,
 * and charges its 37.5 % the rest of the time — the only time the help is
 * wanted.
 *
 * Leaving it off has a second benefit worth keeping: the line at the top of this
 * file claiming the gate runs ESLint "exactly as `npm run lint` runs it" stays
 * true, because `npm run lint` passes no concurrency either.
 *
 * `cache` is refused on correctness grounds rather than on speed. With
 * `projectService: true` the cache key is the linted file, not the files its
 * types come from, so changing a dependency can leave a type-aware rule's
 * verdict stale — a lint gate that reports a clean tree it did not re-examine.
 */
const eslint = new ESLint({ cwd: repoRoot });

let results;
try {
  results = await eslint.lintFiles(['.']);
} catch (error) {
  // A broken config, an unresolvable parser, a missing tsconfig: the gate could
  // not run, which is a different thing from code that fails it.
  console.error(color.red(`\n${symbol.fail} eslint could not run: ${error.message}`));
  process.exit(2);
}

const formatter = await eslint.loadFormatter('stylish');
const rendered = await formatter.format(results);
if (rendered.trim()) console.log(rendered);

const sarif = toSarif(results, {
  version: ESLint.version,
  rulesMeta: eslint.getRulesMetaForResults(results),
  rootDir: repoRoot,
});
writeJsonReport(REPORT, sarif);

const counts = countLevels(sarif);
const errors = results.reduce((total, result) => total + result.errorCount, 0);
const warnings = results.reduce((total, result) => total + result.warningCount, 0);

console.log(
  color.gray(
    `      ${String(results.length)} file(s) linted · ${String(errors)} error(s) · ` +
      `${String(warnings)} warning(s) · ${path.relative(repoRoot, reportPath(REPORT))}`,
  ),
);

// The SARIF is the report a later gate ratchets against, so a disagreement
// between it and ESLint's own counters means the conversion dropped findings —
// which would make a clean-looking report out of a dirty tree.
if (counts.error + counts.warning !== errors + warnings) {
  console.error(
    color.red(
      `\n${symbol.fail} SARIF holds ${String(counts.error + counts.warning)} finding(s) but ESLint reported ${String(errors + warnings)}`,
    ),
  );
  process.exit(2);
}

if (errors > 0 || warnings > 0) {
  console.error(
    color.red(
      `\n${symbol.fail} lint: ${String(errors)} error(s), ${String(warnings)} warning(s) — the gate is --max-warnings=0`,
    ),
  );
  process.exit(1);
}

console.log(color.green(`${symbol.pass} lint: no errors, no warnings`));
