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
