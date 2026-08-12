#!/usr/bin/env node
/**
 * The `report` task — turns the gates' artifacts into `warnings.json`.
 *
 * Warning counts have no industry format, and they are the numbers most likely
 * to end up unmeasured; an unmeasured number is an ungated one. So this writes
 * a flat map keyed by CANONICAL TASK NAME — `lint`, `typecheck`, `compiler` —
 * and never by tool name. A key called `eslint` would never satisfy a baseline
 * that declares `warnings.lint`, and the result would be a permanently red gate
 * on a perfectly clean tree.
 *
 * A count is `null` when the run that produced these artifacts did not include
 * the gate that measures it (`verify:fast` runs no build, so `compiler` is
 * unknown there). `null` means UNMEASURED and is deliberately not `0`: a
 * fabricated zero is indistinguishable from a real one, and the whole point of
 * the ratchet is that it can tell the difference.
 *
 * That last part is why "did this gate run?" is answered by `summary.json` and
 * NOT by "is the artifact on disk?". The runner only clears the reports of the
 * gates it SELECTED, so a `verify:fast` run leaves the previous full run's
 * `build.log` sitting there — and reading it would report a stale count as a
 * freshly measured one, which is exactly the lie the `null` exists to prevent.
 *
 *   node scripts/ci/report.mjs      (also run automatically at the end of a
 *                                    pipeline run)
 */
import { countLevels } from './lib/sarif.mjs';
import { readJsonReport, readTextReport, writeJsonReport } from './lib/reports.mjs';
import { color, note } from './lib/ui.mjs';

/**
 * Which canonical tasks the last run actually executed. A task that was skipped
 * ("not reached", `HVAULT_SKIP_GATES`, tooling unavailable) measured nothing, so
 * it counts as absent here too.
 *
 * With no summary at all — a bare `npm run report` in a fresh tree — nothing is
 * claimed to have run, so every count is `null`. Under-claiming is the safe
 * direction: the ratchet treats an unmeasured field as a failure, which is a
 * loud, fixable outcome, whereas a stale number is a silent wrong one.
 */
const summary = readJsonReport('summary.json');
const measured = new Set(
  (summary?.tasks ?? [])
    .filter((task) => task.status === 'pass' || task.status === 'fail')
    .map((task) => task.task),
);
const ran = (task) => measured.has(task);

/** A tsc diagnostic. tsc has no warning level of its own; every one is an error. */
const TSC_DIAGNOSTIC = /\b(?:error|warning) TS\d+\b/g;

/**
 * A build-time compiler warning, as each tool in this toolchain spells it.
 * npm's own `npm warn ...` notices are excluded: they are the package manager
 * talking, not the compiler, and counting them would make `warnings.compiler`
 * regress on an npm upgrade that says something new.
 */
const COMPILER_WARNING = [
  /\bwarning TS\d+\b/, // tsc
  /^\s*\(!\)/, // rollup / rolldown
  /\[WARNING\]/, // esbuild ("▲ [WARNING] …")
  /^\s*warning:/i, // generic toolchain line
];

const countMatches = (text, pattern) => (text.match(pattern) ?? []).length;

function lintWarnings() {
  if (!ran('lint')) return null;
  const sarif = readJsonReport('eslint.sarif');
  return sarif === null ? null : countLevels(sarif).warning;
}

function typecheckWarnings() {
  if (!ran('typecheck')) return null;
  const log = readTextReport('tsc.log');
  return log === null ? null : countMatches(log, TSC_DIAGNOSTIC);
}

function compilerWarnings() {
  if (!ran('build')) return null;
  const log = readTextReport('build.log');
  if (log === null) return null;
  return log
    .split(/\r?\n/)
    .filter((line) => !/^\s*npm\s+(?:warn|WARN)\b/.test(line))
    .filter((line) => COMPILER_WARNING.some((pattern) => pattern.test(line))).length;
}

const warnings = {
  lint: lintWarnings(),
  typecheck: typecheckWarnings(),
  compiler: compilerWarnings(),
};

writeJsonReport('warnings.json', warnings);

const render = (value) => (value === null ? color.yellow('unmeasured') : String(value));
note(
  `warnings.json — lint ${render(warnings.lint)} · typecheck ${render(warnings.typecheck)} · compiler ${render(warnings.compiler)}`,
);
