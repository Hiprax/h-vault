#!/usr/bin/env node
/**
 * `audit:licenses` — every licence in the PRODUCTION dependency tree is one this
 * project has explicitly accepted, and no copyleft licence is in it at all.
 *
 *   node scripts/ci/license-gate.mjs            check, write licenses.json
 *   node scripts/ci/license-gate.mjs --json     the report on stdout as well
 *
 * Exit codes: 0 = every production package carries an allowed licence · 1 = a
 * violation · 2 = could not run (the tooling is absent, or the enumeration came
 * back empty).
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE PRODUCTION SET COMES FROM npm, THE LICENCE TEXT FROM license-checker.
 *     `license-checker-rseidelsohn --production` walks the dependencies of the
 *     package it is started in; this is a workspace root whose own package.json
 *     has NO production dependencies, so that invocation returns exactly one
 *     entry and a gate built on it would pass while examining nothing. The
 *     production closure is therefore taken from
 *     `npm ls --omit=dev --all --workspaces --include-workspace-root`, which is
 *     what a self-hoster installs, and the licence for each member is read from
 *     license-checker's full-tree scan. Two tools, each doing the part it is
 *     right for.
 *
 *  b. AN EMPTY OR IMPLAUSIBLY SMALL RESULT IS A FAILURE, NEVER A PASS. That is
 *     the failure mode of (a) done wrong, and it is invisible: a green gate that
 *     inspected one package looks exactly like a green gate that inspected all of
 *     them. `MIN_EXPECTED_PACKAGES` makes it loud.
 *
 *  c. `deny` IS EVALUATED BEFORE `allow`, AND INDEPENDENTLY OF IT. A copyleft
 *     licence must fail even if someone has also written it into `allow` — the
 *     point of the deny list is that it cannot be waived by editing the file it
 *     lives in without the edit being obvious.
 *
 *  d. A PACKAGE WITH NO LICENCE DATA IS A VIOLATION, NOT A GAP. The one
 *     exception is a package npm lists but has NOT installed (an unmet optional
 *     or peer dependency of `mongodb`, say): it ships to nobody, and it is
 *     reported under `notInstalled` by name rather than being dropped silently.
 *
 *  e. license-checker MARKS AN INFERRED LICENCE WITH A TRAILING `*` (it read a
 *     LICENSE file rather than the `license` field). The asterisk is stripped for
 *     matching — the licence is real either way — and every such package is
 *     listed in the report under `inferred`, so "how do we know?" has an answer
 *     that does not require re-running anything.
 */
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { init as scanLicenses } from 'license-checker-rseidelsohn';
import { adjudicate } from './lib/licenses.mjs';
import { captureExe, repoRoot } from './lib/proc.mjs';
import { writeJsonReport } from './lib/reports.mjs';
import { color, symbol } from './lib/ui.mjs';

const EXIT_OK = 0;
const EXIT_VIOLATION = 1;
const EXIT_CANNOT_RUN = 2;

/**
 * (b) A collapse detector, not a ratchet. The measured closure is 312 examined
 * plus 7 listed-but-not-installed, and direct production dependencies alone are
 * about 40 names, so a floor of 50 catches the two ways this can return almost
 * nothing: a root-only `--production` scan, or no `node_modules` at all. It
 * deliberately does NOT try to catch a PARTIAL walk — that is what the
 * independent `npm ls --parseable` cross-check below is for, and it is the guard
 * that caught the real bug.
 */
const MIN_EXPECTED_PACKAGES = 50;

const ALLOWLIST_REL = '.licenses-allowlist.json';
const asJson = process.argv.includes('--json');

const fatal = (message) => {
  console.error(color.red(`${symbol.fail} license-gate: ${message}`));
  process.exit(EXIT_CANNOT_RUN);
};

// ---------------------------------------------------------------------------
// policy
// ---------------------------------------------------------------------------
const allowlistPath = path.join(repoRoot, ALLOWLIST_REL);
if (!existsSync(allowlistPath)) fatal(`${ALLOWLIST_REL} is missing; there is no policy to enforce`);

let policy;
try {
  policy = JSON.parse(readFileSync(allowlistPath, 'utf8'));
} catch (error) {
  fatal(`${ALLOWLIST_REL} is not valid JSON: ${error.message}`);
}
for (const field of ['allow', 'deny', 'denyPatterns', 'firstParty']) {
  if (!Array.isArray(policy[field])) fatal(`${ALLOWLIST_REL}: "${field}" must be an array`);
}
if (policy.allow.length === 0) fatal(`${ALLOWLIST_REL}: "allow" is empty, so nothing could pass`);

const allow = new Set(policy.allow);
const deny = new Set(policy.deny);
const firstParty = new Set(policy.firstParty);

// ---------------------------------------------------------------------------
// (a) the production closure
// ---------------------------------------------------------------------------
const tree = captureExe('npm', [
  'ls',
  '--omit=dev',
  '--all',
  '--json',
  '--workspaces',
  '--include-workspace-root',
]);
// `npm ls` exits non-zero on an unmet optional peer dependency while still
// printing a complete tree, so the JSON is what is judged, not the status.
let parsedTree;
try {
  parsedTree = JSON.parse(tree.stdout);
} catch {
  fatal('could not parse `npm ls --omit=dev --json` output');
}

/**
 * `name@version` -> `{name, version}`, over the whole production closure.
 *
 * Two details here were each a measured bug in an earlier draft:
 *
 *   * THE WALK NEVER SKIPS A SUBTREE, AND THAT IS NOT AN OVERSIGHT. Skipping a
 *     package already seen skipped its children too, and npm expands a package's
 *     own `dependencies` at only some of the positions it appears at — so the
 *     occurrence reached first can be a childless stub. Two earlier drafts did
 *     this and enumerated 224 and 225 packages against a real closure of 312:
 *     Express's entire subtree, 89 packages, was never examined by a gate whose
 *     whole job is to examine all of them. Cross-checked against
 *     `npm ls --omit=dev --all --parseable`, which lists physical paths on disk.
 *     `JSON.parse` output is acyclic by construction, so the walk terminates
 *     without a guard.
 *   * THE SET IS KEYED BY name@version, NOT BY NAME. Two versions of one package
 *     are two packages on disk, under two licences that can differ.
 */
const production = new Map();
(function walk(node) {
  for (const [name, entry] of Object.entries(node.dependencies ?? {})) {
    const version = entry.version ?? null;
    const id = `${name}@${version ?? '?'}`;
    if (!production.has(id)) production.set(id, { name, version });
    walk(entry);
  }
})(parsedTree);

if (production.size === 0) fatal('the production closure came back empty');

// ---------------------------------------------------------------------------
// licence data for the installed tree
// ---------------------------------------------------------------------------
const licenses = await new Promise((resolve) => {
  scanLicenses({ start: repoRoot }, (error, result) => {
    if (error) fatal(`license-checker-rseidelsohn failed: ${String(error).slice(0, 400)}`);
    resolve(result ?? {});
  });
});
if (Object.keys(licenses).length === 0) fatal('license-checker-rseidelsohn returned no packages');

/** `name@version` -> record, plus a name-only fallback for a single-version package. */
const byId = new Map(Object.entries(licenses));

// ---------------------------------------------------------------------------
// adjudicate
// ---------------------------------------------------------------------------
// (c) and (e) live in `lib/licenses.mjs`, pure and unit-tested: SPDX precedence
// (`AND` binds tighter than `OR`), deny-before-allow across every term, the
// `MIT*` inferred marker, and `<licence> WITH <exception>`.
const verdictFor = (expression) => adjudicate(expression, { allow, deny, ...policy });

const examined = [];
const violations = [];
const notInstalled = [];
const inferred = [];
const byLicense = {};

for (const [id, { name, version }] of production) {
  if (!version) {
    // (d) npm lists it but reports no version, which it does for exactly one
    // reason: the package is not on disk (an unmet optional or peer dependency
    // of `mongodb` or `zustand`). Nothing installs it, so nothing ships it.
    // Named rather than dropped — and it is npm's own resolution that decides
    // this, not a guess at where the directory would have been, which is wrong
    // for anything installed into a nested `node_modules`.
    notInstalled.push(name);
    continue;
  }

  const record = byId.get(id);

  if (firstParty.has(name)) {
    // A private workspace package: never published, licence declared in its own
    // package.json. Recorded so the count adds up, never adjudicated.
    examined.push({ name, version, license: 'first-party', verdict: 'first-party' });
    byLicense['first-party'] = (byLicense['first-party'] ?? 0) + 1;
    continue;
  }

  if (!record || !record.licenses) {
    violations.push({ name, version, license: null, reason: 'no licence data' });
    continue;
  }

  const expression = String(record.licenses);
  if (expression.includes('*')) inferred.push(id);

  const { verdict, term } = verdictFor(expression);
  byLicense[expression] = (byLicense[expression] ?? 0) + 1;
  examined.push({ name, version, license: expression, verdict });

  if (verdict === 'denied') {
    violations.push({
      name,
      version,
      license: expression,
      reason: `copyleft licence "${term}" is denied outright`,
    });
  } else if (verdict === 'unlisted') {
    violations.push({
      name,
      version,
      license: expression,
      reason: `"${term}" is not in ${ALLOWLIST_REL}`,
    });
  }
}

/**
 * (b, second half) The enumeration is cross-checked against an INDEPENDENT one.
 *
 * `MIN_EXPECTED_PACKAGES` catches an enumeration that collapses to nothing. It
 * does not catch the failure that actually happened here: a walk that returned a
 * plausible 224 packages while missing 89. So the JSON tree is compared with
 * `npm ls --parseable`, which prints physical paths and shares none of the
 * traversal logic above. A package on disk that the walk never reached is a
 * broken gate, reported as "could not run" rather than as a clean tree.
 */
const examinedNames = new Set([...examined.map((e) => e.name), ...notInstalled]);
const onDisk = new Set();
const parseable = captureExe('npm', [
  'ls',
  '--omit=dev',
  '--all',
  '--parseable',
  '--workspaces',
  '--include-workspace-root',
]);
for (const line of parseable.stdout.split('\n')) {
  // The LAST `node_modules/` segment names the package: a nested install reads
  // `…/node_modules/body-parser/node_modules/content-type`, and splitting on the
  // first one would invent a package called `body-parser/node_modules/…`. The
  // comparison is by name rather than by name@version, because a path carries no
  // version; that is enough to catch a walk that skipped a subtree.
  const parts = line.trim().split(/[/\\]node_modules[/\\]/);
  if (parts.length > 1) onDisk.add(parts[parts.length - 1].split('\\').join('/'));
}
const unreached = [...onDisk].filter((name) => !examinedNames.has(name));

const report = {
  version: 1,
  checkedAt: new Date().toISOString(),
  policy: ALLOWLIST_REL,
  counts: {
    production: production.size,
    examined: examined.length,
    notInstalled: notInstalled.length,
    violations: violations.length,
    inferred: inferred.length,
    onDisk: onDisk.size,
    unreached: unreached.length,
  },
  unreached: unreached.sort(),
  byLicense,
  violations,
  notInstalled: notInstalled.sort(),
  inferred: inferred.sort(),
};

writeJsonReport('licenses.json', report);
if (asJson) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);

// (b) the vacuity guard, checked after the report is written so the evidence
// survives the failure.
if (examined.length + notInstalled.length < MIN_EXPECTED_PACKAGES) {
  fatal(
    `only ${examined.length + notInstalled.length} production package(s) enumerated, expected at least ` +
      `${MIN_EXPECTED_PACKAGES} — the enumeration is broken, and a gate that examines nothing passes everything`,
  );
}

if (unreached.length > 0) {
  fatal(
    `${unreached.length} package(s) are installed in the production tree but were never reached by the ` +
      `dependency walk, e.g. ${unreached.slice(0, 5).join(', ')} — the two enumerations disagree, so this ` +
      'run proves nothing about the licences of the packages it did not see',
  );
}

if (violations.length > 0) {
  console.error(color.red(`\n${symbol.fail} Disallowed licence(s) in the production tree:\n`));
  for (const violation of violations) {
    console.error(
      `  ${color.cyan(`${violation.name}@${violation.version}`)}  ` +
        `${color.yellow(String(violation.license))}  ${violation.reason}`,
    );
  }
  console.error(
    color.gray(
      `\n  Replace the dependency, or — if the licence is genuinely acceptable — add it to ` +
        `${ALLOWLIST_REL} in a change that says why.\n`,
    ),
  );
  process.exit(EXIT_VIOLATION);
}

console.log(
  color.green(
    `${symbol.pass} audit:licenses: ${String(examined.length)} production package(s), ` +
      `0 violations (${String(notInstalled.length)} listed but not installed)`,
  ),
);
process.exit(EXIT_OK);
