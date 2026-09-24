/**
 * The verdict over a browser run of the sandbox specs, shared by the two gates
 * that make one: `test:sandbox` (the built artifact, served by Express in
 * production mode) and `test:deploy` (the Compose stack, behind its own Nginx).
 *
 * Pure functions over the JUnit document Playwright writes, so the judgement is
 * unit-tested on its own (`packages/server/tests/sandbox-gate.test.ts`) instead of
 * being trusted to two gate scripts that each take minutes to run.
 *
 * ---------------------------------------------------------------------------
 * WHY A GREEN EXIT CODE IS NOT ENOUGH
 * ---------------------------------------------------------------------------
 *
 * Playwright exits 0 for a run that executed nothing it was asked to. A
 * `testMatch` entry that has gone stale matches nothing and is ignored while the
 * other one still runs (it errors only when NOTHING matches — the trap
 * `playwright.a11y.config.ts` records), and a `test.skip` or a `test.fixme` left
 * in a spec is reported as skipped, not failed. Either way the gate would say
 * "the isolated document renders under the production headers" having rendered
 * less than it claims. So the run's own report must name every file in the suite,
 * each with at least one executed test, and nothing skipped anywhere.
 */

/**
 * The files the sandbox browser run executes. Mirrors `SANDBOX_SUITE` in
 * `playwright.sandbox.config.ts`, restated rather than imported for the reason
 * `a11y-gate.mjs` restates its own: this file is plain ESM and the config is
 * TypeScript. `gate-surface.test.ts` holds the two equal.
 */
export const SANDBOX_SUITE = Object.freeze(['document-viewer.spec.ts', 'sandbox-policy.prod.ts']);

/** Where the Express run writes its JUnit document, relative to the report directory. */
export const SANDBOX_JUNIT = 'junit-sandbox.xml';

/**
 * Where the Nginx leg inside `test:deploy` writes its own, so neither run
 * overwrites the other's evidence. Selected in the config by
 * `HVAULT_SANDBOX_LEG=nginx`; nothing else is accepted.
 */
export const SANDBOX_NGINX_JUNIT = 'junit-sandbox-nginx.xml';

/** Read one numeric attribute off a `<testsuite …>` start tag, or 0 when it is absent. */
function numericAttribute(tag, name) {
  const match = new RegExp(`\\s${name}="(\\d+)"`).exec(tag);
  return match ? Number(match[1]) : 0;
}

/**
 * Every `<testsuite>` in a Playwright JUnit document, by file name.
 *
 * Suites of the same name are SUMMED rather than overwritten: a second project
 * over the same file writes a second element, and a later element replacing an
 * earlier one would hide the earlier one's failures.
 *
 * @param {string} xml
 * @returns {Map<string, {tests: number, failures: number, errors: number, skipped: number}>}
 */
export function summariseJunit(xml) {
  const suites = new Map();
  for (const match of xml.matchAll(/<testsuite\s[^>]*>/g)) {
    const tag = match[0];
    const name = /\sname="([^"]*)"/.exec(tag)?.[1];
    if (name === undefined) continue;
    const previous = suites.get(name) ?? { tests: 0, failures: 0, errors: 0, skipped: 0 };
    suites.set(name, {
      tests: previous.tests + numericAttribute(tag, 'tests'),
      failures: previous.failures + numericAttribute(tag, 'failures'),
      errors: previous.errors + numericAttribute(tag, 'errors'),
      skipped: previous.skipped + numericAttribute(tag, 'skipped'),
    });
  }
  return suites;
}

/**
 * What is wrong with a run, as sentences; an empty list is a complete, green run.
 *
 * `xml` is `null` when the run wrote no report at all, which is its own finding:
 * a Playwright that crashed on its config writes nothing, and "no failures in a
 * report that does not exist" must never read as a pass.
 *
 * @param {string | null} xml
 * @param {readonly string[]} suite
 * @returns {string[]}
 */
export function sandboxRunProblems(xml, suite = SANDBOX_SUITE) {
  if (xml === null) return ['the run wrote no JUnit report, so nothing proves any spec ran'];
  const suites = summariseJunit(xml);
  const problems = [];
  for (const file of suite) {
    const found = suites.get(file);
    if (!found) {
      problems.push(`no results for ${file} — the suite has shrunk`);
      continue;
    }
    const executed = found.tests - found.skipped;
    if (executed < 1) problems.push(`${file} executed no test`);
    if (found.skipped > 0) problems.push(`${file} skipped ${String(found.skipped)} test(s)`);
    if (found.failures + found.errors > 0) {
      problems.push(`${file} failed ${String(found.failures + found.errors)} test(s)`);
    }
  }
  for (const name of suites.keys()) {
    if (!suite.includes(name)) problems.push(`${name} ran, but is not in the declared suite`);
  }
  return problems;
}
