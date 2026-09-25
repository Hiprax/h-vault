/**
 * The verdict `test:sandbox` and the Nginx leg of `test:deploy` pass over a
 * browser run of the sandbox specs (`scripts/ci/lib/sandbox-browser.mjs`).
 *
 * The gates themselves take minutes and need Docker, so what is pinned HERE is
 * the judgement they share, on every push: that a run is complete only when its
 * own JUnit report names every declared file, each having executed a test and
 * skipped none. Each case below is a way Playwright exits 0 — or a way a report
 * can look clean — while the gate would otherwise have claimed more than it
 * rendered.
 *
 * The XML is written out by hand in the shape Playwright's JUnit reporter emits
 * (one `<testsuite>` per spec file, the project name folded into each test name),
 * because the subject is the parser's reading of that shape, not Playwright.
 */
import { describe, expect, it } from 'vitest';
import {
  SANDBOX_JUNIT,
  SANDBOX_NGINX_JUNIT,
  SANDBOX_SUITE,
  sandboxRunProblems,
  summariseJunit,
} from '../../../scripts/ci/lib/sandbox-browser.mjs';

interface SuiteCounts {
  tests?: number;
  failures?: number;
  errors?: number;
  skipped?: number;
}

/** One `<testsuite>` element, as Playwright writes it. */
function suite(name: string, counts: SuiteCounts = {}): string {
  const { tests = 1, failures = 0, errors = 0, skipped = 0 } = counts;
  return (
    `<testsuite name="${name}" timestamp="2026-09-24T03:00:00.000Z" hostname="chromium" ` +
    `tests="${String(tests)}" failures="${String(failures)}" skipped="${String(skipped)}" ` +
    `time="8.1" errors="${String(errors)}">\n` +
    `<testcase name="[chromium] › ${name} › a test" classname="${name}" time="8.1"></testcase>\n` +
    '</testsuite>'
  );
}

function report(...suites: string[]): string {
  return (
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    `<testsuites id="" name="" tests="2" failures="0" skipped="0" errors="0" time="17.7">\n` +
    `${suites.join('\n')}\n</testsuites>\n`
  );
}

const complete = () => report(...SANDBOX_SUITE.map((name) => suite(name)));

describe('the sandbox browser run verdict', () => {
  it('declares the two viewer files, the production-only one outside the default spec pattern', () => {
    expect([...SANDBOX_SUITE]).toEqual(['document-viewer.spec.ts', 'sandbox-policy.prod.ts']);
    // Playwright's default testMatch is `*.spec.*` / `*.test.*`. The policy file
    // must stay outside it, or `test:e2e` would run it against a dev server that
    // sends no policy at all.
    expect(SANDBOX_SUITE[1]).not.toMatch(/\.(?:spec|test)\.[cm]?[jt]sx?$/);
  });

  it('keeps the two legs in two reports, so a release run keeps both', () => {
    expect(SANDBOX_JUNIT).toBe('junit-sandbox.xml');
    expect(SANDBOX_NGINX_JUNIT).toBe('junit-sandbox-nginx.xml');
    expect(SANDBOX_NGINX_JUNIT).not.toBe(SANDBOX_JUNIT);
  });

  it('accepts a run in which every declared file executed a test and nothing was skipped', () => {
    expect(sandboxRunProblems(complete())).toEqual([]);
  });

  it('refuses a run that wrote no report, rather than reading "no failures" into nothing', () => {
    expect(sandboxRunProblems(null)).toEqual([
      'the run wrote no JUnit report, so nothing proves any spec ran',
    ]);
  });

  it('refuses a run from which a declared file is missing — a stale testMatch entry', () => {
    const problems = sandboxRunProblems(report(suite('document-viewer.spec.ts')));
    expect(problems).toEqual(['no results for sandbox-policy.prod.ts — the suite has shrunk']);
  });

  it('refuses a file whose only test was skipped, which Playwright reports as a pass', () => {
    const problems = sandboxRunProblems(
      report(
        suite('document-viewer.spec.ts'),
        suite('sandbox-policy.prod.ts', { tests: 1, skipped: 1 }),
      ),
    );
    expect(problems).toEqual([
      'sandbox-policy.prod.ts executed no test',
      'sandbox-policy.prod.ts skipped 1 test(s)',
    ]);
  });

  it('refuses a skip even beside an executed test in the same file', () => {
    const problems = sandboxRunProblems(
      report(
        suite('document-viewer.spec.ts', { tests: 3, skipped: 1 }),
        suite('sandbox-policy.prod.ts'),
      ),
    );
    expect(problems).toEqual(['document-viewer.spec.ts skipped 1 test(s)']);
  });

  it('counts failures and errors together, and names the file', () => {
    const problems = sandboxRunProblems(
      report(
        suite('document-viewer.spec.ts', { tests: 2, failures: 1, errors: 1 }),
        suite('sandbox-policy.prod.ts'),
      ),
    );
    expect(problems).toEqual(['document-viewer.spec.ts failed 2 test(s)']);
  });

  it('refuses a file the suite does not declare, so the scope cannot widen unseen', () => {
    const problems = sandboxRunProblems(
      report(...SANDBOX_SUITE.map((name) => suite(name)), suite('clipboard-hygiene.spec.ts')),
    );
    expect(problems).toEqual(['clipboard-hygiene.spec.ts ran, but is not in the declared suite']);
  });

  it('holds a file with zero tests as unexecuted, at the boundary', () => {
    const problems = sandboxRunProblems(
      report(suite('document-viewer.spec.ts', { tests: 0 }), suite('sandbox-policy.prod.ts')),
    );
    expect(problems).toEqual(['document-viewer.spec.ts executed no test']);
  });

  it('sums suites that share a name instead of letting the later one hide the earlier', () => {
    // Two projects over one file write two elements of the same name. A map that
    // overwrote would report the second, clean element and lose the failure.
    const summary = summariseJunit(
      report(
        suite('document-viewer.spec.ts', { tests: 1, failures: 1 }),
        suite('document-viewer.spec.ts', { tests: 2 }),
      ),
    );
    expect(summary.get('document-viewer.spec.ts')).toEqual({
      tests: 3,
      failures: 1,
      errors: 0,
      skipped: 0,
    });
  });

  it('reads an attribute absent from the element as zero, and ignores a suite with no name', () => {
    const summary = summariseJunit(
      '<testsuites><testsuite name="document-viewer.spec.ts" tests="2"></testsuite>' +
        '<testsuite tests="9" failures="9"></testsuite></testsuites>',
    );
    expect([...summary.entries()]).toEqual([
      ['document-viewer.spec.ts', { tests: 2, failures: 0, errors: 0, skipped: 0 }],
    ]);
  });

  it('judges against a caller-supplied suite when one is given', () => {
    expect(sandboxRunProblems(report(suite('only.spec.ts')), ['only.spec.ts'])).toEqual([]);
    expect(sandboxRunProblems(report(suite('only.spec.ts')), ['other.spec.ts'])).toEqual([
      'no results for other.spec.ts — the suite has shrunk',
      'only.spec.ts ran, but is not in the declared suite',
    ]);
  });
});
