/**
 * The integrity scanner's own fixture suite.
 *
 * An integrity gate nobody tested is a placebo: it grants confidence it never
 * earned, and it is the one check whose silent failure hides every other silent
 * failure. So the scanner is driven end to end, as a process, against
 * throw-away git repositories with planted violations.
 *
 * Three groups, and the second and third are the ones that decide whether this
 * scanner is real:
 *
 *   1. THE DOCTRINE'S FIFTEEN. Half of them assert a PASS, which is the half
 *      people skip and the half that matters most: a gate a correct codebase
 *      cannot pass is the pressure that gets the gate bypassed.
 *   2. ANTI-OVERFITTING. The audit handed this project the rule, file and line
 *      of every marker in the tree, so a scanner narrow enough to match only
 *      those known strings would pass its own suite today and pass again once
 *      Phase 3 removes them — a placebo that ships. Every fixture here plants a
 *      form that appears NOWHERE in this repository or in the audit's census, so
 *      a rule that only recognises what it was told about fails.
 *   3. THE FALSE POSITIVES THAT WERE MEASURED. Each of these was a real hit in
 *      this tree that is not a violation. They are pinned so a later "tidy-up"
 *      of a pattern cannot quietly reintroduce five permanent false positives,
 *      which would force a blanket ledger entry, which would then hide the real
 *      hits.
 *
 * Markers are assembled from fragments (`m(...)`) wherever a literal would make
 * THIS file a violation in the repository it is testing. That is not cosmetic:
 * `packages/server/tests/**` is scanned, `.only` and a tautology are real
 * findings there, and a test suite that trips the gate it tests would be
 * "fixed" by weakening the gate.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const SCANNER = path.join(repoRoot, 'scripts', 'ci', 'integrity-scan.mjs');

/** Assemble a marker so this file does not itself carry it. */
const m = (...parts: string[]): string => parts.join('');

const TODAY = new Date();
const iso = (d: Date): string => d.toISOString().slice(0, 10);
const inDays = (n: number): string => iso(new Date(TODAY.getTime() + n * 86_400_000));

interface Violation {
  file?: string;
  line?: number;
  rule?: string;
  entry?: string;
  violation: string;
  detail: string;
}
interface Hit {
  file: string;
  line: number;
  rule: string;
  disposition: string;
}
interface ScanResult {
  exitCode: number;
  violations: Violation[];
  hits: Hit[];
  summary: {
    fingerprints: Record<string, string>;
    suppressions: { count: number; totalHits: number };
  };
  stderr: string;
}

interface LedgerEntry {
  id: string;
  rule: string;
  kind?: string;
  file?: string;
  symbol?: string;
  maxHits?: number;
  reason?: string;
  owner?: string;
  created?: string;
  expires?: string;
  approvedBy?: string[];
  condition?: string;
  satisfiedIn?: string;
}

interface FixtureOptions {
  ledger?: { policy?: Record<string, unknown>; entries: LedgerEntry[] };
  config?: Record<string, unknown>;
  manifest?: Record<string, unknown>;
  /** Written into `.git/info/exclude` of the fixture repo. */
  infoExclude?: string;
  /** Applied AFTER the fingerprints are pinned, so a hash change is observable. */
  after?: (dir: string) => void;
}

const dirs: string[] = [];

/** A valid ledger entry, so each fixture only has to state what it is testing. */
const entry = (over: Partial<LedgerEntry> & { id: string; rule: string }): LedgerEntry => ({
  kind: 'conditional-skip',
  maxHits: 1,
  reason: 'fixture',
  owner: 'fixture',
  created: inDays(-1),
  expires: inDays(30),
  approvedBy: ['judge:fixture'],
  ...over,
});

function runScanner(dir: string): ScanResult {
  const proc = spawnSync(process.execPath, [SCANNER, '--json'], {
    cwd: dir,
    encoding: 'utf-8',
    env: { ...process.env, FORCE_COLOR: '0' },
  });
  const parsed = JSON.parse(proc.stdout) as Omit<ScanResult, 'exitCode' | 'hits' | 'stderr'>;
  const report = JSON.parse(
    readFileSync(path.join(dir, '.testfortress', 'reports', 'integrity.json'), 'utf-8'),
  ) as { hits: Hit[] };
  return {
    exitCode: proc.status ?? -1,
    violations: parsed.violations,
    hits: report.hits,
    summary: parsed.summary,
    stderr: proc.stderr,
  };
}

/**
 * Builds a throw-away repository, pins the scanner's own fingerprints into its
 * baseline, and scans it.
 *
 * Nothing is ever `git add`ed: every fixture file is UNTRACKED, which makes the
 * whole suite a standing test of decision (a). If the scanner ever went back to
 * an index-only listing, all of these would report a clean tree.
 */
function scan(files: Record<string, string>, options: FixtureOptions = {}): ScanResult {
  const dir = mkdtempSync(path.join(tmpdir(), 'hv-integrity-'));
  dirs.push(dir);
  execFileSync('git', ['init', '-q'], { cwd: dir });

  const write = (rel: string, contents: string): void => {
    const p = path.join(dir, rel);
    mkdirSync(path.dirname(p), { recursive: true });
    writeFileSync(p, contents, 'utf-8');
  };

  for (const [rel, contents] of Object.entries(files)) write(rel, contents);
  write(
    '.testfortress/suppressions.json',
    JSON.stringify(options.ledger ?? { version: 1, policy: {}, entries: [] }, null, 2),
  );
  if (options.config)
    write('.testfortress/integrity.config.json', JSON.stringify(options.config, null, 2));
  if (options.manifest)
    write('.testfortress/verify.json', JSON.stringify(options.manifest, null, 2));
  if (options.infoExclude !== undefined) write('.git/info/exclude', options.infoExclude);

  const baseline = {
    version: 1,
    suppressions: { count: 99, totalHits: 99 },
    integrity: {},
  };
  write('.testfortress/baseline.json', JSON.stringify(baseline, null, 2));

  // Pass 1 only to learn this scanner's fingerprints for THIS fixture, then pin
  // them. A fixture that could not pin them would report FINGERPRINT-UNPINNED on
  // every case and no PASS fixture could exist.
  const first = runScanner(dir);
  baseline.integrity = first.summary.fingerprints;
  write('.testfortress/baseline.json', JSON.stringify(baseline, null, 2));

  options.after?.(dir);
  return runScanner(dir);
}

const rulesReported = (r: ScanResult): string[] =>
  [...new Set(r.violations.map((v) => v.rule).filter(Boolean))].sort() as string[];
const at = (r: ScanResult, file: string, line?: number): Violation[] =>
  r.violations.filter((v) => v.file === file && (line === undefined || v.line === line));
const kinds = (r: ScanResult): string[] =>
  [...new Set(r.violations.map((v) => v.violation))].sort();

/** A tree with nothing to find, used as the base of most fixtures. */
const CLEAN: Record<string, string> = {
  'package.json': JSON.stringify({ name: 'fixture', scripts: { test: 'vitest run' } }, null, 2),
  'src/index.ts': 'export const add = (a: number, b: number): number => a + b;\n',
  'tests/add.test.ts':
    "import { it, expect } from 'vitest';\nit('adds', () => expect(1 + 1).toBe(2));\n",
};

afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// 1. The doctrine's fifteen fixtures
// ---------------------------------------------------------------------------
describe('the doctrine fixtures', () => {
  it('1: passes on a clean tree with an empty ledger and a baseline', () => {
    const result = scan(CLEAN);
    expect(result.violations).toEqual([]);
    expect(result.exitCode).toBe(0);
  });

  it('2: fails on a tautology in an untracked, never-staged new test file', () => {
    const result = scan({
      ...CLEAN,
      'tests/new.test.ts': `import { it, expect } from 'vitest';\nit('x', () => { ${m('expect(', 'true)', '.to')}Be(true); });\n`,
    });
    expect(rulesReported(result)).toContain('TAUTOLOGY');
    expect(at(result, 'tests/new.test.ts')).toHaveLength(1);
    expect(result.exitCode).toBe(1);
  });

  it('3: fails on an unledgered skipped test', () => {
    const result = scan({
      ...CLEAN,
      'tests/add.test.ts': `it${m('.sk', 'ip(')}'adds', () => {});\n`,
    });
    expect(rulesReported(result)).toEqual(['SKIP-JS']);
    expect(kinds(result)).toEqual(['UNLEDGERED']);
    expect(result.exitCode).toBe(1);
  });

  it('4: passes when that skip carries an entry with a condition and a tier that satisfies it', () => {
    const result = scan(
      { ...CLEAN, 'tests/add.test.ts': `it${m('.sk', 'ip(')}'adds', () => {});\n` },
      {
        ledger: {
          entries: [
            entry({
              id: 'SUP-0001',
              rule: 'SKIP-JS',
              file: 'tests/add.test.ts',
              condition: "process.env.DOCKER === '1'",
              satisfiedIn: 'verify:full (container tier)',
            }),
          ],
        },
      },
    );
    expect(result.violations).toEqual([]);
    expect(result.exitCode).toBe(0);
  });

  it('5: fails when that entry mislabels `kind`, because kind is derived from the rule', () => {
    const result = scan(
      { ...CLEAN, 'tests/add.test.ts': `it${m('.sk', 'ip(')}'adds', () => {});\n` },
      {
        ledger: {
          entries: [
            entry({
              id: 'SUP-0001',
              rule: 'SKIP-JS',
              kind: 'known-gap',
              file: 'tests/add.test.ts',
              condition: "process.env.DOCKER === '1'",
              satisfiedIn: 'verify:full',
            }),
          ],
        },
      },
    );
    expect(kinds(result)).toContain('LEDGER-KIND-MISMATCH');
    expect(result.exitCode).toBe(1);
  });

  it('6: fails on a future-dated entry whose window is short, because the window is measured from today', () => {
    const result = scan(
      { ...CLEAN, 'tests/add.test.ts': `it${m('.sk', 'ip(')}'adds', () => {});\n` },
      {
        ledger: {
          entries: [
            entry({
              id: 'SUP-0001',
              rule: 'SKIP-JS',
              file: 'tests/add.test.ts',
              created: inDays(365),
              expires: inDays(424), // a 59-day window that never expires in any observable horizon
              condition: 'true',
              satisfiedIn: 'verify:full',
            }),
          ],
        },
      },
    );
    expect(kinds(result)).toEqual(
      expect.arrayContaining(['LEDGER-FUTURE-DATED', 'LEDGER-TOO-LONG']),
    );
    expect(result.exitCode).toBe(1);
  });

  it('7: fails on a neutered gate in package.json EVEN WITH a ledger entry for it', () => {
    const result = scan(
      {
        ...CLEAN,
        'package.json': JSON.stringify(
          { scripts: { verify: `eslint . ${m('||', ' true')}` } },
          null,
          2,
        ),
      },
      {
        ledger: {
          entries: [
            entry({
              id: 'SUP-0001',
              rule: 'EXIT-NEUTER',
              kind: 'gate-neutered',
              file: 'package.json',
              symbol: 'eslint',
            }),
          ],
        },
      },
    );
    expect(at(result, 'package.json')[0]?.violation).toBe('FORBIDDEN');
    expect(result.exitCode).toBe(1);
  });

  it('8: passes for the same pattern in a teardown script with a symbol-anchored entry', () => {
    const result = scan(
      { ...CLEAN, 'scripts/teardown.sh': `#!/bin/sh\nrm -rf tmp ${m('||', ' true')}\n` },
      {
        ledger: {
          entries: [
            entry({
              id: 'SUP-0001',
              rule: 'EXIT-NEUTER',
              kind: 'gate-neutered',
              file: 'scripts/teardown.sh',
              symbol: 'rm -rf tmp',
              expires: inDays(20), // the forbidden family gets the 30-day cap
            }),
          ],
        },
      },
    );
    expect(result.violations).toEqual([]);
    expect(result.exitCode).toBe(0);
  });

  it('9: passes when a document quotes the pattern while explaining the standard', () => {
    const result = scan({
      ...CLEAN,
      'CONTRIBUTING.md': `Never append \`${m('||', ' true')}\` to a gate command.\n`,
    });
    expect(result.violations).toEqual([]);
    expect(
      result.hits.some((h) => h.file === 'CONTRIBUTING.md' && h.disposition === 'report-only'),
    ).toBe(true);
    expect(result.exitCode).toBe(0);
  });

  it('10: fails on any active rule in .git/info/exclude', () => {
    const result = scan(CLEAN, { infoExclude: '# a comment is fine\nbuild-output/\n' });
    expect(kinds(result)).toEqual(['UNTRACKED-EXCLUDE']);
    expect(result.violations[0]?.detail).toMatch(/build-output/);
    expect(result.exitCode).toBe(1);
  });

  it('11: fails when .gitignore is widened after the baseline pinned its hash', () => {
    const result = scan(CLEAN, {
      after: (dir) => writeFileSync(path.join(dir, '.gitignore'), 'src/legacy/**\n', 'utf-8'),
    });
    expect(kinds(result)).toEqual(['FINGERPRINT-CHANGED']);
    expect(result.violations[0]?.detail).toMatch(/gitignoreHash/);
    expect(result.exitCode).toBe(1);
  });

  it('12: fails when one entry claims more capacity than the policy ceiling allows', () => {
    const result = scan(
      { ...CLEAN, 'tests/add.test.ts': `it${m('.sk', 'ip(')}'adds', () => {});\n` },
      {
        ledger: {
          policy: { maxHitsPerEntry: 3 },
          entries: [
            entry({
              id: 'SUP-0001',
              rule: 'SKIP-JS',
              file: 'tests/add.test.ts',
              maxHits: 200,
              condition: 'true',
              satisfiedIn: 'verify:full',
            }),
          ],
        },
      },
    );
    expect(kinds(result)).toContain('LEDGER-CAPACITY-CEILING');
    expect(result.exitCode).toBe(1);
  });

  it('13: passes for two markers of one rule in a file with two individually anchored entries', () => {
    const result = scan(
      {
        ...CLEAN,
        'src/index.ts': [
          `export const a = 1; ${m('//', ' eslint-', 'disable-line no-magic-numbers -- first')}`,
          `export const b = 2; ${m('//', ' eslint-', 'disable-line no-magic-numbers -- second')}`,
        ].join('\n'),
      },
      {
        ledger: {
          entries: [
            entry({
              id: 'SUP-0001',
              rule: 'LINT-SUPPRESS',
              kind: 'lint-suppression',
              file: 'src/index.ts',
              symbol: 'first',
            }),
            entry({
              id: 'SUP-0002',
              rule: 'LINT-SUPPRESS',
              kind: 'lint-suppression',
              file: 'src/index.ts',
              symbol: 'second',
            }),
          ],
        },
      },
    );
    expect(result.violations).toEqual([]);
    expect(result.summary.suppressions).toEqual({ count: 2, totalHits: 2, entriesTotal: 2 });
    expect(result.exitCode).toBe(0);
  });

  it('14: fails when an entry survives the marker it excused, so the ledger is pruned', () => {
    const result = scan(CLEAN, {
      ledger: {
        entries: [
          entry({
            id: 'SUP-0001',
            rule: 'SKIP-JS',
            file: 'tests/add.test.ts',
            condition: 'true',
            satisfiedIn: 'verify:full',
          }),
        ],
      },
    });
    expect(kinds(result)).toEqual(['LEDGER-STALE']);
    expect(result.exitCode).toBe(1);
  });

  it('15: fails on an entry naming a rule id that does not exist', () => {
    const result = scan(CLEAN, {
      ledger: { entries: [entry({ id: 'SUP-0001', rule: 'NOT-A-RULE', kind: 'known-gap' })] },
    });
    expect(kinds(result)).toContain('LEDGER-UNKNOWN-RULE');
    expect(result.exitCode).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// 2. Anti-overfitting: one previously-unseen marker per non-ledgerable family
// ---------------------------------------------------------------------------
describe('anti-overfitting: a previously-unseen marker of each non-ledgerable family', () => {
  it('EXIT-NEUTER: a workflow step allowed to fail is forbidden, not merely reported', () => {
    const result = scan({
      ...CLEAN,
      '.github/workflows/ci.yml': `jobs:\n  test:\n    ${m('continue', '-on-error')}: true\n    steps: []\n`,
    });
    expect(at(result, '.github/workflows/ci.yml')[0]).toMatchObject({
      rule: 'EXIT-NEUTER',
      violation: 'FORBIDDEN',
    });
    expect(result.exitCode).toBe(1);
  });

  it('CMD-SILENCED: a manifest command that discards its own stderr is forbidden', () => {
    const result = scan(CLEAN, {
      manifest: {
        version: 1,
        reportDir: '.testfortress/reports',
        tasks: {
          lint: {
            cmd: `eslint . ${m('2>', '/dev/null')}`,
            tier: 0,
            gate: 'clean',
            report: 'lint.log',
          },
        },
      },
    });
    expect(at(result, '.testfortress/verify.json')[0]).toMatchObject({
      rule: 'CMD-SILENCED',
      violation: 'FORBIDDEN',
    });
    expect(result.exitCode).toBe(1);
  });

  it('NO-TESTS-OK: a runner told to pass on an empty suite is forbidden in a gate file', () => {
    const result = scan({
      ...CLEAN,
      'package.json': JSON.stringify(
        { scripts: { test: `vitest run ${m('--passWith', 'NoTests')}` } },
        null,
        2,
      ),
    });
    expect(at(result, 'package.json')[0]).toMatchObject({
      rule: 'NO-TESTS-OK',
      violation: 'FORBIDDEN',
    });
    expect(result.exitCode).toBe(1);
  });

  it('TEST-FILTER: a committed name filter is forbidden, while a bare workspace filter is not', () => {
    const result = scan({
      ...CLEAN,
      'package.json': JSON.stringify(
        {
          scripts: {
            test: `vitest run ${m('--testName', 'Pattern')}=smoke`,
            build: 'turbo run build --filter=./packages/*',
          },
        },
        null,
        2,
      ),
    });
    const reported = at(result, 'package.json');
    expect(reported).toHaveLength(1);
    expect(reported[0]).toMatchObject({ rule: 'TEST-FILTER', violation: 'FORBIDDEN' });
  });

  it('CMD-TEST-FILTER: a filter appended to a manifest command is forbidden, a plain one is not', () => {
    // The hole this closes, found by a judge picking a probe the executor had
    // not imagined. TEST-FILTER (above) anchors on a runner NAME so that a bare
    // workspace filter in a monorepo build script is not a false positive.
    // (This comment names neither a runner nor a flag on one line, because that
    // rule reads comments too and reported this very paragraph the first time.)
    // But EVERY command in this repository's manifest is
    // phrased `npm run <script>`, so a filter appended to one matched nothing at
    // all: Forbidden Action 1, committed into the file that defines the gates,
    // reported as zero violations. Here the anchor is the LOCATION instead, and
    // a manifest `cmd` is a gate command by definition.
    const result = scan(CLEAN, {
      manifest: {
        version: 1,
        reportDir: '.testfortress/reports',
        tasks: {
          'test:unit': {
            cmd: `npm run test:unit -- ${m('--testName', 'Pattern')}=smoke`,
            tier: 0,
            gate: 'all pass',
            report: 'junit-unit.xml',
          },
          lint: { cmd: 'npm run lint', tier: 0, gate: 'clean', report: 'lint.log' },
        },
      },
    });
    const reported = at(result, '.testfortress/verify.json');
    // Exactly one: the untouched `lint` command must not be swept up with it.
    expect(reported).toHaveLength(1);
    expect(reported[0]).toMatchObject({
      rule: 'CMD-TEST-FILTER',
      violation: 'FORBIDDEN',
      // The offending command itself, so the report names WHICH task carries the
      // filter rather than only that some task does.
      text: expect.stringContaining('test:unit') as unknown as string,
    });
    expect(result.exitCode).toBe(1);
  });

  it('FLAKE-HIDE: a runner config may set retries to the literal 0 and to nothing else', () => {
    // The other half of the same judge probe, and the reason the rule is stated
    // positively rather than as a negative lookahead. This repository shipped
    // `retries: process.env.CI ? 2 : 0` in its Playwright config — two retries in
    // exactly the environment the release job runs in — and no `[1-9]` pattern
    // can see it, because the character after the colon is a `p`.
    const result = scan({
      ...CLEAN,
      'playwright.config.ts': 'export default { retries: process.env.CI ? 2 : 0 };\n',
      'playwright.flake.config.ts': 'export default { retries: 0 };\n',
      // Not a runner config, so the same expression there is ordinary code.
      'src/http/client.ts': 'const retries = process.env.RETRIES ?? 3;\n',
    });
    expect(at(result, 'playwright.config.ts')[0]).toMatchObject({ rule: 'FLAKE-HIDE' });
    // Both negatives matter: a config that is already correct must stay silent,
    // or the rule reports the fix as the defect.
    expect(at(result, 'playwright.flake.config.ts')).toEqual([]);
    expect(at(result, 'src/http/client.ts')).toEqual([]);
  });

  it('STRICT-DOWN: a strictness downgrade is forbidden in a gate file and reported elsewhere', () => {
    const result = scan({
      ...CLEAN,
      'package.json': JSON.stringify(
        { scripts: { typecheck: `tsc ${m('--no-', 'strict')}` } },
        null,
        2,
      ),
      'tsconfig.json': JSON.stringify({ compilerOptions: { [m('str', 'ict')]: false } }, null, 2),
    });
    expect(at(result, 'package.json')[0]).toMatchObject({
      rule: 'STRICT-DOWN',
      violation: 'FORBIDDEN',
    });
    expect(at(result, 'tsconfig.json')[0]).toMatchObject({ rule: 'STRICT-DOWN' });
    expect(result.exitCode).toBe(1);
  });

  it('TAUTOLOGY: the self-comparison form is caught in a test file and in a gate file', () => {
    const selfCompare = `${m('expect(', 'total)', '.toBe(', 'total)')};`;
    const result = scan({
      ...CLEAN,
      'tests/add.test.ts': `it('adds', () => { const total = 2; ${selfCompare} });\n`,
      'package.json': JSON.stringify({ scripts: { check: `node -e "${selfCompare}"` } }, null, 2),
    });
    expect(at(result, 'tests/add.test.ts')[0]).toMatchObject({
      rule: 'TAUTOLOGY',
      violation: 'UNLEDGERED',
    });
    expect(at(result, 'package.json')[0]).toMatchObject({
      rule: 'TAUTOLOGY',
      violation: 'FORBIDDEN',
    });
  });

  it('SWALLOW: an empty catch spanning two lines in a hook directory is forbidden', () => {
    const result = scan({
      ...CLEAN,
      '.githooks/pre-commit.mjs': [
        'try {',
        '  verify();',
        `} ${m('cat', 'ch')} (error) {`,
        '}',
        '',
      ].join('\n'),
    });
    const reported = at(result, '.githooks/pre-commit.mjs');
    expect(reported).toHaveLength(1);
    expect(reported[0]).toMatchObject({ rule: 'SWALLOW', violation: 'FORBIDDEN' });
    // The marker is reported at the `catch`, once — not also from the window
    // that starts one line above it.
    expect(reported[0]?.line).toBe(3);
  });

  it('HOOK-BYPASS: an environment-variable bypass in a hook is forbidden', () => {
    const result = scan({
      ...CLEAN,
      '.githooks/pre-push': `#!/bin/sh\n${m('SKIP_SIMPLE', '_GIT_HOOKS')}=1 npm run verify\n`,
    });
    expect(at(result, '.githooks/pre-push')[0]).toMatchObject({
      rule: 'HOOK-BYPASS',
      violation: 'FORBIDDEN',
    });
  });

  it('SNAPSHOT-UPD: the sanctioned `ratchet --accept --reason` command is NOT reported', () => {
    const result = scan({
      ...CLEAN,
      'package.json': JSON.stringify(
        {
          scripts: {
            'audit:ratchet': 'node scripts/ci/ratchet-check.mjs',
            'audit:ratchet:accept': 'node scripts/ci/ratchet-check.mjs --accept --reason=measured',
          },
        },
        null,
        2,
      ),
    });
    expect(result.violations).toEqual([]);
    expect(result.exitCode).toBe(0);
  });

  it('SNAPSHOT-UPD: a blanket snapshot update in the same file IS reported', () => {
    const result = scan({
      ...CLEAN,
      'package.json': JSON.stringify(
        { scripts: { test: `vitest run ${m('--update', '-snapshots')}` } },
        null,
        2,
      ),
    });
    expect(at(result, 'package.json')[0]).toMatchObject({
      rule: 'SNAPSHOT-UPD',
      violation: 'FORBIDDEN',
    });
  });
});

// ---------------------------------------------------------------------------
// 2b. The SKIP-JS anchor, against directories this plan has not created yet
// ---------------------------------------------------------------------------
describe('anti-overfitting: the SKIP-JS anchor covers directories that do not exist yet', () => {
  // Every shape PLAN.md's later phases introduce. A naive anchor such as
  // `packages/*/tests/**/*.test.{ts,tsx}` matches some of these and misses
  // others; nothing in the tree exercises the rule at all today, because there
  // is not one skipped, focused or todo test in 237 files. So this is the only
  // thing standing between a `.only` left in a new spec and a silent pass for
  // the rest of the plan.
  const NEW_SHAPES = [
    'packages/client/tests/property/roundtrip.test.ts',
    'packages/shared/tests/property/schemas.test.ts',
    'packages/server/tests/property/folder-graph.test.ts',
    'packages/client/tests/fuzz/parsers.test.ts',
    'packages/server/tests/fuzz/import.test.ts',
    'packages/client/tests/export/formats.test.ts',
    'packages/server/tests/resource/volume.test.ts',
    'packages/server/tests/upgrade/n-1.test.ts',
    'packages/server/tests/recovery/restore.test.ts',
    'packages/server/tests/support/helpers.test.ts',
    'e2e/import-export.spec.ts',
  ];

  const MARKERS: Record<string, string> = {
    only: `it${m('.on', 'ly(')}'x', () => {});`,
    fit: `${m('f', 'it(')}'x', () => {});`,
    fdescribe: `${m('f', 'describe(')}'x', () => {});`,
  };

  for (const file of NEW_SHAPES) {
    for (const [name, marker] of Object.entries(MARKERS)) {
      it(`reports \`${name}\` in ${file}`, () => {
        const result = scan({ ...CLEAN, [file]: `${marker}\n` });
        expect(at(result, file)).toMatchObject([
          { rule: 'SKIP-JS', violation: 'UNLEDGERED', line: 1 },
        ]);
        expect(result.exitCode).toBe(1);
      });
    }
  }
});

// ---------------------------------------------------------------------------
// 3. The false positives that were measured in this tree
// ---------------------------------------------------------------------------
describe('the measured false positives stay false', () => {
  it('SKIP-JS ignores database pagination and a truncation label in a component', () => {
    const result = scan({
      ...CLEAN,
      'packages/server/src/controllers/vaultController.ts': `const rows = await VaultItem.find(filter)${m('.sk', 'ip(')}skip).limit(limit).lean();\n`,
      // Single-quoted so the component's own template literal survives verbatim.
      'packages/client/src/components/vault/BackupCodesEditor.tsx':
        'const label = `${count} will not ' + m('f', 'it (limit') + ' ${MAX})`;\n',
    });
    expect(result.violations).toEqual([]);
    expect(result.exitCode).toBe(0);
  });

  it('FLAKE-HIDE ignores a container healthcheck but catches a retry in a gate command', () => {
    const result = scan({
      ...CLEAN,
      'docker-compose.yml': 'services:\n  db:\n    healthcheck:\n      retries: 12\n',
      'docker/Dockerfile':
        'HEALTHCHECK --interval=30s --retries=3 CMD curl -f http://localhost/ok\n',
      'package.json': JSON.stringify(
        { scripts: { 'test:e2e': 'playwright test --retries=2' } },
        null,
        2,
      ),
    });
    expect(at(result, 'docker-compose.yml')).toEqual([]);
    expect(at(result, 'docker/Dockerfile')).toEqual([]);
    expect(at(result, 'package.json')[0]).toMatchObject({ rule: 'FLAKE-HIDE' });
  });

  it('SLEEP-SYNC ignores a UI timer in production code but catches the same call in a test', () => {
    const result = scan({
      ...CLEAN,
      'src/components/Toast.tsx': `${m('setTime', 'out')}(() => onDismiss(id), 300);\n`,
      'tests/slow.test.ts': `await new Promise((r) => ${m('setTime', 'out')}(r, 1100));\n`,
    });
    expect(at(result, 'src/components/Toast.tsx')).toEqual([]);
    expect(at(result, 'tests/slow.test.ts')[0]).toMatchObject({ rule: 'SLEEP-SYNC' });
  });

  it('TYPE-SUPPRESS ignores a comment explaining a cast but catches the cast', () => {
    const result = scan({
      ...CLEAN,
      'src/index.ts': [
        `${m('//', ' `as ', 'any` is required here because the driver types cannot express it')}`,
        `export const row = query({ id }) ${m('as ', 'any')};`,
        '',
      ].join('\n'),
    });
    const reported = at(result, 'src/index.ts');
    expect(reported).toHaveLength(1);
    expect(reported[0]).toMatchObject({ rule: 'TYPE-SUPPRESS', line: 2 });
  });

  it('LINT-SUPPRESS ignores prose naming the directive but catches the directive itself', () => {
    const result = scan({
      ...CLEAN,
      'src/index.ts': [
        `${m('//', ' written once rather than four separate eslint-', 'disable comments')}`,
        `${m('//', ' eslint-', 'disable-next-line no-console -- boot banner')}`,
        'console.log("boot");',
        '',
      ].join('\n'),
    });
    const reported = at(result, 'src/index.ts');
    expect(reported).toHaveLength(1);
    expect(reported[0]).toMatchObject({ rule: 'LINT-SUPPRESS', line: 2 });
  });

  it('FLAKE-HIDE catches single-worker execution in whichever spelling the runner uses', () => {
    // The doctrine's pattern names Jest's `maxWorkers`; Playwright and Vitest
    // spell it `workers`, which is the spelling this repository actually uses.
    const result = scan({
      ...CLEAN,
      'playwright.config.ts': `export default { ${m('work', 'ers')}: 1 };\n`,
      'vitest.config.ts': `export default { test: { ${m('maxWork', 'ers')}: 1 } };\n`,
    });
    expect(at(result, 'playwright.config.ts')[0]).toMatchObject({ rule: 'FLAKE-HIDE', line: 1 });
    expect(at(result, 'vitest.config.ts')[0]).toMatchObject({ rule: 'FLAKE-HIDE', line: 1 });
  });

  it('FLAKE-HIDE catches a per-spec retry, which no runner config would show', () => {
    const result = scan({
      ...CLEAN,
      'tests/racy.test.ts': `it('x', { ${m('retr', 'y')}: 2 }, () => {});\n`,
      'e2e/racy.spec.ts': `test.describe.${m('config', 'ure')}({ ${m('retr', 'ies')}: 2 });\n`,
    });
    expect(at(result, 'tests/racy.test.ts')[0]).toMatchObject({ rule: 'FLAKE-HIDE' });
    expect(at(result, 'e2e/racy.spec.ts')[0]).toMatchObject({ rule: 'FLAKE-HIDE' });
  });

  it('SLEEP-SYNC catches a bare sleep helper in a test but not the same name in production code', () => {
    // `sleep`/`delay` helpers are legitimate production code here — the
    // progressive login delay, the breach-seed backoff, the HIBP retry.
    const result = scan({
      ...CLEAN,
      'src/utils/backoff.ts': `export const wait = async (): Promise<void> => ${m('sle', 'ep')}(500);\n`,
      'tests/racy.test.ts': `await ${m('sle', 'ep')}(2000);\n`,
    });
    expect(at(result, 'src/utils/backoff.ts')).toEqual([]);
    expect(at(result, 'tests/racy.test.ts')[0]).toMatchObject({ rule: 'SLEEP-SYNC' });
  });

  it('does not let a URL in a comment hide a marker behind it', () => {
    // `stripLineComment` removes prose, and a `//` preceded by a colon is a URL
    // scheme rather than a comment: truncating there would hide everything after
    // it, including a swallowed failure in a file where none can be ledgered.
    const result = scan({
      ...CLEAN,
      '.githooks/pre-commit.mjs': `try { get('https://host/health'); } ${m('cat', 'ch')} {}\n`,
      'src/client.ts': `const row = get('https://api/v1', opts ${m('as ', 'any')});\n`,
    });
    expect(at(result, '.githooks/pre-commit.mjs')[0]).toMatchObject({
      rule: 'SWALLOW',
      violation: 'FORBIDDEN',
    });
    expect(at(result, 'src/client.ts')[0]).toMatchObject({ rule: 'TYPE-SUPPRESS' });
  });

  it('counts two markers of one rule on one line as two occurrences', () => {
    // Otherwise N suppressions written on one line consume ONE unit of a ledger
    // entry's capacity, which is the blanket-entry effect `maxHits` exists to
    // prevent, reproduced at line granularity.
    const twoCasts = `middleware(req ${m('as ', 'any')}, res ${m('as ', 'any')});`;
    const oneEntry = scan(
      { ...CLEAN, 'tests/mw.test.ts': `${twoCasts}\n` },
      {
        ledger: {
          entries: [
            entry({
              id: 'SUP-0001',
              rule: 'TYPE-SUPPRESS',
              kind: 'type-suppression',
              file: 'tests/mw.test.ts',
              maxHits: 1,
            }),
          ],
        },
      },
    );
    expect(kinds(oneEntry)).toEqual(['LEDGER-CAPACITY']);

    const twoCovered = scan(
      { ...CLEAN, 'tests/mw.test.ts': `${twoCasts}\n` },
      {
        ledger: {
          entries: [
            entry({
              id: 'SUP-0001',
              rule: 'TYPE-SUPPRESS',
              kind: 'type-suppression',
              file: 'tests/mw.test.ts',
              maxHits: 2,
            }),
          ],
        },
      },
    );
    expect(twoCovered.violations).toEqual([]);
    expect(twoCovered.summary.suppressions.totalHits).toBe(2);
  });

  it('COV-EXCLUDE catches an inline coverage pragma', () => {
    const result = scan({
      ...CLEAN,
      'src/index.ts': `${m('/* is', 'tanbul ignore next */')}\nexport const unreachable = (): void => {};\n`,
    });
    expect(at(result, 'src/index.ts')[0]).toMatchObject({
      rule: 'COV-EXCLUDE',
      violation: 'UNLEDGERED',
    });
  });
});

// ---------------------------------------------------------------------------
// 4. The scanner's own blind spots
// ---------------------------------------------------------------------------
describe('the blind spots are pinned rather than trusted', () => {
  it('reports every operator-added exclude as a marker needing its own entry', () => {
    const result = scan(CLEAN, { config: { exclude: ['src/**'] } });
    expect(at(result, '.testfortress/integrity.config.json')[0]).toMatchObject({
      rule: 'SCAN-EXCLUDE',
      violation: 'UNLEDGERED',
    });
    expect(result.exitCode).toBe(1);
  });

  it('never lets an operator exclude hide a FORBIDDEN marker', () => {
    const result = scan(
      {
        ...CLEAN,
        'package.json': JSON.stringify(
          { scripts: { test: `vitest ${m('||', ' true')}` } },
          null,
          2,
        ),
      },
      {
        config: { exclude: ['package.json'] },
        ledger: {
          entries: [
            entry({
              id: 'SUP-0001',
              rule: 'SCAN-EXCLUDE',
              kind: 'known-gap',
              file: '.testfortress/integrity.config.json',
              symbol: 'package.json',
            }),
          ],
        },
      },
    );
    expect(at(result, 'package.json')[0]).toMatchObject({
      rule: 'EXIT-NEUTER',
      violation: 'FORBIDDEN',
    });
  });

  it('truncates a very long line rather than skipping it', () => {
    const padding = 'x'.repeat(20_000);
    const result = scan({
      ...CLEAN,
      'package.json': JSON.stringify(
        { scripts: { verify: `eslint . ${m('||', ' true')} # ${padding}` } },
        null,
        2,
      ),
    });
    expect(at(result, 'package.json')[0]).toMatchObject({ rule: 'EXIT-NEUTER' });
  });

  it('fails when the baseline pins no fingerprints at all', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'hv-integrity-'));
    dirs.push(dir);
    execFileSync('git', ['init', '-q'], { cwd: dir });
    mkdirSync(path.join(dir, '.testfortress'), { recursive: true });
    writeFileSync(path.join(dir, 'src.ts'), 'export const a = 1;\n');
    writeFileSync(
      path.join(dir, '.testfortress', 'baseline.json'),
      JSON.stringify({ version: 1, suppressions: { count: 0, totalHits: 0 } }),
    );
    const result = runScanner(dir);
    expect(kinds(result)).toEqual(['FINGERPRINT-UNPINNED']);
    expect(result.exitCode).toBe(1);
  });

  it('fails when the ledger grows past the count recorded in the baseline', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'hv-integrity-'));
    dirs.push(dir);
    execFileSync('git', ['init', '-q'], { cwd: dir });
    mkdirSync(path.join(dir, '.testfortress'), { recursive: true });
    writeFileSync(path.join(dir, 'a.test.ts'), `it${m('.sk', 'ip(')}'x', () => {});\n`);
    writeFileSync(
      path.join(dir, '.testfortress', 'suppressions.json'),
      JSON.stringify({
        version: 1,
        entries: [
          entry({
            id: 'SUP-0001',
            rule: 'SKIP-JS',
            file: 'a.test.ts',
            condition: 'true',
            satisfiedIn: 'verify:full',
          }),
        ],
      }),
    );
    writeFileSync(
      path.join(dir, '.testfortress', 'baseline.json'),
      JSON.stringify({ version: 1, suppressions: { count: 0, totalHits: 0 }, integrity: {} }),
    );
    const first = runScanner(dir);
    writeFileSync(
      path.join(dir, '.testfortress', 'baseline.json'),
      JSON.stringify({
        version: 1,
        suppressions: { count: 0, totalHits: 0 },
        integrity: first.summary.fingerprints,
      }),
    );
    const result = runScanner(dir);
    expect(kinds(result)).toEqual(['LEDGER-RATCHET']);
    expect(result.exitCode).toBe(1);
  });

  it('reports capacity an entry provisions but never uses', () => {
    const result = scan(
      { ...CLEAN, 'tests/add.test.ts': `it${m('.sk', 'ip(')}'adds', () => {});\n` },
      {
        ledger: {
          entries: [
            entry({
              id: 'SUP-0001',
              rule: 'SKIP-JS',
              file: 'tests/add.test.ts',
              maxHits: 3,
              condition: 'true',
              satisfiedIn: 'verify:full',
            }),
          ],
        },
      },
    );
    expect(kinds(result)).toEqual(['LEDGER-UNUSED-CAPACITY']);
    expect(result.exitCode).toBe(1);
  });

  it('exempts DEFERRED-ROW from staleness and from both counts, so the escape valve is usable', () => {
    const result = scan(CLEAN, {
      ledger: {
        policy: {
          maxTotal: 0,
          exemptFromTotal: ['DEFERRED-ROW', 'EQUIV-MUTANT', 'BASELINE-REDUCTION'],
        },
        entries: [
          entry({
            id: 'SUP-0001',
            rule: 'DEFERRED-ROW',
            kind: 'known-gap',
            reason:
              'the applicability row for load testing is deferred; no marker exists in the tree',
          }),
        ],
      },
    });
    expect(result.violations).toEqual([]);
    expect(result.summary.suppressions.count).toBe(0);
    expect(result.exitCode).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 5. This repository, right now
// ---------------------------------------------------------------------------
describe('the real repository', () => {
  let real: { summary: { violations: number }; violations: Violation[] };

  beforeAll(() => {
    const proc = spawnSync(process.execPath, [SCANNER, '--json'], {
      cwd: repoRoot,
      encoding: 'utf-8',
      env: { ...process.env, FORCE_COLOR: '0' },
    });
    real = JSON.parse(proc.stdout) as typeof real;
  });

  /**
   * These are UNIVERSALLY QUANTIFIED on purpose. The exact five rule ids present
   * today are recorded as evidence in the phase log, not asserted here: Phase 3
   * Task 3.4 removes them, and a test pinned to "exactly these seven findings"
   * would then have to be edited to stay green — which is indistinguishable from
   * editing a test to match observed behaviour. Every assertion below holds both
   * before and after that task.
   */
  it('keeps the committed ledger internally consistent', () => {
    const hygiene = real.violations.filter(
      (v) => v.violation.startsWith('LEDGER-') || v.violation === 'ANCHOR-REQUIRED',
    );
    expect(hygiene).toEqual([]);
  });

  it('keeps the scanner blind spots pinned to the values in baseline.json', () => {
    const drift = real.violations.filter((v) => v.violation.startsWith('FINGERPRINT-'));
    expect(drift).toEqual([]);
  });

  it('reports nothing except the families Phase 3 Task 3.4 is about to remove', () => {
    // Nine of these are the doctrine's non-ledgerable families: no entry can
    // ever excuse one, so allowing them here allows nothing that could have been
    // written down instead. FLAKE-HIDE is the exception and is named as one: it
    // IS ledgerable, and the single live hit — `--retries=2` in the E2E gate
    // command — is deliberately left unledgered because Task 3.4 deletes it
    // rather than excusing it. Every OTHER ledgerable rule is excluded from this
    // allowance, which is what makes the assertion catch a new unledgered
    // suppression anywhere in the tree.
    const ALLOWED_UNTIL_TASK_3_4 = new Set([
      'EXIT-NEUTER',
      'CMD-SILENCED',
      'NO-TESTS-OK',
      'TEST-FILTER',
      'STRICT-DOWN',
      'SNAPSHOT-UPD',
      'HOOK-BYPASS',
      'TAUTOLOGY',
      'SWALLOW',
      'FLAKE-HIDE',
    ]);
    const unexpected = real.violations.filter(
      (v) => v.violation !== 'UNTRACKED-EXCLUDE' && !ALLOWED_UNTIL_TASK_3_4.has(v.rule ?? ''),
    );
    expect(unexpected).toEqual([]);
  });
});
