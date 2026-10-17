/**
 * `verify:selftest`'s own guarantees.
 *
 * The expensive half of this gate — planting a defect and watching a real gate
 * go red — is T2 and takes minutes, so it is run on demand and its transcript is
 * the evidence. What is asserted HERE is the part that must hold on every push,
 * because it is the part a later phase can break by accident:
 *
 *   · every registered gate has a defect case, so the catalog cannot silently
 *     shrink to the subset that existed when it was written;
 *   · a registered gate WITHOUT a case is a hard error that names it, rather
 *     than a quiet omission;
 *   · every case can actually plant its defect: the files it mutates exist, and
 *     the mutation genuinely changes them. A mutation whose regex stopped
 *     matching would leave the tree untouched, the gate would pass, and the case
 *     would report "this gate cannot fail" — pointing the reader at the wrong
 *     file entirely.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFECTS } from '../../../scripts/ci/lib/selftest-defects.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const SELFTEST = path.join(repoRoot, 'scripts', 'ci', 'selftest.mjs');

interface ManifestTask {
  cmd: string;
  composite?: boolean;
  report: string | string[];
}
const manifest = JSON.parse(
  readFileSync(path.join(repoRoot, '.testfortress', 'verify.json'), 'utf-8'),
) as { tasks: Record<string, ManifestTask> };

const registered = Object.entries(manifest.tasks)
  .filter(([, task]) => task.composite !== true)
  .map(([name]) => name);

describe('the defect-injection registry', () => {
  it('covers every registered gate, so the catalog cannot shrink below the manifest', () => {
    const uncovered = registered.filter((name) => !(name in DEFECTS));
    expect(uncovered).toEqual([]);
  });

  it('carries no case for a task the manifest does not register', () => {
    const orphaned = Object.keys(DEFECTS).filter((name) => !registered.includes(name));
    expect(orphaned).toEqual([]);
  });

  it('describes what each case plants, in one line', () => {
    for (const [name, defect] of Object.entries(DEFECTS)) {
      expect(defect.title, `${name} has no title`).toMatch(/\S/);
      expect(defect.create ?? defect.mutate, `${name} plants nothing`).toBeTruthy();
    }
  });

  it('plants a defect that actually changes every file it claims to mutate', () => {
    for (const [name, defect] of Object.entries(DEFECTS)) {
      for (const [rel, mutate] of Object.entries(defect.mutate ?? {})) {
        const target = path.join(repoRoot, rel);
        expect(existsSync(target), `${name} mutates ${rel}, which does not exist`).toBe(true);
        const before = readFileSync(target, 'utf-8');
        expect(mutate(before), `${name}'s mutation of ${rel} left it unchanged`).not.toBe(before);
      }
    }
  });

  it('recognises its own planted defect through each case evidence predicate', () => {
    // A predicate that matches nothing would turn every proven gate into an
    // unattributable one; a predicate that matches everything would accept a
    // failure caused by something else entirely.
    for (const [name, defect] of Object.entries(DEFECTS)) {
      if (!defect.evidence) continue;
      expect(defect.evidence(''), `${name}'s evidence predicate matches empty output`).toBe(false);
    }
  });
});

/**
 * The two scanner cases, whose evidence has to be narrower than "the gate's
 * output mentions the package or the file". Both gates fail in the self-test's
 * workspace for a reason nobody planted as well: the workspace is a fresh
 * repository whose one baseline commit re-introduces every fixture line
 * `.gitleaksignore` pins to its ORIGINAL commit, and `osv-scanner
 * --all-packages` lists every package it read, vulnerable or not. So each
 * predicate must be satisfied by the planted defect's own finding line and by
 * nothing else in a run that did not plant it.
 */
describe('the scanner cases attribute a failure to the planted defect alone', () => {
  const gitleaks = DEFECTS['audit:secrets:gitleaks'];
  const osv = DEFECTS['audit:deps:osv'];

  it('buries the gitleaks plant in history, so it proves the history scan', () => {
    expect(gitleaks?.requires).toEqual(['gitleaks']);
    expect(gitleaks?.buryInHistory).toBe(true);
    const planted = Object.keys(gitleaks?.create ?? {});
    expect(planted).toHaveLength(1);
    // A fixture finding from the workspace's baseline commit is not the plant.
    const fixtureOnly =
      '  generic-api-key | packages/server/tests/email.test.ts:932 | 0123abc\n' +
      '✖ gitleaks: 1 unignored finding(s)';
    expect(gitleaks?.evidence?.(fixtureOnly)).toBe(false);
    // The plant's own finding line, as `gitleaks-gate.mjs` prints it.
    const plantedRun = `${fixtureOnly}\n  aws-access-token | ${planted[0] ?? ''}:1 | 4567def`;
    expect(gitleaks?.evidence?.(plantedRun)).toBe(true);
  });

  it('plants a vulnerable lockfile entry and accepts only its advisory line', () => {
    expect(osv?.requires).toEqual(['osv-scanner']);
    const lockPath = path.join(repoRoot, 'package-lock.json');
    const lock = JSON.parse(readFileSync(lockPath, 'utf-8')) as {
      packages: Record<string, { version?: string }>;
    };
    // The real lockfile does not carry the package, so the plant is the only copy.
    expect(Object.keys(lock.packages).filter((key) => key.endsWith('/minimist'))).toEqual([]);
    const planted = JSON.parse(
      osv!.mutate!['package-lock.json']!(readFileSync(lockPath, 'utf-8')),
    ) as {
      packages: Record<string, { version?: string }>;
    };
    expect(planted.packages['node_modules/minimist']?.version).toBe('1.2.5');
    // Listed as a scanned package is not a finding.
    const listedOnly =
      '{"results":[{"packages":[{"package":{"name":"minimist","version":"1.2.5"}}]}]}';
    expect(osv?.evidence?.(listedOnly)).toBe(false);
    // `osv-gate.mjs`'s finding line is.
    expect(osv?.evidence?.('  minimist@1.2.5  GHSA-xvch-5gv4-984h  Prototype Pollution')).toBe(
      true,
    );
  });
});

describe('the runner', () => {
  it('is a hard error, naming the task, when a registered gate has no defect case', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'hv-selftest-'));
    mkdirSync(path.join(dir, '.testfortress'), { recursive: true });
    writeFileSync(
      path.join(dir, '.testfortress', 'verify.json'),
      JSON.stringify({
        version: 1,
        reportDir: '.testfortress/reports',
        tasks: {
          'audit:invented': { cmd: 'true', tier: 1, gate: 'invented', report: 'invented.log' },
        },
      }),
    );
    const proc = spawnSync(process.execPath, [SELFTEST], { cwd: dir, encoding: 'utf-8' });
    expect(proc.status).toBe(2);
    expect(proc.stderr).toMatch(/audit:invented/);
    expect(proc.stderr).toMatch(/no defect-injection case/);
  });

  it('lists what it would plant without planting anything', () => {
    const proc = spawnSync(process.execPath, [SELFTEST, '--list'], {
      cwd: repoRoot,
      encoding: 'utf-8',
    });
    expect(proc.status).toBe(0);
    for (const name of registered) expect(proc.stdout).toContain(name);
  });
});
