import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  adjudicate,
  spdxTerms,
  stripException,
  stripInferred,
} from '../../../scripts/ci/lib/licenses.mjs';
import { KNIP_LABELS, summariseKnip } from '../../../scripts/ci/lib/knip-report.mjs';

// The static-floor gates (`deadcode`, `audit:config`, `audit:licenses`) run
// external tools, but the part that DECIDES — how an SPDX expression is
// adjudicated against the policy, and how knip's report is counted — is pure and
// belongs under test. Both were wrong in an earlier draft in ways no green run
// would have shown: `MIT AND ISC OR CC0-1.0` was reported unlisted, and a knip
// category renamed upstream was silently counted as zero.
//
// Resolved from this module's own URL, never `process.cwd()`, so the suite
// behaves the same run from the package or from the repo root.
const testDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(testDir, '..', '..', '..');
const readJson = (rel: string): Record<string, unknown> =>
  JSON.parse(readFileSync(path.join(repoRoot, rel), 'utf-8')) as Record<string, unknown>;

describe('licence adjudication (audit:licenses)', () => {
  const policy = {
    allow: new Set(['MIT', 'ISC', 'Apache-2.0', 'CC0-1.0', 'BSD-3-Clause']),
    deny: new Set(['GPL-3.0-only', 'MPL-2.0']),
    denyPatterns: ['GPL', 'AGPL', 'LGPL', 'MPL'],
  };

  it.each([
    // [expression, verdict, what the case pins]
    ['MIT', 'allowed', 'a plain allowed licence'],
    ['MIT*', 'allowed', "license-checker's inferred-from-file marker is not part of the licence"],
    ['(MIT OR Apache-2.0)', 'allowed', 'a dual licence where both options are allowed'],
    ['MIT AND CC0-1.0', 'allowed', 'a conjunction where every term is allowed'],
    [
      'Apache-2.0 WITH LLVM-exception',
      'allowed',
      'an exception qualifies the licence, it does not replace it',
    ],
    // AND binds tighter than OR, so this is (MIT AND ISC) OR (CC0-1.0): two
    // allowed branches. Splitting on OR first and matching the whole left side
    // against the allowlist reported this as unlisted.
    ['MIT AND ISC OR CC0-1.0', 'allowed', 'SPDX precedence: AND binds tighter than OR'],
    ['MIT AND WTFPL', 'unlisted', 'one unrecognised term poisons its whole conjunction'],
    ['WTFPL', 'unlisted', 'an unrecognised licence fails closed'],
    ['UNLICENSED', 'unlisted', 'a private package that is not first-party fails closed'],
    ['SEE LICENSE IN LICENSE', 'unlisted', 'a licence nobody can machine-read fails closed'],
    ['', 'unlisted', 'an empty expression fails closed'],
    ['GPL-3.0-only', 'denied', 'copyleft is denied outright'],
    // Deny sweeps every branch: a dual licence still puts the copyleft option in
    // the tree, and no scanner can prove which one an operator took.
    ['(MIT OR GPL-3.0-only)', 'denied', 'deny beats an allowed alternative in the same expression'],
    ['MIT AND MPL-2.0', 'denied', 'deny beats allow inside a conjunction'],
    ['GPL-2.0-or-later', 'denied', 'an unlisted copyleft is caught by the deny PATTERN'],
  ])('adjudicates %s as %s (%s)', (expression, verdict) => {
    expect(adjudicate(expression, policy).verdict).toBe(verdict);
  });

  it('names the offending term, so a violation says which licence caused it', () => {
    expect(adjudicate('MIT AND MPL-2.0', policy)).toEqual({ verdict: 'denied', term: 'MPL-2.0' });
    expect(adjudicate('MIT AND WTFPL', policy)).toEqual({ verdict: 'unlisted', term: 'WTFPL' });
  });

  it('denies a copyleft term even when the policy also allows it', () => {
    // The deny list exists so that adding a licence to `allow` cannot quietly
    // waive it; if allow won, the deny list would be decoration.
    const contradictory = { ...policy, allow: new Set([...policy.allow, 'MPL-2.0']) };
    expect(adjudicate('MPL-2.0', contradictory).verdict).toBe('denied');
  });

  it('splits an expression into an OR of AND-groups', () => {
    expect(spdxTerms('MIT AND ISC OR CC0-1.0')).toEqual([['MIT', 'ISC'], ['CC0-1.0']]);
    expect(spdxTerms('(MIT OR Apache-2.0)')).toEqual([['MIT'], ['Apache-2.0']]);
    expect(stripInferred('MIT*')).toBe('MIT');
    expect(stripException('Apache-2.0 WITH LLVM-exception')).toBe('Apache-2.0');
  });
});

describe('the committed licence policy', () => {
  const policy = readJson('.licenses-allowlist.json') as unknown as {
    allow: string[];
    deny: string[];
    denyPatterns: string[];
    firstParty: string[];
  };

  it('never allows a licence its own deny patterns forbid', () => {
    // A self-contradictory policy is worse than none: `deny` wins at run time, so
    // an allowed-and-denied licence reads as accepted in the file and fails in
    // the gate, which is exactly the confusion that gets a deny list deleted.
    const contradictions = policy.allow.filter(
      (license) =>
        policy.deny.includes(license) ||
        policy.denyPatterns.some((pattern) =>
          license.toUpperCase().includes(pattern.toUpperCase()),
        ),
    );
    expect(contradictions).toEqual([]);
  });

  it('lists this repository, and only this repository, as first-party', () => {
    expect([...policy.firstParty].sort()).toEqual([
      '@hvault/client',
      '@hvault/server',
      '@hvault/shared',
    ]);
  });
});

describe('knip report aggregation (deadcode)', () => {
  it('counts a category it has never heard of, rather than dropping it', () => {
    // The failure this pins: knip renamed `classMembers` to `namespaceMembers`
    // between majors. Against a fixed key list the renamed category reports zero
    // while knip itself exits 1, and the gate prints "0 unused".
    const { counts, findings } = summariseKnip([
      { file: 'src/a.ts', aCategoryFromTheFuture: [{ name: 'ghost', line: 4 }] },
    ]);
    expect(counts['unmapped:aCategoryFromTheFuture']).toBe(1);
    expect(findings).toEqual([
      { category: 'unmapped:aCategoryFromTheFuture', file: 'src/a.ts', name: 'ghost', line: 4 },
    ]);
    // …and nothing was invented for the categories that were not reported.
    expect(counts.unusedExports).toBe(0);
  });

  it('initialises every known label at zero, so the baseline can gate on it', () => {
    const { counts } = summariseKnip([]);
    for (const label of Object.values(KNIP_LABELS)) expect(counts[label]).toBe(0);
    expect(Object.values(counts).every((count) => count === 0)).toBe(true);
  });

  it('labels the categories knip 6 actually emits, including the renamed one', () => {
    const { counts } = summariseKnip([
      { file: 'package.json', devDependencies: [{ name: 'unused-tool', line: 9 }] },
      { file: 'src/b.ts', namespaceMembers: [{ name: 'Klass.method', line: 12 }] },
      { file: 'src/c.ts', files: ['src/c.ts'] },
    ]);
    expect(counts.unusedDevDependencies).toBe(1);
    expect(counts.unusedNamespaceMembers).toBe(1);
    expect(counts.unusedFiles).toBe(1);
  });

  it('ignores the non-array fields of an issue record', () => {
    const { counts, findings } = summariseKnip([{ file: 'src/d.ts', exports: [] }]);
    expect(findings).toEqual([]);
    expect(Object.values(counts).every((count) => count === 0)).toBe(true);
  });
});

describe('the duplication ceiling is recorded in both places that enforce it', () => {
  it('.jscpd.json and baseline.json agree, so raising one trips the ratchet', () => {
    // jscpd fails the run above its own `threshold`; the ratchet fails any
    // attempt to raise that threshold, because it is copied into the report as
    // `duplication.ceiling` and pinned lower-is-better. The pair only works while
    // the two numbers are the same one.
    const jscpd = readJson('.jscpd.json') as unknown as { threshold: number };
    const baseline = readJson('.testfortress/baseline.json') as unknown as {
      duplication: { ceiling: number; percentage: number };
    };
    expect(baseline.duplication.ceiling).toBe(jscpd.threshold);
    expect(baseline.duplication.percentage).toBeLessThanOrEqual(jscpd.threshold);
  });

  it('scans source, not tests, and states jscpd’s defaults rather than lowering them', () => {
    const jscpd = readJson('.jscpd.json') as unknown as {
      path: string[];
      minLines: number;
      minTokens: number;
    };
    expect([...jscpd.path].sort()).toEqual([
      'packages/client/src',
      'packages/server/src',
      'packages/shared/src',
    ]);
    // Lowering either would shrink the measured duplication without removing one
    // duplicated line — a narrowed gate wearing the costume of a config tweak.
    expect(jscpd.minLines).toBe(5);
    expect(jscpd.minTokens).toBe(50);
  });
});
