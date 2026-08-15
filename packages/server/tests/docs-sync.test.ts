import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { AUDIT_ACTIONS } from '@hvault/shared';
import { TIER_BUDGET_SECONDS } from '../../../scripts/ci/lib/tiers.mjs';

// Documentation-lint: the README API reference, rate-limit table, env table,
// and counts must stay in sync with the code. Resolve the monorepo-root
// README.md (3 levels up from packages/server/tests/) regardless of cwd.
const testDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(testDir, '..', '..', '..');
const readmePath = path.resolve(repoRoot, 'README.md');
const readme = readFileSync(readmePath, 'utf-8');

describe('README documentation sync', () => {
  it('does not reference the removed POST /tools/generate-password route (generation is client-side)', () => {
    expect(readme).not.toContain('/tools/generate-password');
  });

  it('documents the EXPORT_MAX_SIZE_MB, ENABLE_SWAGGER, and TRUST_PROXY env vars', () => {
    expect(readme).toContain('EXPORT_MAX_SIZE_MB');
    expect(readme).toContain('ENABLE_SWAGGER');
    expect(readme).toContain('TRUST_PROXY');
  });

  it('documents the authenticated POST /auth/lock endpoint', () => {
    expect(readme).toContain('/auth/lock');
  });

  it('the documented HVAULT_VERSION default matches the root package.json version', () => {
    // The Compose-variable table quotes a concrete default. A release that bumps
    // package.json, docker-compose.yml and .env.example but forgets this cell tells
    // operators to pin the PREVIOUS tag: on a host that still holds the old images,
    // following the README produces a stack that silently serves the old release.
    const rootPackageJson = JSON.parse(
      readFileSync(path.resolve(testDir, '..', '..', '..', 'package.json'), 'utf-8'),
    ) as { version: string };

    const documented = /\|\s*`HVAULT_VERSION`\s*\|\s*`([^`]+)`\s*\|/.exec(readme)?.[1];
    expect(documented).toBe(rootPackageJson.version);
  });

  it('the audit-operations count matches AUDIT_ACTIONS.length', () => {
    expect(readme).toContain(`${String(AUDIT_ACTIONS.length)} distinct operations`);
  });

  /**
   * SECURITY.md's supported-versions table is the one line in that document a
   * reader consults before deciding whether their deployment still receives
   * security fixes, and it is prose, so nothing moved it: it still said `0.1.x`
   * at 0.8.0, seven minor releases later. Every other place the version appears
   * is already pinned to `package.json` by a test — the README's Compose cell
   * above, the three image tags in `docker-hardening.test.ts` — and this one was
   * simply missed. Pinning it makes the table a release step that cannot be
   * forgotten rather than one that has to be remembered.
   *
   * Only MAJOR.MINOR is asserted. The row names a supported LINE (`0.9.x`), so a
   * patch release must not be required to edit it, and "only the latest release
   * receives security fixes" is the sentence above it rather than something this
   * can check.
   */
  it('the SECURITY.md supported-versions row names the current MAJOR.MINOR line', () => {
    const security = readFileSync(path.resolve(repoRoot, 'SECURITY.md'), 'utf-8');
    const { version } = JSON.parse(
      readFileSync(path.resolve(repoRoot, 'package.json'), 'utf-8'),
    ) as { version: string };
    const [major, minor] = version.split('.');
    const line = `${String(major)}.${String(minor)}`;

    // The supported row, and the unsupported row that must move with it.
    expect(security).toMatch(new RegExp(`^\\|\\s*${line}\\.x\\s*\\|\\s*Yes\\s*\\|`, 'm'));
    expect(security).toMatch(new RegExp(`^\\|\\s*<\\s*${line}\\s*\\|\\s*No\\s*\\|`, 'm'));
  });

  it('the Heavy Ops rate-limit row reflects the real targets, not "password generation"', () => {
    const heavyOpsRow = readme.split('\n').find((line) => line.includes('Heavy Ops'));
    expect(heavyOpsRow).toBeDefined();
    expect(heavyOpsRow).not.toMatch(/password generation/i);
    // Real heavyOpLimiter targets (empty trash, bulk delete/move, export/import,
    // backup trigger/download).
    expect(heavyOpsRow).toMatch(/empty trash/i);
  });

  /**
   * The gate table is the README's central claim about this repository — that
   * the pipeline runs here rather than on a runner — and it is a list, which is
   * the shape documentation rots in fastest and least visibly. A gate added
   * without a row is not merely undocumented: the paragraph under the table
   * counts the release tier, the escape-hatch prose counts what is left when two
   * are skipped, and both quietly become wrong.
   *
   * The runner's `--list --json` is the source, deliberately: it reads NO
   * manifest (that independence is what keeps `gate-surface.test.ts` a real
   * check rather than the manifest compared with itself), so this compares the
   * README against the gates that actually run.
   */
  describe('the pipeline gate table', () => {
    interface ListedGate {
      id: string;
      tier: number;
    }

    const listed = JSON.parse(
      execFileSync(process.execPath, ['scripts/ci/local-ci.mjs', '--list', '--json'], {
        cwd: repoRoot,
        encoding: 'utf-8',
      }),
    ) as ListedGate[];

    /** `| \`id\` | T1 | … |` rows of the gate table, as id → tier. */
    const documented = new Map<string, number>(
      [...readme.matchAll(/^\|\s*`([a-z][a-z0-9-]*)`\s*\|\s*T([012])\s*\|/gm)].map((m) => [
        m[1]!,
        Number(m[2]),
      ]),
    );

    it('lists every gate the runner registers, and no gate it does not', () => {
      expect(listed.length).toBeGreaterThan(30);
      // BOTH directions. A missing row is the common rot; a row for a gate that
      // no longer exists is the quieter one, and it is worse — it advertises a
      // check this repository does not perform.
      expect([...documented.keys()].sort()).toEqual(listed.map((g) => g.id).sort());
    });

    it('states each gate in the tier it actually runs in', () => {
      // A gate documented as T1 but registered as T2 tells a reader the push
      // gate covers something it does not — which is the precise claim the
      // release tier's existence turns on.
      const wrong = listed
        .filter((gate) => documented.get(gate.id) !== gate.tier)
        .map(
          (gate) =>
            `${gate.id}: README says T${String(documented.get(gate.id))}, runner T${String(gate.tier)}`,
        );
      expect(wrong).toEqual([]);
    });

    it('counts the release tier correctly in the prose under the table', () => {
      // The paragraph names the T2 gates in words. Both the count and the names
      // are checked, because a count alone is satisfied by swapping one for
      // another — the same reason the fuzz suite pins its field list by name.
      const tier2 = listed.filter((gate) => gate.tier === 2).map((gate) => gate.id);
      expect(tier2).toHaveLength(8);
      const prose = readme.slice(readme.indexOf('Eight gates sit in'));
      expect(prose.slice(0, 400)).toContain('Eight gates sit in');
      for (const id of tier2) {
        expect(prose.slice(0, 400), `the release-tier paragraph must name \`${id}\``).toContain(
          `\`${id}\``,
        );
      }
    });
  });

  it('documents the tier budgets that scripts/ci/lib/tiers.mjs actually records', () => {
    // The budgets are stated in a table in the README and consumed by the runner
    // from `tiers.mjs`, which writes `budgetSeconds` into every `summary.json`.
    // Two copies of a number is exactly the shape that drifts, and the drift is
    // invisible: nothing else compares the sentence a contributor reads with the
    // number the runner measures against.
    const rows = new Map<string, string>(
      [...readme.matchAll(/^\|\s*\*\*(T[012])\*\*\s*\|[^|]*\|\s*\*\*([^*]+)\*\*\s*\|/gm)].map(
        (m) => [m[1]!, m[2]!.trim()],
      ),
    );
    expect([...rows.keys()]).toEqual(['T0', 'T1', 'T2']);
    expect(rows.get('T0')).toBe(`${String(TIER_BUDGET_SECONDS[0])} s`);
    expect(rows.get('T1')).toBe(`${String(TIER_BUDGET_SECONDS[1] / 60)} min`);
    // T2 is unbounded, and the README must say so rather than quoting a number
    // that would be fiction — `mutation` re-runs the suite once per mutant.
    expect(TIER_BUDGET_SECONDS[2]).toBeNull();
    expect(rows.get('T2')).toBe('unbounded');
  });

  it('documents the portable plaintext export formats (Bitwarden JSON/CSV, Chrome/Edge CSV)', () => {
    // CSV used to be import-only, so the docs previously advertised "JSON only". The
    // "Leave H-Vault" portable export now produces plaintext Bitwarden JSON, Bitwarden CSV
    // and Chrome/Edge CSV, so the README must document those formats and the dedicated page.
    expect(readme).toContain('/settings/export-data');
    expect(readme).toContain('Bitwarden CSV');
    expect(readme).toContain('Chrome/Edge CSV');
  });
});
