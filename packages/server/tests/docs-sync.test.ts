import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { AUDIT_ACTIONS, MAX_PREVIEW_BYTES, PREVIEW_MODES, formatBytes } from '@hvault/shared';
import { TIER_BUDGET_SECONDS } from '../../../scripts/ci/lib/tiers.mjs';

// Documentation-lint: the README API reference, rate-limit table, env table,
// and counts must stay in sync with the code. Resolve the monorepo-root
// README.md (3 levels up from packages/server/tests/) regardless of cwd.
const testDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(testDir, '..', '..', '..');
const readmePath = path.resolve(repoRoot, 'README.md');
const readme = readFileSync(readmePath, 'utf-8');

interface ListedGate {
  id: string;
  tier: number;
}

/**
 * The gates the runner actually registers.
 *
 * `--list --json` reads NO manifest — that independence is what keeps
 * `gate-surface.test.ts` a real check rather than the manifest compared with
 * itself — so this is the gate set as it runs, and it is what both the README's
 * gate table and CONTRIBUTING's prose below are compared against.
 */
const listedGates = JSON.parse(
  execFileSync(process.execPath, ['scripts/ci/local-ci.mjs', '--list', '--json'], {
    cwd: repoRoot,
    encoding: 'utf-8',
  }),
) as ListedGate[];

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
    const listed = listedGates;

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

  /**
   * The README's Documents section tells a reader which file types the app will
   * display and which it will only hand back as a download, and every
   * download-only case is given a REASON so it reads as a decision. That table
   * is prose over a lookup table in `@hvault/shared`, which is the shape
   * documentation rots in silently: adding one entry to `PREVIEW_MODES` is a
   * one-line change that makes the README wrong, and nothing else would notice.
   *
   * Both directions are checked, and the second is the one that matters more.
   * An extension the code renders but the README omits is a feature nobody
   * knows about; an extension the README advertises and the code does not
   * render is a promise the product breaks, and it is the failure a reader
   * meets as "download to view" on a file the docs said would open.
   */
  describe('the document preview table', () => {
    /** The `#### What renders, and what is download-only` subsection. */
    const viewer = readme.slice(
      readme.indexOf('#### What renders, and what is download-only'),
      readme.indexOf('#### Documents are not in your backups'),
    );

    /** `mode -> the extensions the README lists for it`, from the first table. */
    const documented = new Map<string, Set<string>>(
      [...viewer.matchAll(/^\|\s*`([a-z]+)`\s*\|([^|]*)\|/gm)].map((row): [string, Set<string>] => [
        row[1]!,
        new Set([...row[2]!.matchAll(/`([a-z0-9]+)`/g)].map((m) => m[1]!)),
      ]),
    );

    /** `mode -> the extensions the code actually maps to it`, minus `none`. */
    const actual = new Map<string, Set<string>>();
    for (const [extension, mode] of Object.entries(PREVIEW_MODES)) {
      if (mode === 'none') continue;
      const set = actual.get(mode) ?? new Set<string>();
      set.add(extension);
      actual.set(mode, set);
    }

    const sorted = (set: Set<string> | undefined): string[] => [...(set ?? [])].sort();

    it('lists every render mode the code has, and no mode it does not', () => {
      expect([...documented.keys()].sort()).toEqual([...actual.keys()].sort());
    });

    it.each([...actual.keys()].sort())(
      'lists exactly the extensions PREVIEW_MODES maps to `%s`',
      (mode) => {
        expect(sorted(documented.get(mode))).toEqual(sorted(actual.get(mode)));
      },
    );

    it('names every deliberately-unrendered extension in the download-only table', () => {
      // `none` is a first-class answer in PREVIEW_MODES rather than the absence
      // of one: it marks the types this project DECIDED against rendering, as
      // distinct from the ones it merely does not recognise. Each of those owes
      // the reader a reason, so each must appear below the split.
      const downloadOnly = viewer.slice(viewer.indexOf('Everything else is **download-only'));
      const decided = Object.entries(PREVIEW_MODES)
        .filter(([, mode]) => mode === 'none')
        .map(([extension]) => extension);
      expect(decided.length).toBeGreaterThan(0);
      for (const extension of decided) {
        expect(downloadOnly, `the download-only table must name \`${extension}\``).toContain(
          `\`${extension}\``,
        );
      }
    });

    it('quotes the size past which a document is download-only, as the app renders it', () => {
      // The app builds its refusal with formatBytes(MAX_PREVIEW_BYTES), so the
      // README has to quote the same string or a reader is told one number and
      // shown another.
      expect(viewer).toContain(`over ${formatBytes(MAX_PREVIEW_BYTES)}`);
    });
  });

  /**
   * CONTRIBUTING's "N gates whose failure asks for something specific" heading
   * counts GATES, not bullets — one bullet names two of them, and one names no
   * gate at all (the duplication ceiling, which belongs to `deadcode`).
   *
   * It is spelled out in words in two places, a heading and the sentence under
   * it, which is why it has drifted twice: the phase that added the `storage`
   * bullet moved it correctly, and the phase that added the `e2e`/`a11y` bullet
   * did not, leaving "Ten" over twelve gates. A word is invisible to every
   * numeric check in this repository, so it needs its own.
   */
  it('CONTRIBUTING counts the gates it singles out, in the words it spells them in', () => {
    const contributing = readFileSync(path.resolve(repoRoot, 'CONTRIBUTING.md'), 'utf-8');
    const WORDS = [
      'Zero',
      'One',
      'Two',
      'Three',
      'Four',
      'Five',
      'Six',
      'Seven',
      'Eight',
      'Nine',
      'Ten',
      'Eleven',
      'Twelve',
      'Thirteen',
      'Fourteen',
      'Fifteen',
      'Sixteen',
    ];

    const heading = /^### ([A-Z][a-z]+) gates whose failure asks for something specific$/m.exec(
      contributing,
    );
    expect(heading, 'the singled-out-gates heading must still exist').not.toBeNull();

    const rest = contributing.slice(heading!.index + heading![0].length);
    // Bounded at the next heading of ANY level, so the section can never
    // silently run on into the escape-hatch table below it and count a gate
    // named there.
    const nextHeading = rest.search(/\n#{2,4} /);
    const section = nextHeading === -1 ? rest : rest.slice(0, nextHeading);

    // Only ids the runner actually registers count. A bullet naming something
    // that is not a gate (the duplication ceiling) must not inflate the number,
    // and a bullet naming a gate that no longer exists must fail rather than
    // keep the arithmetic working.
    const registered = new Set(listedGates.map((gate) => gate.id));
    // `[a-z0-9-]`, not `[a-z-]`: two gate ids carry digits (`e2e`, `a11y`) and
    // they share one bullet, so a class without them skipped that bullet
    // ENTIRELY and made the expected number two too low — which is the shape of
    // arithmetic that agrees with a wrong document.
    const named = new Set(
      [...section.matchAll(/^- \*\*`([a-z0-9-]+)`\*\*(?: and \*\*`([a-z0-9-]+)`\*\*)?/gm)]
        .flatMap((match) => [match[1], match[2]])
        .filter((id): id is string => id !== undefined),
    );
    const unregistered = [...named].filter((id) => !registered.has(id));
    expect(unregistered, 'every gate this section singles out must still be registered').toEqual(
      [],
    );
    expect(named.size).toBeGreaterThan(0);

    const word = WORDS[named.size];
    expect(word, `no word for ${String(named.size)} gates`).toBeDefined();
    expect(heading![1]).toBe(word);
    // The sentence under it repeats the number, and it is the copy that gets
    // forgotten, so it is asserted separately rather than inferred.
    expect(section).toContain(`These ${String(word).toLowerCase()} are worth reading`);
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
