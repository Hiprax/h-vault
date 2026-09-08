import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { AUDIT_ACTIONS, MAX_PREVIEW_BYTES, PREVIEW_MODES, formatBytes } from '@hvault/shared';
import { TIER_BUDGET_SECONDS } from '../../../scripts/ci/lib/tiers.mjs';
// The accessibility gate's membership, read from the ONE list that defines it —
// the same import `gate-surface.test.ts` takes, for the same reason: a count
// written down twice is a count that drifts.
import { A11Y_VIEW_IDS } from '../../../e2e/a11yViews.js';

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
   * The MEASURED cost of the fast tier, as opposed to its budget.
   *
   * The test above pins the budget, which `tiers.mjs` exports and a reader can
   * therefore never disagree with silently. The measured span is the opposite
   * shape of problem: it is prose, it lives in three files at once, and nothing
   * exports it. It has already drifted once — `tiers.mjs` spent twenty-five
   * phases claiming "the measured value is ~82 s" with "eight seconds of
   * headroom" while the README published 1m 19s to 2m 44s and CONTRIBUTING
   * agreed with the README, so the file the RUNNER lives in was the one telling
   * contributors the tier still fit. Two documents agreeing is not a check when
   * the third is the one that matters.
   *
   * The production change that turns this red is the one that caused the drift:
   * re-measuring the tier and updating one copy of the number without the
   * others. Every `Xm YYs to Xm YYs` span in these three files is a statement
   * about T0 — verified by inspection, and enforced here by requiring them all
   * to be the same span — so a stale copy has nowhere to hide.
   */
  it('quotes ONE measured fast-tier cost, in tiers.mjs, the README and CONTRIBUTING alike', () => {
    const tiersSource = readFileSync(
      path.resolve(repoRoot, 'scripts', 'ci', 'lib', 'tiers.mjs'),
      'utf-8',
    );
    const contributing = readFileSync(path.resolve(repoRoot, 'CONTRIBUTING.md'), 'utf-8');

    const toSeconds = (value: string): number => {
      const parts = /^(\d+)m (\d+)s$/.exec(value)!;
      return Number(parts[1]) * 60 + Number(parts[2]);
    };

    /**
     * A duration range that STRADDLES the budget is a claim about what the whole
     * tier costs — nothing else in these documents can straddle it, because the
     * per-gate figures quoted beside it sit wholly on one side or the other
     * (`lint` + `format` busy is 1m 42s to 2m 00s, both above; `lint` alone is
     * 1m 05s to 1m 16s, both below). That is what makes this checkable without
     * pinning anyone's prose: find every range of that shape and require them to
     * agree. `1m 19s to 2m 44s` and `1m 19s-2m 44s` are the same claim.
     */
    const tierSpans = (text: string): string[] =>
      [...text.matchAll(/(\d+m \d+s) ?(?:to|-|–) ?(\d+m \d+s)/g)]
        .filter(
          (m) =>
            toSeconds(m[1]!) < TIER_BUDGET_SECONDS[0] && toSeconds(m[2]!) > TIER_BUDGET_SECONDS[0],
        )
        .map((m) => `${m[1]!} to ${m[2]!}`);

    // `tiers.mjs` is the source of truth: it sits beside the runner that does the
    // measuring, and it is the copy that went stale last time while the two
    // Markdown files agreed with each other.
    const declared = new Set(tierSpans(tiersSource));
    expect(
      [...declared],
      'scripts/ci/lib/tiers.mjs must state the measured busy-machine T0 span exactly once',
    ).toHaveLength(1);
    const span = [...declared][0]!;

    for (const [name, text] of [
      ['README.md', readme],
      ['CONTRIBUTING.md', contributing],
    ] as const) {
      const found = tierSpans(text);
      expect(found.length, `${name} must quote the measured T0 span`).toBeGreaterThan(0);
      for (const quoted of found) {
        expect(quoted, `${name} quotes a fast-tier span that tiers.mjs does not`).toBe(span);
      }
    }

    /**
     * The idle figure is the other half of the measurement and the half a reader
     * acts on, because it is the one that says whether the budget is met at all.
     * It is a point value, so the straddle rule above cannot see it, and it would
     * drift on its own.
     */
    const idle = /idle machine: \*\*(\d+m \d+s)\*\*/.exec(tiersSource)?.[1];
    expect(idle, 'scripts/ci/lib/tiers.mjs must state the idle T0 figure').toBeDefined();
    for (const [name, text] of [
      ['README.md', readme],
      ['CONTRIBUTING.md', contributing],
    ] as const) {
      expect(text, `${name} must quote the idle T0 figure ${idle!}`).toContain(idle!);
    }

    // The point of splitting the measurement in two is that the halves fall on
    // opposite sides of the budget. If they ever stop doing so, every sentence
    // built on that split is wrong wherever it appears.
    expect(
      toSeconds(idle!),
      'the idle measurement no longer fits the budget — the prose saying it does is now wrong',
    ).toBeLessThanOrEqual(TIER_BUDGET_SECONDS[0]);
    expect(
      toSeconds(span.split(' to ')[1]!),
      'the slowest measured T0 run now fits the budget — re-word the prose that says it does not',
    ).toBeGreaterThan(TIER_BUDGET_SECONDS[0]);
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
   * The README's CodeQL section publishes the accepted-findings total and a
   * per-rule breakdown, each rule given the reason it was accepted rather than
   * fixed. That list is the repository's answer to "why does a security gate pass
   * with error-severity findings in it", so a reader who wants to check the
   * reasoning is reading these numbers, and they are the numbers nothing moved:
   * the section said 24 accepted and 20 `js/sql-injection` over a baseline
   * holding 27 and 23, and had been wrong across several refreshes of the
   * baseline.
   *
   * The drift is structural, not careless: the baseline is REGENERATED by a
   * command (`npm run ci:sast -- --update-baseline`) that accepts everything
   * currently reported, so the file moves whenever the code does, while the prose
   * moves only when somebody remembers it. Both directions are checked, and the
   * second matters more: a rule in the baseline with no bullet is an accepted
   * finding with no stated reason, which is precisely the thing this section
   * exists to rule out.
   */
  describe('the accepted CodeQL findings', () => {
    interface CodeqlBaseline {
      findings: { rule: string; file: string; fingerprint: string }[];
    }

    const baseline = JSON.parse(
      readFileSync(path.resolve(repoRoot, 'scripts', 'ci', 'codeql-baseline.json'), 'utf-8'),
    ) as CodeqlBaseline;

    /**
     * The prose block, bounded so no bullet outside it can be counted.
     *
     * BOTH anchors are asserted present, because the two failures are not
     * symmetrical: losing the opening one makes `slice(-1, n)` empty, which reds
     * the rule-set case for the right reason, while losing the CLOSING one makes
     * `slice(i, -1)` run to the end of the README and start counting bullets from
     * unrelated sections. That one would fail confusingly or, worse, not at all.
     */
    const sectionStart = readme.indexOf('CodeQL currently reports');
    const sectionEnd = readme.indexOf('They are recorded in `scripts/ci/codeql-baseline.json`');
    const section = readme.slice(sectionStart, sectionEnd);

    /** `rule -> the count the README claims for it`, in the order it lists them. */
    const claimedBullets = [...section.matchAll(/^\s*- (\d+) `(js\/[a-z0-9-]+)`/gm)].map(
      (m) => [m[2]!, Number(m[1])] as const,
    );
    const claimed = new Map<string, number>(claimedBullets);

    /** `rule -> the number of entries the baseline actually holds`. */
    const actual = new Map<string, number>();
    for (const finding of baseline.findings) {
      actual.set(finding.rule, (actual.get(finding.rule) ?? 0) + 1);
    }

    it('keeps the section this reads bounded at both ends', () => {
      expect(sectionStart, 'the README must open the CodeQL findings section').toBeGreaterThan(-1);
      expect(sectionEnd, 'the README must close the CodeQL findings section').toBeGreaterThan(
        sectionStart,
      );
    });

    it('states the accepted total the baseline file actually holds', () => {
      const total = /CodeQL currently reports (\d+) accepted error-severity findings/.exec(readme);
      expect(total, 'the README must state the accepted-findings total').not.toBeNull();
      expect(Number(total![1])).toBe(baseline.findings.length);
    });

    it('gives a reason for every rule in the baseline, and for no rule that is not', () => {
      // A rule listed here but absent from the baseline advertises a review of
      // something the gate is not accepting; a rule in the baseline with no
      // bullet is an unexplained exemption. Neither is visible from the other
      // direction, so both are asserted.
      expect([...claimed.keys()].sort()).toEqual([...actual.keys()].sort());
      expect(actual.size).toBeGreaterThan(0);
      // One bullet per rule. Two bullets for the same rule would collapse into
      // the map above, silently discarding the first — and the sum below would
      // then be the only thing that noticed, which it would report as a wrong
      // total rather than as a duplicated rule.
      expect(claimedBullets.map(([rule]) => rule)).toEqual([...claimed.keys()]);
    });

    it.each([...actual.keys()].sort())('counts the accepted `%s` findings correctly', (rule) => {
      expect(claimed.get(rule)).toBe(actual.get(rule));
    });

    it('breaks the total down without losing or inventing a finding', () => {
      // The total and the bullets are two independent statements in the prose,
      // and a phase that corrects one and not the other leaves the section
      // self-contradicting while both of the checks above still pass.
      const summed = [...claimed.values()].reduce((sum, count) => sum + count, 0);
      expect(summed).toBe(baseline.findings.length);
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

/**
 * The number of views the accessibility gate scans, in every document that
 * states it.
 *
 * `e2e/a11yViews.ts` is the gate's MEMBERSHIP, and three things already read it
 * so that a scan of nothing cannot pass as a scan that found nothing (the spec's
 * own final assertion, `scripts/ci/a11y-gate.mjs`'s report check, and
 * `gate-surface.test.ts`'s literal pin of the id list). What NOTHING read was
 * the number spelled out in the prose beside them, and it drifted the moment the
 * document store's viewer gained two more views: the list and the ratcheted
 * `a11y.viewsScanned` said 22 while seven sentences across six files — the spec's
 * own docblock, the README's gate table, CONTRIBUTING's prerequisite note, the
 * gate script's header and the coverage manifest's two known-gap entries — still
 * said twenty. Four more turned up the next day, in the pipeline runner's own
 * gate title and in the manifest's statement of what a green run means, which
 * still said twenty and four after the sweep had grown twice.
 *
 * **The production change that turns this red is adding or removing an entry in
 * `A11Y_VIEWS` without moving the prose with it.** It was written the day before
 * ten views were added, on purpose: a guard added afterwards records the drift, a
 * guard added before prevents it. It earned that immediately — the ten-view
 * change had to move fourteen sentences, and this is what said which ones.
 *
 * Spelled-out words rather than digits, because that is how these sentences are
 * written and rewriting seven documents to suit a regular expression is the wrong
 * way round. The same technique, and the same reason, as the CONTRIBUTING
 * gate-count case above.
 *
 * The document-store subset is derived rather than listed: every id that names a
 * document begins with `document`, and `sandbox-rendered` — the isolated render
 * document, scanned as a top-level page — deliberately does not, because it needs
 * neither a session nor the storage engine. Two of the sentences below count that
 * subset instead of the whole, and both had it wrong as well.
 */
describe('the accessibility gate’s scanned-view count', () => {
  /** `n` spelled the way English spells it, for the range these counts live in. */
  const NUMBER_WORDS = [
    'zero',
    'one',
    'two',
    'three',
    'four',
    'five',
    'six',
    'seven',
    'eight',
    'nine',
    'ten',
    'eleven',
    'twelve',
    'thirteen',
    'fourteen',
    'fifteen',
    'sixteen',
    'seventeen',
    'eighteen',
    'nineteen',
    'twenty',
    'twenty-one',
    'twenty-two',
    'twenty-three',
    'twenty-four',
    'twenty-five',
    'twenty-six',
    'twenty-seven',
    'twenty-eight',
    'twenty-nine',
    'thirty',
    'thirty-one',
    'thirty-two',
    'thirty-three',
    'thirty-four',
    'thirty-five',
    'thirty-six',
    'thirty-seven',
    'thirty-eight',
    'thirty-nine',
    'forty',
  ] as const;

  const viewIds = A11Y_VIEW_IDS;
  const total = viewIds.length;
  const documentViews = viewIds.filter((id) => id.startsWith('document')).length;

  /**
   * One sentence that states one of the two counts.
   *
   * `expected` is a function of the two real numbers rather than a literal, so a
   * sentence that legitimately says "the other N-1" moves with the list too — the
   * spec has two of those, and a guard that only knew the total would have left
   * them behind.
   */
  interface CountSite {
    file: string;
    pattern: RegExp;
    expected: number;
    what: string;
  }

  const SITES: CountSite[] = [
    {
      // The sentence this used to pin said "two of the twenty-two views below",
      // and the "two" was a second stale count — it meant sign-in and
      // registration, and there are now SEVEN pages a signed-out browser can
      // reach. Rewritten to carry one number instead of two, so there is nothing
      // left in it that can drift independently of the list.
      file: 'e2e/a11y.spec.ts',
      pattern: /would miss most of the ([a-z-]+) views below/,
      expected: total,
      what: 'the spec docblock’s own view total',
    },
    {
      file: 'e2e/a11y.spec.ts',
      pattern: /does not hide the state of the other\n \* ([a-z-]+) —/,
      expected: total - 1,
      what: 'the views a soft failure leaves reportable',
    },
    {
      file: 'e2e/a11y.spec.ts',
      pattern: /report somebody has to run ([a-z-]+) times/,
      expected: total,
      what: 'the runs a fail-fast report would cost',
    },
    {
      file: 'e2e/a11y.spec.ts',
      pattern: /for the sign-in, ([a-z-]+) axe runs over a/,
      expected: total,
      what: 'the timeout rationale’s run count',
    },
    {
      file: 'e2e/a11y.spec.ts',
      pattern: /the walk continues: ([a-z-]+) more views are worth more/,
      expected: total - 1,
      what: 'the soft-assertion rationale',
    },
    {
      file: 'README.md',
      pattern: /axe-core over ([a-z-]+) primary views and modals/,
      expected: total,
      what: 'the README gate table',
    },
    {
      file: 'CONTRIBUTING.md',
      pattern: /document journeys plus ([a-z-]+) of the [a-z-]+ scanned accessibility views/,
      expected: documentViews,
      what: 'CONTRIBUTING’s count of views that need the storage engine',
    },
    {
      file: 'CONTRIBUTING.md',
      pattern: /document journeys plus [a-z-]+ of the ([a-z-]+) scanned accessibility views/,
      expected: total,
      what: 'CONTRIBUTING’s view total',
    },
    {
      file: 'scripts/ci/a11y-gate.mjs',
      pattern: /runs axe over ([a-z-]+) views and modals/,
      expected: total,
      what: 'the gate script’s header',
    },
    {
      file: 'scripts/ci/a11y-gate.mjs',
      pattern: /([A-Za-z-]+) of those [a-z-]+ views are the document store's/,
      expected: documentViews,
      what: 'the gate script’s reason for declaring `docker`',
    },
    {
      file: 'scripts/ci/a11y-gate.mjs',
      pattern: /[A-Za-z-]+ of those ([a-z-]+) views are the document store's/,
      expected: total,
      what: 'the gate script’s view total',
    },
    {
      file: '.testfortress/verify.json',
      pattern: /covered by axe over ([a-z-]+) views/,
      expected: total,
      what: 'the visual-regression known gap',
    },
    {
      file: '.testfortress/verify.json',
      pattern: /currently open across the ([a-z-]+) scanned views/,
      expected: total,
      what: 'the below-threshold-a11y known gap',
    },
    {
      file: 'packages/client/tests/theme-contrast.test.ts',
      pattern: /`test:a11y`, axe over ([a-z-]+) views\)/,
      expected: total,
      what: 'the theme-contrast suite’s note on what the a11y gate cannot see',
    },
    // The last three unguarded copies, added when Phase 21 found them still
    // saying "twenty" and "four" after the sweep had grown twice. The runner's
    // title is what an operator reads while the gate is running, and the
    // manifest's `gate` string is the sentence that says what a green run means
    // — both are prose about this number, so both belong here.
    {
      file: 'scripts/ci/local-ci.mjs',
      pattern: /Accessibility \(axe over ([a-z-]+) views/,
      expected: total,
      what: 'the pipeline runner’s gate title',
    },
    {
      file: 'scripts/ci/local-ci.mjs',
      pattern: /its ([a-z-]+) document views need the engine/,
      expected: documentViews,
      what: 'the runner’s reason for declaring `docker`',
    },
    // A THIRD sentence in the same file, three lines above the `e2e` gate's title,
    // found only when the cross-browser leg was added and the gate around it was
    // read line by line. It still said "four" — the number two sweeps ago — while
    // its exact twin in `CONTRIBUTING.md` was pinned and correct at six. That is
    // the rule at the top of this block earning itself for the third time: a
    // sentence in a file that already has entries is not covered by them.
    {
      file: 'scripts/ci/local-ci.mjs',
      pattern: /the document specs plus ([a-z-]+) of the\n    \/\/ accessibility views fail/,
      expected: documentViews,
      what: 'the runner’s reason for declaring `docker` on `e2e`',
    },
    // Two more found on a second sweep of the tree, both saying "twenty" and
    // "four" long after the numbers were 32 and 6, and both the direct twin of a
    // sentence already pinned above: the README's Docker-prerequisite paragraph
    // is CONTRIBUTING's twin, and the suppression ledger's visual-regression
    // entry is the manifest's known-gap twin. Finding a copy is not the same as
    // finding them all, so the rule now is that every sentence stating either
    // number gets an entry the moment it is noticed.
    {
      file: 'README.md',
      pattern: /its journeys and ([a-z-]+) of its scanned views/,
      expected: documentViews,
      what: 'the README’s reason for declaring `docker` on `e2e` and `a11y`',
    },
    {
      file: '.testfortress/suppressions.json',
      pattern: /`test:a11y` runs axe over ([a-z-]+) views and asserts/,
      expected: total,
      what: 'the suppression ledger’s visual-regression deferral',
    },
    {
      file: '.testfortress/verify.json',
      pattern: /every primary view and modal \\u2014 ([a-z-]+) of them, in the real/,
      expected: total,
      what: 'the manifest’s statement of what a green a11y run means',
    },
    {
      file: '.testfortress/verify.json',
      pattern: /authenticated DOM, ([a-z-]+) of them the document store's/,
      expected: documentViews,
      what: 'the manifest’s count of views that need the storage engine',
    },
  ];

  it('has a word for both counts, over a non-empty view list', () => {
    // The denominator. A `viewIds` that came back empty would make every `%s`
    // case below compare `undefined` against `undefined` and pass.
    expect(total).toBeGreaterThan(10);
    expect(documentViews).toBeGreaterThan(0);
    expect(documentViews).toBeLessThan(total);
    expect(NUMBER_WORDS[total], `no word for ${String(total)}`).toBeDefined();
    expect(NUMBER_WORDS[total - 1]).toBeDefined();
    expect(NUMBER_WORDS[documentViews]).toBeDefined();
    // And the derivation of the subset is checked rather than trusted: the
    // isolated render document must NOT be counted as a document-store view,
    // because it needs neither a session nor the storage engine and the two
    // sentences that use this number are about the engine.
    expect(viewIds).toContain('sandbox-rendered');
    expect(viewIds.filter((id) => id.startsWith('document'))).not.toContain('sandbox-rendered');
  });

  it.each(SITES.map((site) => [`${site.file} — ${site.what}`, site] as const))(
    'states the right number in %s',
    (_label, site) => {
      const source = readFileSync(path.resolve(repoRoot, site.file), 'utf-8');
      const match = site.pattern.exec(source);
      expect(match, `${site.file} no longer contains the sentence this pins`).not.toBeNull();
      // Lower-cased before comparing: one of these sentences opens a paragraph, so
      // the same word is capitalised there. The NUMBER is what this pins; its case
      // belongs to the sentence it sits in.
      expect(match![1]?.toLowerCase()).toBe(NUMBER_WORDS[site.expected]);
    },
  );
});
