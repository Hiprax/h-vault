/**
 * The pipeline moved off GitHub Actions and onto the developer's machine. These
 * tests are what stops it from moving back by accident.
 *
 * Three things are guarded:
 *
 *   1. The BILLING invariant. A single re-added workflow — or a restored
 *      dependabot.yml, whose PRs are what triggered the old CI in the first
 *      place — silently starts spending Actions minutes again on a private repo.
 *      The failure is a bill, not a red test, so it needs a red test.
 *   2. The COVERAGE invariant. Deleting ci.yml deleted the only written record
 *      of what CI checked. If a gate is dropped from the local runner, nothing
 *      else in the repository would notice.
 *   3. The RELEASE invariant. Tag selection has to be idempotent and monotonic:
 *      a release workflow that re-mints an existing tag fails the push with the
 *      exact red X this whole change exists to remove.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import {
  computeNextTag,
  majorBumpAccountsForBreaking,
  majorOf,
  planRelease,
} from '../../../scripts/ci/lib/version.mjs';
import { evaluateDenominator } from '../../../scripts/ci/lib/scan-denominator.mjs';
import { extractRelease } from '../../../scripts/ci/changelog-extract.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..', '..');

const read = (...segments: string[]): string =>
  readFileSync(path.join(repoRoot, ...segments), 'utf-8');

interface ReleaseWorkflow {
  on: {
    push?: { branches?: string[]; tags?: string[] };
    workflow_dispatch?: unknown;
    pull_request?: unknown;
    schedule?: unknown;
  };
  permissions: Record<string, string>;
  concurrency: { group: string; 'cancel-in-progress': boolean };
  jobs: Record<
    string,
    {
      needs?: string[];
      'timeout-minutes'?: number;
      steps: {
        name?: string;
        id?: string;
        if?: string;
        uses?: string;
        with?: Record<string, unknown>;
        run?: string;
      }[];
    }
  >;
}

const workflowsDir = path.join(repoRoot, '.github', 'workflows');
const releaseYaml = read('.github', 'workflows', 'release.yml');
const release = parse(releaseYaml) as ReleaseWorkflow;

describe('GitHub Actions billing surface', () => {
  it('ships exactly one workflow — the release', () => {
    const workflows = readdirSync(workflowsDir).filter(
      (file) => file.endsWith('.yml') || file.endsWith('.yaml'),
    );
    expect(workflows).toEqual(['release.yml']);
  });

  it('has no dependabot configuration', () => {
    // Dependabot itself does not consume Actions minutes — but every PR it
    // opened triggered the CI workflow on `pull_request`, and that did.
    expect(existsSync(path.join(repoRoot, '.github', 'dependabot.yml'))).toBe(false);
    expect(existsSync(path.join(repoRoot, '.github', 'dependabot.yaml'))).toBe(false);
  });

  it('never uploads artifacts or populates a cache', () => {
    // Both are billed storage, metered by peak usage per hour, and charges
    // already accrued are not refunded when the artifact is deleted. The gate
    // transcripts are printed into the job log instead, so a red run is still
    // diagnosable without them. `setup-node`'s own `cache: npm` is a different
    // thing and is deliberately kept: it is managed by the action, and it is
    // what keeps a 40-minute verification job from spending a minute of it
    // re-downloading a lockfile's worth of packages.
    expect(releaseYaml).not.toMatch(/actions\/upload-artifact/);
    expect(releaseYaml).not.toMatch(/actions\/cache/);
  });

  it('bounds every job with a timeout', () => {
    for (const [name, job] of Object.entries(release.jobs)) {
      expect(job['timeout-minutes'], `job ${name}`).toBeGreaterThan(0);
    }
  });
});

describe('release workflow', () => {
  it('triggers on pushes to main and by hand — and on nothing else', () => {
    expect(release.on.push?.branches).toEqual(['main']);
    expect(release.on).toHaveProperty('workflow_dispatch');
    // A `pull_request` trigger is how the old CI got run by every Dependabot PR.
    expect(release.on.pull_request).toBeUndefined();
    expect(release.on.schedule).toBeUndefined();
  });

  it('filters on branches, so its own tag push cannot re-trigger it', () => {
    // A bare `on: push` matches branches AND tags. With the branches filter, a
    // `refs/tags/*` push cannot match — the second of two independent guards
    // against recursion (the first: GITHUB_TOKEN-triggered events never start a
    // new workflow run).
    expect(release.on.push?.branches).toBeDefined();
    expect(release.on.push?.tags).toBeUndefined();
  });

  it('grants only contents: write', () => {
    // Enough to push a tag and publish a release ("write" implies read, so
    // checkout still works); nothing else — notably not the `security-events:
    // write` the deleted CodeQL job required.
    expect(release.permissions).toEqual({ contents: 'write' });
  });

  it('serialises runs without cancelling one mid-release', () => {
    expect(release.concurrency.group).toBeTruthy();
    expect(release.concurrency['cancel-in-progress']).toBe(false);
  });

  it('runs the whole gauntlet before it will tag anything', () => {
    // This assertion is the REVERSE of the one it replaces ("is gated on
    // nothing"), and the reversal is deliberate. That test encoded an argument
    // the repository has since outgrown on both of its premises:
    //
    //   1. "a commit that reaches `main` has already passed all of it" — but
    //      CONTRIBUTING.md's "Escape hatches" table documents three supported
    //      ways past the pre-push hook, so an unverified commit reaching `main`
    //      is a supported operation, and the release published it with nothing
    //      having run anywhere.
    //   2. "re-running them on a hosted runner would spend money" — this
    //      repository is PUBLIC, where GitHub-hosted runners are free and
    //      uncapped. The saving was zero.
    //
    // So the gauntlet runs, and the tag is created only after it passes.
    expect(release.jobs['verify']).toBeDefined();
    expect(release.jobs['release']?.needs).toContain('verify');
  });

  it('verifies with the same command the pre-push hook runs, and no narrower one', () => {
    // `npm run ci` is the T0+T1 tier surface. Pinning the COMMAND rather than a
    // list of steps is what stops this job from drifting into checking less than
    // the hook does: a gate added to the manifest joins both at once.
    const steps = release.jobs['verify']?.steps ?? [];
    const gauntlet = steps.filter((step) => /npm run ci\b/.test(step.run ?? ''));
    expect(gauntlet).toHaveLength(1);
    expect(steps.some((step) => step.run === 'npm ci')).toBe(true);

    // EXACTLY `npm run ci`, with no arguments. A substring match is satisfied by
    // `npm run ci -- --only=lint`, which is a committed test filter wearing the
    // full gauntlet's name — the job would look verified and check one gate.
    expect(gauntlet[0]?.run?.trim()).toBe('npm run ci');
  });

  it('never skips a gate through the environment', () => {
    // The other half of the same hole. `local-ci.mjs` honours HVAULT_SKIP_GATES
    // from the environment, so a job-level or step-level `env:` entry shrinks the
    // run without touching the command the assertion above pins. Both halves are
    // needed; either one alone leaves the job able to check less than it claims.
    expect(releaseYaml).not.toMatch(/HVAULT_SKIP_GATES/);
    expect(releaseYaml).not.toMatch(/HUSKY/);
  });

  it('installs every gate prerequisite, so no gate can report "could not run"', () => {
    // `local-ci.mjs` declares host binaries per gate and reports a missing one
    // as exit 2 rather than as a pass. A prerequisite left uninstalled here does
    // not silently shrink the job — it turns it red — but naming them keeps the
    // two lists together, since the failure would otherwise be diagnosed on a
    // runner rather than here.
    const install = (release.jobs['verify']?.steps ?? []).map((step) => step.run ?? '').join('\n');
    for (const binary of ['actionlint', 'hadolint', 'oasdiff', 'diff-cover']) {
      expect(install, `prerequisite ${binary}`).toContain(binary);
    }
  });

  it('checks out full history in both jobs', () => {
    // The release job derives the tag from every tag that exists; the verify job
    // needs it too, because the secret scan reads every blob ever committed and
    // the coverage gate diffs against `main`. A shallow clone breaks all three.
    for (const [name, job] of Object.entries(release.jobs)) {
      const checkout = job.steps.find((step) => step.uses?.startsWith('actions/checkout'));
      expect(checkout?.with?.['fetch-depth'], `job ${name}`).toBe(0);
    }
  });

  it('passes --verify-tag when publishing the release', () => {
    // Without it, `gh release create` given a missing tag does not fail: it
    // creates the tag from the tip of the default branch, publishing a release
    // that points at a different commit than the one this run built.
    const publish = release.jobs['release']?.steps.find((step) =>
      step.run?.includes('gh release create'),
    );
    expect(publish?.run).toMatch(/--verify-tag/);
  });

  it('publishes the curated changelog section, never a generated commit list', () => {
    // `--generate-notes` threw away the one artifact this project treats as a
    // blocking requirement of every change, at the only place users read it.
    //
    // Asserted over the steps' `run` scripts rather than over the file text: the
    // workflow's own comments NAME the flag they explain the absence of, and a
    // whole-file match cannot tell a comment from a command.
    const scripts = Object.values(release.jobs)
      .flatMap((job) => job.steps)
      .map((step) => step.run ?? '')
      .join('\n');
    expect(scripts).not.toMatch(/--generate-notes/);
    const publish = release.jobs['release']?.steps.find((step) =>
      step.run?.includes('gh release create'),
    );
    expect(publish?.run).toMatch(/--notes-file/);
    expect(releaseYaml).toMatch(/changelog-extract\.mjs/);
  });

  it('refuses to publish without deciding the release from package.json', () => {
    // The guard: `next-version.mjs` exits non-zero when the tag it would create
    // disagrees with the version of truth, and every publishing step is gated on
    // its `should_release` output rather than running unconditionally.
    const steps = release.jobs['release']?.steps ?? [];
    const decide = steps.find((step) => step.run?.includes('next-version.mjs'));
    expect(decide?.id).toBe('version');
    for (const stepName of ['gh release create', 'git tag -a']) {
      const step = steps.find((s) => s.run?.includes(stepName));
      expect(step?.if, `step running ${stepName}`).toMatch(
        /steps\.version\.outputs\.should_release == 'true'/,
      );
    }
  });
});

describe('local pipeline covers every job the deleted CI workflow ran', () => {
  const localCi = read('scripts', 'ci', 'local-ci.mjs');
  const gateIds = [...localCi.matchAll(/^\s{4}id: '([a-z0-9-]+)',$/gm)].map((match) => match[1]);

  it.each([
    ['build', 'ci job · Build'],
    ['lint', 'ci job · Lint'],
    ['type-check', 'ci job · Type check'],
    // The old `Test` job ran every workspace in one step. It is now two gates,
    // because they belong to different tiers: `test` is the hermetic half
    // (shared + client) and `test-integration` spawns a real mongod. BOTH must
    // exist, or half the CI job's coverage disappears with nothing to notice.
    ['test', 'ci job · Test (shared + client)'],
    ['test-integration', 'ci job · Test (server)'],
    ['audit', 'ci job · npm audit'],
    ['e2e', 'e2e job'],
    ['docker', 'docker-build job (images, nginx -t, compose config, Trivy)'],
    ['sast', 'sast job (CodeQL)'],
  ])('gate "%s" stands in for the %s', (gate) => {
    expect(gateIds).toContain(gate);
  });

  it('runs every workspace suite between the two test gates', () => {
    // Splitting the job is only safe while the two halves still add up to all
    // three workspaces; dropping one would leave a package untested with every
    // gate green.
    const pkg = JSON.parse(read('package.json')) as { scripts: Record<string, string> };
    const covered = `${pkg.scripts['test:unit']} ${pkg.scripts['test:integration']}`;
    for (const workspace of ['packages/shared', 'packages/client', 'packages/server']) {
      expect(covered).toContain(workspace);
    }
  });

  it('adds the checks the hosted pipeline never ran', () => {
    expect(gateIds).toContain('secrets');
    expect(gateIds).toContain('format');
  });

  it('is wired into pre-push', () => {
    expect(read('.husky', 'pre-push')).toMatch(/local-ci\.mjs/);
  });

  it('scans staged files for secrets on pre-commit', () => {
    expect(read('.husky', 'pre-commit')).toMatch(/secret-scan\.mjs --staged/);
  });

  it('uses the husky v9 hook format', () => {
    // The shebang + `. "$(dirname -- "$0")/_/husky.sh"` preamble is deprecated
    // and husky's own runtime warns that it WILL FAIL in v10.
    for (const hook of ['pre-push', 'pre-commit']) {
      const contents = read('.husky', hook);
      expect(contents).not.toMatch(/#!\/usr\/bin\/env sh/);
      expect(contents).not.toMatch(/husky\.sh/);
    }
  });

  it('only lets the sast gate report SKIPPED, so no failure masquerades as a skip', () => {
    // exit 78 is honoured as "tooling unavailable" for `sast` alone (CodeQL is
    // optional). Any other gate returning 78 is a failure, not a skip.
    //
    // Counting `canSkip: true === 1` is not enough: moving the flag from the
    // `sast` gate onto the `test` gate keeps the count at 1 while breaking the
    // invariant. So bind the ONE occurrence to the `sast` gate specifically.
    const skipMatches = [...localCi.matchAll(/canSkip:\s*true/g)];
    expect(skipMatches).toHaveLength(1);

    const sastIndex = localCi.indexOf("id: 'sast'");
    expect(sastIndex).toBeGreaterThan(-1);

    const skipIndex = skipMatches[0]!.index!;
    // The flag must sit AFTER the sast gate's id...
    expect(skipIndex).toBeGreaterThan(sastIndex);
    // ...with no OTHER gate id declared between them, so it belongs to the sast
    // gate object and not to a later gate. (Moving it onto an earlier gate such
    // as `test` puts skipIndex before sastIndex and already fails above.)
    const between = localCi.slice(sastIndex, skipIndex);
    expect(between).not.toMatch(/id: '(?!sast)[a-z0-9-]+'/);

    // and the runner gates the SKIP branch on that flag
    expect(localCi).toMatch(/code === SKIP_EXIT && gate\.canSkip/);
  });

  it('docker-gate suggests a skip command that actually works', () => {
    // Regression: it used to print `HVAULT_SKIP_GATES=docker,trivy`, but there is
    // no `trivy` gate — the runner rejects unknown gate ids and aborts, so
    // following the tool's own advice failed the push instead of skipping Docker.
    const dockerGate = read('scripts', 'ci', 'docker-gate.mjs');
    expect(dockerGate).not.toMatch(/HVAULT_SKIP_GATES=[a-z,]*trivy/);
    const gateIds = [
      'engines',
      'secrets',
      'build',
      'lint',
      'format',
      'type-check',
      'test',
      'test-integration',
      'audit',
      'e2e',
      'docker',
      'sast',
    ];
    for (const suggested of [...dockerGate.matchAll(/HVAULT_SKIP_GATES=([a-z,]+)/g)]) {
      for (const id of suggested[1]!.split(',')) {
        expect(gateIds).toContain(id);
      }
    }
  });

  it('exposes the pipeline through npm scripts', () => {
    const pkg = JSON.parse(read('package.json')) as { scripts: Record<string, string> };
    expect(pkg.scripts['ci']).toMatch(/local-ci\.mjs/);
    expect(pkg.scripts['format:check']).toBeDefined();
    expect(pkg.scripts['audit:prod']).toMatch(/npm audit/);
    // Warnings were invisible in CI (`eslint .` exits 0 on them). Running
    // locally, they are cheap enough to forbid outright.
    expect(pkg.scripts['lint']).toMatch(/--max-warnings=0/);
  });

  it('exposes each tier as its own entry point', () => {
    // `verify:fast` is the T0 subset that fits a pre-commit budget; `ci` is the
    // T0+T1 push gate; `verify:full` adds T2. A tier with no command is a tier
    // nobody runs.
    const pkg = JSON.parse(read('package.json')) as { scripts: Record<string, string> };
    expect(pkg.scripts['verify:fast']).toMatch(/--tier=0\b/);
    expect(pkg.scripts['verify:full']).toMatch(/--tier=full\b/);
    expect(pkg.scripts['ci']).not.toMatch(/--tier=/);
  });
});

describe('computeNextTag', () => {
  const pkgVersion = '1.1.0';

  it('uses the package.json version when no release was ever cut', () => {
    expect(computeNextTag({ tags: [], headTags: [], pkgVersion })).toEqual({
      tag: 'v1.1.0',
      tagExists: false,
    });
  });

  it('bumps the patch of the highest existing tag', () => {
    expect(
      computeNextTag({ tags: ['v1.1.0', 'v1.1.1', 'v1.1.2'], headTags: [], pkgVersion }),
    ).toEqual({ tag: 'v1.1.3', tagExists: false });
  });

  it('orders tags numerically, not lexically', () => {
    // The bug this guards: "v1.9.0" > "v1.10.0" as strings, so a lexical sort
    // picks v1.9.0 as the highest, computes v1.9.1 — and pushes a tag that
    // already exists. Every push after the tenth minor would fail.
    expect(computeNextTag({ tags: ['v1.9.0', 'v1.10.0'], headTags: [], pkgVersion })).toEqual({
      tag: 'v1.10.1',
      tagExists: false,
    });
    expect(computeNextTag({ tags: ['v1.99.99', 'v2.0.0'], headTags: [], pkgVersion })).toEqual({
      tag: 'v2.0.1',
      tagExists: false,
    });
  });

  it('lets a manual package.json bump cut a minor or major release', () => {
    expect(
      computeNextTag({ tags: ['v1.1.0', 'v1.1.5'], headTags: [], pkgVersion: '1.2.0' }),
    ).toEqual({ tag: 'v1.2.0', tagExists: false });
    expect(
      computeNextTag({ tags: ['v1.1.0', 'v1.1.5'], headTags: [], pkgVersion: '2.0.0' }),
    ).toEqual({ tag: 'v2.0.0', tagExists: false });
  });

  it('ignores a package.json version that has fallen behind the tags', () => {
    // Otherwise a forgotten (or reverted) version field would try to re-mint a
    // tag that already exists.
    expect(computeNextTag({ tags: ['v1.2.0'], headTags: [], pkgVersion: '1.1.0' })).toEqual({
      tag: 'v1.2.1',
      tagExists: false,
    });
  });

  it('is idempotent: an already-tagged HEAD mints nothing new', () => {
    // A re-run, or a workflow_dispatch on an unchanged commit. Stacking a second
    // tag on the same commit would produce two releases of identical code.
    expect(
      computeNextTag({ tags: ['v1.1.0', 'v1.1.1'], headTags: ['v1.1.1'], pkgVersion }),
    ).toEqual({ tag: 'v1.1.1', tagExists: true });
  });

  it('picks the highest tag when HEAD carries several', () => {
    expect(
      computeNextTag({ tags: ['v1.1.0', 'v1.2.0'], headTags: ['v1.1.0', 'v1.2.0'], pkgVersion }),
    ).toEqual({ tag: 'v1.2.0', tagExists: true });
  });

  it('ignores tags that are not plain vX.Y.Z', () => {
    // A hand-made `v1.3.0-rc.1` must never become the base for an automated tag.
    expect(
      computeNextTag({
        tags: ['v1.1.0', 'v1.3.0-rc.1', 'nightly', 'release-2024', 'v1.1.1'],
        headTags: [],
        pkgVersion,
      }),
    ).toEqual({ tag: 'v1.1.2', tagExists: false });
  });

  it('ignores a non-release tag sitting on HEAD', () => {
    expect(computeNextTag({ tags: ['v1.1.0'], headTags: ['nightly'], pkgVersion })).toEqual({
      tag: 'v1.1.1',
      tagExists: false,
    });
  });

  it('refuses a package.json version that is not semver', () => {
    expect(() => computeNextTag({ tags: [], headTags: [], pkgVersion: 'not-a-version' })).toThrow(
      /not semver/,
    );
  });
});

describe('planRelease: the tag may never disagree with the version of truth', () => {
  // `package.json` is what `scripts/inject-version.js` compiles into
  // APP_VERSION, which `/health` and the OpenAPI document both serve. A release
  // tagged v0.9.1 whose artifact reports 0.8.0 is the defect this guards.

  it('releases when the version has never been tagged and the series agrees', () => {
    expect(planRelease({ tags: ['v0.8.0'], headTags: [], pkgVersion: '0.9.0' })).toMatchObject({
      tag: 'v0.9.0',
      shouldRelease: true,
      createTag: true,
      mismatch: false,
    });
  });

  it('cuts the first release when no tag exists at all', () => {
    expect(planRelease({ tags: [], headTags: [], pkgVersion: '0.1.0' })).toMatchObject({
      tag: 'v0.1.0',
      shouldRelease: true,
      createTag: true,
      mismatch: false,
    });
  });

  it('publishes nothing on an ordinary push that bumped no version', () => {
    // The common case, and emphatically NOT a failure: the version on this
    // commit was released already, so there is nothing new to publish. The old
    // behaviour minted v0.8.1 here — a release nobody wrote notes for, whose
    // own /health endpoint reported 0.8.0.
    const plan = planRelease({ tags: ['v0.8.0'], headTags: [], pkgVersion: '0.8.0' });
    expect(plan).toMatchObject({ shouldRelease: false, createTag: false, mismatch: false });
    expect(plan.reason).toMatch(/already released/);
  });

  it('still reconciles the Release when HEAD already carries its tag', () => {
    // A run interrupted between pushing the tag and publishing the Release, or
    // a workflow_dispatch re-run. The tag must not be created twice, but the
    // Release still has to appear, which is what makes the workflow idempotent.
    expect(
      planRelease({ tags: ['v0.8.0'], headTags: ['v0.8.0'], pkgVersion: '0.8.0' }),
    ).toMatchObject({ tag: 'v0.8.0', shouldRelease: true, createTag: false, mismatch: false });
  });

  it('REFUSES when the tag series has run ahead of package.json', () => {
    // The guard firing. Tags reached v0.9.0 while package.json stayed at 0.8.0,
    // so the series would mint v0.9.1 for an artifact that reports 0.8.0.
    const plan = planRelease({
      tags: ['v0.8.0', 'v0.9.0'],
      headTags: [],
      pkgVersion: '0.8.1',
    });
    expect(plan.mismatch).toBe(true);
    expect(plan.shouldRelease).toBe(false);
    expect(plan.createTag).toBe(false);
    expect(plan.tag).not.toBe('v0.8.1');
    expect(plan.reason).toMatch(/package\.json says 0\.8\.1/);
  });

  it('REFUSES to release a bumped version from a commit already tagged as another', () => {
    // package.json says 0.9.0 but HEAD is already released as v0.8.0. Tagging
    // the same commit twice would publish two releases of identical code under
    // two version numbers, only one of which the artifact reports.
    expect(
      planRelease({ tags: ['v0.8.0'], headTags: ['v0.8.0'], pkgVersion: '0.9.0' }),
    ).toMatchObject({ mismatch: true, shouldRelease: false });
  });

  it('REFUSES a version no vX.Y.Z tag can name', () => {
    // `1.2.3-beta.1` would be truncated to v1.2.3 — a tag naming a different
    // version than the one the artifact reports, which is the same defect
    // arriving through the front door.
    const plan = planRelease({ tags: [], headTags: [], pkgVersion: '1.2.3-beta.1' });
    expect(plan.mismatch).toBe(true);
    expect(plan.shouldRelease).toBe(false);
    expect(plan.reason).toMatch(/plain X\.Y\.Z/);
  });

  it('agrees with the repository as it stands right now', () => {
    // Not a tautology: it reads the real package.json and asserts the plan is
    // one of the two states a well-formed repository can be in, never a
    // mismatch. A version field edited into a shape no tag can name fails here.
    const version = (JSON.parse(read('package.json')) as { version: string }).version;
    const plan = planRelease({ tags: [`v${version}`], headTags: [], pkgVersion: version });
    expect(plan.mismatch).toBe(false);
    expect(plan.versionTag).toBe(`v${version}`);
  });
});

describe('majorOf', () => {
  it('reads the MAJOR component, and refuses a non-version', () => {
    expect(majorOf('0.8.0')).toBe(0);
    expect(majorOf('1.0.0')).toBe(1);
    expect(majorOf('10.2.3')).toBe(10);
    expect(majorOf('not-a-version')).toBeNull();
  });
});

describe('the OpenAPI breaking-change exemption expires with the release that earned it', () => {
  // `audit:openapi` lets a breaking API change through only when a MAJOR bump
  // accounts for it. The exemption is granted against a COMMITTED snapshot that
  // may lag, which is what makes the obvious test wrong.

  it('grants the exemption to the release that is the bump', () => {
    expect(majorBumpAccountsForBreaking('0.8.0', '1.0.0')).toBe(true);
    expect(majorBumpAccountsForBreaking('1.4.2', '2.0.0')).toBe(true);
  });

  it('does NOT keep granting it for the rest of that major line', () => {
    // The hole this closes. Once 1.0.0 ships a breaking change without the
    // snapshot being refreshed, the snapshot describes 0.8.0 forever — and
    // `major(current) > major(snapshot)` is then true for every 1.x release, so
    // the gate would wave through unversioned breaking changes indefinitely
    // while still reporting that it checked.
    expect(majorBumpAccountsForBreaking('0.8.0', '1.1.0')).toBe(false);
    expect(majorBumpAccountsForBreaking('0.8.0', '1.0.1')).toBe(false);
    expect(majorBumpAccountsForBreaking('0.8.0', '1.9.9')).toBe(false);
  });

  it('refuses a bump that skips a major, so a two-major-stale snapshot cannot be leaned on', () => {
    expect(majorBumpAccountsForBreaking('0.8.0', '2.0.0')).toBe(false);
  });

  it('refuses when nothing was bumped, or when the version went backwards', () => {
    expect(majorBumpAccountsForBreaking('0.8.0', '0.9.0')).toBe(false);
    expect(majorBumpAccountsForBreaking('0.8.0', '0.8.0')).toBe(false);
    expect(majorBumpAccountsForBreaking('2.0.0', '1.0.0')).toBe(false);
  });

  it('refuses rather than throwing on a version it cannot read', () => {
    expect(majorBumpAccountsForBreaking('', '1.0.0')).toBe(false);
    expect(majorBumpAccountsForBreaking('0.8.0', 'not-a-version')).toBe(false);
  });
});

describe('changelog extraction: the release body is the curated entry', () => {
  const changelog = read('CHANGELOG.md');

  it('extracts a real section from the real CHANGELOG.md', () => {
    // Against the committed file, not a fixture: a format the extractor cannot
    // read is a release with no notes, and the file it must read is this one.
    const section = extractRelease(changelog, '0.8.0');
    expect(section).not.toBeNull();
    expect(section).toMatch(/^### /m);
    // It stops at the next release's heading.
    expect(section).not.toMatch(/^## \[0\.7\.0\]/m);
    expect(section).not.toMatch(/^## \[/m);
  });

  it('extracts every released version the file documents', () => {
    // Every `## [X.Y.Z]` heading must be extractable, or some future release
    // publishes empty notes. Derived from the file rather than hard-coded, so a
    // new release section is covered the day it is written.
    const versions = [...changelog.matchAll(/^## \[(\d+\.\d+\.\d+)\]/gm)].map((m) => m[1]!);
    expect(versions.length).toBeGreaterThan(5);
    for (const version of versions) {
      expect(extractRelease(changelog, version), `section ${version}`).not.toBeNull();
    }
  });

  it('excludes the link-reference block from the oldest section', () => {
    // Keep a Changelog puts `[0.1.0]: https://…` at the foot of the file with no
    // heading between it and the oldest release, so "read to the next heading or
    // EOF" appends the entire link table to those notes.
    const oldest = extractRelease(changelog, '0.1.0');
    expect(oldest).not.toBeNull();
    expect(oldest).not.toMatch(/compare\/v/);
    expect(oldest).not.toMatch(/^\[Unreleased\]:/m);
  });

  it('never answers a version with the Unreleased section', () => {
    // Cutting a release means renaming that heading. Falling back to it would
    // publish the pending section under a version it does not describe — and
    // then publish the same text again under the next one.
    const unreleased = extractRelease(changelog, '9.9.9');
    expect(unreleased).toBeNull();
  });

  it('treats a heading with no content as missing', () => {
    // An empty body is indistinguishable from notes that were silently dropped.
    expect(
      extractRelease('## [1.0.0] - 2026-01-01\n\n## [0.9.0] - 2025-12-01\n\n- old\n', '1.0.0'),
    ).toBeNull();
  });

  it('does not let a version match a longer one that starts with it', () => {
    const markdown = '## [0.1.10] - 2026-01-02\n\n- ten\n\n## [0.1.1] - 2026-01-01\n\n- one\n';
    expect(extractRelease(markdown, '0.1.1')).toBe('- one');
    expect(extractRelease(markdown, '0.1.10')).toBe('- ten');
  });

  it('keeps the subheadings inside a section', () => {
    const markdown = '## [1.0.0] - 2026-01-01\n\n### Added\n\n- a thing\n\n### Fixed\n\n- a bug\n';
    const section = extractRelease(markdown, '1.0.0');
    expect(section).toContain('### Added');
    expect(section).toContain('### Fixed');
    expect(section).toContain('- a bug');
  });
});

/**
 * The secret scanner's DENOMINATOR, which decides whether a scan read enough to
 * be believed.
 *
 * The rule is not "zero scanned files is fatal": that shipped as a pre-commit
 * hook which refused every documentation-only and test-only commit, because
 * every file such a commit stages is one the scanner was deliberately told to
 * skip. The three causes of "zero scanned" have to be told apart, and the
 * relaxation has to stay confined to the staged mode — over the whole tree,
 * "everything was excluded" is the over-broad-pattern failure the check exists
 * to catch.
 */
describe('secret-scan denominator: zero scanned files has three causes, not one', () => {
  it('fails a staged scan that enumerated nothing at all', () => {
    const verdict = evaluateDenominator({ staged: true, enumerated: 0, excluded: [], scanned: 0 });

    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toBe('empty-enumeration');
    expect(verdict.message).toContain('a scan of nothing finds nothing');
    // The hole this fix must not open: an empty enumeration is not the same
    // thing as an enumeration that was entirely excluded, and must never be
    // answered with the excluded-only pass.
    expect(verdict.message).not.toContain('nothing to scan');
  });

  it('fails a whole-tree scan that enumerated nothing at all', () => {
    const verdict = evaluateDenominator({ staged: false, enumerated: 0, excluded: [], scanned: 0 });

    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toBe('empty-enumeration');
    expect(verdict.message).toContain('the enumeration is broken');
    expect(verdict.message).not.toContain('nothing to scan');
  });

  it('passes a staged set whose every file is on the exclusion list', () => {
    const verdict = evaluateDenominator({
      staged: true,
      enumerated: 1,
      excluded: ['SECURITY.md'],
      scanned: 0,
    });

    expect(verdict.ok).toBe(true);
    expect(verdict.reason).toBe('all-excluded');
    // It has to say WHAT was excluded, or the developer is told a hook passed
    // for a reason they cannot check.
    expect(verdict.message).toContain('SECURITY.md');
    expect(verdict.message).toContain('nothing to scan');
    // ...and it must not claim to have read anything, which is the whole point
    // of keeping a denominator at all.
    expect(verdict.message).not.toMatch(/no secrets in/);
  });

  it('still fails a WHOLE-TREE scan whose every file is on the exclusion list', () => {
    // The mode-awareness, asserted from the side that keeps the guard: a tree of
    // thousands of files cannot legitimately be nothing but documentation and
    // fixtures, so this is the over-broad-pattern failure. Making the staged
    // relaxation global would turn this green and delete the check.
    const verdict = evaluateDenominator({
      staged: false,
      enumerated: 1,
      excluded: ['SECURITY.md'],
      scanned: 0,
    });

    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toBe('all-excluded');
    expect(verdict.message).toContain('over-broad');
    expect(verdict.message).not.toContain('nothing to scan');
  });

  it('fails when files survived exclusion but none of them could be read', () => {
    // `readContent` returns null on a `git show` failure or a file that vanished
    // mid-scan, and the loop steps past it without counting it. Bytes were owed
    // to this scan and it did not get them — in either mode.
    for (const staged of [true, false]) {
      const verdict = evaluateDenominator({
        staged,
        enumerated: 3,
        excluded: ['README.md'],
        scanned: 0,
      });

      expect(verdict.ok, `staged=${String(staged)}`).toBe(false);
      expect(verdict.reason).toBe('nothing-readable');
      expect(verdict.message).toContain('2 file(s) survived the exclusion list');
      expect(verdict.message).not.toContain('nothing to scan');
    }
  });

  it('reports the files it read, not the files it was handed', () => {
    // The denominator is what was READ. An excluded file that inflated this
    // count would be a scan reporting coverage it never had.
    const verdict = evaluateDenominator({
      staged: true,
      enumerated: 3,
      excluded: ['SECURITY.md', 'README.md'],
      scanned: 1,
    });

    expect(verdict.ok).toBe(true);
    expect(verdict.reason).toBe('scanned');
    expect(verdict.message).toBe('no secrets in 1 file(s)');
  });

  it('passes a set with nothing excluded at all', () => {
    const verdict = evaluateDenominator({ staged: false, enumerated: 2, excluded: [], scanned: 2 });

    expect(verdict.ok).toBe(true);
    expect(verdict.reason).toBe('scanned');
    expect(verdict.message).toBe('no secrets in 2 file(s)');
  });

  it('refuses counts that cannot describe a real scan, rather than passing them', () => {
    // The only caller derives all three from one deduped list partitioned by
    // `isExcluded`, so none of these is reachable from it. They are refused
    // anyway: this module is meant to be usable away from that caller, and the
    // wrong default for a security gate handed arithmetic it cannot explain is
    // to vouch for the scan. `staged: true` throughout, because that is the mode
    // with a passing branch to fall into.
    const incoherent = [
      {
        label: 'more excluded than enumerated',
        enumerated: 2,
        excluded: ['a', 'b', 'c'],
        scanned: 0,
      },
      { label: 'negative enumeration', enumerated: -1, excluded: [], scanned: 0 },
      { label: 'negative scan count', enumerated: 2, excluded: [], scanned: -1 },
      { label: 'scanned more than survived exclusion', enumerated: 2, excluded: ['a'], scanned: 2 },
      { label: 'fractional enumeration', enumerated: 1.5, excluded: [], scanned: 1 },
      { label: 'fractional scan count', enumerated: 3, excluded: [], scanned: 1.5 },
    ];

    for (const { label, ...counts } of incoherent) {
      const verdict = evaluateDenominator({ staged: true, ...counts });

      expect(verdict.ok, label).toBe(false);
      expect(verdict.reason, label).toBe('incoherent');
      // Never the excluded-only pass, which is the branch these would otherwise
      // fall into, and never a claimed scan.
      expect(verdict.message, label).not.toContain('nothing to scan');
      expect(verdict.message, label).not.toMatch(/no secrets in/);
    }
  });

  it('names a bounded sample of the exclusions rather than the whole commit', () => {
    // A hook's output is the only feedback `git commit` gives; a docs commit
    // touching fifty files must not bury it.
    const excluded = Array.from({ length: 7 }, (_, index) => `docs/page-${String(index)}.md`);
    const verdict = evaluateDenominator({ staged: true, enumerated: 7, excluded, scanned: 0 });

    expect(verdict.ok).toBe(true);
    expect(verdict.message).toContain('docs/page-4.md');
    expect(verdict.message).toContain('and 2 more');
    expect(verdict.message).not.toContain('docs/page-5.md');
  });
});

/**
 * A throwaway repository holding a copy of the scanner, so the program runs end
 * to end against a real git index that is not this checkout's.
 *
 * `lib/proc.mjs` derives `repoRoot` from its own location (`../../..`), so a
 * copy at `<tmp>/scripts/ci/` makes `<tmp>` the repository the scanner
 * enumerates. That is the only honest way to drive the real program: the
 * alternative is staging files in the developer's own working tree, which would
 * clobber whatever they had staged. The WHOLE `lib` directory is copied rather
 * than the modules the scanner imports today, so a new import turns this into a
 * test of the scanner rather than a test of a module-resolution error.
 */
/**
 * The variables through which git tells a child process WHERE the repository is.
 * `githooks(5)` requires clearing them before invoking git "in a foreign
 * repository or in a different working tree", which is precisely what the
 * harness below does.
 */
const GIT_LOCATION_VARIABLES = new Set([
  'GIT_DIR',
  'GIT_WORK_TREE',
  'GIT_INDEX_FILE',
  'GIT_OBJECT_DIRECTORY',
  'GIT_ALTERNATE_OBJECT_DIRECTORIES',
  'GIT_COMMON_DIR',
  'GIT_NAMESPACE',
  'GIT_CEILING_DIRECTORIES',
]);

function runScannerOn(
  files: Record<string, string>,
  options: { stage?: string[]; args?: string[] } = {},
): { status: number; output: string } {
  const dir = mkdtempSync(path.join(tmpdir(), 'hv-secret-scan-'));
  try {
    mkdirSync(path.join(dir, 'scripts', 'ci'), { recursive: true });
    cpSync(path.join(repoRoot, 'scripts', 'ci', 'lib'), path.join(dir, 'scripts', 'ci', 'lib'), {
      recursive: true,
    });
    copyFileSync(
      path.join(repoRoot, 'scripts', 'ci', 'secret-scan.mjs'),
      path.join(dir, 'scripts', 'ci', 'secret-scan.mjs'),
    );
    for (const [relative, contents] of Object.entries(files)) {
      const target = path.join(dir, relative);
      mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, contents);
    }

    // git's own variables are STRIPPED, not inherited. `githooks(5)` is explicit
    // that a hook invoking git "in a foreign repository or in a different
    // working tree" must clear these, and this harness is exactly that: with
    // `GIT_DIR` inherited, `git init` silently re-initialises the REAL
    // repository and `git add` writes these fixtures into the developer's own
    // index — both exit 0, and the assertions here would still pass, because
    // the enumeration read back is the one just written. Measured on git 2.55.0:
    // no hook on this version exports `GIT_DIR`, so nothing leaks today; forcing
    // it reproduces the overwrite exactly, which is why this does not rely on
    // which variables a given git version happens to export.
    const env = Object.fromEntries(
      Object.entries(process.env).filter(([key]) => !GIT_LOCATION_VARIABLES.has(key)),
    );

    const git = (...args: string[]): string => {
      const result = spawnSync('git', args, { cwd: dir, env, encoding: 'utf-8' });
      if (result.status !== 0) throw new Error(`git ${args.join(' ')}: ${result.stderr}`);
      return result.stdout.trim();
    };
    git('-c', 'init.defaultBranch=main', 'init', '-q');

    // The isolation, asserted rather than assumed: every later `git add` writes
    // to THIS index. A harness that silently staged into the real repository
    // would still make every assertion below pass.
    // Matched on the temp directory's unique basename rather than on the whole
    // path: git reports forward slashes on Windows, and macOS resolves
    // `/var/folders/...` to `/private/var/folders/...`, so a prefix comparison
    // would fail on two platforms for reasons that are not this bug. The real
    // repository's git dir cannot contain this basename.
    const gitDir = git('rev-parse', '--absolute-git-dir');
    expect(gitDir, `scanner harness escaped its temp repo: ${gitDir}`).toContain(
      path.basename(dir),
    );

    const staged = options.stage ?? [];
    if (staged.length > 0) git('add', ...staged);

    const result = spawnSync(
      process.execPath,
      [path.join(dir, 'scripts', 'ci', 'secret-scan.mjs'), ...(options.args ?? ['--staged'])],
      { cwd: dir, env, encoding: 'utf-8' },
    );
    return { status: result.status ?? -1, output: `${result.stdout}${result.stderr}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('secret-scan --staged: the pre-commit hook, run against a real index', () => {
  // Assembled rather than written out, so the scanner never has a reason to
  // flag this file — the same trick `lib/selftest-defects.mjs` uses.
  const AWS_KEY = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join('');
  // Everything the tree-mode cases need out of the way: the copied scanner and
  // the ignore file itself, leaving only the fixtures to enumerate.
  const IGNORE_THE_HARNESS = 'scripts/\n.gitignore\n';

  it('passes a commit that stages nothing but excluded files', () => {
    const result = runScannerOn({ 'SECURITY.md': '# Security\n' }, { stage: ['SECURITY.md'] });

    expect(result.status).toBe(0);
    expect(result.output).toContain('nothing to scan');
    expect(result.output).toContain('SECURITY.md');
    // The regression, named: this is the message that blocked the commit.
    expect(result.output).not.toContain('0 files scanned');
    expect(result.output).not.toMatch(/no secrets in/);
  });

  it('counts only the files it actually read', () => {
    const result = runScannerOn(
      { 'SECURITY.md': '# Security\n', 'src/app.ts': "export const greeting = 'hello';\n" },
      { stage: ['SECURITY.md', 'src/app.ts'] },
    );

    expect(result.status).toBe(0);
    expect(result.output).toContain('no secrets in 1 file(s)');
    // The excluded file neither inflated the denominator nor took the
    // all-excluded exit beside a file that did need reading.
    expect(result.output).not.toContain('2 file(s)');
    expect(result.output).not.toContain('nothing to scan');
  });

  it('still finds a secret in the scannable file beside an excluded one', () => {
    const result = runScannerOn(
      { 'SECURITY.md': '# Security\n', 'src/app.ts': `export const key = '${AWS_KEY}';\n` },
      { stage: ['SECURITY.md', 'src/app.ts'] },
    );

    expect(result.status).toBe(1);
    expect(result.output).toContain('src/app.ts:1');
    expect(result.output).toContain('aws-access-key');
    // The exclusion must not leak sideways into the file next to it.
    expect(result.output).not.toContain('nothing to scan');
  });

  it('still fails when nothing was staged at all', () => {
    const result = runScannerOn({ 'SECURITY.md': '# Security\n' }, { stage: [] });

    expect(result.status).toBe(1);
    expect(result.output).toContain('0 files enumerated');
    expect(result.output).toContain('a scan of nothing finds nothing');
    expect(result.output).not.toContain('nothing to scan');
  });

  it('still fails a WHOLE-TREE scan in which everything was excluded', () => {
    const result = runScannerOn(
      { '.gitignore': IGNORE_THE_HARNESS, 'SECURITY.md': '# Security\n' },
      { args: [] },
    );

    expect(result.status).toBe(1);
    expect(result.output).toContain('over-broad');
    // The staged relaxation must not reach the mode where "everything was
    // excluded" is a claim about the repository rather than about one commit.
    expect(result.output).not.toContain('nothing to scan');
  });

  it('still fails a WHOLE-TREE scan that enumerated nothing', () => {
    const result = runScannerOn({ '.gitignore': IGNORE_THE_HARNESS }, { args: [] });

    expect(result.status).toBe(1);
    expect(result.output).toContain('0 files enumerated');
    expect(result.output).not.toContain('nothing to scan');
  });

  it('still passes a WHOLE-TREE scan over a clean file', () => {
    const result = runScannerOn(
      { '.gitignore': IGNORE_THE_HARNESS, 'src/app.ts': "export const greeting = 'hello';\n" },
      { args: [] },
    );

    expect(result.status).toBe(0);
    expect(result.output).toContain('no secrets in 1 file(s)');
    expect(result.output).not.toContain('nothing to scan');
  });
});
