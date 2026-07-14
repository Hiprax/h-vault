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
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import { computeNextTag } from '../../../scripts/ci/lib/version.mjs';

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
      steps: { name?: string; uses?: string; with?: Record<string, unknown>; run?: string }[];
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
    // already accrued are not refunded when the artifact is deleted.
    expect(releaseYaml).not.toMatch(/actions\/upload-artifact/);
    expect(releaseYaml).not.toMatch(/actions\/cache/);
  });

  it('runs one job, so it is billed one rounded-up minute per push', () => {
    expect(Object.keys(release.jobs)).toHaveLength(1);
  });

  it('bounds the job with a timeout', () => {
    const job = Object.values(release.jobs)[0];
    expect(job?.['timeout-minutes']).toBeGreaterThan(0);
  });

  it('does not install dependencies or build anything', () => {
    expect(releaseYaml).not.toMatch(/npm ci|npm install|npm run build/);
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

  it('is gated on nothing', () => {
    // The whole point: the release is never blocked by a check, because the
    // checks already ran locally before the push.
    const job = Object.values(release.jobs)[0];
    expect(job?.needs).toBeUndefined();
  });

  it('checks out full history, so tag computation can see every tag', () => {
    const job = Object.values(release.jobs)[0];
    const checkout = job?.steps.find((step) => step.uses?.startsWith('actions/checkout'));
    expect(checkout?.with?.['fetch-depth']).toBe(0);
  });

  it('passes --verify-tag when publishing the release', () => {
    // Without it, `gh release create` given a missing tag does not fail: it
    // creates the tag from the tip of the default branch, publishing a release
    // that points at a different commit than the one this run built.
    const job = Object.values(release.jobs)[0];
    const publish = job?.steps.find((step) => step.run?.includes('gh release create'));
    expect(publish?.run).toMatch(/--verify-tag/);
  });
});

describe('local pipeline covers every job the deleted CI workflow ran', () => {
  const localCi = read('scripts', 'ci', 'local-ci.mjs');
  const gateIds = [...localCi.matchAll(/^\s{4}id: '([a-z0-9-]+)',$/gm)].map((match) => match[1]);

  it.each([
    ['build', 'ci job · Build'],
    ['lint', 'ci job · Lint'],
    ['type-check', 'ci job · Type check'],
    ['test', 'ci job · Test'],
    ['audit', 'ci job · npm audit'],
    ['e2e', 'e2e job'],
    ['docker', 'docker-build job (images, nginx -t, compose config, Trivy)'],
    ['sast', 'sast job (CodeQL)'],
  ])('gate "%s" stands in for the %s', (gate) => {
    expect(gateIds).toContain(gate);
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
