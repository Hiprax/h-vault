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
import { afterAll, describe, it, expect } from 'vitest';
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
import playwrightConfig from '../../../playwright.config';
import {
  computeNextTag,
  majorBumpAccountsForBreaking,
  majorOf,
  planRelease,
} from '../../../scripts/ci/lib/version.mjs';
import { evaluateDenominator } from '../../../scripts/ci/lib/scan-denominator.mjs';
import { extractRelease } from '../../../scripts/ci/changelog-extract.mjs';
import {
  OSV_EXIT,
  OsvLedgerError,
  OsvReportError,
  VULN_ACCEPT,
  acceptanceExitCode,
  classifyFindings,
  formatAccepted,
  parseAcceptanceSymbol,
  readAcceptances,
  summarizeVerdict,
  exitCodeFor as osvExitCodeFor,
  formatFinding as formatOsvFinding,
  parseOsvReport,
  summarizeReport,
} from '../../../scripts/ci/osv-gate.mjs';
import {
  COMMIT_FINGERPRINT,
  GitleaksReportError,
  LOG_OPTS,
  exitCodeFor as gitleaksExitCodeFor,
  formatFinding as formatGitleaksFinding,
  parseGitleaksSarif,
  parseIgnoreFile,
} from '../../../scripts/ci/gitleaks-gate.mjs';

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
  permissions?: Record<string, string>;
  concurrency: { group: string; 'cancel-in-progress': boolean };
  jobs: Record<
    string,
    {
      needs?: string[];
      'runs-on'?: unknown;
      permissions?: Record<string, string>;
      'timeout-minutes'?: number;
      steps: {
        name?: string;
        id?: string;
        if?: string;
        uses?: string;
        with?: Record<string, unknown>;
        env?: Record<string, unknown>;
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

  it('grants write access only to the job that publishes, and none at workflow level', () => {
    // A workflow-level block is inherited by EVERY job, so the one that runs
    // `npm ci` (every dependency's install script) and the whole gauntlet held a
    // token able to push to `main` and move tags. Each job now names its own
    // scopes: `verify` reads, `release` writes `contents` (enough to push a tag
    // and publish a Release) and nothing else — notably not the `security-events:
    // write` the deleted CodeQL job required. A job added without a block of its
    // own would inherit the repository default, which can be read-write, so every
    // job must declare one.
    expect(release.permissions).toBeUndefined();
    for (const [name, job] of Object.entries(release.jobs)) {
      expect(job.permissions, `job ${name} must declare its own permissions`).toBeDefined();
    }
    expect(release.jobs['verify']?.permissions).toEqual({ contents: 'read' });
    expect(release.jobs['release']?.permissions).toEqual({ contents: 'write' });
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
    // not silently shrink the job — it turns it red — but checking it here moves
    // the diagnosis from a runner, minutes into a hosted run, to this file.
    //
    // DERIVED from the runner's own listing rather than written out: the list
    // this replaced named four binaries, so registering a gate that requires a
    // fifth passed here and failed only on the hosted runner. What the runner
    // provides itself (a daemon the image ships, the builds its own gates
    // produce) is the one thing excluded, by name.
    const RUNNER_PROVIDED = new Set(['docker', 'build:shared', 'build:server', 'build:client']);
    const binaries = [...new Set(listedGates().flatMap((gate) => gate.requires))]
      .filter((name) => !RUNNER_PROVIDED.has(name))
      .sort();
    // Non-vacuous, and a record of what the derivation found today.
    expect(binaries).toEqual([
      'actionlint',
      'diff-cover',
      'gitleaks',
      'hadolint',
      'oasdiff',
      'osv-scanner',
    ]);
    // INSTALLED onto PATH, not merely mentioned: a name in a comment or an echo
    // satisfies a substring check while nothing lands where the gate looks.
    const commands = (release.jobs['verify']?.steps ?? [])
      .flatMap((step) => shellCommands(step.run ?? ''))
      .join('\n');
    for (const binary of binaries) {
      expect(commands, `prerequisite ${binary} installed into $HOME/.local/bin`).toMatch(
        new RegExp(`"\\$HOME/\\.local/bin(?:/|"\\s+)${binary.replace(/[-.]/g, '\\$&')}(?:"|\\s|$)`),
      );
    }
  });

  it('installs a browser for every Playwright project the E2E gate declares', () => {
    // The one prerequisite `local-ci.mjs` cannot declare, because it is not a
    // binary on `PATH` but a per-version download in Playwright's own cache. A
    // missing one is NOT reported as "could not run": Playwright fails the spec
    // with `browserType.launch: Executable doesn't exist at …`, which is exit 1
    // and reads exactly like a defect. MEASURED, on the day the second engine was
    // added: all six of its tests failed that way before the browser was fetched.
    //
    // Derived from the config rather than written out, so adding a third project
    // turns THIS red on the machine, in a second, instead of turning the hosted
    // release run red minutes into the gauntlet.
    // The `playwright install` LINE, not the whole job. Joining every step's `run`
    // and asking whether it contains "firefox" is satisfied by the word appearing in
    // a comment, or in an unrelated step, while the install command itself has
    // quietly dropped it — which is the exact failure this is here to catch.
    const installLine = (release.jobs['verify']?.steps ?? [])
      .flatMap((step) => (step.run ?? '').split('\n'))
      .find((line) => /\bplaywright install\b/.test(line));
    expect(installLine, 'release.yml must install Playwright browsers at all').toBeDefined();

    const projects = playwrightConfig.projects ?? [];
    expect(projects.length).toBeGreaterThan(0);
    for (const project of projects) {
      expect(installLine, `Playwright browser for project ${String(project.name)}`).toContain(
        String(project.name),
      );
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

/**
 * A `run:` script as the shell will execute it: backslash-continued lines joined
 * into one command, comments and blank lines dropped. Asserting over raw lines
 * lets a command split across a continuation hide the half that matters (the old
 * `curl … \` / `| tar xz` pair did exactly that).
 */
const shellCommands = (script: string): string[] =>
  script
    .replace(/\\\n\s*/g, ' ')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('#'));

const allRunScripts = (): string[] =>
  Object.values(release.jobs)
    .flatMap((job) => job.steps)
    .map((step) => step.run ?? '');

const unquote = (word: string): string => word.replace(/^(["'])(.*)\1$/, '$2');

const DIFF_COVER_REQUIREMENTS = 'scripts/ci/requirements-diff-cover.txt';
const SHA256_HEX = /^[0-9a-f]{64}$/;

/**
 * The hash-locked requirements file, one entry per requirement with its
 * continuation lines folded in. pip-compile writes each as `name==version \`
 * followed by `--hash=sha256:…` lines and a `# via` comment, which is dropped.
 */
const parseLockedRequirements = (
  text: string,
): { name: string; version: string; hashes: string[] }[] =>
  shellCommands(text).map((entry) => {
    const [spec = '', ...options] = entry.split(/\s+/);
    const match = /^([A-Za-z0-9._-]+)==(\S+)$/.exec(spec);
    if (!match) throw new Error(`not an exact pin: ${entry}`);
    const hashes = options
      .filter((option) => !option.startsWith('#'))
      .map((option) => {
        const hash = /^--hash=sha256:(.+)$/.exec(option);
        if (!hash) throw new Error(`unexpected option ${option} in ${spec}`);
        return hash[1] ?? '';
      });
    return { name: (match[1] ?? '').toLowerCase(), version: match[2] ?? '', hashes };
  });

describe('release workflow supply chain (F-01): nothing it runs can change under it', () => {
  it('keeps the checkout token out of .git/config in the job that runs third-party code', () => {
    // actions/checkout otherwise writes the job token into the clone's git config
    // for every later step to read, `npm ci`'s install scripts included. `verify`
    // pushes nothing, so it keeps nothing.
    const verifyCheckout = release.jobs['verify']?.steps.find((step) =>
      step.uses?.startsWith('actions/checkout@'),
    );
    expect(verifyCheckout?.with?.['persist-credentials']).toBe(false);

    // The release job is the opposite case, and is NOT to be "fixed" the same
    // way: `git push origin refs/tags/$TAG` authenticates with that persisted
    // token, so turning it off there breaks every release at the tag step.
    const releaseCheckout = release.jobs['release']?.steps.find((step) =>
      step.uses?.startsWith('actions/checkout@'),
    );
    expect(releaseCheckout).toBeDefined();
    expect(releaseCheckout?.with?.['persist-credentials']).not.toBe(false);
  });

  it('pins every action to a full commit SHA, naming the release in a comment', () => {
    // A tag is a pointer its owner (or whoever compromises them) can move; a
    // 40-hex commit id cannot be moved. The trailing `# vX.Y.Z` is what makes
    // the pin reviewable and refreshable (CONTRIBUTING.md), and is read from the
    // RAW text because the YAML parser discards comments.
    const usesLines = releaseYaml
      .split('\n')
      .map((line) => /^\s*(?:-\s+)?uses:\s*(.*)$/.exec(line)?.[1]?.trim())
      .filter((value): value is string => value !== undefined);
    const parsedUses = Object.values(release.jobs)
      .flatMap((job) => job.steps)
      .flatMap((step) => (step.uses === undefined ? [] : [step.uses]));

    // Every `uses` the parser sees was on a line checked here, so a flow-style
    // `{ uses: … }` cannot slip past the raw-text check.
    expect(parsedUses.length).toBeGreaterThan(0);
    expect(usesLines).toHaveLength(parsedUses.length);

    const pinned = /^([\w.-]+\/[\w.-]+(?:\/[\w./-]+)?)@([0-9a-f]{40})\s+#\s*v\d+\.\d+\.\d+$/;
    const refsByAction = new Map<string, Set<string>>();
    for (const line of usesLines) {
      const match = pinned.exec(line);
      expect(match, `uses: ${line}`).not.toBeNull();
      const [, action = '', sha = ''] = match ?? [];
      refsByAction.set(action, (refsByAction.get(action) ?? new Set<string>()).add(line));
      expect(parsedUses).toContain(`${action}@${sha}`);
    }
    // One action, one pin: two checkouts at different commits would mean one of
    // them was refreshed and the other forgotten.
    for (const [action, refs] of refsByAction) {
      expect([...refs], `${action} is pinned more than one way`).toHaveLength(1);
    }
  });

  it('runs every job on one explicitly versioned runner image, never a moving -latest label', () => {
    // `ubuntu-latest` moves to a new Ubuntu release on GitHub's schedule, which
    // changes the operating system, kernel and Docker under the gauntlet with no
    // commit here (it moved to 26.04 from 2026-10-19). A named image moves only by
    // an edit to this file, like every other pin.
    const labels = Object.values(release.jobs).map((job) => job['runs-on']);
    expect(labels.length).toBeGreaterThan(1);
    for (const label of labels) {
      expect(label).toMatch(/^ubuntu-\d{2}\.\d{2}$/);
    }
    expect(new Set(labels).size).toBe(1);
  });

  it('pins actions that run on a supported Node runtime (checkout and setup-node v5 or later)', () => {
    // Their v4 releases run on Node 20, which GitHub has deprecated for actions
    // and forces onto Node 24 with a warning; v5 is the first of each on Node 24.
    for (const action of ['actions/checkout', 'actions/setup-node']) {
      const majors = [
        ...releaseYaml.matchAll(
          new RegExp(`uses:\\s*${action}@[0-9a-f]{40}\\s+#\\s*v(\\d+)\\.`, 'g'),
        ),
      ].map((match) => Number(match[1]));
      expect(majors.length, action).toBeGreaterThan(0);
      for (const major of majors) expect(major, action).toBeGreaterThanOrEqual(5);
    }
  });

  it('declares to actionlint exactly the runner label the workflow uses, and nothing else', () => {
    // actionlint's built-in list of hosted labels predates `ubuntu-26.04`, and it
    // reports an unknown label as an error. `.github/actionlint.yaml` declares that
    // one label; holding it to exactly the workflow's label, with no other key,
    // keeps it from ever becoming a place to silence a finding.
    const config = parse(read('.github', 'actionlint.yaml')) as Record<string, unknown>;
    expect(Object.keys(config)).toEqual(['self-hosted-runner']);
    const labels = [...new Set(Object.values(release.jobs).map((job) => job['runs-on']))];
    expect(config['self-hosted-runner']).toEqual({ labels });
  });

  it('verifies every downloaded binary against a committed checksum before using it', () => {
    // A release asset can be replaced after the fact, and `curl … | tar xz`
    // unpacked whatever arrived. Each download now goes to a file, and the very
    // next command checks that file against a SHA-256 written in this workflow;
    // `set -e` stops the step on a mismatch, before the binary is ever run.
    const downloads: string[] = [];
    for (const script of allRunScripts()) {
      const commands = shellCommands(script);
      commands.forEach((command, index) => {
        expect(command, 'no download tool but curl').not.toMatch(/\bwget\b/);
        if (!/\bcurl\b/.test(command)) return;
        expect(script, 'a step that downloads stops on the first failure').toMatch(
          /set -euo pipefail/,
        );
        // Never streamed into an extractor or an interpreter.
        expect(command, `curl piped: ${command}`).not.toMatch(/\|/);
        const target = /\s(?:-o|--output)\s+(\S+)/.exec(command)?.[1];
        expect(target, `curl without -o: ${command}`).toBeDefined();
        const next = commands[index + 1] ?? '';
        const check =
          /^echo\s+"([0-9a-f]+)\s{2}(\S+)"\s*\|\s*sha256sum\s+--check\s+--strict\s+-$/.exec(next);
        expect(check, `no checksum right after: ${command}`).not.toBeNull();
        expect(check?.[1], `checksum for ${String(target)}`).toMatch(SHA256_HEX);
        expect(check?.[2]).toBe(unquote(target ?? ''));
        downloads.push(unquote(target ?? ''));
      });
    }
    // Non-vacuous: every binary this job fetches itself is among them, the two
    // security scanners included.
    for (const tool of ['actionlint', 'hadolint', 'oasdiff', 'gitleaks', 'osv-scanner']) {
      expect(
        downloads.some((file) => file.startsWith(tool)),
        `${tool} is downloaded and checked`,
      ).toBe(true);
    }
  });

  it('installs diff-cover only from its hash-locked requirements, inside a venv', () => {
    // `pipx install diff-cover` took whatever version PyPI served that minute,
    // with whatever dependencies. `--require-hashes` refuses any archive whose
    // hash is not in the committed file; `--no-deps` refuses to resolve anything
    // the file does not already list; `pip check` then proves the list complete.
    const commands = allRunScripts().flatMap(shellCommands);
    expect(commands.join('\n')).not.toMatch(/\bpipx\b/);
    const installs = commands.filter((command) => /\bpip3?["']?\s+install\b/.test(command));
    expect(installs.length).toBeGreaterThan(0);
    for (const install of installs) {
      expect(install).toMatch(/\s--require-hashes(\s|$)/);
      expect(install).toMatch(/\s--no-deps(\s|$)/);
      // Wheels only: an sdist would run its own build backend, installed
      // without any hash check, before a single file is verified.
      expect(install).toMatch(/\s--only-binary=:all:(\s|$)/);
      expect(install).toMatch(new RegExp(`\\s-r\\s+${DIFF_COVER_REQUIREMENTS}$`));
      // Into the venv, never the runner's own interpreter.
      expect(install).toMatch(/^"\$HOME\/\.diff-cover\/bin\/pip"\s/);
    }
    expect(commands).toContain('python3 -m venv "$HOME/.diff-cover"');
    expect(commands).toContain('"$HOME/.diff-cover/bin/pip" check');

    const locked = parseLockedRequirements(read(...DIFF_COVER_REQUIREMENTS.split('/')));
    expect(locked.map((entry) => entry.name)).toContain('diff-cover');
    // diff-cover has runtime dependencies; a file listing it alone would make
    // `--no-deps` install a diff-cover that cannot import them.
    expect(locked.length).toBeGreaterThan(1);
    for (const entry of locked) {
      expect(entry.hashes.length, `${entry.name} carries a hash`).toBeGreaterThan(0);
      for (const hash of entry.hashes) expect(hash, entry.name).toMatch(SHA256_HEX);
    }
    // The compiled file is the input's resolution, not a hand edit of it.
    const inputs = shellCommands(read('scripts', 'ci', 'requirements-diff-cover.in'));
    expect(inputs.length).toBeGreaterThan(0);
    for (const input of inputs) {
      const [name = '', version = ''] = input.split('==');
      expect(
        locked.find((entry) => entry.name === name.toLowerCase())?.version,
        `input ${input}`,
      ).toBe(version);
    }
  });

  it('names the pinned versions wherever a contributor is told what to install', () => {
    // A pin refreshed in the workflow but not in the prose sends every local run
    // back to the old version, and several gates ratchet counts that another
    // scanner version reports differently. The README table, its version-check
    // block and every `diff-cover==` spelling are held to the workflow and the lock.
    const install = release.jobs['verify']?.steps.find(
      (step) => step.env?.['ACTIONLINT_VERSION'] !== undefined,
    );
    const lockedDiffCover = parseLockedRequirements(
      read(...DIFF_COVER_REQUIREMENTS.split('/')),
    ).find((entry) => entry.name === 'diff-cover')?.version;
    expect(lockedDiffCover).toBeDefined();
    const diffCoverVersion = String(lockedDiffCover);
    const pinned: Record<string, string> = {
      actionlint: String(install?.env?.['ACTIONLINT_VERSION']),
      hadolint: String(install?.env?.['HADOLINT_VERSION']),
      oasdiff: String(install?.env?.['OASDIFF_VERSION']),
      gitleaks: String(install?.env?.['GITLEAKS_VERSION']),
      'osv-scanner': String(install?.env?.['OSV_SCANNER_VERSION']),
      'diff-cover': diffCoverVersion,
    };
    for (const [tool, version] of Object.entries(pinned)) {
      expect(version, `${tool} is pinned in the workflow`).toMatch(/^\d+\.\d+\.\d+$/);
    }
    const escaped = (version: string): string => version.replaceAll('.', '\\.');

    const readme = read('README.md');
    // The rows are read from the prerequisites table itself: a tool can share
    // its name with a gate (`gitleaks` is both), and the gate table, which comes
    // first, would otherwise answer with a tier.
    const prerequisitesAt = readme.indexOf(
      'binaries on `PATH`, pinned to the versions the release workflow installs.',
    );
    expect(prerequisitesAt, 'the README prerequisites paragraph').toBeGreaterThan(-1);
    const prerequisites = readme.slice(prerequisitesAt);
    for (const [tool, version] of Object.entries(pinned)) {
      const row = new RegExp(`^\\| \`${tool}\`\\s*\\|\\s*([^|\\s]+)\\s*\\|`, 'm').exec(
        prerequisites,
      );
      expect(row?.[1], `README prerequisites row for ${tool}`).toBe(version);
    }
    // The version-check block: each line is the command and the answer it gives
    // at the pin, so a reader compares their own output against it.
    for (const [command, answer] of [
      ['diff-cover --version', `diff-cover ${escaped(diffCoverVersion)}`],
      ['gitleaks version', escaped(pinned['gitleaks'] ?? '')],
      ['osv-scanner --version', `osv-scanner version: ${escaped(pinned['osv-scanner'] ?? '')}`],
    ] as const) {
      expect(readme, `README version check for ${command}`).toMatch(
        new RegExp(`${command}\\s+# ${answer}\\n`),
      );
    }

    // The runner's own install hint for each scanner, which is what a contributor
    // reads when the gate reports "could not run", names the same pin.
    const fixes = new Map(
      listedGates()
        .flatMap((gate) => gate.prerequisites)
        .map((prerequisite) => [prerequisite.name, prerequisite.fix]),
    );
    for (const tool of ['gitleaks', 'osv-scanner']) {
      expect(fixes.get(tool), `local-ci.mjs install hint for ${tool}`).toContain(
        `${tool} ${pinned[tool] ?? ''}`,
      );
    }

    const spellings = [
      readme,
      read('CONTRIBUTING.md'),
      read('scripts', 'ci', 'local-ci.mjs'),
    ].flatMap((text) => [...text.matchAll(/diff-cover==([^\s`'")]+)/g)].map((m) => m[1]));
    expect(spellings.length).toBeGreaterThan(0);
    for (const spelling of spellings) expect(spelling).toBe(diffCoverVersion);
  });

  it('reads the requirements file strictly, so a weakened lock fails the check above', () => {
    // The parser is what the assertions above stand on; a lenient one would
    // pass a file that pip itself would install without verifying.
    expect(parseLockedRequirements('a==1 \\\n    --hash=sha256:' + 'a'.repeat(64))).toEqual([
      { name: 'a', version: '1', hashes: ['a'.repeat(64)] },
    ]);
    expect(parseLockedRequirements('a==1\n')).toEqual([{ name: 'a', version: '1', hashes: [] }]);
    expect(() => parseLockedRequirements('a>=1 \\\n    --hash=sha256:00')).toThrow(
      /not an exact pin/,
    );
    expect(() => parseLockedRequirements('a==1 --index-url=http://x')).toThrow(/unexpected option/);
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
  // APP_VERSION, which the OpenAPI document and the signed-in release status both serve. A release
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

// ---------------------------------------------------------------------------
// The two scanner gates: their verdicts are decided from RECORDED reports here,
// so no test calls the OSV API, runs gitleaks, or needs either binary.
// ---------------------------------------------------------------------------

/** The skip sentinel; `sast` is the only gate allowed to return it. */
const SKIP_EXIT = 78;

describe('osv gate: the verdict is read from the report and the exit code together', () => {
  /**
   * Recorded with osv-scanner 2.4.0 (`scan source --lockfile <throwaway lockfile>
   * --format json --all-packages`) against lockfiles naming minimist 1.2.8 and
   * 1.2.5; only `source.path` was rewritten to `/recorded/package-lock.json`.
   */
  const clean = parseOsvReport(
    read('packages', 'server', 'tests', 'fixtures', 'osv-report-clean.json'),
  );
  const vulnerable = parseOsvReport(
    read('packages', 'server', 'tests', 'fixtures', 'osv-report-vulnerable.json'),
  );

  it('passes the recorded clean report and counts its packages from the report', () => {
    expect(clean).toEqual({ packages: 1, vulnerabilities: [] });
    expect(osvExitCodeFor(OSV_EXIT.CLEAN, clean)).toBe(0);
    expect(summarizeReport(clean)).toBe('0 vulnerabilities across 1 package');
    expect(summarizeReport({ packages: 1450, vulnerabilities: [] })).toBe(
      '0 vulnerabilities across 1,450 packages',
    );
  });

  it('fails the recorded vulnerable report and names the package, version and advisory', () => {
    expect(vulnerable.packages).toBe(1);
    expect(vulnerable.vulnerabilities).toHaveLength(1);
    const [finding] = vulnerable.vulnerabilities;
    expect(finding).toMatchObject({
      package: 'minimist',
      version: '1.2.5',
      id: 'GHSA-xvch-5gv4-984h',
    });
    expect(finding!.summary).not.toBe('');
    expect(formatOsvFinding(finding!)).toBe(
      `minimist@1.2.5  GHSA-xvch-5gv4-984h  ${finding!.summary}`,
    );
    expect(summarizeReport(vulnerable)).toBe('1 vulnerability across 1 package');
    expect(osvExitCodeFor(OSV_EXIT.VULNERABLE, vulnerable)).toBe(1);
  });

  it('is red whenever the report lists a vulnerability, whatever the tool exited with', () => {
    for (const toolExit of [0, 1, 2, 124, 127, 128]) {
      expect(osvExitCodeFor(toolExit, vulnerable)).toBe(1);
    }
  });

  it('never reads a scan that did not complete as clean', () => {
    // A failed advisory fetch, a scan of nothing, a hang and an exit 1 whose
    // report names nothing are all "could not run", never a pass.
    for (const toolExit of [
      OSV_EXIT.VULNERABLE,
      OSV_EXIT.GENERAL_ERROR,
      OSV_EXIT.NO_PACKAGES,
      124,
      129,
      255,
    ]) {
      expect(osvExitCodeFor(toolExit, clean)).toBe(2);
    }
    expect(osvExitCodeFor(OSV_EXIT.CLEAN, null)).toBe(2);
    // Without `--all-packages` a clean report lists no packages at all.
    const unlisted = parseOsvReport('{"results": []}');
    expect(unlisted).toEqual({ packages: 0, vulnerabilities: [] });
    expect(osvExitCodeFor(OSV_EXIT.CLEAN, unlisted)).toBe(2);
  });

  it('never answers with the skip sentinel', () => {
    for (const toolExit of [0, 1, 2, 78, 124, 127, 128, 255]) {
      for (const report of [clean, vulnerable, null]) {
        expect(osvExitCodeFor(toolExit, report)).not.toBe(SKIP_EXIT);
      }
    }
  });

  it('refuses a report it cannot read rather than finding nothing in it', () => {
    const cases: [string, RegExp][] = [
      ['not json', /report is not JSON/],
      ['{}', /no `results` array/],
      ['{"results": [{"source": {}}]}', /results\[0\] has no `packages` array/],
      ['{"results": [{"packages": [{"package": {"name": "a"}}]}]}', /names no package and version/],
      [
        '{"results": [{"packages": [{"package": {"name": "a", "version": "1"}, "vulnerabilities": {}}]}]}',
        /a@1: `vulnerabilities` is not an array/,
      ],
      [
        '{"results": [{"packages": [{"package": {"name": "a", "version": "1"}, "vulnerabilities": [{"summary": "x"}]}]}]}',
        /a@1: a vulnerability has no id/,
      ],
    ];
    for (const [text, message] of cases) {
      expect(() => parseOsvReport(text)).toThrow(OsvReportError);
      expect(() => parseOsvReport(text)).toThrow(message);
    }
  });
});

describe('gitleaks gate: only commit-pinned fingerprints, and a finding is never green', () => {
  const COMMIT = '0123456789abcdef0123456789abcdef01234567';

  /** The shape gitleaks 8.30.1 writes with `--report-format sarif --redact`. */
  const sarifWith = (results: unknown[]): unknown => ({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'gitleaks', rules: [] } }, results }],
  });
  const result = (overrides: { uri?: string; line?: unknown; commit?: unknown } = {}): unknown => ({
    message: { text: 'generic-api-key has detected secret' },
    ruleId: 'generic-api-key',
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: overrides.uri ?? 'tests/token.test.ts' },
          region: { startLine: overrides.line ?? 12, snippet: { text: 'REDACTED' } },
        },
      },
    ],
    partialFingerprints: { commitSha: overrides.commit ?? COMMIT },
  });

  it('accepts every line of the committed .gitleaksignore as a commit-pinned fingerprint', () => {
    const { fingerprints, refused } = parseIgnoreFile(read('.gitleaksignore'));
    expect(refused).toEqual([]);
    expect(fingerprints.length).toBeGreaterThan(0);
    for (const { value } of fingerprints) expect(value).toMatch(COMMIT_FINGERPRINT);
    // One line per finding: a duplicate would be dead capacity in the ledger.
    expect(new Set(fingerprints.map((f) => f.value)).size).toBe(fingerprints.length);
  });

  it('reads .gitleaksignore the way gitleaks does and refuses a global fingerprint', () => {
    const text = [
      '# fixture fingerprints',
      '',
      `  ${COMMIT}:tests/token.test.ts:generic-api-key:12  `,
      'tests/token.test.ts:generic-api-key:12',
      `${COMMIT}:tests/token.test.ts:generic-api-key`,
      `${COMMIT.toUpperCase()}:tests/token.test.ts:generic-api-key:12`,
      `${COMMIT}:tests/token.test.ts:generic-api-key:0`,
    ].join('\n');
    const { fingerprints, refused } = parseIgnoreFile(text);
    expect(fingerprints).toEqual([
      { line: 3, value: `${COMMIT}:tests/token.test.ts:generic-api-key:12` },
    ]);
    expect(refused.map((r) => r.line)).toEqual([4, 5, 6, 7]);
    // Line 5 also has three parts, so it is refused as global too.
    expect(refused[0]!.reason).toMatch(/global fingerprint ignores this line in every commit/);
    expect(refused[1]!.reason).toMatch(/global fingerprint/);
    expect(refused[2]!.reason).toMatch(/not a `<commit>:<file>:<rule>:<line>` fingerprint/);
    expect(refused[3]!.reason).toMatch(/not a `<commit>:<file>:<rule>:<line>` fingerprint/);
  });

  it("reads the history with git's own output filters off", () => {
    // Measured in a throwaway clone: each of `* -diff` in .git/info/attributes, a
    // textconv driver, `color.ui=always` and `log.showRoot=false` hid findings
    // from the default options; these flags are what restored all of them. A
    // `--log-opts` value REPLACES gitleaks' defaults, so those are restated too.
    const opts = LOG_OPTS.split(' ');
    for (const flag of [
      '--full-history',
      '--all',
      '--diff-filter=tuxdb',
      '--text',
      '--no-textconv',
      '--no-ext-diff',
      '--no-color',
      '--root',
    ]) {
      expect(opts).toContain(flag);
    }
    // gitleaks splits the value on single spaces: an empty token would reach git.
    expect(opts).not.toContain('');
  });

  it('rebuilds the fingerprint gitleaks matches .gitleaksignore against', () => {
    const findings = parseGitleaksSarif(JSON.stringify(sarifWith([result()])));
    expect(findings).toEqual([
      {
        rule: 'generic-api-key',
        file: 'tests/token.test.ts',
        line: 12,
        commit: COMMIT,
        fingerprint: `${COMMIT}:tests/token.test.ts:generic-api-key:12`,
      },
    ]);
    expect(findings[0]!.fingerprint).toMatch(COMMIT_FINGERPRINT);
    expect(formatGitleaksFinding(findings[0]!)).toBe(
      `generic-api-key | tests/token.test.ts:12 | ${COMMIT}\n` +
        `    fingerprint: ${COMMIT}:tests/token.test.ts:generic-api-key:12`,
    );
    expect(parseGitleaksSarif(sarifWith([]))).toEqual([]);
  });

  it('refuses a report it cannot read rather than finding nothing in it', () => {
    const cases: [unknown, RegExp][] = [
      ['not json', /report is not JSON/],
      [{}, /report has no `runs`/],
      [{ runs: [] }, /report has no `runs`/],
      [{ runs: [{}] }, /runs\[0\] has no `results` array/],
      [sarifWith([result({ line: '12' })]), /runs\[0\]\.results\[0\] names no rule, file and line/],
      [sarifWith([result({ commit: '' })]), /names no commit \(was the history scanned\?\)/],
    ];
    for (const [input, message] of cases) {
      expect(() => parseGitleaksSarif(input)).toThrow(GitleaksReportError);
      expect(() => parseGitleaksSarif(input)).toThrow(message);
    }
  });

  it('maps the tool exit and the report to one verdict, and never to the skip sentinel', () => {
    const finding = parseGitleaksSarif(sarifWith([result()]));
    expect(gitleaksExitCodeFor(0, [], 0)).toBe(0);
    // gitleaks exits 1 for leaks AND for a fatal error; the report decides.
    expect(gitleaksExitCodeFor(1, finding, 0)).toBe(1);
    expect(gitleaksExitCodeFor(1, [], 0)).toBe(2);
    expect(gitleaksExitCodeFor(1, null, 0)).toBe(2);
    expect(gitleaksExitCodeFor(124, null, 0)).toBe(2);
    // A finding in the report is red whatever the exit code said.
    expect(gitleaksExitCodeFor(0, finding, 0)).toBe(1);
    // An allowlist the gate may not use is red even over a clean scan.
    expect(gitleaksExitCodeFor(0, [], 1)).toBe(1);
    expect(gitleaksExitCodeFor(2, null, 1)).toBe(1);
    for (const toolExit of [0, 1, 2, 78, 124, 127]) {
      for (const findings of [[], finding, null]) {
        for (const refused of [0, 1]) {
          expect(gitleaksExitCodeFor(toolExit, findings, refused)).not.toBe(SKIP_EXIT);
        }
      }
    }
  });
});

/**
 * The two scanners are tier-1 gates that DECLARE their binary rather than
 * skipping without it: `sast` is the only gate allowed to report itself
 * SKIPPED, so an absent `gitleaks` or `osv-scanner` must be exit 2, "could not
 * run", which fails the pipeline. The runner checks the declared prerequisite
 * before it starts the gate; this is the gate's OWN answer when it is started
 * directly (`npm run audit:secrets:gitleaks`, the self-test, a clean room), on
 * a PATH that holds nothing at all.
 */
describe('an absent scanner is "could not run", never a pass or a skip', () => {
  const emptyPath = mkdtempSync(path.join(tmpdir(), 'hv-no-scanner-'));
  afterAll(() => {
    rmSync(emptyPath, { recursive: true, force: true });
  });

  it.each([
    ['gitleaks', 'gitleaks-gate.mjs', 'GITLEAKS_VERSION', 'gitleaks.sarif'],
    ['osv-scanner', 'osv-gate.mjs', 'OSV_SCANNER_VERSION', 'osv.json'],
  ])(
    '%s: exit 2 with the pinned install hint, and no report touched',
    (tool, script, versionKey, reportName) => {
      const report = path.join(repoRoot, '.testfortress', 'reports', reportName);
      const before = existsSync(report) ? readFileSync(report) : null;
      const run = spawnSync(process.execPath, [path.join(repoRoot, 'scripts', 'ci', script)], {
        cwd: repoRoot,
        encoding: 'utf-8',
        env: { ...process.env, PATH: emptyPath },
      });
      expect(run.status).toBe(2);
      expect(run.status).not.toBe(SKIP_EXIT);
      expect(run.stderr).toContain(`${tool} is not installed`);
      // The hint names the version the release workflow installs, so a
      // contributor who follows it gets the scanner the ratchet was recorded with.
      const pinned = release.jobs['verify']?.steps.find(
        (step) => step.env?.[versionKey] !== undefined,
      )?.env?.[versionKey];
      expect(pinned, `${versionKey} in release.yml`).toBeDefined();
      expect(run.stderr).toContain(`v${String(pinned)}`);
      // Nothing that reads as a verdict about the subject.
      expect(run.stdout).not.toMatch(/✔|unignored findings in the history|across/);
      // The gate stopped before it deleted or wrote its report.
      expect(existsSync(report) ? readFileSync(report) : null).toEqual(before);
    },
  );
});

/** One gate as `local-ci.mjs --list --json` reports it. */
interface ListedGate {
  id: string;
  task: string;
  tier: number;
  canSkip: boolean;
  requires: string[];
  prerequisites: { name: string; label: string; fix: string }[];
}

let listing: ListedGate[] | undefined;
/** The runner's own gate table, asked for rather than parsed out of its source. */
function listedGates(): ListedGate[] {
  listing ??= JSON.parse(
    spawnSync(
      process.execPath,
      [path.join(repoRoot, 'scripts', 'ci', 'local-ci.mjs'), '--list', '--json'],
      {
        encoding: 'utf-8',
      },
    ).stdout,
  ) as ListedGate[];
  return listing;
}

/**
 * An advisory with no fixed release can only be ACCEPTED, never ignored, and
 * only through a ledger entry the osv gate itself re-validates: rule
 * `VULN-ACCEPT`, the exact advisory id and `name@version`, a reviewer, and an
 * expiry at most thirty days out. The integrity scan exempts marker-less rules
 * from its staleness and unused-capacity checks, so a dead or lapsed acceptance
 * is caught here or nowhere. The two recordings are real osv-scanner 2.4.0
 * output for throwaway lockfiles (braces 3.0.3 alone, and with minimist 1.2.5),
 * with only `source.path` rewritten.
 */
describe('osv gate: an advisory is accepted only by a strict, dated, reviewed ledger entry', () => {
  const TODAY = '2026-10-16';
  const fixture = (name: string): ReturnType<typeof parseOsvReport> =>
    parseOsvReport(read('packages', 'server', 'tests', 'fixtures', name));
  const braces = fixture('osv-report-accepted.json');
  const mixed = fixture('osv-report-mixed.json');
  const entry = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
    id: 'SUP-9001',
    rule: 'VULN-ACCEPT',
    kind: 'vulnerability-acceptance',
    file: 'package-lock.json',
    symbol: 'GHSA-vfj7-8cjw-p6xm braces@3.0.3',
    maxHits: 1,
    reason: 'dev-only, no fixed release',
    owner: 'maintainer',
    created: '2026-10-16',
    expires: '2026-11-15',
    approvedBy: ['judge:readonly'],
    ...overrides,
  });
  const ledgerOf = (...entries: Record<string, unknown>[]): unknown => ({
    version: 1,
    policy: {},
    entries: [{ id: 'SUP-0001', rule: 'KNOWN-GAP', kind: 'known-gap' }, ...entries],
  });

  it('reads the recordings as the advisories the acceptance names', () => {
    expect(braces.packages).toBe(1);
    expect(braces.vulnerabilities.map((v) => [v.package, v.version, v.id])).toEqual([
      ['braces', '3.0.3', 'GHSA-vfj7-8cjw-p6xm'],
    ]);
    expect(mixed.vulnerabilities.map((v) => [v.package, v.version, v.id])).toEqual([
      ['braces', '3.0.3', 'GHSA-vfj7-8cjw-p6xm'],
      ['minimist', '1.2.5', 'GHSA-xvch-5gv4-984h'],
    ]);
  });

  it('parses a symbol only in the exact `<id> <name>@<version>` shape, scoped names included', () => {
    expect(parseAcceptanceSymbol('GHSA-vfj7-8cjw-p6xm braces@3.0.3')).toEqual({
      id: 'GHSA-vfj7-8cjw-p6xm',
      name: 'braces',
      version: '3.0.3',
    });
    expect(parseAcceptanceSymbol('GHSA-aaaa-bbbb-cccc @scope/pkg@1.0.0-beta.1')).toEqual({
      id: 'GHSA-aaaa-bbbb-cccc',
      name: '@scope/pkg',
      version: '1.0.0-beta.1',
    });
    for (const loose of [
      'GHSA-vfj7-8cjw-p6xm braces',
      'GHSA-vfj7-8cjw-p6xm braces@',
      'GHSA-vfj7-8cjw-p6xm braces@^3.0.0',
      'GHSA-vfj7-8cjw-p6xm  braces@3.0.3',
      'braces@3.0.3',
      'GHSA-vfj7-8cjw-p6xm braces@3.0.3 extra',
      'GHSA-vfj7-8cjw-p6xm braces@3.0.*',
      '',
    ]) {
      expect(parseAcceptanceSymbol(loose), JSON.stringify(loose)).toBeNull();
    }
  });

  it('accepts the one valid entry and ignores every other rule in the ledger', () => {
    const { acceptances, problems } = readAcceptances(ledgerOf(entry()), TODAY);
    expect(problems).toEqual([]);
    expect(acceptances).toEqual([
      {
        entryId: 'SUP-9001',
        id: 'GHSA-vfj7-8cjw-p6xm',
        name: 'braces',
        version: '3.0.3',
        maxHits: 1,
        expires: '2026-11-15',
      },
    ]);
    expect(VULN_ACCEPT.maxDays).toBe(30);
  });

  it('refuses, by entry id and reason, every entry that is not exactly a reviewed, current acceptance', () => {
    const cases: [Record<string, unknown>, RegExp][] = [
      [{ kind: 'known-gap' }, /kind/],
      [{ file: 'packages/server/package.json' }, /file/],
      [{ symbol: 'braces@3.0.3' }, /symbol/],
      [{ symbol: undefined }, /symbol/],
      [{ maxHits: 0 }, /maxHits/],
      [{ maxHits: 1.5 }, /maxHits/],
      [{ approvedBy: [] }, /approvedBy/],
      [{ approvedBy: [''] }, /approvedBy/],
      [{ approvedBy: undefined }, /approvedBy/],
      [{ reason: '' }, /reason/],
      [{ created: '2026-10-17' }, /created/],
      [{ created: '16/10/2026' }, /created/],
      // The day after expiry.
      [{ expires: '2026-10-15' }, /expired/],
      // Thirty-one days out is one day past the cap.
      [{ expires: '2026-11-16' }, /30 days/],
      [{ expires: 'never' }, /expires/],
      // Dates the calendar does not have: each has the shape, and each made the
      // day arithmetic NaN, which no cap comparison is ever true of.
      [{ expires: '2099-13-01' }, /expires/],
      [{ expires: '2026-11-99' }, /expires/],
      [{ created: '2026-02-30' }, /created/],
    ];
    for (const [overrides, reason] of cases) {
      const { acceptances, problems } = readAcceptances(ledgerOf(entry(overrides)), TODAY);
      expect(acceptances, JSON.stringify(overrides)).toEqual([]);
      expect(problems, JSON.stringify(overrides)).toHaveLength(1);
      expect(problems[0]!.entryId).toBe('SUP-9001');
      expect(problems[0]!.reason, JSON.stringify(overrides)).toMatch(reason);
    }
    // The boundaries themselves are inside: expiring today, and exactly 30 days out.
    for (const expires of ['2026-10-16', '2026-11-15']) {
      expect(readAcceptances(ledgerOf(entry({ expires })), TODAY).problems).toEqual([]);
    }
  });

  it('refuses a ledger it cannot read rather than reading it as "nothing accepted"', () => {
    for (const ledger of [null, 'text', [], { entries: {} }, { version: 1 }]) {
      expect(() => readAcceptances(ledger, TODAY), JSON.stringify(ledger)).toThrow(OsvLedgerError);
    }
  });

  it('matches on the exact id, name and version, never an alias, another version or another package', () => {
    for (const symbol of [
      'GHSA-vfj7-8cjw-p6xm braces@3.0.2',
      'CVE-2026-93687 braces@3.0.3',
      'GHSA-vfj7-8cjw-p6xx braces@3.0.3',
      'GHSA-vfj7-8cjw-p6xm brace@3.0.3',
    ]) {
      const { acceptances } = readAcceptances(ledgerOf(entry({ symbol })), TODAY);
      const verdict = classifyFindings(braces.vulnerabilities, acceptances);
      expect(verdict.accepted, symbol).toEqual([]);
      expect(
        verdict.unaccepted.map((v) => v.package),
        symbol,
      ).toEqual(['braces']);
      expect(verdict.dead, symbol).toEqual(['SUP-9001']);
      expect(acceptanceExitCode(OSV_EXIT.VULNERABLE, braces, verdict, []), symbol).toBe(1);
    }
  });

  it('is green when every finding is accepted and the tool said so, and only then', () => {
    const { acceptances } = readAcceptances(ledgerOf(entry()), TODAY);
    const verdict = classifyFindings(braces.vulnerabilities, acceptances);
    expect(verdict.unaccepted).toEqual([]);
    expect(verdict.accepted.map((a) => [a.entryId, a.finding.package, a.expires])).toEqual([
      ['SUP-9001', 'braces', '2026-11-15'],
    ]);
    expect(verdict.dead).toEqual([]);
    expect(acceptanceExitCode(OSV_EXIT.VULNERABLE, braces, verdict, [])).toBe(0);
    // osv-scanner exits 1 whenever it found anything, accepted or not: any other
    // exit with findings in the report is a scan that did not complete.
    for (const toolExit of [0, 2, 124, 127, 128]) {
      expect(acceptanceExitCode(toolExit, braces, verdict, []), String(toolExit)).toBe(2);
    }
    expect(summarizeVerdict(braces, verdict)).toBe(
      '0 unaccepted vulnerabilities and 1 accepted (SUP-9001) across 1 package',
    );
    const [accepted] = verdict.accepted;
    expect(formatAccepted(accepted!)).toBe(
      'accepted  braces@3.0.3  GHSA-vfj7-8cjw-p6xm  (SUP-9001, until 2026-11-15)',
    );
    // Never the line shape an unaccepted finding is printed in.
    expect(formatAccepted(accepted!)).not.toMatch(/^braces@3\.0\.3 {2}GHSA/);
  });

  it('stays red for the unaccepted finding beside an accepted one', () => {
    const { acceptances } = readAcceptances(ledgerOf(entry()), TODAY);
    const verdict = classifyFindings(mixed.vulnerabilities, acceptances);
    expect(verdict.accepted.map((a) => a.finding.package)).toEqual(['braces']);
    expect(verdict.unaccepted.map((v) => v.package)).toEqual(['minimist']);
    for (const toolExit of [0, 1, 2, 127]) {
      expect(acceptanceExitCode(toolExit, mixed, verdict, []), String(toolExit)).toBe(1);
    }
    expect(summarizeVerdict(mixed, verdict)).toBe(
      '1 unaccepted vulnerability and 1 accepted (SUP-9001) across 2 packages',
    );
  });

  it('fails on an entry that excuses nothing, but only once the scan completed', () => {
    const { acceptances } = readAcceptances(ledgerOf(entry()), TODAY);
    const clean = parseOsvReport(
      read('packages', 'server', 'tests', 'fixtures', 'osv-report-clean.json'),
    );
    const verdict = classifyFindings(clean.vulnerabilities, acceptances);
    expect(verdict.dead).toEqual(['SUP-9001']);
    // The good outcome (a fix shipped, the package left the tree), and still a
    // red gate: an acceptance with nothing to accept must be pruned.
    expect(acceptanceExitCode(OSV_EXIT.CLEAN, clean, verdict, [])).toBe(1);
    // A scan that did not complete says nothing about whether it is dead.
    expect(acceptanceExitCode(OSV_EXIT.GENERAL_ERROR, clean, verdict, [])).toBe(2);
    expect(acceptanceExitCode(OSV_EXIT.CLEAN, null, verdict, [])).toBe(2);
    expect(
      acceptanceExitCode(OSV_EXIT.CLEAN, { packages: 0, vulnerabilities: [] }, verdict, []),
    ).toBe(2);
  });

  it('fails on unused capacity and on a reused entry id, once the scan completed', () => {
    // The integrity scan skips its unused-capacity and staleness checks for
    // marker-less rules, so an acceptance sized for more than it excuses would
    // otherwise stand ready to excuse a second finding nobody reviewed.
    const roomy = readAcceptances(ledgerOf(entry({ maxHits: 2 })), TODAY);
    const verdict = classifyFindings(braces.vulnerabilities, roomy.acceptances);
    expect(verdict.underused).toEqual([{ entryId: 'SUP-9001', hits: 1, maxHits: 2 }]);
    expect(acceptanceExitCode(OSV_EXIT.VULNERABLE, braces, verdict, [])).toBe(1);
    expect(acceptanceExitCode(OSV_EXIT.GENERAL_ERROR, braces, verdict, [])).toBe(2);
    // Two entries sharing an id would let the live one hide the dead one, so
    // NEITHER accepts anything: each is refused by that id.
    const twins = readAcceptances(
      ledgerOf(entry(), entry({ symbol: 'GHSA-xvch-5gv4-984h minimist@1.2.5' })),
      TODAY,
    );
    expect(twins.acceptances).toEqual([]);
    expect(twins.problems).toEqual([
      { entryId: 'SUP-9001', reason: expect.stringMatching(/exactly one ledger entry/) },
      { entryId: 'SUP-9001', reason: expect.stringMatching(/exactly one ledger entry/) },
    ]);
    // An entry with no id at all cannot be named in a verdict, so it accepts nothing.
    const anonymous = readAcceptances(ledgerOf(entry({ id: undefined })), TODAY);
    expect(anonymous.acceptances).toEqual([]);
    expect(anonymous.problems).toEqual([
      { entryId: '(no id)', reason: expect.stringMatching(/exactly one ledger entry/) },
    ]);
    // Any entry in the ledger counts, not only another acceptance.
    const clash = readAcceptances(ledgerOf(entry({ id: 'SUP-0001' })), TODAY);
    expect(clash.acceptances).toEqual([]);
    expect(clash.problems.map((p) => p.entryId)).toEqual(['SUP-0001']);
  });

  it('fails when one entry would excuse more findings than its capacity', () => {
    const twice = {
      packages: 2,
      vulnerabilities: [braces.vulnerabilities[0]!, braces.vulnerabilities[0]!],
    };
    const { acceptances } = readAcceptances(ledgerOf(entry()), TODAY);
    const verdict = classifyFindings(twice.vulnerabilities, acceptances);
    expect(verdict.overused).toEqual([{ entryId: 'SUP-9001', hits: 2, maxHits: 1 }]);
    expect(acceptanceExitCode(OSV_EXIT.VULNERABLE, twice, verdict, [])).toBe(1);
  });

  it('fails on an invalid entry even when the scan is clean and the entry matches nothing', () => {
    const { acceptances, problems } = readAcceptances(ledgerOf(entry({ approvedBy: [] })), TODAY);
    const clean = parseOsvReport(
      read('packages', 'server', 'tests', 'fixtures', 'osv-report-clean.json'),
    );
    const verdict = classifyFindings(clean.vulnerabilities, acceptances);
    expect(acceptanceExitCode(OSV_EXIT.CLEAN, clean, verdict, problems)).toBe(1);
    expect(acceptanceExitCode(OSV_EXIT.CLEAN, null, verdict, problems)).toBe(1);
  });

  it('with no acceptance at all, decides exactly as the unaccepting verdict always did', () => {
    const none = classifyFindings([], []);
    const clean = parseOsvReport(
      read('packages', 'server', 'tests', 'fixtures', 'osv-report-clean.json'),
    );
    const vulnerable = parseOsvReport(
      read('packages', 'server', 'tests', 'fixtures', 'osv-report-vulnerable.json'),
    );
    for (const toolExit of [0, 1, 2, 78, 124, 127, 128, 255]) {
      for (const report of [clean, vulnerable, null, { packages: 0, vulnerabilities: [] }]) {
        const verdict = classifyFindings(report?.vulnerabilities ?? [], []);
        expect(acceptanceExitCode(toolExit, report, verdict, [])).toBe(
          osvExitCodeFor(toolExit, report),
        );
        expect(acceptanceExitCode(toolExit, report, verdict, [])).not.toBe(SKIP_EXIT);
      }
    }
    expect(none).toEqual({ accepted: [], unaccepted: [], dead: [], overused: [], underused: [] });
  });
});
