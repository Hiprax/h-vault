#!/usr/bin/env node
/**
 * Builds, publishes and verifies the release images.
 *
 * Run by `.github/workflows/release.yml`, one subcommand per job. The decisions
 * live in `lib/release-images.mjs`, which is unit-tested; this file runs the
 * docker commands they describe, and turns any problem into exit code 1.
 *
 *   build --platform linux/<arch> --version X.Y.Z --revision <sha> --builder <name>
 *       One bake of the three images for this runner's platform, pushed by digest
 *       and untagged. Then each digest is pulled back, the registry credential is
 *       dropped, and the pulled bytes are scanned (Trivy, from a saved tarball,
 *       with no Docker socket and no credential) and run (the real
 *       docker-compose.yml, a real user journey through its one port). Writes the
 *       three digests as step outputs. Nothing can pull these images by name yet.
 *
 *   publish --version X.Y.Z --revision <sha>
 *       After BOTH platforms passed: one index per image from the two digests in
 *       $AMD64_DIGESTS and $ARM64_DIGESTS (each job's outputs, as JSON), tagged
 *       X.Y.Z and annotated. Refuses when git already has vX.Y.Z, so a released
 *       tag is never moved onto new bytes. Writes the three index digests.
 *
 *   verify-public --version X.Y.Z --revision <sha> [--expect-from-env]
 *       What an anonymous user gets: every tag must be pullable without a
 *       credential, hold both platforms, and be annotated with this version and
 *       commit; with --expect-from-env it must also be exactly the index in
 *       $EXPECTED_INDEXES. The release job runs this before it tags or releases.
 *
 *   agree
 *       The release job's own decision (OWN_VERSION, OWN_SHOULD_RELEASE,
 *       OWN_CREATE_TAG) against the plan's (PLANNED_*): lib
 *       `decisionChangeProblem`.
 *
 *   plan
 *       The `plan` job's decision (lib `planImages`): reads SHOULD_RELEASE and
 *       CREATE_TAG (next-version.mjs's outputs), STAGE (the normalised
 *       `stage_images` input) and GITHUB_REF, and writes `stage`, `build` and
 *       `publish`, each exactly true or false.
 *
 * `--registry <host/namespace>` (with `--insecure-registry` for a plain-HTTP one)
 * points any subcommand at a throwaway test registry instead of GHCR.
 */
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { captureExe, repoRoot, runExe } from './lib/proc.mjs';
import { color, note, symbol } from './lib/ui.mjs';
import { IMAGE_REGISTRY, PUBLISHED_IMAGES, imageRepository } from './lib/images.mjs';
import {
  bakeArgs,
  bakeDefinition,
  confirmedIndexDigest,
  decisionChangeProblem,
  digestsFromMetadata,
  githubOutputLines,
  imagetoolsCreateArgs,
  indexProblems,
  ociMetadata,
  parseCreated,
  parseFlag,
  parseLegDigests,
  parsePlatform,
  parseRevision,
  parseVersion,
  planImages,
  publicImageProblems,
  pullOnlyServices,
  releaseTagState,
  shellScriptPath,
  smokeTag,
  smokeUpArgs,
  trivyRunArgs,
} from './lib/release-images.mjs';
import {
  extractFindings,
  judgeFindings,
  parseBaseline,
  scanCoverageProblem,
} from './lib/trivy.mjs';
import {
  MARK_EMAIL_VERIFIED_SCRIPT,
  emailVerifiedProblem,
  mongoshExecArgs,
  parseComposePs,
  renderEnvFile,
  renderOverride,
  scratchStackEnvironment,
  serviceVerdicts,
  singlePortProblems,
} from './lib/drill.mjs';
import { runVaultFlow, waitForHealth } from './lib/vault-flow.mjs';

/** The smoke test's stack, namespaced away from a real one and from the drill's. */
const SMOKE_STACK = 'hvault-release-smoke';
const SMOKE_PORT = 18090;
const SMOKE_EDGE_SUBNET = '172.31.246.0/24';
const SMOKE_DATA_SUBNET = '172.31.247.0/24';
/** Bounds `up --wait`'s wait phase, so a stuck healthcheck is an error rather than a hang. */
const WAIT_TIMEOUT_SECONDS = 300;
const HEALTH_DEADLINE_MS = 120_000;
/** A cold bake of all three images on a hosted runner, with room to spare. */
const BAKE_TIMEOUT_MS = 45 * 60_000;
const TRIVY_CACHE_VOLUME = 'hvault-release-trivy-cache';

class ReleaseImageError extends Error {}

const fail = (message) => {
  throw new ReleaseImageError(message);
};

/** Parses `--name value` pairs and bare `--flag`s; refuses anything it does not know. */
function parseOptions(argv, known) {
  const options = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const name = /^--([a-z-]+)$/.exec(arg ?? '')?.[1];
    if (!name || !(name in known)) fail(`unknown argument: ${String(arg)}`);
    if (known[name] === 'flag') options[name] = true;
    else {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) fail(`--${name} needs a value`);
      options[name] = value;
      i += 1;
    }
  }
  return options;
}

/** Captured command that must succeed; its stderr becomes the failure. */
function must(command, args, options) {
  const result = captureExe(command, args, options);
  if (!result.ok) {
    fail(
      `${command} ${args.slice(0, 3).join(' ')} … exited ${String(result.status)}: ${result.stderr.trim().slice(0, 800)}`,
    );
  }
  return result;
}

/** Streamed command that must succeed. */
async function mustStream(command, args, options) {
  const code = await runExe(command, args, options);
  if (code !== 0) fail(`${command} ${args.slice(0, 3).join(' ')} … exited ${String(code)}`);
}

function writeOutputs(outputs) {
  const lines = githubOutputLines(outputs);
  process.stdout.write(lines);
  const target = process.env['GITHUB_OUTPUT'];
  if (target) appendFileSync(target, lines);
}

function registryOptions(options) {
  const registry = options['registry'] ?? IMAGE_REGISTRY;
  if (!/^[a-z0-9.-]+(?::\d+)?\/[a-z0-9-]+$/.test(registry))
    fail(`not a registry/namespace: ${registry}`);
  return { registry, insecure: options['insecure-registry'] === true };
}

/** The commit's own time, in UTC to the second: the same for both platforms' images. */
function commitTime(revision) {
  const iso = must('git', ['show', '-s', '--format=%cI', revision]).stdout.trim();
  const time = new Date(iso);
  if (Number.isNaN(time.getTime())) fail(`git gave an unreadable commit time: ${iso}`);
  return parseCreated(time.toISOString().replace(/\.\d{3}Z$/, 'Z'));
}

// ---------------------------------------------------------------------------
// build
// ---------------------------------------------------------------------------

async function build(options) {
  const platform = parsePlatform(options['platform']);
  const version = parseVersion(options['version']);
  const revision = parseRevision(options['revision']);
  const builder = options['builder'] ?? fail('--builder is required');
  const { registry, insecure } = registryOptions(options);
  const created = commitTime(revision);
  const workspace = mkdtempSync(path.join(tmpdir(), 'hvault-release-images-'));
  const tag = smokeTag(version, platform);
  const smokeReferences = [];

  try {
    // 1. One bake of all three images, pushed by digest.
    const bakeFile = path.join(workspace, 'bake.json');
    const metadataFile = path.join(workspace, 'bake-metadata.json');
    writeFileSync(
      bakeFile,
      JSON.stringify(
        bakeDefinition({
          context: repoRoot,
          platform,
          version,
          revision,
          created,
          registry,
          insecureRegistry: insecure,
        }),
        null,
        2,
      ),
    );
    console.log(
      color.cyan(
        `\n  building ${PUBLISHED_IMAGES.map((image) => image.name).join(', ')} for ${platform}`,
      ),
    );
    await mustStream('docker', bakeArgs({ file: bakeFile, metadataFile, builder }), {
      timeoutMs: BAKE_TIMEOUT_MS,
    });
    const digests = digestsFromMetadata(JSON.parse(readFileSync(metadataFile, 'utf8')));

    // 2. Pull back exactly what was pushed, then drop the credential: nothing
    //    after this point needs the registry, and the scanner and the smoke
    //    stack must run on a host that holds no push credential.
    for (const image of PUBLISHED_IMAGES) {
      const pushed = `${imageRepository(image.name, registry)}@${digests[image.key]}`;
      await mustStream('docker', ['pull', '--quiet', pushed]);
      const local = `${imageRepository(image.name)}:${tag}`;
      must('docker', ['tag', pushed, local]);
      smokeReferences.push({ image, pushed, local });
    }
    if (registry.startsWith('ghcr.io/')) must('docker', ['logout', 'ghcr.io']);

    // 3. Scan the bytes about to be published, on this architecture.
    scanImages(workspace, smokeReferences);

    // 4. Run them.
    await smokeTest(workspace, tag, smokeReferences);

    writeOutputs(digests);
    console.log(
      color.green(
        `\n${symbol.pass} ${platform}: built, pushed by digest, scanned and smoke-tested`,
      ),
    );
  } finally {
    // The runner is thrown away, but a developer's machine is not: leave neither
    // the smoke tags, nor the pulled-back images, nor the database image the
    // smoke test built behind.
    for (const { local, pushed } of smokeReferences) {
      captureExe('docker', ['image', 'rm', local]);
      captureExe('docker', ['image', 'rm', pushed]);
    }
    captureExe('docker', ['image', 'rm', `hvault-db:8.0-${tag}`]);
    rmSync(workspace, { recursive: true, force: true });
  }
}

/**
 * Trivy over a saved tarball of each image. No Docker socket and no credential
 * reach the scanner (`trivyRunArgs`): the job holding `packages: write` must not
 * hand a third-party tool the means to read its push credential or start a
 * container of its choosing.
 */
function scanImages(workspace, references) {
  const baseline = parseBaseline(
    readFileSync(path.join(repoRoot, 'scripts', 'ci', 'trivy-baseline.json'), 'utf8'),
  );
  const vulnerable = [];
  try {
    for (const { image, local } of references) {
      const tarball = `${image.name}.tar`;
      must('docker', ['save', '--output', path.join(workspace, tarball), local]);
      console.log(color.cyan(`\n  scanning ${image.name}`));
      const scan = captureExe(
        'docker',
        trivyRunArgs({ workspace, tarball, cacheVolume: TRIVY_CACHE_VOLUME }),
      );
      if (!scan.ok)
        fail(
          `trivy could not scan ${image.name} (exit ${String(scan.status)}): ${scan.stderr.trim().slice(0, 800)}`,
        );
      let report;
      try {
        report = JSON.parse(scan.stdout);
      } catch {
        fail(`trivy produced no parseable JSON report for ${image.name}`);
      }
      const coverage = scanCoverageProblem(report);
      if (coverage) fail(`${image.name}: ${coverage}`);
      const { accepted, unresolved } = judgeFindings(extractFindings(report), baseline, image.name);
      for (const { finding } of accepted) {
        note(
          `accepted ${finding.id} (${finding.pkg} ${finding.installed}) in ${image.name}: see scripts/ci/trivy-baseline.json`,
        );
      }
      for (const finding of unresolved) {
        console.log(
          color.red(
            `    ${finding.severity}  ${finding.id}  ${finding.pkg} ${finding.installed} -> ${finding.fixed || '(no fix)'}\n      ${finding.path}`,
          ),
        );
      }
      if (unresolved.length > 0) vulnerable.push(image.name);
      else note(`${image.name}: no fixable CRITICAL/HIGH beyond the baseline`);
      rmSync(path.join(workspace, tarball), { force: true });
    }
  } finally {
    captureExe('docker', ['volume', 'rm', TRIVY_CACHE_VOLUME]);
  }
  if (vulnerable.length > 0)
    fail(`fixable CRITICAL/HIGH vulnerabilities in: ${vulnerable.join(', ')}`);
}

/**
 * The real docker-compose.yml, on the images just pulled, from nothing.
 *
 * It builds only the two local database images and pulls only the image-only
 * services (`pullOnlyServices`: the storage engine), then starts with
 * `--no-build --pull never` (`smokeUpArgs`), which Compose applies to every
 * service: if the stack wanted any image other than those, it fails instead of
 * quietly building the app from source or fetching something else. Every running
 * container is then checked against the image it should run.
 */
async function smokeTest(workspace, tag, references) {
  const secret = () => randomBytes(32).toString('hex');
  const env = scratchStackEnvironment({
    stackName: SMOKE_STACK,
    httpPort: SMOKE_PORT,
    edgeSubnet: SMOKE_EDGE_SUBNET,
    dataSubnet: SMOKE_DATA_SUBNET,
    imageTag: tag,
    secret,
  });
  const envFile = path.join(workspace, 'smoke.env');
  const overrideFile = path.join(workspace, 'smoke-override.yml');
  writeFileSync(envFile, renderEnvFile(env), 'utf8');
  writeFileSync(overrideFile, renderOverride(envFile), 'utf8');
  const composeArgs = (rest) => [
    'compose',
    '--env-file',
    envFile,
    '-f',
    'docker-compose.yml',
    '-f',
    overrideFile,
    ...rest,
  ];
  // The same values in the process environment: a variable exported in the
  // runner's shell would otherwise outrank the env file for interpolation.
  const compose = (rest, extraEnv = {}) =>
    captureExe('docker', composeArgs(rest), { env: { ...env, ...extraEnv } });
  const baseUrl = `http://127.0.0.1:${String(SMOKE_PORT)}`;
  const problems = [];

  compose(['down', '-v', '--remove-orphans']);
  try {
    await mustStream('docker', composeArgs(['build', 'hvault-db', 'hvault-db-init']), { env });
    const config = JSON.parse(
      must('docker', composeArgs(['config', '--format', 'json']), { env }).stdout,
    );
    const pullFirst = pullOnlyServices(config);
    if (pullFirst.length > 0)
      await mustStream('docker', composeArgs(['pull', ...pullFirst]), { env });
    const up = await runExe('docker', composeArgs(smokeUpArgs(WAIT_TIMEOUT_SECONDS)), { env });
    if (up !== 0) problems.push(`docker compose up exited ${String(up)}`);

    const ps = compose(['ps', '--all', '--format', 'json']);
    const rows = ps.ok ? parseComposePs(ps.stdout) : [];
    const { unhealthy, unexpected } = serviceVerdicts(rows);
    for (const verdict of unhealthy) problems.push(`${verdict.service}: ${verdict.detail}`);
    for (const service of unexpected) problems.push(`${service}: a service nothing here examines`);
    problems.push(...singlePortProblems(rows, { port: SMOKE_PORT }));

    for (const { image, pushed } of references) {
      const expected = must('docker', [
        'image',
        'inspect',
        '--format',
        '{{.Id}}',
        pushed,
      ]).stdout.trim();
      const container = compose(['ps', '--all', '--quiet', image.service]).stdout.trim();
      const running = container
        ? captureExe('docker', ['inspect', '--format', '{{.Image}}', container]).stdout.trim()
        : '';
      if (running !== expected) {
        problems.push(
          `${image.service} runs ${running || 'nothing'}, not the pulled ${image.name} (${expected})`,
        );
      }
    }

    if (problems.length === 0) {
      const health = await waitForHealth(baseUrl, { deadlineMs: HEALTH_DEADLINE_MS });
      if (!health.ok) problems.push(`no healthy answer through the port: ${health.detail}`);
      else {
        // A deep link, so the SPA shell is proxied to Express and carries its
        // per-request nonce, exactly as the deploy drill asks.
        const shell = await fetch(new URL('/vault', baseUrl));
        const html = await shell.text();
        if (shell.status !== 200 || !/<script[^>]+nonce="/i.test(html)) {
          problems.push(`GET /vault answered ${String(shell.status)} without a nonce'd script`);
        }
        const script = shellScriptPath(html);
        const asset = script ? await fetch(new URL(script, baseUrl)) : null;
        if (!asset || asset.status !== 200) {
          problems.push(
            `the shell's script ${String(script)} answered ${String(asset?.status)}: the app and web images are not one build`,
          );
        }
        if (problems.length === 0) {
          const flow = await runVaultFlow({
            baseUrl,
            log: (message) => {
              note(message);
            },
            verifyEmail: async (email) => {
              const result = compose(
                mongoshExecArgs(MARK_EMAIL_VERIFIED_SCRIPT, ['R_U', 'R_P', 'MAIL']),
                {
                  R_U: env.MONGO_ROOT_USERNAME,
                  R_P: env.MONGO_ROOT_PASSWORD,
                  MAIL: email,
                },
              );
              const problem = emailVerifiedProblem(result);
              if (problem) throw new Error(problem);
              await Promise.resolve();
            },
          });
          note(`registered, signed in and round-tripped item ${flow.itemId}`);
        }
      }
    }
  } catch (error) {
    problems.push(error instanceof Error ? error.message : String(error));
  } finally {
    if (problems.length > 0) {
      const logs = compose(['logs', '--no-color', '--tail', '80']);
      console.error(`${logs.stdout}${logs.stderr}`);
    }
    compose(['down', '-v', '--remove-orphans']);
  }
  if (problems.length > 0) fail(`the smoke test failed:\n  - ${problems.join('\n  - ')}`);
}

// ---------------------------------------------------------------------------
// publish
// ---------------------------------------------------------------------------

async function publish(options) {
  const version = parseVersion(options['version']);
  const revision = parseRevision(options['revision']);
  const { registry } = registryOptions(options);
  const created = commitTime(revision);
  // spawnSync directly, not captureExe: a git killed by a signal has no exit
  // status, and reading that as "untagged" is the one wrong answer here.
  const tagged = spawnSync('git', ['rev-parse', '--quiet', '--verify', `refs/tags/v${version}`], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
  if (tagged.error || tagged.signal || tagged.status === null) {
    fail(
      `git could not say whether v${version} is tagged: ${String(tagged.error ?? tagged.signal)}`,
    );
  }
  if (releaseTagState(tagged.status) === 'tagged')
    fail(`v${version} is already tagged in git: a released version's images are never replaced`);
  const legs = {
    'linux/amd64': parseLegDigests(process.env['AMD64_DIGESTS'] ?? '', 'AMD64_DIGESTS'),
    'linux/arm64': parseLegDigests(process.env['ARM64_DIGESTS'] ?? '', 'ARM64_DIGESTS'),
  };
  const indexes = {};
  for (const image of PUBLISHED_IMAGES) {
    const digests = Object.fromEntries(
      Object.entries(legs).map(([platform, leg]) => [platform, leg[image.key]]),
    );
    await mustStream(
      'docker',
      imagetoolsCreateArgs({ image, version, revision, created, digests, registry }),
    );
    const reference = `${imageRepository(image.name, registry)}:${version}`;
    const raw = must('docker', ['buildx', 'imagetools', 'inspect', '--raw', reference]).stdout;
    const manifest = JSON.parse(
      must('docker', [
        'buildx',
        'imagetools',
        'inspect',
        '--format',
        '{{json .Manifest}}',
        reference,
      ]).stdout,
    );
    const problems = indexProblems(raw, {
      expected: digests,
      annotations: ociMetadata(image, { version, revision, created }),
    });
    if (problems.length > 0) fail(`${reference}: ${problems.join('; ')}`);
    indexes[image.key] = confirmedIndexDigest(raw, manifest);
    note(`${reference} = ${indexes[image.key]}`);
  }
  writeOutputs(indexes);
}

// ---------------------------------------------------------------------------
// verify-public
// ---------------------------------------------------------------------------

async function verifyPublic(options) {
  const version = parseVersion(options['version']);
  const revision = parseRevision(options['revision']);
  const { registry, insecure } = registryOptions(options);
  // Every tag must name this release and THIS commit, whoever published it: the
  // check a heal run (which publishes nothing itself) relies on.
  const expectedAnnotations = {
    'org.opencontainers.image.version': version,
    'org.opencontainers.image.revision': revision,
  };
  const expected = options['expect-from-env']
    ? parseLegDigests(process.env['EXPECTED_INDEXES'] ?? '', 'EXPECTED_INDEXES')
    : null;
  const problems = [];
  for (const image of PUBLISHED_IMAGES) {
    const found = await publicImageProblems({
      image,
      version,
      registry,
      insecure,
      expectedAnnotations,
      ...(expected ? { expectedIndex: expected[image.key] } : {}),
    });
    if (found.length === 0)
      note(`${imageRepository(image.name, registry)}:${version} is public, with both platforms`);
    problems.push(...found);
  }
  if (problems.length > 0)
    fail(`the release images are not ready for anyone to pull:\n  - ${problems.join('\n  - ')}`);
}

// ---------------------------------------------------------------------------

const [command, ...rest] = process.argv.slice(2);
const REGISTRY_OPTIONS = { registry: 'value', 'insecure-registry': 'flag' };

try {
  if (command === 'build') {
    await build(
      parseOptions(rest, {
        platform: 'value',
        version: 'value',
        revision: 'value',
        builder: 'value',
        ...REGISTRY_OPTIONS,
      }),
    );
  } else if (command === 'publish') {
    await publish(parseOptions(rest, { version: 'value', revision: 'value', ...REGISTRY_OPTIONS }));
  } else if (command === 'verify-public') {
    await verifyPublic(
      parseOptions(rest, {
        version: 'value',
        revision: 'value',
        'expect-from-env': 'flag',
        ...REGISTRY_OPTIONS,
      }),
    );
  } else if (command === 'agree') {
    // The release job's own decision against the plan's (lib decisionChangeProblem).
    parseOptions(rest, {});
    const decision = (prefix) => ({
      version: parseVersion(process.env[`${prefix}_VERSION`]),
      shouldRelease: parseFlag(process.env[`${prefix}_SHOULD_RELEASE`], `${prefix}_SHOULD_RELEASE`),
      createTag: parseFlag(process.env[`${prefix}_CREATE_TAG`], `${prefix}_CREATE_TAG`),
    });
    const problem = decisionChangeProblem(decision('PLANNED'), decision('OWN'));
    if (problem) fail(`${problem}. Nothing is tagged.`);
    note('the release decision is the one the images were planned for');
  } else if (command === 'plan') {
    // The `plan` job's decision, from next-version.mjs's outputs and the run's
    // facts, every one of them passed as an exact true/false (see parseFlag).
    parseOptions(rest, {});
    const plan = planImages({
      shouldRelease: parseFlag(process.env['SHOULD_RELEASE'], 'SHOULD_RELEASE'),
      createTag: parseFlag(process.env['CREATE_TAG'], 'CREATE_TAG'),
      stage: parseFlag(process.env['STAGE'], 'STAGE'),
      ref: String(process.env['GITHUB_REF'] ?? ''),
    });
    writeOutputs({
      stage: String(plan.stage),
      build: String(plan.build),
      publish: String(plan.publish),
    });
  } else {
    fail('usage: release-images.mjs plan|build|publish|verify-public|agree …');
  }
} catch (error) {
  console.error(
    color.red(`\n${symbol.fail} ${error instanceof Error ? error.message : String(error)}`),
  );
  process.exitCode = 1;
}
