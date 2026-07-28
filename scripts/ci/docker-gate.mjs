#!/usr/bin/env node
/**
 * Container gate — the local stand-in for the old `docker-build` CI job.
 *
 * Builds all four production images, proves the Nginx config parses, proves the
 * compose stack resolves, and scans the three application images with Trivy.
 *
 * Two things it does NOT do the obvious way, both learned from a real Docker
 * setup rather than from the docs:
 *
 *   * It never reads a container's stdout by attaching to it. A daemon reached
 *     over `DOCKER_HOST=tcp://…` can fail to relay the hijacked attach stream,
 *     and the container then appears to produce no output at all while still
 *     exiting with the right code — a scanner whose findings are invisible.
 *     `docker run -d` + `docker wait` + `docker logs` uses ordinary HTTP
 *     endpoints and works on every transport.
 *   * It never bind-mounts a host path. A Windows path (`D:\…`) contains the
 *     colon that `-v` splits on, and the daemon rejects the mount outright.
 *     The Trivy cache therefore lives in a named volume.
 *
 * Trivy fails the gate only on vulnerabilities that HAVE a fix. This gate blocks
 * `git push`, and an unfixable CRITICAL in an upstream base image would
 * otherwise wall off the repository until someone else shipped a patch — a gate
 * nobody can satisfy gets bypassed, and then it protects nothing. Unfixed
 * findings are still printed; they are just not fatal.
 *
 * `scripts/ci/trivy-baseline.json` extends that same reasoning to the case a
 * fix exists for the LIBRARY but not in anything this project can install — the
 * concrete instance being a vulnerable package inside npm's own bundled tree,
 * which no lockfile or `overrides` entry of ours can reach. Such a finding is
 * accepted only by an entry naming the CVE, the image, the package AND the path
 * it was reviewed at, so the same CVE appearing in our own dependencies still
 * fails. The gate therefore fails on anything NEW — the same contract as
 * `codeql-baseline.json` — rather than on everything or nothing.
 */
import { existsSync, copyFileSync, unlinkSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { captureExe, runExe, hasExe, repoRoot } from './lib/proc.mjs';
import { color, symbol, note, warn } from './lib/ui.mjs';

const TAG = 'local-ci';
const TRIVY_CACHE_VOLUME = 'hvault-trivy-cache';
const TRIVY_IMAGE = 'aquasec/trivy:latest';
// Reviewed, accepted container findings. Consulted here rather than through a
// repo-root `.trivyignore`, which only a NATIVE trivy binary would read: this
// gate usually runs Trivy in a container and deliberately bind-mounts no host
// path (see the header), so an ignore file on disk would be invisible exactly
// where it is most often needed — and an exception nobody can see is worse than
// no exception at all.
const BASELINE = path.join(repoRoot, 'scripts', 'ci', 'trivy-baseline.json');

const IMAGES = [
  { name: 'hvault-app', file: 'docker/Dockerfile', target: 'app', scan: true },
  { name: 'hvault-web', file: 'docker/Dockerfile', target: 'web', scan: true },
  // The bootstrap image carries the full devDependency tree into the production
  // stack, so it is the largest attack surface of the three — it must not be the
  // one image nobody scans.
  { name: 'hvault-bootstrap', file: 'docker/Dockerfile', target: 'bootstrap', scan: true },
  { name: 'hvault-db', file: 'docker/mongo.Dockerfile', target: null, scan: false },
];

const fail = (message) => {
  console.error(color.red(`\n${symbol.fail} ${message}`));
  process.exit(1);
};

/**
 * Runs a container and returns its exit code AND its output, without relying on
 * the attach stream. See the header comment for why this indirection exists.
 *
 * `stdout` is returned SEPARATELY from the combined `output`. Trivy writes its
 * report to stdout and its progress logs to stderr, so a machine-readable
 * `--format json` report can only be parsed from the stream that carries it
 * alone — the combined form interleaves INFO lines into the JSON and cannot be
 * parsed at all.
 */
function runContainer(runArgs) {
  const created = captureExe('docker', ['run', '-d', ...runArgs]);
  if (!created.ok) {
    return { status: 127, output: created.stderr, stdout: '' };
  }
  const id = created.stdout.trim();

  try {
    const waited = captureExe('docker', ['wait', id]);
    const logs = captureExe('docker', ['logs', id]);
    const status = waited.ok ? Number.parseInt(waited.stdout.trim(), 10) : 1;
    return {
      status: Number.isNaN(status) ? 1 : status,
      output: `${logs.stdout}${logs.stderr}`.trim(),
      stdout: logs.stdout,
    };
  } finally {
    captureExe('docker', ['rm', '-f', id]);
  }
}

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------

if (!hasExe('docker', ['version', '--format', '{{.Client.Version}}'])) {
  fail(
    'docker CLI not found on PATH.\n' +
      '      Start Docker, or skip this gate:  HVAULT_SKIP_GATES=docker git push',
  );
}

const daemon = captureExe('docker', ['info', '--format', '{{.ServerVersion}}']);
if (!daemon.ok) {
  fail(
    'the Docker daemon is not reachable (is Docker Desktop running?).\n' +
      '      Start it, or skip this gate:  HVAULT_SKIP_GATES=docker git push',
  );
}
note(`docker daemon ${daemon.stdout.trim()}`);

// ---------------------------------------------------------------------------
// 1. Build every production image
// ---------------------------------------------------------------------------
// The app and web images MUST come from the same Dockerfile (and therefore the
// same client build stage): app serves the index.html that references the
// content-hashed assets web serves. Building them from two separate contexts
// could emit two sets of hashes, and the app would 404 every script.

for (const image of IMAGES) {
  console.log(
    color.cyan(
      `\n  building ${image.name}:${TAG}${image.target ? ` (target: ${image.target})` : ''}`,
    ),
  );

  const args = ['build', '-f', image.file];
  if (image.target) args.push('--target', image.target);
  args.push('-t', `${image.name}:${TAG}`, '.');

  const code = await runExe('docker', args);
  if (code !== 0) fail(`docker build failed for ${image.name} (exit ${String(code)})`);
}

// ---------------------------------------------------------------------------
// 2. Validate the Nginx configuration inside the image that ships it
// ---------------------------------------------------------------------------

console.log(color.cyan('\n  validating nginx configuration'));
const nginx = runContainer([`hvault-web:${TAG}`, 'nginx', '-t']);
if (nginx.output) note(nginx.output.replaceAll('\n', '\n      '));
if (nginx.status !== 0) fail(`nginx -t rejected the configuration (exit ${String(nginx.status)})`);

// ---------------------------------------------------------------------------
// 3. Validate the compose stack
// ---------------------------------------------------------------------------
// The stack's `env_file` is optional (`required: false`), but its MONGODB_URI
// interpolates `${MONGO_ROOT_PASSWORD:?...}` — a deliberate guard, so a stack can
// never come up on a default database password — and Compose reads that from the
// `.env` sitting next to the compose file. A clone has no .env, so stand a
// throwaway one up from the committed example and remove it again. An existing
// .env is never touched: it is the developer's real configuration.
//
// `.env.example` ships MONGO_ROOT_PASSWORD **empty**, on purpose: a placeholder
// would be a working database root password published in this repository. `${VAR:?}`
// rejects an empty value exactly as it rejects a missing one, so the gate supplies a
// throwaway of its own through the environment (Compose reads the shell first, then
// the file) rather than weakening the example. It never touches the real .env, and
// the value never leaves this process.

console.log(color.cyan('\n  validating compose stack'));
const envPath = path.join(repoRoot, '.env');
const createdEnv = !existsSync(envPath);
if (createdEnv) {
  copyFileSync(path.join(repoRoot, '.env.example'), envPath);
  note('created a temporary .env from .env.example for interpolation');
}

try {
  const config = captureExe('docker', ['compose', 'config', '--quiet'], {
    // captureExe merges this over process.env for the child only.
    // Both guarded secrets: the app/bootstrap URI interpolates
    // ${MONGO_APP_PASSWORD:?...} and hvault-db-init interpolates both, so
    // supplying only the root password makes `compose config` fail here.
    env: {
      MONGO_ROOT_PASSWORD: 'docker-gate-throwaway-not-a-real-secret',
      MONGO_APP_PASSWORD: 'docker-gate-throwaway-not-a-real-secret',
    },
  });
  if (!config.ok) {
    fail(`docker compose config rejected the stack:\n${config.stderr.trim()}`);
  }
  note('compose stack resolves');
} finally {
  if (createdEnv) unlinkSync(envPath);
}

// ---------------------------------------------------------------------------
// 4. Trivy vulnerability scan
// ---------------------------------------------------------------------------

const nativeTrivy = hasExe('trivy');
if (!nativeTrivy) {
  note(`no trivy binary on PATH — using ${TRIVY_IMAGE} (cache: volume ${TRIVY_CACHE_VOLUME})`);
}

// `--exit-code 0` is deliberate: Trivy reports, this gate DECIDES. The verdict
// has to be taken after the baseline in `trivy-baseline.json` is applied, and a
// non-zero exit here would fail the push before that could happen. A scan that
// genuinely could not run is still caught — that surfaces as a non-zero exit
// from a scanner that produced no parseable report, handled below.
//
// `--format json` rather than `table` for the same reason: an accepted finding
// can only be matched on (id, image, package, path) if those fields survive as
// data. The human-readable table is re-rendered from the JSON.
const scanArgs = [
  'image',
  '--severity',
  'CRITICAL,HIGH',
  '--ignore-unfixed',
  '--exit-code',
  '0',
  '--scanners',
  'vuln',
  '--format',
  'json',
  '--timeout',
  '15m',
];

/**
 * The accepted-findings list. Read once, up front, so a malformed or missing
 * file fails the gate loudly rather than silently accepting nothing (which
 * would look identical to "the baseline worked" on a clean scan) — or, worse,
 * silently accepting everything.
 */
function loadBaseline() {
  if (!existsSync(BASELINE)) {
    fail(`missing ${path.relative(repoRoot, BASELINE)} — the Trivy baseline must exist`);
  }
  try {
    const parsed = JSON.parse(readFileSync(BASELINE, 'utf8'));
    if (!Array.isArray(parsed.findings)) throw new Error('`findings` must be an array');
    return parsed.findings;
  } catch (error) {
    return fail(
      `${path.relative(repoRoot, BASELINE)} is not valid: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

const baseline = loadBaseline();
const baselineHits = new Set();

/**
 * A finding is accepted only when EVERY field of a baseline entry matches: the
 * CVE, the image it was reviewed in, the package, and the path prefix. Matching
 * on the CVE alone would let an entry reviewed for npm's bundled copy silently
 * excuse the same CVE appearing in our own application dependencies — which is
 * exactly the finding that must never be waved through.
 */
function acceptedBy(finding, imageName) {
  return baseline.find(
    (entry) =>
      entry.id === finding.id &&
      entry.image === imageName &&
      entry.package === finding.pkg &&
      finding.path.startsWith(entry.pathPrefix),
  );
}

function extractFindings(report) {
  const findings = [];
  for (const result of report.Results ?? []) {
    for (const vulnerability of result.Vulnerabilities ?? []) {
      findings.push({
        id: vulnerability.VulnerabilityID,
        pkg: vulnerability.PkgName,
        installed: vulnerability.InstalledVersion,
        fixed: vulnerability.FixedVersion ?? '',
        severity: vulnerability.Severity,
        // PkgPath is where the package actually lives; Target is the scan unit
        // it was found through. The path is what distinguishes npm's bundled
        // tree from our own, so it must never fall back to nothing.
        path: vulnerability.PkgPath ?? result.Target ?? '',
        title: vulnerability.Title ?? '',
      });
    }
  }
  return findings;
}

const vulnerable = [];
let acceptedCount = 0;

for (const image of IMAGES.filter((candidate) => candidate.scan)) {
  const reference = `${image.name}:${TAG}`;
  console.log(color.cyan(`\n  scanning ${reference}`));

  let status;
  let report;

  if (nativeTrivy) {
    const scan = captureExe('trivy', [...scanArgs, reference]);
    status = scan.status;
    report = scan.stdout;
    if (scan.stderr.trim()) console.log(scan.stderr.trim());
  } else {
    const scan = runContainer([
      '-v',
      '/var/run/docker.sock:/var/run/docker.sock',
      '-v',
      `${TRIVY_CACHE_VOLUME}:/root/.cache`,
      TRIVY_IMAGE,
      ...scanArgs,
      reference,
    ]);
    status = scan.status;
    report = scan.stdout;
  }

  if (status !== 0) {
    fail(`trivy could not scan ${reference} (exit ${String(status)})`);
  }

  let parsed;
  try {
    parsed = JSON.parse(report);
  } catch {
    fail(`trivy produced no parseable JSON report for ${reference}`);
  }

  const findings = extractFindings(parsed);
  const unresolved = [];

  for (const finding of findings) {
    const entry = acceptedBy(finding, image.name);
    if (entry) {
      baselineHits.add(entry.id);
      acceptedCount += 1;
      note(
        `accepted ${finding.id} (${finding.pkg} ${finding.installed}) in ${reference} — see scripts/ci/trivy-baseline.json`,
      );
    } else {
      unresolved.push(finding);
    }
  }

  if (unresolved.length === 0) {
    note(`${reference}: no fixable CRITICAL/HIGH beyond the baseline`);
    continue;
  }

  for (const finding of unresolved) {
    console.log(
      color.red(
        `    ${finding.severity}  ${finding.id}  ${finding.pkg} ${finding.installed} -> ${finding.fixed || '(no fix)'}\n      ${finding.path}\n      ${finding.title}`,
      ),
    );
  }
  vulnerable.push(reference);
}

// A baseline entry that matched nothing is either fixed upstream or wrong. It is
// reported rather than fatal on purpose: making it fail the push would block a
// release at the exact moment the news is GOOD, which is how an exception list
// turns into something people route around.
for (const entry of baseline) {
  if (!baselineHits.has(entry.id)) {
    warn(
      `baselined ${entry.id} (${entry.package}, ${entry.image}) no longer matches — remove it from scripts/ci/trivy-baseline.json`,
    );
  }
}

if (vulnerable.length > 0) {
  warn('findings above are FIXABLE — update the base image or the dependency.');
  fail(`Trivy found fixable CRITICAL/HIGH vulnerabilities in: ${vulnerable.join(', ')}`);
}

if (acceptedCount > 0) {
  note(
    `${String(acceptedCount)} finding(s) accepted by the baseline — each one states why, and what removes it`,
  );
}

console.log(
  color.green(
    `\n${symbol.pass} images build, nginx config parses, compose resolves, no fixable CRITICAL/HIGH vulnerabilities`,
  ),
);
