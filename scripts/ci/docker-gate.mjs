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
 */
import { existsSync, copyFileSync, unlinkSync } from 'node:fs';
import path from 'node:path';
import { captureExe, runExe, hasExe, repoRoot } from './lib/proc.mjs';
import { color, symbol, note, warn } from './lib/ui.mjs';

const TAG = 'local-ci';
const TRIVY_CACHE_VOLUME = 'hvault-trivy-cache';
const TRIVY_IMAGE = 'aquasec/trivy:latest';

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
 */
function runContainer(runArgs) {
  const created = captureExe('docker', ['run', '-d', ...runArgs]);
  if (!created.ok) {
    return { status: 127, output: created.stderr };
  }
  const id = created.stdout.trim();

  try {
    const waited = captureExe('docker', ['wait', id]);
    const logs = captureExe('docker', ['logs', id]);
    const status = waited.ok ? Number.parseInt(waited.stdout.trim(), 10) : 1;
    return {
      status: Number.isNaN(status) ? 1 : status,
      output: `${logs.stdout}${logs.stderr}`.trim(),
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

const scanArgs = [
  'image',
  '--severity',
  'CRITICAL,HIGH',
  '--ignore-unfixed',
  '--exit-code',
  '1',
  '--scanners',
  'vuln',
  '--format',
  'table',
  '--timeout',
  '15m',
];

const vulnerable = [];

for (const image of IMAGES.filter((candidate) => candidate.scan)) {
  const reference = `${image.name}:${TAG}`;
  console.log(color.cyan(`\n  scanning ${reference}`));

  let status;
  let output;

  if (nativeTrivy) {
    // A native binary streams fine and picks up a repo-root .trivyignore itself.
    status = await runExe('trivy', [...scanArgs, reference]);
    output = '';
  } else {
    ({ status, output } = runContainer([
      '-v',
      '/var/run/docker.sock:/var/run/docker.sock',
      '-v',
      `${TRIVY_CACHE_VOLUME}:/root/.cache`,
      TRIVY_IMAGE,
      ...scanArgs,
      reference,
    ]));
    if (output) console.log(output);
  }

  if (status === 1) {
    vulnerable.push(reference);
  } else if (status !== 0) {
    fail(`trivy could not scan ${reference} (exit ${String(status)})`);
  }
}

if (vulnerable.length > 0) {
  warn('findings above are FIXABLE — update the base image or the dependency.');
  fail(`Trivy found fixable CRITICAL/HIGH vulnerabilities in: ${vulnerable.join(', ')}`);
}

console.log(
  color.green(
    `\n${symbol.pass} images build, nginx config parses, compose resolves, no fixable CRITICAL/HIGH vulnerabilities`,
  ),
);
