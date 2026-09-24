/**
 * The BUILT artifact, staged in the image's layout and booted in production mode.
 *
 * ONE copy, shared by the two gates that run the JavaScript this repository
 * actually ships: `test:smoke` (one vault journey over HTTP) and `test:sandbox`
 * (the isolated render document, rendered by a real browser under the headers
 * the artifact sends). Two copies of "how the artifact is laid out and started"
 * would drift, and the difference between them is exactly where a gate starts
 * testing a tree production never has — the reason `lib/vault-flow.mjs` is
 * shared rather than copied too.
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE ARTIFACT IS STAGED IN A TEMPORARY DIRECTORY, NOT IN THE CHECKOUT. In
 *     production the server resolves its static root as `<dist>/../public`, so
 *     a naive gate would copy the client bundle into `packages/server/public` —
 *     an untracked, un-ignored tree that the secret scan, the integrity scan and
 *     the format check would all then walk, and that a crashed run would leave
 *     behind. Staging `dist/`, `public/` and `sandbox-document/` as siblings
 *     under a temp directory reproduces the image's layout exactly and writes
 *     nothing into the repository. The third one is the security-relevant one:
 *     the isolated render document is emitted OUTSIDE the static root on
 *     purpose, and a gate that flattened the two would be exercising a tree
 *     production never has. `node_modules` is SYMLINKED (600 MB, and nothing
 *     writes to it), which also proves the emitted tree resolves its
 *     dependencies by ordinary Node resolution rather than by accident of
 *     location.
 *
 *  b. IT RUNS IN PRODUCTION MODE, WITH REAL SECRETS. `NODE_ENV=production` is
 *     where the config schema refuses `dev-` secrets and a non-https CORS
 *     origin, where the rate limiters stop being no-ops and start needing their
 *     MongoDB store, where 5xx bodies are redacted, where the SPA shell is served
 *     by Express with a per-request CSP nonce, and where `/sandbox.html` exists
 *     at all. The secrets are minted per run and never leave the process.
 *
 *  c. A DEAD PROCESS IS NOT WAITED FOR. The single most likely thing either gate
 *     catches — the production config validation refusing to boot — exits in
 *     about a second, and polling the full deadline afterwards spent 45 s
 *     proving nothing. `waitForHealth` still owns the timeout for a process that
 *     is merely slow, and the deadline is a FAILURE, never a skip: a server that
 *     never listens produces no exit code, so a gate waiting on it would hang
 *     rather than fail.
 */
import { cpSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { repoRoot } from './proc.mjs';
import { waitForHealth } from './vault-flow.mjs';

/** A production boot on a cold machine is seconds; 45 of them is a hang. */
export const BOOT_DEADLINE_MS = 45_000;
/** How long a SIGTERMed artifact may take to exit before it is SIGKILLed. */
export const SHUTDOWN_GRACE_MS = 5_000;

/**
 * The three build outputs the image carries, where the build leaves each one,
 * and the directory name each is staged under.
 *
 * The isolated render document is emitted OUTSIDE the client's `dist/`, because
 * `dist/` becomes the `express.static` root and the document's whole containment
 * is the per-response CSP Express attaches to it. It is staged into its own
 * sibling for the same reason the image copies it into its own directory: the
 * layout IS the control. `sandbox-document` matches
 * `packages/server/src/config/clientArtifacts.ts`, which is the one place the
 * server resolves either path.
 */
const ARTIFACT_PARTS = [
  {
    label: 'server',
    from: path.join(repoRoot, 'packages', 'server', 'dist'),
    probe: 'server.js',
    to: 'dist',
  },
  {
    label: 'client',
    from: path.join(repoRoot, 'packages', 'client', 'dist'),
    probe: 'index.html',
    to: 'public',
  },
  {
    label: 'sandbox document',
    from: path.join(repoRoot, 'packages', 'client', 'dist-sandbox'),
    probe: 'sandbox.html',
    to: 'sandbox-document',
  },
];

/**
 * The first build output that is missing, as a sentence naming it, or `null`.
 *
 * A gate reports this as a failed `artifact` step rather than letting the boot
 * fail obscurely: "run npm run build" is the whole remedy, and saying which of
 * the two Vite builds is absent is the difference between an actionable message
 * and "build again and hope".
 */
export function missingArtifact() {
  for (const part of ARTIFACT_PARTS) {
    const file = path.join(part.from, part.probe);
    if (!existsSync(file)) {
      return `no built ${part.label} artifact at ${path.relative(repoRoot, file)} — run npm run build`;
    }
  }
  return null;
}

/**
 * (a) Copy the three build outputs into the image's layout inside a fresh temp
 * directory, beside a linked dependency tree.
 *
 * `workspace` is the directory to boot FROM (it holds `node_modules` and becomes
 * the child's cwd, so the logger's eager `<cwd>/logs` lands there rather than in
 * the checkout); `artifact` holds `dist/`, `public/` and `sandbox-document/`.
 */
export function stageArtifact(prefix) {
  const workspace = mkdtempSync(path.join(tmpdir(), prefix));
  const artifact = path.join(workspace, 'artifact');
  mkdirSync(artifact, { recursive: true });
  for (const part of ARTIFACT_PARTS) {
    cpSync(part.from, path.join(artifact, part.to), { recursive: true });
  }
  symlinkSync(path.join(repoRoot, 'node_modules'), path.join(workspace, 'node_modules'), 'dir');
  return { workspace, artifact };
}

/** An OS-assigned free port, released immediately; the server binds it a moment later. */
export function freePort() {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.on('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => {
        resolve(port);
      });
    });
  });
}

const secret = () => randomBytes(32).toString('hex');

/**
 * (b) The environment the artifact boots under.
 *
 * `origin` is the https origin the configuration requires in production: the
 * schema refuses a non-https CORS origin and any `dev-` secret, which is half of
 * what running the artifact proves. `extra` is spread LAST, so a gate adds what
 * its own journey needs (the object-storage connection, for one) without being
 * able to forget the rest.
 */
export function productionEnv({ port, mongoUri, origin, extra = {} }) {
  return {
    ...process.env,
    NODE_ENV: 'production',
    PORT: String(port),
    HOST: '127.0.0.1',
    MONGODB_URI: mongoUri,
    JWT_ACCESS_SECRET: secret(),
    JWT_REFRESH_SECRET: secret(),
    SESSION_SECRET: secret(),
    APP_URL: origin,
    CORS_ORIGIN: origin,
    APP_NAME: 'H-Vault',
    SMTP_HOST: '',
    SMTP_USER: '',
    SMTP_PASS: '',
    ...extra,
  };
}

/**
 * Start `dist/server.js` exactly as the image's CMD does, and wait until it
 * answers its health route or dies.
 *
 * Resolves to `{ child, health, output }`: `health` is `waitForHealth`'s verdict
 * (or a synthesized failure naming the exit), and `output()` returns the tail of
 * everything the process printed, for the failure report.
 *
 * `onSpawn` receives the process the moment it exists, BEFORE the wait. A caller
 * with a signal handler needs it then: the wait can last the whole boot
 * deadline, and a teardown that only learns of the process when this function
 * returns would leave a server running if a signal lands inside that window.
 */
export async function bootArtifact({
  workspace,
  artifact,
  env,
  deadlineMs = BOOT_DEADLINE_MS,
  onSpawn = () => {},
}) {
  const started = Date.now();
  const log = [];
  const child = spawn(process.execPath, [path.join(artifact, 'dist', 'server.js')], {
    cwd: workspace,
    stdio: ['ignore', 'pipe', 'pipe'],
    env,
  });
  onSpawn(child);
  for (const source of [child.stdout, child.stderr]) {
    source?.on('data', (chunk) => {
      log.push(chunk.toString('utf8'));
    });
  }
  child.once('exit', (code, signal) => {
    if (code !== 0 && code !== null) log.push(`\n[artifact exited with code ${String(code)}]`);
    else if (signal) log.push(`\n[artifact terminated by ${signal}]`);
  });

  const baseUrl = `http://127.0.0.1:${env.PORT}`;
  // (c) A dead process cannot become healthy, so stop waiting for it.
  const health = await Promise.race([
    waitForHealth(baseUrl, { deadlineMs, intervalMs: 500 }),
    new Promise((resolve) => {
      child.once('exit', (code, signal) =>
        resolve({
          ok: false,
          attempts: 0,
          waitedMs: Date.now() - started,
          detail: `the artifact exited before serving a health response (${signal ? `signal ${signal}` : `code ${String(code)}`})`,
        }),
      );
    }),
  ]);
  return { child, baseUrl, health, output: () => log.join('').slice(-4000) };
}

/** SIGTERM the artifact, and SIGKILL it if it has not exited within the grace. */
export async function stopArtifact(child, graceMs = SHUTDOWN_GRACE_MS) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.kill('SIGTERM');
  await new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      resolve(undefined);
    }, graceMs);
    timer.unref?.();
    child.once('exit', () => {
      clearTimeout(timer);
      resolve(undefined);
    });
  });
}

/** Remove a staged workspace. Never throws: a teardown must not destroy a run's evidence. */
export function removeWorkspace(workspace) {
  if (workspace) rmSync(workspace, { recursive: true, force: true });
}
