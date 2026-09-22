#!/usr/bin/env node
/**
 * `test:deploy` — the deployment clean room.
 *
 * `audit:image` proves the images BUILD; the E2E suite proves the application
 * WORKS against a development server. Nothing between them ever ran the thing
 * this project actually ships: six containers, one published port, a
 * least-privilege database user, an object storage engine on an internal
 * network, two one-shots the app gates on, and a config surface that only exists
 * in production. This gate stands that stack up from nothing and drives a real
 * user journey — a vault item AND a stored document — through the single port it
 * publishes.
 *
 * It is also the ONLY gate where the real Nginx, the real image layout and the
 * real header set meet, which makes it the only place three things are actually
 * proven: that the isolated render document reaches a client from Express with
 * its own far stricter policy and from neither document root on disk; that no
 * route-missing URL spelling hands that document out under any other policy; and
 * that the two CORS-ish headers an opaque origin needs are scoped to
 * `sandbox-assets/`. The E2E and a11y suites drive the Vite dev server, which
 * has neither helmet nor Nginx.
 *
 *   node scripts/ci/deploy-drill.mjs            the gate (what the pipeline runs)
 *   npm run test:deploy                         the same thing
 *   npm run test:deploy -- --keep               leave the stack up for inspection
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE DRILL GETS ITS OWN STACK NAME, PORT AND SUBNETS. `HVAULT_STACK_NAME`
 *     namespaces the Compose project and with it every container, network and
 *     volume, and the drill's very first act is `down -v` — which destroys the
 *     project's volumes. Sharing the operator's default name would mean a gate
 *     that deletes a running deployment's database. Its own name makes the drill
 *     safe to run on a host that is serving H-Vault, and its own port and
 *     subnets keep the two from colliding while both are up.
 *
 *  b. EVERY REQUEST GOES THROUGH THE PUBLISHED PORT. Not one line here talks to
 *     the app container directly. The single-port topology IS the deployment —
 *     Nginx serving `/assets/*` from disk, proxying every HTML document and
 *     every `/api/*` call to Express, with `resolver 127.0.0.11` and a variable
 *     `proxy_pass` so a restarted app is re-resolved — and a drill that bypassed
 *     it would prove the application works while leaving the deployment
 *     untested.
 *
 *  c. CONFIGURATION ARRIVES THE WAY AN OPERATOR'S DOES. The stack reads one root
 *     `.env`, declared `required: false` so the compose file still parses in a
 *     clean checkout. A clean checkout therefore has no JWT secrets, and the app
 *     would exit at config validation. The drill appends a second env file
 *     through a Compose override instead of editing, faking or substituting the
 *     compose file — the real one is the thing under test.
 *
 *  d. THE PORT-EXPOSURE CHECK IS A DIFFERENTIAL. See `portExposureVerdict` in
 *     lib/drill.mjs: reading 27017 BEFORE the stack starts is what distinguishes
 *     "this stack published the database" from "this developer runs MongoDB".
 *     The absolute claim — exactly one published port, bound to 127.0.0.1 — is
 *     made from Compose's own port table, where there is no ambiguity at all.
 *
 *  e. THE RESTART CHECK RE-AUTHENTICATES. Data survival is proved by signing in
 *     again and comparing the stored ciphertext byte for byte, not by reusing
 *     the access token from before the restart — which would prove only that a
 *     five-minute JWT is still inside its window.
 *
 *  f. THE ROTATION CHECK IS BEHAVIOURAL. `provision-app-user.js` promises it
 *     never rewrites an existing password, and an operator's rotated credential
 *     depends on that promise holding across every redeploy. So the drill
 *     rotates the password inside the database, re-runs the provisioning
 *     one-shot, and then AUTHENTICATES: the rotated password must still work and
 *     the one in the deployment's own configuration must not. The script's log
 *     line is corroboration, never the assertion — a log line can only say what
 *     the script believes it did.
 *
 *  g. A FAILING RUN CAPTURES THE LOGS BEFORE TEARING DOWN. A container drill
 *     that removes the evidence with the stack is a gate people stop running.
 *
 *  h. THE STORAGE CREDENTIAL IS A DIFFERENT TRAP FROM THE DATABASE ONE, and the
 *     drill asserts the difference rather than assuming the two behave alike.
 *     The database provisioner boots anyway and leaves an existing password
 *     alone (f); the storage engine REFUSES to boot when it is handed the same
 *     access key id with a different secret, exiting 1 rather than rewriting the
 *     key, so an operator who rotates one value ends up with a crash loop. Both
 *     halves of the supported procedure are exercised: the refusal, and the
 *     rotation of the id and the secret TOGETHER — after which the newly minted
 *     key must still read a document written under the superseded one. That last
 *     read is what makes the whole sequence an assertion about the bucket rather
 *     than about a container's exit code.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createConnection } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { captureExe, hasExe, repoRoot, runExe } from './lib/proc.mjs';
import { color, note, symbol, warn } from './lib/ui.mjs';
import { ensureReportDir, writeJsonReport } from './lib/reports.mjs';
import {
  SERVICE_EXPECTATIONS,
  parseComposePs,
  parseProvisionLog,
  portExposureVerdict,
  publishedPorts,
  renderEnvFile,
  renderOverride,
  serviceVerdicts,
  singlePortProblems,
} from './lib/drill.mjs';
import {
  purgeDocumentFlow,
  reReadDocument,
  reReadVault,
  readDocumentsConfig,
  runDocumentFlow,
  runVaultFlow,
  waitForHealth,
} from './lib/vault-flow.mjs';
import {
  SANDBOX_ASSET_HEADERS_EXPECTED,
  SANDBOX_BYPASS_SPELLINGS,
  SANDBOX_CSP_EXPECTED,
  SANDBOX_DOCUMENT_CACHE_CONTROL,
  appAssetProblems,
  assetResponseProblems,
  bypassUrl,
  cspProblems,
  sandboxAssetProblems,
  sandboxAssetUrls,
  sandboxBypassProblems,
} from './lib/sandbox-headers.mjs';

/** (a) Everything about the drill's stack is namespaced away from a real one. */
const STACK_NAME = 'hvault-drill';
const HTTP_PORT = 18080;
const EDGE_SUBNET = '172.31.244.0/24';
const DATA_SUBNET = '172.31.245.0/24';
/**
 * The ports the stack must NOT publish: MongoDB, the app's internal listener, and
 * the object storage engine's S3 API.
 *
 * The storage port is here for the same reason the database's is, and it is the
 * more dangerous of the two: the bucket holds every stored document's ciphertext,
 * the engine authenticates with a static key pair out of `.env`, and it sits on
 * the `internal: true` network precisely so nothing outside the stack can reach
 * it. `docker-compose.dev.yml` DOES publish it on loopback for host tooling,
 * which is exactly the differential in (d): a developer running the dev stack
 * held the port before `up`, and the verdict says so rather than blaming this one.
 */
const FORBIDDEN_PORTS = [
  { port: 27017, label: 'MongoDB' },
  { port: 5000, label: "the app's internal listener" },
  { port: 3900, label: "the object storage engine's S3 API" },
];
/** Bounds `up --wait`'s wait phase (not the build) so a stuck healthcheck is an error, not a hang. */
const WAIT_TIMEOUT_SECONDS = 300;
const HEALTH_DEADLINE_MS = 120_000;
const RESTART_DEADLINE_MS = 120_000;
/** A TCP probe answers or refuses in microseconds on loopback; a second is generous. */
const PROBE_TIMEOUT_MS = 1_000;
/**
 * How `waitForContainerExit` polls, and how long it waits.
 *
 * The storage engine refuses a mismatched credential within a second of starting,
 * so thirty is generous for a container that is going to stop; the bound exists
 * for the container that does NOT, which is exactly the failure the credential
 * probe is there to catch.
 */
const CONTAINER_POLL_MS = 500;
const CONTAINER_EXIT_DEADLINE_MS = 30_000;

const argv = process.argv.slice(2);
const keepStack = argv.includes('--keep');

const secret = () => randomBytes(32).toString('hex');
const baseUrl = `http://127.0.0.1:${String(HTTP_PORT)}`;

const workspace = mkdtempSync(path.join(tmpdir(), 'hvault-drill-'));
const envFile = path.join(workspace, 'drill.env');
const overrideFile = path.join(workspace, 'drill-override.yml');
/** Written only when the credential probe runs; see `renderNoRestartOverride`. */
const probeOverrideFile = path.join(workspace, 'drill-no-restart.yml');

/**
 * (c) The throwaway deployment's configuration.
 *
 * Every secret is generated per run. `dev-` prefixes are refused outside
 * development and `CORS_ORIGIN` must be https in production, so these values are
 * not placeholders: they are the minimum a real production boot accepts, which
 * is part of what this gate proves.
 */
const APP_PASSWORD = secret();
const drillEnv = {
  HVAULT_STACK_NAME: STACK_NAME,
  HVAULT_HTTP_PORT: String(HTTP_PORT),
  HVAULT_EDGE_SUBNET: EDGE_SUBNET,
  HVAULT_DATA_SUBNET: DATA_SUBNET,
  // One proxy in front of Express here — this stack's own Nginx — because the
  // drill hits the published port directly instead of through a host Nginx. The
  // documented production value is 2, and a count that does not match reality
  // makes `req.ip` wrong, which is what the rate limiters key on.
  TRUST_PROXY_HOPS: '1',
  MONGO_ROOT_USERNAME: 'hvault',
  MONGO_ROOT_PASSWORD: secret(),
  MONGO_APP_USERNAME: 'hvault_app',
  MONGO_APP_PASSWORD: APP_PASSWORD,
  JWT_ACCESS_SECRET: secret(),
  JWT_REFRESH_SECRET: secret(),
  SESSION_SECRET: secret(),
  APP_URL: 'https://drill.hvault.test',
  CORS_ORIGIN: 'https://drill.hvault.test',
  APP_NAME: 'H-Vault',
  BCRYPT_ROUNDS: '12',
  SMTP_FROM: 'noreply@hvault.test',
  // Object storage. All four are `${...:?}`-guarded in docker-compose.yml, so
  // Compose refuses to resolve the stack without them and the drill would fail
  // before a container existed — the same reason the two Mongo passwords are
  // here. S3_ENDPOINT is deliberately absent: the stack pins the in-stack address
  // itself, and supplying one here would only test a value the deployment
  // overrides.
  //
  // The access key id is a fixed literal rather than a generated secret because
  // the storage engine refuses an id shorter than 8 characters at boot, and
  // because an id is not a secret; the two that are get a fresh 32-byte value per
  // run, like every other credential above.
  S3_BUCKET: 'hvault-drill',
  S3_ACCESS_KEY_ID: 'hvaultdrillkey',
  S3_SECRET_ACCESS_KEY: secret(),
  S3_RPC_SECRET: secret(),
};

writeFileSync(envFile, renderEnvFile(drillEnv), 'utf8');
writeFileSync(overrideFile, renderOverride(envFile), 'utf8');

/**
 * Compose, always with the drill's project, override and env file.
 *
 * `extraFiles` is appended AFTER the drill's own override, because Compose merges
 * `-f` files in order and the last one wins for a scalar. Exactly one caller uses
 * it (the credential probe, which takes the restart policy off one service), and
 * it is a parameter rather than a second argument list so there is still one
 * place that knows how to invoke Compose for this stack.
 */
const composeArgs = (rest, extraFiles = []) => [
  'compose',
  '--env-file',
  envFile,
  '-f',
  'docker-compose.yml',
  '-f',
  overrideFile,
  ...extraFiles.flatMap((file) => ['-f', file]),
  ...rest,
];
/**
 * The same values reach Compose through the process environment as well.
 *
 * `--env-file` replaces the default `.env` for interpolation, but a variable
 * EXPORTED in the operator's shell still outranks it — so a developer with
 * `HVAULT_HTTP_PORT` exported would silently move the drill's port and the flow
 * would knock on a door nobody is behind. Setting the same values here makes the
 * precedence irrelevant.
 */
const composeEnv = { ...drillEnv };

const compose = (rest, options = {}) =>
  captureExe('docker', composeArgs(rest), { env: composeEnv, ...options });
const composeStreamed = (rest, extraFiles = []) =>
  runExe('docker', composeArgs(rest, extraFiles), { env: composeEnv });

const steps = [];
const failures = [];
const started = Date.now();

const record = (name, ok, detail, extra = {}) => {
  steps.push({ name, ok, detail, ...extra });
  if (ok) console.log(color.green(`  ${symbol.pass} ${name} — ${detail}`));
  else {
    failures.push(`${name}: ${detail}`);
    console.error(color.red(`  ${symbol.fail} ${name} — ${detail}`));
  }
};

/**
 * Is anything listening on a loopback port right now?
 *
 * `refused` is the answer a port nobody published gives; `timeout` is what a
 * filtered port gives and is treated as "not reachable" rather than as an error,
 * because the claim being tested is reachability.
 */
function probeTcp(port) {
  return new Promise((resolve) => {
    const socket = createConnection({ host: '127.0.0.1', port });
    const settle = (result) => {
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(PROBE_TIMEOUT_MS);
    socket.once('connect', () => {
      settle('open');
    });
    socket.once('timeout', () => {
      settle('timeout');
    });
    socket.once('error', () => {
      settle('refused');
    });
  });
}

/** Runs a mongosh script inside the database container, with secrets passed as env, never argv. */
function mongosh(script, env) {
  const envArgs = Object.entries(env).flatMap(([key, value]) => ['-e', `${key}=${value}`]);
  return compose([
    'exec',
    '-T',
    ...envArgs,
    'hvault-db',
    'mongosh',
    '--quiet',
    '--host',
    '127.0.0.1',
    '--eval',
    script,
  ]);
}

/** Runs a one-shot service again, exactly as a redeploy would, and waits for its exit code. */
async function rerunOneShot(service) {
  const code = await composeStreamed(['up', '-d', '--no-deps', '--force-recreate', service]);
  if (code !== 0) return { exitCode: code, logs: '', started: false };
  const container = `${STACK_NAME}-${service.replace(/^hvault-/, '')}`;
  const waited = captureExe('docker', ['wait', container]);
  const logs = captureExe('docker', ['logs', container]);
  const exitCode = waited.ok ? Number.parseInt(waited.stdout.trim(), 10) : 1;
  return {
    exitCode: Number.isNaN(exitCode) ? 1 : exitCode,
    logs: `${logs.stdout}${logs.stderr}`.trim(),
    started: true,
  };
}

/**
 * Waits for one container to STOP, and reports the state it stopped in.
 *
 * A BOUNDED poll over `docker inspect` rather than `docker wait`, and the bound
 * is the whole reason it exists. `docker wait` blocks until the container is not
 * running, so a container that BOOTS when the probe expects a refusal would hang
 * this gate for ever rather than fail it — and `local-ci.mjs` puts no deadline on
 * a gate, so the hang would be the whole pipeline's. The one caller takes the
 * restart policy off first (`renderNoRestartOverride`), so the container stops
 * exactly once and `.State.ExitCode` is stable once it has; under
 * `restart: unless-stopped` it would be whatever the last cycle of a crash loop
 * happened to leave, which is the other reason that override is not optional.
 *
 * A container still running at the deadline is reported as such rather than as an
 * exit code, so the caller's message says "did not stop" instead of inventing a
 * number.
 */
async function waitForContainerExit(container, deadlineMs) {
  const started = Date.now();
  let last = { status: 'unknown', exitCode: null };
  do {
    const result = captureExe('docker', [
      'inspect',
      '--format',
      '{{.State.Status}} {{.State.ExitCode}}',
      container,
    ]);
    if (result.ok) {
      const [status = 'unknown', code = ''] = result.stdout.trim().split(/\s+/);
      const exitCode = Number.parseInt(code, 10);
      last = { status, exitCode: Number.isNaN(exitCode) ? null : exitCode };
      if (status === 'exited' || status === 'dead') return last;
    } else {
      last = { status: 'absent', exitCode: null };
    }
    await new Promise((resolve) => setTimeout(resolve, CONTAINER_POLL_MS));
  } while (Date.now() - started < deadlineMs);
  return last;
}

/**
 * Records one assertion whose failure arrives as a thrown `VaultFlowError`.
 *
 * The flow helpers throw with a `context`, so the alternative at each of the six
 * call sites is the same six-line `.catch(error => error)` / `instanceof Error`
 * block — and `.jscpd.json`'s duplication counters are ratcheted DOWNWARD. It
 * returns `null` on failure so the caller can skip what depended on it without a
 * second verdict about the same thing.
 */
async function recordFlow(name, describe, attempt) {
  const outcome = await attempt().catch((error) => error);
  if (outcome instanceof Error) {
    record(name, false, outcome.message, { context: outcome.context ?? {} });
    return null;
  }
  record(name, true, describe(outcome));
  return outcome;
}

/**
 * Rewrites the drill's env file in place, which is what a credential rotation IS.
 *
 * In place, and not through a second `--env-file`, because the two halves of the
 * stack read this configuration by two different routes: the storage engine's
 * `environment:` block is INTERPOLATED from the file Compose was pointed at,
 * while the app receives it as an `env_file` whose absolute path is baked into
 * the override written once at startup. A second file would therefore rotate the
 * engine's credentials and leave the app holding the old ones — which is a state
 * no operator can reach and which would make the "it can still read the bucket"
 * assertion below prove the opposite of what it claims.
 *
 * `composeEnv` is patched too, for the reason it exists at all: an exported
 * variable in the operator's shell outranks `--env-file`.
 */
function rewriteEnv(patch) {
  Object.assign(drillEnv, patch);
  Object.assign(composeEnv, patch);
  writeFileSync(envFile, renderEnvFile(drillEnv), 'utf8');
}

/**
 * A Compose override that takes the restart policy OFF one service, for the one
 * probe that needs to observe an exit code.
 *
 * `restart: unless-stopped` is correct for the deployment and
 * `docker-hardening.test.ts` requires it — but it turns a service that refuses to
 * boot into a crash LOOP, where `.State.ExitCode` is whatever the last cycle
 * happened to leave and a poller can land on a `running` container that is about
 * to die again. The credential probe below is asking a question about the
 * ENGINE's boot behaviour rather than about the restart policy, so it takes the
 * policy off for that one container and puts it back by recreating without this
 * file. Quoted, because an unquoted `no` is a boolean in YAML.
 */
function renderNoRestartOverride(service) {
  return `services:\n  ${service}:\n    restart: "no"\n`;
}

/**
 * Runs one long-lived service again from a fresh container, exactly as a redeploy
 * would, and waits for it to report healthy.
 *
 * `--no-deps`, so a redeploy of storage does not re-run the two one-shots the app
 * gates on; `--wait`, because "it came back" is the claim and Compose's own
 * readiness condition is the honest way to make it.
 */
async function recreateAndWait(services) {
  return composeStreamed([
    'up',
    '-d',
    '--no-deps',
    '--force-recreate',
    '--wait',
    '--wait-timeout',
    String(WAIT_TIMEOUT_SECONDS),
    ...services,
  ]);
}

async function teardown() {
  if (keepStack) {
    warn(`--keep: the stack is still up on ${baseUrl} (project ${STACK_NAME})`);
    warn(`its configuration is at ${envFile} — delete it when you are done`);
    return;
  }
  // Recorded, not discarded. A teardown that fails leaves six containers and
  // four volumes on the host, and the only thing that would ever notice is the
  // NEXT run's `down -v` — which happens before this run's port differential is
  // read, so the leak is invisible in every report. It is not fatal (the drill's
  // verdict is about the stack it brought up), but it must be visible.
  const down = await composeStreamed(['down', '-v', '--remove-orphans']);
  if (down !== 0) {
    // RECORDED, and deliberately not a failure of this gate. The subject is
    // whether the deployment comes up, serves, survives a restart and redeploys
    // idempotently; a volume that will not detach is a fault in the DISPOSAL of
    // that subject, and this pipeline draws that line sharply elsewhere (exit 1 =
    // a gate failed, exit 2 = a gate could not run). The leak is not unowned
    // either: the NEXT run opens with the same `down -v` and fails hard on it
    // (`clean-room` below), which is the moment it genuinely makes the drill
    // unrunnable. What was wrong before was that it went into no artifact at all.
    record(
      'teardown',
      true,
      `docker compose down -v exited ${String(down)} — containers or volumes may still exist ` +
        `for project ${STACK_NAME}; the next run's clean-room step will fail on them`,
    );
    warn(`teardown did not complete cleanly for project ${STACK_NAME}`);
  }
  rmSync(workspace, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------
ensureReportDir();
console.log(
  color.bold(`\n  deployment clean room — project ${STACK_NAME}, port ${String(HTTP_PORT)}\n`),
);

if (!hasExe('docker', ['version', '--format', '{{.Client.Version}}'])) {
  console.error(color.red('deploy-drill: the docker CLI is not on PATH'));
  process.exit(1);
}
if (!captureExe('docker', ['info', '--format', '{{.ServerVersion}}']).ok) {
  console.error(color.red('deploy-drill: the Docker daemon is not reachable'));
  process.exit(1);
}

/** @type {Record<number, string>} the BEFORE half of the differential (d) */
const portsBefore = {};

try {
  // -------------------------------------------------------------------------
  // 1. Clean room: destroy anything left of a previous drill, volumes included
  // -------------------------------------------------------------------------
  const down = await composeStreamed(['down', '-v', '--remove-orphans']);
  record(
    'clean-room',
    down === 0,
    down === 0
      ? 'previous drill stack and volumes removed'
      : `docker compose down exited ${String(down)}`,
  );

  // (d) Read AFTER the teardown, deliberately. Probing first would read a stack
  // a previous crashed run left behind — including, in the exact case this
  // differential exists to judge, a port THAT stack was publishing. The verdict
  // would then attribute it to "a host process already held it" and pass. After
  // `down -v` nothing of this project is running, so anything still answering
  // belongs to something else on the machine.
  for (const { port } of FORBIDDEN_PORTS) portsBefore[port] = await probeTcp(port);

  // -------------------------------------------------------------------------
  // 2. Build and start, and let Compose itself decide when the stack is up
  // -------------------------------------------------------------------------
  const up = await composeStreamed([
    'up',
    '-d',
    '--build',
    '--wait',
    '--wait-timeout',
    String(WAIT_TIMEOUT_SECONDS),
  ]);
  record(
    'up',
    up === 0,
    up === 0
      ? 'every service reached its ready condition'
      : `docker compose up --wait exited ${String(up)}`,
  );

  if (up === 0) {
    // -----------------------------------------------------------------------
    // 3. Every service healthy, and the two one-shots completed
    // -----------------------------------------------------------------------
    const ps = compose(['ps', '--all', '--format', 'json']);
    const rows = ps.ok ? parseComposePs(ps.stdout) : [];
    const { verdicts, unhealthy, unexpected } = serviceVerdicts(rows);
    // An empty table would make every check below pass by vacuity.
    const expectedCount = Object.keys(SERVICE_EXPECTATIONS).length;
    if (rows.length < expectedCount) {
      record(
        'services',
        false,
        `docker compose ps reported ${String(rows.length)} container(s), expected at least ${String(expectedCount)}`,
        { rows: rows.length },
      );
    } else {
      record(
        'services',
        unhealthy.length === 0,
        unhealthy.length === 0
          ? `${String(verdicts.length)} services at their expected state`
          : unhealthy.map((verdict) => `${verdict.service}: ${verdict.detail}`).join('; '),
        { verdicts },
      );
    }
    // A service this table does not name is a FAILURE, not a warning, and the
    // difference is the whole value of the check. `docker compose up --wait`
    // waits for `running|healthy`, so a sidecar added without a `healthcheck`
    // satisfies it by merely having started — and every check in this drill
    // iterates SERVICE_EXPECTATIONS, so the new container is examined by nothing:
    // not its state, not its ports, not its network. Warning about it left the
    // drill reporting "13 checks passed" over a stack it had not looked at,
    // which is the same shrinking-surface hole `A11Y_VIEWS` is triple-pinned
    // against. Adding a service is therefore a deliberate act: name it here,
    // with the state it must reach.
    record(
      'service-surface',
      unexpected.length === 0,
      unexpected.length === 0
        ? `no service outside the expected set of ${String(expectedCount)}`
        : `unexamined service(s) in the stack: ${unexpected.join(', ')} — add each to SERVICE_EXPECTATIONS with the state it must reach`,
      { unexpected },
    );

    // -----------------------------------------------------------------------
    // 4. Exactly one published port, bound to loopback
    // -----------------------------------------------------------------------
    const portProblems = singlePortProblems(rows, { port: HTTP_PORT });
    record(
      'single-port',
      portProblems.length === 0,
      portProblems.length === 0
        ? `only 127.0.0.1:${String(HTTP_PORT)} is published`
        : portProblems.join('; '),
      { published: publishedPorts(rows) },
    );

    // The storage engine's own row, named rather than merely covered by the
    // exact-set assertion above.
    //
    // `singlePortProblems` already fails if ANY second port appears, so this adds
    // no coverage today — it adds ATTRIBUTION, and it survives a future edit that
    // relaxes the set assertion (a second published port is exactly the sort of
    // thing a later feature argues for). The bucket holds every stored document's
    // ciphertext and the engine authenticates with a static key pair out of
    // `.env`, so "no `ports:` at all, on the internal network only" is the control
    // that keeps it unreachable, and it is one line of YAML away from being lost.
    const storagePorts = publishedPorts(rows).filter((entry) => entry.service === 'hvault-s3');
    record(
      'storage-no-port',
      storagePorts.length === 0,
      storagePorts.length === 0
        ? 'the object storage engine publishes no host port at all'
        : `hvault-s3 publishes ${String(storagePorts.length)} host port(s): ` +
            storagePorts
              .map((entry) => `${entry.url || '*'}:${String(entry.published)}`)
              .join(', '),
      { storagePorts },
    );

    // -----------------------------------------------------------------------
    // 5. (d) Nothing else is reachable from the host
    // -----------------------------------------------------------------------
    for (const { port, label } of FORBIDDEN_PORTS) {
      const verdict = portExposureVerdict({
        port,
        label,
        before: portsBefore[port],
        after: await probeTcp(port),
      });
      record(`port-${String(port)}`, verdict.ok, `${label}: ${verdict.detail}`, { verdict });
    }

    // -----------------------------------------------------------------------
    // 6. (b) The published port answers, and serves the SPA shell through Express
    // -----------------------------------------------------------------------
    const health = await waitForHealth(baseUrl, { deadlineMs: HEALTH_DEADLINE_MS });
    record(
      'health',
      health.ok,
      health.ok
        ? `database connected after ${String(health.attempts)} probe(s)`
        : `no healthy response within ${String(HEALTH_DEADLINE_MS)}ms — ${health.detail}`,
    );

    if (health.ok) {
      // A DEEP LINK, not `/`. Every HTML document is proxied to Express precisely
      // so helmet can attach the CSP with its per-request nonce, and the handler
      // that injects that nonce into the document is the SPA fallback — `/` is
      // answered by `express.static` from the file on disk. A nonce-less response
      // here means Nginx served a copy of index.html from its own root instead of
      // proxying, which is the header-free version of the app the image build
      // deliberately deletes.
      //
      // INSIDE the health guard: on a stack that never became healthy this
      // `fetch` rejects with ECONNREFUSED into the outer catch, and the drill's
      // headline failure becomes an unattributed `drill: fetch failed` instead of
      // the `health` step that actually explains it.
      const shell = await fetch(new URL('/vault', baseUrl));
      const html = await shell.text();
      const csp = shell.headers.get('content-security-policy') ?? '';
      const shellOk =
        shell.status === 200 && /<script[^>]+nonce="/i.test(html) && /'nonce-/.test(csp);
      record(
        'spa-shell',
        shellOk,
        shellOk
          ? 'a deep-linked route is proxied to Express and served with a matching CSP nonce'
          : `GET /vault returned ${String(shell.status)}; script nonce=${String(/<script[^>]+nonce="/i.test(html))}, CSP nonce=${String(/'nonce-/.test(csp))}`,
      );

      // ---------------------------------------------------------------------
      // 6b. The isolated render document, through the real Nginx
      // ---------------------------------------------------------------------
      // THIS GATE IS THE ONLY PLACE THE `web-root` DELETION IS PROVEN. Every
      // header the document sandbox depends on is invisible everywhere else: the
      // E2E and a11y suites drive the Vite dev server, which has no helmet, no
      // tailored policy and no Nginx at all, and the smoke gate boots Express
      // with no proxy in front of it. Here the real image, the real doc root and
      // the real proxy meet.
      //
      // What could go wrong, and is silent in a browser when it does: the
      // `web-root` stage stops deleting `sandbox.html`, `try_files $uri @app`
      // finds the file on disk, and Nginx answers with the doc root's
      // `default-src 'self'` and NONE of the sandbox's own directives — no
      // `connect-src 'none'`, no `worker-src 'none'`, no `sandbox
      // allow-scripts`. The frame still renders, and the isolation is simply
      // gone. `Cache-Control` is the second half of the same discriminator:
      // Express sends `no-cache`, `location /` sends
      // `public, max-age=0, must-revalidate`.
      const sandbox = await fetch(new URL('/sandbox.html', baseUrl));
      const sandboxHtml = await sandbox.text();
      // Directive by directive, in BOTH directions, against the same expectation
      // the smoke gate reads and `clean-room.test.ts` pins to the server's own
      // exported constant — so this drill cannot drift from the policy it claims
      // to be checking. It also catches TWO policies on one response, which a
      // browser INTERSECTS: helmet's application CSP surviving beside the
      // sandbox's would kill `blob:` media and `data:` images in one stroke.
      const sandboxCspDiff = cspProblems(sandbox.headers.get('content-security-policy'));
      const sandboxCache = sandbox.headers.get('cache-control');
      // Not the SPA shell, either. `/sandbox.html` and `/vault` are both proxied
      // to Express through `@app`, so a route registered wrongly — or removed —
      // would fall through to the SPA fallback and answer 200 with the
      // application's own HTML, nonce and all. The document names its own
      // `sandbox-assets/` entry and carries no nonce, and both halves are
      // asserted because either alone is satisfied by the other document.
      const isSandboxDocument =
        /<script[^>]+src="\/sandbox-assets\//.test(sandboxHtml) &&
        !/<script[^>]+nonce="/i.test(sandboxHtml);
      const sandboxOk =
        sandbox.status === 200 &&
        sandboxCache === SANDBOX_DOCUMENT_CACHE_CONTROL &&
        isSandboxDocument &&
        sandboxCspDiff.length === 0;
      record(
        'sandbox-document',
        sandboxOk,
        sandboxOk
          ? `/sandbox.html comes back through the published port from Express, not off the Nginx disk and not as the SPA shell, with exactly one Content-Security-Policy matching all ${String(Object.keys(SANDBOX_CSP_EXPECTED).length)} directives`
          : `GET /sandbox.html returned ${String(sandbox.status)}; Cache-Control=${String(sandboxCache)}; is the sandbox document=${String(isSandboxDocument)}${sandboxCspDiff.length > 0 ? `; ${sandboxCspDiff.join('; ')}` : ''}`,
        { cspDiff: sandboxCspDiff },
      );

      // The spellings that miss the Express route, asked through the whole
      // stack. Express 5 matches the RAW pathname while `send` decodes and
      // normalises it, so each of these reached `express.static`; the document is
      // now emitted outside every static root, so neither server has it to give.
      //
      // Through Nginx there is a SECOND question, and this is the only gate that
      // can answer it: `try_files $uri @app` matches on the NORMALISED, decoded
      // `$uri`, but `proxy_pass` with no URI part may forward either the raw
      // request line or the rewritten one. The answer is observable rather than
      // assumed — if Express receives the normalised `/sandbox.html` it answers
      // from the ROUTE, document and full policy; if it receives the raw
      // spelling it answers with the SPA shell. Both are correct outcomes; the
      // one that is not is the document under any other policy, which is what
      // `sandboxBypassProblems` judges. What reached Express is RECORDED, since
      // it is a property of the proxy that nothing else here pins.
      const bypassProblems = [];
      const bypassSeen = [];
      for (const spelling of SANDBOX_BYPASS_SPELLINGS) {
        const probe = await fetch(bypassUrl(baseUrl, spelling));
        const body = await probe.text();
        bypassProblems.push(...sandboxBypassProblems(spelling, probe, body));
        // Three outcomes, and each says something different about the proxy
        // hop. The document means Nginx forwarded the NORMALISED `/sandbox.html`
        // and Express answered from the route; the SPA shell means it forwarded
        // the RAW spelling and Express fell through to the catch-all; anything
        // else was refused before either — which is where Nginx's own handling
        // of the traversal spelling shows up, since Express never sees that one
        // as a refusal (`serve-static` falls through and the shell answers).
        const reached = /<script[^>]+src="\/sandbox-assets\//.test(body)
          ? 'normalised (Express saw /sandbox.html and served the document)'
          : /<script[^>]+nonce="/i.test(body)
            ? 'raw (Express saw the spelling and served the SPA shell)'
            : `refused before either (${String(probe.status)})`;
        bypassSeen.push(`${spelling} -> ${String(probe.status)}, ${reached}`);
      }
      record(
        'sandbox-spellings',
        bypassProblems.length === 0,
        bypassProblems.length === 0
          ? `none of the ${String(SANDBOX_BYPASS_SPELLINGS.length)} route-missing spellings hands out the isolated document through the published port — ${bypassSeen.join('; ')}`
          : bypassProblems.join('; '),
        { proxiedUri: bypassSeen },
      );

      // The two headers an opaque origin's fetches need, on the SCRIPT and on the
      // STYLESHEET — and NOT on `/assets/`, which is the half that keeps the
      // widening scoped.
      //
      // The stylesheet is asserted for a reason the client's own build config
      // names: `build.assetsDir` routes chunks and assets through one setting
      // today, so they cannot diverge, but a later switch to explicit
      // `entryFileNames`/`chunkFileNames` that forgot `assetFileNames` would
      // leave the stylesheet in `/assets/` and ship the viewer UNSTYLED in
      // production only, while every script-only assertion still passed.
      //
      // Under this stack both directories are served from the Nginx document root
      // rather than by Express, so the negative half names what THAT block sends:
      // no `Access-Control-Allow-Origin` at all (Nginx adds none for `/assets/`)
      // and no CORP. On the smoke gate the same negative names Express's own two
      // values instead, which is why `appAssetProblems` takes them as arguments.
      const { script: sandboxAsset, stylesheet: sandboxStyle } = sandboxAssetUrls(sandboxHtml);
      const appAsset = /<script[^>]+src="(\/assets\/[^"]+)"/.exec(html)?.[1];
      if (!sandboxAsset || !sandboxStyle || !appAsset) {
        record(
          'sandbox-assets',
          false,
          `could not locate an asset to probe (sandbox script=${String(sandboxAsset)}, ` +
            `sandbox stylesheet=${String(sandboxStyle)}, app script=${String(appAsset)})`,
        );
      } else {
        const [scriptRes, styleRes, appRes] = await Promise.all([
          fetch(new URL(sandboxAsset, baseUrl)),
          fetch(new URL(sandboxStyle, baseUrl)),
          fetch(new URL(appAsset, baseUrl)),
        ]);
        const assetProblems = [
          // WHAT ANSWERED, before what it carried, and through the SAME helper the
          // smoke gate uses so the two cannot decide it differently. The negative
          // half of this check is the half that can pass on nothing, and it can do
          // so in two shapes: `location /assets/` serves from disk, so a missing
          // file is a real 404 — which carries no ACAO and no CORP either, i.e. a
          // clean pass — and its own `try_files $uri @app` means the same request
          // can instead reach Express and come back as the SPA shell, 200, with
          // the application's own two headers. Status and content type together
          // are what tell either from the asset. Nothing else in the drill fetches
          // the app bundle — `spa-shell` reads only the document and its nonce —
          // so this is the only place that notices. Asserted on all three.
          ...assetResponseProblems(sandboxAsset, scriptRes),
          ...assetResponseProblems(sandboxStyle, styleRes),
          ...assetResponseProblems(appAsset, appRes),
          ...sandboxAssetProblems(sandboxAsset, (name) => scriptRes.headers.get(name)),
          ...sandboxAssetProblems(sandboxStyle, (name) => styleRes.headers.get(name)),
          ...appAssetProblems(appAsset, (name) => appRes.headers.get(name), {
            acao: null,
            corp: null,
          }),
        ];
        record(
          'sandbox-assets',
          assetProblems.length === 0,
          assetProblems.length === 0
            ? `sandbox-assets/ carries the ${String(Object.keys(SANDBOX_ASSET_HEADERS_EXPECTED).length)} headers an opaque origin needs on its script AND its stylesheet; /assets/ carries neither`
            : assetProblems.join('; '),
        );
      }

      // ---------------------------------------------------------------------
      // 7. One real user journey, entirely through the published port
      // ---------------------------------------------------------------------
      const flow = await runVaultFlow({
        baseUrl,
        log: (message) => {
          note(message);
        },
        verifyEmail: async (email) => {
          const result = mongosh(
            "db.getSiblingDB('admin').auth(process.env.R_U, process.env.R_P);" +
              "const r = db.getSiblingDB('hvault').users.updateOne({ email: process.env.MAIL }, { $set: { emailVerified: true } });" +
              "print('matched=' + r.matchedCount + ' modified=' + r.modifiedCount);",
            {
              R_U: drillEnv.MONGO_ROOT_USERNAME,
              R_P: drillEnv.MONGO_ROOT_PASSWORD,
              MAIL: email,
            },
          );
          if (!result.ok || !/matched=1 modified=1/.test(result.stdout)) {
            throw new Error(
              `could not verify the drill account in the database: ${result.stdout}${result.stderr}`.slice(
                0,
                400,
              ),
            );
          }
          await Promise.resolve();
        },
      });
      record('vault-flow', true, `registered, signed in and round-tripped item ${flow.itemId}`, {
        steps: flow.steps,
      });

      // ---------------------------------------------------------------------
      // 7b. One document, all the way through the same port
      // ---------------------------------------------------------------------
      // The deployment's promise is that `cp .env.example .env`, fill in the
      // secrets, `docker compose up` — and the document store is ON, with no
      // bucket created by hand and no storage step in the setup. The public
      // config route is where a browser learns that, so it is read first and
      // asserted rather than assumed; it also checks the framing the deployment
      // ADVERTISES against the framing this flow seals to, so neither side is
      // trusted.
      const documentsConfig = await recordFlow(
        'documents-enabled',
        (config) =>
          `the deployment advertises the document store: ${String(config.maxSizeMB)} MB per file, ` +
          `${String(config.maxDocuments)} files, ${String(config.quotaMB)} MB quota, ` +
          `${String(config.chunkPlaintextBytes)}-byte plaintext chunks`,
        () => readDocumentsConfig({ baseUrl }),
      );

      // The journey: one sealed segment up, the same bytes back, and the quota
      // the deployment reports about them. Nothing here is a document the SERVER
      // could read — it stores ciphertext, a wrapped key and sizes — so what is
      // being proved is the deployment's own job: that a 12 KiB octet-stream
      // body survives Nginx (`proxy_request_buffering off`, `client_max_body_size
      // 32m`, `gzip off` on `/api/`) in both directions, unchanged, and that the
      // engine on the internal network really did store it.
      const documentFlow =
        documentsConfig === null
          ? null
          : await recordFlow(
              'document-journey',
              (result) =>
                `uploaded, downloaded byte-identically and accounted for document ${result.documentId}`,
              () =>
                runDocumentFlow({
                  client: flow.client,
                  // Read out of the deployment's own advertisement rather than
                  // restated: `constants.test.ts` fails on a second copy of
                  // either chunk size anywhere but its definition, and the init
                  // response is then checked against THIS number, so the two
                  // server surfaces that publish the framing are compared with
                  // each other.
                  chunkPlaintextBytes: documentsConfig.chunkPlaintextBytes,
                  log: (message) => {
                    note(message);
                  },
                }),
            );

      // ---------------------------------------------------------------------
      // 8. (e) Restart the whole stack; the vault must survive it
      // ---------------------------------------------------------------------
      const restarted = await composeStreamed(['restart']);
      const afterRestart = await waitForHealth(baseUrl, { deadlineMs: RESTART_DEADLINE_MS });
      record(
        'restart',
        restarted === 0 && afterRestart.ok,
        restarted === 0 && afterRestart.ok
          ? `stack healthy again after ${String(afterRestart.attempts)} probe(s)`
          : `restart exited ${String(restarted)}; healthy=${String(afterRestart.ok)}`,
      );

      if (afterRestart.ok) {
        // A FRESH sign-in, with the credential the flow registered with: the
        // account, its bcrypt hash and the item's ciphertext all have to have
        // outlived the containers for this to return.
        await recordFlow(
          'data-survives-restart',
          () => 'the item and its ciphertext outlived the restart',
          () =>
            reReadVault({
              baseUrl,
              email: flow.email,
              authHash: flow.authHash,
              itemId: flow.itemId,
              expected: flow.item,
            }),
        );

        // The document is a THREE-part claim where the vault item is a
        // one-part one, which is why it gets its own step rather than an extra
        // assertion inside that one: the row must have outlived the database
        // container, the object must have outlived the STORAGE container and its
        // volume, and the bytes must still be identical. A restart also re-runs
        // the engine's own boot provisioning with the same credentials, so this
        // is the first place the "second boot is a clean no-op" behaviour is
        // observed at all — the explicit redeploy below then asks it of a
        // FRESH container.
        if (documentFlow !== null) {
          await recordFlow(
            'document-survives-restart',
            (result) =>
              `document ${result.documentId} still downloads ${String(result.bytes)} identical bytes after the restart`,
            () =>
              reReadDocument({
                baseUrl,
                email: flow.email,
                authHash: flow.authHash,
                documentId: documentFlow.documentId,
                expected: documentFlow.fixture.segment,
                expectedKey: documentFlow.fixture.init,
                what: '(after restart)',
              }),
          );
        }
      }

      // ---------------------------------------------------------------------
      // 9. The index bootstrap is idempotent
      // ---------------------------------------------------------------------
      const bootstrap = await rerunOneShot('hvault-bootstrap');
      record(
        'bootstrap-idempotent',
        bootstrap.exitCode === 0,
        bootstrap.exitCode === 0
          ? 're-running the index bootstrap against an initialised database exits 0'
          : `the bootstrap exited ${String(bootstrap.exitCode)} on its second run`,
        { logs: bootstrap.logs.slice(-2000) },
      );

      // ---------------------------------------------------------------------
      // 10. (h) A redeploy of the storage engine does not rewrite its key
      // ---------------------------------------------------------------------
      // The engine provisions itself on EVERY boot from `GARAGE_DEFAULT_*`, and
      // a boot that rewrote the key from the same `.env` values would be
      // invisible — the values match, so the app would keep working. What makes
      // the claim testable is the one case where a rewrite and a no-op differ,
      // and that is the case below (11). This step is the positive control for
      // it: a FRESH container, the same credentials, and the pre-existing bucket
      // still readable through the app that never restarted.
      const storageRedeployed = await recreateAndWait(['hvault-s3']);
      record(
        'storage-redeploy',
        storageRedeployed === 0,
        storageRedeployed === 0
          ? 'a fresh storage container with the same credentials reaches its healthcheck'
          : `up --wait for hvault-s3 exited ${String(storageRedeployed)}`,
      );
      if (storageRedeployed === 0 && documentFlow !== null) {
        await recordFlow(
          'storage-key-not-rewritten',
          (result) =>
            `the same credentials still read the pre-existing bucket: ${String(result.bytes)} identical bytes`,
          () =>
            reReadDocument({
              baseUrl,
              email: flow.email,
              authHash: flow.authHash,
              documentId: documentFlow.documentId,
              expected: documentFlow.fixture.segment,
              expectedKey: documentFlow.fixture.init,
              what: '(after storage redeploy)',
            }),
        );
      }

      // ---------------------------------------------------------------------
      // 11. (h) The credential-rotation trap, measured rather than assumed
      // ---------------------------------------------------------------------
      // MEASURED, and it is the reason `.env` names a rotation procedure at all:
      // the same access key id with a DIFFERENT secret makes the engine exit 1
      // (`Access key <id> is associated with a secret key different than the one
      // given in GARAGE_DEFAULT_SECRET_KEY`) rather than rewriting the stored
      // key — which is NOT the database provisioner's boot-anyway behaviour, so
      // an operator who rotates one value the way they would rotate the other
      // gets a crash loop. The supported rotation is to change the id AND the
      // secret together, after which the new key reads and writes the existing
      // bucket.
      //
      // The refusal is asserted as an EXIT CODE plus the engine's own message;
      // `waitForContainerExit` records why the exit code is read by a bounded
      // poll rather than by `docker wait`.
      rewriteEnv({ S3_SECRET_ACCESS_KEY: secret() });
      writeFileSync(probeOverrideFile, renderNoRestartOverride('hvault-s3'), 'utf8');
      const probeStarted = await composeStreamed(
        ['up', '-d', '--no-deps', '--force-recreate', 'hvault-s3'],
        [probeOverrideFile],
      );
      if (probeStarted !== 0) {
        record(
          'storage-secret-rotation-refused',
          false,
          `could not start the storage container for the credential probe: up exited ${String(probeStarted)}`,
        );
      } else {
        const storageContainer = `${STACK_NAME}-s3`;
        const stopped = await waitForContainerExit(storageContainer, CONTAINER_EXIT_DEADLINE_MS);
        const probeLogs = captureExe('docker', ['logs', storageContainer]);
        const output = `${probeLogs.stdout}${probeLogs.stderr}`;
        const namesTheRefusal = /associated with a secret key different/i.test(output);
        // BOTH halves, because either alone is weak: an exit 1 could come from a
        // bad config file or an unwritable volume, and a log line only says what
        // the process printed on its way to whatever it did next. A container
        // still RUNNING at the deadline is the failure this exists to catch —
        // the trap stopped firing — and it is reported as that rather than as an
        // exit code nobody observed.
        const refusedOk = stopped.exitCode === 1 && namesTheRefusal;
        record(
          'storage-secret-rotation-refused',
          refusedOk,
          refusedOk
            ? 'changing the secret alone makes the storage engine exit 1 naming the mismatched key, rather than rewriting it'
            : `the storage engine is ${stopped.status} with exit code ${String(stopped.exitCode)} and ` +
                `${namesTheRefusal ? 'named' : 'did NOT name'} the key mismatch`,
          { stopped, output: output.slice(-1500) },
        );
      }

      // And the supported rotation: BOTH values, together. The app is recreated
      // with them too, because it reads its credentials at boot from the same
      // `.env` — a rotation that moved the engine's key and left the app holding
      // the old one is a state no operator can reach, and asserting the download
      // against it would prove the opposite of what this claims. The document was
      // written under the SUPERSEDED key, so the read below is the whole point:
      // the newly minted key can still read the pre-existing bucket.
      rewriteEnv({
        S3_ACCESS_KEY_ID: `${drillEnv.S3_ACCESS_KEY_ID}2`,
        S3_SECRET_ACCESS_KEY: secret(),
      });
      const rotatedPair = await recreateAndWait(['hvault-s3', 'hvault-app']);
      record(
        'storage-credential-rotation',
        rotatedPair === 0,
        rotatedPair === 0
          ? 'changing the access key id and the secret together boots the storage engine and the app'
          : `up --wait after rotating both credentials exited ${String(rotatedPair)}`,
      );
      if (rotatedPair === 0 && documentFlow !== null) {
        await recordFlow(
          'rotated-credentials-read-the-bucket',
          (result) =>
            `the newly minted key reads the pre-existing bucket: ${String(result.bytes)} identical bytes`,
          () =>
            reReadDocument({
              baseUrl,
              email: flow.email,
              authHash: flow.authHash,
              documentId: documentFlow.documentId,
              expected: documentFlow.fixture.segment,
              expectedKey: documentFlow.fixture.init,
              what: '(after credential rotation)',
            }),
        );

        // -------------------------------------------------------------------
        // 12. The document goes away, object and all
        // -------------------------------------------------------------------
        // LAST, because everything above needed the document to still be there.
        // Trash then purge, because they are two different operations with two
        // different consequences, and the negative is asserted on both sides:
        // the row 404s, the trash is empty, and the quota is back to zero.
        //
        // Be exact about which claim rests on which fact, because the difference
        // decides what a green run means. The quota is a Mongo aggregation over
        // the rows, so a zero there proves the ROW is gone and says nothing about
        // the bucket. What carries the object is the 200 on the purge itself:
        // `purgeDocument` deliberately does not catch a storage failure, so an
        // engine that refused or silently dropped the delete surfaces as a 5xx
        // that `expectEnvelope` rejects. The drill cannot go and look in the
        // bucket, by design — the engine publishes no port to look through.
        await recordFlow(
          'document-purge',
          (result) =>
            `document ${result.documentId} was trashed, purged and is gone from the quota`,
          () =>
            purgeDocumentFlow({
              baseUrl,
              email: flow.email,
              authHash: flow.authHash,
              documentId: documentFlow.documentId,
            }),
        );
      }

      // ---------------------------------------------------------------------
      // 13. (f) A rotated application password survives a redeploy
      // ---------------------------------------------------------------------
      // LAST, AND THAT ORDER IS LOAD-BEARING — measured, on the run that added
      // the storage steps above. This step rotates the app's database password
      // INSIDE the database and deliberately does NOT touch the deployment's
      // configuration, because the assertion is that the value in `.env` stops
      // authenticating while the rotated one keeps working. The consequence is
      // that from here on the stack's own `.env` holds a SUPERSEDED database
      // credential: the running app is unaffected (it read its URI at boot and
      // holds an open connection), but any container RECREATED afterwards comes
      // up with the stale password and cannot authenticate at all. That is
      // exactly what the storage-credential rotation above does to `hvault-app`,
      // and running it after this step failed its healthcheck with
      // `SCRAM authentication failed, storedKey mismatch` — a failure in the
      // DRILL's ordering that reads like a broken deployment. So every step that
      // recreates a container belongs above this one, and nothing may be
      // appended below it.
      const rotated = secret();
      const rotation = mongosh(
        "db.getSiblingDB('admin').auth(process.env.R_U, process.env.R_P);" +
          "db.getSiblingDB('hvault').changeUserPassword(process.env.A_U, process.env.NEW_P);" +
          "print('rotated');",
        {
          R_U: drillEnv.MONGO_ROOT_USERNAME,
          R_P: drillEnv.MONGO_ROOT_PASSWORD,
          A_U: drillEnv.MONGO_APP_USERNAME,
          NEW_P: rotated,
        },
      );
      if (!rotation.ok || !/rotated/.test(rotation.stdout)) {
        record(
          'password-rotation',
          false,
          `could not rotate the application password: ${rotation.stderr.slice(0, 300)}`,
        );
      } else {
        const provision = await rerunOneShot('hvault-db-init');
        const log = parseProvisionLog(provision.logs);
        // Two SEPARATE mongosh processes, deliberately. `db.auth()` mutates the
        // shell's own authentication state and throws on refusal, so trying both
        // credentials in one session makes the second result depend on how the
        // first one left the connection — a coupling that would quietly turn
        // this into a test of mongosh's session handling.
        const authProbe = (password) =>
          mongosh(
            "try { db.getSiblingDB('hvault').auth(process.env.A_U, process.env.A_P); print('AUTH_OK') }" +
              " catch (e) { print('AUTH_FAILED') }",
            { A_U: drillEnv.MONGO_APP_USERNAME, A_P: password },
          );
        const withRotated = authProbe(rotated);
        const withConfigured = authProbe(APP_PASSWORD);
        const behaviourOk =
          provision.exitCode === 0 &&
          /AUTH_OK/.test(withRotated.stdout) &&
          /AUTH_FAILED/.test(withConfigured.stdout);
        record(
          'password-rotation',
          behaviourOk,
          behaviourOk
            ? 'the provisioner reconciled roles and left the rotated password in place'
            : `db-init exited ${String(provision.exitCode)}; rotated=${withRotated.stdout.trim()} configured=${withConfigured.stdout.trim()}`,
          { provisionLog: log, provisionOutput: provision.logs.slice(-1000) },
        );
      }
    }
  }
} catch (error) {
  record('drill', false, error instanceof Error ? error.message : String(error), {
    context: error?.context ?? {},
  });
} finally {
  // (g) Evidence first, teardown second.
  if (failures.length > 0) {
    const logs = compose(['logs', '--no-color', '--tail', '120']);
    console.error(color.gray(logs.stdout.slice(-20000)));
  }
  await teardown();
}

const payload = {
  version: 1,
  task: 'test:deploy',
  checkedAt: new Date().toISOString(),
  durationMs: Date.now() - started,
  stack: { name: STACK_NAME, port: HTTP_PORT, edgeSubnet: EDGE_SUBNET, dataSubnet: DATA_SUBNET },
  portsBefore,
  failures,
  steps,
};
writeJsonReport('deploy.json', payload);

if (failures.length > 0) {
  console.error(
    color.red(`\n${symbol.fail} deployment clean room: ${String(failures.length)} failed check(s)`),
  );
  for (const failure of failures) console.error(color.red(`      ${failure}`));
  process.exit(1);
}

console.log(
  color.green(
    `\n${symbol.pass} deployment clean room: ${String(steps.length)} checks passed — stack healthy, one published port, the isolated render document served through it with its own policy, a vault item and a document round-tripped byte for byte, both survived a restart, redeploy idempotent, and the storage credential rotation behaves as measured`,
  ),
);
