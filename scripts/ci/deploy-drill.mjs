#!/usr/bin/env node
/**
 * `test:deploy` — the deployment clean room.
 *
 * `audit:image` proves the images BUILD; the E2E suite proves the application
 * WORKS against a development server. Nothing between them ever ran the thing
 * this project actually ships: five containers, one published port, a
 * least-privilege database user, two one-shots the app gates on, and a config
 * surface that only exists in production. This gate stands that stack up from
 * nothing and drives a real user journey through the single port it publishes.
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
import { reReadVault, runVaultFlow, waitForHealth } from './lib/vault-flow.mjs';

/** (a) Everything about the drill's stack is namespaced away from a real one. */
const STACK_NAME = 'hvault-drill';
const HTTP_PORT = 18080;
const EDGE_SUBNET = '172.31.244.0/24';
const DATA_SUBNET = '172.31.245.0/24';
/** The ports the stack must NOT publish: MongoDB, and the app's internal listener. */
const FORBIDDEN_PORTS = [
  { port: 27017, label: 'MongoDB' },
  { port: 5000, label: "the app's internal listener" },
];
/** Bounds `up --wait`'s wait phase (not the build) so a stuck healthcheck is an error, not a hang. */
const WAIT_TIMEOUT_SECONDS = 300;
const HEALTH_DEADLINE_MS = 120_000;
const RESTART_DEADLINE_MS = 120_000;
/** A TCP probe answers or refuses in microseconds on loopback; a second is generous. */
const PROBE_TIMEOUT_MS = 1_000;

const argv = process.argv.slice(2);
const keepStack = argv.includes('--keep');

const secret = () => randomBytes(32).toString('hex');
const baseUrl = `http://127.0.0.1:${String(HTTP_PORT)}`;

const workspace = mkdtempSync(path.join(tmpdir(), 'hvault-drill-'));
const envFile = path.join(workspace, 'drill.env');
const overrideFile = path.join(workspace, 'drill-override.yml');

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
};

writeFileSync(envFile, renderEnvFile(drillEnv), 'utf8');
writeFileSync(overrideFile, renderOverride(envFile), 'utf8');

/** Compose, always with the drill's project, override and env file. */
const composeArgs = (...rest) => [
  'compose',
  '--env-file',
  envFile,
  '-f',
  'docker-compose.yml',
  '-f',
  overrideFile,
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
  captureExe('docker', composeArgs(...rest), { env: composeEnv, ...options });
const composeStreamed = (rest) => runExe('docker', composeArgs(...rest), { env: composeEnv });

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

async function teardown() {
  if (keepStack) {
    warn(`--keep: the stack is still up on ${baseUrl} (project ${STACK_NAME})`);
    warn(`its configuration is at ${envFile} — delete it when you are done`);
    return;
  }
  await composeStreamed(['down', '-v', '--remove-orphans']);
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
    for (const service of unexpected) {
      warn(`the stack contains an unexamined service: ${service}`);
    }

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

    // A DEEP LINK, not `/`. Every HTML document is proxied to Express precisely
    // so helmet can attach the CSP with its per-request nonce, and the handler
    // that injects that nonce into the document is the SPA fallback — `/` is
    // answered by `express.static` from the file on disk. A nonce-less response
    // here means Nginx served a copy of index.html from its own root instead of
    // proxying, which is the header-free version of the app the image build
    // deliberately deletes.
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

    if (health.ok) {
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
        const survived = await reReadVault({
          baseUrl,
          email: flow.email,
          authHash: flow.authHash,
          itemId: flow.itemId,
          expected: flow.item,
        }).catch((error) => error);
        if (survived instanceof Error) {
          record('data-survives-restart', false, survived.message, {
            context: survived.context ?? {},
          });
        } else {
          record('data-survives-restart', true, 'the item and its ciphertext outlived the restart');
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
      // 10. (f) A rotated application password survives a redeploy
      // ---------------------------------------------------------------------
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
    `\n${symbol.pass} deployment clean room: ${String(steps.length)} checks passed — stack healthy, one published port, journey through it, data survived a restart, redeploy idempotent`,
  ),
);
