#!/usr/bin/env node
/**
 * `test:smoke` — boot the BUILT artifact in production mode and complete one
 * real user journey against it.
 *
 * This is the deployment drill's fast sibling, and it exists because of a gap
 * between the two gates on either side of it. `build` proves the TypeScript
 * compiles. `test:e2e` drives the application through the Vite dev server and
 * `tsx`, i.e. through the sources. `audit:image` builds the container images and
 * scans them without ever starting one. So until this gate, nothing anywhere ran
 * the JavaScript that actually ships, and a defect in the emitted tree — a
 * missing file, an import that only resolves through the TypeScript path map, a
 * production-only branch of the configuration schema — reached the container
 * drill or the operator before anything noticed.
 *
 *   node scripts/ci/smoke-gate.mjs        the gate (this is what the pipeline runs)
 *   npm run test:smoke                    the same thing
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE ARTIFACT IS STAGED IN A TEMPORARY DIRECTORY, NOT IN THE CHECKOUT. In
 *     production the server resolves its static root as `<dist>/../public`, so
 *     a naive version of this gate would copy the client bundle into
 *     `packages/server/public` — an untracked, un-ignored tree that the secret
 *     scan, the integrity scan and the format check would all then walk, and
 *     that a crashed run would leave behind. Staging `dist/` and `public/` as
 *     siblings under a temp directory reproduces the image's layout exactly and
 *     writes nothing into the repository. `node_modules` is SYMLINKED there
 *     (600 MB, and nothing writes to it), which also proves the emitted tree
 *     resolves its dependencies by ordinary Node resolution rather than by
 *     accident of location.
 *
 *  b. IT RUNS IN PRODUCTION MODE, WITH REAL SECRETS. That is most of the value:
 *     `NODE_ENV=production` is where the config schema refuses `dev-` secrets
 *     and a non-https CORS origin, where the rate limiters stop being no-ops and
 *     start needing their MongoDB store, where 5xx bodies are redacted, and
 *     where the SPA shell is served by Express with a per-request CSP nonce.
 *     None of that is exercised anywhere else in the pipeline.
 *
 *  c. THE DATABASE IS A REAL mongod. `mongodb-memory-server` spawns the actual
 *     binary, so this is not a stubbed datastore — and the rseq tunable below is
 *     required for it to start at all on this kernel line.
 *
 *  d. THE BOOT DEADLINE IS A FAILURE, NEVER A SKIP. A server that never listens
 *     produces no exit code, so a gate waiting on it would hang rather than
 *     fail; the deadline is what turns "it hung" into a verdict. The total
 *     runtime is reported but is NOT a gate: a budget that fails on a loaded
 *     machine is a flake, and a flake is how a gate gets deleted.
 *
 *  e. THE JOURNEY IS THE ONE `test:deploy` RUNS, imported rather than copied
 *     (`lib/vault-flow.mjs`). Two copies of "the flow" would drift, and the
 *     difference between them is exactly where the interesting failure hides.
 */
import { cpSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { repoRoot } from './lib/proc.mjs';
import { color, formatDuration, note, symbol, warn } from './lib/ui.mjs';
import { ensureReportDir, writeJsonReport } from './lib/reports.mjs';
import { runVaultFlow, waitForHealth } from './lib/vault-flow.mjs';

/**
 * The policy `/sandbox.html` must carry, restated here ON PURPOSE.
 *
 * `packages/server/src/config/sandboxCsp.ts` is the single home of this policy
 * and a server unit test pins that CONSTANT directive by directive. This is the
 * second, INDEPENDENT pin, over the header the built artifact actually sends —
 * because a constant test alone passes happily while the route sends something
 * else (or while `express.static` answers the URL first with helmet's
 * application policy), and a served-header test alone would leave the constant
 * free to drift. A gate script cannot import a TypeScript module, so the
 * restatement is structural rather than a choice; the two copies disagreeing is
 * exactly the failure worth having.
 *
 * Compared DIRECTIVE BY DIRECTIVE, never by substring. `connect-src 'none'` and
 * `worker-src 'none'` are the containment — the sandbox opens no socket of any
 * kind — and each is one appended word away from being widened, which a
 * `.includes("connect-src 'none'")` check stays green through.
 */
const SANDBOX_CSP_EXPECTED = {
  'default-src': "'none'",
  'script-src': "'self'",
  'style-src': "'self'",
  'img-src': "'self' blob: data:",
  'font-src': "'self' data:",
  'media-src': 'blob:',
  'connect-src': "'none'",
  'worker-src': "'none'",
  'frame-src': "'none'",
  'child-src': "'none'",
  'object-src': "'none'",
  'base-uri': "'none'",
  'form-action': "'none'",
  'frame-ancestors': "'self'",
  sandbox: 'allow-scripts',
};

/** `"a 'b'; c 'd'"` -> `{ a: "'b'", c: "'d'" }`, whitespace normalised. */
function parseCsp(header) {
  const directives = {};
  for (const part of header.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    const [name, ...sources] = tokens;
    if (name) directives[name.toLowerCase()] = sources.join(' ');
  }
  return directives;
}

/** (d) A production boot on a cold machine is seconds; 45 of them is a hang. */
const BOOT_DEADLINE_MS = 45_000;
/** What the gate is meant to cost, reported rather than enforced — see (d). */
const BUDGET_MS = 60_000;
const SHUTDOWN_GRACE_MS = 5_000;

/**
 * SERVER-121912 — mongod 8.x aborts at startup on Linux kernels >= 6.19 unless
 * restartable sequences are handed back to glibc.
 *
 * `mongodb-memory-server` downloads and spawns a REAL mongod, so this runner is
 * one of the launch sites that has to set it. The merge (rather than an
 * assignment) preserves any tunable an operator has already set, and an explicit
 * `glibc.pthread.rseq=` choice is left alone — including `=0`, which is the
 * value that crashes and which nobody sets by accident. The full explanation,
 * and the shared implementation the two TypeScript harnesses use, is
 * `packages/server/tests/mongoKernelCompat.ts`; it cannot be imported here
 * because this is plain JavaScript with no build step in front of it.
 */
function applyRseqTunable(env = process.env) {
  const current = env['GLIBC_TUNABLES']?.trim();
  const tunable = 'glibc.pthread.rseq=1';
  if (!current) env['GLIBC_TUNABLES'] = tunable;
  else if (!/(?:^|:)glibc\.pthread\.rseq=/.test(current)) {
    env['GLIBC_TUNABLES'] = `${current}:${tunable}`;
  }
}

const secret = () => randomBytes(32).toString('hex');
const started = Date.now();
const steps = [];
const failures = [];

const record = (name, ok, detail, extra = {}) => {
  steps.push({ name, ok, detail, ...extra });
  if (ok) console.log(color.green(`  ${symbol.pass} ${name} — ${detail}`));
  else {
    failures.push(`${name}: ${detail}`);
    console.error(color.red(`  ${symbol.fail} ${name} — ${detail}`));
  }
  return ok;
};

/** An OS-assigned free port, released immediately; the server binds it a moment later. */
function freePort() {
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

ensureReportDir();
console.log(color.bold('\n  smoke — the built artifact, in production mode\n'));

const serverDist = path.join(repoRoot, 'packages', 'server', 'dist');
const clientDist = path.join(repoRoot, 'packages', 'client', 'dist');
for (const [label, dir, file] of [
  ['server', serverDist, 'server.js'],
  ['client', clientDist, 'index.html'],
]) {
  if (!existsSync(path.join(dir, file))) {
    record(
      'artifact',
      false,
      `no built ${label} artifact at ${path.relative(repoRoot, path.join(dir, file))} — run npm run build`,
    );
    writeJsonReport('smoke.json', { version: 1, task: 'test:smoke', failures, steps });
    process.exit(1);
  }
}

// (a) The image's layout, in a directory nothing else can see.
const workspace = mkdtempSync(path.join(tmpdir(), 'hvault-smoke-'));
const artifact = path.join(workspace, 'artifact');
mkdirSync(artifact, { recursive: true });
cpSync(serverDist, path.join(artifact, 'dist'), { recursive: true });
cpSync(clientDist, path.join(artifact, 'public'), { recursive: true });
symlinkSync(path.join(repoRoot, 'node_modules'), path.join(workspace, 'node_modules'), 'dir');
record('stage', true, 'dist + public staged beside a linked dependency tree');

let mongo;
let child;

const stop = async () => {
  if (child && child.exitCode === null) {
    child.kill('SIGTERM');
    await new Promise((resolve) => {
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        resolve(undefined);
      }, SHUTDOWN_GRACE_MS);
      timer.unref?.();
      child.once('exit', () => {
        clearTimeout(timer);
        resolve(undefined);
      });
    });
  }
  // A teardown failure must not destroy the run's evidence. `mongo.stop()`
  // rejecting here escaped before `writeJsonReport`, so the runner reported the
  // gate as failed AND as having written no report — losing the transcript of
  // whatever it had just proved. The failure is recorded instead, which is both
  // visible and survivable.
  if (mongo) {
    try {
      await mongo.stop();
    } catch (error) {
      record('teardown', false, `mongod did not stop cleanly: ${String(error)}`);
    }
  }
  rmSync(workspace, { recursive: true, force: true });
};

try {
  // -------------------------------------------------------------------------
  // 1. A real mongod (c)
  // -------------------------------------------------------------------------
  applyRseqTunable();
  const { MongoMemoryServer } = await import('mongodb-memory-server');
  mongo = await MongoMemoryServer.create({ instance: { dbName: 'hvault' } });
  const mongoUri = mongo.getUri('hvault');
  record('mongod', true, 'a real mongod is listening for the artifact');

  // -------------------------------------------------------------------------
  // 2. Boot the artifact exactly as the image's CMD does (b)
  // -------------------------------------------------------------------------
  const port = await freePort();
  const baseUrl = `http://127.0.0.1:${String(port)}`;
  const bootLog = [];
  child = spawn(process.execPath, [path.join(artifact, 'dist', 'server.js')], {
    // cwd is the temp workspace, not the checkout: the logger eagerly creates
    // `<cwd>/logs` at module scope and throws if it cannot, and a gate has no
    // business writing into the repository to prove the artifact boots.
    cwd: workspace,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NODE_ENV: 'production',
      PORT: String(port),
      HOST: '127.0.0.1',
      MONGODB_URI: mongoUri,
      JWT_ACCESS_SECRET: secret(),
      JWT_REFRESH_SECRET: secret(),
      SESSION_SECRET: secret(),
      // Production refuses a non-https CORS origin and any `dev-` secret, which
      // is half of what this gate proves about the artifact.
      APP_URL: 'https://smoke.hvault.test',
      CORS_ORIGIN: 'https://smoke.hvault.test',
      APP_NAME: 'H-Vault',
      SMTP_HOST: '',
      SMTP_USER: '',
      SMTP_PASS: '',
    },
  });
  for (const source of [child.stdout, child.stderr]) {
    source?.on('data', (chunk) => {
      bootLog.push(chunk.toString('utf8'));
    });
  }
  child.once('exit', (code, signal) => {
    if (code !== 0 && code !== null) bootLog.push(`\n[artifact exited with code ${String(code)}]`);
    else if (signal) bootLog.push(`\n[artifact terminated by ${signal}]`);
  });

  // A dead process cannot become healthy, so stop waiting for it. The single
  // most likely thing this gate catches — the production config validation
  // refusing to boot — exits in about a second, and polling the full deadline
  // afterwards spent 45 s proving nothing. `waitForHealth` still owns the
  // timeout for a process that is merely slow.
  const health = await Promise.race([
    waitForHealth(baseUrl, { deadlineMs: BOOT_DEADLINE_MS, intervalMs: 500 }),
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
  const booted = record(
    'boot',
    health.ok,
    health.ok
      ? `listening and connected after ${formatDuration(health.waitedMs)} (${String(health.attempts)} probes)`
      : `no healthy response within ${String(BOOT_DEADLINE_MS)}ms — ${health.detail}`,
    health.ok ? {} : { output: bootLog.join('').slice(-4000) },
  );
  if (!booted) console.error(color.gray(bootLog.join('').slice(-4000)));

  if (booted) {
    // -----------------------------------------------------------------------
    // 3. The SPA shell, with the nonce production attaches to it (b)
    // -----------------------------------------------------------------------
    // A DEEP LINK, not `/`. `express.static` is mounted first and answers `/`
    // with the file on disk; the handler that injects the per-request nonce is
    // the SPA fallback below it, which is what a deep-linked route reaches. Both
    // documents are served by Express and both carry helmet's CSP header, so
    // asking `/` would have quietly tested the static file server instead of the
    // production HTML path — measured, and the reason this line names /vault.
    const shell = await fetch(new URL('/vault', baseUrl));
    const html = await shell.text();
    const csp = shell.headers.get('content-security-policy') ?? '';
    const shellOk =
      shell.status === 200 && /<script[^>]+nonce="/i.test(html) && /'nonce-/.test(csp);
    record(
      'spa-shell',
      shellOk,
      shellOk
        ? 'a deep-linked route is served from the artifact with a matching CSP nonce'
        : `GET /vault returned ${String(shell.status)}; script nonce=${String(/<script[^>]+nonce="/i.test(html))}, CSP nonce=${String(/'nonce-/.test(csp))}`,
    );

    // -----------------------------------------------------------------------
    // 4. The document sandbox, which is production-only in every part
    // -----------------------------------------------------------------------
    // The route, its policy and the two headers `sandbox-assets/` needs all
    // live inside `if (NODE_ENV === 'production')` or in a built asset
    // directory, so this gate is the only push-tier place any of them can be
    // observed. Every failure mode here is SILENT in a browser — a blank
    // rectangle, no console error worth reporting — which is why they are
    // asserted over the wire rather than trusted to review.
    const sandbox = await fetch(new URL('/sandbox.html', baseUrl));
    const sandboxHtml = await sandbox.text();
    const sandboxCspRaw = sandbox.headers.get('content-security-policy') ?? '';
    // `Headers.get` joins repeated headers with ", ". A CSP source list never
    // contains a comma, so its presence means TWO policies reached the client —
    // and two policies on one response are INTERSECTED by the browser, which
    // would kill `blob:` media and `data:` images in one stroke. This is also
    // what would catch helmet's application policy surviving beside the
    // sandbox's own.
    const singleCspHeader = sandboxCspRaw !== '' && !sandboxCspRaw.includes(',');
    const served = parseCsp(sandboxCspRaw);
    const cspDiff = [];
    for (const [directive, sources] of Object.entries(SANDBOX_CSP_EXPECTED)) {
      if (served[directive] !== sources) {
        cspDiff.push(
          `${directive}: expected "${sources}", got "${served[directive] ?? '(absent)'}"`,
        );
      }
    }
    for (const directive of Object.keys(served)) {
      if (!(directive in SANDBOX_CSP_EXPECTED)) cspDiff.push(`unexpected directive ${directive}`);
    }
    // Revalidated, never held. The document names content-hashed
    // `/sandbox-assets/` URLs that change on every deploy, so a cached copy is a
    // frame asking for assets that no longer exist — a dead viewer for every
    // returning user, one deploy late.
    const sandboxCache = sandbox.headers.get('cache-control');
    const cacheOk = sandboxCache === 'no-cache';
    const sandboxOk = sandbox.status === 200 && singleCspHeader && cacheOk && cspDiff.length === 0;
    record(
      'sandbox-document',
      sandboxOk,
      sandboxOk
        ? `/sandbox.html is served by Express with exactly one Content-Security-Policy, matching all ${String(Object.keys(SANDBOX_CSP_EXPECTED).length)} directives`
        : `GET /sandbox.html returned ${String(sandbox.status)}; single CSP header=${String(singleCspHeader)}; Cache-Control=${String(sandboxCache)}${cspDiff.length > 0 ? `; ${cspDiff.join('; ')}` : ''}`,
    );

    // The asset headers. A module script is fetched in CORS mode
    // unconditionally, so from the frame's opaque origin it sends `Origin:
    // null` and needs ACAO; helmet's default CORP (`same-origin`) separately
    // blocks the no-cors stylesheet wherever EXPRESS serves it, which is the
    // path a pm2 deployment and this gate use.
    //
    // The negative half keeps the widening scoped, and is phrased as the exact
    // values `/assets/` carries rather than as their ABSENCE — measured, and
    // the difference matters. Every Express response already carries both
    // header NAMES: the `cors` middleware is configured with a fixed string
    // origin, so it emits `Access-Control-Allow-Origin: <CORS_ORIGIN>`
    // unconditionally on every response, and helmet's default emits
    // `Cross-Origin-Resource-Policy: same-origin`. An "must not be present"
    // assertion is therefore false on a correct build, and the tempting way to
    // make it pass is to delete the negative — which is the whole check.
    const sandboxAsset = /<script[^>]+src="(\/sandbox-assets\/[^"]+)"/.exec(sandboxHtml)?.[1];
    const appAsset = /<script[^>]+src="(\/assets\/[^"]+)"/.exec(html)?.[1];
    if (!sandboxAsset || !appAsset) {
      record(
        'sandbox-assets',
        false,
        `could not locate a module script to probe (sandbox-assets=${String(sandboxAsset)}, assets=${String(appAsset)})`,
      );
    } else {
      const [sandboxRes, appRes] = await Promise.all([
        fetch(new URL(sandboxAsset, baseUrl)),
        fetch(new URL(appAsset, baseUrl)),
      ]);
      const problems = [];
      if (sandboxRes.headers.get('access-control-allow-origin') !== '*') {
        problems.push(
          `${sandboxAsset} Access-Control-Allow-Origin=${String(sandboxRes.headers.get('access-control-allow-origin'))}, expected *`,
        );
      }
      if (sandboxRes.headers.get('cross-origin-resource-policy') !== 'cross-origin') {
        problems.push(
          `${sandboxAsset} Cross-Origin-Resource-Policy=${String(sandboxRes.headers.get('cross-origin-resource-policy'))}, expected cross-origin`,
        );
      }
      const appAcao = appRes.headers.get('access-control-allow-origin');
      const appCorp = appRes.headers.get('cross-origin-resource-policy');
      // Exactly what the application's own bundle carries today: the single
      // configured CORS origin, and helmet's same-origin CORP. Either one moving
      // to the sandbox's values would mean the widening had leaked out of its
      // directory and handed every sandboxed document on the internet read
      // access to the app's bundle.
      if (appAcao !== 'https://smoke.hvault.test') {
        problems.push(
          `${appAsset} Access-Control-Allow-Origin=${String(appAcao)}, expected the configured CORS origin`,
        );
      }
      if (appCorp !== 'same-origin') {
        problems.push(
          `${appAsset} Cross-Origin-Resource-Policy=${String(appCorp)}, expected same-origin`,
        );
      }
      record(
        'sandbox-assets',
        problems.length === 0,
        problems.length === 0
          ? 'sandbox-assets/ is readable by an opaque origin; assets/ still carries only the app’s own CORS origin and same-origin CORP'
          : problems.join('; '),
      );
    }

    // -----------------------------------------------------------------------
    // 5. The journey (e)
    // -----------------------------------------------------------------------
    const { MongoClient } = await import('mongodb');
    const client = new MongoClient(mongoUri);
    await client.connect();
    try {
      const flow = await runVaultFlow({
        baseUrl,
        log: (message) => {
          note(message);
        },
        verifyEmail: async (email) => {
          const result = await client
            .db('hvault')
            .collection('users')
            .updateOne({ email }, { $set: { emailVerified: true } });
          if (result.matchedCount !== 1) {
            throw new Error(
              `the registered account is not in the database (matched ${String(result.matchedCount)})`,
            );
          }
        },
      });
      record('vault-flow', true, `registered, signed in and round-tripped item ${flow.itemId}`, {
        steps: flow.steps,
      });
    } finally {
      await client.close();
    }
  }
} catch (error) {
  record('smoke', false, error instanceof Error ? error.message : String(error), {
    context: error?.context ?? {},
  });
} finally {
  await stop();
}

const durationMs = Date.now() - started;
const payload = {
  version: 1,
  task: 'test:smoke',
  checkedAt: new Date().toISOString(),
  durationMs,
  budgetMs: BUDGET_MS,
  bootDeadlineMs: BOOT_DEADLINE_MS,
  failures,
  steps,
};
writeJsonReport('smoke.json', payload);

if (failures.length > 0) {
  console.error(color.red(`\n${symbol.fail} smoke: ${String(failures.length)} failed check(s)`));
  for (const failure of failures) console.error(color.red(`      ${failure}`));
  process.exit(1);
}

// (d) Reported, never enforced.
if (durationMs > BUDGET_MS) {
  warn(
    `the smoke gate took ${formatDuration(durationMs)}, over its ${formatDuration(BUDGET_MS)} budget`,
  );
}
console.log(
  color.green(
    `\n${symbol.pass} smoke: the built artifact boots in production mode, serves its shell, and completes a vault journey (${formatDuration(durationMs)})`,
  ),
);
