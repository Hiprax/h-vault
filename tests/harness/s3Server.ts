/**
 * A real object-storage engine, in a container, on a loopback port.
 *
 * Two suites need one and they must not stand up two different engines: the
 * server package's storage-conformance gate (`test:storage`), which runs the
 * shared `StorageProvider` contract against the thing production talks to, and
 * the end-to-end harness, which boots a dev server with the document store
 * switched on. Both call {@link startStorageEngine}, so "the engine the tests
 * run against" has one definition and it is the one `docker-compose.yml` ships.
 *
 * It lives at the repository root beside `socketEgress.ts` and `repoWrites.ts`,
 * and for the same reason: two tiers need identical semantics, and a per-package
 * copy is two definitions of which engine, which configuration and which
 * credentials — the shape where a gate quietly stops testing what it claims to.
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE IMAGE IS READ OUT OF `docker-compose.yml`, NEVER WRITTEN HERE. The
 *     compose file pins it by tag AND by digest, and `docker-hardening.test.ts`
 *     asserts every reference in that file carries the digest. A literal here
 *     would be a second definition that the pin does not cover, so a conformance
 *     gate could go on passing against an image the stack stopped running.
 *     `docker-hardening.test.ts` compares what this resolver returns against what
 *     a real YAML parser reads, so the scan below cannot drift from the file it
 *     reads either.
 *
 *  b. THE COMMITTED `docker/garage/garage.toml` IS MOUNTED, NOT A TEST COPY.
 *     `block_size` in that file is pinned to `DOCUMENT_CIPHERTEXT_CHUNK_BYTES` so
 *     one uploaded part is exactly one engine block. A conformance suite running
 *     against a differently-configured engine would prove nothing about the
 *     deployment, and the framing is precisely what it is there to check.
 *
 *  c. THE PORT IS ASSIGNED BY DOCKER, NOT PROBED, AND A LOST ALLOCATION IS
 *     RETRIED. `-p 127.0.0.1:0:3900` makes the daemon pick the host port, and
 *     `docker port` reports which one. Probing for a free port here and then
 *     binding it would leave a window in which a sibling worker takes it — the
 *     race `packages/server/tests/mongoHarness.ts` needs whole port bands to
 *     work around — so nothing probes.
 *
 *     What this file used to claim next was that the daemon binds the port
 *     before `docker run` returns, so there is no window at all. That is FALSE,
 *     and it was measured here rather than reasoned about: `docker run` failed
 *     with `RootlessKit PortManager.AddPort(): listen tcp4 127.0.0.1:33498:
 *     bind: address already in use`, taking the conformance gate down with it.
 *     Two things make it false. Docker's allocator draws its dynamic range from
 *     `/proc/sys/net/ipv4/ip_local_port_range` and tracks only its OWN bitmap,
 *     so it hands out numbers the kernel is simultaneously handing to every
 *     outbound socket on the machine — and this suite owns a great many of them.
 *     And under ROOTLESS Docker the daemon is namespaced inside RootlessKit,
 *     while the real host `listen()` happens afterwards, outside it, in
 *     `PortManager.AddPort` — so the allocation has no visibility of host port
 *     usage whatsoever.
 *
 *     The answer is {@link withHostPortRetry}, and what makes it sufficient is a
 *     property of the allocator rather than optimism: dynamic allocation walks a
 *     monotonically advancing cursor that releasing a port does NOT rewind, so a
 *     retry is offered a DIFFERENT number, not the one that just lost. This is
 *     deliberately weaker than what `mongoHarness.ts` does for mongod, which is
 *     band-FIRST (a range below the ephemeral floor, so the systematic cause is
 *     gone) and retry-second. A band cannot be shared with it from here:
 *     `gate-surface.test.ts` restricts this file to `node:` builtins and
 *     relative paths inside this directory, so `PORT_BAND_START` would have to
 *     be copied, and the sub-ephemeral window is already spoken for by hand.
 *     A second, unenforced copy of that constant is a worse failure than the one
 *     being fixed, so the band stays in reserve.
 *
 *  d. READINESS IS POLLED, AND THE PROBE IS THE CALLER'S. `test:flake` runs every
 *     suite ten times, so a fixed sleep is either ten times too long or a race
 *     that surfaces as an unexplained failure in run seven. The probe is supplied
 *     by the caller rather than made here, and that is not indirection for its own
 *     sake: "ready" has to mean ready FOR THE CLIENT THAT WILL USE IT — the same
 *     credentials, the same signing, the same addressing style. A probe built here
 *     from a second S3 client could succeed while the caller's own client is
 *     rejected, which is a green wait in front of a red suite. `StorageProvider`
 *     declares `headBucket()` for exactly this.
 *
 *  e. THE CONTAINER IS REMOVED ON EVERY EXIT PATH. `--rm` covers the ordinary
 *     one; a `process.on('exit')` hook with a synchronous `docker rm -f` covers a
 *     suite that throws, and the signal handlers cover an interrupted run. The
 *     volumes are tmpfs, so a leaked container would hold RAM until the daemon
 *     reaped it — the same failure the mongod harness leaves behind when a run is
 *     killed, and it is worth not repeating.
 */
import { execFile, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/** The repository root, derived from this module's own URL, never `process.cwd()`. */
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

/** The compose service whose image and configuration this harness reuses. */
export const STORAGE_COMPOSE_SERVICE = 'hvault-s3';

/** The port the engine's S3 API listens on inside the container. */
const CONTAINER_S3_PORT = 3900;

/**
 * Fixed credentials, a fixed bucket and a fixed region, because a harness that
 * drew them from entropy would make a failing assertion irreproducible from the
 * seed. They are not secrets: they authenticate to a container that exists for
 * the length of one test file, holds nothing, and is reachable only from
 * loopback.
 *
 * The access key id is deliberately longer than eight characters: the engine
 * refuses a shorter one at boot, and that failure arrives as a container that
 * exited rather than as anything a test could read.
 */
const ACCESS_KEY_ID = 'hvaultharnesskey';
const SECRET_ACCESS_KEY = 'hvault-harness-storage-credential';
const BUCKET = 'hvault-harness';
const REGION = 'us-east-1';

/**
 * The engine's cluster RPC secret: sixty-four hex characters, DERIVED rather than
 * written down, so no credential-shaped literal is committed. A single-node
 * cluster has no peer to talk to, so this authenticates nothing; the engine
 * simply refuses to start without one.
 */
const RPC_SECRET = createHash('sha256').update('hvault-storage-harness-rpc').digest('hex');

/** How long to wait for a freshly started engine before giving up. */
const READY_TIMEOUT_MS = 60_000;

/**
 * Attempts at standing the container up before the harness gives up.
 *
 * Five, matching `mongoHarness.ts`'s `PORT_ATTEMPTS` for the same class of
 * failure. Each attempt is a fresh allocation from a cursor that has moved on
 * (see decision (c)), so five consecutive losses are worth REPORTING rather than
 * retrying around — not because they prove the host has nothing free, which on a
 * contended ephemeral range they do not, but because past that point a louder
 * failure is more use than a sixth attempt.
 */
const PORT_ATTEMPTS = 5;

/** How long to wait between readiness probes. */
const READY_POLL_INTERVAL_MS = 100;

/** Everything a caller needs in order to reach the engine this harness started. */
export interface StorageConnection {
  /** `http://127.0.0.1:<mapped port>` — always loopback, never a wildcard bind. */
  endpoint: string;
  region: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  /**
   * Always true. Virtual-host addressing puts the bucket in the hostname, and
   * `127.0.0.1` has no DNS to resolve `hvault-harness.127.0.0.1` with.
   */
  forcePathStyle: true;
}

/** A running engine, and the one way to stop it. */
export interface StorageEngine extends StorageConnection {
  /** The container id, so a failing test can name it in a diagnostic. */
  containerId: string;
  /** The image reference the stack pins, for the same reason. */
  image: string;
  /**
   * Removes the container and its tmpfs volumes.
   *
   * Safe to call twice, and a second call JOINS the first rather than resolving
   * beside it: a caller that exits once its own call resolves would otherwise
   * leave the removal in flight. See `stop` for the run this was measured on.
   */
  stop: () => Promise<void>;
}

export interface StartStorageEngineOptions {
  /**
   * Proves the engine is ready FOR THIS CALLER. Called repeatedly with the
   * connection details until it resolves; every rejection is a "not yet". See
   * decision (d): the caller supplies it so that readiness is measured through
   * the same client, credentials and addressing the suite will use.
   */
  probe: (connection: StorageConnection) => Promise<unknown>;
  /** Overrides the readiness deadline. Only a test of this harness needs it. */
  readyTimeoutMs?: number;
}

/**
 * The image reference `docker-compose.yml` pins for the storage service.
 *
 * A deliberately small hand-rolled scan rather than a YAML parse, because this
 * module is imported by the end-to-end harness at the repository root as well as
 * by the server package, and `yaml` is a devDependency of the server package
 * alone — an import that resolves today only because npm hoists it. The compose
 * file's indentation is fixed (two spaces for a service, four for its keys) and
 * `docker-hardening.test.ts` asserts this function agrees with a real parser, so
 * the scan cannot drift from the document it reads.
 *
 * Exported for that assertion.
 */
export function resolveComposeImage(service = STORAGE_COMPOSE_SERVICE): string {
  const composePath = path.join(REPO_ROOT, 'docker-compose.yml');
  const lines = readFileSync(composePath, 'utf8').split('\n');
  const start = lines.findIndex((line) => line === `  ${service}:`);
  if (start === -1) {
    throw new Error(`docker-compose.yml declares no service named "${service}"`);
  }
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    // A line indented by two spaces that is not a comment starts the NEXT
    // service, so the search stops before it can read a sibling's image.
    if (/^ {2}\S/.test(line)) break;
    const image = /^ {4}image:\s*(\S+)\s*$/.exec(line);
    if (image?.[1] !== undefined) return image[1];
  }
  throw new Error(`docker-compose.yml declares no image for the "${service}" service`);
}

/** `docker` arguments that stand the engine up, as one list, for readability. */
function runArguments(image: string): string[] {
  return [
    'run',
    '-d',
    // (e) The ordinary exit path. The tmpfs mounts below go with the container.
    '--rm',
    // Findable by a human whose run was killed, without being a name two
    // concurrent runs could collide on.
    '--label',
    'hvault-test=storage-harness',
    // (c) The daemon picks the host port. It has NOT necessarily bound it by the
    // time this returns — that is the claim decision (c) measured false — so the
    // call this list feeds is wrapped in `withHostPortRetry`.
    '-p',
    `127.0.0.1:0:${String(CONTAINER_S3_PORT)}`,
    // The image's own CMD is `/garage server` with an empty entrypoint, exactly as
    // docker-compose.yml spells it out, so the flags below read as a whole command.
    '--entrypoint',
    '/garage',
    '-e',
    `GARAGE_DEFAULT_ACCESS_KEY=${ACCESS_KEY_ID}`,
    '-e',
    `GARAGE_DEFAULT_SECRET_KEY=${SECRET_ACCESS_KEY}`,
    '-e',
    `GARAGE_DEFAULT_BUCKET=${BUCKET}`,
    '-e',
    `GARAGE_RPC_SECRET=${RPC_SECRET}`,
    // (b) The committed configuration, read-only, exactly as the stack mounts it.
    '-v',
    `${path.join(REPO_ROOT, 'docker', 'garage', 'garage.toml')}:/etc/garage.toml:ro`,
    // RAM-backed and ephemeral: nothing here outlives the test file, and a disk
    // volume would need reclaiming on a path that may never run.
    '--tmpfs',
    '/var/lib/garage/meta:size=64m',
    '--tmpfs',
    '/var/lib/garage/data:size=512m',
    // No uid pin, matching docker-compose.yml: this image declares no USER, so the
    // process is root inside the container and a uid-pinned tmpfs is one it cannot
    // write — which presents as a container that restarts silently.
    '--tmpfs',
    '/tmp:size=64m,mode=1777',
    // The same hardening the stack runs it under, so the harness cannot pass
    // against a permission the deployment does not grant.
    '--read-only',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges:true',
    '--memory',
    '512m',
    '--pids-limit',
    '100',
    image,
    'server',
    '--single-node',
    '--default-bucket',
  ];
}

/**
 * Whether a `docker run` failure is a LOST HOST-PORT ALLOCATION rather than
 * anything about this harness, this image or this daemon.
 *
 * Both `stderr` and the message are read. `promisify(execFile)` rejects with an
 * error whose message is `Command failed: <argv>\n<stderr>`, so the message
 * alone does carry the daemon's words today — but that is a formatting
 * convention, and the property is the contract.
 *
 * Exported for its own test, and narrow in BOTH directions on purpose. One that
 * answered `true` for everything would turn a single readable "that image
 * cannot be pulled" into five slow identical failures; one that did not match
 * the spelling this host actually produces would leave the gate a coin toss
 * again. Both spellings are matched because the harness runs under either
 * daemon: rootless Docker reports the kernel's own words from the `listen()`
 * RootlessKit performs itself, and rootful Docker reports its allocator's.
 */
export function isHostPortCollision(error: unknown): boolean {
  const parts: string[] = [];
  if (error instanceof Error) {
    parts.push(error.message);
    // `ExecFileException` carries the streams as their own properties. Read
    // defensively rather than by cast: this predicate is handed whatever the
    // rejection was, and a harness that threw on inspecting a failure would
    // replace one clear error with a useless one.
    const stderr = (error as { stderr?: unknown }).stderr;
    if (typeof stderr === 'string') parts.push(stderr);
  } else {
    parts.push(String(error));
  }
  return /bind: address already in use|port is already allocated/i.test(parts.join('\n'));
}

/**
 * Runs `start` again while it loses the host port, and ONLY while it loses the
 * host port.
 *
 * Generic and exported so its own test can drive it without a daemon: the loop
 * is the part that has to be right, and a test that needed real containers to
 * reach the give-up path would cost five container starts to assert one
 * sentence. It wraps the `docker run` call alone rather than the whole of
 * {@link startStorageEngine}, because the exit and signal hooks are registered
 * after that call — a retry placed any wider would register one per attempt and
 * remove a container a later attempt still owned.
 *
 * A LOST ATTEMPT LEAVES NOTHING TO RECLAIM, and that was measured rather than
 * assumed, because a retry that stranded a container per attempt would be worse
 * than the flake it removes. With a host port held by a listener, `docker run -d
 * --rm` exits 125 with `PortManager.AddPort(): … bind: address already in use`,
 * and `docker ps -a` is unchanged: the daemon force-removes an `AutoRemove`
 * container whose start failed, and a lost attempt never yields an id anyway.
 *
 * That placement is the ONE thing here no test pins, and honestly so: nothing
 * fires the retry on a healthy run, and a seam that let a test fail `docker run`
 * on demand would be a seam production never has. `harness-teardown.test.ts`
 * catches a widened retry only on a run that actually loses a port, so this
 * paragraph is the control.
 */
export async function withHostPortRetry<T>(start: () => Promise<T>): Promise<T> {
  let lastError: unknown;

  for (let attempt = 0; attempt < PORT_ATTEMPTS; attempt += 1) {
    try {
      return await start();
    } catch (error) {
      // Anything else is rethrown on the FIRST attempt, for the reason
      // `mongoHarness.ts` gives about mongod: retrying a configuration error
      // turns one readable failure into five identical slow ones.
      if (!isHostPortCollision(error)) throw error;
      lastError = error;
    }
  }

  throw new Error(
    `Could not start the storage engine: ${String(PORT_ATTEMPTS)} host-port allocations in a ` +
      'row were taken before the daemon could bind them. Last error: ' +
      `${lastError instanceof Error ? lastError.message : String(lastError)}`,
    // The daemon's words are quoted above so a reader sees them without digging;
    // the rejection itself is carried so nothing (its `stderr`, its exit code)
    // is lost to the summary.
    { cause: lastError },
  );
}

/** Removes a container, ignoring the case where it is already gone. */
function removeContainerSync(containerId: string): void {
  try {
    execFileSync('docker', ['rm', '-f', containerId], { stdio: 'ignore' });
  } catch {
    // Already removed by `--rm`, or the daemon went away with it. Either way
    // there is nothing left to clean up and nothing a caller could do about it.
  }
}

/** The container's log tail, for a diagnostic. Never throws. */
function containerLogs(containerId: string): string {
  try {
    return execFileSync('docker', ['logs', '--tail', '40', containerId], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch {
    return '(no logs available)';
  }
}

/** Whether the daemon still reports the container as running. */
async function isRunning(containerId: string): Promise<boolean> {
  try {
    const { stdout } = await execFileAsync('docker', [
      'inspect',
      '-f',
      '{{.State.Running}}',
      containerId,
    ]);
    return stdout.trim() === 'true';
  } catch {
    return false;
  }
}

/**
 * Starts the pinned storage engine and returns once {@link StartStorageEngineOptions.probe}
 * has succeeded against it.
 *
 * Throws if docker is absent, if the container dies during the wait (with its log
 * tail, because a credential the engine refuses is otherwise a silent exit), or if
 * the probe has not succeeded by the deadline.
 */
export async function startStorageEngine(
  options: StartStorageEngineOptions,
): Promise<StorageEngine> {
  const image = resolveComposeImage();
  const deadlineMs = options.readyTimeoutMs ?? READY_TIMEOUT_MS;

  // (c) The allocation can lose a race with the rest of the machine, so it is
  // retried — and NOTHING below is inside the retry, because the reclaim hooks
  // start at the next statement.
  const { stdout: idOut } = await withHostPortRetry(() =>
    execFileAsync('docker', runArguments(image)),
  );
  const containerId = idOut.trim();
  if (containerId === '') {
    throw new Error(`docker run returned no container id for ${image}`);
  }

  // (e) Registered immediately after the container exists, so a throw anywhere
  // below still reclaims it. `exit` may only run synchronous work, which is why
  // the removal helper is the sync one.
  const cleanUp = (): void => {
    removeContainerSync(containerId);
  };
  process.once('exit', cleanUp);
  const onSignal = (): void => {
    cleanUp();
    process.exit(1);
  };
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);

  const removeContainer = async (): Promise<void> => {
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);
    try {
      await execFileAsync('docker', ['rm', '-f', containerId]);
    } catch {
      // As in `removeContainerSync`: already gone is the outcome we wanted.
    } finally {
      // Unregistered only AFTER the removal has actually happened, never before
      // the await: this hook is the synchronous last resort for an exit that
      // races this removal, so disarming it first left exactly the window it
      // exists to cover uncovered.
      process.off('exit', cleanUp);
    }
  };

  // Latches the PROMISE rather than a boolean, so a second caller JOINS the
  // removal instead of resolving beside it. MEASURED: `e2e/start-server.ts`
  // reaches teardown from two directions at once — Playwright's SIGTERM, and the
  // dev server's `exit` handler, which then calls `process.exit()` — and a second
  // `stop()` that returned immediately let that exit run while `docker rm -f` was
  // still in flight, stranding one engine per `test:e2e` and `test:a11y` run on
  // runs that ended green. `stopMongo` in that file already memoizes its promise
  // for the same reason; this makes the two teardowns behave alike.
  let stopping: Promise<void> | undefined;
  const stop = (): Promise<void> => (stopping ??= removeContainer());

  try {
    const { stdout: portOut } = await execFileAsync('docker', [
      'port',
      containerId,
      String(CONTAINER_S3_PORT),
    ]);
    // `docker port` prints one `host:port` line per binding; there is exactly one
    // here, and the port is the last colon-separated field so an IPv6 host would
    // not confuse it.
    const first = portOut.trim().split('\n')[0] ?? '';
    const port = Number(first.split(':').pop());
    if (!Number.isInteger(port) || port <= 0) {
      throw new Error(`could not read the mapped port from "docker port": ${portOut.trim()}`);
    }

    const connection: StorageConnection = {
      endpoint: `http://127.0.0.1:${String(port)}`,
      region: REGION,
      bucket: BUCKET,
      accessKeyId: ACCESS_KEY_ID,
      secretAccessKey: SECRET_ACCESS_KEY,
      forcePathStyle: true,
    };

    // (d) Poll, never sleep.
    const started = Date.now();
    let lastError: unknown;
    for (;;) {
      // Checked BEFORE the elapsed-time test, so a container that refused its
      // configuration is reported in milliseconds with its own explanation
      // rather than as a sixty-second timeout that names nothing.
      if (!(await isRunning(containerId))) {
        throw new Error(
          `the storage engine container exited while starting up.\n${containerLogs(containerId)}`,
        );
      }
      try {
        await options.probe(connection);
        break;
      } catch (error) {
        lastError = error;
      }
      if (Date.now() - started >= deadlineMs) {
        throw new Error(
          `the storage engine was not ready within ${String(deadlineMs)}ms — last probe failure: ` +
            `${String(lastError)}\n${containerLogs(containerId)}`,
        );
      }
      await new Promise((resolve) => setTimeout(resolve, READY_POLL_INTERVAL_MS));
    }

    return { ...connection, containerId, image, stop };
  } catch (error) {
    await stop();
    throw error;
  }
}
