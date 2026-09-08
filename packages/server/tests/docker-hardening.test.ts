/**
 * Docker deployment invariants.
 *
 * Parses docker-compose.yml, docker/Dockerfile and docker/nginx/internal.conf and
 * asserts the properties the production stack depends on. Most of what follows is
 * not a style preference — it encodes failures observed for real while bringing
 * the stack up, each of which produced something that looked healthy from outside:
 *
 *   * mongod REFUSES TO BOOT when a replica set and authentication are combined
 *     without a key file;
 *   * a tmpfs whose owner is not pinned to the app's user makes the container die
 *     silently — exit code 0, no output — on its FIRST restart;
 *   * an auto-allocated bridge subnet can collide with another project's network
 *     and blackhole traffic between containers that resolve each other happily;
 *   * serving the SPA's HTML from Nginx's own document root strips every security
 *     header helmet attaches to it;
 *   * the object storage engine refuses to boot when its access key id is known
 *     with a different secret, so a half-rotated credential is a crash loop rather
 *     than a quiet adoption.
 *
 * A refactor that drops one of these gets a red test instead of an incident.
 *
 * The service lists below (`longRunning`, `everyService`) are built BY LITERAL
 * NAME. A service added to docker-compose.yml and not to them escapes every
 * cross-service rule in this file silently, so they are part of the cost of
 * adding a service, not an afterthought.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import { DOCUMENT_CIPHERTEXT_CHUNK_BYTES } from '@hvault/shared';
import { resolveComposeImage, STORAGE_COMPOSE_SERVICE } from '../../../tests/harness/s3Server.js';

interface HealthCheck {
  test?: string[] | string;
}

/** `env_file` accepts both the short (`- .env`) and long (`- path: … required: …`) forms. */
type EnvFileEntry = string | { path?: string; required?: boolean };

/** `networks` accepts a plain list, or a map (the map form carries the priorities). */
type NetworkAttachment =
  string[] | Record<string, { priority?: number; gw_priority?: number } | null>;

interface ServiceConfig {
  image?: string;
  /** Long form only in this repo; the short `build: .` form is typed for completeness. */
  build?: string | { context?: string; dockerfile?: string };
  container_name?: string;
  stop_signal?: string;
  security_opt?: string[];
  cap_drop?: string[];
  cap_add?: string[];
  pids_limit?: number;
  read_only?: boolean;
  init?: boolean;
  mem_limit?: string;
  cpus?: string;
  restart?: string;
  stop_grace_period?: string;
  logging?: { driver?: string; options?: Record<string, string> };
  healthcheck?: HealthCheck;
  tmpfs?: string[];
  ports?: string[];
  networks?: NetworkAttachment;
  environment?: Record<string, string>;
  env_file?: EnvFileEntry[];
  entrypoint?: string[] | string;
  command?: string[] | string;
  volumes?: string[];
  depends_on?: Record<string, { condition?: string }>;
}

interface NetworkConfig {
  driver?: string;
  internal?: boolean;
  ipam?: { config?: { subnet?: string }[] };
}

interface ComposeConfig {
  services: Record<string, ServiceConfig | undefined>;
  networks: Record<string, NetworkConfig | undefined>;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// tests/ → packages/server/ → packages/ → repo root
const repoRoot = path.resolve(__dirname, '..', '..', '..');

const composeYaml = readFileSync(path.join(repoRoot, 'docker-compose.yml'), 'utf-8');
// `merge: true` expands YAML merge keys (`<<: *anchor`), which the compose file uses to
// layer a service-specific value over the shared topology anchor (the app's NODE_OPTIONS
// and its own MONGODB_URI). Without it the parser hands back a literal `<<` key
// and every assertion about an INHERITED value — NODE_ENV, PORT, MONGODB_URI,
// TRUST_PROXY — silently reads `undefined` and the tests that matter most go quiet.
const compose = parse(composeYaml, { merge: true }) as ComposeConfig;
const dockerfile = readFileSync(path.join(repoRoot, 'docker', 'Dockerfile'), 'utf-8');
const mongoDockerfile = readFileSync(path.join(repoRoot, 'docker', 'mongo.Dockerfile'), 'utf-8');
const nginxConf = readFileSync(path.join(repoRoot, 'docker', 'nginx', 'internal.conf'), 'utf-8');
const envExample = readFileSync(path.join(repoRoot, '.env.example'), 'utf-8');
const ecosystemConfig = readFileSync(path.join(repoRoot, 'ecosystem.config.cjs'), 'utf-8');
const rootPackageJson = JSON.parse(readFileSync(path.join(repoRoot, 'package.json'), 'utf-8')) as {
  version: string;
};

/**
 * The `COPY` statements of the `web` stage that run after a `USER` directive has
 * dropped the build out of root, classified for the hermeticity rule below.
 *
 * `fromBuildContext` separates the copies whose source modes come from the
 * developer's checkout (and must therefore be pinned) from `--from=<stage>`
 * copies, whose modes were already decided inside this build.
 * `sourcesAreFiles` is resolved by stat-ing the real path in the repository,
 * because a file copy and a directory copy need OPPOSITE treatment and guessing
 * from the destination string would get that backwards on the first path without
 * an extension.
 */
interface WebStageCopy {
  line: string;
  fromBuildContext: boolean;
  sourcesAreFiles: boolean;
}

const webStageCopyStatements: WebStageCopy[] = (() => {
  const stage = dockerfile.slice(dockerfile.indexOf('FROM nginxinc/nginx-unprivileged'));
  const lines = stage.split('\n');
  const firstUser = lines.findIndex((line) => /^USER\s/.test(line.trim()));
  if (firstUser === -1) return [];

  return lines
    .slice(firstUser + 1)
    .map((line) => line.trim())
    .filter((line) => line.startsWith('COPY '))
    .map((line) => {
      const tokens = line.split(/\s+/).slice(1);
      const flags = tokens.filter((token) => token.startsWith('--'));
      // Everything but the flags and the final destination argument.
      const sources = tokens.filter((token) => !token.startsWith('--')).slice(0, -1);
      const fromBuildContext = !flags.some((flag) => flag.startsWith('--from='));
      const sourcesAreFiles =
        fromBuildContext &&
        sources.length > 0 &&
        sources.every((source) => {
          try {
            return statSync(path.join(repoRoot, source)).isFile();
          } catch {
            // A context source that does not exist is a broken build, not this
            // rule's business — the image build gate reports it far more clearly.
            return false;
          }
        });
      return { line, fromBuildContext, sourcesAreFiles };
    });
})();

/**
 * Every `COPY` in the Dockerfile, whatever stage it is in, classified the same
 * way {@link webStageCopyStatements} classifies the `web` stage's.
 *
 * The `web` stage was the first place this bit, but it is not the only one: the
 * node stages copy the whole source tree from the same checkout, and the two
 * images that drop to `USER node` read those files as uid 1000.
 */
const contextCopyStatements: (WebStageCopy & { sources: string[]; stageAfterCopy: string })[] =
  dockerfile
    .split('\n')
    .map((line, index) => ({ line: line.trim(), index }))
    .filter(({ line }) => line.startsWith('COPY '))
    .map(({ line, index }) => {
      const tokens = line.split(/\s+/).slice(1);
      const flags = tokens.filter((token) => token.startsWith('--'));
      const sources = tokens.filter((token) => !token.startsWith('--')).slice(0, -1);
      const fromBuildContext = !flags.some((flag) => flag.startsWith('--from='));
      const statOf = (source: string): ReturnType<typeof statSync> | null => {
        try {
          // `package-lock.json*` is the one globbed source; strip the glob so the
          // stat sees the file it actually names.
          return statSync(path.join(repoRoot, source.replace(/\*$/, '')));
        } catch {
          return null;
        }
      };
      const sourcesAreFiles =
        fromBuildContext &&
        sources.length > 0 &&
        sources.every((s) => statOf(s)?.isFile() === true);
      // Everything from this COPY to the end of the stage it lives in: the only
      // region where a `chmod` can be said to normalise THIS copy.
      const lines = dockerfile.split('\n');
      const nextStage = lines.findIndex(
        (candidate, at) => at > index && /^FROM\s/.test(candidate.trim()),
      );
      const stageAfterCopy = lines
        .slice(index + 1, nextStage === -1 ? lines.length : nextStage)
        .join('\n');
      return { line, fromBuildContext, sourcesAreFiles, sources, stageAfterCopy };
    })
    .filter((copy) => copy.fromBuildContext);

/** The config default for HIBP_CACHE_MAX_BYTES — one worker's full L1 cache. */
const HIBP_CACHE_MAX_BYTES_DEFAULT = 67_108_864; // 64 MiB
const MIB = 1024 * 1024;

/** Parse a PM2 `max_memory_restart` string (e.g. '768M', '1G') to bytes. */
function parseMemoryToBytes(value: string): number {
  const match = /^(\d+(?:\.\d+)?)\s*([KMG])?B?$/i.exec(value.trim());
  if (!match) throw new Error(`unparseable memory value: ${value}`);
  const magnitude = Number(match[1]);
  const unit = (match[2] ?? '').toUpperCase();
  const scale = unit === 'G' ? 1024 ** 3 : unit === 'M' ? 1024 ** 2 : unit === 'K' ? 1024 : 1;
  return magnitude * scale;
}

const app = compose.services['hvault-app'];
const db = compose.services['hvault-db'];
const nginx = compose.services['hvault-nginx'];
const bootstrap = compose.services['hvault-bootstrap'];
/** One-shot that provisions the least-privilege application database user. */
const dbInit = compose.services['hvault-db-init'];
/** The S3-compatible object storage the document store writes ciphertext to. */
const s3 = compose.services['hvault-s3'];

/**
 * The two lists every cross-service rule below iterates, BY LITERAL NAME.
 *
 * That is the trap they carry, and it is why adding a service to the stack means
 * editing this file in the same change: a service missing from these arrays is
 * not partially checked, it is checked by NOTHING — not log rotation, not the
 * restart policy, not `container_name` namespacing, not `init:`, and above all
 * not "publishes a port from Nginx and from nowhere else", which is the one
 * assertion whose failure puts an unauthenticated surface on the host.
 */
const longRunning: [string, ServiceConfig | undefined][] = [
  ['hvault-nginx', nginx],
  ['hvault-app', app],
  ['hvault-db', db],
  ['hvault-s3', s3],
];
const everyService: [string, ServiceConfig | undefined][] = [
  ...longRunning,
  ['hvault-bootstrap', bootstrap],
  ['hvault-db-init', dbInit],
];

/** tmpfs entries look like `"/path:opt=val,opt=val"`; pull the options for one path. */
function tmpfsOptions(service: ServiceConfig | undefined, mountPath: string): string {
  const entry = (service?.tmpfs ?? []).find((t) => t.startsWith(`${mountPath}:`));
  return entry?.slice(mountPath.length + 1) ?? '';
}

function probeOf(service: ServiceConfig | undefined): string {
  return [service?.healthcheck?.test ?? []].flat().join(' ');
}

/** The networks a service attaches to, whichever of the two YAML forms it uses. */
function networksOf(service: ServiceConfig | undefined): string[] {
  const networks = service?.networks;
  if (!networks) return [];
  return Array.isArray(networks) ? networks : Object.keys(networks);
}

/** A service's `priority` on one network — the ATTACHMENT order, not the gateway. */
function networkPriority(service: ServiceConfig | undefined, name: string): number | undefined {
  const networks = service?.networks;
  if (!networks || Array.isArray(networks)) return undefined;
  return networks[name]?.priority;
}

/** A service's `gw_priority` on one network — this is the one that picks the gateway. */
function networkGwPriority(service: ServiceConfig | undefined, name: string): number | undefined {
  const networks = service?.networks;
  if (!networks || Array.isArray(networks)) return undefined;
  return networks[name]?.gw_priority;
}

function envFilePaths(service: ServiceConfig | undefined): string[] {
  return (service?.env_file ?? []).map((entry) =>
    typeof entry === 'string' ? entry : (entry.path ?? ''),
  );
}

/**
 * Reads the pinned default out of a `${VAR:-default}` interpolation, so a test can
 * assert BOTH that a value is operator-overridable and that its committed default is
 * still a sane, pinned one. Returns the raw value unchanged when it is not interpolated.
 */
function interpolationDefault(value: string | undefined): string {
  const match = /^\$\{[A-Z_][A-Z0-9_]*:-([^}]+)\}$/.exec(value ?? '');
  return match?.[1] ?? value ?? '';
}

describe('Docker deployment', () => {
  describe('exposure: exactly one port, on loopback', () => {
    it('publishes a port from Nginx and from nowhere else', () => {
      // The whole point of the topology: the host's system Nginx is the only thing
      // that talks to this stack, over loopback. A port published anywhere else —
      // above all on the database — puts an unauthenticated surface on the host.
      expect(nginx?.ports).toHaveLength(1);
      expect(app?.ports).toBeUndefined();
      expect(db?.ports).toBeUndefined();
      expect(bootstrap?.ports).toBeUndefined();
      expect(dbInit?.ports).toBeUndefined();
      // The storage engine holds every document's ciphertext and speaks an S3 API
      // that authenticates with a static key pair. Published, it would be a
      // second front door to the deployment's data with none of the app's rate
      // limiting, CSRF or session handling in front of it.
      expect(s3?.ports).toBeUndefined();

      // ...and named services are not the rule. Enumerating them one by one is
      // how a seventh service arrives with a `ports:` block nobody asserted
      // against, so the closing claim is made over EVERY service the compose file
      // declares: exactly one of them publishes anything at all.
      const publishing = Object.entries(compose.services)
        .filter(([, service]) => (service?.ports ?? []).length > 0)
        .map(([name]) => name);
      expect(publishing).toEqual(['hvault-nginx']);
    });

    it('binds that port to 127.0.0.1, never 0.0.0.0', () => {
      // Without an explicit bind address Docker listens on every interface and
      // publishes the stack to the network, bypassing the host Nginx and its TLS.
      // Worse, it does so through the DOCKER iptables chain, which is evaluated
      // BEFORE INPUT — so the port stays reachable from the internet even with an
      // active `ufw deny`. The 127.0.0.1 prefix is the only thing that keeps the
      // stack private.
      const published = nginx?.ports?.[0] ?? '';
      expect(published.startsWith('127.0.0.1:')).toBe(true);
      expect(published.endsWith(':8080')).toBe(true);
    });
  });

  describe('operability', () => {
    it('rotates every container log, so a long deployment cannot fill the disk', () => {
      // The default json-file driver grows without bound. This is the classic
      // 3-a.m. outage: the stack runs fine for weeks and then the host's disk is
      // full — including the database's.
      for (const [name, service] of everyService) {
        expect(service?.logging?.driver, name).toBe('json-file');
        expect(service?.logging?.options?.['max-size'], name).toBeDefined();
        expect(service?.logging?.options?.['max-file'], name).toBeDefined();
      }
    });

    it('restarts every long-running service, and never the one-shot', () => {
      // Docker is the supervisor here (there is no pm2 inside a container), so the
      // restart policy is what brings the stack back after a crash or a host reboot.
      // The bootstrap is the exception: a restart policy on it would make
      // `service_completed_successfully` unreachable and the app would never start.
      for (const [name, service] of longRunning) {
        expect(service?.restart, name).toBe('unless-stopped');
      }
      expect(bootstrap?.restart).toBe('no');
    });

    it('gives the app a longer stop grace period than its own drain deadline', () => {
      // createGracefulShutdown force-destroys lingering connections at 30 s. Docker
      // must not SIGKILL the container before that has run, or every deploy severs
      // in-flight requests and any background job mid-write.
      const graceSeconds = Number(/^(\d+)s$/.exec(app?.stop_grace_period ?? '')?.[1] ?? 0);
      expect(graceSeconds).toBeGreaterThan(30);
    });

    it('runs an init in the Node containers — and NOT in MongoDB, which it breaks', () => {
      // The Node services need a reaper: without an init, node is PID 1, and PID 1
      // gets no default signal handlers, so a SIGTERM it has not explicitly wired up
      // is simply discarded.
      expect(app?.init).toBe(true);
      expect(bootstrap?.init).toBe(true);

      // MongoDB must NOT have one, and this is the regression guard for a change
      // that looks like tidying up. mongod is already a well-behaved PID 1 (the
      // entrypoint execs it through gosu and it handles SIGTERM by flushing and
      // shutting down cleanly). Putting Docker's init in front of it was MEASURED to
      // turn an ordinary `docker compose stop` into container exit code 1 — the
      // mongod log still reported a clean "mongod shutdown complete", but the
      // container's recorded exit code went 0 → 1, which is a false failure signal
      // in `docker compose ps`, in monitoring, and in exactly the moment you want to
      // know whether the database went down cleanly. Nginx is likewise left without
      // one: its master reaps its own workers, and it exits 0 either way.
      expect(db?.init).toBeUndefined();
      expect(nginx?.init).toBeUndefined();
      // The storage engine is a single static Rust binary that execs as PID 1 and
      // handles its own signals; it forks nothing, so there are no zombies for an
      // init to reap.
      expect(s3?.init).toBeUndefined();
    });

    it('tags its own images with the release, and the default tracks package.json', () => {
      // A rollback is `git checkout v<previous> && docker compose up -d --build`:
      // the old release's images are still on the host under their own tag. That
      // only works if the tag actually names the release — a default that drifted
      // from package.json would silently overwrite one version's image with
      // another's, and `docker compose ps` would lie about what is serving.
      for (const service of [app, nginx, bootstrap]) {
        // Everything after the FIRST colon: the tag is itself an interpolation that
        // contains colons (`${HVAULT_VERSION:-1.1.0}`), so a naive split loses it.
        const image = service?.image ?? '';
        const tag = image.slice(image.indexOf(':') + 1);
        expect(tag).toMatch(/^\$\{HVAULT_VERSION:-\d+\.\d+\.\d+\}$/);
        expect(interpolationDefault(tag)).toBe(rootPackageJson.version);
      }
      // ...and .env.example must carry the key, or a fresh clone silently takes the
      // fallback and never knows the knob exists.
      expect(envExample).toMatch(/^HVAULT_VERSION=/m);
      // The VALUE has to track package.json too, not merely be present. A release
      // that bumps the Compose defaults but leaves .env.example on the previous
      // version hands operators a file that pins the stack to the OLD tag: on a host
      // that still has the previous release's images, `docker compose up -d` then
      // serves the old stack and reports success.
      const envVersion = /^HVAULT_VERSION=(.*)$/m.exec(envExample)?.[1]?.trim();
      expect(envVersion).toBe(rootPackageJson.version);
    });

    it('namespaces the project AND the container names, so a second stack can coexist', () => {
      // Networks and volumes are namespaced by the Compose project automatically —
      // `container_name` is NOT. And the project name itself must be a variable: two
      // checkouts both claiming the project `hvault` do not collide loudly, they are
      // treated as the SAME project, so the second `up` recreates the first one's
      // containers and adopts its volumes. The README and .env.example actively invite
      // running several of these behind one system Nginx, so this has to work.
      expect(composeYaml).toMatch(/^name: \$\{HVAULT_STACK_NAME:-hvault\}$/m);
      for (const [label, service] of everyService) {
        expect(service?.container_name, label).toMatch(/^\$\{HVAULT_STACK_NAME:-hvault\}-/);
      }
      expect(envExample).toMatch(/^HVAULT_STACK_NAME=/m);
    });

    it('never ships a WORKING database password as a placeholder', () => {
      // A placeholder is a working password. `cp .env.example .env`, fill in the
      // secrets that shout at you, and the database root credential would be a literal
      // published in this repository — with nothing to tell you. Empty fails closed
      // instead: `${MONGO_ROOT_PASSWORD:?…}` rejects an empty value exactly as it
      // rejects a missing one, so `docker compose up` stops before a container exists.
      expect(envExample).toMatch(/^MONGO_ROOT_PASSWORD=$/m);
    });
  });

  describe('network segmentation', () => {
    it('keeps the data tier internal (no route to or from the internet)', () => {
      expect(compose.networks['data']?.internal).toBe(true);
      expect(compose.networks['edge']?.internal).not.toBe(true);
    });

    it('keeps Nginx off the data network, so it cannot reach MongoDB', () => {
      expect(networksOf(nginx)).toEqual(['edge']);
    });

    it('keeps MongoDB on the data network only', () => {
      expect(networksOf(db)).toEqual(['data']);
    });

    it('puts the app on both, as the only bridge between them', () => {
      expect(networksOf(app)).toEqual(expect.arrayContaining(['edge', 'data']));
    });

    it('pins the app default route to edge with gw_priority — NOT priority', () => {
      // The app is the one container on both tiers, so it is the one whose default
      // gateway decides how its outbound traffic (SMTP, the HIBP breach API) leaves.
      //
      // The field name is the entire finding here. `priority` only orders network
      // ATTACHMENTS and has no say in gateway selection; `gw_priority` is what
      // selects the default gateway. Measured on this stack, with `data` temporarily
      // made non-internal so it had a gateway at all:
      //
      //   edge: priority 100     -> default via the DATA gateway   (wrong)
      //   edge: gw_priority 100  -> default via the EDGE gateway   (right)
      //
      // So a test that merely asserted `edge > data` under `priority` would be
      // guarding a property that does not exist. Assert the field that works.
      expect(networkGwPriority(app, 'edge')).toBeTypeOf('number');
      expect(networkGwPriority(app, 'data')).toBeTypeOf('number');
      expect(networkGwPriority(app, 'edge') as number).toBeGreaterThan(
        networkGwPriority(app, 'data') as number,
      );
      // And make the wrong field's return fail the test if someone swaps it back.
      expect(networkPriority(app, 'edge')).toBeUndefined();
    });

    it('pins both subnets, but leaves them overridable per host', () => {
      // Pinned: an auto-allocated block lands wherever Docker's pool is free that
      // day. If it overlaps a network another project already created, forwarding
      // between this stack's own containers breaks in a way that mimics an
      // application bug — DNS resolves, ARP is answered, and the packets simply
      // never arrive.
      //
      // Overridable: these stacks are designed to sit several-to-a-host behind one
      // system Nginx, so a hard-coded block is not a theoretical collision. Docker
      // refuses to create an overlapping network outright ("Pool overlaps with other
      // one on this address space") and the second stack never starts.
      const edgeSubnet = compose.networks['edge']?.ipam?.config?.[0]?.subnet;
      const dataSubnet = compose.networks['data']?.ipam?.config?.[0]?.subnet;
      expect(edgeSubnet).toMatch(/^\$\{HVAULT_EDGE_SUBNET:-[\d.]+\/\d+\}$/);
      expect(dataSubnet).toMatch(/^\$\{HVAULT_DATA_SUBNET:-[\d.]+\/\d+\}$/);
      expect(interpolationDefault(edgeSubnet)).toMatch(/^\d+\.\d+\.\d+\.\d+\/\d+$/);
      expect(interpolationDefault(dataSubnet)).toMatch(/^\d+\.\d+\.\d+\.\d+\/\d+$/);
      expect(edgeSubnet).not.toBe(dataSubnet);
      // Both knobs must be discoverable, or an operator hitting a collision has no
      // way to know they exist short of reading the compose file.
      expect(envExample).toMatch(/^HVAULT_EDGE_SUBNET=/m);
      expect(envExample).toMatch(/^HVAULT_DATA_SUBNET=/m);
    });
  });

  describe('hvault-app', () => {
    it('is hardened: no-new-privileges, every capability dropped, read-only root', () => {
      expect(app?.security_opt).toContain('no-new-privileges:true');
      expect(app?.cap_drop).toContain('ALL');
      expect(app?.read_only).toBe(true);
      // Node listens on 5000 as a non-root user, so it needs no capability at all —
      // not even NET_BIND_SERVICE, which only matters below port 1024.
      expect(app?.cap_add).toBeUndefined();
    });

    it('pins tmpfs ownership to the non-root app user (the silent-restart bug)', () => {
      // @hiprax/logger creates a subdirectory for any module whose name contains a
      // slash (`jobs/trashCleanup` -> /app/logs/jobs). If the tmpfs root is owned by
      // root, the `node` user cannot mkdir into it and the logger throws during
      // module evaluation — before the app has installed any error handling. The
      // process then exits with code 0 and prints NOTHING: the container comes up
      // clean the first time and silently refuses to come back after any restart.
      const logsOpts = tmpfsOptions(app, '/app/logs');
      expect(logsOpts).toContain('uid=1000');
      expect(logsOpts).toContain('gid=1000');
      expect(logsOpts).toMatch(/mode=\d+/);

      const tmpOpts = tmpfsOptions(app, '/tmp');
      expect(tmpOpts).toContain('uid=1000');
      expect(tmpOpts).toContain('gid=1000');
    });

    it('bounds processes, memory and CPU', () => {
      expect(app?.pids_limit).toBeGreaterThanOrEqual(50);
      expect(app?.pids_limit).toBeLessThanOrEqual(1000);
      expect(app?.mem_limit).toBeDefined();
      expect(app?.cpus).toBeDefined();
    });

    it('runs an init, so SIGTERM reaches node and the drain completes', () => {
      expect(app?.init).toBe(true);
    });

    it('probes health silently, leaking no internals into `docker inspect`', () => {
      const probe = probeOf(app);
      expect(probe).toContain('catch(');
      expect(probe).toContain('process.exit(1)');
      expect(probe).not.toMatch(/console\.(log|error|warn)/);
    });

    it('exits the probe explicitly on success, rather than waiting for the event loop', () => {
      // An unconsumed fetch body leaves undici's pooled socket ref'd, so a probe that
      // just lets the event loop drain runs for as long as the keep-alive timer says —
      // a duration set by an HTTP library's connection-pool heuristics, not by the
      // app. A probe that overruns `timeout: 5s` is recorded as a FAILURE: retries
      // exhaust, Nginx (which gates on `service_healthy`) never starts, and
      // `up --wait` fails an entirely healthy stack.
      expect(probeOf(app)).toMatch(/process\.exit\(r\.ok\?0:1\)/);
      // The image's own HEALTHCHECK must agree — it is what a bare `docker run` gets.
      expect(dockerfile).toMatch(/HEALTHCHECK[\s\S]{0,200}process\.exit\(r\.ok\?0:1\)/);
    });

    it('takes its configuration from the single root .env', () => {
      // The "one .env for every package" contract: the file is handed to the
      // container wholesale, and only container-topology values are overridden.
      // There is no per-package env file anywhere in this repo, by design.
      expect(envFilePaths(app)).toContain('.env');
      expect(envFilePaths(bootstrap)).toContain('.env');
    });

    it('cannot boot on a default database password even with no .env present', () => {
      // The env file is `required: false`, so `docker compose config` still parses in
      // a checkout that has none. That is NOT a licence to boot on defaults: each
      // credential below is interpolated with a `${VAR:?…}` guard, which makes
      // Compose refuse to resolve the stack at all when the value is missing — the
      // failure happens before a container exists, and it names the variable.
      // Both passwords are covered: the app now authenticates with the scoped
      // MONGO_APP_PASSWORD, while root still guards the database and its
      // provisioning one-shot.
      expect(app?.environment?.['MONGODB_URI']).toMatch(/\$\{MONGO_APP_PASSWORD:\?/);
      expect(db?.environment?.['MONGO_INITDB_ROOT_PASSWORD']).toMatch(/\$\{MONGO_ROOT_PASSWORD:\?/);
      expect(dbInit?.environment?.['MONGO_ROOT_PASSWORD']).toMatch(/\$\{MONGO_ROOT_PASSWORD:\?/);
      expect(dbInit?.environment?.['MONGO_APP_PASSWORD']).toMatch(/\$\{MONGO_APP_PASSWORD:\?/);
    });

    it('overrides only the values the container topology fixes', () => {
      const env = app?.environment ?? {};
      expect(env['NODE_ENV']).toBe('production');
      expect(env['PORT']).toBe('5000');
      expect(env['MONGODB_URI']).toBeDefined();
    });

    it('pins the proxy hop count to exactly 2 — the number of proxies there are', () => {
      // Not `toBeDefined()`: this is the one number in the stack an attacker benefits
      // from directly. Express trusts the last N entries of X-Forwarded-For, so a
      // count HIGHER than the real number of proxies (2: the host's system Nginx, then
      // the stack's) means a client can prepend its own X-Forwarded-For entry and
      // become any IP it likes — defeating every IP-keyed rate limiter (login,
      // password reset, CSRF issuance) and poisoning the audit log. `true` would be
      // worse still: Express then trusts the leftmost entry outright.
      expect(app?.environment?.['TRUST_PROXY']).toBe('${TRUST_PROXY_HOPS:-2}');
      expect(envExample).toMatch(/^TRUST_PROXY_HOPS=2$/m);
    });

    it('gives the app enough memory for its heaviest legitimate request', () => {
      // The heaviest thing the app legitimately does is a 30 MB backup restore or
      // full-vault key rotation, which decrypts, re-encrypts and rewrites up to 10,000
      // items while still serving ordinary traffic.
      //
      // Node 24 is cgroup-aware — it sizes V8's heap from the CONTAINER's limit, not
      // the host's RAM — so this one number decides how much heap the app gets.
      // Measured in this image: 512m -> a 259 MB heap ceiling; 1g -> 560 MB. (The
      // familiar "V8 ignores the cgroup and takes gigabytes" only happens with NO
      // limit set at all, where the same image reports 4288 MB.) Hence no
      // `--max-old-space-size` here: pinning one under this limit would be a no-op at
      // best and would only shrink the headroom the limit exists to give.
      const limitMatch = /^(\d+)([mg])$/.exec(app?.mem_limit ?? '');
      const limitInMb = Number(limitMatch?.[1] ?? 0) * (limitMatch?.[2] === 'g' ? 1024 : 1);
      expect(limitInMb).toBeGreaterThanOrEqual(1024);
      expect(app?.environment?.['NODE_OPTIONS']).toBeUndefined();
    });

    it('connects to MongoDB as a replica set, so transactions are available', () => {
      // Without `replicaSet=rs0` the driver reports no replica set and every
      // transactional path (cascadeDeleteUser, bulkReEncrypt, changePassword,
      // refresh, deleteFolder) silently degrades to non-atomic sequential writes.
      const uri = app?.environment?.['MONGODB_URI'] ?? '';
      expect(uri).toContain('replicaSet=rs0');
      // The app authenticates as the least-privilege user, which is created IN
      // `hvault` — not as root, which lives in `admin`.
      expect(uri).toContain('authSource=hvault');
      // directConnection would force a Single topology and defeat the point: the set
      // advertises `hvault-db:27017`, which resolves inside the stack, so the driver
      // discovers the primary properly.
      expect(uri).not.toContain('directConnection');
    });

    it('authenticates as the scoped user, never as cluster root', () => {
      // The whole point of hvault-db-init. If a refactor ever points the app back
      // at MONGO_ROOT_*, a compromise of the app container regains admin over every
      // database — the failure this separation exists to prevent, and one that
      // nothing else in the suite would notice (no test authenticates to MongoDB).
      const appUri = app?.environment?.['MONGODB_URI'] ?? '';
      expect(appUri).not.toContain('MONGO_ROOT_PASSWORD');
      expect(appUri).not.toContain('MONGO_ROOT_USERNAME');
      expect(appUri).toMatch(/\$\{MONGO_APP_PASSWORD:\?/);

      // The bootstrap inherits the same URI through the YAML anchor; assert it
      // rather than assume, since the anchor could be overridden per-service.
      const bootstrapUri = bootstrap?.environment?.['MONGODB_URI'] ?? '';
      expect(bootstrapUri).toBe(appUri);

      // hvault-db-init is the ONLY non-database service that INTERPOLATES root.
      expect(JSON.stringify(dbInit?.environment ?? {})).toContain('MONGO_ROOT_PASSWORD');
    });

    it('scrubs the discrete MongoDB credentials out of the app and bootstrap containers', () => {
      // The subtle half of the least-privilege change, and the one a review caught
      // after the first pass shipped: `env_file: .env` injects EVERY key from the
      // single root .env into the container, INCLUDING the root credential that only
      // the database services need — so without an explicit override the app would
      // still carry MONGO_ROOT_PASSWORD in process.env, and an RCE could open a
      // fresh ROOT connection, defeating the entire point of the scoped user.
      // `environment:` is the only per-key override Compose offers over `env_file:`,
      // so the app-environment anchor blanks all four discrete MONGO_* creds. The
      // app reads only MONGODB_URI, so this is invisible to it. Verified on the live
      // container: `printenv MONGO_ROOT_PASSWORD` is empty.
      for (const [label, service] of [
        ['hvault-app', app],
        ['hvault-bootstrap', bootstrap],
      ] as const) {
        for (const key of [
          'MONGO_ROOT_USERNAME',
          'MONGO_ROOT_PASSWORD',
          'MONGO_APP_USERNAME',
          'MONGO_APP_PASSWORD',
        ]) {
          // Present-and-empty, not merely absent: absent would let `env_file`'s
          // value through, which is exactly the bug. The empty string is what
          // overrides it.
          expect(service?.environment, `${label}.${key}`).toHaveProperty(key, '');
        }
      }
      // Nginx never joins the data network and needs no database credential at all.
      expect(JSON.stringify(nginx?.environment ?? {})).not.toContain('MONGO_ROOT_PASSWORD');
    });

    it("scrubs the storage engine's cluster RPC secret out of the app and bootstrap too", () => {
      // Exactly the same mechanism as the four MongoDB credentials above, for
      // exactly the same reason: `env_file: .env` injects EVERY key, and
      // S3_RPC_SECRET is the storage engine's CLUSTER secret — the credential that
      // lets a peer join the storage cluster and read every stored block, bypassing
      // the S3 API and its bucket key entirely. Only hvault-s3 has any business
      // holding it. The app never reads it (the server's Zod schema deliberately
      // does not declare it), so blanking it is invisible to the application.
      //
      // Present-and-empty, not merely absent: absent lets `env_file`'s value
      // through, which is the bug.
      for (const [label, service] of [
        ['hvault-app', app],
        ['hvault-bootstrap', bootstrap],
      ] as const) {
        expect(service?.environment, `${label}.S3_RPC_SECRET`).toHaveProperty('S3_RPC_SECRET', '');
      }
      // ...and the one service that DOES read it interpolates the same key.
      expect(s3?.environment?.['GARAGE_RPC_SECRET']).toMatch(/\$\{S3_RPC_SECRET:\?/);
    });

    it('pins the storage endpoint at the in-stack service, so the config cannot be partial', () => {
      // S3_ENDPOINT is container topology, exactly like MONGODB_URI: .env cannot
      // know the in-stack address, and the app validates the four connection
      // variables ALL-OR-NONE, throwing in production on a partial set. The stack
      // guards the other three with `${...:?}`, so an operator who fills in only
      // what Compose demands would otherwise hand the app three of four and watch
      // it refuse to boot.
      //
      // Plain http is correct here and is not an oversight: `hvault-s3` is a
      // single-label host on an `internal: true` network, which is one of the three
      // shapes isProductionStorageEndpoint accepts precisely so that two containers
      // on a private bridge are not asked to terminate TLS to each other.
      expect(app?.environment?.['S3_ENDPOINT']).toBe('http://hvault-s3:3900');
      // The negative the exact match does not give: .env.example must NOT ship a
      // value for the same key. `environment:` silently outranks `env_file:`, so a
      // populated S3_ENDPOINT there is a setting an operator can edit, redeploy,
      // and watch have no effect whatsoever.
      expect(envExample).toMatch(/^S3_ENDPOINT=$/m);
    });

    it('provisions the scoped user from a gated, egress-less one-shot', () => {
      // Ordering: createUser is a WRITE, so it needs a writable primary — which is
      // exactly what hvault-db's healthcheck proves before this is allowed to run.
      expect(dbInit?.depends_on?.['hvault-db']?.condition).toBe('service_healthy');
      // One-shot. A restart policy would make `service_completed_successfully`
      // unreachable and wedge every service gating on it.
      expect(dbInit?.restart).toBe('no');
      // It holds root, so it must not be able to reach the internet.
      expect(networksOf(dbInit)).toEqual(['data']);
      expect(dbInit?.ports).toBeUndefined();
      // Neither secret may be passed on the command line, where `docker inspect`
      // and the process table would expose it — the script reads them from env.
      const entrypoint = [dbInit?.entrypoint ?? []].flat().join(' ');
      expect(entrypoint).toContain('provision-app-user.js');
      expect(entrypoint).not.toContain('--password');
      expect(entrypoint).not.toContain('--username');
      // ...and the bootstrap must wait for the user to exist before authenticating.
      expect(bootstrap?.depends_on?.['hvault-db-init']?.condition).toBe(
        'service_completed_successfully',
      );
    });

    it('ships the app-user password key in .env.example, empty so it fails closed', () => {
      // Mirrors the MONGO_ROOT_PASSWORD check: a placeholder would be a working
      // database credential published in this repository.
      expect(envExample).toMatch(/^MONGO_APP_PASSWORD=$/m);
      expect(envExample).toMatch(/^MONGO_APP_USERNAME=/m);
    });

    it('waits for the index bootstrap to finish before it starts', () => {
      // Production disables autoIndex, so nothing creates indexes implicitly. The
      // Folder (userId, searchHash) UNIQUE partial index is what makes duplicate
      // detection return 409, and the AuditLog / RefreshToken TTL indexes are what
      // bound those collections — an app started without them looks healthy and
      // quietly loses both guarantees.
      expect(app?.depends_on?.['hvault-bootstrap']?.condition).toBe(
        'service_completed_successfully',
      );
      expect(app?.depends_on?.['hvault-db']?.condition).toBe('service_healthy');
    });

    it('waits for storage to START, never for it to be HEALTHY', () => {
      // The one-word difference is a blast-radius decision, and it is invisible
      // in a diff: `service_healthy` reads like the safer choice and is the
      // opposite. Documents are an OPTIONAL feature. Gate the app on storage
      // HEALTH and a storage engine that is slow, wedged or misconfigured holds
      // `up --wait` and then fails it — on a stack whose logins, items and folders
      // are perfectly fine. A password manager must not be taken down by the
      // service that holds its attachments.
      //
      // `service_started` still preserves ORDERING, which is all that is wanted,
      // and the engine still HAS a healthcheck: the deploy drill's
      // SERVICE_EXPECTATIONS demands `healthy` there, deliberately stricter than
      // this, because "did the deployment come up correctly" is a different
      // question from "may the app start".
      expect(app?.depends_on?.['hvault-s3']?.condition).toBe('service_started');

      // ...and the index bootstrap has NO dependency on storage at all. It
      // creates MongoDB indexes and never makes a storage call, so a dependency
      // there would be coupling with no purpose — and it would put storage on the
      // critical path of `service_completed_successfully`, which the app DOES gate
      // on, quietly undoing the decision above by another route.
      expect(bootstrap?.depends_on).not.toHaveProperty('hvault-s3');
      expect(Object.keys(bootstrap?.depends_on ?? {})).toEqual(
        expect.arrayContaining(['hvault-db', 'hvault-db-init']),
      );
    });
  });

  describe('hvault-bootstrap (one-shot index creation)', () => {
    it('never restarts, so `service_completed_successfully` stays reachable', () => {
      expect(bootstrap?.restart).toBe('no');
    });

    it('runs on the data network only — it needs no egress', () => {
      expect(networksOf(bootstrap)).toEqual(['data']);
    });

    it('is hardened like the app, despite living for only two seconds', () => {
      // This image carries the whole devDependency tree (it runs the TypeScript
      // create-indexes script through tsx), which makes it the widest attack surface
      // in the stack — and it holds root MongoDB credentials while it runs. A
      // short life is not a reason to exempt it.
      expect(bootstrap?.security_opt).toContain('no-new-privileges:true');
      expect(bootstrap?.cap_drop).toContain('ALL');
      expect(bootstrap?.cap_add).toBeUndefined();
      expect(bootstrap?.read_only).toBe(true);

      // Everything it writes goes to a tmpfs owned by its non-root user: the log
      // directory @hiprax/logger mkdirs at module scope from
      // cwd=/app/packages/server, and a general-purpose /tmp.
      //
      // `npm_config_cache` is deliberately GONE, and asserted gone: the image
      // ships no npm any more, so an env var pointing npm's cache at a tmpfs
      // describes a tool that is not there. Leaving it would read as though the
      // package manager were still expected.
      expect(bootstrap?.environment?.['npm_config_cache']).toBeUndefined();
      expect(tmpfsOptions(bootstrap, '/tmp')).toContain('uid=1000');
      expect(tmpfsOptions(bootstrap, '/app/packages/server/logs')).toContain('uid=1000');
    });

    it('waits for a writable primary before it creates indexes', () => {
      expect(bootstrap?.depends_on?.['hvault-db']?.condition).toBe('service_healthy');
    });

    it('owns a writable log directory before dropping to the non-root user', () => {
      // The bootstrap runs with cwd = /app/packages/server (an explicit WORKDIR
      // now; it used to be npm's `-w` doing it implicitly), and the script
      // imports src/config, which calls createLogger() at MODULE
      // SCOPE. @hiprax/logger eagerly mkdirs `<cwd>/logs` and THROWS if it cannot —
      // and /app/packages/server is root-owned (COPY runs as root), so uid 1000
      // gets EACCES, the bootstrap exits non-zero, and the app's
      // `service_completed_successfully` gate never opens: the whole stack is dead.
      //
      // It hid for a long time because a developer's machine usually has a stale
      // packages/server/logs/ from a local `npm run dev`, and mkdir on an existing
      // directory succeeds even without write permission. A fresh clone has none.
      expect(dockerfile).toMatch(
        /RUN mkdir -p \/app\/packages\/server\/logs && chown -R node:node \/app\/packages\/server\/logs/,
      );
      // ...and the host's own logs must never be copied in (which is what masked it).
      const dockerignore = readFileSync(path.join(repoRoot, '.dockerignore'), 'utf-8');
      expect(dockerignore).toMatch(/^\*\*\/logs$/m);
      expect(dockerignore).not.toMatch(/^logs$/m);
    });

    it('never bakes a .env into the image, at ANY depth', () => {
      // The bootstrap image derives from `build-server`, which does
      // `COPY packages/server ./packages/server`. A bare `.env` pattern in
      // .dockerignore is matched against the whole context-relative path, so it
      // excludes ONLY the root `.env` — and `packages/server/.env` (a real,
      // gitignored local config holding JWT and session secrets) was copied into the
      // layer, readable by anyone who could pull the image.
      //
      // Same class of bug as the bare `logs` above, and the reason both are asserted
      // here rather than merely commented in the file.
      const dockerignore = readFileSync(path.join(repoRoot, '.dockerignore'), 'utf-8');
      expect(dockerignore).toMatch(/^\*\*\/\.env$/m);
      expect(dockerignore).toMatch(/^\*\*\/\.env\.\*$/m);
      expect(dockerignore).not.toMatch(/^\.env$/m);
      expect(dockerignore).not.toMatch(/^\.env\.\*$/m);
      // A stray Rule-1 style `.tmp` backup must not ride in either.
      expect(dockerignore).toMatch(/^\*\*\/\*\.tmp$/m);
      expect(dockerignore).not.toMatch(/^\*\.tmp$/m);
    });
  });

  describe('hvault-db', () => {
    it('passes a key file, without which mongod REFUSES TO BOOT', () => {
      // Authentication plus a replica set is exactly the combination H-Vault needs,
      // and mongod rejects it outright without a key file:
      //   "BadValue: security.keyFile is required when authorization is enabled with
      //    replica sets"
      // The key is generated on first boot by the image's entrypoint wrapper.
      const command = [db?.command ?? []].flat().join(' ');
      expect(command).toContain('--replSet');
      expect(command).toContain('rs0');
      expect(command).toContain('--keyFile');
    });

    it('persists the key file, so the set keeps the identity it was initiated with', () => {
      const volumes = db?.volumes ?? [];
      expect(volumes.some((v) => v.includes('/data/configdb'))).toBe(true);
      expect(volumes.some((v) => v.includes('/data/db'))).toBe(true);
    });

    it('runs the current MongoDB LTS (8.0), not the previous one', () => {
      // 8.0 is supported to 2029-10-31; 7.0 runs out on 2027-08-31. A password
      // manager's datastore should not be the thing that drops out of security
      // support first.
      expect(mongoDockerfile).toMatch(/^FROM mongo:8\.0$/m);
      expect(db?.image).toMatch(/^hvault-db:8\.\d+$/);
    });

    it('carries the rseq tunable MongoDB 8.x needs on Linux 6.19+ (Ubuntu 26.04)', () => {
      // SERVER-121912, and on the 8.0 image above this is LOAD-BEARING, not
      // insurance. MongoDB 8.0 moved TCMalloc to per-CPU caches, and that TCMalloc
      // drives them with restartable sequences in a way that violates the rseq ABI
      // as it changed in kernel 6.19: mongod's startup self-check aborts, and
      // `restart: unless-stopped` turns that into an endless crash loop with no hint
      // of the cause. Still unpatched upstream.
      //
      // 0 is mongod's own default and exactly the value that breaks, so it must be 1.
      expect(db?.environment?.['GLIBC_TUNABLES']).toBe('glibc.pthread.rseq=1');
    });

    it('sets that tunable at EVERY mongod launch site in the repo, enumerated not listed', () => {
      // `npm test`, the E2E harness and the smoke gate all spawn a REAL mongod
      // (mongodb-memory-server downloads the binary), so a developer or CI box on
      // Ubuntu 26.04 hits the same abort — a compose-only fix leaves the test suite
      // unrunnable on a modern kernel, which is exactly the kind of half-fix that
      // gets rediscovered a year later.
      //
      // This test used to be a LIST: two Node harnesses by name, and it was named
      // "EVERY launch site" while missing `scripts/ci/smoke-gate.mjs`, which spawns
      // a mongod of its own. Proved, before it was rewritten, by deleting that
      // gate's tunable call outright and watching this test pass. So both halves
      // below DISCOVER their launch sites and then check each one; the literal names
      // that remain are a FLOOR — they exist so a discovery pattern that stops
      // matching is a red test rather than a vacuous green one — and a fourth site
      // is checked when it appears, with no edit here.
      //
      // "When it appears" is a claim about the discovery patterns, so read what
      // each one actually keys on before trusting it. The container half PARSES the
      // compose files rather than grepping them, and classifies from the effective
      // entrypoint+command (see `startsMongod` below) rather than from the presence
      // of the word `mongod`, so a service that passes mongod its flags through
      // `command:` is caught while `hvault-db-init` — the mongo IMAGE running
      // `mongosh` — is correctly not one. The Node half keys on a VALUE IMPORT of
      // the memory-server package, which an aliased import cannot dodge, and not on
      // the construction call, which it trivially could.
      //
      // What neither half reaches, stated so a green run is not read as more than
      // it is: a mongod started by something other than that package (a raw
      // `spawn('mongod')`, or a `docker run` inside a future gate) is outside both
      // mechanisms, and so is a compose file living outside the repository root.
      //
      // Note for a future editor: the container half is checked from the parsed
      // compose files rather than from a substring, so a service that starts a
      // mongod under an overridden entrypoint is still caught, and `hvault-db-init`
      // — the mongo IMAGE running `mongosh`, not mongod — is correctly not one.

      // ── 1. Container launch sites ──────────────────────────────────────────
      const composeFiles = readdirSync(repoRoot)
        .filter((name) => /^docker-compose(?:\..+)?\.ya?ml$/.test(name))
        .sort();
      expect(composeFiles).toEqual(
        expect.arrayContaining(['docker-compose.yml', 'docker-compose.dev.yml']),
      );

      /**
       * Whether a compose service actually starts a mongod.
       *
       * The asymmetry between `command` and `entrypoint` is the whole of it, and
       * getting it backwards is how a real service escapes. Compose's `entrypoint`
       * REPLACES the image's; `command` only replaces its CMD. On a mongo image —
       * whose ENTRYPOINT chain ends in `exec mongod` (this repo's
       * `docker/mongo.Dockerfile` execs the official one) — a `command:` is
       * therefore read as ARGUMENTS TO mongod, not as a different program. So the
       * ordinary shape
       *
       *     hvault-db:
       *       image: hvault-db:8.0
       *       command: ["--replSet", "rs0", "--bind_ip_all"]
       *
       * launches a mongod while containing no `mongod` token anywhere. An earlier
       * draft of this helper bailed out on any non-empty `command`, which excluded
       * exactly that service and left its missing tunable checked by nothing.
       *
       * The rule is therefore: name `mongod` and you are one; otherwise, be a mongo
       * image and let the image's own entrypoint run, and you are one. Only an
       * `entrypoint` naming a DIFFERENT program takes you out — which is what
       * `hvault-db-init` does with `mongosh`, and why it is correctly not a mongod
       * launch site despite being built from the same Dockerfile.
       */
      const startsMongod = (service: ServiceConfig): boolean => {
        const flat = (value: string[] | string | undefined): string =>
          Array.isArray(value) ? value.join(' ') : (value ?? '');
        const entrypoint = flat(service.entrypoint);
        const command = flat(service.command);
        if (/\bmongod\b/.test(`${entrypoint} ${command}`)) return true;

        const dockerfile =
          typeof service.build === 'object' ? (service.build.dockerfile ?? '') : '';
        const isMongoImage = /^mongo(?::|$)/.test(service.image ?? '') || /mongo/i.test(dockerfile);
        if (!isMongoImage) return false;

        // An `entrypoint` that names another program is the only thing that stops a
        // mongo image being a mongod. Listed rather than inferred, because guessing
        // from "is it an absolute path" would classify a wrapper script — which is
        // how THIS repo's image starts mongod — as not-mongod.
        const ANOTHER_PROGRAM =
          /\b(?:mongosh|mongo|bash|sh|node|npm|npx|python[23]?|mongodump|mongorestore|mongoexport|mongoimport|sleep|true)\b/;
        return !(entrypoint !== '' && ANOTHER_PROGRAM.test(entrypoint));
      };

      const containerSites: string[] = [];
      const misconfigured: string[] = [];
      for (const file of composeFiles) {
        const parsed = parse(readFileSync(path.join(repoRoot, file), 'utf-8'), {
          merge: true,
        }) as ComposeConfig;
        for (const [name, service] of Object.entries(parsed.services)) {
          if (!service || !startsMongod(service)) continue;
          const site = `${file} → ${name}`;
          containerSites.push(site);
          // The literals, not the shared constant: a test that imports the value it
          // is checking agrees with the code by construction and would accept a
          // wrong-but-consistent change. 0 is mongod's own default and exactly the
          // value that breaks, so it must be 1.
          const tunables = service.environment?.['GLIBC_TUNABLES'] ?? '';
          if (
            !tunables.includes('glibc.pthread.rseq=1') ||
            tunables.includes('glibc.pthread.rseq=0')
          ) {
            misconfigured.push(`${site} — GLIBC_TUNABLES=${tunables || '<unset>'}`);
          }
        }
      }
      expect(
        misconfigured,
        'these compose services start a mongod that will abort at startup on any ' +
          'Linux 6.19+ kernel, and `restart: unless-stopped` turns that into a silent ' +
          'crash loop',
      ).toEqual([]);
      expect(containerSites).toEqual(
        expect.arrayContaining([
          'docker-compose.yml → hvault-db',
          'docker-compose.dev.yml → hvault-db',
        ]),
      );

      // ── 2. Node launch sites ───────────────────────────────────────────────
      // Every file in the repository that constructs an in-memory mongod. There are
      // three, in three different tiers, reached by three different runners, and the
      // point of discovering them is that a fourth cannot be added quietly.
      const SKIP_DIRS = new Set([
        '.git',
        '.cache',
        '.husky',
        '.orchestrator',
        '.stryker-tmp',
        '.testfortress',
        'coverage',
        'dev-dist',
        'dist',
        'node_modules',
        'playwright-report',
        'test-results',
      ]);
      const SCANNED = /\.(?:tsx?|mjs|cjs|js)$/;
      const walk = (dir: string, out: string[] = []): string[] => {
        for (const entry of readdirSync(dir, { withFileTypes: true })) {
          if (entry.isDirectory()) {
            if (SKIP_DIRS.has(entry.name)) continue;
            walk(path.join(dir, entry.name), out);
          } else if (entry.isFile() && SCANNED.test(entry.name)) {
            out.push(path.join(dir, entry.name));
          }
        }
        return out;
      };

      const scanned = walk(repoRoot);
      // The denominator: a walker that silently found nothing satisfies every
      // per-file assertion below while proving nothing at all.
      expect(scanned.length).toBeGreaterThan(400);

      /**
       * A file that can spawn a mongod, and the criterion is the IMPORT rather
       * than the construction.
       *
       * Matching the class name beside its `create` call was the first draft, and
       * it is one `as` away from useless: an aliased import followed by
       * `Mem.create(…)` contains neither literal, so a fourth launch site could
       * have been added with the tunable missing and this test would not even
       * have listed it. A VALUE import of the package cannot be hidden that way —
       * the specifier is a string and the module is the only way to reach the
       * class. `import type` is excluded because a type has no runtime and spawns
       * nothing, which is exactly what `tests/setup.ts` and
       * `tests/recovery/restore-drill.test.ts` do (both reach mongod through
       * `mongoHarness.ts` instead). The construction forms are kept beside it as
       * a second net, so a file that re-exports or lazily requires the class is
       * still caught.
       *
       * Known edge: an inline `{ type X }` import specifier is a value import
       * syntactically and would be listed here. That is a false RED naming the
       * file, which someone resolves in a minute — the opposite failure, a launch
       * site that is silently never checked, is the one this test exists for.
       *
       * And a warning for whoever edits these comments: this file is inside the
       * tree the walk below covers, so writing the package specifier or the class
       * name beside its `create` call in PROSE makes this file discover ITSELF and
       * go red. That is not hypothetical — it happened while this paragraph was
       * being written. Describe the patterns; do not spell them out.
       */
      const CONSTRUCTS =
        /^\s*import\s+(?!type\b)[^;]*from\s*['"]mongodb-memory-server['"]|(?:import|require)\s*\(\s*['"]mongodb-memory-server['"]\s*\)|MongoMemory(?:Server|ReplSet)\s*\.\s*create\s*\(|new\s+MongoMemory(?:Server|ReplSet)\s*\(/m;
      /** The applier, called at MODULE SCOPE — unindented, so no branch can strand it. */
      const APPLIED_AT_MODULE_SCOPE = /^appl(?:yMongoKernelCompat|yRseqTunable)\(\);$/m;
      /** Reached from one of the two shared modules, never hand-copied again. */
      const FROM_SHARED = /from '[^']*(?:mongoKernelCompat\.js|mongo-rseq\.mjs)';/;

      const nodeSites: string[] = [];
      const unprotected: string[] = [];
      for (const file of scanned) {
        const contents = readFileSync(file, 'utf-8');
        if (!CONSTRUCTS.test(contents)) continue;
        const rel = path.relative(repoRoot, file).split(path.sep).join('/');
        nodeSites.push(rel);
        if (!APPLIED_AT_MODULE_SCOPE.test(contents) || !FROM_SHARED.test(contents)) {
          unprotected.push(rel);
        }
      }

      expect(
        unprotected,
        'these files spawn a mongod without applying the rseq tunable from the shared ' +
          'merge (scripts/ci/lib/mongo-rseq.mjs) at module scope — mongod will abort at ' +
          'startup on any Linux 6.19+ kernel',
      ).toEqual([]);

      // The floor. `mongoHarness.ts` is the one that matters most: it constructs
      // BOTH the standalone every test file gets and the replica set the
      // transaction branches need, for every vitest config in the repository.
      expect(nodeSites.sort()).toEqual(
        expect.arrayContaining([
          'e2e/start-server.ts',
          'packages/server/tests/mongoHarness.ts',
          'scripts/ci/smoke-gate.mjs',
        ]),
      );
    });

    it('keeps no-new-privileges and drops all but the capabilities gosu needs', () => {
      // The official entrypoint starts as root, fixes ownership on the data volume
      // and the key file, then drops to the `mongodb` user with gosu. Dropping ALL
      // without adding these back makes setuid fail and the container never starts.
      expect(db?.security_opt).toContain('no-new-privileges:true');
      expect(db?.cap_drop).toContain('ALL');
      expect(db?.cap_add).toEqual(
        expect.arrayContaining(['CHOWN', 'FOWNER', 'DAC_OVERRIDE', 'SETUID', 'SETGID']),
      );
      // Notably absent: NET_RAW, SYS_CHROOT, MKNOD, SETFCAP, SETPCAP.
      expect(db?.cap_add).not.toContain('NET_RAW');
      expect(db?.cap_add).not.toContain('SYS_ADMIN');
    });

    it('bounds processes, memory and CPU', () => {
      expect(db?.pids_limit).toBeGreaterThanOrEqual(100);
      expect(db?.pids_limit).toBeLessThanOrEqual(2000);
      expect(db?.mem_limit).toBeDefined();
      expect(db?.cpus).toBeDefined();
    });

    it('probes health silently, with credentials read from its own environment', () => {
      const probe = probeOf(db);
      // `$$` is Compose's escape for a literal `$`: the shell inside the container
      // expands it, so the password never appears in what `docker inspect` shows.
      expect(probe).toContain('$$MONGO_INITDB_ROOT_PASSWORD');
      // The set must advertise the SERVICE NAME. Initiating it as `localhost:27017`
      // leaves the primary unreachable from every other container in the stack.
      expect(probe).toContain('hvault-db:27017');
      // Healthy only once this node is actually a writable primary — i.e. once
      // transactions are available.
      expect(probe).toContain('isWritablePrimary');
      expect(probe).toContain('/dev/null');
    });
  });

  describe('hvault-nginx', () => {
    it('is hardened and needs no capability at all', () => {
      // nginx-unprivileged runs as uid 101 on port 8080, so it needs neither root
      // nor NET_BIND_SERVICE.
      expect(nginx?.security_opt).toContain('no-new-privileges:true');
      expect(nginx?.cap_drop).toContain('ALL');
      expect(nginx?.cap_add).toBeUndefined();
      expect(nginx?.read_only).toBe(true);
    });

    it('starts only once the app is healthy', () => {
      expect(nginx?.depends_on?.['hvault-app']?.condition).toBe('service_healthy');
    });

    it('probes health THROUGH the proxy, so a green check proves the whole path', () => {
      expect(probeOf(nginx)).toContain('/api/v1/health');
    });

    it('pins its tmpfs to uid 101, the unprivileged user the image actually runs as', () => {
      // nginx-unprivileged relocates its pid file and every temp path under /tmp. A
      // tmpfs its user cannot write to is a boot failure — and, as with the app's
      // /app/logs, one that only shows up on a RESTART, long after the deploy looked
      // fine.
      const tmpOpts = tmpfsOptions(nginx, '/tmp');
      expect(tmpOpts).toContain('uid=101');
      expect(tmpOpts).toContain('gid=101');
    });

    it('is stopped with SIGQUIT, because nginx SIGTERM is the FAST (severing) shutdown', () => {
      // nginx has its signals the opposite way round from almost everything else:
      // SIGTERM — Docker's default — is the fast shutdown that closes every open
      // connection immediately; SIGQUIT is the graceful one that lets in-flight
      // requests finish. Left at the default, a deploy that recreates this container
      // guillotines whatever is passing through it, and what passes through it
      // includes the long operations internal.conf sets `proxy_read_timeout 300s`
      // for: a full-vault key rotation, a 30 MB backup restore. The app behind it was
      // given a 40 s drain window precisely so those can finish; without this line the
      // front door does not honour it.
      expect(nginx?.stop_signal).toBe('SIGQUIT');
      const graceSeconds = Number(/^(\d+)s$/.exec(nginx?.stop_grace_period ?? '')?.[1] ?? 0);
      expect(graceSeconds).toBeGreaterThanOrEqual(30);
    });
  });

  describe('hvault-s3 (object storage for the document store)', () => {
    it('pins the image by DIGEST as well as by tag, because this one is not built here', () => {
      // Every other image in the stack is a `docker build` target from this
      // repository, so its contents are decided by this checkout. This one is
      // pulled. A tag is a mutable pointer — the publisher can move `v2.3.0` onto
      // different bytes at any time, and nothing in a `docker compose up` would
      // notice — so the digest is what actually pins what runs. Both are kept: the
      // tag is what a human reads, the digest is what Docker enforces.
      const image = s3?.image ?? '';
      expect(image).toMatch(/^dxflrs\/garage:v\d+\.\d+\.\d+@sha256:[0-9a-f]{64}$/);
      // The negative that the regex above does NOT give for free: no OTHER
      // reference to this image anywhere in the file may lack the digest. A
      // second, un-pinned mention — a comment someone copies, an override, a
      // future sidecar — is how the pin stops being the thing that runs.
      const references = composeYaml.match(/dxflrs\/garage:[^\s'"]+/g) ?? [];
      expect(references.length).toBeGreaterThan(0);
      expect(references.filter((reference) => !reference.includes('@sha256:'))).toEqual([]);
    });

    it('is the same image the storage conformance harness starts, read from this very file', () => {
      // `test:storage` stands this engine up outside Compose, in a bare
      // container, and runs the storage port against it. That gate is only worth
      // anything while the engine it starts is the engine the stack runs, so the
      // harness READS the reference out of this file rather than carrying its
      // own copy — a literal there would be a second definition that the digest
      // pin above does not cover, and the conformance suite could go on passing
      // against an image the deployment stopped using.
      //
      // The harness cannot use a YAML parser (`yaml` is a devDependency of this
      // package alone, and the end-to-end harness at the repository root imports
      // the same module), so it scans the file by indentation. This is the
      // assertion that keeps that scan honest: what it returns must equal what a
      // real parser reads.
      expect(STORAGE_COMPOSE_SERVICE).toBe('hvault-s3');
      expect(resolveComposeImage()).toBe(s3?.image);
      // And the negative: the scan must not silently answer for some other
      // service when the one it names is gone, which is how it would keep
      // returning an image after the service was renamed.
      expect(() => resolveComposeImage('hvault-no-such-service')).toThrow(/no service named/);
    });

    it('runs the provisioning flags that make the bucket exist without an operator step', () => {
      // The promise this service exists to keep is that `docker compose up` brings
      // the document store up ALREADY PROVISIONED: no bucket to create by hand, no
      // access key to mint, no storage step in the setup instructions.
      // `--single-node` writes the cluster layout on first boot; `--default-bucket`
      // creates the bucket from GARAGE_DEFAULT_BUCKET and IMPLIES
      // `--default-access-key`, which mints the key pair from the other two
      // variables. Both of the latter require `--single-node`, so dropping it
      // silently removes the provisioning rather than failing loudly.
      const command = [s3?.command ?? []].flat().join(' ');
      expect(command).toContain('--single-node');
      expect(command).toContain('--default-bucket');
      // The image's own CMD is `/garage server` with an EMPTY entrypoint, so the
      // entrypoint is spelled out and the command reads as a whole command rather
      // than as an append to something invisible.
      expect([s3?.entrypoint ?? []].flat().join(' ')).toBe('/garage');
      expect(command.startsWith('server ')).toBe(true);
    });

    it('maps the engine variables onto the SAME .env keys the app reads', () => {
      // Two independent key names for one credential is how an operator ends up
      // with an app that 403s against its own bucket and no diagnostic to explain
      // it: they rotate S3_ACCESS_KEY_ID, the engine keeps minting the old
      // GARAGE_DEFAULT_ACCESS_KEY, and both halves look correctly configured. One
      // value driving both sides makes that impossible, which is also why there is
      // no GARAGE_* key anywhere in .env.example.
      const env = s3?.environment ?? {};
      expect(env['GARAGE_DEFAULT_ACCESS_KEY']).toMatch(/\$\{S3_ACCESS_KEY_ID:\?/);
      expect(env['GARAGE_DEFAULT_SECRET_KEY']).toMatch(/\$\{S3_SECRET_ACCESS_KEY:\?/);
      expect(env['GARAGE_DEFAULT_BUCKET']).toMatch(/\$\{S3_BUCKET:\?/);
      expect(envExample).not.toMatch(/^GARAGE_/m);
    });

    it('cannot boot on an empty storage credential, and ships all four empty', () => {
      // Same fail-closed contract as the database passwords: `${VAR:?…}` makes
      // Compose refuse to RESOLVE the stack when the value is missing or empty, so
      // the failure happens before a container exists and it names the variable.
      // A placeholder in .env.example would be a working bucket credential
      // published in this repository, with nothing to tell the operator.
      //
      // BOTH halves of the title are asserted here, deliberately. The guard on its
      // own is satisfied by an example file that ships a working value, and an
      // empty example on its own is satisfied by a `${VAR:-default}` that quietly
      // substitutes one — it is the PAIR that fails closed, so the pair is pinned
      // in one place rather than split across two tests that each look complete.
      const guarded: Record<string, string | undefined> = {
        S3_BUCKET: s3?.environment?.['GARAGE_DEFAULT_BUCKET'],
        S3_ACCESS_KEY_ID: s3?.environment?.['GARAGE_DEFAULT_ACCESS_KEY'],
        S3_SECRET_ACCESS_KEY: s3?.environment?.['GARAGE_DEFAULT_SECRET_KEY'],
        S3_RPC_SECRET: s3?.environment?.['GARAGE_RPC_SECRET'],
      };
      for (const [key, interpolation] of Object.entries(guarded)) {
        expect(envExample, key).toMatch(new RegExp(`^${key}=$`, 'm'));
        // `:?` and not `:-`. The colon is what makes it reject an EMPTY value as
        // well as a missing one, and `.env.example` ships every one of these empty.
        expect(interpolation, key).toMatch(new RegExp(`^\\$\\{${key}:\\?`));
      }
    });

    it('is hardened: no-new-privileges, every capability dropped, read-only root', () => {
      expect(s3?.security_opt).toContain('no-new-privileges:true');
      expect(s3?.cap_drop).toContain('ALL');
      expect(s3?.read_only).toBe(true);
      // It listens on 3900/3901, both unprivileged, so it needs no capability at
      // all — not even NET_BIND_SERVICE.
      expect(s3?.cap_add).toBeUndefined();
    });

    it('gives the read-only root a writable /tmp, WITHOUT pinning it to a uid', () => {
      // The opposite of the app's and Nginx's tmpfs rule, and the reason it gets
      // its own assertion rather than being folded into theirs. Those two images
      // declare a non-root USER (1000 and 101), so a root-owned tmpfs is one their
      // process cannot write and the container dies silently on its first restart.
      // This image declares NO user, so the process IS root inside the container
      // and a `uid=1000` pin here would reproduce that same failure from the other
      // direction.
      const tmpOpts = tmpfsOptions(s3, '/tmp');
      expect(tmpOpts).toMatch(/size=\d+m/);
      expect(tmpOpts).not.toContain('uid=');
    });

    it('bounds processes, memory and CPU', () => {
      // Idle footprint is ~6 MiB, so 512 MB is headroom rather than a target; the
      // point of the bound is that a leak or a compromise cannot take the host down
      // with it.
      expect(s3?.pids_limit).toBeGreaterThanOrEqual(50);
      expect(s3?.pids_limit).toBeLessThanOrEqual(1000);
      expect(s3?.mem_limit).toBeDefined();
      expect(s3?.cpus).toBeDefined();
    });

    it('probes health in EXEC form, because the image ships no shell', () => {
      // A `CMD-SHELL` probe on a scratch-style image does not fail loudly — it
      // fails as "unhealthy", forever, and the stack never finishes coming up.
      // Compose's list form with a leading `CMD` is what runs the binary directly.
      const test = [s3?.healthcheck?.test ?? []].flat();
      expect(test[0]).toBe('CMD');
      expect(test).toContain('/garage');
      // The negative `test[0] === 'CMD'` does not cover: a probe that keeps the
      // exec form but invokes a shell that is not in the image
      // (`['CMD', '/bin/sh', '-c', ...]`) fails exactly the same way, and looks
      // right at a glance.
      expect(test.some((token) => /sh$|bash$/.test(token))).toBe(false);
    });

    it('sits on the data network only, with the config mounted read-only', () => {
      // `data` is `internal: true`: no published port and no route to the
      // internet, in either direction. The app is the only thing that talks to it.
      expect(networksOf(s3)).toEqual(['data']);
      const volumes = s3?.volumes ?? [];
      // The config file holds no secret (credentials arrive through the
      // environment), which is what makes committing and mounting it safe — and
      // `:ro` is what keeps a compromised engine from rewriting its own block size
      // or data directory.
      expect(volumes).toContain('./docker/garage/garage.toml:/etc/garage.toml:ro');
      // Both named volumes, because the metadata and the blocks are separate and
      // BOTH are needed to read a stored document back.
      expect(volumes.some((volume) => volume.startsWith('hvault-s3-meta:'))).toBe(true);
      expect(volumes.some((volume) => volume.startsWith('hvault-s3-data:'))).toBe(true);
    });

    it("configures a block size that matches the app's ciphertext chunk exactly", () => {
      // One crypto segment is one uploaded part is one downloaded range, and
      // DOCUMENT_CIPHERTEXT_CHUNK_BYTES fixes that at 8 MiB. The engine
      // re-serialises an object's block list once per block, and upstream asks that
      // multipart parts be at least block_size and an exact multiple of it — so a
      // block size left at the 1 MiB default makes every part eight blocks and
      // rewrites the block list eight times per part. The two numbers are one
      // decision written in two files; this is what stops them drifting apart.
      const garageToml = readFileSync(
        path.join(repoRoot, 'docker', 'garage', 'garage.toml'),
        'utf-8',
      );
      expect(garageToml).toMatch(/^block_size = "8M"$/m);
      expect(DOCUMENT_CIPHERTEXT_CHUNK_BYTES).toBe(8 * 1024 * 1024);
      // The app reaches it at the address the app's environment pins, so the
      // listener has to be the one that address names.
      expect(garageToml).toMatch(/^api_bind_addr = "\[::\]:3900"$/m);
      // ...and the region has to be the one the app defaults to, because SigV4
      // signs it: a mismatch is a signature failure against your own bucket.
      expect(garageToml).toMatch(/^s3_region = "us-east-1"$/m);
      expect(envExample).toMatch(/^S3_REGION=us-east-1$/m);
    });

    it('runs the same pinned engine in the development stack, and publishes it on loopback', () => {
      // A storage behaviour difference between dev and prod must never be able to
      // be a storage ENGINE difference — the same rule the two compose files
      // already hold for MongoDB's major version. The dev stack does publish a
      // port, which production must not: it is bound to 127.0.0.1 for host tooling,
      // exactly as the dev database is.
      const devCompose = readFileSync(path.join(repoRoot, 'docker-compose.dev.yml'), 'utf-8');
      const digest = /@(sha256:[0-9a-f]{64})/.exec(s3?.image ?? '')?.[1];
      expect(digest).toBeDefined();
      expect(devCompose).toContain(digest!);
      expect(devCompose).toMatch(/^ {6}- '127\.0\.0\.1:3900:3900'$/m);
      // The dev credentials are literals so the dev stack needs no .env at all,
      // and they must never be the production stack's guarded keys.
      expect(devCompose).not.toMatch(/GARAGE_DEFAULT_SECRET_KEY: \$\{/);
    });
  });

  describe('image build', () => {
    it('builds the app and the Nginx bundle from ONE client build stage', () => {
      // The app serves the index.html that references the content-hashed assets Nginx
      // serves. Two independent client builds could emit two different sets of hashes,
      // and the app would 404 every script it asks for. Both targets copying from the
      // same stage makes that impossible — so assert there IS only one such stage, and
      // that every client-bundle COPY draws from it (directly, or via `web-root`,
      // which is itself derived from it). Counting COPY lines was not enough: it
      // passed just as happily if `app` copied from a second, independent build.
      const clientStages = dockerfile.match(/^FROM .+ AS build-client$/gm) ?? [];
      expect(clientStages).toHaveLength(1);
      expect(dockerfile).toContain('FROM build-shared AS build-client');
      expect(dockerfile).toMatch(/^FROM build-client AS web-root$/m);

      // Every stage that any client asset is copied FROM must be one of those two.
      const sources = [...dockerfile.matchAll(/COPY --from=(\S+) \/app\/packages\/client/g)].map(
        (m) => m[1],
      );
      expect(sources.length).toBeGreaterThanOrEqual(2);
      for (const source of sources) {
        expect(['build-client', 'web-root']).toContain(source);
      }
    });

    it('ships a lockfile carrying integrity metadata for every registry package', () => {
      // Every image stage installs with `npm ci`, which verifies each downloaded
      // tarball against the Subresource-Integrity hash recorded in the lockfile. A
      // lockfile regenerated while node_modules was still on disk is re-serialised
      // from that tree rather than from registry packuments, and silently loses
      // `resolved`/`integrity` on every package npm did not have to re-download —
      // leaving `npm ci` to install the bulk of the tree with no integrity
      // verification and no pinned tarball URL. For a zero-knowledge password
      // manager that is a supply-chain control disappearing in silence: the install
      // still succeeds, `npm audit` still reports zero, and .gitattributes marks
      // package-lock.json linguist-generated, so the regression shows up as no
      // reviewable diff at all. Assert it structurally instead.
      const lockfile = JSON.parse(
        readFileSync(path.join(repoRoot, 'package-lock.json'), 'utf-8'),
      ) as {
        packages: Record<
          string,
          { version?: string; link?: boolean; resolved?: string; integrity?: string }
        >;
      };

      // Only real registry artifacts qualify. The root entry ("") and the workspace
      // sources ("packages/…") are not downloaded, and the `node_modules/@hvault/*`
      // entries are symlinks into this repo — none of them can carry a hash.
      //
      // `includes`, not `startsWith`: npm places a package NESTED when hoisting it
      // would break a peer range, and a workspace-nested artifact is keyed
      // `packages/<ws>/node_modules/<pkg>` — a path that a `startsWith` filter drops
      // on the floor. Measured: a dependency refresh moved `@vitejs/plugin-react`
      // and `@hookform/resolvers` under `packages/client/node_modules/` and this
      // assertion stopped covering them, silently, while still passing. The
      // supply-chain claim is about every downloaded tarball, so the predicate has
      // to be about every downloaded tarball too, wherever npm decided to put it.
      const registryPackages = Object.entries(lockfile.packages).filter(
        ([name, entry]) => name.includes('node_modules/') && !entry.link && entry.version,
      );
      expect(registryPackages.length).toBeGreaterThan(500);

      expect(
        registryPackages.filter(([, entry]) => !entry.integrity).map(([name]) => name),
      ).toEqual([]);
      expect(registryPackages.filter(([, entry]) => !entry.resolved).map(([name]) => name)).toEqual(
        [],
      );
    });

    it('bounds nginx worker_processes to the CPU limit instead of the host core count', () => {
      // nginx's shipped `worker_processes auto` resolves through
      // sysconf(_SC_NPROCESSORS_ONLN), which reports the HOST's cores and ignores
      // the container's CFS quota. Measured: on a 4-core host the service spawned
      // 4 workers while capped at `cpus: '0.5'`; on a 32-core host that is 32
      // workers in the same half-core, 256 MB box, and past ~99 cores they cannot
      // all be forked under `pids_limit: 100`. The pin has to be baked into the
      // image — the runtime autotune hook rewrites nginx.conf on boot, which the
      // service's read-only root filesystem forbids.
      // Directives only: the comment above the fix quotes `worker_processes auto`
      // to explain what is being replaced, and prose must not trip the guard.
      const webStageDirectives = dockerfile
        .slice(dockerfile.indexOf('FROM nginxinc/nginx-unprivileged'))
        .split('\n')
        .filter((line) => !line.trimStart().startsWith('#'))
        .join('\n');
      expect(webStageDirectives).toMatch(/worker_processes \d+;/);
      expect(webStageDirectives).not.toMatch(/worker_processes\s+auto/);
      // ...and the cap only means something while the CPU limit it was chosen for
      // is still in place.
      expect(nginx?.cpus).toBeDefined();
    });

    it('removes index.html from the Nginx document root', () => {
      // Structural, not merely configured. Helmet (inside Express) is what attaches
      // the CSP, its nonce, X-Frame-Options and Referrer-Policy to the document; an
      // index.html sitting in Nginx's root would be a header-free copy of the app one
      // URL away. Nginx cannot serve what it does not have.
      expect(dockerfile).toMatch(/rm -f \/app\/packages\/client\/dist\/index\.html/);
    });

    it('removes sandbox.html from the Nginx document root too', () => {
      // Sharper than the index.html case above, and the reason it gets its own
      // assertion. The document sandbox's entire isolation IS the per-response
      // Content-Security-Policy that Express attaches to /sandbox.html
      // (src/config/sandboxCsp.ts): `connect-src 'none'`, `worker-src 'none'`,
      // `sandbox allow-scripts` and the rest. Answered off this disk it would
      // carry the document root's `default-src 'self'` and NONE of those, so
      // every renderer would keep working while the containment silently
      // stopped existing. With the file absent, `try_files` falls through to
      // `@app` and the tailored policy is the one that reaches the client.
      // Anchored at the end of the path: an unanchored match would also be
      // satisfied by `.../sandbox.html.bak`, which deletes nothing that matters.
      expect(dockerfile).toMatch(/rm -f[^\n]*\/app\/packages\/client\/dist\/sandbox\.html(?:\s|$)/);
    });

    it('serves from a document root this repo owns, not the base image default', () => {
      // The nginx-unprivileged image ships its own /usr/share/nginx/html/index.html
      // (the "Welcome to nginx!" page), and COPY overlays rather than replaces — so
      // serving from there answers /index.html with the stock page, stripped of every
      // security header.
      expect(dockerfile).toContain('/srv/hvault');
      expect(nginxConf).toMatch(/root\s+\/srv\/hvault;/);
    });

    it('patches the Nginx base image OS packages that Trivy flags as fixable HIGH', () => {
      // The nginx-unprivileged:1.29-alpine base ships fixable HIGH CVEs in c-ares,
      // openssl (libcrypto3 / libssl3), libexpat and libxml2. The web stage runs
      // `apk upgrade` to pull the patched packages; dropping this reopens the
      // Docker/Trivy gate, so it is asserted rather than merely commented.
      const webStage = dockerfile.slice(dockerfile.indexOf('FROM nginxinc/nginx-unprivileged'));
      expect(webStage).toMatch(/RUN apk upgrade --no-cache/);
      // The upgrade runs as root, but the image must still SERVE as the
      // unprivileged uid 101 — the root switch is only for the apk transaction.
      // Assert the ORDER: root, then the apk RUN, then drop back to 101 as the
      // final (serving) user — not merely that all three tokens appear somewhere.
      // `USER 0`, spelled numerically like the `USER 101` it is paired with.
      expect(webStage).toMatch(/^USER 0$[\s\S]*RUN apk upgrade --no-cache[\s\S]*^USER 101$/m);
    });

    it('upgrades BEFORE it edits nginx.conf, in one RUN that fixes that order', () => {
      // An nginx package upgrade rewrites /etc/nginx/nginx.conf and takes
      // `worker_processes 2;` with it, so the sed has to come second. As two
      // separate RUN instructions that order was a convention a reordering edit
      // could break silently — the image still builds, and the only symptom is
      // nginx forking one worker per HOST core inside a `cpus: '0.5'` service.
      // `&&` makes the order the instruction rather than the layout, and it is
      // also what clears hadolint DL3059 (which fires on two consecutive RUNs
      // only when NEITHER already chains).
      const webStage = dockerfile.slice(dockerfile.indexOf('FROM nginxinc/nginx-unprivileged'));
      expect(webStage).toMatch(
        /RUN apk upgrade --no-cache \\\n \&\& sed -i 's\/\^worker_processes \.\*\/worker_processes 2;\/' \/etc\/nginx\/nginx\.conf/,
      );
      // NEGATIVE: the sed must not ALSO exist as an instruction of its own, which
      // is what a half-applied revert would leave behind — the second copy would
      // run after the upgrade either way today, and stop doing so the moment
      // anything is inserted between them.
      expect(webStage).not.toMatch(/^RUN sed -i/m);
    });

    it('names both node runtime users by the uid their tmpfs mounts are pinned to', () => {
      // `USER node` and `USER 1000:1000` select the SAME account — the base
      // image's /etc/passwd carries `node:x:1000:1000`, and a numeric USER is
      // resolved through it, so even $HOME is unchanged (measured on
      // node:24-alpine3.23). The reason to insist on the number is that the other
      // half of this contract is already written as one: every tmpfs these two
      // services mount is pinned to `uid=1000,gid=1000`, and a tmpfs whose owner
      // disagrees with the process is the silent-restart bug the compose tests
      // above exist for. One spelling of one uid is how the two stay comparable.
      //
      // The expected uid is DERIVED from compose rather than written twice: a
      // second literal would agree with a wrong Dockerfile as readily as a right
      // one. hadolint DL3066 wants the same thing for its own reason — a name has
      // to be resolvable at runtime, a number always is.
      const uid = /uid=(\d+)/.exec(tmpfsOptions(app, '/app/logs'))?.[1];
      expect(uid).toBe('1000');

      for (const stage of ['bootstrap', 'app']) {
        const start = dockerfile.indexOf(`AS ${stage}\n`);
        expect(start, `stage ${stage} must exist`).toBeGreaterThan(-1);
        const end = dockerfile.indexOf('\nFROM ', start + 1);
        const body = dockerfile.slice(start, end === -1 ? undefined : end);
        const users = [...body.matchAll(/^USER (.+)$/gm)].map((match) => match[1]);
        expect(users, `stage ${stage} must drop out of root`).toEqual([`${uid}:${uid}`]);
      }
    });

    it('probes health through an exec-form HEALTHCHECK, with no shell in between', () => {
      // The shell form (`HEALTHCHECK CMD node -e "…"`) wraps the probe in
      // `/bin/sh -c`, so every 30-second check forks an extra process and the
      // status Docker records is the SHELL's, not node's — a difference that only
      // shows up when the probe is killed. The exec form also matches the CMD
      // below it, so both entry points into this image read the same way.
      // hadolint DL3025 asks for it; the extra process is the reason to want it.
      const appStage = dockerfile.slice(
        dockerfile.indexOf('FROM base AS app'),
        dockerfile.indexOf('FROM build-client AS web-root'),
      );
      expect(appStage).toMatch(/\n {2}CMD \["node", "-e", "fetch\(/);
      // NEGATIVE: no shell-form CMD anywhere in the stage — neither the
      // healthcheck's nor the entry point's. Both are JSON arrays.
      const directives = appStage
        .split('\n')
        .filter((line) => !line.trim().startsWith('#'))
        .join('\n');
      expect(directives).not.toMatch(/^\s*CMD (?!\[)/m);
    });

    it('patches the Node base image OS packages that Trivy flags as fixable HIGH', () => {
      // Same class of finding as the Nginx stage above, and the same remedy. The
      // node:24-alpine base is rebuilt on NODE releases rather than on Alpine
      // security releases, so it ships openssl behind its own branch and the image
      // gate goes red in `app` AND `bootstrap` at once. The upgrade lives in `base`
      // so both runtime images inherit it from one instruction; dropping it reopens
      // both, which is why it is asserted rather than merely commented.
      const baseStage = dockerfile.slice(
        dockerfile.indexOf('FROM node:24-alpine'),
        dockerfile.indexOf('FROM base AS development'),
      );
      expect(baseStage).toMatch(/RUN apk upgrade --no-cache/);
      // NEGATIVE: never a pinned apk revision in its place. `apk add libssl3=3.5.8-r0`
      // fixes today and breaks every build the day Alpine drops that revision from
      // the mirror, turning an unrelated gate red for a reason no reader would
      // connect to this line.
      expect(baseStage).not.toMatch(/apk add[^\n]*=\d/);
    });

    it('gives every config file it copies an explicit mode, so the host checkout cannot decide it', () => {
      // Docker COPY PRESERVES the source file's mode. The nginx config files are
      // copied from the build context, so on a checkout whose files are 0600 —
      // which is what a `umask 077` machine produces, and what this repo was
      // measured at — they land in the image as `-rw-------` owned by root, and
      // the image serves as uid 101. `nginx -t` then dies with
      //   open() "/etc/nginx/conf.d/default.conf" failed (13: Permission denied)
      // and the whole stack is unbootable, for a reason that lives in the
      // developer's umask rather than anywhere in this repository. An explicit
      // --chmod makes the built image byte-identical regardless of the checkout.
      //
      // The scope is BUILD-CONTEXT copies of FILES, and both halves are load-bearing:
      //
      //   - `COPY --from=<stage>` is exempt because its source modes were set
      //     inside a previous build stage, not by the host filesystem.
      //   - a DIRECTORY copy is exempt because `--chmod=0444` applied to a
      //     directory strips its execute bit, producing `dr--r--r--` that no
      //     non-root user can traverse — the same EACCES with a different cause.
      //     docker/mongo.Dockerfile documents that trap; a directory needs 0555,
      //     or a `RUN mkdir -p` first (see the next test).
      const offenders = webStageCopyStatements
        .filter((copy) => copy.fromBuildContext && copy.sourcesAreFiles)
        .filter((copy) => !/--chmod=/.test(copy.line));

      expect(offenders.map((copy) => copy.line)).toEqual([]);

      // A rule with no live subjects cannot fail, so pin that this one still has
      // some: if the config copies are ever removed or renamed, the assertion
      // above starts passing vacuously and this catches that.
      const governed = webStageCopyStatements.filter(
        (copy) => copy.fromBuildContext && copy.sourcesAreFiles,
      );
      expect(governed.length).toBeGreaterThanOrEqual(2);
      expect(governed.every((copy) => /--chmod=0444\b/.test(copy.line))).toBe(true);
    });

    it('creates /etc/nginx/hvault before copying into it, or the directory inherits 0444', () => {
      // The other half of the same trap, and it only appears once the --chmod
      // above exists. `/etc/nginx/hvault` does NOT exist in the
      // nginx-unprivileged base (verified against the image), so BuildKit creates
      // it for the COPY — and when the COPY carries --chmod, the created parent
      // gets that same mode. Measured: `dr--r--r--`, and uid 101 gets
      // "Permission denied" on the file inside while root still sees it as
      // world-readable. Without the --chmod the parent is created 0755 and
      // nothing looks wrong, which is why removing this mkdir would break the
      // image only in combination with the fix above.
      const webStage = dockerfile.slice(dockerfile.indexOf('FROM nginxinc/nginx-unprivileged'));
      expect(webStage).toMatch(
        /RUN mkdir -p \/etc\/nginx\/hvault[\s\S]*COPY --chmod=0444 \S*proxy_app\.conf \/etc\/nginx\/hvault\//,
      );
    });

    it('never lets the builder umask decide what the runtime user can read', () => {
      // The same defect as the two nginx tests above, in the node stages, and it
      // was live: measured on the images this repository built, `/app/package.json`
      // arrived `-rw-------` root-owned, so `hvault-app` exited 1 at launch with
      //   Cannot find package '/app/node_modules/@hvault/shared/index.js'
      // (Node reads a workspace's package.json to resolve it) and
      // `hvault-bootstrap` exited 1 with
      //   npm error EACCES ... open '/app/package.json'
      // The app gates on `hvault-bootstrap` completing successfully, so the whole
      // stack stayed down — on any checkout with a restrictive umask, and on no
      // other. The image gate cannot see it: it builds and scans these images
      // without ever running one.
      //
      // Two shapes, opposite treatments, both asserted:
      //   * a FILE copy carries `--chmod=`;
      //   * a DIRECTORY copy is normalised by a following `chmod -R a+rX,go-w`, NEVER
      //     by `--chmod`, which would apply one mode to files and directories
      //     alike and strip the traversal bit every directory needs.
      const fileCopies = contextCopyStatements.filter((copy) => copy.sourcesAreFiles);
      const dirCopies = contextCopyStatements.filter((copy) => !copy.sourcesAreFiles);

      expect(
        fileCopies.filter((copy) => !/--chmod=/.test(copy.line)).map((copy) => copy.line),
        'build-context FILE copy with no explicit mode',
      ).toEqual([]);

      // A rule with no subjects cannot fail. Both sides are pinned so a rename
      // that empties either list is a failure rather than a silent pass.
      expect(fileCopies.length).toBeGreaterThanOrEqual(10);
      expect(dirCopies.length).toBeGreaterThanOrEqual(4);

      const normalised = dirCopies.filter((copy) =>
        copy.sources.every((source) => {
          // `COPY . .` copies the whole context; what has to be readable at
          // runtime is the source tree and the manifests it resolves through.
          const target = source === '.' ? 'packages' : source;
          // Scoped to the REST OF THE COPY'S OWN STAGE, not the whole file. An
          // unscoped search passes when any stage anywhere happens to chmod a
          // path with a matching name — `\bpackages\b` matches inside
          // `packages/shared`, so one stage's normalisation would vouch for
          // another's. It must also come AFTER the copy: a chmod that ran first
          // is undone by the copy it was supposed to fix.
          return new RegExp(
            `chmod -R a\\+rX[^\\n]*\\b${target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`,
          ).test(copy.stageAfterCopy);
        }),
      );
      expect(
        dirCopies.filter((copy) => !normalised.includes(copy)).map((copy) => copy.line),
        'build-context DIRECTORY copy with no `chmod -R a+rX,go-w` normalising it',
      ).toEqual([]);

      // And the directory form is never attempted with --chmod, which is the
      // trap the next assertion is about.
      expect(dirCopies.filter((copy) => /--chmod=/.test(copy.line)).map((c) => c.line)).toEqual([]);
    });

    it('creates packages/ before the mode-setting manifest copies, or it inherits 0644', () => {
      // The other half of the trap, and it is not hypothetical: the first attempt
      // at the fix above created `/app/packages` as `drw-r--r--`, because
      // `COPY --chmod=0644 packages/shared/package.json ./packages/shared/` into a
      // path that does not exist yet makes BuildKit create BOTH parents with that
      // mode. uid 1000 then cannot traverse into `packages` at all and every file
      // below it is EACCES — while root still sees them as world-readable, which
      // is why it survives a casual `docker run` as root.
      for (const stage of ['deps', 'prod-deps', 'development']) {
        const start = dockerfile.indexOf(`AS ${stage}\n`);
        expect(start, `stage ${stage} must exist`).toBeGreaterThan(-1);
        const body = dockerfile.slice(start, dockerfile.indexOf('\nFROM ', start + 1));
        expect(body, `${stage} must mkdir its package directories first`).toMatch(
          /RUN mkdir -p packages\/[\s\S]*COPY --chmod=0644 packages\/\S+\/package\.json/,
        );
      }
    });

    it('ships no package manager in the one-shot bootstrap image', () => {
      // npm was installed there solely so `npm run create-indexes -w` worked, and
      // npm's own BUNDLED tree then became the stack's largest source of Trivy
      // findings — undici, brace-expansion twice, ip-address — none reachable in a
      // one-shot on an egress-less network, every one needing an argued exception.
      // The script is invoked through its own binary instead, exactly as the `app`
      // stage already does, which removes the class rather than accepting it again.
      const start = dockerfile.indexOf('AS bootstrap\n');
      expect(start).toBeGreaterThan(-1);
      const stage = dockerfile.slice(start, dockerfile.indexOf('\nFROM ', start + 1));
      // Comments are stripped before the negative assertion: the stage's own
      // docblock has to NAME the install it no longer performs in order to
      // explain why, and a naive match on the raw text is satisfied by that
      // explanation — a rule that fails on its own rationale.
      const directives = stage
        .split('\n')
        .filter((line) => !line.trim().startsWith('#'))
        .join('\n');
      expect(directives).not.toMatch(/npm install -g/);
      // The positive assertions read `directives` too, not the raw stage text.
      // Reading the raw text would let a comment QUOTING one of these lines
      // satisfy it — the same trap in the opposite direction, and the reason the
      // test this one replaced had stopped meaning anything.
      expect(directives).toMatch(
        /RUN rm -rf \/usr\/local\/lib\/node_modules\/npm \/usr\/local\/bin\/npm \/usr\/local\/bin\/npx/,
      );
      // The cwd the script's relative path and @hiprax/logger's `<cwd>/logs`
      // mkdir both depend on, followed by the direct invocation.
      expect(directives).toMatch(
        /WORKDIR \/app\/packages\/server\nCMD \["\/app\/node_modules\/\.bin\/tsx", "scripts\/create-indexes\.ts"\]/,
      );
    });

    it('pins the node base image to an explicit Alpine minor, not the floating tag', () => {
      // The floating `node:24-alpine` tag rolled onto Alpine 3.24, whose musl
      // userspace SIGSEGVs npm at process launch under the WSL2 kernel used for
      // local image builds (`npm ci` exits 139 — the image cannot be built there).
      // The 3.23 variant carries the identical Node runtime and is unaffected, so
      // the base is pinned to it. Reverting to the floating tag reopens the crash,
      // and does so invisibly (it builds fine on hosts unaffected by the 3.24
      // regression), so pin it structurally.
      const baseLine = /^FROM (node:24-alpine[^\s]*) AS base$/m.exec(dockerfile);
      expect(baseLine).not.toBeNull();
      // An explicit Alpine minor suffix (e.g. `node:24-alpine3.23`), never the bare
      // floating `node:24-alpine`.
      expect(baseLine?.[1]).toMatch(/^node:24-alpine\d+\.\d+$/);
    });

    it('removes npm from the app runtime, which executes node directly', () => {
      // The Alpine base ships npm bundling advisories Trivy flags as fixable
      // HIGHs — undici (CVE-2026-12151) first, then brace-expansion and
      // ip-address — inside npm's OWN dependency tree, where this project's root
      // `overrides` cannot reach. The app launches via `node` and never invokes
      // npm, so a package manager here is pure attack surface.
      //
      // This test used to have a second half asserting the BOOTSTRAP stage
      // upgraded npm instead of removing it. That half is gone because the
      // premise is: the bootstrap no longer ships npm either, and the assertion
      // that remained would have been satisfied by the comment explaining its own
      // removal — the exact trap the comment-stripping in
      // 'ships no package manager in the one-shot bootstrap image' guards
      // against. The bootstrap's half of this rule lives in that test now.
      // Comment-stripped, like its sibling: an assertion read against raw stage
      // text can be satisfied by a comment quoting the very line it is looking
      // for, which is how the test this one replaced stopped meaning anything.
      const appStage = dockerfile
        .slice(
          dockerfile.indexOf('FROM base AS app'),
          dockerfile.indexOf('FROM build-client AS web-root'),
        )
        .split('\n')
        .filter((line) => !line.trim().startsWith('#'))
        .join('\n');
      expect(appStage).toMatch(/rm -rf \/usr\/local\/lib\/node_modules\/npm/);
    });
  });

  describe('PM2 process manager (ecosystem.config.cjs)', () => {
    it('sizes max_memory_restart for one worker holding a full L1 HIBP cache', () => {
      // max_memory_restart is enforced PER worker, not aggregated across `instances`.
      // The threshold therefore has to fit ONE worker's fully-populated 64 MiB HIBP L1
      // cache plus its ordinary Node/V8 heap — comfortably, not on the edge — so the
      // bound is (HIBP_CACHE_MAX_BYTES default + 256 MiB of heap headroom). Sizing it as
      // `HIBP_CACHE_MAX_BYTES × instances` would be the wrong model and is what this
      // guards against.
      const match = /max_memory_restart:\s*'([^']+)'/.exec(ecosystemConfig);
      expect(match).not.toBeNull();
      const restartBytes = parseMemoryToBytes(match![1]!);
      expect(restartBytes).toBeGreaterThanOrEqual(HIBP_CACHE_MAX_BYTES_DEFAULT + 256 * MIB);
    });

    it('documents the per-worker (not aggregate) sizing rationale', () => {
      // The number is only safe while the comment explaining WHY it is per-worker
      // survives; a future editor who reads it as aggregate would wrongly shrink it.
      expect(ecosystemConfig).toMatch(/PER PM2 worker/);
      expect(ecosystemConfig).not.toMatch(/max_memory_restart:\s*'512M'/);
    });
  });

  describe('nginx routing contract', () => {
    it('proxies every HTML document to Express, so helmet owns its headers', () => {
      expect(nginxConf).toMatch(/location = \/ \{/);
      expect(nginxConf).toMatch(/location @app \{/);
      // The SPA fallback goes to the app, never to a local index.html.
      expect(nginxConf).toMatch(/try_files\s+\$uri @app;/);
      expect(nginxConf).not.toMatch(/try_files[^;]*\/index\.html/);
    });

    it('serves the sandbox assets, and only those, with the CORS and CORP headers an opaque origin needs', () => {
      // /sandbox.html is framed WITHOUT `allow-same-origin`, so it holds an
      // opaque origin. A module script is fetched in CORS mode unconditionally
      // and Vite emits `<script type="module" crossorigin>`, so that request
      // carries `Origin: null` and needs ACAO; the stylesheet is a no-cors
      // subresource and needs CORP. Miss either and the frame is SILENTLY
      // blank — no console error a user would report, no failing request a gate
      // that only checks status codes would see.
      // Sliced at the block's own closing brace rather than at the next
      // `location`, so the COMMENTS between two blocks (which necessarily name
      // the very headers being asserted absent below) cannot satisfy or defeat
      // either half of this test.
      const locationBlock = (header: string): string => {
        const start = nginxConf.indexOf(header);
        expect(start, `${header} is not in internal.conf`).toBeGreaterThanOrEqual(0);
        const end = nginxConf.indexOf('\n    }', start);
        expect(end, `${header} is never closed`).toBeGreaterThan(start);
        return nginxConf.slice(start, end);
      };

      const sandboxBlock = locationBlock('location /sandbox-assets/ {');
      expect(sandboxBlock).toMatch(/add_header\s+Access-Control-Allow-Origin\s+"\*"\s+always;/);
      expect(sandboxBlock).toMatch(
        /add_header\s+Cross-Origin-Resource-Policy\s+"cross-origin"\s+always;/,
      );
      // Immutable caching, exactly as /assets/ gets: these are content-hashed.
      expect(sandboxBlock).toMatch(/max-age=31536000, immutable/);

      // The negative, and the one that matters: the APPLICATION's assets are
      // NOT readable by an opaque origin. Widening /assets/ would be the easy
      // "fix" for a blank frame and would hand any sandboxed document on the
      // internet read access to the app's own bundle.
      const appAssetsBlock = locationBlock('location /assets/ {');
      expect(appAssetsBlock).not.toMatch(/Access-Control-Allow-Origin/);
      expect(appAssetsBlock).not.toMatch(/Cross-Origin-Resource-Policy/);
    });

    it('never compresses API responses (BREACH)', () => {
      // Compressing a response that mixes a secret (a CSRF or bearer token) with
      // attacker-influenced content is the precondition for a compression oracle.
      const apiBlock = nginxConf.slice(
        nginxConf.indexOf('location /api/'),
        nginxConf.indexOf('location /assets/'),
      );
      expect(apiBlock).toMatch(/gzip off;/);
    });

    it("allows a body larger than the app's own 30 MB route cap", () => {
      // So an oversized backup restore or key rotation is rejected by the app, with a
      // structured JSON error, rather than cut off here with an opaque 413.
      const match = /client_max_body_size\s+(\d+)m;/.exec(nginxConf);
      expect(match).not.toBeNull();
      expect(Number(match?.[1])).toBeGreaterThan(30);
    });

    it('re-resolves the app through Docker DNS instead of pinning one IP', () => {
      // Nginx resolves a static `upstream` hostname once, at config load, and holds
      // that address forever — recreate only the app container and every request 502s
      // until someone restarts Nginx. A variable defers the lookup to request time.
      expect(nginxConf).toMatch(/resolver\s+127\.0\.0\.11/);
      expect(nginxConf).toMatch(/proxy_pass\s+http:\/\/\$hvault_app;/);
      expect(nginxConf).not.toMatch(/^upstream\s/m);
    });
  });
});
