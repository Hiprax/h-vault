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
 *     header helmet attaches to it.
 *
 * A refactor that drops one of these gets a red test instead of an incident.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

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
// layer a service-specific value over the shared topology anchor (the app's NODE_OPTIONS,
// the bootstrap's npm_config_cache). Without it the parser hands back a literal `<<` key
// and every assertion about an INHERITED value — NODE_ENV, PORT, MONGODB_URI,
// TRUST_PROXY — silently reads `undefined` and the tests that matter most go quiet.
const compose = parse(composeYaml, { merge: true }) as ComposeConfig;
const dockerfile = readFileSync(path.join(repoRoot, 'docker', 'Dockerfile'), 'utf-8');
const mongoDockerfile = readFileSync(path.join(repoRoot, 'docker', 'mongo.Dockerfile'), 'utf-8');
const nginxConf = readFileSync(path.join(repoRoot, 'docker', 'nginx', 'internal.conf'), 'utf-8');
const envExample = readFileSync(path.join(repoRoot, '.env.example'), 'utf-8');
const rootPackageJson = JSON.parse(readFileSync(path.join(repoRoot, 'package.json'), 'utf-8')) as {
  version: string;
};

const app = compose.services['hvault-app'];
const db = compose.services['hvault-db'];
const nginx = compose.services['hvault-nginx'];
const bootstrap = compose.services['hvault-bootstrap'];

const longRunning: [string, ServiceConfig | undefined][] = [
  ['hvault-nginx', nginx],
  ['hvault-app', app],
  ['hvault-db', db],
];
const everyService: [string, ServiceConfig | undefined][] = [
  ...longRunning,
  ['hvault-bootstrap', bootstrap],
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
      // a checkout that has none. That is NOT a licence to boot on defaults: the
      // MONGODB_URI below interpolates `${MONGO_ROOT_PASSWORD:?…}`, which makes
      // Compose refuse to resolve the stack at all when the value is missing — the
      // failure happens before a container exists, and it names the variable.
      expect(app?.environment?.['MONGODB_URI']).toMatch(/\$\{MONGO_ROOT_PASSWORD:\?/);
      expect(db?.environment?.['MONGO_INITDB_ROOT_PASSWORD']).toMatch(/\$\{MONGO_ROOT_PASSWORD:\?/);
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
      // Root credentials live in `admin`.
      expect(uri).toContain('authSource=admin');
      // directConnection would force a Single topology and defeat the point: the set
      // advertises `hvault-db:27017`, which resolves inside the stack, so the driver
      // discovers the primary properly.
      expect(uri).not.toContain('directConnection');
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

      // Everything it writes goes to a tmpfs owned by its non-root user: npm's cache
      // (relocated off the now read-only $HOME) and the log directory @hiprax/logger
      // mkdirs at module scope from cwd=/app/packages/server.
      expect(bootstrap?.environment?.['npm_config_cache']).toMatch(/^\/tmp\//);
      expect(tmpfsOptions(bootstrap, '/tmp')).toContain('uid=1000');
      expect(tmpfsOptions(bootstrap, '/app/packages/server/logs')).toContain('uid=1000');
    });

    it('waits for a writable primary before it creates indexes', () => {
      expect(bootstrap?.depends_on?.['hvault-db']?.condition).toBe('service_healthy');
    });

    it('owns a writable log directory before dropping to the non-root user', () => {
      // `npm run <script> -w packages/server` runs with cwd = /app/packages/server,
      // and the script imports src/config, which calls createLogger() at MODULE
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

    it('sets that tunable at EVERY mongod launch site in the repo, not just this one', () => {
      // `npm test` and the E2E harness both spawn a REAL mongod (mongodb-memory-server
      // downloads the binary), so a developer or CI box on Ubuntu 26.04 hits the same
      // abort — a compose-only fix leaves the test suite unrunnable on a modern
      // kernel, which is exactly the kind of half-fix that gets rediscovered a year
      // later.
      //
      // The two compose files carry the literal; the two Node harnesses go through the
      // shared merge-safe helper (mongoKernelCompat.ts), so assert the CALL there
      // rather than the string — the point is that the tunable reaches the spawned
      // mongod, not how it is spelled.
      const devCompose = readFileSync(path.join(repoRoot, 'docker-compose.dev.yml'), 'utf-8');
      expect(devCompose).toContain('glibc.pthread.rseq=1');
      expect(devCompose).not.toContain('glibc.pthread.rseq=0');

      const helper = readFileSync(
        path.join(repoRoot, 'packages', 'server', 'tests', 'mongoKernelCompat.ts'),
        'utf-8',
      );
      expect(helper).toContain("'glibc.pthread.rseq=1'");

      for (const harness of [
        path.join(repoRoot, 'packages', 'server', 'tests', 'setup.ts'),
        path.join(repoRoot, 'e2e', 'start-server.ts'),
      ]) {
        const contents = readFileSync(harness, 'utf-8');
        expect(contents, harness).toMatch(/import\s*\{[^}]*applyMongoKernelCompat[^}]*\}/);
        // Called at module scope — BEFORE mongodb-memory-server spawns mongod, since
        // the child inherits process.env at spawn time and not a moment later.
        expect(contents, harness).toMatch(/^applyMongoKernelCompat\(\);$/m);
      }
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

    it('removes index.html from the Nginx document root', () => {
      // Structural, not merely configured. Helmet (inside Express) is what attaches
      // the CSP, its nonce, X-Frame-Options and Referrer-Policy to the document; an
      // index.html sitting in Nginx's root would be a header-free copy of the app one
      // URL away. Nginx cannot serve what it does not have.
      expect(dockerfile).toMatch(/rm -f \/app\/packages\/client\/dist\/index\.html/);
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
      // nginx-unprivileged:1.29-alpine trails node:24-alpine by a full Alpine
      // minor (3.23 vs 3.24) and ships fixable HIGH CVEs in c-ares, openssl
      // (libcrypto3 / libssl3), libexpat and libxml2. The web stage runs
      // `apk upgrade` to pull the patched packages; dropping this reopens the
      // Docker/Trivy gate, so it is asserted rather than merely commented.
      const webStage = dockerfile.slice(dockerfile.indexOf('FROM nginxinc/nginx-unprivileged'));
      expect(webStage).toMatch(/RUN apk upgrade --no-cache/);
      // The upgrade runs as root, but the image must still SERVE as the
      // unprivileged uid 101 — the root switch is only for the apk transaction.
      // Assert the ORDER: root, then the apk RUN, then drop back to 101 as the
      // final (serving) user — not merely that all three tokens appear somewhere.
      expect(webStage).toMatch(/USER root[\s\S]*RUN apk upgrade --no-cache[\s\S]*USER 101/);
    });

    it('mitigates the npm bundled-undici HIGH in the node images', () => {
      // The Alpine base ships npm bundling a vulnerable undici (CVE-2026-12151).
      // The app runtime executes `node` directly and never uses npm, so it removes
      // npm entirely; the bootstrap runs `npm run create-indexes`, so it upgrades
      // npm to a build bundling a patched undici. Dropping either reopens the
      // Trivy gate on that image.
      const bootstrapStage = dockerfile.slice(
        dockerfile.indexOf('FROM build-server AS bootstrap'),
        dockerfile.indexOf('FROM base AS app'),
      );
      expect(bootstrapStage).toMatch(/npm install -g npm@\d+/);
      // ...and that upgrade must be PINNED to a major, never a floating `@latest`.
      // This one-shot is load-bearing (the app gates on
      // `service_completed_successfully`), so a future npm major that changed
      // `npm run -w` behavior would take the whole stack down at DEPLOY time —
      // which this gate cannot catch, since it builds and scans the image but
      // never runs create-indexes against a live Mongo.
      expect(bootstrapStage).not.toMatch(/npm install -g npm@latest/);

      const appStage = dockerfile.slice(
        dockerfile.indexOf('FROM base AS app'),
        dockerfile.indexOf('FROM build-client AS web-root'),
      );
      expect(appStage).toMatch(/rm -rf \/usr\/local\/lib\/node_modules\/npm/);
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
