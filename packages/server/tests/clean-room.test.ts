/**
 * The clean-room gates' decisions: `test:deploy`'s verdicts and the end-to-end
 * flow's HTTP contract.
 *
 * Both runners are unavoidably slow — one stands five containers up, the other
 * checks out HEAD and installs it from scratch — so the parts that DECIDE
 * anything live in `scripts/ci/lib/{drill,vault-flow}.mjs` and are exercised
 * here, for the same reason `lib/tiers.mjs` is exercised beside the pipeline
 * runner: a rule that can only be tested by running a four-minute gate is a rule
 * nobody tests, and every one of these has a failure mode that reads as a PASS.
 *
 * The three that matter most, each of which was observed rather than imagined:
 *
 *   · An empty `docker compose ps` makes "is anything unhealthy?" true by
 *     vacuity, so a drill against a stack that never started reports green.
 *   · A container with a healthcheck that has not run yet reports NO health at
 *     all, and accepting `''` as healthy turns the gate's central claim into
 *     "the container exists".
 *   · Compose spells a publisher's host binding several ways across versions;
 *     the first version of `singlePortProblems` read a correctly-bound
 *     `127.0.0.1` port as unbound, which is a gate that fails on a correct stack
 *     — and the usual repair for that is deleting the check.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SERVICE_EXPECTATIONS,
  hostBindingOf,
  isLoopbackBinding,
  parseComposePs,
  parseProvisionLog,
  portExposureVerdict,
  publishedPorts,
  renderEnvFile,
  renderOverride,
  serviceVerdicts,
  singlePortProblems,
  verdictFor,
} from '../../../scripts/ci/lib/drill.mjs';
import {
  createCookieJar,
  expectEnvelope,
  parseSetCookie,
  waitForHealth,
} from '../../../scripts/ci/lib/vault-flow.mjs';

/** Anchored on this module's own URL, never on `process.cwd()`. */
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

/** A `docker compose ps --format json` row, as Compose emits it. */
const row = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  Service: 'hvault-app',
  State: 'running',
  Health: 'healthy',
  ExitCode: 0,
  Publishers: [],
  ...over,
});

/** A whole healthy stack: three long-lived services and two completed one-shots. */
const healthyStack = (): Record<string, unknown>[] => [
  row({
    Service: 'hvault-nginx',
    Publishers: [
      { URL: '127.0.0.1', PublishedPort: 18080, TargetPort: 8080, Protocol: 'tcp' },
      // A container-side port with no host binding: Compose lists it, but
      // nothing on the host can reach it, so it must not count as published.
      { URL: '', PublishedPort: 0, TargetPort: 8080, Protocol: 'tcp' },
    ],
  }),
  row({ Service: 'hvault-app' }),
  row({ Service: 'hvault-db' }),
  row({ Service: 'hvault-bootstrap', State: 'exited', Health: '', ExitCode: 0 }),
  row({ Service: 'hvault-db-init', State: 'exited', Health: '', ExitCode: 0 }),
];

describe('service health verdicts', () => {
  it('accepts a long-lived service only when it is running AND reporting healthy', () => {
    expect(verdictFor('hvault-app', 'healthy', row()).ok).toBe(true);
    expect(verdictFor('hvault-app', 'healthy', row({ State: 'restarting' })).ok).toBe(false);
    expect(verdictFor('hvault-app', 'healthy', row({ Health: 'unhealthy' })).ok).toBe(false);
  });

  it('refuses a running container whose healthcheck has not reported yet', () => {
    // Compose leaves `Health` empty BOTH for a container with no probe and for
    // one whose probe has not run, so treating "" as healthy would let a
    // container that never passed a check satisfy the gate's central claim.
    const verdict = verdictFor('hvault-app', 'healthy', row({ Health: '' }));
    expect(verdict.ok).toBe(false);
    expect(verdict.detail).toContain('no health reported');
  });

  it('accepts a one-shot only when it has exited zero', () => {
    const done = verdictFor('hvault-bootstrap', 'completed', row({ State: 'exited', ExitCode: 0 }));
    expect(done.ok).toBe(true);
    expect(
      verdictFor('hvault-bootstrap', 'completed', row({ State: 'exited', ExitCode: 1 })).ok,
    ).toBe(false);
    // Still running is not "completed": the app gates on
    // service_completed_successfully, so a bootstrap that never exits is a stack
    // that never serves.
    expect(verdictFor('hvault-bootstrap', 'completed', row({ State: 'running' })).ok).toBe(false);
  });

  it('reports a service with no container at all rather than skipping it', () => {
    const verdict = verdictFor('hvault-db', 'healthy', undefined);
    expect(verdict.ok).toBe(false);
    expect(verdict.status).toBe('absent');
  });

  it('passes a whole healthy stack, and names the one service that is not', () => {
    const healthy = serviceVerdicts(healthyStack());
    expect(healthy.unhealthy).toEqual([]);
    expect(healthy.verdicts).toHaveLength(Object.keys(SERVICE_EXPECTATIONS).length);
    expect(healthy.unexpected).toEqual([]);

    const broken = healthyStack().map((entry) =>
      entry.Service === 'hvault-db' ? { ...entry, Health: 'unhealthy' } : entry,
    );
    const verdicts = serviceVerdicts(broken);
    expect(verdicts.unhealthy.map((verdict) => verdict.service)).toEqual(['hvault-db']);
  });

  it('reports a service the stack grew that nothing in the table examines', () => {
    const grown = [...healthyStack(), row({ Service: 'hvault-redis' })];
    expect(serviceVerdicts(grown).unexpected).toEqual(['hvault-redis']);
  });

  it('names exactly the services docker-compose.yml declares, so the drill cannot examine a stale set', () => {
    // `SERVICE_EXPECTATIONS` is what every check in the drill iterates: states,
    // ports, networks. A service added to the stack and not to this table is
    // examined by nothing, and `docker compose up --wait` waits only for
    // `running|healthy`, so one without a healthcheck satisfies the wait by
    // merely having started. The drill now FAILS on an unexamined service at run
    // time; this is the other half, at push time — a table that has fallen behind
    // the compose file it stands for is caught before anyone spends five minutes
    // on the drill to find out.
    const compose = readFileSync(path.join(repoRoot, 'docker-compose.yml'), 'utf8');
    const servicesAt = compose.search(/^services:$/m);
    expect(servicesAt).toBeGreaterThan(-1);
    // Only the `services:` block — the file also declares `networks:` and
    // `volumes:` at the top level, whose children would otherwise read as
    // services and make this assertion permanently, confusingly red.
    const afterServices = compose.slice(servicesAt + 'services:'.length);
    const nextTopLevel = afterServices.search(/^[a-zA-Z]/m);
    const servicesBlock =
      nextTopLevel === -1 ? afterServices : afterServices.slice(0, nextTopLevel);
    const declared = [...servicesBlock.matchAll(/^ {2}([a-zA-Z0-9_-]+):$/gm)].map(
      (match) => match[1]!,
    );
    expect(declared.length).toBeGreaterThan(0);
    expect(declared.sort()).toEqual(Object.keys(SERVICE_EXPECTATIONS).sort());
  });

  it('finds every expected service missing when the stack never started', () => {
    // The vacuity trap: an empty table must fail every expectation, not none.
    const { verdicts, unhealthy } = serviceVerdicts([]);
    expect(unhealthy).toHaveLength(verdicts.length);
    expect(unhealthy.every((verdict) => verdict.status === 'absent')).toBe(true);
  });
});

describe('docker compose ps parsing', () => {
  it('reads both shapes Compose emits, and neither invents rows', () => {
    const ndjson = '{"Service":"hvault-app"}\n{"Service":"hvault-db"}';
    const array = '[{"Service":"hvault-app"},{"Service":"hvault-db"}]';
    expect(parseComposePs(ndjson).map((entry) => entry.Service)).toEqual([
      'hvault-app',
      'hvault-db',
    ]);
    expect(parseComposePs(array).map((entry) => entry.Service)).toEqual([
      'hvault-app',
      'hvault-db',
    ]);
    expect(parseComposePs('')).toEqual([]);
    expect(parseComposePs('   \n  ')).toEqual([]);
  });
});

describe('the single published port', () => {
  it('passes a stack that publishes exactly one loopback-bound port', () => {
    expect(singlePortProblems(healthyStack(), { port: 18080 })).toEqual([]);
    // And the unbound container-side entry is not counted as published.
    expect(publishedPorts(healthyStack())).toHaveLength(1);
  });

  it('fails when a second service publishes anything', () => {
    const leaky = [
      ...healthyStack(),
      row({
        Service: 'hvault-db',
        Publishers: [{ URL: '127.0.0.1', PublishedPort: 27017, TargetPort: 27017 }],
      }),
    ];
    const problems = singlePortProblems(leaky, { port: 18080 });
    expect(problems.join(' ')).toContain('2 host port');
    expect(problems.join(' ')).toContain('only hvault-nginx may publish a port');
  });

  it('fails when the one port loses its loopback binding', () => {
    const exposed = healthyStack().map((entry) =>
      entry.Service === 'hvault-nginx'
        ? {
            ...entry,
            Publishers: [{ URL: '0.0.0.0', PublishedPort: 18080, TargetPort: 8080 }],
          }
        : entry,
    );
    const problems = singlePortProblems(exposed, { port: 18080 });
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain('not bound to loopback');
  });

  it('fails when the host or container port is not the one the deployment declares', () => {
    const moved = healthyStack().map((entry) =>
      entry.Service === 'hvault-nginx'
        ? { ...entry, Publishers: [{ URL: '127.0.0.1', PublishedPort: 8080, TargetPort: 5000 }] }
        : entry,
    );
    const problems = singlePortProblems(moved, { port: 18080 }).join(' ');
    expect(problems).toContain('host port 8080');
    expect(problems).toContain('container port 5000');
  });

  it('reads every host-binding spelling Compose has used', () => {
    expect(hostBindingOf('127.0.0.1')).toBe('127.0.0.1');
    expect(hostBindingOf('127.0.0.1:18080')).toBe('127.0.0.1');
    expect(hostBindingOf('[::1]:18080')).toBe('::1');
    expect(hostBindingOf('::1')).toBe('::1');
    expect(hostBindingOf('')).toBe('');
    expect(isLoopbackBinding('127.0.0.1:18080')).toBe(true);
    expect(isLoopbackBinding('[::1]:18080')).toBe(true);
    // An empty binding means every interface, which is the failure this exists
    // to catch — never a missing value to be forgiven.
    expect(isLoopbackBinding('')).toBe(false);
    expect(isLoopbackBinding('0.0.0.0')).toBe(false);
    expect(isLoopbackBinding('192.168.1.10')).toBe(false);
  });
});

describe('the port-exposure differential', () => {
  const port = 27017;
  const label = 'MongoDB';

  it('passes when the port refuses a connection after the stack is up', () => {
    expect(portExposureVerdict({ port, label, before: 'refused', after: 'refused' }).ok).toBe(true);
  });

  it('fails when a port that was free before `up` answers afterwards', () => {
    const verdict = portExposureVerdict({ port, label, before: 'refused', after: 'open' });
    expect(verdict.ok).toBe(false);
    expect(verdict.detail).toContain('this stack published it');
  });

  it('does not blame the stack for a port the host already held', () => {
    // A developer running MongoDB locally must not turn this gate red; the
    // published-port assertion is what carries the verdict in that case, and the
    // report says so rather than passing silently.
    const verdict = portExposureVerdict({ port, label, before: 'open', after: 'open' });
    expect(verdict.ok).toBe(true);
    expect(verdict.detail).toContain('host process already held this port');
  });

  it('treats a filtered port as not reachable', () => {
    expect(portExposureVerdict({ port, label, before: 'refused', after: 'timeout' }).ok).toBe(true);
  });
});

describe('the throwaway deployment configuration', () => {
  it('renders KEY=VALUE lines a Compose env file can read', () => {
    expect(renderEnvFile({ A: '1', B: 'ff00' })).toBe('A=1\nB=ff00\n');
  });

  it('refuses a value that is not a bare literal', () => {
    // Compose would read a `#` as a comment and a quote as a quote, so a value
    // that needed quoting would silently arrive truncated — and the app would
    // fail its config validation for a reason nothing could explain.
    for (const bad of ['two words', 'has#hash', "quo'te", 'inter$polated']) {
      expect(() => renderEnvFile({ SECRET: bad })).toThrow(/not a bare literal/);
    }
  });

  it('gives both configured services the absolute path to the env file', () => {
    // The EXACT document, not three substrings. The override used to be JSON,
    // which validated itself — a malformed emission threw in `JSON.parse`. YAML
    // does not: with `- path:` indented to the wrong column every `toContain`
    // still passes and Compose rejects the file at run time, five minutes into a
    // gate. This is the assertion that replaces the parser.
    expect(renderOverride('/tmp/drill/drill.env')).toBe(
      'services:\n' +
        '  hvault-app:\n' +
        '    env_file: !override\n' +
        '      - path: "/tmp/drill/drill.env"\n' +
        '        required: true\n' +
        '  hvault-bootstrap:\n' +
        '    env_file: !override\n' +
        '      - path: "/tmp/drill/drill.env"\n' +
        '        required: true\n',
    );
  });

  it('REPLACES the base env_file list rather than extending it', () => {
    // Compose merges sequences by appending, so an override without `!override`
    // loads the operator's root `.env` underneath the drill's throwaway one: the
    // pinned `environment:` block still wins for the keys it names, and every key
    // it does not — METRICS_TOKEN, ENABLE_SWAGGER, SMTP_*, LOG_DIRECTORY — reaches
    // the containers. A clean room that inherits the desk it runs on is measuring
    // something other than "this stack comes up from nothing".
    const override = renderOverride('/tmp/drill/drill.env');
    expect(override.match(/env_file:/g)).toHaveLength(2);
    expect(override.match(/env_file: !override/g)).toHaveLength(2);
  });

  it('keeps a Windows path intact through the YAML it emits', () => {
    // The override used to be JSON precisely because a bare YAML scalar mangles
    // backslashes; a YAML double-quoted scalar uses JSON's own escaping, so the
    // path is still JSON-encoded now that the document must carry a tag.
    const override = renderOverride('D:\\hv drill\\drill.env');
    expect(override).toContain('- path: "D:\\\\hv drill\\\\drill.env"');
  });

  it('refuses a relative env-file path', () => {
    // Relative paths in a Compose file resolve against the PROJECT directory,
    // not against the override that declares them, so a relative path here would
    // quietly resolve inside the repository.
    expect(() => renderOverride('drill.env')).toThrow(/must be absolute/);
    expect(() => renderOverride('./tmp/drill.env')).toThrow(/must be absolute/);
  });
});

describe("the provisioner's own account of what it did", () => {
  it('tells the two branches apart', () => {
    expect(
      parseProvisionLog("[hvault-db-init] created 'hvault_app' with readWrite on hvault"),
    ).toEqual({ created: true, reconciled: false });
    expect(
      parseProvisionLog(
        "[hvault-db-init] 'hvault_app' already exists; roles reconciled, password untouched",
      ),
    ).toEqual({ created: false, reconciled: true });
    expect(parseProvisionLog('')).toEqual({ created: false, reconciled: false });
  });
});

describe('the flow client', () => {
  it('keeps the last value of each cookie and drops a cleared one', () => {
    const jar = createCookieJar();
    expect(jar.header()).toBeUndefined();

    jar.capture(['refreshToken=abc; Path=/; HttpOnly; Secure', '__csrf=t1; Path=/']);
    expect(jar.header()).toBe('refreshToken=abc; __csrf=t1');

    jar.capture(['__csrf=t2; Path=/']);
    expect(jar.header()).toBe('refreshToken=abc; __csrf=t2');

    // A server that ends the session must not have its own instruction ignored.
    jar.capture(['refreshToken=; Path=/; Max-Age=0']);
    expect(jar.has('refreshToken')).toBe(false);
    expect(jar.header()).toBe('__csrf=t2');
  });

  it('parses the Set-Cookie forms this API sends, and refuses nonsense', () => {
    expect(parseSetCookie('a=b; Path=/')).toEqual({ name: 'a', value: 'b', cleared: false });
    expect(parseSetCookie('a=b; Max-Age=0')?.cleared).toBe(true);
    expect(parseSetCookie('a=b; Expires=Thu, 01 Jan 1970 00:00:00 GMT')?.cleared).toBe(true);
    expect(parseSetCookie('novalue')).toBeNull();
    expect(parseSetCookie('')).toBeNull();
  });

  it('rejects a wrong status and a wrong envelope, quoting the body either way', () => {
    const ok = {
      status: 200,
      text: '{"success":true,"data":{"csrfToken":"t"}}',
      json: { success: true, data: { csrfToken: 't' } },
    };
    expect(expectEnvelope('csrf', ok, 200)).toEqual({ csrfToken: 't' });

    expect(() =>
      expectEnvelope(
        'login',
        { status: 403, text: '{"message":"nope"}', json: { message: 'nope' } },
        200,
      ),
    ).toThrow(/expected HTTP 200, got 403/);
    // A 200 carrying the wrong shape is a real regression class here, and it is
    // the one a status-only assertion waves through.
    expect(() =>
      expectEnvelope(
        'login',
        { status: 200, text: '{"success":false}', json: { success: false } },
        200,
      ),
    ).toThrow(/envelope is not/);
  });
});

describe('waiting for health', () => {
  /** Exactly what the poller needs from a response, and nothing more. */
  interface HealthResponse {
    status: number;
    json: () => Promise<unknown>;
  }

  /** A clock the test owns: no wall-clock reading, so no timing flake. */
  const fakeClock = (stepMs: number) => {
    let value = 0;
    return () => {
      const current = value;
      value += stepMs;
      return current;
    };
  };

  it('returns as soon as the database reports connected, and counts the attempts', async () => {
    let call = 0;
    const fetchImpl = async (): Promise<HealthResponse> => {
      call += 1;
      return {
        status: call < 3 ? 503 : 200,
        json: async () => ({ data: { database: call < 3 ? 'disconnected' : 'connected' } }),
      };
    };
    const result = await waitForHealth('http://127.0.0.1:1/', {
      deadlineMs: 10_000,
      intervalMs: 0,
      fetchImpl,
      now: fakeClock(10),
    });
    expect(result.ok).toBe(true);
    expect(result.attempts).toBe(3);
  });

  it('gives up at the deadline and reports the last thing it saw', async () => {
    const fetchImpl = async (): Promise<never> => {
      throw new Error('ECONNREFUSED 127.0.0.1:18080');
    };
    const result = await waitForHealth('http://127.0.0.1:1/', {
      deadlineMs: 50,
      intervalMs: 0,
      fetchImpl,
      now: fakeClock(10),
    });
    expect(result.ok).toBe(false);
    expect(result.detail).toContain('ECONNREFUSED');
    // It must not report success on a 200 that never says "connected", either —
    // covered by the shape of the check above: only `database: 'connected'` at
    // status 200 returns ok.
    expect(result.attempts).toBeGreaterThan(0);
  });

  it('refuses a 200 whose body does not say the database is connected', async () => {
    const fetchImpl = async (): Promise<HealthResponse> => ({
      status: 200,
      json: async () => ({ data: { database: 'disconnected' } }),
    });
    const result = await waitForHealth('http://127.0.0.1:1/', {
      deadlineMs: 30,
      intervalMs: 0,
      fetchImpl,
      now: fakeClock(10),
    });
    expect(result.ok).toBe(false);
  });
});
