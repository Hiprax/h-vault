/**
 * The clean-room gates' decisions: `test:deploy`'s verdicts and the end-to-end
 * flow's HTTP contract.
 *
 * Both runners are unavoidably slow — one stands six containers up, the other
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
  DOCUMENT_FRAMING,
  VaultFlowError,
  buildDocumentFixture,
  createClient,
  createCookieJar,
  expectEnvelope,
  parseSetCookie,
  readDocumentSegment,
  waitForHealth,
  wrappedKeyProblem,
} from '../../../scripts/ci/lib/vault-flow.mjs';
import {
  SANDBOX_ASSET_HEADERS_EXPECTED,
  SANDBOX_CSP_EXPECTED,
  SANDBOX_DOCUMENT_CACHE_CONTROL,
  appAssetProblems,
  assetResponseProblems,
  cspProblems,
  sandboxAssetProblems,
  sandboxAssetUrls,
} from '../../../scripts/ci/lib/sandbox-headers.mjs';
import {
  SANDBOX_ASSET_HEADERS,
  SANDBOX_CSP_DIRECTIVES,
  SANDBOX_CSP_HEADER,
  SANDBOX_DOCUMENT_CACHE_CONTROL as SANDBOX_DOCUMENT_CACHE_CONTROL_HEADER,
} from '../src/config/sandboxCsp.js';
import {
  DOCUMENT_NONCE_PREFIX_BYTES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_STREAM_SALT_BYTES,
  DOCUMENT_TAG_BYTES,
  completeDocumentUploadSchema,
  initDocumentUploadSchema,
} from '@hvault/shared';

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

/** A whole healthy stack: four long-lived services and two completed one-shots. */
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
  // The object storage engine. `healthy` here, deliberately stricter than the
  // app's own `service_started` dependency on it: the app must not be held down by
  // storage, but the DRILL is asking whether the deployment came up correctly, and
  // there the engine reaching its own healthcheck is the thing to prove.
  row({ Service: 'hvault-s3' }),
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
  it('gives up on a request that is never answered, rather than waiting for ever', async () => {
    // The pipeline has no deadline of its own: `local-ci.mjs` puts no timeout on
    // a gate, so a deployment that accepts the connection and then answers
    // nothing would hang `test:deploy` and `test:smoke` indefinitely instead of
    // failing them. A hung gate is worse than a red one — nobody gets a report.
    const client = createClient('http://stack.invalid', {
      timeoutMs: 25,
      // Answers only when the deadline fires, which is what a stalled server
      // looks like from here.
      fetchImpl: (_url: string | URL, init?: object) =>
        new Promise<never>((_resolve, reject) => {
          (init as { signal?: AbortSignal } | undefined)?.signal?.addEventListener('abort', () => {
            reject(new DOMException('The operation was aborted', 'TimeoutError'));
          });
        }),
    });

    const error = await client.get('/api/v1/health').catch((thrown: unknown) => thrown);
    expect(error).toBeInstanceOf(VaultFlowError);
    expect((error as VaultFlowError).message).toBe('GET /api/v1/health: no answer within 25 ms');
    expect((error as VaultFlowError).context).toMatchObject({ timeoutMs: 25 });
  });

  it('does not relabel an ordinary transport failure as a timeout', async () => {
    // The negative, and the reason the abort is discriminated on the SIGNAL
    // rather than on an error name: a connection refused while the stack is
    // still booting is what `waitForHealth` retries on, and a client that
    // reported it as "no answer within 60000 ms" would turn every honest boot
    // into a mystery.
    const client = createClient('http://stack.invalid', {
      timeoutMs: 60_000,
      fetchImpl: () => Promise.reject(new TypeError('fetch failed')),
    });

    const error = await client.get('/api/v1/health').catch((thrown: unknown) => thrown);
    expect(error).toBeInstanceOf(TypeError);
    expect(error).not.toBeInstanceOf(VaultFlowError);
    expect((error as Error).message).toBe('fetch failed');
  });

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

describe('the gate-side restatement of the sandbox serving contract', () => {
  // The one assertion that makes the restatement safe.
  //
  // `scripts/ci/lib/sandbox-headers.mjs` restates the policy because a gate
  // runner is plain JavaScript with no build step and cannot import a TypeScript
  // module — and BOTH gates that read the served header (`test:smoke` over the
  // built artifact, `test:deploy` over the header that reaches a client through
  // Nginx) compare against that restatement. Without this test the two copies
  // are free to diverge, and the failure is the worst shape available: a gate
  // that passes while checking a policy the server no longer sends.
  it('describes exactly the policy the server exports, directive for directive', () => {
    const serverPolicy = Object.fromEntries(
      Object.entries(SANDBOX_CSP_DIRECTIVES).map(([directive, sources]) => [
        directive,
        sources.join(' '),
      ]),
    );
    // WHOLE, not per key: an added or removed directive on either side must fail
    // as loudly as a widened source list.
    expect({ ...SANDBOX_CSP_EXPECTED }).toEqual(serverPolicy);
  });

  it('describes exactly the two asset headers and the cache directive the server exports', () => {
    // Lower-cased on the gate side because `Headers.get` takes a lower-cased
    // name; the server side is spelled the way it goes on the wire. The
    // normalisation is what this compares, so a header RENAMED on one side
    // cannot slip through.
    const serverHeaders = Object.fromEntries(
      Object.entries(SANDBOX_ASSET_HEADERS).map(([name, value]) => [name.toLowerCase(), value]),
    );
    expect({ ...SANDBOX_ASSET_HEADERS_EXPECTED }).toEqual(serverHeaders);
    expect(SANDBOX_DOCUMENT_CACHE_CONTROL).toBe(SANDBOX_DOCUMENT_CACHE_CONTROL_HEADER);
  });

  it('passes the header the server actually serializes, and nothing weaker', () => {
    // The positive control: the real serialized header, through the real parser.
    expect(cspProblems(SANDBOX_CSP_HEADER)).toEqual([]);
  });

  it('refuses a widened source list, an added directive, and a missing one', () => {
    // Each of the three is one edit away from the correct policy, and each is the
    // exact shape a substring check stays green through.
    const widened = cspProblems(
      SANDBOX_CSP_HEADER.replace("connect-src 'none'", "connect-src 'none' https:"),
    );
    expect(widened).toEqual(['connect-src: expected "\'none\'", got "\'none\' https:"']);

    const added = cspProblems(`${SANDBOX_CSP_HEADER}; script-src-elem 'self'`);
    expect(added).toEqual(['unexpected directive script-src-elem in the served policy']);

    const removed = cspProblems(SANDBOX_CSP_HEADER.replace('; sandbox allow-scripts', ''));
    expect(removed).toEqual(['sandbox: expected "allow-scripts", got "(absent)"']);
  });

  it('refuses two policies on one response, and an absent header', () => {
    // `Headers.get` joins repeated headers with ", ". A browser INTERSECTS two
    // policies, which would kill `blob:` media and `data:` images in one stroke,
    // so a response carrying helmet's application policy BESIDE the sandbox's
    // own is a failure even though every directive of the sandbox's is present.
    const doubled = cspProblems(`${SANDBOX_CSP_HEADER}, default-src 'self'`);
    expect(doubled.some((problem) => problem.includes('two Content-Security-Policy headers'))).toBe(
      true,
    );

    expect(cspProblems('')).toEqual(['no Content-Security-Policy header reached the client']);
    expect(cspProblems(null)).toEqual(['no Content-Security-Policy header reached the client']);
  });

  it('checks BOTH the sandbox script and its stylesheet, and refuses either without the headers', () => {
    // The failure this exists for is named in `vite.config.sandbox.ts`: a switch
    // to explicit `entryFileNames`/`chunkFileNames` that forgot `assetFileNames`
    // leaves the stylesheet in `/assets/` and ships the viewer unstyled in
    // production only, while every script-only assertion still passes.
    const good = (name: string): string | null =>
      SANDBOX_ASSET_HEADERS_EXPECTED[name as keyof typeof SANDBOX_ASSET_HEADERS_EXPECTED] ?? null;
    expect(sandboxAssetProblems('/sandbox-assets/sandbox-abc.js', good)).toEqual([]);

    const noCorp = (name: string): string | null =>
      name === 'cross-origin-resource-policy' ? 'same-origin' : good(name);
    expect(sandboxAssetProblems('/sandbox-assets/sandbox-abc.css', noCorp)).toEqual([
      '/sandbox-assets/sandbox-abc.css cross-origin-resource-policy=same-origin, expected cross-origin',
    ]);

    const noAcao = (name: string): string | null =>
      name === 'access-control-allow-origin' ? null : good(name);
    expect(sandboxAssetProblems('/sandbox-assets/sandbox-abc.js', noAcao)).toEqual([
      '/sandbox-assets/sandbox-abc.js access-control-allow-origin=null, expected *',
    ]);
  });

  it('keeps the widening out of /assets/, phrased as the values that directory does carry', () => {
    // Phrased as exact values rather than as ABSENCE, deliberately: under Express
    // every response already carries both header NAMES (a fixed CORS origin and
    // helmet's same-origin CORP), so a "must not be present" assertion would be
    // false on a correct build — and the tempting way to make it pass is to
    // delete the negative, which is the whole check. Nginx serves the directory
    // from disk and sends neither, so the expected pair is the caller's to
    // declare.
    const nginx = (): string | null => null;
    expect(appAssetProblems('/assets/main-abc.js', nginx, { acao: null, corp: null })).toEqual([]);

    const leaked = (name: string): string | null =>
      name === 'access-control-allow-origin' ? '*' : 'cross-origin';
    const problems = appAssetProblems('/assets/main-abc.js', leaked, { acao: null, corp: null });
    expect(problems).toHaveLength(2);
    expect(problems[0]).toContain('must stay inside sandbox-assets/');
  });

  it('refuses a probe that was answered by anything other than the asset itself', () => {
    // The half of the asset check that can pass on nothing, and it can pass on
    // nothing in two different shapes — one per gate, both of them reachable.
    //
    // Under Express (`test:smoke`) a path with no file behind it does NOT 404:
    // `express.static` falls through and `app.ts`'s SPA catch-all answers 200
    // with index.html, carrying the application's own CORS origin and helmet's
    // same-origin CORP — which is EXACTLY what `appAssetProblems` is asked to
    // expect for `/assets/`. So the header check alone reports a clean pass over
    // a response that is not the bundle.
    //
    // Under Nginx (`test:deploy`) `/assets/` is served from disk, so the same
    // request can be a real 404 — and a 404 carries neither header, which is a
    // clean pass for the very same negative.
    //
    // Status and content type together are the only thing that tells either from
    // the asset, which is why both live in one helper rather than one in each
    // gate.
    const respond = (status: number, contentType: string | null) => ({
      status,
      headers: { get: (name: string) => (name === 'content-type' ? contentType : null) },
    });

    // The positive control, and it is load-bearing: without it every assertion
    // below is satisfied by a helper that reports a problem for everything.
    expect(
      assetResponseProblems('/assets/main-abc.js', respond(200, 'text/javascript; charset=UTF-8')),
    ).toEqual([]);
    expect(
      assetResponseProblems('/sandbox-assets/sandbox-abc.css', respond(200, 'text/css')),
    ).toEqual([]);

    // The SPA shell, 200 and all. This is the Express shape.
    const shell = assetResponseProblems(
      '/assets/main-abc.js',
      respond(200, 'text/html; charset=UTF-8'),
    );
    expect(shell).toHaveLength(1);
    expect(shell[0]).toContain('HTML document');

    // The Nginx shape, reported as the status alone: "it answered 404" already
    // says everything there is to say about the body, so a second complaint about
    // its content type would be noise in a failure report.
    expect(assetResponseProblems('/assets/main-abc.js', respond(404, 'text/html'))).toEqual([
      '/assets/main-abc.js answered 404, not 200',
    ]);

    // AND THE LIMIT OF THE CHECK, pinned so it reads as a decision. Only an HTML
    // answer is refused, because that is the one shape a path with no file behind
    // it actually takes; a 200 with no content type at all is accepted. Refusing
    // that too would be a rule with no measured failure behind it, and the cost
    // of getting it wrong is a release gate that fails on a proxy rather than on
    // this application.
    expect(assetResponseProblems('/sandbox-assets/sandbox-abc.js', respond(200, null))).toEqual([]);
  });

  it('finds the sandbox document’s own script and stylesheet, and neither in the SPA shell', () => {
    // Both are content-hashed, so there is nothing to hard-code; the regexes have
    // to tolerate Vite's real attribute order, which puts `crossorigin` between
    // `rel`/`type` and `href`/`src`.
    const html =
      '<link rel="stylesheet" crossorigin href="/sandbox-assets/sandbox-laVbjAIq.css">' +
      '<script type="module" crossorigin src="/sandbox-assets/sandbox-L38d8GGN.js"></script>';
    expect(sandboxAssetUrls(html)).toEqual({
      script: '/sandbox-assets/sandbox-L38d8GGN.js',
      stylesheet: '/sandbox-assets/sandbox-laVbjAIq.css',
    });

    // The SPA shell names `/assets/` and carries a nonce. Returning its URLs here
    // would make the drill probe the application's own bundle and then assert
    // that it carries the sandbox's headers — a check that fails on a correct
    // build, which is how a check gets deleted.
    const shell =
      '<link rel="stylesheet" crossorigin href="/assets/index-Tp2RFl97.css">' +
      '<script type="module" nonce="abc" crossorigin src="/assets/main-4aSwR9SA.js"></script>';
    expect(sandboxAssetUrls(shell)).toEqual({ script: null, stylesheet: null });
  });
});

describe('the document leg of the deployment journey', () => {
  it('restates exactly the framing constants the wire contract is built from', () => {
    // The gate-side copy exists because a gate runner cannot import TypeScript.
    // Every one of these is a number the server REFUSES a transfer over, so a
    // stale value here would fail the drill with a 400 that reads like a broken
    // deployment rather than like a stale constant.
    expect(DOCUMENT_FRAMING).toEqual({
      tagBytes: DOCUMENT_TAG_BYTES,
      streamSaltBytes: DOCUMENT_STREAM_SALT_BYTES,
      noncePrefixBytes: DOCUMENT_NONCE_PREFIX_BYTES,
    });
    // And the CHUNK SIZE is not among them, which is enforced rather than
    // stylistic: `packages/shared/tests/constants.test.ts` scans every source
    // file for either chunk size as a decimal literal and fails on a second copy
    // anywhere but the definition. The drill reads that number out of the
    // deployment's own `GET /config` instead, and then checks the init response
    // against it — so the two server surfaces that publish the framing are
    // compared with each other rather than with a gate-side copy. This assertion
    // is what stops the copy coming back.
    expect(Object.keys(DOCUMENT_FRAMING)).not.toContain('plaintextChunkBytes');
  });

  it('builds an init body the real wire schema accepts, framed to exactly one segment', () => {
    // The fixture is checked against the SERVER's own schema rather than against
    // a restatement of it, which is what makes this a test of the drill's
    // payload: `streamSalt` and `noncePrefix` are validated as padded standard
    // base64 of an exact byte count, and `declaredChunkCount` must equal
    // `ceil(declaredPlaintextBytes / the server chunk size)`.
    const fixture = buildDocumentFixture();
    const parsed = initDocumentUploadSchema.safeParse(fixture.init);
    expect(parsed.success).toBe(true);
    expect(fixture.init.declaredChunkCount).toBe(1);
    // The identity the completion endpoint DERIVES the row from: it computes
    // `plaintextBytes` as `ciphertextBytes - tagBytes * chunkCount` and refuses
    // the transfer when the result cannot frame the document. A segment that was
    // not exactly one tag longer than its plaintext would be a 400 there.
    expect(fixture.segment.length).toBe(fixture.plaintextBytes + DOCUMENT_TAG_BYTES);
    expect(fixture.plaintextBytes).toBeLessThanOrEqual(DOCUMENT_PLAINTEXT_CHUNK_BYTES);
    // Odd and unaligned on purpose: a round power of two would let an off-by-one
    // in the tag arithmetic round to the same answer.
    expect(fixture.plaintextBytes % 2).toBe(1);
  });

  it('builds a completion body the real wire schema accepts, carrying the wrapped key again', () => {
    const fixture = buildDocumentFixture();
    const parsed = completeDocumentUploadSchema.safeParse({
      ...fixture.meta,
      encryptedDek: fixture.init.encryptedDek,
      dekIv: fixture.init.dekIv,
      dekTag: fixture.init.dekTag,
      vaultKeyVersion: 0,
    });
    expect(parsed.success).toBe(true);
  });

  it('generates fresh bytes per document, so a round trip cannot pass against a cached response', () => {
    const first = buildDocumentFixture();
    const second = buildDocumentFixture();
    expect(Buffer.compare(first.segment, second.segment)).not.toBe(0);
    expect(first.init.streamSalt).not.toBe(second.init.streamSalt);
  });
});

describe('the flow client’s binary request', () => {
  /** What `createClient` touches on a response, and nothing more. */
  interface StubResponse {
    status: number;
    headers: { get: (name: string) => string | null; getSetCookie: () => string[] };
    text: () => Promise<string>;
    arrayBuffer: () => Promise<ArrayBuffer>;
  }

  const headersOf = (map: Record<string, string>): StubResponse['headers'] => ({
    get: (name) => map[name.toLowerCase()] ?? null,
    getSetCookie: () => [],
  });

  it('sends a part as octet-stream with the digest header, and never as JSON', async () => {
    const seen: { headers: Record<string, string>; body: unknown }[] = [];
    const fetchImpl = async (_input: URL | string, init?: object): Promise<StubResponse> => {
      const request = (init ?? {}) as { headers: Record<string, string>; body: unknown };
      seen.push({ headers: request.headers, body: request.body });
      return {
        status: 200,
        headers: headersOf({}),
        text: async () => '{"success":true,"data":{"receivedBytes":3}}',
        arrayBuffer: async () => new ArrayBuffer(0),
      };
    };
    const client = createClient('http://127.0.0.1:1/', { fetchImpl });
    const segment = Buffer.from([1, 2, 3]);
    const response = await client.put('/api/v1/documents/uploads/x/parts/1', {
      rawBody: segment,
      extraHeaders: { 'x-hv-part-sha256': 'a'.repeat(64) },
      csrfToken: 'token',
    });

    expect(response.status).toBe(200);
    expect(seen).toHaveLength(1);
    // The body must be the Buffer ITSELF, not a JSON re-encoding of it: the part
    // route parses `application/octet-stream` alone, and a JSON body arrives at
    // the handler as `{0: 1, 1: 2, ...}` — which the handler refuses with a 415,
    // three steps after the mistake.
    expect(seen[0]!.body).toBe(segment);
    expect(seen[0]!.headers['content-type']).toBe('application/octet-stream');
    expect(seen[0]!.headers['x-hv-part-sha256']).toBe('a'.repeat(64));
    expect(seen[0]!.headers['x-csrf-token']).toBe('token');
  });

  it('reads a binary response as exact bytes, and still decodes an error envelope', async () => {
    const payload = new Uint8Array([9, 8, 7, 0, 255]);
    const client = createClient('http://127.0.0.1:1/', {
      fetchImpl: async (): Promise<StubResponse> => ({
        status: 200,
        headers: headersOf({ 'content-type': 'application/octet-stream' }),
        text: async () => '',
        arrayBuffer: async () => payload.buffer.slice(0),
      }),
    });
    const ok = await client.get('/api/v1/documents/x/segments/0', { responseType: 'bytes' });
    // `bytes` is present only on the binary branch of the union `request`
    // returns, so it is asserted to exist before it is spread — a spread of
    // `undefined` is a TypeError, not a failed assertion.
    expect(ok.bytes).toBeInstanceOf(Uint8Array);
    expect([...ok.bytes!]).toEqual([9, 8, 7, 0, 255]);

    // A refusal on that route is a JSON envelope rather than bytes, and a drill
    // whose message is a byte count instead of the envelope costs more time than
    // the gate saves.
    const refusing = createClient('http://127.0.0.1:1/', {
      fetchImpl: async (): Promise<StubResponse> => ({
        status: 404,
        headers: headersOf({}),
        text: async () => '',
        arrayBuffer: async () =>
          new TextEncoder().encode('{"success":false,"message":"Document not found"}').buffer,
      }),
    });
    const gone = await refusing.get('/api/v1/documents/x/segments/0', { responseType: 'bytes' });
    expect(gone.status).toBe(404);
    expect(gone.json).toEqual({ success: false, message: 'Document not found' });
  });
});

describe('reading one sealed segment back', () => {
  const segment = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);

  /**
   * A client double: only the one GET `readDocumentSegment` issues.
   *
   * It RECORDS what it was asked for rather than ignoring it. A double that
   * answers correctly whatever the path is cannot notice a request aimed at the
   * wrong segment, or one that asked for a decoded body — and both would corrupt
   * every byte comparison downstream while this file stayed green.
   */
  const clientReturning = (
    over: { status?: number; headers?: Record<string, string>; bytes?: Uint8Array } = {},
  ): {
    get: (path: string, options?: unknown) => Promise<unknown>;
    calls: { path: string; options: unknown }[];
  } => {
    const bytes = over.bytes ?? new Uint8Array(segment);
    const headers: Record<string, string> = {
      'content-type': 'application/octet-stream',
      'cache-control': 'no-store',
      'content-length': String(bytes.length),
      ...over.headers,
    };
    const calls: { path: string; options: unknown }[] = [];
    return {
      calls,
      get: async (path: string, options?: unknown) => {
        calls.push({ path, options });
        return {
          status: over.status ?? 200,
          headers: { get: (name: string) => headers[name.toLowerCase()] ?? null },
          bytes,
          text: '',
        };
      },
    };
  };

  it('accepts a segment whose bytes and headers are both right, read from segment zero as bytes', async () => {
    const client = clientReturning();
    const read = await readDocumentSegment({ client, documentId: 'd', expected: segment });
    expect(read.bytes).toBe(segment.length);
    // Pinned HERE rather than left to the drill, where the same mistake is a
    // 400 an hour into a container run: exactly one request, at segment zero of
    // the document asked for, and asked for as BYTES. Without `responseType`
    // the client decodes the body as text, which mangles ciphertext silently.
    expect(client.calls).toEqual([
      { path: '/api/v1/documents/d/segments/0', options: { responseType: 'bytes' } },
    ]);
  });

  it('refuses a segment served without no-store, or as anything but octet-stream', async () => {
    // Both are the DEPLOYMENT's job and both are silent when wrong: `no-store` is
    // what keeps user ciphertext out of a disk cache and out of an intermediary
    // on the way through Nginx, and the content type is what stops a browser
    // sniffing it.
    await expect(
      readDocumentSegment({
        client: clientReturning({ headers: { 'cache-control': 'public, max-age=60' } }),
        documentId: 'd',
        expected: segment,
      }),
    ).rejects.toThrow(/headers are not the ones a segment carries/);
    await expect(
      readDocumentSegment({
        client: clientReturning({ headers: { 'content-type': 'text/plain' } }),
        documentId: 'd',
        expected: segment,
      }),
    ).rejects.toThrow(/headers are not the ones a segment carries/);
  });

  it('refuses a Content-Length that disagrees with the framing, even when the body is right', async () => {
    // The header is the exact segment length taken from the row rather than from
    // whatever the engine reported, so a mismatch means a truncated response the
    // client could otherwise mistake for a whole segment.
    await expect(
      readDocumentSegment({
        client: clientReturning({ headers: { 'content-length': '7' } }),
        documentId: 'd',
        expected: segment,
      }),
    ).rejects.toThrow(/headers are not the ones a segment carries/);
  });

  it('names the FIRST differing byte when the bytes changed in transit', async () => {
    const flipped = new Uint8Array(segment);
    flipped[5] = 0xff;
    const error = await readDocumentSegment({
      client: clientReturning({ bytes: flipped }),
      documentId: 'd',
      expected: segment,
    }).catch((thrown: unknown) => thrown);
    expect(error).toBeInstanceOf(VaultFlowError);
    expect((error as VaultFlowError).message).toMatch(/bytes changed in transit/);
    // The index, not just "they differ": over twelve kilobytes a bare mismatch
    // says nothing about whether a proxy re-encoded the body or dropped a chunk.
    expect((error as VaultFlowError).context).toMatchObject({ firstDifferingByte: 5 });
  });

  it('reports a refusal with the response body rather than a byte count', async () => {
    const error = await readDocumentSegment({
      client: {
        get: async () => ({
          status: 404,
          headers: { get: () => null },
          bytes: new Uint8Array(0),
          text: '{"success":false,"message":"The stored contents of this document are missing."}',
        }),
      },
      documentId: 'd',
      expected: segment,
    }).catch((thrown: unknown) => thrown);
    expect((error as VaultFlowError).message).toContain('expected HTTP 200, got 404');
    expect(JSON.stringify((error as VaultFlowError).context)).toContain('are missing');
  });
});

describe('the wrapped key a re-read document must still carry', () => {
  const key = { encryptedDek: 'dek', dekIv: 'iv', dekTag: 'tag' };

  it('passes a row that came back with the same three key fields', () => {
    // The positive control: without it, a check that reported a problem for
    // everything would look identical to a working one in every case below.
    expect(
      wrappedKeyProblem({ ...key, encryptedMeta: 'anything', ciphertextBytes: 9 }, key),
    ).toBeNull();
  });

  it('names the field when a wrapped-key value changed, and stops at the first one', () => {
    // Each of the three, because a check that compared only the ciphertext would
    // pass a rewrapped key under a re-minted IV — and the drill cannot decrypt,
    // so nothing downstream would notice a document that no longer opens.
    expect(wrappedKeyProblem({ ...key, encryptedDek: 'other' }, key)).toEqual({
      field: 'encryptedDek',
      expected: 'dek',
      returned: 'other',
    });
    expect(wrappedKeyProblem({ ...key, dekIv: 'other' }, key)).toEqual({
      field: 'dekIv',
      expected: 'iv',
      returned: 'other',
    });
    expect(wrappedKeyProblem({ ...key, dekTag: 'other' }, key)).toEqual({
      field: 'dekTag',
      expected: 'tag',
      returned: 'other',
    });
  });

  it('reports an absent key as null rather than as a match', () => {
    // `undefined === undefined` is the trap this normalisation exists for: a row
    // that dropped the field entirely, compared against an expectation that also
    // lost it, would otherwise be reported as intact.
    expect(wrappedKeyProblem({ dekIv: 'iv', dekTag: 'tag' }, key)).toEqual({
      field: 'encryptedDek',
      expected: 'dek',
      returned: null,
    });
    expect(wrappedKeyProblem({}, {})).toEqual({
      field: 'encryptedDek',
      expected: null,
      returned: null,
    });
  });

  it('says nothing about the fields that are not the key', () => {
    // Scope, asserted as a negative: `encryptedMeta` is the document's name and
    // framing and is checked elsewhere. Folding it in here would report a
    // metadata difference as a key failure, which is the wrong diagnosis on the
    // one check an operator reads when a restart went wrong.
    expect(
      wrappedKeyProblem({ ...key, encryptedMeta: 'changed' }, { ...key, encryptedMeta: 'was' }),
    ).toBeNull();
  });
});
