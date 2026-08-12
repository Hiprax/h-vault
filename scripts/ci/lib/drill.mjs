/**
 * The deployment drill's decisions, separated from its plumbing.
 *
 * Everything here is pure: what "every service is healthy" means for a stack
 * that contains two one-shots, what the stack is allowed to publish, and what
 * configuration a throwaway deployment needs. They are the claims the gate
 * makes, and a claim that can only be exercised by standing a five-service
 * Compose stack up is a claim nothing tests — the same reason `lib/tiers.mjs`
 * exists beside the runner rather than inside it.
 *
 * `scripts/ci/deploy-drill.mjs` owns the docker commands; this file owns the
 * verdicts.
 */

/**
 * What each service must be doing once `up --wait` returns.
 *
 * The distinction is load-bearing rather than bookkeeping. `hvault-bootstrap`
 * and `hvault-db-init` are ONE-SHOTS: they run to completion and exit 0, and the
 * app gates on `service_completed_successfully`. A drill that demanded every
 * service be "running" would fail on a perfectly healthy stack, and the obvious
 * repair — asserting only on the services that stay up — would stop checking the
 * two containers whose failure silently costs the deployment its indexes and its
 * least-privilege database user.
 */
export const SERVICE_EXPECTATIONS = {
  'hvault-nginx': 'healthy',
  'hvault-app': 'healthy',
  'hvault-db': 'healthy',
  'hvault-bootstrap': 'completed',
  'hvault-db-init': 'completed',
};

/**
 * Parses `docker compose ps --format json`.
 *
 * Compose has emitted BOTH shapes within its supported range: newline-delimited
 * objects, and a single JSON array. Handling only one of them produces an empty
 * service list, and an empty list would make every "is anything unhealthy?"
 * check below pass by vacuity — a green drill against a stack nobody looked at.
 * `expectedCount` is the caller's guard against exactly that.
 */
export function parseComposePs(stdout) {
  const text = String(stdout ?? '').trim();
  if (text.length === 0) return [];
  if (text.startsWith('[')) {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed) ? parsed : [];
  }
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('{'))
    .map((line) => JSON.parse(line));
}

/** `running`/`exited`/`healthy` as Compose spells them, normalised to lower case. */
const lower = (value) => String(value ?? '').toLowerCase();

/**
 * One service's adjudication. Named rather than inlined because the test suite
 * for this file is type-checked, and an `object[]` return type makes every
 * assertion about a verdict's contents a compile error.
 *
 * @typedef {{service: string, ok: boolean, status: string, detail: string,
 *            health?: string, exitCode?: number}} ServiceVerdict
 */

/**
 * Adjudicates one `docker compose ps` row against its expectation.
 *
 * A service with a healthcheck that reports no health at all is NOT treated as
 * healthy: Compose leaves `Health` empty both for a container without a probe
 * and for one whose probe has not run yet, and accepting "" would turn the
 * gate's central claim into "the container exists".
 *
 * @param {string} service
 * @param {'healthy'|'completed'} expectation
 * @param {Record<string, any> | undefined} row
 * @returns {ServiceVerdict}
 */
export function verdictFor(service, expectation, row) {
  if (!row)
    return { service, ok: false, status: 'absent', detail: 'no container for this service' };

  const state = lower(row.State);
  const health = lower(row.Health);
  const exitCode = Number(row.ExitCode ?? 0);

  if (expectation === 'completed') {
    const ok = state === 'exited' && exitCode === 0;
    return {
      service,
      ok,
      status: state,
      exitCode,
      detail: ok
        ? 'ran to completion (exit 0)'
        : `expected a completed one-shot, got ${state} (exit ${String(exitCode)})`,
    };
  }

  const ok = state === 'running' && health === 'healthy';
  return {
    service,
    ok,
    status: state,
    health: row.Health ?? '',
    detail: ok
      ? 'running and healthy'
      : `expected running+healthy, got ${state || 'unknown'}/${health || 'no health reported'}`,
  };
}

/**
 * @param {Record<string, any>[]} rows   parsed `docker compose ps --all` output
 * @param {Record<string,string>} [expectations]
 * @returns {{verdicts: ServiceVerdict[], unhealthy: ServiceVerdict[], unexpected: string[]}}
 */
export function serviceVerdicts(rows, expectations = SERVICE_EXPECTATIONS) {
  const byService = new Map(rows.map((row) => [String(row.Service ?? ''), row]));
  const verdicts = Object.entries(expectations).map(([service, expectation]) =>
    verdictFor(service, expectation, byService.get(service)),
  );
  // A service the stack grew that this table does not name is reported rather
  // than ignored: an unexamined container in a production stack is precisely the
  // thing a deployment drill exists to notice.
  const unexpected = [...byService.keys()].filter(
    (service) => service.length > 0 && !(service in expectations),
  );
  return { verdicts, unhealthy: verdicts.filter((verdict) => !verdict.ok), unexpected };
}

/**
 * Every host port the running project publishes, from Compose's own view.
 *
 * `Publishers` entries with no `PublishedPort` are container-side ports Compose
 * lists for completeness (an `expose`, or a mapping that was never bound); only
 * a non-zero published port is reachable from the host, so only those count.
 */
export function publishedPorts(rows) {
  const ports = [];
  for (const row of rows) {
    for (const publisher of row.Publishers ?? []) {
      const published = Number(publisher.PublishedPort ?? 0);
      if (published === 0) continue;
      ports.push({
        service: String(row.Service ?? ''),
        url: String(publisher.URL ?? ''),
        published,
        target: Number(publisher.TargetPort ?? 0),
        protocol: String(publisher.Protocol ?? 'tcp'),
      });
    }
  }
  return ports;
}

/**
 * The host address a Compose publisher is bound to.
 *
 * `Publishers[].URL` is the HOST side of the mapping and Compose has spelled it
 * several ways across versions — `127.0.0.1` on its own (measured, v5.4), a
 * `host:port` pair, a bracketed IPv6 literal, and empty for a port published on
 * every interface. Parsing it in one place, tolerantly, is what keeps the
 * loopback assertion below from silently becoming true-for-the-wrong-reason when
 * the format shifts: a naive `startsWith('127.0.0.1:')` reads a correctly-bound
 * port as unbound (measured), and a naive `/:\d+$/` strip turns `::1` into `:`.
 */
export function hostBindingOf(url) {
  const raw = String(url ?? '').trim();
  if (raw.length === 0) return '';
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(raw);
  if (bracketed) return bracketed[1];
  const parts = raw.split(':');
  // Exactly one colon followed by digits is `host:port`; anything with more
  // colons is a bare IPv6 address and is returned whole.
  if (parts.length === 2 && /^\d+$/.test(parts[1])) return parts[0];
  return raw;
}

/** An empty binding means "every interface", which is the failure this exists to catch. */
export const isLoopbackBinding = (url) =>
  ['127.0.0.1', '::1', 'localhost'].includes(hostBindingOf(url));

/**
 * The stack's single-port claim, checked as an EXACT set rather than as "the one
 * we wanted is there".
 *
 * Two failures matter equally and only this shape catches both: a second
 * published port appearing anywhere in the stack (the database, the app's 5000),
 * and the one legitimate port losing its `127.0.0.1` host binding — which is not
 * a hardening nicety here, because Docker's iptables DOCKER chain is evaluated
 * before INPUT, so a port published on 0.0.0.0 is reachable from the whole
 * network even behind an active `ufw deny`.
 */
export function singlePortProblems(rows, { port, service = 'hvault-nginx', target = 8080 }) {
  const problems = [];
  const ports = publishedPorts(rows);

  const describe = (entry) => `${entry.service}→${entry.url || '*'}:${String(entry.published)}`;

  if (ports.length !== 1) {
    problems.push(
      `the stack publishes ${String(ports.length)} host port(s), expected exactly 1: ` +
        (ports.map(describe).join(', ') || '(none)'),
    );
  }
  for (const entry of ports) {
    if (entry.service !== service) {
      problems.push(`${describe(entry)}; only ${service} may publish a port`);
    }
    if (!isLoopbackBinding(entry.url)) {
      problems.push(
        `${describe(entry)} is not bound to loopback — a port published on every interface is reachable from the whole network even behind an active ufw deny, because Docker's iptables DOCKER chain is evaluated before INPUT`,
      );
    }
    if (entry.published !== port) {
      problems.push(
        `${entry.service} publishes host port ${String(entry.published)}, expected ${String(port)}`,
      );
    }
    if (entry.target !== target) {
      problems.push(
        `${entry.service} maps to container port ${String(entry.target)}, expected ${String(target)}`,
      );
    }
  }
  return problems;
}

/**
 * A TCP probe's two readings, before and after the stack came up, turned into a
 * verdict.
 *
 * The differential is what makes this assertion honest on a developer's machine.
 * A host that already runs MongoDB on 27017 answers the probe whatever the stack
 * does, so a bare "the port must refuse" check would be red for a reason that
 * has nothing to do with the deployment — and the usual repair (delete the
 * check) removes the very assertion that catches a database published to the
 * host. Reading the port BEFORE `up` attributes it: occupied beforehand means
 * the host owns it, free beforehand and open afterwards means the stack opened
 * it, which is a failure.
 */
export function portExposureVerdict({ port, before, after, label }) {
  if (after !== 'open') {
    return {
      port,
      label,
      ok: true,
      before,
      after,
      detail: `not reachable from the host (${after})`,
    };
  }
  if (before === 'open') {
    return {
      port,
      label,
      ok: true,
      before,
      after,
      detail:
        'a host process already held this port before the stack started, so the stack did not open it — the published-port assertion is what carries the verdict here',
    };
  }
  return {
    port,
    label,
    ok: false,
    before,
    after,
    detail: 'the port was free before `up` and is reachable now, so this stack published it',
  };
}

/**
 * Renders a `.env` file for the throwaway deployment.
 *
 * Values are written verbatim and unquoted, which is safe only because every
 * value the drill generates is hex or a fixed literal — the same
 * trusted-literal invariant `proc.mjs` enforces for shell arguments. Compose
 * would otherwise treat a `#` as a comment and a quote as a quote.
 */
export function renderEnvFile(values) {
  for (const [key, value] of Object.entries(values)) {
    if (/[\s#'"$]/.test(String(value))) {
      throw new Error(`drill env value for ${key} is not a bare literal: ${String(value)}`);
    }
  }
  return `${Object.entries(values)
    .map(([key, value]) => `${key}=${String(value)}`)
    .join('\n')}\n`;
}

/**
 * The Compose override that hands the throwaway configuration to the containers.
 *
 * The stack's own `env_file: .env` is `required: false`, so a checkout with no
 * `.env` — which is every clean room, and this repository's own working tree —
 * starts an app with no JWT secrets and dies at config validation. Appending a
 * second env file is exactly what an operator's `.env` does, one key at a time,
 * and it leaves the real compose file under test rather than substituting a
 * simplified copy of it.
 *
 * The path must be ABSOLUTE: relative paths in a Compose file resolve against
 * the PROJECT directory (the first `-f` file's directory), not against the
 * override that declares them, so a relative path here would silently resolve
 * inside the repository.
 */
export function renderOverride(envFileAbsolutePath) {
  if (!envFileAbsolutePath.startsWith('/') && !/^[A-Za-z]:[\\/]/.test(envFileAbsolutePath)) {
    throw new Error(`the drill env file path must be absolute, got: ${envFileAbsolutePath}`);
  }
  // Written as JSON, which every YAML parser accepts and which cannot be broken
  // by a Windows path's backslashes the way a bare YAML scalar can.
  return `${JSON.stringify(
    {
      services: Object.fromEntries(
        ['hvault-app', 'hvault-bootstrap'].map((service) => [
          service,
          { env_file: [{ path: envFileAbsolutePath, required: true }] },
        ]),
      ),
    },
    null,
    2,
  )}\n`;
}

/**
 * Reads `provision-app-user.js`'s one line of output.
 *
 * The drill's real assertion about password rotation is behavioural — the
 * rotated password still authenticates afterwards — because a log line can only
 * say what the script believes it did. This is the corroborating half: it tells
 * a reader WHICH branch ran, which is what turns "the assertion passed" into "it
 * passed for the right reason".
 */
export function parseProvisionLog(text) {
  const output = String(text ?? '');
  return {
    created: /created '.*' with readWrite on hvault/.test(output),
    reconciled: /already exists; roles reconciled, password untouched/.test(output),
  };
}
