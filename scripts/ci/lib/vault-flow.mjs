/**
 * One end-to-end vault flow, over HTTP, against a running deployment.
 *
 * Two gates drive it and neither may have its own copy: `test:smoke` runs it
 * against the BUILT Node artifact, and `test:deploy` runs it against the Compose
 * stack through its single published port. A flow defined twice is a flow that
 * proves two different things while claiming to prove one, and the interesting
 * failure — "the artifact boots but cannot complete a real user journey" — is
 * exactly the one that hides in the difference.
 *
 * The journey is deliberately the shortest path that touches every layer:
 *
 *   csrf-token -> register -> (verify the address out of band) -> login ->
 *   create an item -> read it back -> assert the ciphertext is byte-identical
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE CIPHERTEXT IS COMPARED BYTE FOR BYTE, and the payload is random per
 *     run. A flow that only asserts "201 Created" passes against a deployment
 *     that stores nothing, and one that asserts a fixed blob passes against a
 *     deployment serving a cached response. Round-tripping a fresh random value
 *     is what makes the assertion about THIS write.
 *
 *  b. THE CSRF TOKEN IS RE-FETCHED AFTER LOGIN. The token is an HMAC bound to
 *     `hashToken(refreshToken)` (packages/server/src/middleware/csrf.ts), so the
 *     anonymous token that authorised `register` stops verifying the moment a
 *     refresh cookie exists. Re-fetching is what a browser does; not re-fetching
 *     produces a 403 that reads like a broken deployment.
 *
 *  c. COOKIES ARE KEPT REGARDLESS OF THE `Secure` ATTRIBUTE. In production the
 *     refresh cookie is issued `Secure; SameSite=Strict`, and both gates speak
 *     plain HTTP to a loopback port. That is not a shortcut around the flag: it
 *     is the deployed topology, where TLS is terminated by the host's system
 *     Nginx and the hop this flow drives is the one behind it. A browser would
 *     see https and keep the cookie for the same reason.
 *
 *  d. EVERY STEP ASSERTS THE ENVELOPE, NOT MERELY THE STATUS. This API answers
 *     `{ success, data }` on success and a FLAT `{ success:false, message, ... }`
 *     on failure, and a 200 carrying the wrong shape is a real regression class
 *     here. `expectEnvelope` fails loudly with the body attached, because a
 *     deployment drill whose error message is "undefined is not an object" costs
 *     more time than the gate saves.
 *
 *  e. THE EMAIL VERIFICATION IS INJECTED. `login` answers 403 EMAIL_NOT_VERIFIED
 *     until the address is confirmed, and the two callers reach the database
 *     differently — the smoke gate through the driver it already holds, the
 *     drill through `mongosh` inside the container. Injecting the one step that
 *     genuinely differs keeps everything else identical between them.
 */
import { randomBytes, randomUUID } from 'node:crypto';

/** Registration's `kdfIterations` floor is 500k; the client's real default is 600k. */
const KDF_ITERATIONS = 600_000;

/** Base64 of n random bytes — an opaque stand-in for real ciphertext. */
const b64 = (bytes) => randomBytes(bytes).toString('base64');
/** Lowercase hex, which is what `searchHash` and `authHash` look like on the wire. */
const hex = (bytes) => randomBytes(bytes).toString('hex');

/**
 * The cookie jar.
 *
 * A hand-rolled jar rather than a dependency, because the pipeline's runners are
 * dependency-free by design and this needs exactly two operations. It stores the
 * last value seen per name and ignores every attribute: expiry, path and domain
 * are the browser's job, and this client talks to one origin for a few seconds.
 * `Max-Age=0` is honoured, because that is how the API says "this session is
 * over" and a jar that kept a cleared cookie would send a dead one back.
 */
export function createCookieJar() {
  const jar = new Map();
  return {
    /** @param {string[]} headers raw `set-cookie` lines */
    capture(headers) {
      for (const line of headers ?? []) {
        const parsed = parseSetCookie(line);
        if (!parsed) continue;
        if (parsed.cleared) jar.delete(parsed.name);
        else jar.set(parsed.name, parsed.value);
      }
    },
    /** The `Cookie` request header, or `undefined` when the jar is empty. */
    header() {
      if (jar.size === 0) return undefined;
      return [...jar].map(([name, value]) => `${name}=${value}`).join('; ');
    },
    has: (name) => jar.has(name),
    names: () => [...jar.keys()],
  };
}

/**
 * Parses one `Set-Cookie` line into `{ name, value, cleared }`.
 *
 * Exported because it is the only part of the jar with a decision in it, and a
 * cookie parser that silently mis-handles `Max-Age=0` turns "the server ended
 * the session" into "the client kept using it" — which would surface as a
 * confusing 401 three steps later rather than here.
 */
export function parseSetCookie(line) {
  if (typeof line !== 'string' || line.length === 0) return null;
  const [pair, ...attributes] = line.split(';');
  const eq = pair.indexOf('=');
  if (eq <= 0) return null;
  const name = pair.slice(0, eq).trim();
  const value = pair.slice(eq + 1).trim();
  const cleared =
    value === '' ||
    attributes.some((attribute) => /^\s*max-age\s*=\s*0\s*$/i.test(attribute)) ||
    attributes.some((attribute) => /^\s*expires\s*=\s*thu,\s*01 jan 1970/i.test(attribute));
  return { name, value, cleared };
}

/** Thrown by every assertion below, so a caller can tell a flow failure from a crash. */
export class VaultFlowError extends Error {
  constructor(message, context = {}) {
    super(message);
    this.name = 'VaultFlowError';
    this.context = context;
  }
}

/**
 * An HTTP client bound to one origin, carrying the cookie jar and the bearer
 * token the flow accumulates.
 */
export function createClient(baseUrl, { fetchImpl = fetch } = {}) {
  const jar = createCookieJar();
  let accessToken = '';

  const request = async (method, path, { body, csrfToken, auth = true } = {}) => {
    const headers = { accept: 'application/json' };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (csrfToken) headers['x-csrf-token'] = csrfToken;
    if (auth && accessToken) headers.authorization = `Bearer ${accessToken}`;
    const cookie = jar.header();
    if (cookie) headers.cookie = cookie;

    const response = await fetchImpl(new URL(path, baseUrl), {
      method,
      headers,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      redirect: 'manual',
    });
    // (c) Node's fetch exposes the raw lines here; `headers.get('set-cookie')`
    // would fold several cookies into one comma-joined string that cannot be
    // split again without re-parsing dates.
    jar.capture(response.headers.getSetCookie());

    const text = await response.text();
    let json;
    try {
      json = text.length > 0 ? JSON.parse(text) : undefined;
    } catch {
      json = undefined; // a non-JSON body is reported by the assertion below
    }
    return { status: response.status, headers: response.headers, text, json };
  };

  return {
    request,
    get: (path, options) => request('GET', path, options),
    post: (path, body, options) => request('POST', path, { ...options, body }),
    setAccessToken: (token) => {
      accessToken = token;
    },
    jar,
  };
}

/**
 * (d) Asserts the status AND the success envelope, and puts the real body in the
 * failure message.
 */
export function expectEnvelope(step, response, expectedStatus) {
  if (response.status !== expectedStatus) {
    throw new VaultFlowError(
      `${step}: expected HTTP ${String(expectedStatus)}, got ${String(response.status)}`,
      { body: response.text.slice(0, 600) },
    );
  }
  if (response.json?.success !== true) {
    throw new VaultFlowError(`${step}: response envelope is not { success: true }`, {
      body: response.text.slice(0, 600),
    });
  }
  return response.json.data;
}

/**
 * Polls `/api/v1/health` until it reports a connected database, or the deadline
 * expires.
 *
 * The deadline is wall-clock and the failure is a FAILURE, never a skip: "the
 * deployment came up" is the first thing both gates claim, and a gate that waits
 * forever for it reports nothing at all. `attempts` is counted for the report so
 * a slow start is visible as a number rather than as a feeling.
 *
 * `fetchImpl` and `now` are seams, and they are typed STRUCTURALLY rather than
 * as `typeof fetch` / `typeof Date.now` on purpose: the polling loop is the one
 * piece of this file with a decision in it, its test has to be able to hand it a
 * two-line stub and a clock it owns, and a test that has to fabricate a whole
 * `Response` to exercise a deadline ends up asserting nothing about the deadline.
 *
 * @param {string} baseUrl
 * @param {object} [options]
 * @param {number} [options.deadlineMs]
 * @param {number} [options.intervalMs]
 * @param {(input: URL|string, init?: object) => Promise<{status: number, json: () => Promise<any>}>} [options.fetchImpl]
 * @param {() => number} [options.now]
 */
export async function waitForHealth(
  baseUrl,
  { deadlineMs = 90_000, intervalMs = 1_000, fetchImpl = fetch, now = Date.now } = {},
) {
  const started = now();
  let attempts = 0;
  let lastDetail = 'no response yet';

  while (now() - started < deadlineMs) {
    attempts += 1;
    try {
      const response = await fetchImpl(new URL('/api/v1/health', baseUrl), { method: 'GET' });
      const body = await response.json();
      if (response.status === 200 && body?.data?.database === 'connected') {
        return { ok: true, attempts, waitedMs: now() - started, body };
      }
      lastDetail = `HTTP ${String(response.status)} ${JSON.stringify(body).slice(0, 200)}`;
    } catch (error) {
      lastDetail = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => {
      setTimeout(resolve, intervalMs);
    });
  }
  return { ok: false, attempts, waitedMs: now() - started, detail: lastDetail };
}

/**
 * The payload of one registration + one item, generated fresh per run (a).
 *
 * Every field is opaque to the server by design — this is a zero-knowledge
 * product, so what crosses the wire is ciphertext plus its IV and tag — which is
 * exactly why random bytes are an honest fixture here rather than a shortcut:
 * the server cannot tell them from a real vault entry, and neither can the flow.
 */
export function buildFlowFixture() {
  const email = `drill-${randomUUID().slice(0, 8)}@hvault.test`;
  return {
    email,
    registration: {
      email,
      authHash: hex(32),
      encryptedVaultKey: b64(32),
      vaultKeyIv: b64(12),
      vaultKeyTag: b64(16),
      kdfIterations: KDF_ITERATIONS,
      kdfAlgorithm: 'PBKDF2-SHA256',
    },
    item: {
      itemType: 'login',
      encryptedData: b64(64),
      dataIv: b64(12),
      dataTag: b64(16),
      encryptedName: b64(24),
      nameIv: b64(12),
      nameTag: b64(16),
      searchHash: hex(32),
      tags: ['clean-room'],
      favorite: false,
    },
  };
}

/**
 * Runs the whole journey and returns a structured trace.
 *
 * @param {object} options
 * @param {string} options.baseUrl        the ONE published origin (never the app directly)
 * @param {(email: string) => Promise<void>} options.verifyEmail  see (e)
 * @param {(message: string) => void} [options.log]
 * @param {typeof fetch} [options.fetchImpl]
 */
export async function runVaultFlow({ baseUrl, verifyEmail, log = () => {}, fetchImpl = fetch }) {
  const client = createClient(baseUrl, { fetchImpl });
  const fixture = buildFlowFixture();
  const steps = [];
  const step = (name, detail) => {
    steps.push({ name, detail });
    log(`${name} — ${detail}`);
  };

  const csrfFor = async (what) => {
    const response = await client.get('/api/v1/csrf-token');
    const data = expectEnvelope(`csrf-token (${what})`, response, 200);
    if (typeof data?.csrfToken !== 'string' || data.csrfToken.length === 0) {
      throw new VaultFlowError(`csrf-token (${what}): no token in the response`, {
        body: response.text.slice(0, 300),
      });
    }
    return data.csrfToken;
  };

  // 1. Register. The response is deliberately constant (`emailSent: true`) so it
  //    cannot be used to enumerate accounts, so there is nothing to assert here
  //    beyond the envelope.
  const registerToken = await csrfFor('anonymous');
  const registered = await client.post('/api/v1/auth/register', fixture.registration, {
    csrfToken: registerToken,
    auth: false,
  });
  expectEnvelope('register', registered, 201);
  step('register', `${fixture.email} accepted`);

  // 2. Confirm the address out of band (e). Without this, login answers 403
  //    EMAIL_NOT_VERIFIED and the rest of the journey is unreachable.
  await verifyEmail(fixture.email);
  step('verify-email', 'address marked verified in the database');

  // 3. Sign in. The access token never appears in a log line here; only its
  //    presence is reported.
  const loginToken = await csrfFor('pre-login');
  const loggedIn = await client.post(
    '/api/v1/auth/login',
    { email: fixture.email, authHash: fixture.registration.authHash },
    { csrfToken: loginToken, auth: false },
  );
  const session = expectEnvelope('login', loggedIn, 200);
  if (typeof session?.accessToken !== 'string' || session.accessToken.length === 0) {
    throw new VaultFlowError('login: no access token in the response', {
      keys: Object.keys(session ?? {}),
    });
  }
  client.setAccessToken(session.accessToken);
  if (!client.jar.has('refreshToken')) {
    throw new VaultFlowError('login: no refresh cookie was set', { cookies: client.jar.names() });
  }
  step('login', 'access token issued and refresh cookie set');

  // 4. Write one item. (b) The token has to be re-fetched now that the refresh
  //    cookie exists, or this POST is a 403.
  const writeToken = await csrfFor('authenticated');
  const created = await client.post('/api/v1/vault/items', fixture.item, {
    csrfToken: writeToken,
  });
  const item = expectEnvelope('create item', created, 201);
  if (typeof item?._id !== 'string' && typeof item?.id !== 'string') {
    throw new VaultFlowError('create item: the response carries no id', {
      keys: Object.keys(item ?? {}),
    });
  }
  const itemId = String(item._id ?? item.id);
  step('create-item', `item ${itemId} stored`);

  // 5. Read it back and compare the ciphertext byte for byte (a).
  const listed = await client.get('/api/v1/vault/items');
  const page = expectEnvelope('list items', listed, 200);
  const items = Array.isArray(page) ? page : (page?.items ?? []);
  const found = items.find((candidate) => String(candidate._id ?? candidate.id) === itemId);
  if (!found) {
    throw new VaultFlowError('list items: the item just written is not in the vault', {
      returned: items.length,
    });
  }
  for (const field of [
    'encryptedData',
    'dataIv',
    'dataTag',
    'encryptedName',
    'nameIv',
    'nameTag',
  ]) {
    if (found[field] !== fixture.item[field]) {
      throw new VaultFlowError(`list items: ${field} did not round-trip byte for byte`, {
        field,
        wrote: String(fixture.item[field]).slice(0, 24),
        read: String(found[field]).slice(0, 24),
      });
    }
  }
  step('read-back', 'stored ciphertext round-tripped unchanged');

  return {
    email: fixture.email,
    // The caller needs this to sign in AGAIN later (see `reReadVault`), which is
    // how a restart drill proves the account outlived the containers rather than
    // proving a five-minute JWT is still inside its window.
    authHash: fixture.registration.authHash,
    itemId,
    item: fixture.item,
    steps,
    client,
  };
}

/**
 * Re-reads a vault a previous flow wrote, with a FRESH session.
 *
 * This is what makes "the data survived a restart" mean something: it signs in
 * again (the account and its bcrypt hash must have survived), reads the vault
 * again (the item and its ciphertext must have survived), and compares the same
 * bytes. Reusing the first flow's access token would prove only that a JWT is
 * still inside its five-minute window.
 */
export async function reReadVault({
  baseUrl,
  email,
  authHash,
  itemId,
  expected,
  fetchImpl = fetch,
}) {
  const client = createClient(baseUrl, { fetchImpl });
  const csrf = await client.get('/api/v1/csrf-token');
  const { csrfToken } = expectEnvelope('csrf-token (re-read)', csrf, 200);

  const loggedIn = await client.post(
    '/api/v1/auth/login',
    { email, authHash },
    { csrfToken, auth: false },
  );
  const session = expectEnvelope('login (re-read)', loggedIn, 200);
  client.setAccessToken(session.accessToken);

  const listed = await client.get('/api/v1/vault/items');
  const page = expectEnvelope('list items (re-read)', listed, 200);
  const items = Array.isArray(page) ? page : (page?.items ?? []);
  const found = items.find((candidate) => String(candidate._id ?? candidate.id) === itemId);
  if (!found) {
    throw new VaultFlowError('re-read: the item written before the restart is gone', {
      itemId,
      returned: items.length,
    });
  }
  if (found.encryptedData !== expected.encryptedData) {
    throw new VaultFlowError('re-read: the ciphertext changed across the restart', { itemId });
  }
  return { itemId, returned: items.length };
}
