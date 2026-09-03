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
 *
 *  f. THE DOCUMENT JOURNEY IS A SEPARATE EXPORT, and only the drill calls it.
 *     The document store is off unless object storage is configured, and the
 *     smoke gate boots the built artifact with none — every route would answer
 *     503. So the leg lives here, beside the flow it shares a client, a cookie
 *     jar and a CSRF dance with, rather than in the drill where nothing could
 *     unit-test it; and it is opt-in rather than part of `runVaultFlow`.
 *
 *  g. THE SEALED SEGMENT IS RANDOM BYTES, for exactly the reason (a) gives for a
 *     vault item. The server stores ciphertext, a wrapped key and sizes, and
 *     decrypts nothing — it cannot tell these bytes from a real sealed segment,
 *     and neither can the flow. What the drill proves is the property that is
 *     actually the deployment's job: the bytes that went in through the single
 *     published port come back out of it unchanged. The framing NUMBERS are
 *     restated here (the tag, the salt and prefix widths) because a gate script
 *     cannot import a TypeScript module; `clean-room.test.ts` pins the
 *     restatement against `@hvault/shared`, so it cannot drift.
 *
 *  h. EVERY REQUEST CARRIES A DEADLINE. `local-ci.mjs` puts no timeout on a gate,
 *     so a deployment that accepts a connection and never answers would hang the
 *     whole pipeline instead of failing it — the failure mode `test:deploy`
 *     already refuses to have when it polls for a container's exit rather than
 *     calling `docker wait`. One `AbortSignal.timeout` per request covers the
 *     body stream as well as the headers, and the abort is discriminated on the
 *     SIGNAL, so an ordinary connection refused during boot keeps its own error.
 */
import { createHash, randomBytes, randomUUID } from 'node:crypto';

/** Registration's `kdfIterations` floor is 500k; the client's real default is 600k. */
const KDF_ITERATIONS = 600_000;

/**
 * The ceiling on ONE request, body included. See decision (h).
 *
 * Sized for the slowest honest call in either gate rather than for a typical one:
 * registration hashes with bcrypt at 12 rounds on a container that may be sharing
 * a build machine. It is a HANG DETECTOR, not a performance budget — an expiring
 * deadline here means nothing answered, and every gate that drives this flow is
 * measured in seconds against it.
 */
export const REQUEST_TIMEOUT_MS = 60_000;

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
 *
 * `fetchImpl` is typed STRUCTURALLY rather than as `typeof fetch`, for the reason
 * `waitForHealth` records below: the binary and JSON branches of `request` each
 * have a decision in them, and a test that had to fabricate a whole `Response`
 * to exercise one would end up asserting nothing about it. This lists exactly
 * what the client touches — the status, two header lookups, and one of the two
 * body readers — and a real `fetch` satisfies it.
 *
 * @param {string} baseUrl
 * @param {object} [options]
 * @param {(input: URL|string, init?: object) => Promise<{
 *   status: number,
 *   headers: { get: (name: string) => string | null, getSetCookie: () => string[] },
 *   text: () => Promise<string>,
 *   arrayBuffer: () => Promise<ArrayBuffer>,
 * }>} [options.fetchImpl]
 * @param {number} [options.timeoutMs] the per-request deadline, see (h)
 */
export function createClient(baseUrl, { fetchImpl = fetch, timeoutMs = REQUEST_TIMEOUT_MS } = {}) {
  const jar = createCookieJar();
  let accessToken = '';

  const request = async (
    method,
    path,
    { body, rawBody, extraHeaders, csrfToken, auth = true, responseType = 'json' } = {},
  ) => {
    const headers = {
      accept: responseType === 'bytes' ? 'application/octet-stream' : 'application/json',
    };
    if (body !== undefined) headers['content-type'] = 'application/json';
    // (f) A sealed segment is raw bytes and there is no second representation of
    // one: `express.raw` parses `application/octet-stream` alone, and anything
    // else arrives at the handler as whatever the JSON parser made of it.
    // Node's fetch derives an exact `Content-Length` from a `Uint8Array` body,
    // which the part route requires (411 without it) and re-checks against the
    // bytes it received.
    if (rawBody !== undefined) headers['content-type'] = 'application/octet-stream';
    if (csrfToken) headers['x-csrf-token'] = csrfToken;
    if (auth && accessToken) headers.authorization = `Bearer ${accessToken}`;
    const cookie = jar.header();
    if (cookie) headers.cookie = cookie;
    Object.assign(headers, extraHeaders ?? {});

    // (h) EVERY request carries a deadline, body included. A stack that accepts
    // the connection and then answers nothing is the one failure mode a gate
    // cannot recover from on its own: `local-ci.mjs` puts no timeout on a gate,
    // so an unbounded `fetch` here hangs the whole pipeline rather than failing
    // it — the same reasoning that made `waitForContainerExit` a bounded poll
    // instead of `docker wait`. The signal covers the body stream too, so a
    // response whose headers arrive and whose body stalls is bounded as well.
    const deadline = AbortSignal.timeout(timeoutMs);
    try {
      const response = await fetchImpl(new URL(path, baseUrl), {
        method,
        headers,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        ...(rawBody === undefined ? {} : { body: rawBody }),
        redirect: 'manual',
        signal: deadline,
      });
      // (c) Node's fetch exposes the raw lines here; `headers.get('set-cookie')`
      // would fold several cookies into one comma-joined string that cannot be
      // split again without re-parsing dates.
      jar.capture(response.headers.getSetCookie());

      // (f) A binary response is read as bytes, and the body is STILL decoded as
      // text for the failure path: a refusal on the segment route is a JSON error
      // envelope, and a drill whose message is a byte count instead of that
      // envelope costs more time than the gate saves. `TextDecoder` rather than a
      // `Buffer`, so the two branches return the same shape.
      if (responseType === 'bytes') {
        const bytes = new Uint8Array(await response.arrayBuffer());
        const text = response.status === 200 ? '' : new TextDecoder().decode(bytes);
        return {
          status: response.status,
          headers: response.headers,
          bytes,
          text,
          json: parse(text),
        };
      }

      const text = await response.text();
      return { status: response.status, headers: response.headers, text, json: parse(text) };
    } catch (error) {
      // Discriminated on the SIGNAL rather than on the error's name: undici
      // reports the deadline as a `TimeoutError` and a body abort as an
      // `AbortError`, and a stub in a test may throw neither. Anything the
      // deadline did not cause keeps its own error, so a connection refused
      // while the stack is still booting is never relabelled as a hang.
      if (deadline.aborted) {
        throw new VaultFlowError(`${method} ${path}: no answer within ${String(timeoutMs)} ms`, {
          timeoutMs,
          underlying: error instanceof Error ? `${error.name}: ${error.message}` : String(error),
        });
      }
      throw error;
    }
  };

  return {
    request,
    get: (path, options) => request('GET', path, options),
    post: (path, body, options) => request('POST', path, { ...options, body }),
    put: (path, options) => request('PUT', path, options),
    delete: (path, options) => request('DELETE', path, options),
    setAccessToken: (token) => {
      accessToken = token;
    },
    jar,
  };
}

/** A response body as JSON, or `undefined` — a non-JSON body is reported by the assertions. */
function parse(text) {
  try {
    return text.length > 0 ? JSON.parse(text) : undefined;
  } catch {
    return undefined;
  }
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
 * One CSRF token, asserted rather than assumed.
 *
 * (b) The token is an HMAC bound to `hashToken(refreshToken)`, so the anonymous
 * one that authorised `register` stops verifying the moment a refresh cookie
 * exists: every state-changing request fetches a fresh one, exactly as a browser
 * does. ONE definition, because six call sites now need it and a copy that
 * forgot the emptiness check would fail three steps later with a 403 that reads
 * like a broken deployment.
 */
export async function csrfTokenFor(client, what) {
  const response = await client.get('/api/v1/csrf-token');
  const data = expectEnvelope(`csrf-token (${what})`, response, 200);
  if (typeof data?.csrfToken !== 'string' || data.csrfToken.length === 0) {
    throw new VaultFlowError(`csrf-token (${what}): no token in the response`, {
      body: response.text.slice(0, 300),
    });
  }
  return data.csrfToken;
}

/**
 * A FRESH session on a fresh client, and the one definition of signing in.
 *
 * Every re-read in this file and in the drill goes through it rather than reusing
 * an access token minted earlier, which is what makes "the data survived" mean
 * something: the account, its bcrypt hash and its stored rows all have to have
 * outlived whatever just happened to the containers. Reusing the first flow's
 * token would prove only that a JWT is still inside its window.
 *
 * The refresh cookie is asserted too, and not as decoration: without it the CSRF
 * token this client fetches next is bound to nothing, and the first write would
 * be a 403 that looks like a CSRF bug rather than a login one.
 */
export async function signIn({ baseUrl, email, authHash, what, fetchImpl = fetch }) {
  const client = createClient(baseUrl, { fetchImpl });
  const csrfToken = await csrfTokenFor(client, `pre-login ${what}`);
  const loggedIn = await client.post(
    '/api/v1/auth/login',
    { email, authHash },
    { csrfToken, auth: false },
  );
  const session = expectEnvelope(`login ${what}`, loggedIn, 200);
  if (typeof session?.accessToken !== 'string' || session.accessToken.length === 0) {
    throw new VaultFlowError(`login ${what}: no access token in the response`, {
      keys: Object.keys(session ?? {}),
    });
  }
  client.setAccessToken(session.accessToken);
  if (!client.jar.has('refreshToken')) {
    throw new VaultFlowError(`login ${what}: no refresh cookie was set`, {
      cookies: client.jar.names(),
    });
  }
  return client;
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
  // Reassigned at the sign-in below, deliberately: `signIn` is the ONE definition
  // of a session and it hands back a fresh client, so the anonymous half of the
  // journey and the authenticated half do not share a cookie jar. That is also
  // what a browser does — nothing survives registration but the account.
  let client = createClient(baseUrl, { fetchImpl });
  const fixture = buildFlowFixture();
  const steps = [];
  const step = (name, detail) => {
    steps.push({ name, detail });
    log(`${name} — ${detail}`);
  };

  // 1. Register. The response is deliberately constant (`emailSent: true`) so it
  //    cannot be used to enumerate accounts, so there is nothing to assert here
  //    beyond the envelope.
  const registerToken = await csrfTokenFor(client, 'anonymous');
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
  client = await signIn({
    baseUrl,
    email: fixture.email,
    authHash: fixture.registration.authHash,
    what: '(first session)',
    fetchImpl,
  });
  step('login', 'access token issued and refresh cookie set');

  // 4. Write one item. (b) The token has to be re-fetched now that the refresh
  //    cookie exists, or this POST is a 403.
  const writeToken = await csrfTokenFor(client, 'authenticated');
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
  const client = await signIn({ baseUrl, email, authHash, what: '(re-read)', fetchImpl });

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

// ---------------------------------------------------------------------------
// The document leg (f)
// ---------------------------------------------------------------------------

/**
 * The framing numbers a transfer has to get right, restated on the gate side.
 *
 * They live in `packages/shared/src/constants/index.ts` and a gate runner cannot
 * import a TypeScript module, so this is a second copy — pinned against the real
 * exports by `packages/server/tests/clean-room.test.ts`, which imports both. The
 * pin is what makes the copy safe: every one of these is a number the server
 * refuses a transfer over, so a stale value here would fail the drill with a 400
 * that reads like a broken deployment.
 *
 *   * `tagBytes` — a sealed segment is its plaintext plus one AES-GCM tag, and
 *     the server DERIVES `plaintextBytes` as `ciphertextBytes - tagBytes *
 *     chunkCount` rather than believing the request. A part must therefore be
 *     exactly `declaredPlaintextBytes + tagBytes` long or the completion is
 *     refused as unframeable.
 *   * `streamSaltBytes` / `noncePrefixBytes` — both are validated as padded
 *     standard base64 of EXACTLY that many bytes, so neither can be padded out.
 *
 * The server's CHUNK SIZE is deliberately absent, and its absence is ENFORCED:
 * `packages/shared/tests/constants.test.ts` scans every source file for either
 * chunk size written as a decimal literal and fails on a second copy anywhere but
 * the definition, because a copy that drifts surfaces as a stored document that
 * will not decrypt rather than as a failing build. (Measured: adding one here
 * turned that gate red.) The drill therefore READS the framing from the
 * deployment — `GET /config` advertises it and the init response echoes it — and
 * asserts those two server surfaces agree with each other, which is a real claim
 * rather than a comparison against a number this file invented.
 */
export const DOCUMENT_FRAMING = Object.freeze({
  tagBytes: 16,
  streamSaltBytes: 32,
  noncePrefixBytes: 7,
});

/**
 * The default plaintext size of the drill's document.
 *
 * Deliberately ODD and unaligned. A round power of two would let an off-by-one in
 * the tag arithmetic or a chunk-boundary mistake round to the same answer, and
 * the whole point of the byte-for-byte comparison is that it cannot.
 */
const DOCUMENT_PLAINTEXT_BYTES = 12_345;

/**
 * One document's worth of request bodies and the sealed segment itself (g).
 *
 * ONE segment, so the transfer takes the `PutObject` path: `declaredChunkCount`
 * of 1 is what the framing refine demands for any size at or below one plaintext
 * chunk, and it is the shape a self-hosted deployment serves most of the time.
 * The multi-part path is covered by the storage conformance gate against the real
 * engine and by the resource gate at the configured maximum size; what THIS gate
 * uniquely owns is the round trip through Nginx.
 */
export function buildDocumentFixture({ plaintextBytes = DOCUMENT_PLAINTEXT_BYTES } = {}) {
  return {
    plaintextBytes,
    // The bytes the drill will demand back, unchanged, through the same port.
    segment: randomBytes(plaintextBytes + DOCUMENT_FRAMING.tagBytes),
    init: {
      encryptedDek: b64(48),
      dekIv: b64(12),
      dekTag: b64(16),
      streamSalt: b64(DOCUMENT_FRAMING.streamSaltBytes),
      noncePrefix: b64(DOCUMENT_FRAMING.noncePrefixBytes),
      declaredPlaintextBytes: plaintextBytes,
      declaredChunkCount: 1,
    },
    meta: { encryptedMeta: b64(256), metaIv: b64(12), metaTag: b64(16) },
  };
}

/**
 * What `GET /config` says about the document store, asserted rather than assumed.
 *
 * It is a PUBLIC route, and it is how a browser learns the feature exists at all:
 * the block is absent on a server older than the feature, present with
 * `enabled: false` where no storage is configured, and present with the numbers
 * otherwise. Reading it first is what makes the journey below a statement about
 * THIS deployment — that `docker compose up` alone left the document store on,
 * with no bucket created by hand and no storage step in the setup — and it checks
 * the published framing against {@link DOCUMENT_FRAMING} rather than trusting
 * either side.
 */
export async function readDocumentsConfig({ baseUrl, fetchImpl = fetch }) {
  const client = createClient(baseUrl, { fetchImpl });
  const response = await client.get('/api/v1/config');
  const data = expectEnvelope('config', response, 200);
  const documents = data?.documents;
  if (documents?.enabled !== true) {
    throw new VaultFlowError('config: the deployment does not advertise the document store', {
      documents: documents ?? null,
    });
  }
  if (!Number.isInteger(documents.chunkPlaintextBytes) || documents.chunkPlaintextBytes <= 0) {
    throw new VaultFlowError('config: the advertised plaintext chunk size is not a byte count', {
      advertised: documents.chunkPlaintextBytes ?? null,
    });
  }
  return documents;
}

/**
 * Uploads one document and reads it straight back, byte for byte.
 *
 * The three requests are the whole protocol: init reserves the transfer and mints
 * the id (which is the future document id, because it is bound into the HKDF
 * `info` of every key the browser derives), the part carries the sealed segment
 * with a digest the server recomputes itself, and the completion carries the
 * sealed metadata and the wrapped key a SECOND time — which is what makes a
 * mid-transfer vault-key rotation recoverable without re-sending a byte.
 *
 * Every size on the committed row is DERIVED by the server from the part ledger
 * rather than taken from the request, so asserting them here is asserting the
 * server's arithmetic, not an echo of the drill's own numbers.
 *
 * @param {object} options
 * @param {ReturnType<typeof createClient>} options.client an authenticated client
 * @param {number} options.chunkPlaintextBytes what `GET /config` advertised
 * @param {(message: string) => void} [options.log]
 * @param {ReturnType<typeof buildDocumentFixture>} [options.fixture]
 */
export async function runDocumentFlow({
  client,
  chunkPlaintextBytes,
  log = () => {},
  fixture = buildDocumentFixture(),
}) {
  const steps = [];
  const step = (name, detail) => {
    steps.push({ name, detail });
    log(`${name} — ${detail}`);
  };

  // 1. Open the transfer.
  const initToken = await csrfTokenFor(client, 'document init');
  const opened = await client.post('/api/v1/documents/uploads', fixture.init, {
    csrfToken: initToken,
  });
  const upload = expectEnvelope('init upload', opened, 201);
  if (typeof upload?.uploadId !== 'string' || upload.uploadId.length === 0) {
    throw new VaultFlowError('init upload: the response carries no upload id', {
      keys: Object.keys(upload ?? {}),
    });
  }
  // The two server surfaces that publish the framing must AGREE. `GET /config`
  // is what a browser computes `declaredChunkCount` from, and this response is
  // what the transfer is actually framed by; both read the same constant, so a
  // disagreement means a client would seal segments to one boundary while the
  // server measured them against another. Compared against the deployment's own
  // advertisement rather than a number restated here — see `DOCUMENT_FRAMING`.
  if (upload.chunkPlaintextBytes !== chunkPlaintextBytes) {
    throw new VaultFlowError('init upload: the server framed the transfer to another chunk size', {
      returned: upload.chunkPlaintextBytes,
      advertisedByConfig: chunkPlaintextBytes,
    });
  }
  // And this transfer really is the single-segment shape it declared, measured
  // against the boundary the deployment published rather than an assumed one.
  if (fixture.plaintextBytes > chunkPlaintextBytes) {
    throw new VaultFlowError('init upload: the fixture is larger than one segment', {
      plaintextBytes: fixture.plaintextBytes,
      chunkPlaintextBytes,
    });
  }
  const uploadId = upload.uploadId;
  step(
    'document-init',
    `transfer ${uploadId} opened at vault key version ${String(upload.vaultKeyVersion)}`,
  );

  // 2. Send the one sealed segment. The digest is the client's; the server
  //    computes its own over the bytes it received and compares, which is what
  //    proves the part survived the proxy in front of it.
  const partToken = await csrfTokenFor(client, 'document part');
  const digest = createHash('sha256').update(fixture.segment).digest('hex');
  const sent = await client.put(`/api/v1/documents/uploads/${uploadId}/parts/1`, {
    rawBody: fixture.segment,
    extraHeaders: { 'x-hv-part-sha256': digest },
    csrfToken: partToken,
  });
  const receipt = expectEnvelope('upload part', sent, 200);
  if (receipt?.receivedBytes !== fixture.segment.length) {
    throw new VaultFlowError('upload part: the server recorded a different number of bytes', {
      recorded: receipt?.receivedBytes,
      sent: fixture.segment.length,
    });
  }
  step(
    'document-part',
    `${String(fixture.segment.length)} sealed bytes accepted and digest-verified`,
  );

  // 3. Complete it, and check the sizes the server DERIVED from its own ledger.
  const completeToken = await csrfTokenFor(client, 'document complete');
  const completed = await client.post(
    `/api/v1/documents/uploads/${uploadId}/complete`,
    { ...fixture.meta, ...pickDek(fixture.init), vaultKeyVersion: upload.vaultKeyVersion },
    { csrfToken: completeToken },
  );
  const document = expectEnvelope('complete upload', completed, 201);
  const documentId = String(document?._id ?? document?.id ?? '');
  if (documentId !== uploadId) {
    throw new VaultFlowError('complete upload: the document id is not the upload id', {
      uploadId,
      documentId,
    });
  }
  const derived = {
    chunkCount: document.chunkCount,
    plaintextBytes: document.plaintextBytes,
    ciphertextBytes: document.ciphertextBytes,
  };
  if (
    derived.chunkCount !== 1 ||
    derived.plaintextBytes !== fixture.plaintextBytes ||
    derived.ciphertextBytes !== fixture.segment.length
  ) {
    throw new VaultFlowError('complete upload: the server framed the document wrongly', {
      derived,
      expected: {
        chunkCount: 1,
        plaintextBytes: fixture.plaintextBytes,
        ciphertextBytes: fixture.segment.length,
      },
    });
  }
  step(
    'document-complete',
    `document ${documentId} committed as ${String(derived.plaintextBytes)} plaintext bytes`,
  );

  // 4. Read the segment back and compare it byte for byte (a, g).
  const read = await readDocumentSegment({ client, documentId, expected: fixture.segment });
  step('document-download', `the sealed segment came back byte-identical (${read.headers})`);

  // 5. The quota accounting a client is shown, measured against the same bytes.
  const usage = expectEnvelope('usage', await client.get('/api/v1/documents/usage'), 200);
  if (usage?.documentCount !== 1 || usage.usedBytes !== fixture.plaintextBytes) {
    throw new VaultFlowError('usage: the deployment reports a different document footprint', {
      usage,
      expected: { documentCount: 1, usedBytes: fixture.plaintextBytes },
    });
  }
  step('document-usage', `usage reports 1 document and ${String(usage.usedBytes)} bytes`);

  return { documentId, fixture, steps };
}

/** The wrapped-key trio, which the completion body carries a second time. */
function pickDek({ encryptedDek, dekIv, dekTag }) {
  return { encryptedDek, dekIv, dekTag };
}

/**
 * The first wrapped-key field of a document row that disagrees with the key it
 * was stored under, or `null` when all three match.
 *
 * Compared field by field, exactly as `reReadVault` compares an item's six
 * ciphertext fields, and for the same reason one layer deeper: this drill never
 * decrypts anything, so a row returned with a re-minted, truncated or absent DEK
 * passes every byte comparison in `readDocumentSegment` while being permanently
 * unopenable in a browser. "The document survived" has to mean the file AND the
 * key, or it is a claim about half of what a restart can lose.
 *
 * The trio is selected through the same `pickDek` the upload body used, so the
 * check and the write cannot come to name different fields. It is deliberately
 * ONLY the trio: `encryptedMeta` is the document's name and framing, which the
 * flow asserts elsewhere, and folding it in here would report a metadata
 * difference as a key failure.
 */
export function wrappedKeyProblem(row, expectedKey) {
  for (const [field, expected] of Object.entries(pickDek(expectedKey ?? {}))) {
    const returned = row?.[field] ?? null;
    // An ABSENT expectation is a problem in its own right, never a match. A call
    // site that forgot `expectedKey` — or a fixture that stopped carrying the
    // trio — would otherwise disarm this comparison in the one way a comparison
    // must never be disarmable: silently, while still reporting a pass.
    if (expected == null || returned !== expected) {
      return { field, expected: expected ?? null, returned };
    }
  }
  return null;
}

/**
 * Segment zero, compared with the bytes that were sealed into it.
 *
 * The headers are asserted alongside the payload because both are the
 * deployment's job and both are silent when wrong: `no-store` is what keeps user
 * ciphertext out of a disk cache and out of an intermediary on the way through
 * Nginx, and `application/octet-stream` is what stops a browser sniffing it.
 * `Content-Length` is the exact segment length taken from the row's framing, so a
 * short read cannot be mistaken for a whole segment.
 */
export async function readDocumentSegment({ client, documentId, expected }) {
  const response = await client.get(`/api/v1/documents/${documentId}/segments/0`, {
    responseType: 'bytes',
  });
  if (response.status !== 200) {
    throw new VaultFlowError(`read segment: expected HTTP 200, got ${String(response.status)}`, {
      body: response.text.slice(0, 600),
    });
  }
  const contentType = response.headers.get('content-type') ?? '';
  const cacheControl = response.headers.get('cache-control');
  const contentLength = response.headers.get('content-length');
  if (
    !contentType.startsWith('application/octet-stream') ||
    cacheControl !== 'no-store' ||
    contentLength !== String(expected.length)
  ) {
    throw new VaultFlowError(
      'read segment: the response headers are not the ones a segment carries',
      {
        contentType,
        cacheControl,
        contentLength,
        expectedLength: expected.length,
      },
    );
  }
  if (response.bytes.length !== expected.length) {
    throw new VaultFlowError(
      'read segment: the body is a different length from the sealed segment',
      {
        returned: response.bytes.length,
        expected: expected.length,
      },
    );
  }
  // A byte-for-byte comparison, and the FIRST differing index when it fails: a
  // bare "they differ" over twelve kilobytes tells a reader nothing about
  // whether a proxy re-encoded the body or dropped a chunk.
  for (let index = 0; index < expected.length; index += 1) {
    if (response.bytes[index] !== expected[index]) {
      throw new VaultFlowError('read segment: the bytes changed in transit', {
        firstDifferingByte: index,
        expected: expected[index],
        returned: response.bytes[index],
      });
    }
  }
  return { bytes: response.bytes.length, headers: `${contentType}, ${String(cacheControl)}` };
}

/**
 * Re-reads a document a previous flow wrote, with a FRESH session.
 *
 * The same argument `reReadVault` records, one layer deeper: this is what makes
 * "the document survived" mean the row, its wrapped key AND the object in the
 * bucket all outlived whatever just happened — a restart, a redeployed storage
 * container, or a rotated bucket credential. A cached access token would prove
 * none of it.
 */
export async function reReadDocument({
  baseUrl,
  email,
  authHash,
  documentId,
  expected,
  expectedKey,
  what,
  fetchImpl = fetch,
}) {
  const client = await signIn({ baseUrl, email, authHash, what, fetchImpl });
  const row = expectEnvelope(
    `get document ${what}`,
    await client.get(`/api/v1/documents/${documentId}`),
    200,
  );
  if (String(row?._id ?? row?.id ?? '') !== documentId) {
    throw new VaultFlowError(`get document ${what}: the row returned is a different document`, {
      documentId,
      returned: row?._id ?? row?.id ?? null,
    });
  }
  if (row.ciphertextBytes !== expected.length) {
    throw new VaultFlowError(`get document ${what}: the recorded size changed`, {
      recorded: row.ciphertextBytes,
      expected: expected.length,
    });
  }
  const keyProblem = wrappedKeyProblem(row, expectedKey);
  if (keyProblem) {
    throw new VaultFlowError(`get document ${what}: the wrapped key changed`, keyProblem);
  }
  const read = await readDocumentSegment({ client, documentId, expected });
  return { documentId, bytes: read.bytes };
}

/**
 * Trash the document, purge it, and prove it is gone.
 *
 * Both steps, because they are two different operations with two different
 * consequences: `DELETE /documents/:id` is recoverable and the row still counts
 * against the quota, while `DELETE /documents/:id/permanent` marks the row,
 * deletes the object and then deletes the row — so a deployment where the object
 * delete silently fails is one where the bucket grows for ever. The negative is
 * therefore asserted on BOTH sides of the boundary: the row is a 404 afterwards,
 * the trash listing is empty, and `usage` is back to zero bytes.
 *
 * Which claim rests on which fact matters here. `usage` is an aggregation over the
 * ROWS, so a zero there says the row is gone and nothing about the bucket. What
 * carries the object is the 200 on the purge itself: `purgeDocument` deliberately
 * does not catch a storage failure, so an engine that refused or dropped the
 * delete surfaces as a 5xx that `expectEnvelope` rejects.
 */
export async function purgeDocumentFlow({
  baseUrl,
  email,
  authHash,
  documentId,
  fetchImpl = fetch,
}) {
  const client = await signIn({ baseUrl, email, authHash, what: '(purge)', fetchImpl });

  const trashToken = await csrfTokenFor(client, 'document trash');
  expectEnvelope(
    'trash document',
    await client.delete(`/api/v1/documents/${documentId}`, { csrfToken: trashToken }),
    200,
  );
  const trashed = expectEnvelope(
    'list document trash',
    await client.get('/api/v1/documents/trash'),
    200,
  );
  const trashedIds = (Array.isArray(trashed) ? trashed : []).map((row) =>
    String(row._id ?? row.id),
  );
  if (!trashedIds.includes(documentId)) {
    throw new VaultFlowError('trash document: the trashed document is not in the trash listing', {
      documentId,
      trashedIds,
    });
  }

  const purgeToken = await csrfTokenFor(client, 'document purge');
  expectEnvelope(
    'purge document',
    await client.delete(`/api/v1/documents/${documentId}/permanent`, { csrfToken: purgeToken }),
    200,
  );

  const gone = await client.get(`/api/v1/documents/${documentId}`);
  if (gone.status !== 404) {
    throw new VaultFlowError('purge document: the purged document still answers', {
      status: gone.status,
      body: gone.text.slice(0, 300),
    });
  }
  const emptied = expectEnvelope(
    'list document trash (after purge)',
    await client.get('/api/v1/documents/trash'),
    200,
  );
  if ((Array.isArray(emptied) ? emptied : []).length !== 0) {
    throw new VaultFlowError('purge document: the trash is not empty after the purge', {
      returned: emptied,
    });
  }
  const usage = expectEnvelope(
    'usage (after purge)',
    await client.get('/api/v1/documents/usage'),
    200,
  );
  if (usage?.documentCount !== 0 || usage.usedBytes !== 0) {
    throw new VaultFlowError('purge document: the quota still charges for the purged document', {
      usage,
    });
  }
  return { documentId, trashedIds };
}
