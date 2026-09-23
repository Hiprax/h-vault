import { describe, it, expect, afterEach, beforeAll, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import express from 'express';
import * as shared from '@hvault/shared';
import request from 'supertest';
import TransportStream from 'winston-transport';
import winston from 'winston';
import app from '../src/app.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { authHeader, createTestUser, getCsrf, sampleVaultItem } from './helpers.js';

// The three places a secret can escape the server after it has arrived: the log
// line describing the request, the audit row describing what was done, and the
// error body describing what went wrong. All three are asserted here, and all
// three are driven through the configuration `app.ts` ACTUALLY passes, captured
// at runtime, rather than through a copy of it written down in this file.
//
// The `createRequestLogger` half came first and set the shape: the previous
// version of this suite regex-scraped the `maskBodyKeys` literal out of app.ts's
// SOURCE TEXT and asserted on the extracted strings — it never ran the logger, so
// it would stay green even if the middleware were unmounted, and it broke on
// harmless refactors (hoisting the list into a const, reformatting).
//
// This version instead:
//   1. Captures the ACTUAL `maskBodyKeys` app.ts passes at RUNTIME (by wrapping
//      `createRequestLogger` so the array can't drift from a copied literal).
//   2. Derives what that list MUST contain from the request schemas the routes
//      actually mount (every `validate(schema, 'body')`, captured the same way):
//      every key those schemas accept is either masked or named, with a reason, in
//      a ledger of keys that are not secret. A field added to any request schema
//      tomorrow is in neither, and fails here until someone decides which it is.
//      The list is checked in both directions, so a masked key that no longer
//      exists anywhere and a ledger entry that went stale both fail too. Then it
//      drives the REAL @hiprax/logger masking engine over a body BUILT FROM those
//      schemas, never from the list, so a key missing from the list is a secret
//      value visible in the captured log line. (The version before this planted
//      one value per CONFIGURED key, which is why it could never notice a key that
//      was not configured: six live secret fields went unmasked under it.)
//   3. Plants those same values in REAL requests and requires that none of them
//      reaches an audit row.
//   4. Captures the `createErrorMiddleware` options the same way and drives the
//      REAL error middleware in production mode, where a 5xx body must collapse
//      to its status text.
//
// `includeRequestBody: true` is set for the engine exercise so the redaction
// actually runs against a body — that is the defense the `maskBodyKeys` config
// expresses (redact these keys whenever a body is logged).

const { captured } = vi.hoisted(() => ({
  captured: {
    maskBodyKeys: [] as string[],
    errorOptions: undefined as { exposeServerErrors?: boolean } | undefined,
    bodySchemas: new Set<unknown>(),
  },
}));

// Record every schema a route validates its BODY with, at the moment the route is
// built (importing app.ts builds them all), and call straight through, so the app
// under test is unchanged. This is the set of request bodies the server accepts,
// read from the routes themselves rather than from a list kept beside them.
vi.mock('../src/middleware/validate.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/middleware/validate.js')>();
  return {
    ...actual,
    validate: (...args: Parameters<typeof actual.validate>) => {
      const [schema, location = 'body'] = args;
      if (location === 'body') captured.bodySchemas.add(schema);
      return actual.validate(...args);
    },
  };
});

vi.mock('@hiprax/logger', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@hiprax/logger')>();
  return {
    ...actual,
    // Wrap createRequestLogger to record the maskBodyKeys the app configures,
    // then call through so app.ts still mounts a real, working middleware.
    createRequestLogger: (options?: Parameters<typeof actual.createRequestLogger>[0]) => {
      if (Array.isArray(options?.maskBodyKeys) && options.maskBodyKeys.length > 0) {
        captured.maskBodyKeys = options.maskBodyKeys;
      }
      return actual.createRequestLogger(options);
    },
  };
});

// The same trick, for the error middleware: record the options app.ts mounts and
// call through, so the app under test is unchanged and the redaction exercise
// below runs against the REAL configuration instead of a restatement of it.
// `httpErrors`, `catchAsync` and everything else stay the genuine exports.
vi.mock('@hiprax/errors', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@hiprax/errors')>();
  return {
    ...actual,
    createErrorMiddleware: (options?: Parameters<typeof actual.createErrorMiddleware>[0]) => {
      captured.errorOptions = options as { exposeServerErrors?: boolean };
      return actual.createErrorMiddleware(options);
    },
  };
});

import { createRequestLogger } from '@hiprax/logger';
import { createErrorMiddleware, httpErrors } from '@hiprax/errors';

/** In-memory winston transport that records every log info object it receives. */
class CaptureTransport extends TransportStream {
  public readonly records: Record<string, unknown>[] = [];
  log(info: Record<string, unknown>, next: () => void): void {
    this.records.push(info);
    next();
  }
}

/**
 * Runs the request logger over one request with the given body and returns the
 * captured log records. Uses the REAL masking engine (createRequestLogger from
 * @hiprax/logger) plus the app's runtime-captured maskBodyKeys.
 */
function runRequestLogger(body: unknown, maskBodyKeys: string[]): Record<string, unknown>[] {
  const capture = new CaptureTransport();
  const logger = winston.createLogger({ level: 'silly', transports: [capture] });
  const middleware = createRequestLogger({
    logger,
    level: 'info',
    includeRequestBody: true,
    // Attach the structured HTTP payload (including the redacted requestBody)
    // under info.http so the captured log record carries it — otherwise the
    // middleware logs only the one-line summary string.
    includeHttpContext: true,
    // Never truncate: a secret past the default 3,000-character cap would be absent
    // from the line for the wrong reason, and the assertions below would pass on it.
    maxBodyLength: Number.POSITIVE_INFINITY,
    maskBodyKeys,
  });

  const req = {
    method: 'POST',
    url: '/api/v1/test',
    originalUrl: '/api/v1/test',
    headers: {},
    body,
  };
  const res = new EventEmitter() as EventEmitter & Record<string, unknown>;
  res.statusCode = 200;
  res.getHeader = () => undefined;
  res.getHeaders = () => ({});
  res.writableEnded = true;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  middleware(req as any, res as any, () => {});
  res.emit('finish');
  return capture.records;
}

// ---------------------------------------------------------------------------
// The classification ledger
// ---------------------------------------------------------------------------

const PUBLIC_PARAMETER =
  'an IV, auth tag, salt, nonce or KDF parameter: public by construction and useless without the key';
const CIPHERTEXT =
  'bulk ciphertext under the vault key or a document key; the server stores it, and it is not key material';
const METADATA = 'a plain setting, identifier, flag, count or structural field';
const PERSONAL = 'personal data the server already stores in the clear, not a credential';

/**
 * Every request-body key that is deliberately NOT masked, and why.
 *
 * The rule the entries follow: a CREDENTIAL (a password, an auth hash, a one-time
 * code, a bearer token) and WRAPPED KEY MATERIAL (a vault key, backup key or document
 * key sealed under another key) are masked; bulk ciphertext, the public parameters
 * that travel beside it, settings and identifiers are not. A new schema field goes
 * on this list only with a reason in that vocabulary; if it does not fit, it is a
 * secret and belongs in `maskBodyKeys` in app.ts.
 */
const LOGGABLE_BODY_KEYS = new Map<string, string>([
  ['autoLockTimeout', METADATA],
  ['backupEmails', PERSONAL],
  ['bwkIv', PUBLIC_PARAMETER],
  ['bwkSalt', PUBLIC_PARAMETER],
  ['bwkTag', PUBLIC_PARAMETER],
  ['bwkVaultKeyIv', PUBLIC_PARAMETER],
  ['bwkVaultKeyTag', PUBLIC_PARAMETER],
  ['changedAt', METADATA],
  ['clipboardClearTimeout', METADATA],
  ['color', METADATA],
  ['conflictStrategy', METADATA],
  ['dataIv', PUBLIC_PARAMETER],
  ['dataTag', PUBLIC_PARAMETER],
  ['declaredChunkCount', METADATA],
  ['declaredPlaintextBytes', METADATA],
  ['defaultPasswordLength', METADATA],
  ['defaultPasswordOptions', METADATA],
  ['dekIv', PUBLIC_PARAMETER],
  ['dekTag', PUBLIC_PARAMETER],
  ['deviceInfo', METADATA],
  ['discardPendingVaultKey', METADATA],
  ['documents', METADATA],
  ['email', PERSONAL],
  ['enabled', METADATA],
  ['encryptedData', CIPHERTEXT],
  ['encryptedMeta', CIPHERTEXT],
  ['encryptedName', CIPHERTEXT],
  // A PREVIOUS password of an item, sealed under the vault key exactly as
  // `encryptedData` is: the same class of bulk ciphertext, not a wrapped key.
  ['encryptedPassword', CIPHERTEXT],
  ['encryptionVersion', PUBLIC_PARAMETER],
  ['excludeAmbiguous', METADATA],
  ['favorite', METADATA],
  ['fingerprint', PERSONAL],
  ['folderId', METADATA],
  ['folders', METADATA],
  ['format', METADATA],
  // The first five hex digits of a SHA-1: the k-anonymity range the server forwards
  // to the breach service, public by design.
  ['hashPrefix', PUBLIC_PARAMETER],
  ['hashPrefixes', PUBLIC_PARAMETER],
  ['icon', METADATA],
  ['id', METADATA],
  // An opaque retry token scoped to one account's rotation: replaying it can only
  // make that account's own retry a no-op, so it authenticates nothing.
  ['idempotencyKey', METADATA],
  ['ids', METADATA],
  ['inserts', METADATA],
  ['itemType', METADATA],
  ['items', METADATA],
  ['iv', PUBLIC_PARAMETER],
  ['kdfAlgorithm', PUBLIC_PARAMETER],
  ['kdfIterations', PUBLIC_PARAMETER],
  ['language', METADATA],
  ['length', METADATA],
  ['lockOnHidden', METADATA],
  ['lockOnHiddenDelay', METADATA],
  ['lowercase', METADATA],
  ['metaIv', PUBLIC_PARAMETER],
  ['metaTag', PUBLIC_PARAMETER],
  ['minLowercase', METADATA],
  ['minNumbers', METADATA],
  ['minSymbols', METADATA],
  ['minUppercase', METADATA],
  ['nameIv', PUBLIC_PARAMETER],
  ['nameTag', PUBLIC_PARAMETER],
  ['newBwkIv', PUBLIC_PARAMETER],
  ['newBwkSalt', PUBLIC_PARAMETER],
  ['newBwkTag', PUBLIC_PARAMETER],
  ['newBwkVaultKeyIv', PUBLIC_PARAMETER],
  ['newBwkVaultKeyTag', PUBLIC_PARAMETER],
  ['newPendingVaultKeyIv', PUBLIC_PARAMETER],
  ['newPendingVaultKeyTag', PUBLIC_PARAMETER],
  ['newVaultKeyIv', PUBLIC_PARAMETER],
  ['newVaultKeyTag', PUBLIC_PARAMETER],
  ['noncePrefix', PUBLIC_PARAMETER],
  ['numbers', METADATA],
  ['operations', METADATA],
  ['parentId', METADATA],
  ['passwordHistory', METADATA],
  ['portableFormat', METADATA],
  ['rememberMe', METADATA],
  ['scheduleHour', METADATA],
  // An HMAC of the item NAME, stored server-side for duplicate detection; it reveals
  // nothing the stored row does not.
  ['searchHash', METADATA],
  ['sortOrder', METADATA],
  ['streamSalt', PUBLIC_PARAMETER],
  ['symbols', METADATA],
  ['tag', PUBLIC_PARAMETER],
  ['tags', METADATA],
  ['theme', METADATA],
  ['updates', METADATA],
  ['uppercase', METADATA],
  ['userAgent', PERSONAL],
  ['vaultKeyIv', PUBLIC_PARAMETER],
  ['vaultKeyTag', PUBLIC_PARAMETER],
  ['vaultKeyVersion', METADATA],
]);

/**
 * Masked keys that no request schema accepts today, kept on purpose. Each is a
 * value that must never appear in a log if a client ever sends it, which is exactly
 * the case a schema cannot vouch for. If one of these becomes a real schema field,
 * the reverse check below fails and asks for it to move out of this list: it is
 * then an ordinary, schema-backed secret.
 */
const DEFENSIVE_MASK_KEYS = new Map<string, string>([
  ['masterPassword', 'never leaves the device; a client bug that sent it must still not be logged'],
  ['twoFactorSecret', 'the stored TOTP seed; no endpoint accepts it, and none may leak it'],
  ['pendingTwoFactorSecret', 'the TOTP seed of an unfinished enrolment; same reason'],
  ['backupCodes', 'the stored 2FA recovery codes; same reason'],
]);

/**
 * The secrets named one by one, independently of the ledger: moving one of these
 * onto `LOGGABLE_BODY_KEYS` to quiet the classification check still fails here.
 */
const KNOWN_SECRET_BODY_KEYS = [
  'password',
  'authHash',
  'currentAuthHash',
  'newAuthHash',
  'encryptedVaultKey',
  'newEncryptedVaultKey',
  // The wrapper a crashed rotation left behind, carried across a password change:
  // a vault key sealed under the MEK, exactly as `newEncryptedVaultKey` is.
  'newPendingEncryptedVaultKey',
  'encryptedBWK',
  'newEncryptedBWK',
  'bwkEncryptedVaultKey',
  'newBwkEncryptedVaultKey',
  // The wrapped document key. It crosses the wire twice per upload, at init and
  // again at completion, which is what makes a stale-vault-key 409 recoverable
  // without re-sending the file.
  'encryptedDek',
  // The password-reset, email-verification and account-unlock JWT.
  'token',
  // The signed 2FA challenge: presented with a code, it completes a sign-in.
  'tempToken',
  // A TOTP or 2FA backup code.
  'code',
  // A restore's whole backup file as one JSON string, which carries
  // `encryptedVaultKey`, `encryptedBWK` and `bwkEncryptedVaultKey` inside it. Key
  // masking cannot reach into a string, so the string itself is masked.
  'data',
] as const;

// ---------------------------------------------------------------------------
// Reading the request schemas
// ---------------------------------------------------------------------------

/** The slice of a Zod 4 schema definition this walk reads. */
interface ZodDef {
  type: string;
  shape?: Record<string, unknown>;
  catchall?: unknown;
  element?: unknown;
  innerType?: unknown;
  in?: unknown;
  out?: unknown;
  options?: unknown[];
  left?: unknown;
  right?: unknown;
  getter?: () => unknown;
  items?: unknown[];
  rest?: unknown;
  values?: unknown[];
  /** A Zod 4 enum's members, keyed by name. (`values` is a LITERAL's.) */
  entries?: Record<string, unknown>;
}

const defOf = (schema: unknown): ZodDef => (schema as { _zod: { def: ZodDef } })._zod.def;

/** Leaf kinds: they carry a value and no keys. */
const LEAF_TYPES = new Set([
  'string',
  'number',
  'boolean',
  'bigint',
  'date',
  'enum',
  'literal',
  'null',
  'undefined',
  'nan',
  'transform',
]);

/** Wrappers whose keys are exactly their inner schema's. */
const WRAPPER_TYPES = new Set([
  'optional',
  'nullable',
  'default',
  'prefault',
  'readonly',
  'nonoptional',
  'catch',
]);

/**
 * The schemas directly beneath one, in the order a sample should prefer them, or
 * `null` for a leaf. An unknown kind THROWS: a record, a map or an `unknown` hides
 * keys this walk cannot name, and a wrapper Zod adds tomorrow must not quietly
 * hide a field from the classification.
 */
function childrenOf(schema: unknown, where: string): unknown[] | null {
  const def = defOf(schema);
  if (LEAF_TYPES.has(def.type)) return null;
  if (WRAPPER_TYPES.has(def.type)) return [def.innerType];
  switch (def.type) {
    case 'pipe':
      return [def.in, def.out];
    case 'union':
      return def.options ?? [];
    case 'intersection':
      return [def.left, def.right];
    case 'lazy':
      return [def.getter!()];
    case 'tuple':
      return [...(def.items ?? []), ...(def.rest === undefined ? [] : [def.rest])];
    case 'array':
      return [def.element];
    default:
      throw new Error(`cannot enumerate the keys of a "${def.type}" schema at ${where}`);
  }
}

/** Every object key a schema accepts, at any depth, with the paths it appears at. */
function collectBodyKeys(schema: unknown, where: string, into: Map<string, string[]>): void {
  const def = defOf(schema);
  if (def.type === 'object') {
    if (def.catchall !== undefined && defOf(def.catchall).type !== 'never') {
      throw new Error(`${where} accepts arbitrary keys, which no ledger can classify`);
    }
    for (const [key, child] of Object.entries(def.shape ?? {})) {
      const path = `${where}.${key}`;
      into.set(key, [...(into.get(key) ?? []), path]);
      collectBodyKeys(child, path, into);
    }
    return;
  }
  for (const child of childrenOf(schema, where) ?? []) collectBodyKeys(child, where, into);
}

/**
 * A body shaped like one the schema accepts, with a UNIQUE sentinel string at every
 * string leaf, and the path of keys that leads to each sentinel. Validity is beside
 * the point (the logger never validates); what matters is that every key the schema
 * names is present, at the depth a real request puts it.
 */
function sampleBody(
  schema: unknown,
  path: readonly string[],
  sentinels: Map<string, readonly string[]>,
): unknown {
  const def = defOf(schema);
  if (def.type === 'object') {
    return Object.fromEntries(
      Object.entries(def.shape ?? {}).map(([key, child]) => [
        key,
        sampleBody(child, [...path, key], sentinels),
      ]),
    );
  }
  if (def.type === 'string') {
    const sentinel = `SENTINEL-${sentinels.size}-${path.join('.')}`;
    sentinels.set(sentinel, path);
    return sentinel;
  }
  if (def.type === 'array') return [sampleBody(def.element, path, sentinels)];
  const children = childrenOf(schema, path.join('.'));
  if (children === null) {
    // A leaf: a literal's value, an enum's first member, else a number.
    return def.values?.[0] ?? Object.values(def.entries ?? {})[0] ?? 1;
  }
  // A wrapper, a pipe (its input side), a union (its first option) and so on.
  return sampleBody(children[0], path, sentinels);
}

/** The export name of each captured schema, so a failure names the schema it is about. */
const sharedExportNames = new Map<unknown, string>(
  Object.entries(shared).map(([name, value]) => [value, name]),
);

/** Every key any captured request-body schema accepts, with the paths it appears at. */
function requestBodyKeys(): Map<string, string[]> {
  const keys = new Map<string, string[]>();
  for (const schema of captured.bodySchemas) {
    collectBodyKeys(schema, sharedExportNames.get(schema) ?? '<unexported schema>', keys);
  }
  return keys;
}

describe('Request Logger Sensitive Field Masking', () => {
  beforeAll(() => {
    // Importing app.ts (statically, at the top of this file) evaluates its
    // top-level `app.use(createRequestLogger(...))` and
    // `app.use(createErrorMiddleware(...))`, which trip the two wrappers above and
    // record the real configuration. If either were removed from the middleware
    // stack, nothing would be captured and every assertion below — here and in
    // the two suites that follow — would fail.
    expect(captured.maskBodyKeys.length).toBeGreaterThan(0);
    expect(captured.errorOptions).toBeDefined();
  });

  it('reads the request-body schemas from the routes, and every one is a shared export', () => {
    // Vacuity guard for everything below: the capture saw the routes being built,
    // including the ones this phase exists for.
    for (const schema of [
      shared.loginSchema,
      shared.login2faSchema,
      shared.restoreBackupSchema,
      shared.bulkReEncryptSchema,
      shared.backupChangePasswordSchema,
      shared.changePasswordSchema,
    ]) {
      expect(captured.bodySchemas.has(schema)).toBe(true);
    }
    // A body schema defined inside the server would escape an audit that reads the
    // shared package, and would name no export in the messages below.
    const unexported = [...captured.bodySchemas].filter((schema) => !sharedExportNames.has(schema));
    expect(unexported).toHaveLength(0);
    expect(captured.bodySchemas.size).toBeGreaterThanOrEqual(30);
  });

  it('masks every key a request schema accepts unless the ledger says why it is not secret', () => {
    const masked = new Set(captured.maskBodyKeys);
    const unclassified = [...requestBodyKeys()]
      .filter(([key]) => !masked.has(key) && !LOGGABLE_BODY_KEYS.has(key))
      .map(([key, paths]) => `${key} (${paths.slice(0, 3).join(', ')})`);

    expect(
      unclassified,
      'each of these request fields must be added to maskBodyKeys in app.ts, or to ' +
        'LOGGABLE_BODY_KEYS here with the reason it is not a secret',
    ).toEqual([]);
  });

  it('holds the mask list and the ledger to real fields, in the other direction', () => {
    const bodyKeys = requestBodyKeys();
    const masked = new Set(captured.maskBodyKeys);

    // A masked name no schema accepts is dead configuration unless it is a
    // deliberate defensive entry…
    expect(
      captured.maskBodyKeys.filter((key) => !bodyKeys.has(key) && !DEFENSIVE_MASK_KEYS.has(key)),
      'masked keys no request schema accepts',
    ).toEqual([]);
    // …a defensive entry that a schema now accepts is an ordinary secret, and a
    // defensive entry that is not masked protects nothing…
    expect([...DEFENSIVE_MASK_KEYS.keys()].filter((key) => bodyKeys.has(key))).toEqual([]);
    expect([...DEFENSIVE_MASK_KEYS.keys()].filter((key) => !masked.has(key))).toEqual([]);
    // …a ledger entry naming a field that no longer exists is stale…
    expect(
      [...LOGGABLE_BODY_KEYS.keys()].filter((key) => !bodyKeys.has(key)),
      'LOGGABLE_BODY_KEYS entries no request schema accepts',
    ).toEqual([]);
    // …and a key on both sides is a contradiction the classification cannot resolve.
    expect([...LOGGABLE_BODY_KEYS.keys()].filter((key) => masked.has(key))).toEqual([]);
    // Every ledger entry carries a reason.
    for (const [key, reason] of LOGGABLE_BODY_KEYS) expect(reason, key).not.toBe('');
  });

  it('masks each named secret, independently of the ledger', () => {
    const bodyKeys = requestBodyKeys();
    for (const key of KNOWN_SECRET_BODY_KEYS) {
      expect(captured.maskBodyKeys, `${key} must be masked`).toContain(key);
      // Named because a live schema accepts it, not from memory.
      expect(bodyKeys.has(key), `${key} is a real request field`).toBe(true);
    }
    for (const key of DEFENSIVE_MASK_KEYS.keys()) {
      expect(captured.maskBodyKeys, `${key} must be masked`).toContain(key);
    }
  });

  it('redacts every secret in a body built from each request schema, and nothing else', () => {
    // The body is generated from the SCHEMA and the expectation from the LEDGER;
    // the mask list is only the thing under test. A secret key missing from it is
    // a sentinel that survives into the captured log line.
    let checkedSecrets = 0;
    let checkedLoggable = 0;
    for (const schema of captured.bodySchemas) {
      const name = sharedExportNames.get(schema)!;
      const sentinels = new Map<string, readonly string[]>();
      const body = sampleBody(schema, [], sentinels);

      const records = runRequestLogger(body, captured.maskBodyKeys);
      expect(records, name).toHaveLength(1);
      const serialized = JSON.stringify(records[0]);

      for (const [sentinel, path] of sentinels) {
        const secret = path.some((key) => !LOGGABLE_BODY_KEYS.has(key));
        if (secret) {
          checkedSecrets += 1;
          expect(serialized, `${name}.${path.join('.')} must be redacted`).not.toContain(sentinel);
        } else {
          checkedLoggable += 1;
          expect(serialized, `${name}.${path.join('.')} must be logged`).toContain(sentinel);
        }
      }
    }
    // The defensive names no schema carries go through the same engine, so a list
    // entry that the logger silently failed to honour would show here too.
    const defensiveBody = Object.fromEntries(
      [...DEFENSIVE_MASK_KEYS.keys()].map((key) => [key, `DEFENSIVE-SENTINEL-${key}`]),
    );
    const defensiveLine = JSON.stringify(runRequestLogger(defensiveBody, captured.maskBodyKeys));
    for (const key of DEFENSIVE_MASK_KEYS.keys()) {
      checkedSecrets += 1;
      expect(defensiveLine, `${key} must be redacted`).not.toContain(`DEFENSIVE-SENTINEL-${key}`);
    }
    expect(defensiveLine).toContain('[REDACTED]');

    // Both halves did real work: secrets were planted and hidden, and ordinary
    // fields were planted and shown, so masking is targeted, not blanket.
    expect(checkedSecrets).toBeGreaterThanOrEqual(KNOWN_SECRET_BODY_KEYS.length);
    expect(checkedLoggable).toBeGreaterThan(checkedSecrets);
  });

  it('masks a key case-insensitively (engine contract relied on by the config)', () => {
    // @hiprax/logger matches maskBodyKeys case-insensitively; the app relies on
    // this so an unexpected header/body casing still redacts.
    const records = runRequestLogger({ AuthHash: 'MIXED_CASE_SECRET' }, captured.maskBodyKeys);
    const serialized = JSON.stringify(records[0]);
    expect(serialized).not.toContain('MIXED_CASE_SECRET');
    expect(serialized).toContain('[REDACTED]');
  });
});

// ---------------------------------------------------------------------------
// Audit rows
// ---------------------------------------------------------------------------

/** A value that exists nowhere else, per planted field. */
const auditSentinel = (key: string): string => `AuditSentinel-${key}-4d9b17c0`;

describe('Audit-log rows carry no secret', () => {
  it('records what happened, and none of the sensitive values that made it happen', async () => {
    // Every planted value goes into a field the wire schema actually accepts, so
    // each request reaches its controller and writes its audit row. A value the
    // endpoint rejected would be a plant that proves nothing.
    const sent: string[] = [];
    const plant = (key: string): string => {
      const value = auditSentinel(key);
      sent.push(value);
      return value;
    };

    const correctAuthHash = plant('authHash');
    const user = await createTestUser({ password: correctAuthHash, emailVerified: true });
    const agent = request.agent(app);

    // 1. A successful sign-in → `login`.
    const loginCsrf = await getCsrf(agent);
    await agent
      .post('/api/v1/auth/login')
      .set('Cookie', loginCsrf.cookie)
      .set('x-csrf-token', loginCsrf.token)
      .send({ email: user.email, authHash: correctAuthHash })
      .expect(200);

    // 2. A rejected one → `login_failed`, whose row must not carry the attempt.
    const wrongCsrf = await getCsrf(agent);
    await agent
      .post('/api/v1/auth/login')
      .set('Cookie', wrongCsrf.cookie)
      .set('x-csrf-token', wrongCsrf.token)
      .send({ email: user.email, authHash: plant('newAuthHash') })
      .expect(401);

    // 3. An item, whose ciphertext fields must not be echoed into the row.
    const itemCsrf = await getCsrf(agent);
    await agent
      .post('/api/v1/vault/items')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', itemCsrf.cookie)
      .set('x-csrf-token', itemCsrf.token)
      .send(
        sampleVaultItem({
          encryptedData: plant('encryptedData'),
          encryptedName: plant('encryptedName'),
        }),
      )
      .expect(201);

    // 4. An export, which re-authenticates with the auth hash → `export`.
    const exportCsrf = await getCsrf(agent);
    await agent
      .post('/api/v1/tools/export')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', exportCsrf.cookie)
      .set('x-csrf-token', exportCsrf.token)
      .send({ format: 'json', authHash: correctAuthHash })
      .expect(200);

    // 5. A failed re-authentication → `password_verification_failed`, the row
    //    most likely to be written with the offending value "for debugging".
    const twoFaCsrf = await getCsrf(agent);
    await agent
      .post('/api/v1/user/2fa/setup')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', twoFaCsrf.cookie)
      .set('x-csrf-token', twoFaCsrf.token)
      .send({ password: plant('password') })
      .expect(401);

    const rows = await AuditLog.find({ userId: user.id }).lean();

    // The rows are THERE. Without this the scan below would pass on an empty
    // collection — the same vacuity a masking test has when nothing was logged.
    const actions = rows.map((row) => row.action);
    for (const action of [
      'login',
      'login_failed',
      'item_create',
      'export',
      'password_verification_failed',
    ]) {
      expect(actions, `an audit row for "${action}" must exist`).toContain(action);
    }
    // …and they carry real, non-secret detail, so what follows is a targeted
    // absence rather than the trivial absence of empty rows.
    const created = rows.find((row) => row.action === 'item_create');
    expect(created?.metadata).toMatchObject({ itemType: 'login' });
    expect(rows.find((row) => row.action === 'export')?.metadata).toMatchObject({ itemCount: 1 });

    const serialized = JSON.stringify(rows);
    expect(sent.length).toBeGreaterThanOrEqual(5);
    for (const value of sent) {
      expect(
        serialized,
        'an audit row leaked a value from the request that caused it',
      ).not.toContain(value);
    }
  });

  it('keeps a masked field out of the row even when the request is rejected before its handler', async () => {
    // A Zod rejection never reaches a controller, so nothing should be audited
    // at all — and in particular not the malformed body that caused it. Asserted
    // separately because "no row" and "a clean row" are different outcomes and
    // only one of them is correct here.
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const value = auditSentinel('masterPassword');
    await agent
      .post('/api/v1/auth/login')
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send({ email: 'not-an-email', authHash: value })
      .expect(400);

    // Both halves, because they are different claims: nothing was audited at
    // all, and in particular the offending body was not. The first is what makes
    // the second more than a statement about an empty collection — the suite
    // truncates between tests, so an empty result here would otherwise satisfy
    // any scan whatsoever.
    const rows = await AuditLog.find({}).lean();
    expect(rows, 'a request rejected by validation is not an auditable event').toHaveLength(0);
    expect(JSON.stringify(rows)).not.toContain(value);
  });
});

// ---------------------------------------------------------------------------
// Error response bodies
// ---------------------------------------------------------------------------

/**
 * A throwaway app mounting the app's OWN error middleware.
 *
 * The configuration is the one captured from `app.ts` rather than a copy: flip
 * `exposeServerErrors` there and these assertions fail, which is the whole point
 * of capturing it. A route that throws is used rather than one of the real
 * endpoints because a 500 has to be provoked deliberately — the real ones are
 * built not to have one.
 */
function probeApp(detail: string) {
  const probe = express();
  probe.get('/boom', () => {
    throw new Error(`database connection to admin:hunter2@db-01 failed: ${detail}`);
  });
  probe.get('/bad-input', (_req, _res, next) => {
    next(httpErrors.badRequest('Email is required'));
  });
  probe.use(createErrorMiddleware(captured.errorOptions));
  return probe;
}

describe('Error response bodies in production', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('is configured to redact server errors', () => {
    expect(
      captured.errorOptions?.exposeServerErrors,
      'app.ts must keep exposeServerErrors false, or a production 5xx body leaks internals',
    ).toBe(false);
  });

  it('redacts a 5xx body to its status text in production, stack included', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    const detail = 'INTERNAL-DETAIL-8f21';
    const res = await request(probeApp(detail)).get('/boom').expect(500);

    expect(res.body).toEqual({
      success: false,
      message: 'Internal Server Error',
      statusCode: 500,
      statusText: 'Internal Server Error',
    });
    const serialized = JSON.stringify(res.body);
    expect(serialized).not.toContain(detail);
    // The two things an internal message routinely carries and must never ship:
    // infrastructure names and credentials.
    expect(serialized).not.toContain('db-01');
    expect(serialized).not.toContain('hunter2');
    // A stack is a file map of the server; production gets none.
    expect(res.body).not.toHaveProperty('stack');
  });

  it('still explains a 4xx in production, so the redaction is targeted', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    const res = await request(probeApp('unused')).get('/bad-input').expect(400);
    expect(res.body.message).toBe('Email is required');
    expect(res.body.statusCode).toBe(400);
  });

  it('exposes the same 5xx detail outside production, which is what makes the redaction observable', async () => {
    // The negative control. Without it, the assertion above would pass just as
    // well against a middleware that always answered "Internal Server Error" —
    // including one that had stopped looking at the environment at all.
    const detail = 'INTERNAL-DETAIL-9c04';
    const res = await request(probeApp(detail)).get('/boom').expect(500);
    expect(res.body.message).toContain(detail);
    expect(res.body).toHaveProperty('stack');
  });
});
