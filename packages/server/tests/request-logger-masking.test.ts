import { describe, it, expect, afterEach, beforeAll, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import express from 'express';
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
//   2. Drives the REAL @hiprax/logger masking engine with that exact list and a
//      capturing winston transport, and asserts each configured secret value is
//      redacted while benign fields survive.
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
  },
}));

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

  it('configures the app to mask all documented sensitive fields', () => {
    expect(captured.maskBodyKeys.length).toBeGreaterThanOrEqual(11);
    for (const expected of [
      'password',
      'authHash',
      'masterPassword',
      'encryptedVaultKey',
      'twoFactorSecret',
      'backupCodes',
      'pendingTwoFactorSecret',
      'newAuthHash',
      'currentAuthHash',
      'newEncryptedVaultKey',
      'encryptedBWK',
    ]) {
      expect(captured.maskBodyKeys).toContain(expected);
    }
  });

  it('redacts every configured secret value in the logged body while keeping benign fields', () => {
    const maskBodyKeys = captured.maskBodyKeys;
    expect(maskBodyKeys.length).toBeGreaterThanOrEqual(11);

    // Give each configured key a UNIQUE plaintext value plus one benign field.
    const body: Record<string, string> = { benignField: 'KEEP_THIS_PLAINTEXT' };
    const secretValues: Record<string, string> = {};
    for (const key of maskBodyKeys) {
      const value = `SECRET_${key}_PLAINTEXT`;
      body[key] = value;
      secretValues[key] = value;
    }

    const records = runRequestLogger(body, maskBodyKeys);
    expect(records.length).toBe(1);
    const serialized = JSON.stringify(records[0]);

    // The masking engine redacted the body it captured…
    expect(serialized).toContain('[REDACTED]');
    // …and NOT ONE configured secret's plaintext survived. Dropping a key from
    // the app's maskBodyKeys would let that key's plaintext appear here.
    for (const key of maskBodyKeys) {
      expect(serialized).not.toContain(secretValues[key]);
    }
    // Non-secret fields are logged verbatim (masking is targeted, not blanket).
    expect(serialized).toContain('KEEP_THIS_PLAINTEXT');
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
