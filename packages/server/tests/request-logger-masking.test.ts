import { describe, it, expect, beforeAll, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import TransportStream from 'winston-transport';
import winston from 'winston';

// The app wires @hiprax/logger's `createRequestLogger` with a `maskBodyKeys`
// list. The previous version of this suite regex-scraped that literal out of
// app.ts's SOURCE TEXT and asserted on the extracted strings — it never ran the
// logger, so it would stay green even if the middleware were unmounted, and it
// broke on harmless refactors (hoisting the list into a const, reformatting).
//
// This version instead:
//   1. Captures the ACTUAL `maskBodyKeys` app.ts passes at RUNTIME (by wrapping
//      `createRequestLogger` so the array can't drift from a copied literal).
//   2. Drives the REAL @hiprax/logger masking engine with that exact list and a
//      capturing winston transport, and asserts each configured secret value is
//      redacted while benign fields survive.
//
// `includeRequestBody: true` is set for the engine exercise so the redaction
// actually runs against a body — that is the defense the `maskBodyKeys` config
// expresses (redact these keys whenever a body is logged).

const { captured } = vi.hoisted(() => ({ captured: { maskBodyKeys: [] as string[] } }));

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

import { createRequestLogger } from '@hiprax/logger';

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
  beforeAll(async () => {
    // Importing app.ts evaluates its top-level `app.use(createRequestLogger(...))`,
    // which trips the wrapper above and records the real maskBodyKeys. If the
    // logger were removed from the middleware stack, nothing would be captured
    // and every assertion below would fail.
    await import('../src/app.js');
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
