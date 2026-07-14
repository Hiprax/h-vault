/**
 * Tests for Phase 2 / Tasks 2.7 + 2.8:
 *
 *  - 2.7: `verifyTopology` emits a `warn`-level log when the URI advertises a
 *         replica set but the server's `hello` response doesn't expose a
 *         matching `setName` (or any `setName` at all). Without this, the
 *         runtime `supportsTransactions()` heuristic returns true based on the
 *         URI option alone and transactional writes silently fall back to
 *         sequential writes at runtime.
 *  - 2.8: Emails passed into structured Winston logger metadata are masked via
 *         `maskEmail` before they hit the transport, preventing raw PII from
 *         landing in long-retention log stores.
 *
 * The capture strategy hooks `@hiprax/logger`'s `createLogger` factory: every
 * scoped logger that the server registers at module-load time gets the
 * recorded methods, so we can scan all emitted entries (including the ones
 * created before this test file loads — by replacing the methods on the
 * already-cached instances).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import mongoose from 'mongoose';
import request from 'supertest';
import * as hipraxLogger from '@hiprax/logger';
import app from '../src/app.js';
import { verifyTopology } from '../src/config/database.js';

// ---------------------------------------------------------------------------
// Helper: install a global capture by patching every existing scoped logger
// (the modules that pull in `@hiprax/logger` cache the loggers; we mutate
// them in place to record any subsequent calls without breaking call
// signatures).
// ---------------------------------------------------------------------------

interface CapturedEntry {
  level: 'info' | 'warn' | 'error' | 'debug' | 'verbose' | 'silly' | 'http';
  args: unknown[];
}

interface Capture {
  entries: CapturedEntry[];
  restore: () => void;
}

function installCapture(): Capture {
  const entries: CapturedEntry[] = [];
  const originals: { obj: Record<string, unknown>; key: string; fn: unknown }[] = [];
  const levels: CapturedEntry['level'][] = [
    'info',
    'warn',
    'error',
    'debug',
    'verbose',
    'silly',
    'http',
  ];

  // Patch *every* logger instance that has been created so far. The hiprax
  // factory caches them in a private Map, but the cached instances are also
  // referenced from each module that imported them. We can't reach the
  // factory's private map directly, but we can patch every logger we know
  // about by re-creating one for each known module name (the factory returns
  // the cached instance), then patching its level methods.
  const knownModules = [
    'database',
    'auth',
    'email',
    'backup-controller',
    'jobs/backup',
    'audit-service',
    'config',
    'cascade-delete',
    'app',
    'global',
    'http',
  ];

  for (const moduleName of knownModules) {
    const logger = hipraxLogger.createLogger({ moduleName }) as unknown as Record<string, unknown>;
    for (const level of levels) {
      const orig = logger[level];
      if (typeof orig !== 'function') continue;
      originals.push({ obj: logger, key: level, fn: orig });
      logger[level] = (...args: unknown[]): unknown => {
        entries.push({ level, args });
        return undefined;
      };
    }
  }

  return {
    entries,
    restore: () => {
      for (const { obj, key, fn } of originals) {
        obj[key] = fn;
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Task 2.7: topology mismatch detection
// ---------------------------------------------------------------------------

describe('verifyTopology (Task 2.7)', () => {
  let getClientSpy: ReturnType<typeof vi.spyOn> | undefined;
  let dbDescriptor: PropertyDescriptor | undefined;
  let capture: Capture | undefined;

  beforeEach(() => {
    dbDescriptor = Object.getOwnPropertyDescriptor(mongoose.connection, 'db');
    capture = installCapture();
  });

  afterEach(() => {
    getClientSpy?.mockRestore();
    if (dbDescriptor) {
      Object.defineProperty(mongoose.connection, 'db', dbDescriptor);
    }
    capture?.restore();
  });

  it('emits a warning when the URI requests a replica set but `hello` returns no setName', async () => {
    getClientSpy = vi.spyOn(mongoose.connection, 'getClient').mockReturnValue({
      options: { replicaSet: 'rs0' },
    } as unknown as ReturnType<typeof mongoose.connection.getClient>);

    const fakeAdmin = { command: vi.fn().mockResolvedValue({ ok: 1 }) };
    Object.defineProperty(mongoose.connection, 'db', {
      configurable: true,
      get: () => ({ admin: () => fakeAdmin }),
    });

    await verifyTopology();

    expect(fakeAdmin.command).toHaveBeenCalledWith({ hello: 1 });

    const warned = capture!.entries.some((e) => {
      const msg = typeof e.args[0] === 'string' ? (e.args[0] as string) : '';
      return (
        e.level === 'warn' &&
        msg.includes("requests replica set 'rs0'") &&
        msg.includes('without a setName')
      );
    });
    expect(warned).toBe(true);
  });

  it('emits a warning when the URI replica set name differs from the server setName', async () => {
    getClientSpy = vi.spyOn(mongoose.connection, 'getClient').mockReturnValue({
      options: { replicaSet: 'rs0' },
    } as unknown as ReturnType<typeof mongoose.connection.getClient>);

    const fakeAdmin = {
      command: vi.fn().mockResolvedValue({ ok: 1, setName: 'wrong-rs' }),
    };
    Object.defineProperty(mongoose.connection, 'db', {
      configurable: true,
      get: () => ({ admin: () => fakeAdmin }),
    });

    await verifyTopology();

    const warned = capture!.entries.some((e) => {
      const msg = typeof e.args[0] === 'string' ? (e.args[0] as string) : '';
      return (
        e.level === 'warn' &&
        msg.includes("requests replica set 'rs0'") &&
        msg.includes("setName 'wrong-rs'")
      );
    });
    expect(warned).toBe(true);
  });

  it('does not warn when the URI does not request a replica set', async () => {
    getClientSpy = vi.spyOn(mongoose.connection, 'getClient').mockReturnValue({
      options: {},
    } as unknown as ReturnType<typeof mongoose.connection.getClient>);

    await verifyTopology();

    const warned = capture!.entries.some((e) => {
      const msg = typeof e.args[0] === 'string' ? (e.args[0] as string) : '';
      return msg.includes('requests replica set');
    });
    expect(warned).toBe(false);
  });

  it('does not warn when the URI replica set name matches the server setName', async () => {
    getClientSpy = vi.spyOn(mongoose.connection, 'getClient').mockReturnValue({
      options: { replicaSet: 'rs0' },
    } as unknown as ReturnType<typeof mongoose.connection.getClient>);

    const fakeAdmin = {
      command: vi.fn().mockResolvedValue({ ok: 1, setName: 'rs0' }),
    };
    Object.defineProperty(mongoose.connection, 'db', {
      configurable: true,
      get: () => ({ admin: () => fakeAdmin }),
    });

    await verifyTopology();

    const warned = capture!.entries.some((e) => {
      const msg = typeof e.args[0] === 'string' ? (e.args[0] as string) : '';
      return msg.includes('requests replica set');
    });
    expect(warned).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Task 2.8: structured-log email masking
// ---------------------------------------------------------------------------

/**
 * Recursively scans a captured logger payload for any string value that
 * looks like a raw email address (`local@domain.tld`). The masked form
 * `m***l@example.com` does not match this pattern because `***` precedes `@`.
 */
function containsRawEmail(value: unknown): boolean {
  const RAW_EMAIL_RE = /(^|[^*])[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
  if (typeof value === 'string') {
    return RAW_EMAIL_RE.test(value);
  }
  if (Array.isArray(value)) {
    return value.some((v) => containsRawEmail(v));
  }
  if (value && typeof value === 'object') {
    for (const v of Object.values(value as Record<string, unknown>)) {
      if (containsRawEmail(v)) return true;
    }
  }
  return false;
}

describe('Structured log email masking (Task 2.8)', () => {
  it('masks the email field in registration logs and never leaks the raw address', async () => {
    const capture = installCapture();
    try {
      const email = `pii-test-${Date.now()}@example.com`;

      const csrfRes = await request(app).get('/api/v1/csrf-token');
      const setCookies = csrfRes.headers['set-cookie'] as string[];
      const csrfCookie = setCookies.find((c) => c.startsWith('__csrf='))?.split(';')[0] ?? '';
      const csrfToken: string = csrfRes.body.data.csrfToken;

      await request(app)
        .post('/api/v1/auth/register')
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          email,
          authHash: 'pii-test-auth-hash',
          encryptedVaultKey: 'enc-key',
          vaultKeyIv: 'enc-iv',
          vaultKeyTag: 'enc-tag',
          kdfIterations: 600_000,
          kdfAlgorithm: 'PBKDF2-SHA256',
          encryptionVersion: 1,
        });

      const registered = capture.entries.find((e) => {
        const msg = typeof e.args[0] === 'string' ? (e.args[0] as string) : '';
        return e.level === 'info' && msg.includes('New user registered');
      });
      expect(registered).toBeDefined();
      const meta = registered!.args[1] as Record<string, unknown>;
      const loggedEmail = meta['email'];
      expect(typeof loggedEmail).toBe('string');
      expect(loggedEmail).not.toBe(email);
      expect(loggedEmail).toMatch(/\*\*\*/);

      // No structured log entry that mentions our local-part should contain
      // the unmasked email.
      const localPart = email.split('@')[0]!;
      for (const entry of capture.entries) {
        const haystack = JSON.stringify(entry.args);
        if (!haystack.includes(localPart)) continue;
        expect(haystack.includes(email)).toBe(false);
        expect(containsRawEmail(entry.args)).toBe(false);
      }
    } finally {
      capture.restore();
    }
  });
});
