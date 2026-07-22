import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import mongoose from 'mongoose';

// `config/index.ts` calls `dotenv.config()` at module scope. Stub it so a
// developer's root `.env` cannot leak into (and flip the outcome of) the
// config-loading cases below — same convention as `tests/config.test.ts`.
vi.mock('dotenv', () => ({ default: { config: vi.fn() } }));

const mockWarn = vi.fn();
const mockInfo = vi.fn();
const mockError = vi.fn();
vi.mock('@hiprax/logger', () => ({
  createLogger: () => ({ warn: mockWarn, info: mockInfo, error: mockError, debug: vi.fn() }),
}));

// Static import: `database.ts` and the test share the SAME mongoose singleton,
// so `vi.spyOn(mongoose, 'connect')` intercepts the real call site without
// mocking the module (which would break the models it registers, and the live
// in-memory connection `tests/setup.ts` owns).
const { connectDatabase, disconnectDatabase, verifyTopology } =
  await import('../src/config/database.js');
const { config } = await import('../src/config/index.js');

// Mirrors the constants in `src/config/database.ts`.
const MAX_RETRY_ATTEMPTS = 5;
const RETRY_DELAY_MS = 5000;

describe('config/database.ts', () => {
  beforeEach(() => {
    mockWarn.mockClear();
    mockInfo.mockClear();
    mockError.mockClear();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('connectDatabase — connect options', () => {
    it('passes the configured URI and pool sizes through to mongoose.connect', async () => {
      const connectSpy = vi.spyOn(mongoose, 'connect').mockResolvedValue(mongoose);

      const result = await connectDatabase();

      expect(result).toBe(mongoose);
      expect(connectSpy).toHaveBeenCalledTimes(1);
      const [uri, options] = connectSpy.mock.calls[0]!;
      expect(uri).toBe(config.MONGODB_URI);
      expect(options).toMatchObject({
        maxPoolSize: config.MONGO_MAX_POOL_SIZE,
        minPoolSize: config.MONGO_MIN_POOL_SIZE,
        socketTimeoutMS: 45_000,
        serverSelectionTimeoutMS: 5000,
        heartbeatFrequencyMS: 10_000,
      });
    });

    it('enables autoIndex outside production', async () => {
      const connectSpy = vi.spyOn(mongoose, 'connect').mockResolvedValue(mongoose);

      await connectDatabase();

      expect(connectSpy.mock.calls[0]![1]).toMatchObject({ autoIndex: true });
    });

    it('disables autoIndex in production (indexes are created by the bootstrap step)', async () => {
      const connectSpy = vi.spyOn(mongoose, 'connect').mockResolvedValue(mongoose);
      const originalEnv = config.NODE_ENV;
      config.NODE_ENV = 'production';
      try {
        await connectDatabase();
      } finally {
        config.NODE_ENV = originalEnv;
      }

      expect(connectSpy.mock.calls[0]![1]).toMatchObject({ autoIndex: false });
      // Production additionally runs the index verification pass; with every
      // index present it reports a clean bill of health.
      expect(mockInfo).toHaveBeenCalledWith('All database indexes verified');
    });
  });

  describe('connectDatabase — production index verification', () => {
    /** Runs connectDatabase with NODE_ENV flipped to production, then restores it. */
    async function connectAsProduction(): Promise<void> {
      vi.spyOn(mongoose, 'connect').mockResolvedValue(mongoose);
      const originalEnv = config.NODE_ENV;
      config.NODE_ENV = 'production';
      try {
        await connectDatabase();
      } finally {
        config.NODE_ENV = originalEnv;
      }
    }

    it('warns per model — with the create-indexes hint — when a schema index is missing', async () => {
      // Production disables autoIndex, so a deployment that skipped the
      // bootstrap step silently loses the indexes the app's correctness depends
      // on. Simulate that for one collection by dropping a schema-defined index.
      const model = mongoose.model('VaultItem');
      const collection = model.collection;
      const before = await collection.indexes();
      const victim = before.find((idx) => idx.name !== '_id_');
      expect(victim?.name).toBeTypeOf('string');
      await collection.dropIndex(victim!.name!);

      try {
        await connectAsProduction();

        expect(mockWarn).toHaveBeenCalledWith(
          expect.stringContaining(`Missing index on "${collection.collectionName}"`),
        );
        expect(mockWarn).toHaveBeenCalledWith(
          expect.stringContaining('npm run create-indexes -w packages/server'),
        );
        expect(mockWarn).toHaveBeenCalledWith(
          expect.stringContaining('Found 1 model(s) with missing indexes'),
        );
        expect(mockInfo).not.toHaveBeenCalledWith('All database indexes verified');
      } finally {
        await mongoose.model('VaultItem').createIndexes();
      }
    });

    it('is non-fatal: an index-verification failure warns and still resolves the connection', async () => {
      vi.spyOn(mongoose, 'modelNames').mockImplementation(() => {
        throw new Error('registry unavailable');
      });

      await expect(connectAsProduction()).resolves.toBeUndefined();

      expect(mockWarn).toHaveBeenCalledWith('Index verification failed: registry unavailable');
    });
  });

  describe('connectDatabase — retry/backoff', () => {
    it('retries after a transient failure and eventually resolves', async () => {
      vi.useFakeTimers();
      const connectSpy = vi
        .spyOn(mongoose, 'connect')
        .mockRejectedValueOnce(new Error('ECONNREFUSED'))
        .mockRejectedValueOnce(new Error('ECONNREFUSED'))
        .mockResolvedValueOnce(mongoose);

      const promise = connectDatabase();
      // Let the first rejection settle. The retry must NOT fire until the
      // backoff delay has elapsed.
      await vi.advanceTimersByTimeAsync(0);
      expect(connectSpy).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(RETRY_DELAY_MS - 1);
      expect(connectSpy).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(1);
      expect(connectSpy).toHaveBeenCalledTimes(2);

      await vi.advanceTimersByTimeAsync(RETRY_DELAY_MS);

      await expect(promise).resolves.toBe(mongoose);
      expect(connectSpy).toHaveBeenCalledTimes(3);
      expect(mockWarn).toHaveBeenCalledWith(expect.stringContaining('Connection attempt 1 failed'));
      expect(mockWarn).toHaveBeenCalledWith(expect.stringContaining('Connection attempt 2 failed'));
    });

    it('gives up after MAX_RETRY_ATTEMPTS and rethrows the underlying error', async () => {
      vi.useFakeTimers();
      const fatal = new Error('server selection timed out');
      const connectSpy = vi.spyOn(mongoose, 'connect').mockRejectedValue(fatal);

      const promise = connectDatabase();
      const assertion = expect(promise).rejects.toThrow('server selection timed out');

      // 4 backoffs separate the 5 attempts.
      await vi.advanceTimersByTimeAsync(RETRY_DELAY_MS * MAX_RETRY_ATTEMPTS);
      await assertion;

      expect(connectSpy).toHaveBeenCalledTimes(MAX_RETRY_ATTEMPTS);
      expect(mockError).toHaveBeenCalledWith(
        expect.stringContaining(`Failed to connect after ${String(MAX_RETRY_ATTEMPTS)} attempts`),
      );
      // Exactly MAX_RETRY_ATTEMPTS - 1 retry warnings (no warning on the final,
      // give-up attempt).
      const retryWarnings = mockWarn.mock.calls.filter((c) =>
        String(c[0]).startsWith('Connection attempt'),
      );
      expect(retryWarnings).toHaveLength(MAX_RETRY_ATTEMPTS - 1);
    });
  });

  describe('connectDatabase — connection event handlers', () => {
    /**
     * Captures the handlers `connectDatabase` registers on the mongoose
     * connection and invokes them directly, rather than emitting on the live
     * connection that `tests/setup.ts` owns (emitting `disconnected` on it would
     * disturb every later test in the file).
     */
    async function captureHandlers(): Promise<Map<string, (arg?: unknown) => void>> {
      const handlers = new Map<string, (arg?: unknown) => void>();
      vi.spyOn(mongoose, 'connect').mockResolvedValue(mongoose);
      const onSpy = vi
        .spyOn(mongoose.connection, 'on')
        .mockImplementation((event: string, handler: (...args: unknown[]) => void) => {
          handlers.set(event, handler);
          return mongoose.connection;
        });

      await connectDatabase();
      onSpy.mockRestore();
      return handlers;
    }

    it('registers handlers for connected/disconnected/error/reconnected', async () => {
      const handlers = await captureHandlers();
      expect([...handlers.keys()].sort()).toEqual([
        'connected',
        'disconnected',
        'error',
        'reconnected',
      ]);
    });

    it('logs on connected and reconnected', async () => {
      const handlers = await captureHandlers();

      handlers.get('connected')!();
      expect(mockInfo).toHaveBeenCalledWith('MongoDB connected successfully');

      handlers.get('reconnected')!();
      expect(mockInfo).toHaveBeenCalledWith('MongoDB reconnected');
    });

    it('warns on disconnected', async () => {
      const handlers = await captureHandlers();

      handlers.get('disconnected')!();

      expect(mockWarn).toHaveBeenCalledWith('MongoDB disconnected');
    });

    it('logs the error payload on a connection error', async () => {
      const handlers = await captureHandlers();
      const boom = new Error('topology destroyed');

      handlers.get('error')!(boom);

      expect(mockError).toHaveBeenCalledWith('MongoDB connection error', { error: boom });
    });
  });

  describe('disconnectDatabase', () => {
    it('disconnects mongoose and logs success', async () => {
      const disconnectSpy = vi.spyOn(mongoose, 'disconnect').mockResolvedValue(undefined);

      await expect(disconnectDatabase()).resolves.toBeUndefined();

      expect(disconnectSpy).toHaveBeenCalledTimes(1);
      expect(mockInfo).toHaveBeenCalledWith('MongoDB disconnected gracefully');
    });

    it('rethrows (and logs) when mongoose.disconnect fails', async () => {
      const failure = new Error('disconnect failed');
      vi.spyOn(mongoose, 'disconnect').mockRejectedValue(failure);

      await expect(disconnectDatabase()).rejects.toThrow('disconnect failed');

      expect(mockError).toHaveBeenCalledWith('Error during database disconnection', {
        error: failure,
      });
    });
  });

  describe('verifyTopology', () => {
    it('stays silent when the URI requests no replica set (standalone)', async () => {
      // The live in-memory server is a standalone; `client.options.replicaSet`
      // is undefined, so the check must short-circuit without warning.
      await verifyTopology();

      expect(mockWarn).not.toHaveBeenCalled();
    });

    it('warns when the URI requests a replica set but the server reports no setName', async () => {
      vi.spyOn(mongoose.connection, 'getClient').mockReturnValue({
        options: { replicaSet: 'rs0' },
      } as unknown as ReturnType<typeof mongoose.connection.getClient>);
      vi.spyOn(mongoose.connection.db!, 'admin').mockReturnValue({
        command: vi.fn().mockResolvedValue({}),
      } as unknown as ReturnType<NonNullable<typeof mongoose.connection.db>['admin']>);

      await verifyTopology();

      expect(mockWarn).toHaveBeenCalledWith(
        expect.stringContaining("requests replica set 'rs0' but server reports topology without"),
      );
      // The consequence, stated as the code now states it: there is no silent
      // fallback to sequential writes — every transactional endpoint fails.
      expect(mockWarn).toHaveBeenCalledWith(expect.stringContaining('will fail with a 500'));
    });

    it('warns on a setName mismatch between the URI and the server', async () => {
      vi.spyOn(mongoose.connection, 'getClient').mockReturnValue({
        options: { replicaSet: 'rs0' },
      } as unknown as ReturnType<typeof mongoose.connection.getClient>);
      vi.spyOn(mongoose.connection.db!, 'admin').mockReturnValue({
        command: vi.fn().mockResolvedValue({ setName: 'other-rs' }),
      } as unknown as ReturnType<NonNullable<typeof mongoose.connection.db>['admin']>);

      await verifyTopology();

      expect(mockWarn).toHaveBeenCalledWith(
        expect.stringContaining("server reports setName 'other-rs'"),
      );
    });

    it('does not warn when the reported setName matches the URI', async () => {
      vi.spyOn(mongoose.connection, 'getClient').mockReturnValue({
        options: { replicaSet: 'rs0' },
      } as unknown as ReturnType<typeof mongoose.connection.getClient>);
      vi.spyOn(mongoose.connection.db!, 'admin').mockReturnValue({
        command: vi.fn().mockResolvedValue({ setName: 'rs0' }),
      } as unknown as ReturnType<NonNullable<typeof mongoose.connection.db>['admin']>);

      await verifyTopology();

      expect(mockWarn).not.toHaveBeenCalled();
    });

    it('swallows a failing hello command and warns instead of throwing (non-fatal at boot)', async () => {
      vi.spyOn(mongoose.connection, 'getClient').mockReturnValue({
        options: { replicaSet: 'rs0' },
      } as unknown as ReturnType<typeof mongoose.connection.getClient>);
      vi.spyOn(mongoose.connection.db!, 'admin').mockReturnValue({
        command: vi.fn().mockRejectedValue(new Error('not authorized')),
      } as unknown as ReturnType<NonNullable<typeof mongoose.connection.db>['admin']>);

      await expect(verifyTopology()).resolves.toBeUndefined();

      expect(mockWarn).toHaveBeenCalledWith('Topology verification failed: not authorized');
    });
  });
});

// ---------------------------------------------------------------------------
// config/index.ts — branches not covered by tests/config.test.ts
// ---------------------------------------------------------------------------

describe('config/index.ts — Gmail provider + development security warning', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    vi.resetModules();
    mockWarn.mockClear();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  async function loadConfigWithEnv(envOverrides: Record<string, string | undefined> = {}) {
    process.env = {
      ...originalEnv,
      NODE_ENV: 'test',
      MONGODB_URI: 'mongodb://localhost:27017/hvault-test',
      JWT_ACCESS_SECRET: 'test-access-secret-for-testing-only-32chars!',
      JWT_REFRESH_SECRET: 'test-refresh-secret-for-testing-only-32chars!',
      SESSION_SECRET: 'TestSessionSecret4Testing!!12345',
      CORS_ORIGIN: 'http://localhost:5173',
      APP_URL: 'http://localhost:5000',
      ...envOverrides,
    };

    for (const [key, value] of Object.entries(process.env)) {
      if (value === undefined) {
        Reflect.deleteProperty(process.env, key);
      }
    }

    return import('../src/config/index.js');
  }

  const productionBase = {
    NODE_ENV: 'production',
    JWT_ACCESS_SECRET: 'prod-access-secret-very-secure-and-long-enough!!',
    JWT_REFRESH_SECRET: 'prod-refresh-secret-very-secure-and-long-enough!!',
    SESSION_SECRET: 'ProdSessionSecretVerySecure!!1234',
    TWO_FACTOR_ENCRYPTION_KEY: 'ProdTwoFactorEncryptionKey!!12345',
    CORS_ORIGIN: 'https://hvault.example.com',
  };

  describe('Gmail configuration completeness', () => {
    it('partial Gmail config (username only) in production aborts boot', async () => {
      await expect(
        loadConfigWithEnv({
          ...productionBase,
          EMAIL_PROVIDER: 'gmail',
          GMAIL_USERNAME: 'sender@gmail.com',
          GMAIL_PASSWORD: undefined,
        }),
      ).rejects.toThrow(
        'Gmail configuration is incomplete. Set both GMAIL_USERNAME and GMAIL_PASSWORD or none.',
      );
    });

    it('partial Gmail config (password only) in production aborts boot', async () => {
      await expect(
        loadConfigWithEnv({
          ...productionBase,
          EMAIL_PROVIDER: 'gmail',
          GMAIL_USERNAME: undefined,
          GMAIL_PASSWORD: 'app-password',
        }),
      ).rejects.toThrow('Gmail configuration is incomplete');
    });

    it('partial Gmail config outside production warns and normalises BOTH fields to unset', async () => {
      const {
        config: cfg,
        gmailConfigured,
        emailConfigured,
      } = await loadConfigWithEnv({
        EMAIL_PROVIDER: 'gmail',
        GMAIL_USERNAME: 'sender@gmail.com',
        GMAIL_PASSWORD: undefined,
      });

      expect(mockWarn).toHaveBeenCalledWith(
        expect.stringContaining('Gmail configuration is incomplete'),
      );
      // The half-set username must be dropped, otherwise the email module would
      // build a transporter with missing credentials.
      expect(cfg.GMAIL_USERNAME).toBeUndefined();
      expect(cfg.GMAIL_PASSWORD).toBeUndefined();
      expect(gmailConfigured).toBe(false);
      expect(emailConfigured).toBe(false);
    });

    it('production with EMAIL_PROVIDER=gmail and no Gmail fields warns but boots', async () => {
      const { config: cfg, emailConfigured } = await loadConfigWithEnv({
        ...productionBase,
        EMAIL_PROVIDER: 'gmail',
        GMAIL_USERNAME: undefined,
        GMAIL_PASSWORD: undefined,
      });

      expect(cfg.EMAIL_PROVIDER).toBe('gmail');
      expect(emailConfigured).toBe(false);
      expect(mockWarn).toHaveBeenCalledWith(expect.stringContaining('Gmail not configured'));
    });

    it('a complete Gmail config marks emailConfigured true and leaves SMTP unconfigured', async () => {
      const {
        config: cfg,
        gmailConfigured,
        smtpConfigured,
        emailConfigured,
      } = await loadConfigWithEnv({
        EMAIL_PROVIDER: 'gmail',
        GMAIL_USERNAME: 'sender@gmail.com',
        GMAIL_PASSWORD: 'app-password',
      });

      expect(cfg.GMAIL_USERNAME).toBe('sender@gmail.com');
      expect(cfg.GMAIL_PASSWORD).toBe('app-password');
      expect(gmailConfigured).toBe(true);
      expect(smtpConfigured).toBe(false);
      expect(emailConfigured).toBe(true);
      expect(mockWarn).not.toHaveBeenCalledWith(
        expect.stringContaining('Gmail configuration is incomplete'),
      );
    });

    it('emailConfigured tracks the SELECTED provider (gmail set, provider smtp => false)', async () => {
      const { emailConfigured, gmailConfigured } = await loadConfigWithEnv({
        EMAIL_PROVIDER: 'smtp',
        GMAIL_USERNAME: 'sender@gmail.com',
        GMAIL_PASSWORD: 'app-password',
        SMTP_HOST: undefined,
        SMTP_USER: undefined,
        SMTP_PASS: undefined,
      });

      expect(gmailConfigured).toBe(true);
      expect(emailConfigured).toBe(false);
    });

    it('a complete Gmail config in production does NOT emit the not-configured warning', async () => {
      await loadConfigWithEnv({
        ...productionBase,
        EMAIL_PROVIDER: 'gmail',
        GMAIL_USERNAME: 'sender@gmail.com',
        GMAIL_PASSWORD: 'app-password',
      });

      expect(mockWarn).not.toHaveBeenCalledWith(expect.stringContaining('Gmail not configured'));
    });
  });

  describe('Development insecure-transport warning (CORS not HTTPS + remote Mongo)', () => {
    it('warns when CORS is plain HTTP and MONGODB_URI points at a remote host', async () => {
      await loadConfigWithEnv({
        NODE_ENV: 'development',
        CORS_ORIGIN: 'http://localhost:5173',
        MONGODB_URI: 'mongodb://db.remote.example.com:27017/hvault',
      });

      expect(mockWarn).toHaveBeenCalledWith(expect.stringContaining('SECURITY WARNING'));
    });

    it('does not warn when the remote Mongo host is paired with an HTTPS CORS origin', async () => {
      await loadConfigWithEnv({
        NODE_ENV: 'development',
        CORS_ORIGIN: 'https://app.example.com',
        MONGODB_URI: 'mongodb://db.remote.example.com:27017/hvault',
      });

      expect(mockWarn).not.toHaveBeenCalledWith(expect.stringContaining('SECURITY WARNING'));
    });

    it('does not warn for a local Mongo host over plain HTTP (the normal dev setup)', async () => {
      for (const uri of ['mongodb://localhost:27017/hvault', 'mongodb://127.0.0.1:27017/hvault']) {
        mockWarn.mockClear();
        vi.resetModules();
        await loadConfigWithEnv({
          NODE_ENV: 'development',
          CORS_ORIGIN: 'http://localhost:5173',
          MONGODB_URI: uri,
        });
        expect(mockWarn).not.toHaveBeenCalledWith(expect.stringContaining('SECURITY WARNING'));
      }
    });

    it('does not warn in production (the check is development-only)', async () => {
      await loadConfigWithEnv({
        ...productionBase,
        MONGODB_URI: 'mongodb://db.remote.example.com:27017/hvault',
      });

      expect(mockWarn).not.toHaveBeenCalledWith(expect.stringContaining('SECURITY WARNING'));
    });

    it('tolerates an unparseable MONGODB_URI without throwing or warning', async () => {
      const { config: cfg } = await loadConfigWithEnv({
        NODE_ENV: 'development',
        CORS_ORIGIN: 'http://localhost:5173',
        MONGODB_URI: 'not-a-parseable-uri',
      });

      expect(cfg.MONGODB_URI).toBe('not-a-parseable-uri');
      expect(mockWarn).not.toHaveBeenCalledWith(expect.stringContaining('SECURITY WARNING'));
    });
  });
});
