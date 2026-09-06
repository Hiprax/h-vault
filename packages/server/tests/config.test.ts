import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { MAX_DOCUMENT_EXT_LENGTH, publicConfigResponseSchema } from '@hvault/shared';
import { HIBP_MAX_RANGE_RESPONSE_BYTES } from '../src/constants/index.js';

// Must mock dotenv to prevent .env file dependency during dynamic imports
vi.mock('dotenv', () => ({ default: { config: vi.fn() } }));

const mockWarn = vi.fn();
vi.mock('@hiprax/logger', () => ({
  createLogger: () => ({ warn: mockWarn, info: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

describe('Server Config Validation', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    vi.resetModules();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  /**
   * Helper to load config with specific env var overrides.
   * Sets a base valid env so tests only need to override what they care about.
   */
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

    // Remove keys explicitly set to undefined (to test missing env vars)
    for (const [key, value] of Object.entries(process.env)) {
      if (value === undefined) {
        Reflect.deleteProperty(process.env, key);
      }
    }

    const configModule = await import('../src/config/index.js');
    return configModule;
  }

  // ---------------------------------------------------------------------------
  // Default values
  // ---------------------------------------------------------------------------

  describe('Default values', () => {
    it('PORT defaults to 5000', async () => {
      const { config } = await loadConfigWithEnv({ PORT: undefined });
      expect(config.PORT).toBe(5000);
    });

    it('NODE_ENV defaults to development when not set', async () => {
      const { config } = await loadConfigWithEnv({ NODE_ENV: undefined });
      expect(config.NODE_ENV).toBe('development');
    });

    it('MONGODB_URI has correct default', async () => {
      const { config } = await loadConfigWithEnv({ MONGODB_URI: undefined });
      expect(config.MONGODB_URI).toBe('mongodb://localhost:27017/hvault');
    });

    it('JWT_ACCESS_EXPIRY defaults to 5m', async () => {
      const { config } = await loadConfigWithEnv({ JWT_ACCESS_EXPIRY: undefined });
      expect(config.JWT_ACCESS_EXPIRY).toBe('5m');
    });

    it('REFRESH_TOKEN_DAYS defaults to 7 (reproduces the historical horizon)', async () => {
      const { config } = await loadConfigWithEnv({ REFRESH_TOKEN_DAYS: undefined });
      expect(config.REFRESH_TOKEN_DAYS).toBe(7);
    });

    it('REFRESH_TOKEN_REMEMBER_DAYS defaults to 30', async () => {
      const { config } = await loadConfigWithEnv({ REFRESH_TOKEN_REMEMBER_DAYS: undefined });
      expect(config.REFRESH_TOKEN_REMEMBER_DAYS).toBe(30);
    });

    it('TRUSTED_DEVICE_DAYS defaults to 30', async () => {
      const { config } = await loadConfigWithEnv({ TRUSTED_DEVICE_DAYS: undefined });
      expect(config.TRUSTED_DEVICE_DAYS).toBe(30);
    });

    it('the removed JWT_REFRESH_EXPIRY is no longer surfaced on config', async () => {
      const { config } = await loadConfigWithEnv({ JWT_REFRESH_EXPIRY: '30d' });
      expect((config as Record<string, unknown>).JWT_REFRESH_EXPIRY).toBeUndefined();
    });

    it('BCRYPT_ROUNDS defaults to 12', async () => {
      const { config } = await loadConfigWithEnv({ BCRYPT_ROUNDS: undefined });
      expect(config.BCRYPT_ROUNDS).toBe(12);
    });

    // Rate limiting is deliberately NOT env-configurable. `RATE_LIMIT_WINDOW_MS`
    // and `RATE_LIMIT_MAX` used to be declared, defaulted and asserted here while
    // being read by nothing — every limiter carries its own window and ceiling.
    // These two tests replace the four that pinned the dead pair: one proves the
    // keys are gone, the other proves a stale `.env` still carrying them does not
    // break an operator's boot.
    it('exposes no global rate-limit knobs (every limiter carries its own budget)', async () => {
      const { config } = await loadConfigWithEnv({});
      expect(Object.keys(config)).not.toContain('RATE_LIMIT_WINDOW_MS');
      expect(Object.keys(config)).not.toContain('RATE_LIMIT_MAX');
    });

    it('ignores a stale RATE_LIMIT_* pair left in an existing .env', async () => {
      // Values that the removed schema would have REJECTED, so this fails loudly
      // if the keys are ever reintroduced with their old bounds.
      const { config } = await loadConfigWithEnv({
        RATE_LIMIT_WINDOW_MS: '500',
        RATE_LIMIT_MAX: '0',
      });
      expect(config.NODE_ENV).toBe('test');
    });

    it('BACKUP_MAX_SIZE_MB defaults to 25', async () => {
      const { config } = await loadConfigWithEnv({ BACKUP_MAX_SIZE_MB: undefined });
      expect(config.BACKUP_MAX_SIZE_MB).toBe(25);
    });

    it('BACKUP_RETENTION_DAYS defaults to 30', async () => {
      const { config } = await loadConfigWithEnv({ BACKUP_RETENTION_DAYS: undefined });
      expect(config.BACKUP_RETENTION_DAYS).toBe(30);
    });

    it('AUDIT_LOG_RETENTION_DAYS defaults to 365', async () => {
      const { config } = await loadConfigWithEnv({ AUDIT_LOG_RETENTION_DAYS: undefined });
      expect(config.AUDIT_LOG_RETENTION_DAYS).toBe(365);
    });

    it('BREACH_CACHE_TTL_DAYS defaults to 30', async () => {
      const { config } = await loadConfigWithEnv({ BREACH_CACHE_TTL_DAYS: undefined });
      expect(config.BREACH_CACHE_TTL_DAYS).toBe(30);
    });

    it('BREACH_CACHE_TTL_DAYS coerces a provided value', async () => {
      const { config } = await loadConfigWithEnv({ BREACH_CACHE_TTL_DAYS: '7' });
      expect(config.BREACH_CACHE_TTL_DAYS).toBe(7);
    });

    it('HIBP_CACHE_MAX_BYTES defaults to 64 MiB', async () => {
      const { config } = await loadConfigWithEnv({ HIBP_CACHE_MAX_BYTES: undefined });
      expect(config.HIBP_CACHE_MAX_BYTES).toBe(67_108_864);
    });

    it('HIBP_CACHE_MAX_BYTES coerces a provided value', async () => {
      const { config } = await loadConfigWithEnv({ HIBP_CACHE_MAX_BYTES: '2097152' });
      expect(config.HIBP_CACHE_MAX_BYTES).toBe(2_097_152);
    });

    it('BREACH_SEED_AUTO defaults to false', async () => {
      const { config } = await loadConfigWithEnv({ BREACH_SEED_AUTO: undefined });
      expect(config.BREACH_SEED_AUTO).toBe(false);
    });

    it('BREACH_SEED_AUTO parses "true"', async () => {
      const { config } = await loadConfigWithEnv({ BREACH_SEED_AUTO: 'true' });
      expect(config.BREACH_SEED_AUTO).toBe(true);
    });

    it('BREACH_SEED_REFRESH_CRON is undefined when empty', async () => {
      const { config } = await loadConfigWithEnv({ BREACH_SEED_REFRESH_CRON: '' });
      expect(config.BREACH_SEED_REFRESH_CRON).toBeUndefined();
    });

    it('BREACH_SEED_REFRESH_CRON is preserved when set', async () => {
      const { config } = await loadConfigWithEnv({ BREACH_SEED_REFRESH_CRON: '0 3 * * 0' });
      expect(config.BREACH_SEED_REFRESH_CRON).toBe('0 3 * * 0');
    });

    it('FILE_ENCRYPTION_MAX_SIZE_MB defaults to 100', async () => {
      const { config } = await loadConfigWithEnv({ FILE_ENCRYPTION_MAX_SIZE_MB: undefined });
      expect(config.FILE_ENCRYPTION_MAX_SIZE_MB).toBe(100);
    });

    it('MONGO_MAX_POOL_SIZE defaults to 10', async () => {
      const { config } = await loadConfigWithEnv({ MONGO_MAX_POOL_SIZE: undefined });
      expect(config.MONGO_MAX_POOL_SIZE).toBe(10);
    });

    it('MONGO_MIN_POOL_SIZE defaults to 2', async () => {
      const { config } = await loadConfigWithEnv({ MONGO_MIN_POOL_SIZE: undefined });
      expect(config.MONGO_MIN_POOL_SIZE).toBe(2);
    });

    it('SMTP_PORT defaults to 587', async () => {
      const { config } = await loadConfigWithEnv({ SMTP_PORT: undefined });
      expect(config.SMTP_PORT).toBe(587);
    });

    it('APP_NAME defaults to H-Vault', async () => {
      const { config } = await loadConfigWithEnv({ APP_NAME: undefined });
      expect(config.APP_NAME).toBe('H-Vault');
    });
  });

  // ---------------------------------------------------------------------------
  // Production mode rejects dev- prefixed secrets
  // ---------------------------------------------------------------------------

  describe('Non-development mode rejects dev- prefixed secrets', () => {
    const productionBase = {
      NODE_ENV: 'production',
      JWT_ACCESS_SECRET: 'prod-access-secret-very-secure-and-long-enough!!',
      JWT_REFRESH_SECRET: 'prod-refresh-secret-very-secure-and-long-enough!!',
      SESSION_SECRET: 'ProdSessionSecretVerySecure!!1234',
      CORS_ORIGIN: 'https://hvault.example.com',
      // Provide SMTP to avoid the warning (or leave empty - both valid)
    };

    it('JWT_ACCESS_SECRET starting with dev- in production throws', async () => {
      await expect(
        loadConfigWithEnv({
          ...productionBase,
          JWT_ACCESS_SECRET: 'dev-access-secret-change-me-in-production-32chars',
        }),
      ).rejects.toThrow(
        'JWT_ACCESS_SECRET must be set to a secure value in non-development environments',
      );
    });

    it('JWT_REFRESH_SECRET starting with dev- in production throws', async () => {
      await expect(
        loadConfigWithEnv({
          ...productionBase,
          JWT_REFRESH_SECRET: 'dev-refresh-secret-change-me-in-production-32chars',
        }),
      ).rejects.toThrow(
        'JWT_REFRESH_SECRET must be set to a secure value in non-development environments',
      );
    });

    it('SESSION_SECRET starting with dev- in production throws', async () => {
      await expect(
        loadConfigWithEnv({
          ...productionBase,
          SESSION_SECRET: 'dev-session-secret-change-me-32ch',
        }),
      ).rejects.toThrow(
        'SESSION_SECRET must be set to a secure value in non-development environments',
      );
    });

    it('dev- prefixed secrets in test mode also throws', async () => {
      await expect(
        loadConfigWithEnv({
          NODE_ENV: 'test',
          JWT_ACCESS_SECRET: 'dev-access-secret-change-me-in-production-32chars',
          JWT_REFRESH_SECRET: 'test-refresh-secret-for-testing-only-32chars!',
          SESSION_SECRET: 'TestSessionSecret4Testing!!12345',
        }),
      ).rejects.toThrow(
        'JWT_ACCESS_SECRET must be set to a secure value in non-development environments',
      );
    });

    it('mixed-case DEV- prefix on JWT_ACCESS_SECRET in production throws', async () => {
      await expect(
        loadConfigWithEnv({
          ...productionBase,
          JWT_ACCESS_SECRET: 'DEV-access-secret-change-me-in-production-32chars',
        }),
      ).rejects.toThrow(
        'JWT_ACCESS_SECRET must be set to a secure value in non-development environments',
      );
    });

    it('mixed-case Dev- prefix on JWT_REFRESH_SECRET in production throws', async () => {
      await expect(
        loadConfigWithEnv({
          ...productionBase,
          JWT_REFRESH_SECRET: 'Dev-refresh-secret-change-me-in-production-32chars',
        }),
      ).rejects.toThrow(
        'JWT_REFRESH_SECRET must be set to a secure value in non-development environments',
      );
    });

    it('mixed-case DEv- prefix on SESSION_SECRET in production throws', async () => {
      await expect(
        loadConfigWithEnv({
          ...productionBase,
          SESSION_SECRET: 'DEv-session-secret-change-me-32ch',
        }),
      ).rejects.toThrow(
        'SESSION_SECRET must be set to a secure value in non-development environments',
      );
    });

    it('non-dev- prefixed secrets in production are accepted', async () => {
      const { config } = await loadConfigWithEnv(productionBase);
      expect(config.NODE_ENV).toBe('production');
      expect(config.JWT_ACCESS_SECRET).toBe(productionBase.JWT_ACCESS_SECRET);
      expect(config.JWT_REFRESH_SECRET).toBe(productionBase.JWT_REFRESH_SECRET);
      expect(config.SESSION_SECRET).toBe(productionBase.SESSION_SECRET);
    });

    it('dev- prefixed secrets in development mode are accepted', async () => {
      const { config } = await loadConfigWithEnv({
        NODE_ENV: 'development',
        JWT_ACCESS_SECRET: 'dev-access-secret-change-me-in-production-32chars',
        JWT_REFRESH_SECRET: 'dev-refresh-secret-change-me-in-production-32chars',
        SESSION_SECRET: 'dev-session-secret-change-me-32ch',
      });
      expect(config.NODE_ENV).toBe('development');
    });
  });

  // ---------------------------------------------------------------------------
  // CORS validation
  // ---------------------------------------------------------------------------

  describe('CORS validation', () => {
    it('CORS_ORIGIN with HTTP in production is rejected', async () => {
      // The refine checks process.env.NODE_ENV, so we need it set to production
      await expect(
        loadConfigWithEnv({
          NODE_ENV: 'production',
          JWT_ACCESS_SECRET: 'prod-access-secret-very-secure-and-long-enough!!',
          JWT_REFRESH_SECRET: 'prod-refresh-secret-very-secure-and-long-enough!!',
          SESSION_SECRET: 'ProdSessionSecretVerySecure!!1234',
          CORS_ORIGIN: 'http://insecure.example.com',
        }),
      ).rejects.toThrow(/CORS_ORIGIN must use HTTPS in production/);
    });

    it('CORS_ORIGIN with HTTPS in production is accepted', async () => {
      const { config } = await loadConfigWithEnv({
        NODE_ENV: 'production',
        JWT_ACCESS_SECRET: 'prod-access-secret-very-secure-and-long-enough!!',
        JWT_REFRESH_SECRET: 'prod-refresh-secret-very-secure-and-long-enough!!',
        SESSION_SECRET: 'ProdSessionSecretVerySecure!!1234',
        CORS_ORIGIN: 'https://hvault.example.com',
      });
      expect(config.CORS_ORIGIN).toBe('https://hvault.example.com');
    });

    it('CORS_ORIGIN with HTTP in development is accepted', async () => {
      const { config } = await loadConfigWithEnv({
        NODE_ENV: 'development',
        CORS_ORIGIN: 'http://localhost:5173',
      });
      expect(config.CORS_ORIGIN).toBe('http://localhost:5173');
    });
  });

  // ---------------------------------------------------------------------------
  // SMTP validation
  // ---------------------------------------------------------------------------

  describe('SMTP validation', () => {
    it('partial SMTP config in production throws', async () => {
      await expect(
        loadConfigWithEnv({
          NODE_ENV: 'production',
          JWT_ACCESS_SECRET: 'prod-access-secret-very-secure-and-long-enough!!',
          JWT_REFRESH_SECRET: 'prod-refresh-secret-very-secure-and-long-enough!!',
          SESSION_SECRET: 'ProdSessionSecretVerySecure!!1234',
          CORS_ORIGIN: 'https://hvault.example.com',
          SMTP_HOST: 'smtp.example.com',
          SMTP_USER: undefined,
          SMTP_PASS: undefined,
        }),
      ).rejects.toThrow('SMTP configuration is incomplete');
    });

    it('partial SMTP config in non-production warns and normalises to unconfigured', async () => {
      mockWarn.mockClear();
      const { config, smtpConfigured } = await loadConfigWithEnv({
        SMTP_HOST: 'smtp.example.com',
        SMTP_USER: 'user@example.com',
        SMTP_PASS: undefined,
      });
      expect(mockWarn).toHaveBeenCalledWith(
        expect.stringContaining('SMTP configuration is incomplete'),
      );
      expect(config.SMTP_HOST).toBeUndefined();
      expect(config.SMTP_USER).toBeUndefined();
      expect(config.SMTP_PASS).toBeUndefined();
      expect(smtpConfigured).toBe(false);
    });

    it('all SMTP fields set is accepted', async () => {
      const { config } = await loadConfigWithEnv({
        SMTP_HOST: 'smtp.example.com',
        SMTP_USER: 'user@example.com',
        SMTP_PASS: 'password123',
      });
      expect(config.SMTP_HOST).toBe('smtp.example.com');
      expect(config.SMTP_USER).toBe('user@example.com');
      expect(config.SMTP_PASS).toBe('password123');
    });

    it('no SMTP fields set is accepted', async () => {
      const { config } = await loadConfigWithEnv({
        SMTP_HOST: undefined,
        SMTP_USER: undefined,
        SMTP_PASS: undefined,
      });
      expect(config.SMTP_HOST).toBeUndefined();
      expect(config.SMTP_USER).toBeUndefined();
      expect(config.SMTP_PASS).toBeUndefined();
    });

    it('smtpConfigured is true when all 3 SMTP fields are set', async () => {
      const { smtpConfigured } = await loadConfigWithEnv({
        SMTP_HOST: 'smtp.example.com',
        SMTP_USER: 'user@example.com',
        SMTP_PASS: 'password123',
      });
      expect(smtpConfigured).toBe(true);
    });

    it('smtpConfigured is false when SMTP fields are missing', async () => {
      const { smtpConfigured } = await loadConfigWithEnv({
        SMTP_HOST: undefined,
        SMTP_USER: undefined,
        SMTP_PASS: undefined,
      });
      expect(smtpConfigured).toBe(false);
    });

    it('production with no SMTP logs a warning', async () => {
      mockWarn.mockClear();
      await loadConfigWithEnv({
        NODE_ENV: 'production',
        JWT_ACCESS_SECRET: 'prod-access-secret-very-secure-and-long-enough!!',
        JWT_REFRESH_SECRET: 'prod-refresh-secret-very-secure-and-long-enough!!',
        SESSION_SECRET: 'ProdSessionSecretVerySecure!!1234',
        CORS_ORIGIN: 'https://hvault.example.com',
        SMTP_HOST: undefined,
        SMTP_USER: undefined,
        SMTP_PASS: undefined,
      });
      expect(mockWarn).toHaveBeenCalledWith(expect.stringContaining('SMTP not configured'));
    });

    it('empty string SMTP fields are normalised to undefined', async () => {
      const { config } = await loadConfigWithEnv({
        SMTP_HOST: '',
        SMTP_USER: '',
        SMTP_PASS: '',
      });
      expect(config.SMTP_HOST).toBeUndefined();
      expect(config.SMTP_USER).toBeUndefined();
      expect(config.SMTP_PASS).toBeUndefined();
    });

    it('smtpConfigured is false when SMTP fields are empty strings', async () => {
      const { smtpConfigured } = await loadConfigWithEnv({
        SMTP_HOST: '',
        SMTP_USER: '',
        SMTP_PASS: '',
      });
      expect(smtpConfigured).toBe(false);
    });

    it('emailConfigured is false when SMTP fields are empty strings', async () => {
      const { emailConfigured } = await loadConfigWithEnv({
        EMAIL_PROVIDER: 'smtp',
        SMTP_HOST: '',
        SMTP_USER: '',
        SMTP_PASS: '',
      });
      expect(emailConfigured).toBe(false);
    });

    it('empty string SMTP_FROM is normalised to undefined', async () => {
      const { config } = await loadConfigWithEnv({
        SMTP_FROM: '',
      });
      expect(config.SMTP_FROM).toBeUndefined();
    });

    it('empty string Gmail fields are normalised to undefined', async () => {
      const { config } = await loadConfigWithEnv({
        EMAIL_PROVIDER: 'gmail',
        GMAIL_USERNAME: '',
        GMAIL_PASSWORD: '',
      });
      expect(config.GMAIL_USERNAME).toBeUndefined();
      expect(config.GMAIL_PASSWORD).toBeUndefined();
    });

    it('emailConfigured is false when Gmail fields are empty strings', async () => {
      const { emailConfigured } = await loadConfigWithEnv({
        EMAIL_PROVIDER: 'gmail',
        GMAIL_USERNAME: '',
        GMAIL_PASSWORD: '',
      });
      expect(emailConfigured).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // APP_URL transformation
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // Object storage / document store
  //
  // The four connection variables are all-or-none, exactly like SMTP, because the
  // document store is optional: unconfigured means OFF, and a PARTIAL
  // configuration is the dangerous state, since it looks configured to everything
  // downstream and fails at the first storage call. The endpoint rule and the
  // access-key minimum are both MEASURED behaviours of the storage engine rather
  // than preferences, so the assertions below are what keeps them from being
  // "simplified" later.
  // ---------------------------------------------------------------------------

  describe('Object storage configuration', () => {
    // All four connection variables, valid, for tests that need the feature ON.
    const storageEnv = {
      S3_ENDPOINT: 'http://hvault-s3:3900',
      S3_BUCKET: 'hvault-documents',
      S3_ACCESS_KEY_ID: 'GKtestaccesskeyidnotreal01',
      S3_SECRET_ACCESS_KEY: 'test-secret-access-key-not-a-real-credential',
    };
    // A production base that passes every OTHER production rule, so a failure here
    // is always about storage.
    const productionEnv = {
      NODE_ENV: 'production',
      JWT_ACCESS_SECRET: 'prod-access-secret-very-secure-and-long-enough!!',
      JWT_REFRESH_SECRET: 'prod-refresh-secret-very-secure-and-long-enough!!',
      SESSION_SECRET: 'ProdSessionSecretVerySecure!!1234',
      CORS_ORIGIN: 'https://hvault.example.com',
    };
    const connectionKeys = [
      'S3_ENDPOINT',
      'S3_BUCKET',
      'S3_ACCESS_KEY_ID',
      'S3_SECRET_ACCESS_KEY',
    ] as const;

    it('leaves the document store off when nothing is configured', async () => {
      const { config, storageConfigured } = await loadConfigWithEnv({});
      expect(storageConfigured).toBe(false);
      expect(config.S3_ENDPOINT).toBeUndefined();
      expect(config.S3_BUCKET).toBeUndefined();
      expect(config.S3_ACCESS_KEY_ID).toBeUndefined();
      expect(config.S3_SECRET_ACCESS_KEY).toBeUndefined();
    });

    it('does not warn about unconfigured storage, unlike unconfigured email', async () => {
      // Email is effectively required, documents are not. A warning on every boot
      // of a deployment that does not want them trains an operator to ignore the
      // log, so the absence of this line is deliberate and asserted.
      mockWarn.mockClear();
      await loadConfigWithEnv(productionEnv);
      expect(mockWarn).not.toHaveBeenCalledWith(expect.stringContaining('Object storage'));
      expect(mockWarn).toHaveBeenCalledWith(expect.stringContaining('SMTP not configured'));
    });

    it('enables the store when all four connection variables are set', async () => {
      const { config, storageConfigured } = await loadConfigWithEnv(storageEnv);
      expect(storageConfigured).toBe(true);
      expect(config.S3_ENDPOINT).toBe(storageEnv.S3_ENDPOINT);
      expect(config.S3_BUCKET).toBe(storageEnv.S3_BUCKET);
      expect(config.S3_ACCESS_KEY_ID).toBe(storageEnv.S3_ACCESS_KEY_ID);
      expect(config.S3_SECRET_ACCESS_KEY).toBe(storageEnv.S3_SECRET_ACCESS_KEY);
    });

    it('enables the store in production too, with an in-stack endpoint', async () => {
      const { config, storageConfigured } = await loadConfigWithEnv({
        ...productionEnv,
        ...storageEnv,
      });
      expect(storageConfigured).toBe(true);
      expect(config.S3_ENDPOINT).toBe('http://hvault-s3:3900');
    });

    it.each(connectionKeys)(
      'a partial configuration missing %s throws in production',
      async (missing) => {
        await expect(
          loadConfigWithEnv({ ...productionEnv, ...storageEnv, [missing]: undefined }),
        ).rejects.toThrow('Object storage configuration is incomplete');
      },
    );

    it.each(connectionKeys)(
      'a partial configuration missing %s warns and disables the store in development',
      async (missing) => {
        mockWarn.mockClear();
        const { config, storageConfigured } = await loadConfigWithEnv({
          NODE_ENV: 'development',
          ...storageEnv,
          [missing]: undefined,
        });
        expect(mockWarn).toHaveBeenCalledWith(
          expect.stringContaining('Object storage configuration is incomplete'),
        );
        // The negative that matters: a partial configuration must not HALF-enable
        // the feature. Every field is normalised away, not just the missing one,
        // so nothing downstream can build a client from what survived.
        expect(storageConfigured).toBe(false);
        expect(config.S3_ENDPOINT).toBeUndefined();
        expect(config.S3_BUCKET).toBeUndefined();
        expect(config.S3_ACCESS_KEY_ID).toBeUndefined();
        expect(config.S3_SECRET_ACCESS_KEY).toBeUndefined();
      },
    );

    it('treats an empty assignment as unset rather than as a too-short value', async () => {
      // `.env.example` ships the two credentials empty, so `S3_ACCESS_KEY_ID=` must
      // read as "unset" and not fail `.min(8)` and abort boot. The normalisation has
      // to run BEFORE the length check, which is why these use `z.preprocess`.
      const { config, storageConfigured } = await loadConfigWithEnv({
        S3_ENDPOINT: '',
        S3_BUCKET: '',
        S3_ACCESS_KEY_ID: '',
        S3_SECRET_ACCESS_KEY: '',
      });
      expect(storageConfigured).toBe(false);
      expect(config.S3_ACCESS_KEY_ID).toBeUndefined();
      expect(config.S3_SECRET_ACCESS_KEY).toBeUndefined();
    });

    // Each of these loads the config ONCE: the module is only reset between tests,
    // so a second `loadConfigWithEnv` inside one test would return the first
    // instance from the module cache and assert nothing.
    it('accepts an access key id of exactly 8 characters', async () => {
      const { config } = await loadConfigWithEnv({
        ...storageEnv,
        S3_ACCESS_KEY_ID: 'a'.repeat(8),
      });
      expect(config.S3_ACCESS_KEY_ID).toBe('a'.repeat(8));
    });

    it('rejects an access key id of 7 characters, one below the measured minimum', async () => {
      // MEASURED against the storage engine: it refuses to boot with an access key
      // id shorter than 8, with a message no operator would trace back to `.env`.
      await expect(
        loadConfigWithEnv({ ...storageEnv, S3_ACCESS_KEY_ID: 'a'.repeat(7) }),
      ).rejects.toThrow('S3_ACCESS_KEY_ID');
    });

    it('accepts a secret access key of exactly 16 characters', async () => {
      const { config } = await loadConfigWithEnv({
        ...storageEnv,
        S3_SECRET_ACCESS_KEY: 'b'.repeat(16),
      });
      expect(config.S3_SECRET_ACCESS_KEY).toBe('b'.repeat(16));
    });

    it('rejects a secret access key of 15 characters', async () => {
      await expect(
        loadConfigWithEnv({ ...storageEnv, S3_SECRET_ACCESS_KEY: 'b'.repeat(15) }),
      ).rejects.toThrow('S3_SECRET_ACCESS_KEY');
    });

    it.each([
      ['unset', undefined, 'us-east-1'],
      ['an empty assignment', '', 'us-east-1'],
      ['an explicit value', 'garage', 'garage'],
    ])('S3_REGION with %s resolves to %s', async (_label, value, expected) => {
      const { config } = await loadConfigWithEnv({ S3_REGION: value });
      expect(config.S3_REGION).toBe(expected);
    });

    it.each([
      [undefined, true],
      ['', true],
      ['true', true],
      ['false', false],
    ])(
      'S3_FORCE_PATH_STYLE=%s resolves to %s (it defaults ON, unlike the other flags)',
      async (value, expected) => {
        // Virtual-host addressing puts the bucket in the hostname, which needs DNS
        // the in-stack service does not have, so ONLY the explicit string `false`
        // turns path style off.
        const { config } = await loadConfigWithEnv({ S3_FORCE_PATH_STYLE: value });
        expect(config.S3_FORCE_PATH_STYLE).toBe(expected);
      },
    );

    it('refuses an S3_FORCE_PATH_STYLE value that is neither true nor false', async () => {
      // The enum is the validation: `1` is not a synonym for `true` here, and
      // silently reading it as one would flip addressing modes on a typo.
      await expect(loadConfigWithEnv({ S3_FORCE_PATH_STYLE: '1' })).rejects.toThrow(
        'S3_FORCE_PATH_STYLE',
      );
    });

    // -------------------------------------------------------------------------
    // The production endpoint rule
    // -------------------------------------------------------------------------

    it.each([
      ['an in-stack service name', 'http://hvault-s3:3900'],
      // Not a legal DNS label, but a legal Compose service name that the engine's
      // own DNS resolves, and the refusal message promises a single-label host.
      ['an in-stack service name with an underscore', 'http://hvault_s3:3900'],
      ['localhost', 'http://localhost:3900'],
      ['IPv4 loopback', 'http://127.0.0.1:3900'],
      ['IPv6 loopback', 'http://[::1]:3900'],
      ['RFC 1918 10/8', 'http://10.1.2.3:3900'],
      ['RFC 1918 192.168/16', 'http://192.168.1.9:3900'],
      ['RFC 1918 172.16/12, low edge', 'http://172.16.0.5:3900'],
      ['RFC 1918 172.16/12, high edge', 'http://172.31.255.254:3900'],
      ['a public name over HTTPS', 'https://storage.example.com'],
      // The URL parser normalises a numeric host to its dotted quad, so these ARE
      // loopback and 192.168/16 respectively by the time the rule sees them. Pinned
      // so the normalisation is a known property rather than a lucky one.
      ['a decimal IPv4 loopback', 'http://2130706433'],
      ['a hexadecimal IPv4 loopback', 'http://0x7f000001'],
      ['an octal octet inside RFC 1918', 'http://172.031.0.1:3900'],
    ])('accepts %s as an S3_ENDPOINT in production', async (_label, endpoint) => {
      const { config } = await loadConfigWithEnv({
        ...productionEnv,
        ...storageEnv,
        S3_ENDPOINT: endpoint,
      });
      expect(config.S3_ENDPOINT).toBe(endpoint);
    });

    it.each([
      ['a public name', 'http://storage.example.com'],
      ['a public name with a port', 'http://storage.example.com:9000'],
      ['a hosted S3 endpoint', 'http://s3.amazonaws.com'],
      // Both sides of every range, because a one-sided table lets the comparison be
      // widened without a single test noticing. Deleting `octet >= 16` from the
      // 172.16/12 check would otherwise accept 172.0.0.1, which is public space, on
      // plain HTTP in production.
      ['172.32/16, just above RFC 1918', 'http://172.32.0.1:3900'],
      ['172.15/16, just below RFC 1918', 'http://172.15.255.254:3900'],
      ['172.0/8, public space below the window', 'http://172.0.0.1:3900'],
      ['192.169/16, just outside RFC 1918', 'http://192.169.1.1:3900'],
      ['192.167/16, just below it', 'http://192.167.1.1:3900'],
      ['11/8, which is public space', 'http://11.0.0.1:3900'],
      ['128/8, one past the loopback block', 'http://128.0.0.1:3900'],
      ['126/8, one before it', 'http://126.0.0.1:3900'],
      ['a label that is not a legal DNS label', 'http://hvault-s3-:3900'],
      // Everything below is a host that could be mistaken for a private one. Each
      // must fail CLOSED, which is what makes the rule worth having: `.hostname`
      // discards the userinfo, so a credential-looking prefix cannot smuggle a
      // public host past it, and an address family the rule does not model is
      // refused rather than assumed to be local.
      ['userinfo that only looks like a private host', 'http://hvault-s3@evil.example.com'],
      ['a fully qualified name with a trailing dot', 'http://storage.example.com.'],
      ['an IPv4-mapped IPv6 loopback, which the rule does not model', 'http://[::ffff:127.0.0.1]'],
      ['an IPv6 unique-local address, which the rule does not model', 'http://[fc00::1]'],
      ['the unspecified address', 'http://0.0.0.0:3900'],
    ])('rejects %s as a plain-HTTP S3_ENDPOINT in production', async (_label, endpoint) => {
      await expect(
        loadConfigWithEnv({ ...productionEnv, ...storageEnv, S3_ENDPOINT: endpoint }),
      ).rejects.toThrow('S3_ENDPOINT must use https:// in production');
    });

    it('applies the endpoint rule only in production', async () => {
      // A developer pointing at a remote bucket over plain HTTP is their own call;
      // the rule exists to stop a PRODUCTION deployment shipping credentials in the
      // clear.
      const { config, storageConfigured } = await loadConfigWithEnv({
        ...storageEnv,
        S3_ENDPOINT: 'http://storage.example.com',
      });
      expect(config.S3_ENDPOINT).toBe('http://storage.example.com');
      expect(storageConfigured).toBe(true);
    });

    it('rejects an S3_ENDPOINT with a scheme that is neither http nor https', async () => {
      await expect(
        loadConfigWithEnv({ ...storageEnv, S3_ENDPOINT: 'ftp://storage.example.com/' }),
      ).rejects.toThrow('S3_ENDPOINT must use http:// or https://');
    });

    it('reports an unparseable S3_ENDPOINT once, as a URL error, not as a scheme rule', async () => {
      // The production rule ABSTAINS on a value the field check has already
      // rejected: a second issue about https would only obscure the first. Both
      // halves are asserted, because the abstain branch is invisible otherwise.
      const attempt = loadConfigWithEnv({
        ...productionEnv,
        ...storageEnv,
        S3_ENDPOINT: 'not-a-url',
      });
      await expect(attempt).rejects.toThrow('S3_ENDPOINT');
      await expect(attempt).rejects.not.toThrow('S3_ENDPOINT must use https:// in production');
    });

    // -------------------------------------------------------------------------
    // The document-store knobs
    // -------------------------------------------------------------------------

    it('defaults the document-store knobs', async () => {
      const { config } = await loadConfigWithEnv({});
      expect(config.MAX_DOCUMENT_SIZE_MB).toBe(100);
      expect(config.DOCUMENT_STORAGE_QUOTA_MB_PER_USER).toBe(2048);
      expect(config.DOCUMENT_UPLOAD_TTL_HOURS).toBe(24);
      expect(config.DOCUMENT_ALLOWED_EXTENSIONS).toEqual([]);
    });

    it.each([
      ['MAX_DOCUMENT_SIZE_MB', '1', 1],
      ['MAX_DOCUMENT_SIZE_MB', '1024', 1024],
      ['DOCUMENT_UPLOAD_TTL_HOURS', '1', 1],
      ['DOCUMENT_UPLOAD_TTL_HOURS', '168', 168],
      ['DOCUMENT_STORAGE_QUOTA_MB_PER_USER', '1048576', 1_048_576],
    ])('%s accepts its boundary value %s', async (key, value, expected) => {
      const { config } = await loadConfigWithEnv({ [key]: value });
      expect(config[key as 'MAX_DOCUMENT_SIZE_MB']).toBe(expected);
    });

    it.each([
      ['MAX_DOCUMENT_SIZE_MB', '0'],
      ['MAX_DOCUMENT_SIZE_MB', '1025'],
      ['MAX_DOCUMENT_SIZE_MB', '1.5'],
      ['DOCUMENT_UPLOAD_TTL_HOURS', '0'],
      ['DOCUMENT_UPLOAD_TTL_HOURS', '169'],
      ['DOCUMENT_UPLOAD_TTL_HOURS', '2.5'],
      ['DOCUMENT_STORAGE_QUOTA_MB_PER_USER', '0'],
      ['DOCUMENT_STORAGE_QUOTA_MB_PER_USER', '1048577'],
      ['DOCUMENT_STORAGE_QUOTA_MB_PER_USER', '2048.5'],
    ])('%s rejects %s, which is past its bound or not a whole number', async (key, value) => {
      await expect(loadConfigWithEnv({ [key]: value })).rejects.toThrow(key);
    });

    it('accepts the smallest quota that still covers the size cap', async () => {
      const { config } = await loadConfigWithEnv({
        MAX_DOCUMENT_SIZE_MB: '1',
        DOCUMENT_STORAGE_QUOTA_MB_PER_USER: '1',
      });
      expect(config.MAX_DOCUMENT_SIZE_MB).toBe(1);
      expect(config.DOCUMENT_STORAGE_QUOTA_MB_PER_USER).toBe(1);
    });

    it('refuses a size cap larger than the per-user quota', async () => {
      // Otherwise every upload of a legal size is accepted at the door and refused
      // at the quota check, for every user, forever.
      await expect(
        loadConfigWithEnv({
          MAX_DOCUMENT_SIZE_MB: '200',
          DOCUMENT_STORAGE_QUOTA_MB_PER_USER: '100',
        }),
      ).rejects.toThrow(
        'DOCUMENT_STORAGE_QUOTA_MB_PER_USER cannot be less than MAX_DOCUMENT_SIZE_MB',
      );
    });

    it('accepts a quota exactly equal to the size cap', async () => {
      const { config } = await loadConfigWithEnv({
        MAX_DOCUMENT_SIZE_MB: '100',
        DOCUMENT_STORAGE_QUOTA_MB_PER_USER: '100',
      });
      expect(config.DOCUMENT_STORAGE_QUOTA_MB_PER_USER).toBe(100);
    });

    it.each([
      ['an empty value', '', []],
      ['one extension', 'pdf', ['pdf']],
      ['leading dots, case and padding', ' .PDF , Md ', ['pdf', 'md']],
      ['duplicates, however written', 'pdf,.pdf,PDF', ['pdf']],
      ['stray separators', ',,pdf,,md,', ['pdf', 'md']],
    ])('normalises DOCUMENT_ALLOWED_EXTENSIONS with %s', async (_label, value, expected) => {
      // The client compares a filename's last segment against this list, so the
      // operator's punctuation is normalised ONCE here rather than in every reader.
      // Cleared first: `mockWarn` is module-scoped and the suite runs shuffled, so
      // a later test's warning would otherwise decide this one.
      mockWarn.mockClear();
      const { config } = await loadConfigWithEnv({ DOCUMENT_ALLOWED_EXTENSIONS: value });
      expect(config.DOCUMENT_ALLOWED_EXTENSIONS).toEqual(expected);
      // Normalisation alone is silent: nothing was thrown away that a client could
      // have matched, so there is nothing for an operator to act on.
      expect(mockWarn).not.toHaveBeenCalledWith(
        expect.stringContaining('DOCUMENT_ALLOWED_EXTENSIONS'),
      );
    });

    it('keeps an extension of exactly the metadata bound and drops the one past it', async () => {
      // The bound is the one `MAX_DOCUMENT_EXT_LENGTH` puts on the `ext` field
      // inside the sealed metadata blob, so an entry longer than it could never
      // match a document anyway. n and n+1, because an off-by-one here is a
      // silently narrowed allowlist in one direction and an unparseable `/config`
      // in the other.
      const atBound = 'a'.repeat(MAX_DOCUMENT_EXT_LENGTH);
      const pastBound = 'b'.repeat(MAX_DOCUMENT_EXT_LENGTH + 1);
      mockWarn.mockClear();
      const { config } = await loadConfigWithEnv({
        DOCUMENT_ALLOWED_EXTENSIONS: `pdf, ${atBound}, ${pastBound}, md`,
      });
      expect(config.DOCUMENT_ALLOWED_EXTENSIONS).toEqual(['pdf', atBound, 'md']);
      expect(config.DOCUMENT_ALLOWED_EXTENSIONS).not.toContain(pastBound);
      // Dropped LOUDLY: an operator who mistyped this has to be able to find out.
      expect(mockWarn).toHaveBeenCalledWith(expect.stringContaining('DOCUMENT_ALLOWED_EXTENSIONS'));
    });

    it('keeps GET /config parseable by the client when an entry is over-long', async () => {
      // The reason the filter above exists, stated as the behaviour it protects.
      // `publicConfigDataSchema` bounds EVERY entry, so one over-long extension
      // fails the parse of the WHOLE envelope — and `getFileEncryptionMaxBytes()`
      // answers a failed parse by silently falling back to its shared-constant
      // default. A typo in a DOCUMENTS variable would then change the File
      // Encryption tool's size cap, in a feature that has nothing to do with
      // documents.
      const { config } = await loadConfigWithEnv({
        FILE_ENCRYPTION_MAX_SIZE_MB: '7',
        DOCUMENT_ALLOWED_EXTENSIONS: `pdf,${'c'.repeat(MAX_DOCUMENT_EXT_LENGTH + 40)}`,
        ...storageEnv,
      });

      const envelope = {
        success: true as const,
        data: {
          fileEncryption: { maxSizeMB: config.FILE_ENCRYPTION_MAX_SIZE_MB },
          documents: {
            enabled: true,
            maxSizeMB: config.MAX_DOCUMENT_SIZE_MB,
            allowedExtensions: config.DOCUMENT_ALLOWED_EXTENSIONS,
          },
        },
      };

      const parsed = publicConfigResponseSchema.safeParse(envelope);
      expect(parsed.success).toBe(true);
      expect(parsed.success && parsed.data.data.fileEncryption.maxSizeMB).toBe(7);
      expect(parsed.success && parsed.data.data.documents?.allowedExtensions).toEqual(['pdf']);
    });
  });

  describe('APP_URL transformation', () => {
    it('trailing slashes are stripped from APP_URL', async () => {
      const { config } = await loadConfigWithEnv({
        APP_URL: 'http://localhost:5000/',
      });
      expect(config.APP_URL).toBe('http://localhost:5000');
    });

    it('multiple trailing slashes are stripped from APP_URL', async () => {
      const { config } = await loadConfigWithEnv({
        APP_URL: 'http://localhost:5000///',
      });
      expect(config.APP_URL).toBe('http://localhost:5000');
    });

    it('APP_URL without trailing slash is unchanged', async () => {
      const { config } = await loadConfigWithEnv({
        APP_URL: 'http://localhost:5000',
      });
      expect(config.APP_URL).toBe('http://localhost:5000');
    });

    it('APP_URL with https scheme is accepted', async () => {
      const { config } = await loadConfigWithEnv({
        APP_URL: 'https://hvault.example.com',
      });
      expect(config.APP_URL).toBe('https://hvault.example.com');
    });

    it('APP_URL with javascript: scheme is rejected', async () => {
      await expect(loadConfigWithEnv({ APP_URL: 'javascript:alert(1)//ex.com' })).rejects.toThrow(
        /APP_URL must use http:\/\/ or https:\/\//,
      );
    });

    it('APP_URL with file:// scheme is rejected', async () => {
      await expect(loadConfigWithEnv({ APP_URL: 'file:///etc/passwd' })).rejects.toThrow(
        /APP_URL must use http:\/\/ or https:\/\//,
      );
    });

    it('APP_URL with data: scheme is rejected', async () => {
      await expect(
        loadConfigWithEnv({ APP_URL: 'data:text/html,<script>alert(1)</script>' }),
      ).rejects.toThrow(/APP_URL must use http:\/\/ or https:\/\//);
    });

    it('APP_URL with ftp:// scheme is rejected', async () => {
      await expect(loadConfigWithEnv({ APP_URL: 'ftp://example.com/' })).rejects.toThrow(
        /APP_URL must use http:\/\/ or https:\/\//,
      );
    });

    it('APP_URL with chrome-extension: scheme is rejected', async () => {
      await expect(
        loadConfigWithEnv({ APP_URL: 'chrome-extension://abc/index.html' }),
      ).rejects.toThrow(/APP_URL must use http:\/\/ or https:\/\//);
    });
  });

  // ---------------------------------------------------------------------------
  // Exported helpers
  // ---------------------------------------------------------------------------

  describe('Exported helpers', () => {
    it('isProduction is true when NODE_ENV=production', async () => {
      const { isProduction } = await loadConfigWithEnv({
        NODE_ENV: 'production',
        JWT_ACCESS_SECRET: 'prod-access-secret-very-secure-and-long-enough!!',
        JWT_REFRESH_SECRET: 'prod-refresh-secret-very-secure-and-long-enough!!',
        SESSION_SECRET: 'ProdSessionSecretVerySecure!!1234',
        CORS_ORIGIN: 'https://hvault.example.com',
      });
      expect(isProduction).toBe(true);
    });

    it('isDevelopment is true when NODE_ENV=development', async () => {
      const { isDevelopment } = await loadConfigWithEnv({
        NODE_ENV: 'development',
      });
      expect(isDevelopment).toBe(true);
    });

    it('isTest is true when NODE_ENV=test', async () => {
      const { isTest } = await loadConfigWithEnv({
        NODE_ENV: 'test',
      });
      expect(isTest).toBe(true);
    });

    it('isProduction is false when NODE_ENV=test', async () => {
      const { isProduction } = await loadConfigWithEnv({
        NODE_ENV: 'test',
      });
      expect(isProduction).toBe(false);
    });

    it('isDevelopment is false when NODE_ENV=production', async () => {
      const { isDevelopment } = await loadConfigWithEnv({
        NODE_ENV: 'production',
        JWT_ACCESS_SECRET: 'prod-access-secret-very-secure-and-long-enough!!',
        JWT_REFRESH_SECRET: 'prod-refresh-secret-very-secure-and-long-enough!!',
        SESSION_SECRET: 'ProdSessionSecretVerySecure!!1234',
        CORS_ORIGIN: 'https://hvault.example.com',
      });
      expect(isDevelopment).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // Invalid values
  // ---------------------------------------------------------------------------

  describe('Invalid values', () => {
    it('PORT below 1 is rejected', async () => {
      await expect(loadConfigWithEnv({ PORT: '0' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('PORT above 65535 is rejected', async () => {
      await expect(loadConfigWithEnv({ PORT: '70000' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('BCRYPT_ROUNDS below 4 is rejected', async () => {
      await expect(loadConfigWithEnv({ BCRYPT_ROUNDS: '2' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('BCRYPT_ROUNDS above 31 is rejected', async () => {
      await expect(loadConfigWithEnv({ BCRYPT_ROUNDS: '32' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('JWT_ACCESS_SECRET shorter than 32 chars is rejected', async () => {
      await expect(loadConfigWithEnv({ JWT_ACCESS_SECRET: 'short' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('SESSION_SECRET shorter than 32 chars is rejected', async () => {
      await expect(loadConfigWithEnv({ SESSION_SECRET: 'short' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('JWT_REFRESH_SECRET shorter than 32 chars is rejected', async () => {
      await expect(loadConfigWithEnv({ JWT_REFRESH_SECRET: 'short' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('BACKUP_MAX_SIZE_MB below 1 is rejected', async () => {
      await expect(loadConfigWithEnv({ BACKUP_MAX_SIZE_MB: '0' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('BACKUP_MAX_SIZE_MB above 100 is rejected', async () => {
      await expect(loadConfigWithEnv({ BACKUP_MAX_SIZE_MB: '101' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('BACKUP_RETENTION_DAYS above 365 is rejected', async () => {
      await expect(loadConfigWithEnv({ BACKUP_RETENTION_DAYS: '400' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('AUDIT_LOG_RETENTION_DAYS above 3650 is rejected', async () => {
      await expect(loadConfigWithEnv({ AUDIT_LOG_RETENTION_DAYS: '4000' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('HIBP_CACHE_MAX_BYTES below the 1 MiB floor is rejected', async () => {
      await expect(loadConfigWithEnv({ HIBP_CACHE_MAX_BYTES: '1048575' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    // `HIBP_MAX_RANGE_RESPONSE_BYTES` bounds a single fetched range, and its
    // comment justifies the value partly by claiming it equals the SMALLEST L1
    // budget an operator may configure. That matters: `evictHibpToWithinLimits`
    // never evicts below one entry, so a range larger than the whole budget would
    // sit in L1 permanently over it. Pinned by PARSING at bound and bound-1 —
    // comparing the two constants to each other would stay green if both moved
    // together and would prove nothing about the schema. Two tests, not one,
    // because `loadConfigWithEnv` re-imports a module registry that is reset per
    // test: a second call inside one test returns the first call's cached module.

    it('accepts HIBP_MAX_RANGE_RESPONSE_BYTES as an L1 budget, so one range always fits', async () => {
      const { config } = await loadConfigWithEnv({
        HIBP_CACHE_MAX_BYTES: String(HIBP_MAX_RANGE_RESPONSE_BYTES),
      });
      expect(config.HIBP_CACHE_MAX_BYTES).toBe(HIBP_MAX_RANGE_RESPONSE_BYTES);
    });

    it('rejects an L1 budget one byte below HIBP_MAX_RANGE_RESPONSE_BYTES', async () => {
      await expect(
        loadConfigWithEnv({ HIBP_CACHE_MAX_BYTES: String(HIBP_MAX_RANGE_RESPONSE_BYTES - 1) }),
      ).rejects.toThrow(/Invalid environment configuration/);
    });

    it('invalid NODE_ENV value is rejected', async () => {
      await expect(loadConfigWithEnv({ NODE_ENV: 'staging' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('APP_URL with invalid URL format is rejected', async () => {
      await expect(loadConfigWithEnv({ APP_URL: 'not-a-url' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });
  });

  // ---------------------------------------------------------------------------
  // FILE_ENCRYPTION_MAX_SIZE_MB (client-side guardrail; int 1..1024, default 100)
  // ---------------------------------------------------------------------------

  describe('FILE_ENCRYPTION_MAX_SIZE_MB', () => {
    it('accepts the minimum bound (1)', async () => {
      const { config } = await loadConfigWithEnv({ FILE_ENCRYPTION_MAX_SIZE_MB: '1' });
      expect(config.FILE_ENCRYPTION_MAX_SIZE_MB).toBe(1);
    });

    it('accepts the default value (100)', async () => {
      const { config } = await loadConfigWithEnv({ FILE_ENCRYPTION_MAX_SIZE_MB: '100' });
      expect(config.FILE_ENCRYPTION_MAX_SIZE_MB).toBe(100);
    });

    it('accepts the maximum bound (1024)', async () => {
      const { config } = await loadConfigWithEnv({ FILE_ENCRYPTION_MAX_SIZE_MB: '1024' });
      expect(config.FILE_ENCRYPTION_MAX_SIZE_MB).toBe(1024);
    });

    it('rejects 0 (below the minimum)', async () => {
      await expect(loadConfigWithEnv({ FILE_ENCRYPTION_MAX_SIZE_MB: '0' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('rejects 1025 (above the maximum)', async () => {
      await expect(loadConfigWithEnv({ FILE_ENCRYPTION_MAX_SIZE_MB: '1025' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('rejects a non-integer value', async () => {
      await expect(loadConfigWithEnv({ FILE_ENCRYPTION_MAX_SIZE_MB: '10.5' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });
  });

  // ---------------------------------------------------------------------------
  // TWO_FACTOR_ENCRYPTION_KEY
  // ---------------------------------------------------------------------------

  describe('TWO_FACTOR_ENCRYPTION_KEY', () => {
    it('twoFactorEncryptionKey falls back to SESSION_SECRET when not set', async () => {
      const { twoFactorEncryptionKey, config } = await loadConfigWithEnv({
        TWO_FACTOR_ENCRYPTION_KEY: undefined,
      });
      expect(twoFactorEncryptionKey).toBe(config.SESSION_SECRET);
    });

    it('twoFactorEncryptionKey uses dedicated key when set', async () => {
      const dedicatedKey = 'dedicated-2fa-key-at-least-32-characters-long!!';
      const { twoFactorEncryptionKey } = await loadConfigWithEnv({
        TWO_FACTOR_ENCRYPTION_KEY: dedicatedKey,
      });
      expect(twoFactorEncryptionKey).toBe(dedicatedKey);
    });

    it('TWO_FACTOR_ENCRYPTION_KEY shorter than 32 chars is rejected', async () => {
      await expect(loadConfigWithEnv({ TWO_FACTOR_ENCRYPTION_KEY: 'too-short' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('production without TWO_FACTOR_ENCRYPTION_KEY logs a warning', async () => {
      mockWarn.mockClear();
      await loadConfigWithEnv({
        NODE_ENV: 'production',
        JWT_ACCESS_SECRET: 'prod-access-secret-very-secure-and-long-enough!!',
        JWT_REFRESH_SECRET: 'prod-refresh-secret-very-secure-and-long-enough!!',
        SESSION_SECRET: 'ProdSessionSecretVerySecure!!1234',
        CORS_ORIGIN: 'https://hvault.example.com',
        TWO_FACTOR_ENCRYPTION_KEY: undefined,
      });
      expect(mockWarn).toHaveBeenCalledWith(
        expect.stringContaining('TWO_FACTOR_ENCRYPTION_KEY not set'),
      );
    });

    it('TWO_FACTOR_ENCRYPTION_KEY starting with dev- in production throws', async () => {
      await expect(
        loadConfigWithEnv({
          NODE_ENV: 'production',
          JWT_ACCESS_SECRET: 'prod-access-secret-very-secure-and-long-enough!!',
          JWT_REFRESH_SECRET: 'prod-refresh-secret-very-secure-and-long-enough!!',
          SESSION_SECRET: 'ProdSessionSecretVerySecure!!1234',
          CORS_ORIGIN: 'https://hvault.example.com',
          TWO_FACTOR_ENCRYPTION_KEY: 'dev-2fa-encryption-key-change-me-32chars!!',
        }),
      ).rejects.toThrow(
        'TWO_FACTOR_ENCRYPTION_KEY must be set to a secure value in non-development environments',
      );
    });

    it('TWO_FACTOR_ENCRYPTION_KEY with mixed-case DEV- prefix in production throws', async () => {
      await expect(
        loadConfigWithEnv({
          NODE_ENV: 'production',
          JWT_ACCESS_SECRET: 'prod-access-secret-very-secure-and-long-enough!!',
          JWT_REFRESH_SECRET: 'prod-refresh-secret-very-secure-and-long-enough!!',
          SESSION_SECRET: 'ProdSessionSecretVerySecure!!1234',
          CORS_ORIGIN: 'https://hvault.example.com',
          TWO_FACTOR_ENCRYPTION_KEY: 'DEV-2fa-encryption-key-change-me-32chars!!',
        }),
      ).rejects.toThrow(
        'TWO_FACTOR_ENCRYPTION_KEY must be set to a secure value in non-development environments',
      );
    });

    it('TWO_FACTOR_ENCRYPTION_KEY with dev- prefix in development mode is accepted', async () => {
      const { twoFactorEncryptionKey } = await loadConfigWithEnv({
        NODE_ENV: 'development',
        TWO_FACTOR_ENCRYPTION_KEY: 'dev-2fa-encryption-key-change-me-32chars!!',
      });
      expect(twoFactorEncryptionKey).toBe('dev-2fa-encryption-key-change-me-32chars!!');
    });

    it('TWO_FACTOR_ENCRYPTION_KEY without dev- prefix in production is accepted', async () => {
      const { twoFactorEncryptionKey } = await loadConfigWithEnv({
        NODE_ENV: 'production',
        JWT_ACCESS_SECRET: 'prod-access-secret-very-secure-and-long-enough!!',
        JWT_REFRESH_SECRET: 'prod-refresh-secret-very-secure-and-long-enough!!',
        SESSION_SECRET: 'ProdSessionSecretVerySecure!!1234',
        CORS_ORIGIN: 'https://hvault.example.com',
        TWO_FACTOR_ENCRYPTION_KEY: 'secure-2fa-encryption-key-for-production-32chars!!',
      });
      expect(twoFactorEncryptionKey).toBe('secure-2fa-encryption-key-for-production-32chars!!');
    });
  });

  // ---------------------------------------------------------------------------
  // Custom values override defaults
  // ---------------------------------------------------------------------------

  describe('Custom values override defaults', () => {
    it('PORT accepts custom value', async () => {
      const { config } = await loadConfigWithEnv({ PORT: '3000' });
      expect(config.PORT).toBe(3000);
    });

    it('BCRYPT_ROUNDS accepts custom value within range', async () => {
      const { config } = await loadConfigWithEnv({ BCRYPT_ROUNDS: '10' });
      expect(config.BCRYPT_ROUNDS).toBe(10);
    });

    it('MONGO_MAX_POOL_SIZE accepts custom value', async () => {
      const { config } = await loadConfigWithEnv({ MONGO_MAX_POOL_SIZE: '50' });
      expect(config.MONGO_MAX_POOL_SIZE).toBe(50);
    });

    it('AUDIT_LOG_RETENTION_DAYS accepts custom value', async () => {
      const { config } = await loadConfigWithEnv({ AUDIT_LOG_RETENTION_DAYS: '730' });
      expect(config.AUDIT_LOG_RETENTION_DAYS).toBe(730);
    });
  });

  // ---------------------------------------------------------------------------
  // TRUST_PROXY
  // ---------------------------------------------------------------------------

  describe('TRUST_PROXY', () => {
    it('defaults to false when not set', async () => {
      const { config } = await loadConfigWithEnv({ TRUST_PROXY: undefined });
      expect(config.TRUST_PROXY).toBe(false);
    });

    it('returns false for empty string', async () => {
      const { config } = await loadConfigWithEnv({ TRUST_PROXY: '' });
      expect(config.TRUST_PROXY).toBe(false);
    });

    it('returns false for "false"', async () => {
      const { config } = await loadConfigWithEnv({ TRUST_PROXY: 'false' });
      expect(config.TRUST_PROXY).toBe(false);
    });

    it('returns 1 for "true"', async () => {
      const { config } = await loadConfigWithEnv({ TRUST_PROXY: 'true' });
      expect(config.TRUST_PROXY).toBe(1);
    });

    it('returns 1 for "1"', async () => {
      const { config } = await loadConfigWithEnv({ TRUST_PROXY: '1' });
      expect(config.TRUST_PROXY).toBe(1);
    });

    it('returns numeric value for numeric string', async () => {
      const { config } = await loadConfigWithEnv({ TRUST_PROXY: '3' });
      expect(config.TRUST_PROXY).toBe(3);
    });

    it('returns string value for "loopback"', async () => {
      const { config } = await loadConfigWithEnv({ TRUST_PROXY: 'loopback' });
      expect(config.TRUST_PROXY).toBe('loopback');
    });

    it('returns string value for "uniquelocal"', async () => {
      const { config } = await loadConfigWithEnv({ TRUST_PROXY: 'uniquelocal' });
      expect(config.TRUST_PROXY).toBe('uniquelocal');
    });

    it('accepts the minimum hop count (0)', async () => {
      // 0 passes the bound (integer, >= 0, <= 10). Note: app.ts guards
      // `if (config.TRUST_PROXY)`, so 0 is falsy and leaves trust proxy unset —
      // equivalent to omitting the variable. Pinned here to document that.
      const { config } = await loadConfigWithEnv({ TRUST_PROXY: '0' });
      expect(config.TRUST_PROXY).toBe(0);
    });

    it('accepts the maximum allowed hop count (10)', async () => {
      const { config } = await loadConfigWithEnv({ TRUST_PROXY: '10' });
      expect(config.TRUST_PROXY).toBe(10);
    });

    it('rejects "Infinity" (unbounded proxy trust)', async () => {
      await expect(loadConfigWithEnv({ TRUST_PROXY: 'Infinity' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
      await expect(loadConfigWithEnv({ TRUST_PROXY: 'Infinity' })).rejects.toThrow(/TRUST_PROXY/);
    });

    it('rejects a huge finite hop count ("1e9")', async () => {
      await expect(loadConfigWithEnv({ TRUST_PROXY: '1e9' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
      await expect(loadConfigWithEnv({ TRUST_PROXY: '1e9' })).rejects.toThrow(/TRUST_PROXY/);
    });

    it('rejects a hop count above the ceiling ("11")', async () => {
      await expect(loadConfigWithEnv({ TRUST_PROXY: '11' })).rejects.toThrow(/TRUST_PROXY/);
    });

    it('rejects a negative hop count ("-1")', async () => {
      await expect(loadConfigWithEnv({ TRUST_PROXY: '-1' })).rejects.toThrow(/TRUST_PROXY/);
    });

    it('rejects a non-integer hop count ("2.5")', async () => {
      await expect(loadConfigWithEnv({ TRUST_PROXY: '2.5' })).rejects.toThrow(/TRUST_PROXY/);
    });
  });

  // ---------------------------------------------------------------------------
  // Mongo pool-size cross-field validation
  // ---------------------------------------------------------------------------

  describe('Mongo pool-size cross-field validation', () => {
    it('rejects an inverted config where MIN > MAX', async () => {
      await expect(
        loadConfigWithEnv({ MONGO_MIN_POOL_SIZE: '50', MONGO_MAX_POOL_SIZE: '10' }),
      ).rejects.toThrow(/MONGO_MIN_POOL_SIZE cannot be greater than MONGO_MAX_POOL_SIZE/);
    });

    it('accepts MIN equal to MAX (boundary)', async () => {
      const { config } = await loadConfigWithEnv({
        MONGO_MIN_POOL_SIZE: '10',
        MONGO_MAX_POOL_SIZE: '10',
      });
      expect(config.MONGO_MIN_POOL_SIZE).toBe(10);
      expect(config.MONGO_MAX_POOL_SIZE).toBe(10);
    });

    it('accepts MIN below MAX', async () => {
      const { config } = await loadConfigWithEnv({
        MONGO_MIN_POOL_SIZE: '2',
        MONGO_MAX_POOL_SIZE: '20',
      });
      expect(config.MONGO_MIN_POOL_SIZE).toBe(2);
      expect(config.MONGO_MAX_POOL_SIZE).toBe(20);
    });

    it('accepts the defaults (min 2 <= max 10)', async () => {
      const { config } = await loadConfigWithEnv({
        MONGO_MIN_POOL_SIZE: undefined,
        MONGO_MAX_POOL_SIZE: undefined,
      });
      expect(config.MONGO_MIN_POOL_SIZE).toBe(2);
      expect(config.MONGO_MAX_POOL_SIZE).toBe(10);
    });
  });

  // ---------------------------------------------------------------------------
  // Session lifetimes (integer day counts) + cross-field ordering refines
  // ---------------------------------------------------------------------------

  describe('Session lifetime day counts', () => {
    it('coerces provided values', async () => {
      const { config } = await loadConfigWithEnv({
        REFRESH_TOKEN_DAYS: '14',
        REFRESH_TOKEN_REMEMBER_DAYS: '60',
        TRUSTED_DEVICE_DAYS: '90',
      });
      expect(config.REFRESH_TOKEN_DAYS).toBe(14);
      expect(config.REFRESH_TOKEN_REMEMBER_DAYS).toBe(60);
      expect(config.TRUSTED_DEVICE_DAYS).toBe(90);
    });

    it('the defaults (7/30/30) satisfy both ordering refines', async () => {
      const { config } = await loadConfigWithEnv({
        REFRESH_TOKEN_DAYS: undefined,
        REFRESH_TOKEN_REMEMBER_DAYS: undefined,
        TRUSTED_DEVICE_DAYS: undefined,
      });
      expect(config.REFRESH_TOKEN_DAYS).toBe(7);
      expect(config.REFRESH_TOKEN_REMEMBER_DAYS).toBe(30);
      expect(config.TRUSTED_DEVICE_DAYS).toBe(30);
    });

    it('rejects REFRESH_TOKEN_DAYS below 1', async () => {
      await expect(loadConfigWithEnv({ REFRESH_TOKEN_DAYS: '0' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('rejects REFRESH_TOKEN_DAYS above 90', async () => {
      await expect(loadConfigWithEnv({ REFRESH_TOKEN_DAYS: '91' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('rejects a non-integer REFRESH_TOKEN_DAYS', async () => {
      await expect(loadConfigWithEnv({ REFRESH_TOKEN_DAYS: '7.5' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('rejects REFRESH_TOKEN_REMEMBER_DAYS above 365', async () => {
      await expect(
        loadConfigWithEnv({ REFRESH_TOKEN_REMEMBER_DAYS: '366', TRUSTED_DEVICE_DAYS: '366' }),
      ).rejects.toThrow(/Invalid environment configuration/);
    });

    it('rejects TRUSTED_DEVICE_DAYS above 365', async () => {
      await expect(loadConfigWithEnv({ TRUSTED_DEVICE_DAYS: '366' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('rejects REFRESH_TOKEN_REMEMBER_DAYS below 1', async () => {
      await expect(loadConfigWithEnv({ REFRESH_TOKEN_REMEMBER_DAYS: '0' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('rejects a non-integer REFRESH_TOKEN_REMEMBER_DAYS', async () => {
      // 10.5 >= REFRESH_TOKEN_DAYS default 7 and <= TRUSTED_DEVICE_DAYS default 30,
      // so both refines pass and only the .int() check fires.
      await expect(loadConfigWithEnv({ REFRESH_TOKEN_REMEMBER_DAYS: '10.5' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('rejects TRUSTED_DEVICE_DAYS below 1', async () => {
      await expect(loadConfigWithEnv({ TRUSTED_DEVICE_DAYS: '0' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('rejects a non-integer TRUSTED_DEVICE_DAYS', async () => {
      // 30.5 >= REFRESH_TOKEN_REMEMBER_DAYS default 30, so the refine passes and
      // only the .int() check fires.
      await expect(loadConfigWithEnv({ TRUSTED_DEVICE_DAYS: '30.5' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('rejects REFRESH_TOKEN_REMEMBER_DAYS < REFRESH_TOKEN_DAYS (refine)', async () => {
      await expect(
        loadConfigWithEnv({
          REFRESH_TOKEN_DAYS: '10',
          REFRESH_TOKEN_REMEMBER_DAYS: '7',
          TRUSTED_DEVICE_DAYS: '30',
        }),
      ).rejects.toThrow(/REFRESH_TOKEN_REMEMBER_DAYS cannot be less than REFRESH_TOKEN_DAYS/);
    });

    it('accepts REFRESH_TOKEN_REMEMBER_DAYS === REFRESH_TOKEN_DAYS (boundary)', async () => {
      const { config } = await loadConfigWithEnv({
        REFRESH_TOKEN_DAYS: '7',
        REFRESH_TOKEN_REMEMBER_DAYS: '7',
        TRUSTED_DEVICE_DAYS: '7',
      });
      expect(config.REFRESH_TOKEN_REMEMBER_DAYS).toBe(7);
    });

    it('rejects TRUSTED_DEVICE_DAYS < REFRESH_TOKEN_REMEMBER_DAYS (refine)', async () => {
      await expect(
        loadConfigWithEnv({
          REFRESH_TOKEN_DAYS: '7',
          REFRESH_TOKEN_REMEMBER_DAYS: '30',
          TRUSTED_DEVICE_DAYS: '10',
        }),
      ).rejects.toThrow(/TRUSTED_DEVICE_DAYS cannot be less than REFRESH_TOKEN_REMEMBER_DAYS/);
    });

    it('accepts TRUSTED_DEVICE_DAYS === REFRESH_TOKEN_REMEMBER_DAYS (boundary)', async () => {
      const { config } = await loadConfigWithEnv({
        REFRESH_TOKEN_DAYS: '5',
        REFRESH_TOKEN_REMEMBER_DAYS: '10',
        TRUSTED_DEVICE_DAYS: '10',
      });
      expect(config.TRUSTED_DEVICE_DAYS).toBe(10);
    });
  });

  // ---------------------------------------------------------------------------
  // ENABLE_METRICS removed (dead flag) — gating is solely via METRICS_TOKEN
  // ---------------------------------------------------------------------------

  describe('ENABLE_METRICS dead-flag removal', () => {
    it('config does not expose an ENABLE_METRICS key', async () => {
      const { config } = await loadConfigWithEnv({});
      expect('ENABLE_METRICS' in config).toBe(false);
    });

    it('ENABLE_METRICS in the environment is ignored (not surfaced on config)', async () => {
      const { config } = await loadConfigWithEnv({ ENABLE_METRICS: 'true' });
      expect((config as Record<string, unknown>).ENABLE_METRICS).toBeUndefined();
    });

    it('ENABLE_SWAGGER is still parsed (sanity — only ENABLE_METRICS was removed)', async () => {
      const { config } = await loadConfigWithEnv({ ENABLE_SWAGGER: 'true' });
      expect(config.ENABLE_SWAGGER).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Empty-string normalization for optional secrets (must precede the length check)
  // ---------------------------------------------------------------------------

  describe('METRICS_TOKEN empty-string normalization', () => {
    it('an empty METRICS_TOKEN loads (metrics disabled) instead of crashing boot', async () => {
      const { config } = await loadConfigWithEnv({ METRICS_TOKEN: '' });
      expect(config.METRICS_TOKEN).toBeUndefined();
    });

    it('an unset METRICS_TOKEN is undefined', async () => {
      const { config } = await loadConfigWithEnv({ METRICS_TOKEN: undefined });
      expect(config.METRICS_TOKEN).toBeUndefined();
    });

    it('a valid METRICS_TOKEN (>= 16 chars) is parsed', async () => {
      const { config } = await loadConfigWithEnv({
        METRICS_TOKEN: 'metrics-token-at-least-16-chars',
      });
      expect(config.METRICS_TOKEN).toBe('metrics-token-at-least-16-chars');
    });

    it('a too-short non-empty METRICS_TOKEN is still rejected', async () => {
      await expect(loadConfigWithEnv({ METRICS_TOKEN: 'short' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });
  });

  describe('TWO_FACTOR_ENCRYPTION_KEY empty-string normalization', () => {
    it('an empty key loads and falls back to SESSION_SECRET instead of crashing boot', async () => {
      const { config, twoFactorEncryptionKey } = await loadConfigWithEnv({
        TWO_FACTOR_ENCRYPTION_KEY: '',
      });
      expect(config.TWO_FACTOR_ENCRYPTION_KEY).toBeUndefined();
      expect(twoFactorEncryptionKey).toBe(config.SESSION_SECRET);
    });

    it('an unset key falls back to SESSION_SECRET', async () => {
      const { config, twoFactorEncryptionKey } = await loadConfigWithEnv({
        TWO_FACTOR_ENCRYPTION_KEY: undefined,
      });
      expect(config.TWO_FACTOR_ENCRYPTION_KEY).toBeUndefined();
      expect(twoFactorEncryptionKey).toBe(config.SESSION_SECRET);
    });

    it('a valid key (>= 32 chars) is parsed and used over SESSION_SECRET', async () => {
      const dedicated = 'TestTwoFactorEncryptionKey!!12345';
      const { config, twoFactorEncryptionKey } = await loadConfigWithEnv({
        TWO_FACTOR_ENCRYPTION_KEY: dedicated,
      });
      expect(config.TWO_FACTOR_ENCRYPTION_KEY).toBe(dedicated);
      expect(twoFactorEncryptionKey).toBe(dedicated);
    });

    it('a too-short non-empty key is still rejected', async () => {
      await expect(loadConfigWithEnv({ TWO_FACTOR_ENCRYPTION_KEY: 'too-short' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });
  });
});
