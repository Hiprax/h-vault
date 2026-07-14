import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

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
      CORS_ORIGIN: 'http://localhost:3000',
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

    it('JWT_REFRESH_EXPIRY defaults to 7d', async () => {
      const { config } = await loadConfigWithEnv({ JWT_REFRESH_EXPIRY: undefined });
      expect(config.JWT_REFRESH_EXPIRY).toBe('7d');
    });

    it('BCRYPT_ROUNDS defaults to 12', async () => {
      const { config } = await loadConfigWithEnv({ BCRYPT_ROUNDS: undefined });
      expect(config.BCRYPT_ROUNDS).toBe(12);
    });

    it('RATE_LIMIT_WINDOW_MS defaults to 900000', async () => {
      const { config } = await loadConfigWithEnv({ RATE_LIMIT_WINDOW_MS: undefined });
      expect(config.RATE_LIMIT_WINDOW_MS).toBe(900_000);
    });

    it('RATE_LIMIT_MAX defaults to 100', async () => {
      const { config } = await loadConfigWithEnv({ RATE_LIMIT_MAX: undefined });
      expect(config.RATE_LIMIT_MAX).toBe(100);
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
        CORS_ORIGIN: 'http://localhost:3000',
      });
      expect(config.CORS_ORIGIN).toBe('http://localhost:3000');
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

    it('RATE_LIMIT_WINDOW_MS below 1000 is rejected', async () => {
      await expect(loadConfigWithEnv({ RATE_LIMIT_WINDOW_MS: '500' })).rejects.toThrow(
        /Invalid environment configuration/,
      );
    });

    it('RATE_LIMIT_MAX below 1 is rejected', async () => {
      await expect(loadConfigWithEnv({ RATE_LIMIT_MAX: '0' })).rejects.toThrow(
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

    it('RATE_LIMIT_WINDOW_MS accepts custom value', async () => {
      const { config } = await loadConfigWithEnv({ RATE_LIMIT_WINDOW_MS: '60000' });
      expect(config.RATE_LIMIT_WINDOW_MS).toBe(60_000);
    });

    it('RATE_LIMIT_MAX accepts custom value', async () => {
      const { config } = await loadConfigWithEnv({ RATE_LIMIT_MAX: '50' });
      expect(config.RATE_LIMIT_MAX).toBe(50);
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
