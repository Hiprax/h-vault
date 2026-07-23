import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import dotenv from 'dotenv';
import { z } from 'zod';
import { createLogger } from '@hiprax/logger';

// Resolve .env from the monorepo root (4 levels up from packages/server/src/config/).
// When using npm workspaces, process.cwd() points to the package directory, not the
// monorepo root. This caused dotenv to load packages/server/.env (test config with
// empty SMTP values) instead of the root .env (actual user config).
const configDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(configDir, '..', '..', '..', '..');
const rootEnvPath = path.join(rootDir, '.env');

if (fs.existsSync(rootEnvPath)) {
  dotenv.config({ path: rootEnvPath });
} else {
  // Fallback: load from CWD (standalone deployment without .env at the
  // monorepo root, e.g. inside a Docker container).
  dotenv.config();
}
// NOTE: previously this used `dotenv-safe` to enforce the presence of
// `.env.example` keys at boot. That guard is now redundant: the Zod schema
// below validates every required env var (`z.string().min(32)` etc.) and
// raises a structured error when a required value is missing, so an
// unmaintained dependency on the boot path is no longer needed.

const logger = createLogger({ moduleName: 'config' });

/**
 * Upper bound for a numeric `TRUST_PROXY` hop count. Express treats a numeric
 * `trust proxy` value as "trust the n-th hop from the front", so an unbounded
 * value (`Infinity`, `1e9`, etc.) trusts the entire client-supplied
 * `X-Forwarded-For` chain — letting a client spoof `req.ip` and defeat the
 * IP-keyed rate limiting and audit-IP integrity the app relies on. Real
 * deployments sit behind at most a couple of proxies; 10 is a generous ceiling.
 */
const MAX_TRUST_PROXY_HOPS = 10;

const envSchema = z
  .object({
    PORT: z.coerce.number().int().min(1).max(65535).default(5000),
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

    // Database
    MONGODB_URI: z.string().min(1).default('mongodb://localhost:27017/hvault'),
    MONGO_MAX_POOL_SIZE: z.coerce.number().int().min(1).max(100).default(10),
    MONGO_MIN_POOL_SIZE: z.coerce.number().int().min(0).max(50).default(2),

    // JWT
    JWT_ACCESS_SECRET: z
      .string()
      .min(32)
      .default('dev-access-secret-change-me-in-production-32chars'),
    JWT_REFRESH_SECRET: z
      .string()
      .min(32)
      .default('dev-refresh-secret-change-me-in-production-32chars'),
    JWT_ACCESS_EXPIRY: z.string().min(1).default('5m'),
    JWT_REFRESH_EXPIRY: z.string().min(1).default('7d'),

    // CORS
    CORS_ORIGIN: z
      .string()
      .min(1)
      .default('http://localhost:5173')
      .refine((url) => process.env.NODE_ENV !== 'production' || url.startsWith('https://'), {
        message: 'CORS_ORIGIN must use HTTPS in production',
      }),

    // Email provider
    EMAIL_PROVIDER: z.enum(['smtp', 'gmail']).default('smtp'),

    // SMTP (optional for dev)
    // Empty strings are treated as unset — dotenv loads `SMTP_HOST=` as "" which must
    // be normalised to undefined so downstream checks (!config.SMTP_HOST) work correctly.
    SMTP_HOST: z
      .string()
      .optional()
      .transform((v) => (v === '' ? undefined : v)),
    SMTP_PORT: z.coerce.number().int().min(1).max(65535).default(587),
    SMTP_SECURE: z
      .enum(['true', 'false', ''])
      .optional()
      .transform((val) => (val === 'true' ? true : val === 'false' ? false : undefined)),
    SMTP_USER: z
      .string()
      .optional()
      .transform((v) => (v === '' ? undefined : v)),
    SMTP_PASS: z
      .string()
      .optional()
      .transform((v) => (v === '' ? undefined : v)),
    SMTP_FROM: z
      .string()
      .optional()
      .transform((v) => (v === '' ? undefined : v)),

    // Gmail (optional, used when EMAIL_PROVIDER=gmail)
    GMAIL_USERNAME: z
      .string()
      .optional()
      .transform((v) => (v === '' ? undefined : v)),
    GMAIL_PASSWORD: z
      .string()
      .optional()
      .transform((v) => (v === '' ? undefined : v)),

    // App
    APP_URL: z
      .url()
      .refine((u) => /^https?:\/\//i.test(u), {
        message: 'APP_URL must use http:// or https://',
      })
      .default('http://localhost:5000')
      .transform((url) => url.replace(/\/+$/, '')),
    APP_NAME: z.string().min(1).default('H-Vault'),

    // Rate Limiting
    RATE_LIMIT_WINDOW_MS: z.coerce.number().int().min(1000).default(900_000),
    RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(100),

    // Security
    BCRYPT_ROUNDS: z.coerce.number().int().min(4).max(31).default(12),
    SESSION_SECRET: z
      .string()
      .min(32)
      .default('dev-session-secret-change-me-in-production-32chars'),
    // Empty is treated as unset — `TWO_FACTOR_ENCRYPTION_KEY=` in .env loads as ""
    // and must normalise to undefined BEFORE the length check, otherwise it fails
    // `.min(32)` and aborts boot instead of falling back to SESSION_SECRET as
    // documented. A trailing `.transform()` cannot do this: it runs only after the
    // inner schema has already rejected "".
    TWO_FACTOR_ENCRYPTION_KEY: z.preprocess(
      (v) => (v === '' ? undefined : v),
      z.string().min(32).optional(),
    ),

    // Backup
    BACKUP_MAX_SIZE_MB: z.coerce.number().int().min(1).max(100).default(25),
    BACKUP_RETENTION_DAYS: z.coerce.number().int().min(1).max(365).default(30),

    // Export
    EXPORT_MAX_SIZE_MB: z.coerce.number().int().min(1).max(100).default(25),

    // File Encryption
    // Client-side size guardrail (in MB) for the File Encryption tool. The file
    // is encrypted entirely in the browser and never uploaded, so the server
    // cannot enforce this — it is surfaced to the client via GET /config as an
    // operator-tunable ceiling. Bounded 1..1024; browser one-shot crypto is
    // memory-bound, so 100 MB is a desktop-safe default.
    FILE_ENCRYPTION_MAX_SIZE_MB: z.coerce.number().int().min(1).max(1024).default(100),

    // Audit
    AUDIT_LOG_RETENTION_DAYS: z.coerce.number().int().min(1).max(3650).default(365),

    // Breach range cache (persistent, cross-account HIBP range cache)
    // On-demand (`source: 'hibp'`) entries are re-fetched once older than this
    // many days; seed-imported entries are exempt (refreshed by re-running the
    // seed). The HIBP corpus is additive, so a stale entry can only miss a very
    // recently added breach, never wrongly clear a known one — set 7 for a
    // stricter freshness posture.
    BREACH_CACHE_TTL_DAYS: z.coerce.number().int().min(1).max(365).default(30),
    // When true, the refresh cron below fetches missing/stale ranges from HIBP
    // (tens of GB over a full corpus). Off by default.
    BREACH_SEED_AUTO: z
      .enum(['true', 'false', ''])
      .optional()
      .transform((val) => val === 'true'),
    // Cron expression (UTC) for the range-cache refresh job. Unset disables it.
    // Requires BREACH_SEED_AUTO=true to actually fetch. Empty normalises to
    // undefined before the optional string check.
    BREACH_SEED_REFRESH_CRON: z.preprocess(
      (v) => (v === '' ? undefined : v),
      z.string().optional(),
    ),
    // In-memory (L1) HIBP range cache memory ceiling, in BYTES, per worker process.
    // The L1 cache is a per-process Map of padding-stripped range text; a real HIBP
    // range is ~36 KB, so the default 64 MiB bounds it at ~1,800 ranges per worker.
    // This byte budget is the BINDING bound; HIBP_CACHE_MAX_ENTRIES (10,000) is only
    // a secondary guard against a pathological run of tiny ranges. `max_memory_restart`
    // is enforced PER PM2 worker, not aggregate, so the relevant comparison is one
    // worker's full cache (64 MiB) plus its ordinary heap against the threshold.
    HIBP_CACHE_MAX_BYTES: z.coerce.number().int().min(1_048_576).default(67_108_864),

    // Feature flags
    ENABLE_SWAGGER: z
      .enum(['true', 'false', ''])
      .optional()
      .transform((val) => val === 'true'),

    // Metrics authentication token (min 16 chars when set).
    // When set, the /metrics endpoint requires an `x-metrics-token` header matching this value.
    // When not set (or set to an empty value), the /metrics endpoint is disabled (returns 404).
    // The empty-to-undefined normalisation must run BEFORE `.min(16)` — as a trailing
    // `.transform()` it would never be reached for "", so `METRICS_TOKEN=` crashed boot.
    METRICS_TOKEN: z.preprocess((v) => (v === '' ? undefined : v), z.string().min(16).optional()),

    // Trust proxy (for deployments behind reverse proxy: Nginx, AWS ALB, Docker)
    // Values: false (default), 1 (trust first proxy), 'loopback'/'linklocal'/'uniquelocal',
    // a comma-separated subnet list, or a hop count (0..MAX_TRUST_PROXY_HOPS).
    TRUST_PROXY: z
      .string()
      .optional()
      .transform((v) => {
        if (!v || v === '' || v === 'false') return false;
        if (v === 'true' || v === '1') return 1;
        const num = Number(v);
        if (!Number.isNaN(num)) return num;
        return v; // 'loopback', 'linklocal', 'uniquelocal', or comma-separated subnets
      })
      .refine(
        (val) =>
          typeof val !== 'number' ||
          (Number.isInteger(val) && val >= 0 && val <= MAX_TRUST_PROXY_HOPS),
        {
          // Rejects Infinity / 1e9 / non-integer / negative hop counts, which would
          // otherwise make Express trust an unbounded X-Forwarded-For chain.
          message: `TRUST_PROXY numeric hop count must be an integer between 0 and ${String(MAX_TRUST_PROXY_HOPS)} (use 'loopback'/'linklocal'/'uniquelocal' or a subnet list for named trust)`,
        },
      ),
  })
  .refine((data) => data.MONGO_MIN_POOL_SIZE <= data.MONGO_MAX_POOL_SIZE, {
    // An inverted pool config (min > max) otherwise passes per-field validation
    // and only fails at MongoDB connect time, masked behind the retry loop.
    message: 'MONGO_MIN_POOL_SIZE cannot be greater than MONGO_MAX_POOL_SIZE',
    path: ['MONGO_MIN_POOL_SIZE'],
  });

type EnvConfig = z.infer<typeof envSchema>;

function loadConfig(): EnvConfig {
  const result = envSchema.safeParse(process.env);

  if (!result.success) {
    const formatted = result.error.issues
      .map((issue) => `  ${issue.path.join('.')}: ${issue.message}`)
      .join('\n');
    throw new Error(`Invalid environment configuration:\n${formatted}`);
  }

  const data = result.data;

  // Reject default dev secrets in all non-development environments
  if (data.NODE_ENV !== 'development') {
    if (data.JWT_ACCESS_SECRET.toLowerCase().startsWith('dev-')) {
      throw new Error(
        'JWT_ACCESS_SECRET must be set to a secure value in non-development environments',
      );
    }
    if (data.JWT_REFRESH_SECRET.toLowerCase().startsWith('dev-')) {
      throw new Error(
        'JWT_REFRESH_SECRET must be set to a secure value in non-development environments',
      );
    }
    if (data.SESSION_SECRET.toLowerCase().startsWith('dev-')) {
      throw new Error(
        'SESSION_SECRET must be set to a secure value in non-development environments',
      );
    }
    if (data.TWO_FACTOR_ENCRYPTION_KEY?.toLowerCase().startsWith('dev-')) {
      throw new Error(
        'TWO_FACTOR_ENCRYPTION_KEY must be set to a secure value in non-development environments',
      );
    }
  }

  // Validate email provider configuration
  if (data.EMAIL_PROVIDER === 'gmail') {
    const gmailFields = [data.GMAIL_USERNAME, data.GMAIL_PASSWORD];
    const gmailSet = gmailFields.filter(Boolean).length;
    if (gmailSet > 0 && gmailSet < 2) {
      if (data.NODE_ENV === 'production') {
        throw new Error(
          'Gmail configuration is incomplete. Set both GMAIL_USERNAME and GMAIL_PASSWORD or none.',
        );
      }
      logger.warn(
        'Gmail configuration is incomplete. Set both GMAIL_USERNAME and GMAIL_PASSWORD or none. Email features will not work.',
      );
      data.GMAIL_USERNAME = undefined;
      data.GMAIL_PASSWORD = undefined;
    }
    if (data.NODE_ENV === 'production' && gmailSet === 0) {
      logger.warn(
        'Gmail not configured. Email features (backup, password reset, account unlock) will not work.',
      );
    }
  } else {
    // Validate SMTP fields are either all set or all empty
    const smtpFields = [data.SMTP_HOST, data.SMTP_USER, data.SMTP_PASS];
    const smtpSet = smtpFields.filter(Boolean).length;
    if (smtpSet > 0 && smtpSet < 3) {
      if (data.NODE_ENV === 'production') {
        throw new Error(
          'SMTP configuration is incomplete. Set all of SMTP_HOST, SMTP_USER, SMTP_PASS or none.',
        );
      }
      logger.warn(
        'SMTP configuration is incomplete. Set all of SMTP_HOST, SMTP_USER, SMTP_PASS or none. Email features will not work.',
      );
      // Normalize partial config to unconfigured so the email module does not
      // attempt to create a transporter with missing credentials.
      data.SMTP_HOST = undefined;
      data.SMTP_USER = undefined;
      data.SMTP_PASS = undefined;
    }
    if (data.NODE_ENV === 'production' && smtpSet === 0) {
      logger.warn(
        'SMTP not configured. Email features (backup, password reset, account unlock) will not work.',
      );
    }
  }

  // Warn when CORS allows non-HTTPS origin but MongoDB points to a non-localhost host.
  // This likely means the developer is connecting to a remote database over an
  // insecure network, which is a significant security risk.
  if (data.NODE_ENV === 'development') {
    const corsIsInsecure = !data.CORS_ORIGIN.startsWith('https://');
    let mongoIsRemote = false;
    try {
      const mongoUrl = new URL(data.MONGODB_URI);
      const host = mongoUrl.hostname.toLowerCase();
      mongoIsRemote = host !== 'localhost' && host !== '127.0.0.1' && host !== '::1';
    } catch {
      // Invalid MONGODB_URI — other validation will catch this
    }
    if (corsIsInsecure && mongoIsRemote) {
      logger.warn(
        '⚠ SECURITY WARNING: CORS_ORIGIN is not HTTPS and MONGODB_URI points to a non-localhost host. ' +
          'This combination exposes data in transit. Use HTTPS or connect to a local database.',
      );
    }
  }

  // Warn if TWO_FACTOR_ENCRYPTION_KEY is not set (falls back to SESSION_SECRET)
  if (!data.TWO_FACTOR_ENCRYPTION_KEY && data.NODE_ENV === 'production') {
    logger.warn(
      'TWO_FACTOR_ENCRYPTION_KEY not set. Falling back to SESSION_SECRET for 2FA encryption. Set a dedicated key for better key separation.',
    );
  }

  return data;
}

export const config = loadConfig();

export const isProduction = config.NODE_ENV === 'production';
export const isDevelopment = config.NODE_ENV === 'development';
export const isTest = config.NODE_ENV === 'test';

export const smtpConfigured =
  Boolean(config.SMTP_HOST) && Boolean(config.SMTP_USER) && Boolean(config.SMTP_PASS);

export const gmailConfigured = Boolean(config.GMAIL_USERNAME) && Boolean(config.GMAIL_PASSWORD);

/** Whether any email provider is properly configured and ready to send. */
export const emailConfigured = config.EMAIL_PROVIDER === 'gmail' ? gmailConfigured : smtpConfigured;

/** Dedicated key for 2FA TOTP secret encryption. Falls back to SESSION_SECRET for backward compatibility. */
export const twoFactorEncryptionKey = config.TWO_FACTOR_ENCRYPTION_KEY ?? config.SESSION_SECRET;

export type { EnvConfig };
