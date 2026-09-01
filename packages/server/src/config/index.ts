import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import dotenv from 'dotenv';
import { z } from 'zod';
import { MAX_DOCUMENT_EXT_LENGTH } from '@hvault/shared';
import { createModuleLogger } from '../utils/logger.js';

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

const logger = createModuleLogger('config');

/**
 * Upper bound for a numeric `TRUST_PROXY` hop count. Express treats a numeric
 * `trust proxy` value as "trust the n-th hop from the front", so an unbounded
 * value (`Infinity`, `1e9`, etc.) trusts the entire client-supplied
 * `X-Forwarded-For` chain — letting a client spoof `req.ip` and defeat the
 * IP-keyed rate limiting and audit-IP integrity the app relies on. Real
 * deployments sit behind at most a couple of proxies; 10 is a generous ceiling.
 */
const MAX_TRUST_PROXY_HOPS = 10;

/**
 * Whether `hostname` names a host that ciphertext and bucket credentials can
 * reach without crossing a network in the clear: a loopback address, an RFC 1918
 * private address, or a single DNS label, which in practice is a container or
 * service name resolved by the deployment's own DNS (`hvault-s3`). A dotted
 * public name is none of those, and on a plain `http://` endpoint it would put
 * every byte of a document and the credentials that fetch it on the wire.
 *
 * `localhost` is admitted by the single-label rule rather than by a case of its
 * own; `::1` needs one, because its colons are not a DNS label.
 */
function isLocalOrPrivateStorageHost(hostname: string): boolean {
  // `new URL('http://[::1]:3900').hostname` keeps the brackets.
  const host = hostname.replace(/^\[/, '').replace(/\]$/, '').toLowerCase();
  if (host === '::1') return true;
  // 127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16.
  if (/^127\.\d+\.\d+\.\d+$/.test(host)) return true;
  if (/^10\.\d+\.\d+\.\d+$/.test(host)) return true;
  if (/^192\.168\.\d+\.\d+$/.test(host)) return true;
  // 172.16.0.0/12 is 172.16 THROUGH 172.31 only: 172.32.x.x is public address
  // space, and treating the whole of 172.x as private is the classic version of
  // this mistake.
  const secondOctet = /^172\.(\d{1,3})\.\d+\.\d+$/.exec(host)?.[1];
  if (secondOctet !== undefined) {
    const octet = Number(secondOctet);
    if (octet >= 16 && octet <= 31) return true;
  }
  // A single label has no dot, so it cannot be a public name. The underscore is
  // admitted deliberately: it is not legal in a DNS hostname, but Compose service
  // names may contain one and the engine's embedded DNS resolves them, so refusing
  // it would contradict the message this rule prints. Written as ONE quantifier
  // plus an explicit final-character check rather than the tidier
  // `^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$`: a quantifier nested inside an optional
  // group is the shape `security/detect-unsafe-regex` rejects, and this one is
  // linear by construction.
  return /^[a-z0-9][a-z0-9_-]*$/.test(host) && !host.endsWith('-');
}

/**
 * The hostname of `value`, or undefined when it is not a parseable URL. A string
 * that fails `z.url()` still reaches the cross-field refines (Zod runs them on
 * the partially validated object), and `new URL('http://')` throws, so the
 * production endpoint rule has to survive input the field check has already
 * rejected.
 */
function urlHostname(value: string): string | undefined {
  try {
    return new URL(value).hostname;
  } catch {
    return undefined;
  }
}

/**
 * Whether an `S3_ENDPOINT` is acceptable for a PRODUCTION deployment. `https://`
 * always is. A plain `http://` one is accepted only for a host the traffic never
 * leaves (see `isLocalOrPrivateStorageHost`), which is what makes the in-stack
 * `http://hvault-s3:3900` work without asking an operator to terminate TLS
 * between two containers on an internal network.
 *
 * An unparseable value ABSTAINS rather than failing here: the field's own URL
 * check already reports it, and a second issue about schemes would only obscure
 * the first.
 */
function isProductionStorageEndpoint(endpoint: string): boolean {
  if (/^https:\/\//i.test(endpoint)) return true;
  const hostname = urlHostname(endpoint);
  if (hostname === undefined) return true;
  return isLocalOrPrivateStorageHost(hostname);
}

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

    // Session lifetimes, as integer day counts (no duration-string parser exists
    // in this codebase, so days are used directly). REFRESH_TOKEN_DAYS reproduces
    // the former hardcoded 7-day refresh horizon exactly, so standard sessions are
    // unchanged. REFRESH_TOKEN_REMEMBER_DAYS is the horizon for an opt-in
    // "remember me" session, and TRUSTED_DEVICE_DAYS is how long a recognised
    // device may skip the 2FA step. The two cross-field refines below enforce
    // REMEMBER >= DAYS and TRUSTED >= REMEMBER, rejecting a nonsensical config
    // (remember-me shorter than a normal session, or a 2FA-skip window outliving
    // the session it serves) at boot rather than applying it silently.
    REFRESH_TOKEN_DAYS: z.coerce.number().int().min(1).max(90).default(7),
    REFRESH_TOKEN_REMEMBER_DAYS: z.coerce.number().int().min(1).max(365).default(30),
    TRUSTED_DEVICE_DAYS: z.coerce.number().int().min(1).max(365).default(30),

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

    // Rate limiting has no env knobs, deliberately. `RATE_LIMIT_WINDOW_MS` and
    // `RATE_LIMIT_MAX` used to be declared here, defaulted, documented in
    // `.env.example` and asserted by the config tests — and read by absolutely
    // nothing: every limiter in `middleware/rateLimiter.ts` carries its own
    // window and ceiling, each sized against the specific traffic it bounds.
    // Config an operator can set and that silently does nothing is worse than no
    // config, so they were removed rather than left inert. The per-tier numbers
    // that ARE tunable live in `@hvault/shared` (`LOGIN_RATE_LIMIT_*`); do not
    // reintroduce a global pair here.

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

    // Document store (optional object storage)
    //
    // The four CONNECTION variables are validated ALL-OR-NONE in `loadConfig`
    // below, beside the SMTP check and for the same reason: all four set enables
    // the document store, none set disables it, and a partial set is refused in
    // production. Each one normalises an empty assignment to undefined BEFORE its
    // length check, because `.env.example` ships the two credentials empty (a
    // placeholder access key would be a working credential for the in-stack
    // bucket), so `S3_ACCESS_KEY_ID=` has to read as "unset" rather than fail
    // `.min(8)` and abort boot.
    //
    // `S3_RPC_SECRET` is deliberately NOT declared here. It is the storage
    // engine's own cluster RPC secret, read by the storage container and never by
    // this process, so declaring it would be exactly the inert configuration this
    // schema deleted `RATE_LIMIT_MAX` for. It lives in `.env.example` and the
    // README's Compose table instead.
    S3_ENDPOINT: z.preprocess(
      (v) => (v === '' ? undefined : v),
      z
        .url()
        .refine((u) => /^https?:\/\//i.test(u), {
          message: 'S3_ENDPOINT must use http:// or https://',
        })
        .optional(),
    ),
    // Matches the region the committed storage configuration serves, so the
    // default works untouched against the in-stack engine.
    S3_REGION: z.preprocess(
      (v) => (v === '' ? undefined : v),
      z.string().min(1).default('us-east-1'),
    ),
    S3_BUCKET: z.preprocess((v) => (v === '' ? undefined : v), z.string().min(1).optional()),
    // min(8) is MEASURED against the storage engine, not guessed: an access key id
    // shorter than 8 characters makes it refuse to boot, with a message no
    // operator would connect back to their `.env`. Failing here instead names the
    // variable.
    S3_ACCESS_KEY_ID: z.preprocess((v) => (v === '' ? undefined : v), z.string().min(8).optional()),
    S3_SECRET_ACCESS_KEY: z.preprocess(
      (v) => (v === '' ? undefined : v),
      z.string().min(16).optional(),
    ),
    // Path-style addressing, and it defaults to TRUE unlike the other boolean
    // flags in this schema: virtual-host style puts the bucket in the hostname,
    // which needs DNS the in-stack service does not have. Only the explicit string
    // `false` turns it off, so an empty assignment reads as unset and keeps the
    // default.
    S3_FORCE_PATH_STYLE: z
      .enum(['true', 'false', ''])
      .optional()
      .transform((val) => val !== 'false'),
    // Largest document a client may upload, in MB. Bounded 1..1024 rather than
    // left open: nothing tests a multi-gigabyte transfer, a value above the
    // per-user quota below can never be accepted anyway, and each document costs
    // one part per 8 MiB, so a four-figure part budget is not a size this design
    // is prepared to stand behind.
    MAX_DOCUMENT_SIZE_MB: z.coerce.number().int().min(1).max(1024).default(100),
    // Per-user storage quota, in MB, counted over committed documents plus the
    // declared size of uploads still in flight. The refine below requires it to be
    // at least MAX_DOCUMENT_SIZE_MB, so a configuration cannot advertise a size cap
    // it must always reject.
    DOCUMENT_STORAGE_QUOTA_MB_PER_USER: z.coerce.number().int().min(1).max(1_048_576).default(2048),
    // How long a staging upload row survives before its TTL index removes it.
    // Bounded at a week: the row pins quota against the user's budget, and the
    // stored object and the engine-side multipart upload are only reclaimed after
    // it expires.
    DOCUMENT_UPLOAD_TTL_HOURS: z.coerce.number().int().min(1).max(168).default(24),
    // Comma-separated extension allowlist for uploads, empty meaning every type is
    // allowed. It is ADVISORY and enforced in the browser: the server receives
    // ciphertext and cannot see a filename, so it could not enforce this even if it
    // wanted to. Normalised here (trimmed, lowercased, leading dots removed,
    // blanks dropped, over-long ones dropped, duplicates collapsed) so `GET /config`
    // publishes one shape and the client never has to parse the operator's
    // punctuation.
    //
    // The LENGTH filter is load-bearing and is not about tidiness. This list is
    // published by `GET /config`, whose envelope the browser parses with
    // `publicConfigResponseSchema`, and that schema declares each entry
    // `z.string().max(MAX_DOCUMENT_EXT_LENGTH)` — the same bound the sealed
    // metadata blob's own `ext` field carries. One over-long entry therefore fails
    // the parse of the WHOLE envelope, and `getFileEncryptionMaxBytes()` answers a
    // failed parse by falling back to its shared-constant default: a typo in a
    // DOCUMENTS variable would silently change the File Encryption tool's size cap,
    // in a feature that has nothing to do with documents. An entry no client could
    // ever match is dropped here, loudly, instead.
    DOCUMENT_ALLOWED_EXTENSIONS: z
      .string()
      .optional()
      .transform((v) => {
        const normalised = (v ?? '')
          .split(',')
          .map((ext) => ext.trim().toLowerCase().replace(/^\.+/, ''))
          .filter((ext) => ext.length > 0);
        const kept = [
          ...new Set(normalised.filter((ext) => ext.length <= MAX_DOCUMENT_EXT_LENGTH)),
        ];
        const dropped = [
          ...new Set(normalised.filter((ext) => ext.length > MAX_DOCUMENT_EXT_LENGTH)),
        ];
        if (dropped.length > 0) {
          logger.warn(
            `DOCUMENT_ALLOWED_EXTENSIONS: dropped ${String(dropped.length)} entry/entries longer ` +
              `than ${String(MAX_DOCUMENT_EXT_LENGTH)} characters. No file extension is that long, ` +
              `and publishing one would make GET /config unparseable for every client. First ` +
              `dropped entry begins: ${dropped[0]?.slice(0, MAX_DOCUMENT_EXT_LENGTH) ?? ''}`,
          );
        }
        return kept;
      }),

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
  })
  .refine((data) => data.REFRESH_TOKEN_REMEMBER_DAYS >= data.REFRESH_TOKEN_DAYS, {
    // "Remember me" must never shorten a session relative to a normal login.
    message: 'REFRESH_TOKEN_REMEMBER_DAYS cannot be less than REFRESH_TOKEN_DAYS',
    path: ['REFRESH_TOKEN_REMEMBER_DAYS'],
  })
  .refine((data) => data.TRUSTED_DEVICE_DAYS >= data.REFRESH_TOKEN_REMEMBER_DAYS, {
    // The 2FA-skip window must not outlive the remembered session it exists to serve.
    message: 'TRUSTED_DEVICE_DAYS cannot be less than REFRESH_TOKEN_REMEMBER_DAYS',
    path: ['TRUSTED_DEVICE_DAYS'],
  })
  .refine((data) => data.DOCUMENT_STORAGE_QUOTA_MB_PER_USER >= data.MAX_DOCUMENT_SIZE_MB, {
    // A quota below the size cap accepts an upload at the door and refuses it at
    // the quota check, every time, for every user.
    message: 'DOCUMENT_STORAGE_QUOTA_MB_PER_USER cannot be less than MAX_DOCUMENT_SIZE_MB',
    path: ['DOCUMENT_STORAGE_QUOTA_MB_PER_USER'],
  })
  .refine(
    (data) =>
      data.NODE_ENV !== 'production' ||
      data.S3_ENDPOINT === undefined ||
      isProductionStorageEndpoint(data.S3_ENDPOINT),
    {
      // Documents are ciphertext, but the credentials that fetch them and the
      // object keys that name them are not, so a public endpoint on plain HTTP is
      // refused. An in-stack service name, a loopback address and an RFC 1918
      // address are all accepted, because that traffic never leaves the host.
      message:
        'S3_ENDPOINT must use https:// in production unless it points at a loopback address, an RFC 1918 private address or a single-label host (an in-stack service name)',
      path: ['S3_ENDPOINT'],
    },
  );

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

  // Validate the object-storage fields are either all set or all empty. The
  // document store is an OPTIONAL feature, exactly like SMTP: with none of these
  // set it is simply off, and an existing deployment upgrades without configuring
  // anything. A PARTIAL set is the dangerous case, because it LOOKS configured:
  // the feature would advertise itself through GET /config, the client would show
  // the section, and every upload would fail at the first storage call. So it
  // throws in production and normalises to unconfigured in development.
  //
  // There is deliberately no "storage not configured" warning to match the SMTP
  // one: email is effectively required, documents are not, and a warning on every
  // boot of a deployment that does not want them is noise that trains an operator
  // to ignore the log.
  const storageFields = [
    data.S3_ENDPOINT,
    data.S3_BUCKET,
    data.S3_ACCESS_KEY_ID,
    data.S3_SECRET_ACCESS_KEY,
  ];
  const storageSet = storageFields.filter(Boolean).length;
  if (storageSet > 0 && storageSet < storageFields.length) {
    if (data.NODE_ENV === 'production') {
      throw new Error(
        'Object storage configuration is incomplete. Set all of S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY or none.',
      );
    }
    logger.warn(
      'Object storage configuration is incomplete. Set all of S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY or none. The document store will be disabled.',
    );
    data.S3_ENDPOINT = undefined;
    data.S3_BUCKET = undefined;
    data.S3_ACCESS_KEY_ID = undefined;
    data.S3_SECRET_ACCESS_KEY = undefined;
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

/**
 * Whether the optional document store is configured, and therefore whether the
 * feature is on. All four connection variables are required together, so this is
 * false when nothing is set AND when only some of it is: the group check above
 * normalises a partial set to none, because a half-configured storage must never
 * half-enable a feature whose availability the client learns from GET /config.
 */
export const storageConfigured =
  Boolean(config.S3_ENDPOINT) &&
  Boolean(config.S3_BUCKET) &&
  Boolean(config.S3_ACCESS_KEY_ID) &&
  Boolean(config.S3_SECRET_ACCESS_KEY);

/** Whether any email provider is properly configured and ready to send. */
export const emailConfigured = config.EMAIL_PROVIDER === 'gmail' ? gmailConfigured : smtpConfigured;

/** Dedicated key for 2FA TOTP secret encryption. Falls back to SESSION_SECRET for backward compatibility. */
export const twoFactorEncryptionKey = config.TWO_FACTOR_ENCRYPTION_KEY ?? config.SESSION_SECRET;

export type { EnvConfig };
