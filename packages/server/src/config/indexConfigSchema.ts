/**
 * The SHAPE of the configuration the index bootstrap needs, and nothing secret.
 *
 * Side-effect free on purpose: it validates nothing when it loads. The parsed
 * values live in `indexConfig.ts`, which the index bootstrap and the TTL models
 * read; `config/index.ts` composes this shape into the application schema and
 * imports it from HERE, so a misconfigured server still reports every issue of
 * its environment in one list (from the application schema) rather than only
 * the index keys first. See `indexConfig.ts` for why the subset exists (F-20).
 */
import { z } from 'zod';

export const INDEX_CONFIG_SHAPE = {
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

  // Database
  MONGODB_URI: z.string().min(1).default('mongodb://localhost:27017/hvault'),
  MONGO_MAX_POOL_SIZE: z.coerce.number().int().min(1).max(100).default(10),
  MONGO_MIN_POOL_SIZE: z.coerce.number().int().min(0).max(50).default(2),

  // Backup
  BACKUP_RETENTION_DAYS: z.coerce.number().int().min(1).max(365).default(30),

  // Audit
  AUDIT_LOG_RETENTION_DAYS: z.coerce.number().int().min(1).max(3650).default(365),

  // Breach range cache (persistent, cross-account HIBP range cache)
  // On-demand (`source: 'hibp'`) entries are re-fetched once older than this
  // many days; seed-imported entries are exempt (refreshed by re-running the
  // seed). The HIBP corpus is additive, so a stale entry can only miss a very
  // recently added breach, never wrongly clear a known one — set 7 for a
  // stricter freshness posture.
  BREACH_CACHE_TTL_DAYS: z.coerce.number().int().min(1).max(365).default(30),
};

type IndexConfigKey = keyof typeof INDEX_CONFIG_SHAPE;

/** Every key the bootstrap reads; the compose file passes exactly these (tested). */
export const INDEX_CONFIG_KEYS = Object.freeze(
  Object.keys(INDEX_CONFIG_SHAPE),
) as readonly IndexConfigKey[];

/**
 * An inverted pool configuration (min > max) otherwise passes per-field
 * validation and only fails at MongoDB connect time, masked behind the retry
 * loop. Exported so the application schema applies the same rule.
 */
export function poolSizesAreOrdered(data: {
  MONGO_MIN_POOL_SIZE: number;
  MONGO_MAX_POOL_SIZE: number;
}): boolean {
  return data.MONGO_MIN_POOL_SIZE <= data.MONGO_MAX_POOL_SIZE;
}

export const POOL_SIZE_ORDER_ISSUE = {
  message: 'MONGO_MIN_POOL_SIZE cannot be greater than MONGO_MAX_POOL_SIZE',
  path: ['MONGO_MIN_POOL_SIZE'],
};

/**
 * The ONE refusal both configurations throw: every issue on its own line, under
 * the heading an operator searches the log for.
 */
export function invalidEnvironmentConfiguration(issues: readonly z.core.$ZodIssue[]): Error {
  const formatted = issues.map((issue) => `  ${issue.path.join('.')}: ${issue.message}`).join('\n');
  return new Error(`Invalid environment configuration:\n${formatted}`);
}

const indexConfigSchema = z
  .object(INDEX_CONFIG_SHAPE)
  .refine(poolSizesAreOrdered, POOL_SIZE_ORDER_ISSUE);

type IndexConfig = z.infer<typeof indexConfigSchema>;

/**
 * Parses an environment into the index configuration, refusing it with the same
 * message shape the application configuration uses.
 */
export function parseIndexConfig(env: Readonly<Record<string, string | undefined>>): IndexConfig {
  const result = indexConfigSchema.safeParse(env);
  if (!result.success) throw invalidEnvironmentConfiguration(result.error.issues);
  return result.data;
}
