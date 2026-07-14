import type winston from 'winston';

/**
 * Emits a warning when Swagger UI is enabled in production mode.
 *
 * Swagger at `/api/docs` and `/api/v1/docs.json` is unauthenticated and exposes
 * the full API surface. Enabling it in production is a legitimate but risky
 * configuration choice that must be surfaced in operator logs so it can never
 * be left on by accident after a debugging session.
 *
 * Extracted from `app.ts` so the behavior can be unit-tested without
 * re-importing the entire Express application (which has side effects like
 * mongoose model registration and rate-limiter store initialization).
 */
export function warnIfSwaggerEnabledInProduction(
  config: { NODE_ENV: string; ENABLE_SWAGGER: boolean },
  logger: Pick<winston.Logger, 'warn'>,
): boolean {
  if (config.NODE_ENV !== 'production' || !config.ENABLE_SWAGGER) {
    return false;
  }

  logger.warn(
    'Swagger UI is ENABLED in production (ENABLE_SWAGGER=true). ' +
      'API documentation is publicly accessible at /api/docs and /api/v1/docs.json. ' +
      'This exposes the full API surface to unauthenticated clients — ensure this is intentional.',
  );
  return true;
}
