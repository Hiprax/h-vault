import { httpErrors } from '@hiprax/errors';
import { config } from '../../config/index.js';
import { createS3Provider, type S3StorageOptions } from './s3Provider.js';
import type { StorageProvider } from './types.js';

/**
 * The document store's one entry point into object storage.
 *
 * Everything that needs storage calls `getStorage()`; nothing constructs a
 * provider itself. That gives three properties worth having:
 *
 *   * ONE client per process, so a thirteen-part upload reuses one keep-alive
 *     connection pool instead of building thirteen;
 *   * ONE place the configuration is read, so an operator's settings cannot be
 *     interpreted two ways;
 *   * ONE module the unit tier mocks. `services/storage/index.js` is the seam the
 *     server suite replaces with an in-memory double, which is why the provider
 *     construction lives behind a function rather than at module scope: a client
 *     built on import would be built even in the suites that never touch storage.
 */

/**
 * Memoised provider. `undefined` until the first call, and never reset: the
 * configuration it is built from is read once at boot and cannot change while the
 * process runs.
 */
let provider: StorageProvider | undefined;

/**
 * Reads the four connection variables and narrows them, or reports that storage is
 * not configured.
 *
 * This is the NARROWING counterpart of `storageConfigured` in `config/index.ts`,
 * not a second decision: both are the conjunction of exactly these four variables
 * being set, and `loadConfig` has already normalised a partial set to none (and
 * refused to boot on one in production). It is written as a resolver rather than as
 * a `storageConfigured` check followed by four non-null assertions because the
 * assertions would be unchecked claims, while this returns a value whose type
 * proves the claim.
 *
 * Exported for its own unit test, which is not a testability fig leaf: a PARTIAL
 * set is unreachable through configuration, because `loadConfig` refuses one in
 * production and normalises it to none everywhere else, so calling this directly is
 * the only way to prove it refuses each missing value on its own. `getStorage` is
 * the only production caller.
 */
export function resolveStorageOptions(): S3StorageOptions | undefined {
  const {
    S3_ENDPOINT: endpoint,
    S3_BUCKET: bucket,
    S3_ACCESS_KEY_ID: accessKeyId,
    S3_SECRET_ACCESS_KEY: secretAccessKey,
  } = config;

  if (
    endpoint === undefined ||
    bucket === undefined ||
    accessKeyId === undefined ||
    secretAccessKey === undefined
  ) {
    return undefined;
  }

  return {
    endpoint,
    bucket,
    accessKeyId,
    secretAccessKey,
    region: config.S3_REGION,
    forcePathStyle: config.S3_FORCE_PATH_STYLE,
  };
}

/**
 * The configured storage provider, built on first use.
 *
 * Throws 503 when storage is not configured. Every document route sits behind a
 * `requireStorage` guard that answers 503 before a controller runs, and the
 * garbage-collection job checks the same flag before it starts, so reaching this
 * throw means one of those guards is missing: the status is the honest answer
 * either way, and it keeps a misconfigured deployment from reporting a 500 that
 * looks like a defect in the storage engine.
 */
export function getStorage(): StorageProvider {
  if (provider !== undefined) return provider;

  const options = resolveStorageOptions();
  if (options === undefined) {
    throw httpErrors.serviceUnavailable('Object storage is not configured');
  }

  provider = createS3Provider(options);
  return provider;
}
