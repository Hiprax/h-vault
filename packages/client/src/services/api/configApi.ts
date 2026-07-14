/**
 * Public (unauthenticated) configuration API service.
 *
 * Surfaces the operator-tunable, non-sensitive values the client needs before
 * (or independent of) authentication — currently only the File Encryption
 * tool's client-side size cap.
 *
 * Account-agnostic note: the File Encryption tool is zero-knowledge — nothing is
 * ever uploaded, so the server cannot enforce this limit. It is a client-side
 * guardrail the server merely *advertises*. This request carries no file bytes
 * and no password; it is a plain read-only GET through the shared axios client
 * (which may attach the session Bearer per existing convention).
 */

import type { AxiosResponse } from 'axios';
import type { ApiResponse, PublicConfig } from '@hvault/shared';
import { MAX_FILE_ENCRYPTION_SIZE_MB, publicConfigResponseSchema } from '@hvault/shared';
import { api } from './client.js';

const BYTES_PER_MB = 1024 * 1024;

/** The shared-constant fallback expressed in bytes. */
const FALLBACK_MAX_BYTES = MAX_FILE_ENCRYPTION_SIZE_MB * BYTES_PER_MB;

/**
 * Fetch the public server configuration (`GET /config`).
 *
 * Typed to the standard `{ success, data }` envelope wrapping `PublicConfig`.
 */
export function getPublicConfigApi(): Promise<AxiosResponse<ApiResponse<PublicConfig>>> {
  return api.get('/config');
}

// Module-level memo: the first resolution (server value OR fallback) is cached
// so repeated callers — e.g. every size check as the user picks a file — share
// a single network round-trip. A rejected fetch or a malformed response never
// propagates to the caller: it resolves to the shared-constant fallback, and
// that outcome is cached too, so a transient outage cannot re-hit the endpoint
// on every interaction.
let cachedMaxBytes: Promise<number> | null = null;

/**
 * Resolve the File Encryption size cap in bytes, cached for the tab's lifetime.
 *
 * Reads `fileEncryption.maxSizeMB` from `GET /config` on first call. On any
 * failure — network error, non-2xx, or a response that fails the shared
 * `publicConfigResponseSchema` (e.g. a missing/negative `maxSizeMB`) — it falls
 * back to `MAX_FILE_ENCRYPTION_SIZE_MB` from `@hvault/shared`. Never
 * rejects; always resolves to a positive byte count.
 */
export function getFileEncryptionMaxBytes(): Promise<number> {
  if (cachedMaxBytes) return cachedMaxBytes;

  cachedMaxBytes = (async (): Promise<number> => {
    try {
      const res = await getPublicConfigApi();
      const parsed = publicConfigResponseSchema.safeParse(res.data);
      if (!parsed.success) return FALLBACK_MAX_BYTES;
      return parsed.data.data.fileEncryption.maxSizeMB * BYTES_PER_MB;
    } catch {
      return FALLBACK_MAX_BYTES;
    }
  })();

  return cachedMaxBytes;
}
