/**
 * Public (unauthenticated) configuration API service.
 *
 * Surfaces the operator-tunable, non-sensitive values the client needs before
 * (or independent of) authentication: the File Encryption tool's client-side size
 * cap, and whether the document store exists on this server at all.
 *
 * Account-agnostic note: the File Encryption tool is zero-knowledge — nothing is
 * ever uploaded, so the server cannot enforce its limit. It is a client-side
 * guardrail the server merely *advertises*. This request carries no file bytes
 * and no password; it is a plain read-only GET through the shared axios client
 * (which may attach the session Bearer per existing convention).
 *
 * The document store's size cap and extension allowlist are advisory in exactly
 * the same sense and for a sharper reason: the server receives ciphertext, so it
 * cannot see a file's type or its unencrypted length, and the docs say so.
 *
 * The readers below each validate the ONE block they act on, through their own
 * `.pick()` narrowing of the single full shape. Neither validates the other's
 * block, because one envelope carries two unrelated features and a strict read of
 * the whole document would let a bad value in either one silently disable the
 * other.
 *
 * The document store has TWO readers over that one narrowing, and the difference
 * between them is the difference between deciding what to DISPLAY and deciding
 * what to DO. {@link getDocumentsConfig} is memoised and never rejects, which is
 * right for a navigation entry. {@link readDocumentsConfigFresh} never consults the
 * memo and answers `null` when the server did not say, which is what the vault-key
 * rotation needs, because for it "I could not tell" and "there are none" are not
 * the same answer.
 */

import type { AxiosResponse } from 'axios';
import type { ApiResponse, PublicConfig } from '@hvault/shared';
import {
  MAX_FILE_ENCRYPTION_SIZE_MB,
  documentsConfigResponseSchema,
  fileEncryptionConfigResponseSchema,
  publicConfigDataSchema,
} from '@hvault/shared';
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
 * failure — network error, non-2xx, or a response that fails
 * `fileEncryptionConfigResponseSchema` (e.g. a missing/negative `maxSizeMB`) — it
 * falls back to `MAX_FILE_ENCRYPTION_SIZE_MB` from `@hvault/shared`. Never
 * rejects; always resolves to a positive byte count.
 *
 * The NARROW schema, deliberately, and not the full `publicConfigResponseSchema`:
 * the same envelope also carries the document store's block, and validating a
 * block this function does not read would let one bad value there — an operator's
 * mistyped extension, a field a newer server adds — silently revert this cap to
 * its default. {@link getDocumentsConfig} and {@link readDocumentsConfigFresh}
 * narrow the other way for the mirror reason.
 */
export function getFileEncryptionMaxBytes(): Promise<number> {
  if (cachedMaxBytes) return cachedMaxBytes;

  cachedMaxBytes = (async (): Promise<number> => {
    try {
      const res = await getPublicConfigApi();
      const parsed = fileEncryptionConfigResponseSchema.safeParse(res.data);
      if (!parsed.success) return FALLBACK_MAX_BYTES;
      return parsed.data.data.fileEncryption.maxSizeMB * BYTES_PER_MB;
    } catch {
      return FALLBACK_MAX_BYTES;
    }
  })();

  return cachedMaxBytes;
}

// ---------------------------------------------------------------------------
// The document store's advertisement
// ---------------------------------------------------------------------------

/**
 * What the server says about the document store: the feature flag and, when it is
 * on, the numbers the client needs to guard an upload before reading a byte.
 *
 * Derived from the SCHEMA's output rather than from `PublicConfig`, which
 * describes the same block. The two are not interchangeable under
 * `exactOptionalPropertyTypes`: the interface's optional fields are `?: number`
 * ("absent, or a number"), while Zod's `.optional()` produces
 * `?: number | undefined` ("absent, or a number, or explicitly undefined"), and
 * this value comes straight out of a parse. Restating the shape by hand would be
 * a second definition of the block that could drift from the one the wire is
 * validated against.
 */
export type DocumentsConfig = NonNullable<
  ReturnType<typeof publicConfigDataSchema.parse>['documents']
>;

/**
 * The answer for a server that cannot offer the feature — an older one that
 * predates it, or this one with no object storage configured.
 *
 * Frozen because it is a module-level singleton handed to every caller: a caller
 * that mutated it would change what every later caller sees, and the failure would
 * surface as a feature that is enabled for a reason nobody can find.
 */
const DOCUMENTS_DISABLED: DocumentsConfig = Object.freeze({ enabled: false });

let cachedDocumentsConfig: Promise<DocumentsConfig> | null = null;

/**
 * Resolve the document store's configuration, cached for the tab's lifetime.
 *
 * Memoised exactly like {@link getFileEncryptionMaxBytes}, and for the same
 * reason: every caller that asks "is this feature available" — the navigation
 * entry, the page, the upload panel's size check — shares one round trip, and a
 * transient outage cannot re-hit the endpoint on every interaction because the
 * FALLBACK is cached too. It never rejects.
 *
 * That cached fallback is a DISPLAY decision and nothing more: the cost of getting
 * it wrong during an outage is a navigation entry that is missing until the tab is
 * reloaded. Nothing that acts on the answer may read it — see
 * {@link readDocumentsConfigFresh}, which is also the only thing that can replace
 * this memo once it holds one.
 *
 * Three server states collapse into two answers here, and that is the whole
 * contract: the `documents` block ABSENT (a server older than the feature) and the
 * block present with `enabled: false` (this server, storage unconfigured) both
 * resolve to `{ enabled: false }`, because the client does the same thing in each
 * case. The two are still distinguishable ON THE WIRE, which is what lets an
 * operator tell "my server is old" from "my storage is unconfigured" — two states
 * with completely different fixes.
 *
 * `documentsConfigResponseSchema`, the mirror of the narrowing
 * `getFileEncryptionMaxBytes` uses, and narrow for the same reason pointing the
 * other way: `fileEncryption` is a REQUIRED field of the full envelope, so
 * validating the whole document here would hide the document store whenever that
 * unrelated block was malformed. Narrow is not lenient — within the `documents`
 * block this is exactly as strict as the full schema, because this is the reader
 * that acts on it and a malformed block has to be refused by the code that would
 * otherwise compare a byte count against something that is not a number.
 */
export function getDocumentsConfig(): Promise<DocumentsConfig> {
  if (cachedDocumentsConfig) return cachedDocumentsConfig;

  cachedDocumentsConfig = (async (): Promise<DocumentsConfig> => {
    try {
      const res = await getPublicConfigApi();
      const parsed = documentsConfigResponseSchema.safeParse(res.data);
      if (!parsed.success) return DOCUMENTS_DISABLED;
      return parsed.data.data.documents ?? DOCUMENTS_DISABLED;
    } catch {
      return DOCUMENTS_DISABLED;
    }
  })();

  return cachedDocumentsConfig;
}

/**
 * Read the document store's configuration WITHOUT the memo, and say so when the
 * server did not answer.
 *
 * Three answers rather than {@link getDocumentsConfig}'s two, and the third is the
 * whole point. `{ enabled: false }` is a DETERMINATE answer — the `documents` block
 * absent means a server older than the feature, the block present saying
 * `enabled: false` means this server has no object storage configured, and in both
 * cases the account provably holds no documents. `null` means the server did not
 * tell: the request failed, or its answer did not satisfy the schema. Collapsing
 * that into "there are none" is what the memoised reader does, and it is safe only
 * because its consumers merely decide what to show.
 *
 * The vault-key rotation is not one of those consumers. It uses this answer to
 * decide whether to enumerate and re-wrap every document key the account holds, and
 * a cached failure would make it commit a payload naming NO documents — which the
 * server refuses with a completeness 409 whose diagnosis blames a pending purge or
 * absent storage, neither of which happened. One transient `/config` failure, on
 * some other page, minutes earlier, must not be able to reach that decision, so
 * this reader consults no memo and writes no failure into one.
 *
 * A SUCCESSFUL read does seed the memo, which is a repair rather than a new
 * coupling: the next consumer to ASK gets the truth instead of the fallback an
 * outage left behind. It is not a broadcast — a component that already holds an
 * answer keeps it until it asks again, so the navigation entry, whose effect runs
 * once for the life of the app shell, is unaffected until that shell remounts. A
 * failed read leaves the memo exactly as it was: this reader's failure belongs to
 * its caller and must not become everyone else's.
 *
 * Unlike its neighbours this one is not cached, so it costs a round trip per call.
 * That is affordable precisely because its caller is rare and consequential.
 */
export async function readDocumentsConfigFresh(): Promise<DocumentsConfig | null> {
  let resolved: DocumentsConfig | null = null;
  try {
    const res = await getPublicConfigApi();
    const parsed = documentsConfigResponseSchema.safeParse(res.data);
    if (parsed.success) resolved = parsed.data.data.documents ?? DOCUMENTS_DISABLED;
  } catch {
    return null;
  }
  if (resolved === null) return null;

  cachedDocumentsConfig = Promise.resolve(resolved);
  return resolved;
}
