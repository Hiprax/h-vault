/**
 * Reads the one refusal in this API that carries a number: the recoverable 409
 * a write earns when it names a vault-key generation the account has left
 * behind.
 *
 * ## Why it has its own module
 *
 * The server answers this refusal from six handlers across four controllers —
 * every write that seals NEW ciphertext under the vault key — plus the document
 * completion that established the pattern. Its readers are just as spread out:
 * the vault store, the documents store, the settings page's import and the
 * backup page's restore. It lived in `documentsApi.ts` while the completion was
 * its only source; keeping it there once it is the shared shape would have left
 * the vault store importing its refusal parser from the documents API, which is
 * how a second copy gets written instead.
 *
 * Deliberately dependency-free apart from Axios's own type guard: it is imported
 * by `stores/uiStore.ts`, and anything reaching the configured Axios instance
 * from there would close a cycle through `authStore`.
 *
 * ## Why it reads the number defensively
 *
 * Not every 409 is this one. A rotation currently in progress, a duplicate
 * folder name and a concurrent import are all answered with a bare 409 and no
 * `data`, and each has a different remedy. The discriminant is therefore the
 * PRESENCE of a non-negative integer `data.vaultKeyVersion` and never the
 * message — and a malformed one is treated as an ordinary conflict rather than
 * as generation zero, because zero is a meaningful answer ("this account has
 * never rotated") and must not be invented from a missing field.
 */

import { isAxiosError } from 'axios';

/**
 * The vault key generation a recoverable 409 reports, or `null` when the
 * rejection is anything else.
 */
export function staleVaultKeyVersion(error: unknown): number | null {
  if (!isAxiosError(error) || error.response?.status !== 409) return null;
  const data: unknown = error.response.data;
  if (typeof data !== 'object' || data === null || !('data' in data)) return null;
  const payload: unknown = data.data;
  if (typeof payload !== 'object' || payload === null || !('vaultKeyVersion' in payload)) {
    return null;
  }
  const version: unknown = payload.vaultKeyVersion;
  return typeof version === 'number' && Number.isInteger(version) && version >= 0 ? version : null;
}
