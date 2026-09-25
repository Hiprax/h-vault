import { z } from 'zod';
import { PAGINATION_DEFAULTS, ROW_ID_NONCE_PATTERN } from '../constants/index.js';

export const objectIdSchema = z
  .string()
  .regex(/^[0-9a-fA-F]{24}$/, 'Invalid ObjectId')
  .transform((v) => v.toLowerCase());

export const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(PAGINATION_DEFAULTS.PAGE),
  limit: z.coerce
    .number()
    .int()
    .min(1)
    .max(PAGINATION_DEFAULTS.MAX_LIMIT)
    .default(PAGINATION_DEFAULTS.LIMIT),
});

/**
 * The vault-key generation the caller believes it wrapped this request's
 * ciphertext under — a CLAIM the client makes, never an echo of something the
 * server said.
 *
 * `User.vaultKeyVersion` is `$inc`ed once per completed vault-key rotation, so
 * it names which vault key an account is currently on. A second session that
 * was holding the previous key can still decrypt, and therefore still happily
 * encrypt, for as long as it has not noticed the rotation; the row it writes is
 * not in the set the rotation re-encrypted, so once the new key commits that row
 * is permanently undecryptable and the session that wrote it is never told.
 * Naming the generation turns that silent, unrecoverable loss into a retryable
 * 409 carrying the current number.
 *
 * OPTIONAL ON THE WIRE, AND THAT IS NOT THE SAME AS OPTIONAL IN EFFECT. Making
 * it required would be a breaking request-schema change, which the release this
 * lands in does not account for. The server closes the gap at the other end:
 * `assertVaultKeyVersion` (server `utils/controllerHelpers.ts`) refuses a write
 * that omits the field whenever the account has rotated at least once, so the
 * only caller the omission still serves is one whose account has never rotated
 * and therefore cannot be holding a superseded key.
 *
 * `completeDocumentUploadSchema` deliberately does NOT use this: a document
 * completion is a newer contract with no compatibility debt, so its version is
 * required outright.
 */
export const optionalVaultKeyVersionSchema = z.number().int().min(0).optional();

/**
 * The nonce a create sends so that both sides can derive the new row's id before
 * it exists (`deriveRowId`; the layout is on `ROW_ID_DERIVATION_PREFIX`).
 *
 * Lower-case only, with NO transform, unlike `objectIdSchema`: the nonce is hashed
 * as sent, and the browser has already derived the id from its own spelling, so a
 * server that normalised it would store the row under an id the browser did not
 * seal to. Optional on every create, which keeps the addition non-breaking; a
 * create without one gets a server-minted id, exactly as before.
 */
export const rowIdNonceSchema = z.string().regex(ROW_ID_NONCE_PATTERN, 'Invalid row id nonce');
