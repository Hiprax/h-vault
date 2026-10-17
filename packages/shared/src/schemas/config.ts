import { z } from '../zod.js';
import { MAX_DOCUMENT_EXT_LENGTH, REGISTRATION_MODES } from '../constants/index.js';

// Runtime validation for the public (unauthenticated) GET /config response.
// Mirrors the `PublicConfig` interface in `types/index.ts` and the success
// branch of the standard `{ success, data }` API envelope. Self-contained:
// depends only on zod and on the shared bounds, so it never references server-
// or client-only code.

/**
 * What the server advertises about the document store, in the three states the
 * client has to tell apart:
 *
 *  - the whole block is ABSENT — an older server that predates the feature;
 *  - present with `enabled: false` — this server, with no object storage configured;
 *  - present with `enabled: true` and the numbers — the feature is available.
 *
 * `enabled` is required INSIDE the block and everything else is optional within
 * it, so `{ enabled: false }` alone is valid. `enabled: false` rather than
 * omission is what lets an operator tell "my server is old" from "my storage is
 * unconfigured" — two states with the same client behaviour and completely
 * different fixes.
 */
const documentsConfigSchema = z.object({
  enabled: z.boolean(),
  maxSizeMB: z.number().int().positive().optional(),
  chunkPlaintextBytes: z.number().int().positive().optional(),
  maxDocuments: z.number().int().positive().optional(),
  quotaMB: z.number().int().positive().optional(),
  // Advisory only, and the docs say so: the server sees ciphertext and CANNOT
  // enforce an extension. Each entry carries the same bound the metadata blob's
  // own `ext` field does; the LIST length is left unbounded because it is the
  // operator's own configuration being echoed back, and a cap here would be a
  // number with no configured counterpart.
  allowedExtensions: z.array(z.string().max(MAX_DOCUMENT_EXT_LENGTH)).optional(),
});

export const publicConfigDataSchema = z.object({
  fileEncryption: z.object({
    // Client-side size guardrail in megabytes; must be a positive integer.
    maxSizeMB: z.number().int().positive(),
  }),
  // OPTIONAL, and that is load-bearing rather than lenient: a current client
  // talking to an older server must still parse this envelope, or
  // `getFileEncryptionMaxBytes()` silently falls back to its default and the File
  // Encryption cap changes for a reason no one can see. The `upgrade` gate is what
  // would catch a required field here, one release too late.
  documents: documentsConfigSchema.optional(),
  // Who may register (`REGISTRATION_MODE`). OPTIONAL for the reason `documents`
  // is: an older server sends no such block, and the register page then shows the
  // form it always showed.
  registration: z.object({ mode: z.enum(REGISTRATION_MODES) }).optional(),
});

export const publicConfigResponseSchema = z.object({
  success: z.literal(true),
  data: publicConfigDataSchema,
  message: z.string().optional(),
});

/**
 * The same envelope, narrowed to the ONE block the File Encryption cap reads.
 *
 * It exists because a single envelope carries two features that have nothing to do
 * with each other. `getFileEncryptionMaxBytes()` answers a failed parse by falling
 * back to `MAX_FILE_ENCRYPTION_SIZE_MB`, so validating the whole document against
 * the full schema means one bad value under `documents` — an operator's mistyped
 * extension, a field a newer server adds — silently changes the File Encryption
 * tool's size cap. That is a feature breaking for a reason nobody can see, caused
 * by a block it does not read.
 *
 * `.pick()` rather than a second literal shape, so `fileEncryption` has exactly one
 * definition and cannot drift; STRIP mode (the default) then ignores `documents`
 * entirely rather than validating and rejecting it.
 */
export const fileEncryptionConfigResponseSchema = publicConfigResponseSchema.extend({
  data: publicConfigDataSchema.pick({ fileEncryption: true }),
});

/**
 * The same envelope again, narrowed to the block a DOCUMENTS reader acts on.
 *
 * The coupling runs BOTH ways, which is easy to miss and is the reason this
 * export exists as well as the one above. `fileEncryption` is REQUIRED in
 * `publicConfigDataSchema`, so a documents reader validating the whole document
 * would fail its parse — and fall back to "the feature is unavailable", hiding
 * the document store — because of a value it never reads. That is the same defect
 * as its mirror image, pointing the other way: a feature breaking for a reason
 * nobody can see, caused by a block it does not look at.
 *
 * Both narrowings are `.pick()` off the one full shape, so neither restates a
 * field and the full schema stays available for a reader that genuinely wants the
 * whole envelope. Narrow does NOT mean lenient: within the block it picks, this is
 * exactly as strict as the full schema, so a malformed `documents` block is still
 * refused by the code that would otherwise act on it.
 */
export const documentsConfigResponseSchema = publicConfigResponseSchema.extend({
  data: publicConfigDataSchema.pick({ documents: true }),
});

/**
 * The same envelope a third time, narrowed to the block the REGISTER PAGE reads.
 *
 * Narrow for the reason the two above are: the page must not lose the File
 * Encryption cap or the document store to a mode it does not recognise, and must
 * not lose its own block to a malformed `documents` one. A mode this client does
 * not know fails THIS parse only, and the page then falls back to the plain form,
 * which the server still refuses or admits by its own rule.
 */
export const registrationConfigResponseSchema = publicConfigResponseSchema.extend({
  data: publicConfigDataSchema.pick({ registration: true }),
});
