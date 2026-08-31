import { z } from 'zod';
import { MAX_DOCUMENT_EXT_LENGTH } from '../constants/index.js';

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
});

export const publicConfigResponseSchema = z.object({
  success: z.literal(true),
  data: publicConfigDataSchema,
  message: z.string().optional(),
});
