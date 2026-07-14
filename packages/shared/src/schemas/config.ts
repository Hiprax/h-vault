import { z } from 'zod';

// Runtime validation for the public (unauthenticated) GET /config response.
// Mirrors the `PublicConfig` interface in `types/index.ts` and the success
// branch of the standard `{ success, data }` API envelope. Self-contained:
// depends only on zod so it never references server- or client-only code.

export const publicConfigDataSchema = z.object({
  fileEncryption: z.object({
    // Client-side size guardrail in megabytes; must be a positive integer.
    maxSizeMB: z.number().int().positive(),
  }),
});

export const publicConfigResponseSchema = z.object({
  success: z.literal(true),
  data: publicConfigDataSchema,
  message: z.string().optional(),
});
