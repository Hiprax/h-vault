import type { Request, Response } from 'express';
import { catchAsync } from '@hiprax/errors';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES, MAX_DOCUMENTS_PER_USER } from '@hvault/shared';
import type { PublicConfig } from '@hvault/shared';
import { config, storageConfigured } from '../config/index.js';

// ── Handlers ─────────────────────────────────────────────────────────

/**
 * Public (unauthenticated) configuration endpoint.
 *
 * Returns ONLY non-sensitive, operator-tunable values the client needs before
 * (or without) authentication. No secret is exposed, no credential appears here,
 * and nothing in this payload names the storage engine, its endpoint or its
 * bucket — only whether the feature is available and the numbers the browser has
 * to know before it starts encrypting.
 *
 * Two blocks today, and both exist for the same reason: the work happens in the
 * browser, so the server can only ADVERTISE the operator's limit and the client
 * is what enforces it.
 *
 *   * `fileEncryption` — the File Encryption tool's size guardrail. Files are
 *     encrypted entirely in the browser and never uploaded, so the server could
 *     not enforce this even in principle.
 *   * `documents` — the document store's advertisement, in the THREE states a
 *     client must tell apart: the block ABSENT (a server older than the feature),
 *     present with `enabled: false` (this server, with no object storage
 *     configured), or present with `enabled: true` and the numbers. Reporting
 *     `enabled: false` rather than omitting the block is what lets an operator
 *     tell "my server is old" from "my storage is unconfigured" — two states with
 *     identical client behaviour and completely different fixes. The block is
 *     OPTIONAL in `publicConfigDataSchema` for the other direction of the same
 *     compatibility: a current client must still parse an older server's
 *     envelope, or the File Encryption cap silently falls back too.
 *
 * `allowedExtensions` is advisory and the documentation says so plainly: the
 * server receives ciphertext and never sees a filename, so it cannot enforce an
 * extension allowlist. It is published so the upload panel can refuse a file
 * before any crypto work, not because it is a security control.
 */
export const getPublicConfig = catchAsync((_req: Request, res: Response): void => {
  const data: PublicConfig = {
    fileEncryption: {
      maxSizeMB: config.FILE_ENCRYPTION_MAX_SIZE_MB,
    },
    documents: storageConfigured
      ? {
          enabled: true,
          maxSizeMB: config.MAX_DOCUMENT_SIZE_MB,
          // The SERVER's framing, echoed so the browser can compute
          // `declaredChunkCount` before it seals the first segment. It is the
          // server's own constant rather than anything the client may choose.
          chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
          maxDocuments: MAX_DOCUMENTS_PER_USER,
          quotaMB: config.DOCUMENT_STORAGE_QUOTA_MB_PER_USER,
          allowedExtensions: config.DOCUMENT_ALLOWED_EXTENSIONS,
        }
      : { enabled: false },
  };

  res.json({ success: true, data });
});
