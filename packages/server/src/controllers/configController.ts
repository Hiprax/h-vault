import type { Request, Response } from 'express';
import { catchAsync } from '@hiprax/errors';
import type { PublicConfig } from '@hvault/shared';
import { config } from '../config/index.js';

// ── Handlers ─────────────────────────────────────────────────────────

/**
 * Public (unauthenticated) configuration endpoint.
 *
 * Returns ONLY non-sensitive, operator-tunable values the client needs before
 * (or without) authentication. Currently this is the File Encryption tool's
 * client-side size guardrail: files are encrypted entirely in the browser and
 * never uploaded, so the server cannot enforce the cap — it merely advertises
 * the operator-configured value so the UI can reject oversize files before any
 * crypto work. No secret is exposed and no file is ever received here.
 */
export const getPublicConfig = catchAsync((_req: Request, res: Response): void => {
  const data: PublicConfig = {
    fileEncryption: {
      maxSizeMB: config.FILE_ENCRYPTION_MAX_SIZE_MB,
    },
  };

  res.json({ success: true, data });
});
