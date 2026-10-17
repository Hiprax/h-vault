import type { Request, Response } from 'express';
import crypto from 'node:crypto';
import { catchAsync, httpErrors } from '@hiprax/errors';
import mongoose from 'mongoose';
import { config } from '../config/index.js';
import { getStorageHealth } from '../utils/storageHealth.js';
import { proxyMisconfigSuspected } from '../utils/deploymentChecks.js';
import { vaultStorageSnapshot } from '../utils/vaultQuota.js';

// ── Handlers ─────────────────────────────────────────────────────────

export const getMetrics = catchAsync((req: Request, res: Response): void => {
  // Require a valid metrics token when METRICS_TOKEN is configured
  if (config.METRICS_TOKEN) {
    const provided = req.headers['x-metrics-token'];
    if (typeof provided !== 'string') {
      throw httpErrors.forbidden('Invalid or missing metrics token');
    }
    // Compared as SHA-256 digests (I-13): both sides are always 32 bytes, so the
    // constant-time comparison never depends on either token's length. Padding
    // both to the longer one, as this used to, made the work depend on the
    // presented length. Equal digests mean equal tokens.
    const expected = crypto.createHash('sha256').update(config.METRICS_TOKEN, 'utf8').digest();
    const received = crypto.createHash('sha256').update(provided, 'utf8').digest();
    if (!crypto.timingSafeEqual(expected, received)) {
      throw httpErrors.forbidden('Invalid or missing metrics token');
    }
  }
  const dbState = mongoose.connection.readyState;
  // readyState: 0 = disconnected, 1 = connected, 2 = connecting, 3 = disconnecting
  const isConnected = dbState === mongoose.ConnectionStates.connected;

  const memUsage = process.memoryUsage();

  res.status(200).json({
    success: true,
    data: {
      uptime: process.uptime(),
      memory: {
        rss: memUsage.rss,
        heapTotal: memUsage.heapTotal,
        heapUsed: memUsage.heapUsed,
        external: memUsage.external,
      },
      database: {
        state: isConnected ? 'connected' : 'disconnected',
        readyState: dbState,
      },
      // The object-storage gauge, read rather than measured: the boot preflight
      // is what probes, once, and this endpoint reports what it learned. Nothing
      // here touches the network, so a bucket that is down cannot slow the one
      // endpoint an operator reaches for while it is down. `/api/v1/health`
      // carries no equivalent block on purpose — see `utils/storageHealth.ts`.
      storage: getStorageHealth(),
      // The mode the process runs in, and whether a proxied request has arrived
      // that this server does not trust (`utils/deploymentChecks.ts`). Here and
      // NOT on `/api/v1/health`: an unauthenticated answer naming a non-production
      // mode would advertise an instance whose rate limiters are off.
      mode: config.NODE_ENV,
      proxy: { misconfigSuspected: proxyMisconfigSuspected() },
      // What the vault byte quota counts across every account whose counter is
      // installed (`null` until the first background read lands). A snapshot,
      // refreshed in the background when a request finds it more than five
      // minutes old (`measuredAt` says when it was taken): reading it never waits
      // for the database, so this endpoint answers the same while the database is
      // slow or down.
      vaultStorage: vaultStorageSnapshot(),
    },
  });
});
