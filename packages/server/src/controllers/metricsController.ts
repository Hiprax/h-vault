import type { Request, Response } from 'express';
import crypto from 'node:crypto';
import { catchAsync, httpErrors } from '@hiprax/errors';
import mongoose from 'mongoose';
import { config } from '../config/index.js';
import { getStorageHealth } from '../utils/storageHealth.js';

// ── Handlers ─────────────────────────────────────────────────────────

export const getMetrics = catchAsync((req: Request, res: Response): void => {
  // Require a valid metrics token when METRICS_TOKEN is configured
  if (config.METRICS_TOKEN) {
    const provided = req.headers['x-metrics-token'];
    if (typeof provided !== 'string') {
      throw httpErrors.forbidden('Invalid or missing metrics token');
    }
    const expected = Buffer.from(config.METRICS_TOKEN, 'utf8');
    const received = Buffer.from(provided, 'utf8');
    const maxLen = Math.max(expected.length, received.length);
    const a = Buffer.alloc(maxLen);
    const b = Buffer.alloc(maxLen);
    expected.copy(a);
    received.copy(b);
    const lengthMatch = expected.length === received.length;
    const contentMatch = crypto.timingSafeEqual(a, b);
    if (!lengthMatch || !contentMatch) {
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
    },
  });
});
