import type { Request, Response } from 'express';
import crypto from 'node:crypto';
import { catchAsync, httpErrors } from '@hiprax/errors';
import mongoose from 'mongoose';
import { config } from '../config/index.js';

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
    },
  });
});
