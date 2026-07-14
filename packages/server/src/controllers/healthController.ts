import type { Request, Response } from 'express';
import { catchAsync } from '@hiprax/errors';
import mongoose from 'mongoose';
import { APP_VERSION } from '@hvault/shared';
import { isProduction } from '../config/index.js';

// ── Handlers ─────────────────────────────────────────────────────────

export const healthCheck = catchAsync((_req: Request, res: Response): void => {
  const dbState = mongoose.connection.readyState;
  // readyState: 0 = disconnected, 1 = connected, 2 = connecting, 3 = disconnecting
  const isConnected = dbState === mongoose.ConnectionStates.connected;

  const data: Record<string, unknown> = {
    status: isConnected ? 'ok' : 'error',
    timestamp: new Date().toISOString(),
    database: isConnected ? 'connected' : 'disconnected',
  };

  // Only expose version and uptime in non-production environments
  if (!isProduction) {
    data.uptime = process.uptime();
    data.version = APP_VERSION;
  }

  res.status(isConnected ? 200 : 503).json({
    success: isConnected,
    data,
  });
});
