import type { Request, Response } from 'express';
import { catchAsync } from '@hiprax/errors';
import mongoose from 'mongoose';

// ── Handlers ─────────────────────────────────────────────────────────

export const healthCheck = catchAsync((_req: Request, res: Response): void => {
  const dbState = mongoose.connection.readyState;
  // readyState: 0 = disconnected, 1 = connected, 2 = connecting, 3 = disconnecting
  const isConnected = dbState === mongoose.ConnectionStates.connected;

  // The SAME fields in every mode. This answer is unauthenticated, so it names no
  // version (the running version is never part of an unauthenticated response)
  // and no mode: extra fields outside production would tell a scanner exactly
  // which instances run with their rate limiters off. Uptime and mode are on the
  // token-gated /metrics.
  const data = {
    status: isConnected ? 'ok' : 'error',
    timestamp: new Date().toISOString(),
    database: isConnected ? 'connected' : 'disconnected',
  };

  res.status(isConnected ? 200 : 503).json({
    success: isConnected,
    data,
  });
});
