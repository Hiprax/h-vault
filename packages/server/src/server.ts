import net from 'node:net';
import mongoose from 'mongoose';
import { createLogger, shutdownAllLoggers } from '@hiprax/logger';
import { config } from './config/index.js';
import { connectDatabase } from './config/database.js';
import app from './app.js';
import { startTrashCleanupJob } from './jobs/trashCleanup.js';
import { startTokenCleanupJob } from './jobs/tokenCleanup.js';
import { startBackupScheduler } from './jobs/backupScheduler.js';
import { initBreachRangeCache } from './jobs/breachSeed.js';
import { closeRateLimitStore } from './middleware/rateLimiter.js';
import { runMigrations } from './utils/migrations.js';
import { getRunningJobs } from './utils/jobTracker.js';
import { createGracefulShutdown } from './utils/gracefulShutdown.js';

const logger = createLogger({ moduleName: 'server' });

// Defensive listener-limit margin. @hiprax/logger v1's crash-capture coordinator
// installs a single process-wide uncaughtException/unhandledRejection listener pair
// (no longer one pair per logger), and this file adds only SIGTERM/SIGINT, so the
// process sits well under Node's default of 10 per event; the raised cap simply
// absorbs any handlers third-party libraries register without a spurious warning.
process.setMaxListeners(20);

async function startServer(): Promise<void> {
  try {
    // Connect to database
    await connectDatabase();

    // Run pending migrations before starting anything else
    await runMigrations();

    // Start background jobs only on the primary worker (PM2 instance 0) to avoid
    // duplicate cron executions across clustered instances.
    const isPrimaryWorker = !process.env.NODE_APP_INSTANCE || process.env.NODE_APP_INSTANCE === '0';
    const trashCleanupTask = isPrimaryWorker ? startTrashCleanupJob() : null;
    const tokenCleanupTask = isPrimaryWorker ? startTokenCleanupJob() : null;
    const backupSchedulerTask = isPrimaryWorker ? startBackupScheduler() : null;
    // Boot-time breach-cache init: logs a hint if empty and optionally schedules
    // the refresh cron. NEVER downloads the corpus on boot (that is the opt-in
    // `npm run seed-breaches` command). Primary worker only.
    const breachSeedTask = isPrimaryWorker ? await initBreachRangeCache() : null;
    if (!isPrimaryWorker) {
      logger.info(
        'Skipping background jobs on worker instance ' +
          (process.env.NODE_APP_INSTANCE ?? 'unknown'),
      );
    }

    // Start HTTP server
    const server = app.listen(config.PORT, () => {
      logger.info(
        `${config.APP_NAME} server running on port ${String(config.PORT)} in ${config.NODE_ENV} mode`,
      );

      // Signal PM2 that the process is ready to accept connections (requires wait_ready: true)
      if (typeof process.send === 'function') {
        process.send('ready');
      }
    });

    // Track active connections for graceful shutdown
    const activeConnections = new Set<net.Socket>();

    server.on('connection', (socket: net.Socket) => {
      activeConnections.add(socket);
      socket.on('close', () => activeConnections.delete(socket));
    });

    // Graceful shutdown (re-entrancy-safe; double signals run it once)
    const gracefulShutdown = createGracefulShutdown({
      logger,
      tasks: [trashCleanupTask, tokenCleanupTask, backupSchedulerTask, breachSeedTask],
      server,
      activeConnections,
      getRunningJobs,
      closeRateLimitStore,
      closeDatabaseConnection: () => mongoose.connection.close(),
      // Flush winston transports on shutdown; swallow any flush error so a
      // logging hiccup never downgrades a clean exit to a failure exit.
      flushLoggers: () => shutdownAllLoggers({ timeoutMs: 5_000 }).catch(() => undefined),
      exit: (code) => process.exit(code),
    });

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    // Fatal-crash capture (uncaughtException / unhandledRejection) is owned by
    // @hiprax/logger v1's process-wide coordinator: it records the crash once
    // through the elected logger (with full stack, process/OS context and a
    // parsed trace), flushes that logger's transports under a bounded timeout,
    // then exits the process with code 1 (exitOnUncaught defaults to true). That
    // supersedes the hand-rolled handlers this file used to install, which merely
    // logged a one-line message and exited — and whose synchronous exit truncated
    // the coordinator's richer, fully-flushed crash record. Delegating avoids the
    // double-handling and preserves the crash → exit(1) contract that
    // jobTracker's bookkeeping catch relies on.
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    logger.error(`Failed to start server: ${message}`);
    process.exit(1);
  }
}

void startServer();
