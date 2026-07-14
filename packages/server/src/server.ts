import net from 'node:net';
import mongoose from 'mongoose';
import { createLogger, shutdownAllLoggers } from '@hiprax/logger';
import { config } from './config/index.js';
import { connectDatabase } from './config/database.js';
import app from './app.js';
import { startTrashCleanupJob } from './jobs/trashCleanup.js';
import { startTokenCleanupJob } from './jobs/tokenCleanup.js';
import { startBackupScheduler } from './jobs/backupScheduler.js';
import { closeRateLimitStore } from './middleware/rateLimiter.js';
import { runMigrations } from './utils/migrations.js';
import { getRunningJobs } from './utils/jobTracker.js';
import { createGracefulShutdown } from './utils/gracefulShutdown.js';

const logger = createLogger({ moduleName: 'server' });

// Increase listener limit — multiple modules (logger, database, jobs) register process handlers
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
      tasks: [trashCleanupTask, tokenCleanupTask, backupSchedulerTask],
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

    process.on('unhandledRejection', (reason: unknown) => {
      const message = reason instanceof Error ? reason.message : 'Unknown reason';
      logger.error(`Unhandled rejection: ${message}`);
      // Exit after a brief delay to allow the logger to flush.
      // An unhandled rejection indicates a code path without proper error
      // handling, so continuing could leave the process in an undefined state.
      setTimeout(() => process.exit(1), 100);
    });

    process.on('uncaughtException', (error: Error) => {
      logger.error(`Uncaught exception: ${error.message}`);
      process.exit(1);
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    logger.error(`Failed to start server: ${message}`);
    process.exit(1);
  }
}

void startServer();
