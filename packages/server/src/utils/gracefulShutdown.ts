import type net from 'node:net';
import type winston from 'winston';

/**
 * Minimal shape of a stoppable scheduled task (node-cron's `ScheduledTask`).
 * Only `stop` is needed by the shutdown sequence.
 */
interface StoppableTask {
  stop(): void | Promise<void>;
}

export interface GracefulShutdownDeps {
  logger: Pick<winston.Logger, 'info' | 'warn'>;
  /** Cron tasks to stop; entries may be `null` on non-primary workers. */
  tasks: (StoppableTask | null)[];
  server: { close(callback: () => void): void };
  activeConnections: Set<net.Socket>;
  getRunningJobs: () => Promise<void>[];
  closeRateLimitStore: () => Promise<void>;
  closeDatabaseConnection: () => Promise<void>;
  /**
   * Flush and close all logger transports before the process exits (e.g.
   * `@hiprax/logger`'s `shutdownAllLoggers`). Optional; when omitted the
   * sequence proceeds straight to `exit`. Must resolve (never reject) — a
   * failed log flush should not turn a clean shutdown into an error exit.
   */
  flushLoggers?: () => Promise<void>;
  exit: (code: number) => void;
  /** Max time to wait for in-flight background jobs to drain. */
  jobDrainTimeoutMs?: number;
  /** Deadline after which lingering connections are force-destroyed. */
  forceShutdownTimeoutMs?: number;
}

/**
 * Builds the graceful-shutdown signal handler.
 *
 * Extracted from `server.ts` so the shutdown sequence can be unit-tested with
 * injected dependencies (server.ts itself is the process entry point and is not
 * directly testable).
 *
 * Re-entrancy safety: a closure-scoped `isShuttingDown` flag guards the handler
 * so a double signal (SIGTERM + SIGINT, or a double Ctrl-C) cannot run the
 * shutdown sequence twice. Without it, a second invocation would re-stop the
 * cron jobs, call `server.close()` again, drain jobs twice, and — most
 * dangerously — schedule a second, unclearable force-shutdown timer that could
 * fire `process.exit(1)` after the first invocation already exited cleanly.
 */
export function createGracefulShutdown(deps: GracefulShutdownDeps): (signal: string) => void {
  const {
    logger,
    tasks,
    server,
    activeConnections,
    getRunningJobs,
    closeRateLimitStore,
    closeDatabaseConnection,
    flushLoggers,
    exit,
    jobDrainTimeoutMs = 10_000,
    forceShutdownTimeoutMs = 30_000,
  } = deps;

  let isShuttingDown = false;

  return (signal: string): void => {
    if (isShuttingDown) {
      logger.info(`${signal} received, but shutdown is already in progress; ignoring`);
      return;
    }
    isShuttingDown = true;

    logger.info(`${signal} received. Starting graceful shutdown...`);

    // Stop cron jobs (only started on primary worker; entries may be null).
    for (const task of tasks) {
      if (task) void task.stop();
    }
    logger.info('Cron jobs stopped');

    // Stop accepting new connections
    server.close(() => {
      logger.info('HTTP server closed');

      // Wait for in-flight background jobs to finish (with timeout)
      const jobPromises = getRunningJobs();
      const jobDrain =
        jobPromises.length > 0
          ? Promise.race([
              Promise.allSettled(jobPromises).then(() => {
                logger.info(`${String(jobPromises.length)} in-flight background job(s) completed`);
              }),
              new Promise<void>((resolve) =>
                setTimeout(() => {
                  logger.warn('Timed out waiting for in-flight background jobs');
                  resolve();
                }, jobDrainTimeoutMs),
              ),
            ])
          : Promise.resolve();

      void jobDrain
        .then(() => closeRateLimitStore())
        .then(() => closeDatabaseConnection())
        .then(() => {
          logger.info('MongoDB disconnected');
          clearTimeout(forceShutdownTimer);
          // Flush buffered logger transports (e.g. rotating file writes) so the
          // final shutdown logs are persisted before the process exits. This is
          // the last step because it closes the transports.
          return flushLoggers?.();
        })
        .then(() => {
          exit(0);
        })
        .catch((err: unknown) => {
          // A failure while draining/closing must not become an unhandled
          // rejection (which the process-level handler would escalate). Force
          // an error exit instead.
          const message = err instanceof Error ? err.message : 'Unknown error';
          logger.warn(`Error during graceful shutdown sequence: ${message}`);
          clearTimeout(forceShutdownTimer);
          exit(1);
        });
    });

    // Set deadline for existing connections; store the timer reference
    // so it can be cleared on a clean exit to avoid dangling timers.
    const forceShutdownTimer = setTimeout(() => {
      logger.warn('Forcing shutdown after timeout');
      activeConnections.forEach((socket) => socket.destroy());
      exit(1);
    }, forceShutdownTimeoutMs);
  };
}
