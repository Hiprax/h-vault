import { storageConfigured } from '../config/index.js';
import { getStorage } from '../services/storage/index.js';
import { createModuleLogger } from './logger.js';

const logger = createModuleLogger('utils/storageHealth');

/**
 * The in-process object-storage gauge, and the one-shot boot probe that fills it.
 *
 * ## Why a gauge and not a health check
 *
 * `/api/v1/health` deliberately does NOT probe storage, and that is the whole
 * reason this module exists separately from `healthController`. The health
 * endpoint is what the container healthcheck and the outer Nginx call, so it has
 * to answer while dependencies are down — the same argument that keeps
 * `healthLimiter` on an in-memory store rather than the Mongo-backed one it
 * reports on. A `HeadBucket` on that path would make an unreachable bucket time
 * the healthcheck out and restart a server that is otherwise serving every vault
 * request perfectly well, because the document store is an OPTIONAL feature whose
 * absence must degrade one section of the UI and nothing else.
 *
 * So the probe runs ONCE, at boot, and what it learned is reported by
 * `/api/v1/metrics` — an endpoint that is already token-gated, already for
 * operators rather than for orchestrators, and already free to describe something
 * that is merely broken rather than fatal.
 *
 * It runs on EVERY worker, not only the primary one, which is a deliberate break
 * from how the cron jobs are gated. That gate exists to stop duplicate scheduled
 * executions; a read-only `HeadBucket` has no such hazard. And `/metrics` is a
 * per-process endpoint — it already reports this process's uptime and memory — so
 * under a pm2 deployment running two instances, a primary-only probe would leave
 * the second worker answering `lastProbeAt: null`, which reads as "the preflight
 * never ran" to whoever happened to be balanced onto it.
 *
 * ## What the three fields mean, and why `null` is not `false`
 *
 *   * `configured` — whether the four `S3_*` connection variables are set. Read
 *     live from `storageConfigured` rather than captured, so it always agrees with
 *     the flag every other guard in the process consults.
 *   * `lastProbeAt` — when the probe last ran, or `null` when it has not run at
 *     all, which on a live server means the deployment configured no storage.
 *     `null` says "not measured"; it never means "measured and fine".
 *   * `lastProbeOk` — the probe's verdict, `null` for the same reason.
 *
 * An operator reading `{configured: true, lastProbeAt: null}` therefore knows the
 * preflight never ran, which is a different problem from a preflight that ran and
 * failed, and the two must not collapse into one boolean.
 */
export interface StorageHealthGauge {
  /** Whether the operator configured the four `S3_*` connection variables. */
  configured: boolean;
  /** ISO 8601 instant of the last probe, or `null` when none has run. */
  lastProbeAt: string | null;
  /** The last probe's verdict, or `null` when none has run. */
  lastProbeOk: boolean | null;
}

/**
 * The recorded half of the gauge. Module-scoped because the probe is one-shot and
 * the reader is a request handler: there is no request-scoped place to keep it,
 * and persisting a boot-time diagnostic would outlive the process it describes.
 */
let lastProbeAt: Date | null = null;
let lastProbeOk: boolean | null = null;

/** The gauge as `/metrics` reports it. Never throws and never probes. */
export function getStorageHealth(): StorageHealthGauge {
  return {
    configured: storageConfigured,
    lastProbeAt: lastProbeAt === null ? null : lastProbeAt.toISOString(),
    lastProbeOk,
  };
}

/**
 * The boot preflight: prove the configured bucket exists and the credentials can
 * see it, record the answer, and never let either outcome stop the server.
 *
 * ## Three guarantees, each one load-bearing
 *
 *   1. **It never rejects.** `server.ts` starts it without awaiting (see below),
 *      so a rejection here would arrive as an unhandled rejection, which
 *      `@hiprax/logger`'s crash coordinator escalates to `process.exit(1)` — a
 *      misconfigured bucket would then kill a server whose vault works fine.
 *   2. **It never blocks the listen.** The S3 client is pinned to a 5-second
 *      connect timeout and three attempts, so an endpoint that resolves but never
 *      answers costs upwards of fifteen seconds. Awaiting that would delay
 *      `app.listen`, and therefore the container healthcheck, on exactly the
 *      deployment that is already in trouble.
 *   3. **A failure is loud.** It is logged at error level naming the bucket,
 *      because the symptom an operator would otherwise see is every document
 *      request answering 503 with a redacted body — `exposeServerErrors: false`
 *      turns each one into the bare string `Service Unavailable`, so the log line
 *      is the only place the real reason exists.
 *
 * Returns the verdict for a caller that wants it (the tests do); `server.ts`
 * discards it.
 */
export async function runStoragePreflight(): Promise<boolean> {
  if (!storageConfigured) {
    // Not a failure and not a probe: on a deployment that never enabled the
    // document store there is no bucket to reach, and recording a verdict would
    // put a `false` in the gauge for a feature that is simply off.
    logger.info('Object storage is not configured; the document store is disabled');
    return false;
  }

  try {
    await getStorage().headBucket();
    lastProbeAt = new Date();
    lastProbeOk = true;
    logger.info('Object storage preflight succeeded');
    return true;
  } catch (error: unknown) {
    lastProbeAt = new Date();
    lastProbeOk = false;
    const message = error instanceof Error ? error.message : 'Unknown error';
    logger.error(
      'Object storage preflight FAILED: the configured bucket could not be reached. ' +
        'Every document request will answer 503 until this is fixed, and in production ' +
        `its body is redacted to "Service Unavailable", so this line is the only diagnosis: ${message}`,
    );
    return false;
  }
}
