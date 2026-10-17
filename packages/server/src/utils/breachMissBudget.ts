import type { Response } from 'express';
import { ErrorHandler, httpErrors } from '@hiprax/errors';
import {
  HIBP_MAX_MISSES_PER_USER_PER_DAY,
  HIBP_MAX_MISSES_PER_USER_PER_WINDOW,
  HIBP_MISS_BUDGET_WINDOW_MINUTES,
} from '@hvault/shared';
import { MongoRateLimitStore } from '../middleware/rateLimitStore.js';
import { createModuleLogger } from './logger.js';

/**
 * The per-account budget on breach-range FETCHES (F-06).
 *
 * A breach lookup the shared range cache cannot answer makes the server fetch
 * the range from HIBP and store it in the cache every account shares. Such a
 * fetch is charged to the account whose request caused it, against two budgets:
 * `HIBP_MAX_MISSES_PER_USER_PER_WINDOW` per `HIBP_MISS_BUDGET_WINDOW_MINUTES`,
 * which one full breach scan of the largest vault fits, and
 * `HIBP_MAX_MISSES_PER_USER_PER_DAY`, which bounds what an account can make the
 * server fetch round the clock. A cache hit costs nothing, and neither does
 * joining a fetch another request already started.
 *
 * Unlike the rate limiters, which are off outside production, the budget is
 * enforced in every environment: it bounds a shared sink and an outbound
 * dependency, like the upload admission budgets, rather than throttling requests.
 *
 * The counters live in the rate-limit collection (`breachMiss:<userId>` and
 * `breachMissDay:<userId>`), counted on the database's clock, so every worker
 * shares them. A failure to count fails CLOSED: the lookup is treated as not
 * fetched (a stale cached range, or an error), never as fetched unbudgeted.
 */

const logger = createModuleLogger('breach-miss-budget');

const WINDOW_MS = HIBP_MISS_BUDGET_WINDOW_MINUTES * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

const windowStore = new MongoRateLimitStore(WINDOW_MS);
const dayStore = new MongoRateLimitStore(DAY_MS);

/** The sentence a refused lookup is answered with. */
const BREACH_MISS_BUDGET_MESSAGE =
  'Too many breach lookups this account needed fetched; try again later';

/**
 * A lookup refused because the account's fetch budget is spent. A 429 by its
 * `statusCode`, so one that escapes uncaught still refuses; the handlers catch it
 * to add `Retry-After` ({@link refuseBreachLookup}).
 */
export class BreachMissBudgetError extends ErrorHandler {
  /** Seconds until the budget that refused has room again. */
  readonly retryAfterSeconds: number;

  constructor(retryAfterSeconds: number) {
    super(BREACH_MISS_BUDGET_MESSAGE, 429);
    this.name = 'BreachMissBudgetError';
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** One request's view of its account's budget. */
export interface BreachMissBudget {
  /**
   * Charges one fetch, or throws {@link BreachMissBudgetError} (or the store's
   * own error). Once refused, it refuses again at once without asking the store.
   */
  charge(): Promise<void>;
}

/**
 * The budget of the account `userId`, for ONE request. Create one per request:
 * it remembers its refusal, so a batch that ran out stops charging.
 */
export function breachMissBudgetFor(userId: string): BreachMissBudget {
  let refusal: BreachMissBudgetError | undefined;
  return {
    async charge(): Promise<void> {
      if (refusal) throw refusal;
      const window = await windowStore.increment(`breachMiss:${userId}`);
      if (window.totalHits > HIBP_MAX_MISSES_PER_USER_PER_WINDOW) {
        refusal = refuse('window', window.resetTime, WINDOW_MS);
        throw refusal;
      }
      const day = await dayStore.increment(`breachMissDay:${userId}`);
      if (day.totalHits > HIBP_MAX_MISSES_PER_USER_PER_DAY) {
        refusal = refuse('day', day.resetTime, DAY_MS);
        throw refusal;
      }
    },
  };
}

function refuse(
  budget: 'window' | 'day',
  resetTime: Date | undefined,
  windowMs: number,
): BreachMissBudgetError {
  // The account is deliberately not logged, as the rate limiters omit their key.
  logger.warn('Breach lookup refused: the account has spent its fetch budget', { budget });
  const untilReset = resetTime === undefined ? windowMs : resetTime.getTime() - Date.now();
  const seconds = Math.ceil(untilReset / 1000);
  return new BreachMissBudgetError(Math.min(Math.max(seconds, 1), windowMs / 1000));
}

/**
 * Answers a refused lookup: `Retry-After`, then the 429. The one renderer both
 * breach endpoints use. Throws, for the error middleware to write.
 */
export function refuseBreachLookup(res: Response, refusal: BreachMissBudgetError): never {
  res.setHeader('Retry-After', String(refusal.retryAfterSeconds));
  throw httpErrors.tooManyRequests(BREACH_MISS_BUDGET_MESSAGE);
}
