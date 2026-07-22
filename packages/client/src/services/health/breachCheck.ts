/**
 * Breach-check orchestration for the Vault Health page.
 *
 * Zero-knowledge and rate-limit-aware:
 *  - Passwords are deduplicated client-side and each unique password is SHA-1
 *    hashed with the Web Crypto API; only the first 5 hex chars of each hash (the
 *    k-anonymity prefix) ever leave the device.
 *  - Prefixes are batched and sent to the server's batch proxy, so a large vault
 *    costs a handful of requests instead of one-per-password (which used to burn
 *    through the rate limit and silently drop the rest).
 *  - A prefix whose lookup fails is reported as NOT CHECKED (`failedCount`), never
 *    silently treated as not-breached. The page surfaces this so an unchecked
 *    password can never masquerade as "safe".
 */
import type { AxiosError } from 'axios';
import { HIBP_BATCH_MAX_PREFIXES } from '@hvault/shared';
import { checkBreachBatchApi } from '../api/userApi';
import type { DecryptedVaultItem } from '../../stores/vaultStore';

export interface BreachFinding {
  item: DecryptedVaultItem;
  /** Number of times the password appears in known breaches (HIBP count). */
  count: number;
}

export interface BreachCheckResult {
  breached: BreachFinding[];
  /** Unique passwords the scan set out to check. */
  totalCount: number;
  /** Unique passwords successfully checked (breached or not). */
  checkedCount: number;
  /** Unique passwords whose lookup failed and remain UNCHECKED. */
  failedCount: number;
}

export interface BreachCheckOptions {
  /** Reports `(processed, total)` unique passwords as batches resolve. */
  onProgress?: (processed: number, total: number) => void;
  signal?: AbortSignal;
}

/** Concurrent batch requests in flight. Small: the server rate-limits per user. */
const BATCH_CONCURRENCY = 3;
/** Retries for a 429 before a batch's passwords are marked unchecked. */
const MAX_RETRIES = 3;
/** Fallback backoff when a 429 carries no usable Retry-After. */
const DEFAULT_RETRY_MS = 2000;

async function sha1HexUpper(password: string): Promise<string> {
  const data = new TextEncoder().encode(password);
  const buffer = await crypto.subtle.digest('SHA-1', data);
  return [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

/** Returns the breach count if `suffix` appears in a HIBP range body, else null. */
function findBreachCount(rangeText: string, suffix: string): number | null {
  const lines = rangeText.split('\r\n');
  for (const line of lines) {
    const [hashSuffix, countStr] = line.split(':');
    if (hashSuffix?.toUpperCase() === suffix) {
      return parseInt(countStr ?? '0', 10);
    }
  }
  return null;
}

/** Milliseconds to wait for a 429, from Retry-After (seconds or HTTP-date). */
function retryAfterMs(error: AxiosError): number {
  // Axios types response headers loosely (indexing yields `any`); treat the value
  // as unknown and narrow it explicitly.
  const header: unknown = error.response?.headers['retry-after'];
  if (typeof header === 'string') {
    const seconds = Number(header);
    if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
    const dateMs = Date.parse(header);
    if (!Number.isNaN(dateMs)) return Math.max(0, dateMs - Date.now());
  }
  return DEFAULT_RETRY_MS;
}

function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
  });
}

async function runWithConcurrency<T>(
  items: readonly T[],
  limit: number,
  task: (item: T) => Promise<void>,
): Promise<void> {
  if (items.length === 0) return;
  const workerCount = Math.min(limit, items.length);
  let cursor = 0;
  const worker = async (): Promise<void> => {
    while (cursor < items.length) {
      const index = cursor++;
      const item = items[index];
      if (item === undefined) continue;
      await task(item);
    }
  };
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
}

interface PrefixCheck {
  suffix: string;
  password: string;
}

/**
 * Run a full breach scan over the given login items. Only items with a non-empty
 * password are considered; identical passwords are checked once and the result is
 * fanned back out to every item sharing that password.
 *
 * Contract: the returned counts (`checkedCount` + `failedCount`) sum to
 * `totalCount` ONLY when the scan ran to completion. On abort the scan stops
 * early, so the result is partial and MUST be discarded by the caller (the Vault
 * Health page checks `signal.aborted` before using it) — never rendered.
 */
export async function runBreachCheck(
  loginItems: readonly DecryptedVaultItem[],
  options: BreachCheckOptions = {},
): Promise<BreachCheckResult> {
  const { onProgress, signal } = options;

  // Group items by password (skip password-less items).
  const passwordToItems = new Map<string, DecryptedVaultItem[]>();
  for (const item of loginItems) {
    const password = typeof item.data.password === 'string' ? item.data.password : '';
    if (!password) continue;
    const existing = passwordToItems.get(password);
    if (existing) existing.push(item);
    else passwordToItems.set(password, [item]);
  }

  const uniquePasswords = [...passwordToItems.keys()];
  const totalCount = uniquePasswords.length;
  onProgress?.(0, totalCount);
  if (totalCount === 0) {
    return { breached: [], totalCount: 0, checkedCount: 0, failedCount: 0 };
  }

  // Hash each unique password and group by 5-char prefix.
  const prefixToChecks = new Map<string, PrefixCheck[]>();
  for (const password of uniquePasswords) {
    if (signal?.aborted) break;
    const hash = await sha1HexUpper(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const checks = prefixToChecks.get(prefix);
    if (checks) checks.push({ suffix, password });
    else prefixToChecks.set(prefix, [{ suffix, password }]);
  }

  const prefixes = [...prefixToChecks.keys()];
  const batches: string[][] = [];
  for (let i = 0; i < prefixes.length; i += HIBP_BATCH_MAX_PREFIXES) {
    batches.push(prefixes.slice(i, i + HIBP_BATCH_MAX_PREFIXES));
  }

  const breachedPasswordCounts = new Map<string, number>();
  let checkedCount = 0;
  let failedCount = 0;
  let processed = 0;

  const passwordsUnder = (prefixList: readonly string[]): number =>
    prefixList.reduce((sum, prefix) => sum + (prefixToChecks.get(prefix)?.length ?? 0), 0);

  const markBatchFailed = (batch: readonly string[]): void => {
    const count = passwordsUnder(batch);
    failedCount += count;
    processed += count;
    onProgress?.(processed, totalCount);
  };

  const handleBatch = async (batch: string[]): Promise<void> => {
    let attempt = 0;
    for (;;) {
      if (signal?.aborted) return;
      try {
        const response = await checkBreachBatchApi(batch, signal);
        const { data, errors } = response.data;
        const errorPrefixes = new Set(errors);
        for (const prefix of batch) {
          const checks = prefixToChecks.get(prefix) ?? [];
          const rangeText = data[prefix];
          if (rangeText === undefined || errorPrefixes.has(prefix)) {
            // Never treat an unresolved prefix as "not breached".
            failedCount += checks.length;
            processed += checks.length;
            continue;
          }
          for (const check of checks) {
            const count = findBreachCount(rangeText, check.suffix);
            if (count !== null && count > 0) {
              breachedPasswordCounts.set(check.password, count);
            }
            checkedCount += 1;
            processed += 1;
          }
        }
        onProgress?.(processed, totalCount);
        return;
      } catch (error) {
        if (signal?.aborted) return;
        const axiosError = error as AxiosError;
        if (axiosError.response?.status === 429 && attempt < MAX_RETRIES) {
          attempt += 1;
          await delay(retryAfterMs(axiosError), signal);
          continue;
        }
        markBatchFailed(batch);
        return;
      }
    }
  };

  await runWithConcurrency(batches, BATCH_CONCURRENCY, handleBatch);

  const breached: BreachFinding[] = [];
  for (const [password, count] of breachedPasswordCounts) {
    for (const item of passwordToItems.get(password) ?? []) {
      breached.push({ item, count });
    }
  }

  return { breached, totalCount, checkedCount, failedCount };
}
