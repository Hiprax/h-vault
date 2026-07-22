/**
 * Per-session cache of zxcvbn strength scores, keyed by `${itemId}:${updatedAt}`.
 *
 * A score is reused across re-renders and page revisits (so the Vault Health page
 * does not re-run zxcvbn over the whole vault on every streamed page or navigation)
 * but is recomputed the moment an item changes, because its `updatedAt` bumps and
 * the key no longer matches. Values are plain integers (the zxcvbn 0-4 score); NO
 * plaintext password is ever stored here, so this holds no secret. It is cleared on
 * vault lock/logout via `vaultStore.clearStore()` as memory hygiene, not because it
 * is sensitive.
 */

/**
 * Hard cap on cached scores. Editing items mints new keys (old ones linger), so an
 * unbounded map could grow across a very long session; this bounds it. ~2x
 * MAX_ITEMS_PER_USER comfortably covers a full vault plus churn. Eviction is
 * oldest-first (Map preserves insertion order). The cache is also fully cleared on
 * lock/logout, so this cap only matters within one unlocked session.
 */
export const STRENGTH_CACHE_MAX_ENTRIES = 20_000;

const scoreCache = new Map<string, number>();

export function strengthCacheKey(id: string, version: string): string {
  return `${id}:${version}`;
}

export function getScore(key: string): number | undefined {
  return scoreCache.get(key);
}

export function setScore(key: string, score: number): void {
  if (!scoreCache.has(key) && scoreCache.size >= STRENGTH_CACHE_MAX_ENTRIES) {
    const oldest = scoreCache.keys().next().value;
    if (oldest !== undefined) scoreCache.delete(oldest);
  }
  scoreCache.set(key, score);
}

export function clearScoreCache(): void {
  scoreCache.clear();
}
