/**
 * Pure password-strength scoring, shared by the Web Worker and the main-thread
 * fallback. It deliberately imports nothing that touches the DOM, a Web Worker,
 * or account state so it can be bundled into the worker graph without dragging in
 * the orchestrator (which references `new Worker(...)`). All zxcvbn access is
 * injected, so this module is trivially unit-testable without loading the real
 * ~820 kB dictionary.
 */

/** The single zxcvbn capability this module needs: a score for a password. */
export type ZxcvbnScoreFn = (password: string) => { score: number };

/**
 * zxcvbn scores below this are treated as "weak" on the Vault Health page.
 * (zxcvbn: 0 very weak … 4 very strong; < 3 means "fair or worse".)
 */
export const WEAK_SCORE_THRESHOLD = 3;

/** How many passwords are scored between progress callbacks / cooperative yields. */
const SCORE_PROGRESS_CHUNK = 25;

export interface ScorePasswordsOptions {
  /** Called after each chunk (and once at the end) with `(done, total)`. */
  onProgress?: (done: number, total: number) => void;
  /** Cancels scoring cooperatively; on abort the partial map is returned. */
  signal?: AbortSignal;
  /**
   * Optional yield between chunks. The main-thread fallback passes a macrotask
   * yield so the browser can paint and handle input between chunks; the worker
   * passes none so it runs at full speed on its background thread.
   */
  yieldFn?: () => Promise<void>;
}

/**
 * Scores each UNIQUE password once (duplicates collapse) and returns a
 * `password -> score` map. Honors `signal`: on abort it stops and returns what it
 * has. It does not catch errors from the injected `zxcvbn` — a scorer that threw
 * would reject the call (which the caller then treats as an analysis failure);
 * the real zxcvbn does not throw on the bounded strings passed here.
 */
export async function scorePasswords(
  passwords: readonly string[],
  zxcvbn: ZxcvbnScoreFn,
  options: ScorePasswordsOptions = {},
): Promise<Map<string, number>> {
  const { onProgress, signal, yieldFn } = options;
  const unique = [...new Set(passwords)];
  const scores = new Map<string, number>();
  const total = unique.length;

  // `entries()` yields defined values (no noUncheckedIndexedAccess guard needed)
  // and the numeric index for chunk boundaries.
  for (const [index, candidate] of unique.entries()) {
    if (signal?.aborted) return scores;
    scores.set(candidate, zxcvbn(candidate).score);
    if ((index + 1) % SCORE_PROGRESS_CHUNK === 0) {
      onProgress?.(index + 1, total);
      if (yieldFn) await yieldFn();
    }
  }

  if (!signal?.aborted) onProgress?.(total, total);
  return scores;
}
