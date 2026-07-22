/**
 * Dedicated Web Worker that runs zxcvbn password-strength scoring off the main
 * thread, so the Vault Health page never freezes when analyzing a large vault.
 *
 * It receives a list of unique passwords, scores them (posting periodic progress),
 * and returns a `[password, score]` map. It holds NO account key material and does
 * NO network I/O. This file is intentionally a thin entry point (excluded from
 * coverage); all real logic lives in the directly-tested `scorePasswords`.
 *
 * zxcvbn is imported statically so Vite emits a self-contained classic worker
 * chunk (widest browser support, no module-worker requirement); its ~820 kB
 * dictionary lives in that chunk and is fetched only when this worker is spawned.
 */
import zxcvbn from 'zxcvbn';
import { scorePasswords } from '../services/health/passwordStrength';

// Typed minimally to avoid the "WebWorker" lib, which conflicts with the "DOM"
// lib this project compiles against (duplicate global declarations).
const ctx = self as unknown as {
  postMessage: (message: unknown) => void;
  onmessage: ((event: { data: unknown }) => void) | null;
};

ctx.onmessage = (event: { data: unknown }): void => {
  const payload = event.data as { passwords?: readonly string[] } | null;
  const passwords = payload?.passwords ?? [];
  void scorePasswords(passwords, (password) => zxcvbn(password), {
    onProgress: (done, total) => {
      ctx.postMessage({ type: 'progress', done, total });
    },
  }).then(
    (scores) => {
      ctx.postMessage({ type: 'result', scores: [...scores.entries()] });
    },
    (error: unknown) => {
      // A rejection MUST be reported explicitly. An unhandled rejection inside a
      // worker does NOT fire the host's `worker.onerror`, so staying silent here
      // would leave the host's promise pending forever and park the page on
      // "Analyzing…" instead of degrading to the main-thread scorer.
      ctx.postMessage({
        type: 'error',
        message: error instanceof Error ? error.message : 'Password scoring failed',
      });
    },
  );
};
