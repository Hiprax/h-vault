/**
 * Lightweight client logger that only emits messages in development mode.
 * In production builds the calls are effectively no-ops, preventing
 * sensitive information from leaking into the browser console.
 */

const isDev = import.meta.env.DEV;

function noop(): void {
  // intentionally empty
}

export const logger = {
  error: isDev
    ? (...args: unknown[]) => {
        console.error(...args);
      }
    : noop,
  warn: isDev
    ? (...args: unknown[]) => {
        console.warn(...args);
      }
    : noop,
  info: isDev
    ? (...args: unknown[]) => {
        console.info(...args);
      }
    : noop,
  debug: isDev
    ? (...args: unknown[]) => {
        console.debug(...args);
      }
    : noop,
};
