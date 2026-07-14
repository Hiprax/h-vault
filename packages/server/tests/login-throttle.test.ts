/**
 * Phase 2 — `utils/loginThrottle.ts`
 *
 * The process-local per-email counter that drives the progressive login delay.
 * It exists so the delay can be applied to a NON-EXISTENT email, which has no
 * `User.failedLoginAttempts` row to count against — see the login timing
 * symmetry suite (`login-timing-symmetry.test.ts`) for the property it buys.
 *
 * Lockout is NOT this module's job; it stays in the database.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  recordFailedLoginAttempt,
  resetLoginAttempts,
  peekLoginAttempts,
  loginThrottleSize,
  clearLoginThrottle,
  LOGIN_THROTTLE_TTL_MS,
  LOGIN_THROTTLE_MAX_ENTRIES,
} from '../src/utils/loginThrottle.js';

describe('loginThrottle', () => {
  beforeEach(() => {
    clearLoginThrottle();
  });

  afterEach(() => {
    // Restore real timers BEFORE the global afterEach in tests/setup.ts runs its
    // Mongo cleanup — the driver relies on timers and would hang under fakes.
    vi.useRealTimers();
    clearLoginThrottle();
  });

  describe('recording', () => {
    it('returns a running count that increments per failed attempt', () => {
      expect(recordFailedLoginAttempt('a@example.com')).toBe(1);
      expect(recordFailedLoginAttempt('a@example.com')).toBe(2);
      expect(recordFailedLoginAttempt('a@example.com')).toBe(3);
    });

    it('counts each email independently', () => {
      recordFailedLoginAttempt('a@example.com');
      recordFailedLoginAttempt('a@example.com');
      expect(recordFailedLoginAttempt('b@example.com')).toBe(1);
      expect(peekLoginAttempts('a@example.com')).toBe(2);
    });

    it('normalizes the key (case and surrounding whitespace)', () => {
      recordFailedLoginAttempt('  User@Example.COM ');
      expect(recordFailedLoginAttempt('user@example.com')).toBe(2);
      expect(peekLoginAttempts('USER@EXAMPLE.COM')).toBe(2);
      expect(loginThrottleSize()).toBe(1);
    });
  });

  describe('peek and reset', () => {
    it('peeks 0 for an email that was never recorded', () => {
      expect(peekLoginAttempts('unknown@example.com')).toBe(0);
    });

    it('resets a single email back to 0 without touching the others', () => {
      recordFailedLoginAttempt('a@example.com');
      recordFailedLoginAttempt('a@example.com');
      recordFailedLoginAttempt('b@example.com');

      resetLoginAttempts('a@example.com');

      expect(peekLoginAttempts('a@example.com')).toBe(0);
      expect(peekLoginAttempts('b@example.com')).toBe(1);
    });

    it('restarts at 1 after a reset', () => {
      recordFailedLoginAttempt('a@example.com');
      recordFailedLoginAttempt('a@example.com');
      resetLoginAttempts('a@example.com');

      expect(recordFailedLoginAttempt('a@example.com')).toBe(1);
    });

    it('tolerates resetting an email that was never recorded', () => {
      expect(() => {
        resetLoginAttempts('never@example.com');
      }).not.toThrow();
    });

    it('clears every tracked email', () => {
      recordFailedLoginAttempt('a@example.com');
      recordFailedLoginAttempt('b@example.com');

      clearLoginThrottle();

      expect(loginThrottleSize()).toBe(0);
      expect(peekLoginAttempts('a@example.com')).toBe(0);
    });
  });

  describe('TTL expiry', () => {
    it('treats an entry older than the TTL as absent and restarts the count', () => {
      vi.useFakeTimers();

      recordFailedLoginAttempt('a@example.com');
      expect(recordFailedLoginAttempt('a@example.com')).toBe(2);

      vi.advanceTimersByTime(LOGIN_THROTTLE_TTL_MS + 1);

      expect(peekLoginAttempts('a@example.com')).toBe(0);
      expect(recordFailedLoginAttempt('a@example.com')).toBe(1);
    });

    it('slides the expiry forward on each new attempt', () => {
      vi.useFakeTimers();

      // Step to just short of the TTL, twice. A fixed (non-sliding) window
      // would have expired the entry well before the second step lands, so the
      // count would restart at 1 instead of continuing.
      const ALMOST_TTL = LOGIN_THROTTLE_TTL_MS - 60_000;

      recordFailedLoginAttempt('a@example.com');

      vi.advanceTimersByTime(ALMOST_TTL);
      expect(recordFailedLoginAttempt('a@example.com')).toBe(2);

      vi.advanceTimersByTime(ALMOST_TTL);
      expect(peekLoginAttempts('a@example.com')).toBe(2);
      expect(recordFailedLoginAttempt('a@example.com')).toBe(3);
    });

    it('prunes expired entries so the map does not grow unbounded', () => {
      vi.useFakeTimers();

      recordFailedLoginAttempt('stale-1@example.com');
      recordFailedLoginAttempt('stale-2@example.com');
      expect(loginThrottleSize()).toBe(2);

      // Past the TTL, the next record triggers the lazy sweep (the prune
      // interval has also elapsed), collecting both stale entries.
      vi.advanceTimersByTime(LOGIN_THROTTLE_TTL_MS + 1);
      recordFailedLoginAttempt('fresh@example.com');

      expect(loginThrottleSize()).toBe(1);
      expect(peekLoginAttempts('fresh@example.com')).toBe(1);
    });
  });

  describe('bounded memory', () => {
    it('never exceeds the entry cap, evicting the least recently recorded email', () => {
      for (let i = 0; i < LOGIN_THROTTLE_MAX_ENTRIES; i++) {
        recordFailedLoginAttempt(`user-${String(i)}@example.com`);
      }
      expect(loginThrottleSize()).toBe(LOGIN_THROTTLE_MAX_ENTRIES);

      recordFailedLoginAttempt('overflow@example.com');

      expect(loginThrottleSize()).toBe(LOGIN_THROTTLE_MAX_ENTRIES);
      // The oldest key is gone; the newest is tracked.
      expect(peekLoginAttempts('user-0@example.com')).toBe(0);
      expect(peekLoginAttempts('overflow@example.com')).toBe(1);
      expect(peekLoginAttempts(`user-${String(LOGIN_THROTTLE_MAX_ENTRIES - 1)}@example.com`)).toBe(
        1,
      );
    });

    it('re-recording an email refreshes its recency, sparing it from eviction', () => {
      for (let i = 0; i < LOGIN_THROTTLE_MAX_ENTRIES; i++) {
        recordFailedLoginAttempt(`user-${String(i)}@example.com`);
      }

      // Touch the oldest entry so it moves to the end of the eviction order.
      expect(recordFailedLoginAttempt('user-0@example.com')).toBe(2);

      recordFailedLoginAttempt('overflow@example.com');

      expect(peekLoginAttempts('user-0@example.com')).toBe(2);
      // `user-1` is now the least recently recorded, so it took the eviction.
      expect(peekLoginAttempts('user-1@example.com')).toBe(0);
      expect(loginThrottleSize()).toBe(LOGIN_THROTTLE_MAX_ENTRIES);
    });
  });
});
