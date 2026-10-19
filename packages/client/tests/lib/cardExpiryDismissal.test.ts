/**
 * `lib/cardExpiryDismissal.ts`: the per-browser memory of a hidden card expiry
 * reminder.
 *
 * The fingerprint values are GOLDEN: FNV-1a 32-bit over the UTF-8 bytes of the
 * input, computed by an independent implementation (checked against the
 * algorithm's published vectors: `""` is 811c9dc5, `"a"` e40c292c, `"foobar"`
 * bf9cf968), never by calling this module. A change to the hash, the byte
 * encoding, the separator or the sorting would change what a browser stored
 * yesterday into something that no longer matches, so every existing dismissal
 * would quietly come back; these values are what notices.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  cardExpiryFingerprint,
  dismissCardExpiryReminder,
  isCardExpiryReminderDismissed,
} from '../../src/lib/cardExpiryDismissal';

const STORAGE_KEY = 'hvault_dismissed_card_expiry';

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

describe('cardExpiryFingerprint', () => {
  it('hashes the account and the sorted id:status pairs (golden values)', () => {
    expect(
      cardExpiryFingerprint('user-1', [
        { id: 'b', status: 'expired' },
        { id: 'a', status: 'expiring' },
      ]),
    ).toBe('118d0c0e');
    // Eight digits always, with the leading zero kept: the hash of "\n".
    expect(cardExpiryFingerprint('', [])).toBe('0f0c6cdd');
    expect(cardExpiryFingerprint('u', [{ id: 'x', status: 'expired' }])).toBe('25680159');
  });

  it('hashes UTF-8 bytes, not UTF-16 code units', () => {
    expect(cardExpiryFingerprint('é', [])).toBe('fd957791');
  });

  it('does not depend on the order the vault lists its cards in', () => {
    const forward = cardExpiryFingerprint('user-1', [
      { id: 'a', status: 'expiring' },
      { id: 'b', status: 'expired' },
      { id: 'c', status: 'expiring' },
    ]);
    const reversed = cardExpiryFingerprint('user-1', [
      { id: 'c', status: 'expiring' },
      { id: 'b', status: 'expired' },
      { id: 'a', status: 'expiring' },
    ]);
    expect(reversed).toBe(forward);
  });

  it('changes for another account, a changed status, or an added card', () => {
    const entries = [
      { id: 'a', status: 'expiring' },
      { id: 'b', status: 'expired' },
    ] as const;
    const base = cardExpiryFingerprint('user-1', entries);
    expect(cardExpiryFingerprint('user-2', entries)).toBe('8053fb71');
    expect(
      cardExpiryFingerprint('user-1', [
        { id: 'a', status: 'expired' },
        { id: 'b', status: 'expired' },
      ]),
    ).toBe('7e65d801');
    const added = cardExpiryFingerprint('user-1', [...entries, { id: 'c', status: 'expiring' }]);
    expect(new Set([base, '8053fb71', '7e65d801', added]).size).toBe(4);
  });

  it('stores nothing a card could be recognised by', () => {
    const fingerprint = cardExpiryFingerprint('65f0c0ffee0000000000abcd', [
      { id: '65f0c0ffee0000000000beef', status: 'expired' },
    ]);
    dismissCardExpiryReminder(fingerprint);
    const stored = localStorage.getItem(STORAGE_KEY);
    expect(stored).toMatch(/^[0-9a-f]{8}$/);
    expect(stored).not.toContain('beef');
    expect(stored).not.toContain('expired');
    expect(localStorage).toHaveLength(1);
  });
});

describe('the dismissal', () => {
  it('remembers the hidden fingerprint, and only that one', () => {
    expect(isCardExpiryReminderDismissed('118d0c0e')).toBe(false);
    dismissCardExpiryReminder('118d0c0e');
    expect(isCardExpiryReminderDismissed('118d0c0e')).toBe(true);
    expect(isCardExpiryReminderDismissed('7e65d801')).toBe(false);
    expect(localStorage.getItem(STORAGE_KEY)).toBe('118d0c0e');
  });

  it('keeps one value: hiding a newer set replaces the older one', () => {
    dismissCardExpiryReminder('118d0c0e');
    dismissCardExpiryReminder('7e65d801');
    expect(isCardExpiryReminderDismissed('7e65d801')).toBe(true);
    expect(isCardExpiryReminderDismissed('118d0c0e')).toBe(false);
    expect(localStorage).toHaveLength(1);
  });

  it('treats blocked storage as "not hidden" and never throws', () => {
    const getItem = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('blocked', 'SecurityError');
    });
    const setItem = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('full', 'QuotaExceededError');
    });
    expect(() => dismissCardExpiryReminder('118d0c0e')).not.toThrow();
    expect(isCardExpiryReminderDismissed('118d0c0e')).toBe(false);
    expect(setItem).toHaveBeenCalledWith(STORAGE_KEY, '118d0c0e');
    expect(getItem).toHaveBeenCalledWith(STORAGE_KEY);
  });
});
