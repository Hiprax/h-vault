/**
 * The two tiny eager modules around the release notes: the per-release notice
 * dismissal (a per-browser convenience that must survive blocked storage) and the
 * service-worker handle the release store pokes when the server's version moves.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { dismissUpdateNotice, isUpdateNoticeDismissed } from '../../src/lib/updateNoticeDismissal';

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

describe('update notice dismissal', () => {
  it('remembers the dismissed release, and only that release', () => {
    expect(isUpdateNoticeDismissed('0.16.0')).toBe(false);
    dismissUpdateNotice('0.16.0');
    expect(isUpdateNoticeDismissed('0.16.0')).toBe(true);
    expect(isUpdateNoticeDismissed('0.17.0')).toBe(false);
    expect(localStorage.getItem('hvault_dismissed_update')).toBe('0.16.0');
  });

  it('treats blocked storage as "not dismissed" and never throws', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('blocked', 'SecurityError');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('full', 'QuotaExceededError');
    });
    expect(() => dismissUpdateNotice('0.16.0')).not.toThrow();
    expect(isUpdateNoticeDismissed('0.16.0')).toBe(false);
  });
});

describe('service worker update handle', () => {
  it('does nothing before a registration is known, then asks that registration to update', async () => {
    vi.resetModules();
    const handle = await import('../../src/lib/serviceWorkerUpdate');
    expect(() => handle.requestServiceWorkerUpdate()).not.toThrow();
    const update = vi.fn().mockResolvedValue(undefined);
    handle.rememberServiceWorkerRegistration({ update } as unknown as ServiceWorkerRegistration);
    handle.requestServiceWorkerUpdate();
    expect(update).toHaveBeenCalledTimes(1);
  });

  it('drops a failed update check instead of letting it reject', async () => {
    vi.resetModules();
    const handle = await import('../../src/lib/serviceWorkerUpdate');
    const update = vi.fn().mockRejectedValue(new Error('offline'));
    handle.rememberServiceWorkerRegistration({ update } as unknown as ServiceWorkerRegistration);
    handle.requestServiceWorkerUpdate();
    await Promise.resolve();
    expect(update).toHaveBeenCalledTimes(1);
  });
});
