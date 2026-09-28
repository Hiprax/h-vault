/**
 * The release store: status tagged by account, one request at a time, late
 * answers dropped, the dialog offered once per session per release, and notes
 * acknowledged only once they were actually shown.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { makeStatus, makeUpdate } from './fixtures';

const api = vi.hoisted(() => ({ status: vi.fn(), seen: vi.fn(), check: vi.fn() }));
const sw = vi.hoisted(() => ({ request: vi.fn() }));

vi.mock('../../src/services/api/releaseStatusApi', () => ({
  getReleaseStatusApi: api.status,
  markReleaseNotesSeenApi: api.seen,
  checkForUpdateNowApi: api.check,
}));
vi.mock('../../src/lib/serviceWorkerUpdate', () => ({
  requestServiceWorkerUpdate: sw.request,
  rememberServiceWorkerRegistration: vi.fn(),
}));

import {
  _resetReleaseStoreForTests,
  markReleaseNotesOffered,
  releaseStatusFor,
  shouldAutoOpenReleaseNotes,
  useReleaseStore,
} from '../../src/stores/releaseStore';

/** A promise and the functions that settle it. */
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

beforeEach(() => {
  _resetReleaseStoreForTests();
  api.status.mockReset();
  api.seen.mockReset();
  sw.request.mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('loadStatus', () => {
  it('stores the status for the account it was read for, with when it was read', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-09-28T12:00:00Z'));
    const status = makeStatus();
    api.status.mockResolvedValue(status);
    await useReleaseStore.getState().loadStatus('user-a');
    const state = useReleaseStore.getState();
    expect(state.status).toEqual(status);
    expect(state.statusUserId).toBe('user-a');
    expect(state.statusLoadedAt).toBe(Date.parse('2026-09-28T12:00:00Z'));
    expect(releaseStatusFor(state, 'user-a')).toEqual(status);
    expect(releaseStatusFor(state, 'user-b')).toBeNull();
    expect(releaseStatusFor(state, undefined)).toBeNull();
  });

  it('asks once while a request for the same account is in flight', async () => {
    const answer = deferred<ReturnType<typeof makeStatus>>();
    api.status.mockReturnValue(answer.promise);
    const first = useReleaseStore.getState().loadStatus('user-a');
    const second = useReleaseStore.getState().loadStatus('user-a');
    expect(second).toBe(first);
    answer.resolve(makeStatus());
    await first;
    expect(api.status).toHaveBeenCalledTimes(1);
    // Once settled, a new call asks again.
    api.status.mockResolvedValue(makeStatus());
    await useReleaseStore.getState().loadStatus('user-a');
    expect(api.status).toHaveBeenCalledTimes(2);
  });

  it('keeps what it had when a read fails, and never rejects', async () => {
    const status = makeStatus();
    api.status.mockResolvedValueOnce(status).mockRejectedValueOnce(new Error('offline'));
    await useReleaseStore.getState().loadStatus('user-a');
    await expect(useReleaseStore.getState().loadStatus('user-a')).resolves.toBeUndefined();
    expect(useReleaseStore.getState().status).toEqual(status);
  });

  it('drops a late answer from a request a newer one superseded', async () => {
    const slow = deferred<ReturnType<typeof makeStatus>>();
    api.status
      .mockReturnValueOnce(slow.promise)
      .mockResolvedValueOnce(makeStatus({ version: '0.15.0' }));
    const stale = useReleaseStore.getState().loadStatus('user-a');
    await useReleaseStore.getState().loadStatus('user-b');
    slow.resolve(makeStatus({ version: '0.14.1' }));
    await stale;
    expect(useReleaseStore.getState().statusUserId).toBe('user-b');
    expect(useReleaseStore.getState().status?.version).toBe('0.15.0');
  });

  it('asks the browser for the new build, and names it, when the server version changes', async () => {
    api.status
      .mockResolvedValueOnce(makeStatus({ version: '0.15.0' }))
      .mockResolvedValueOnce(makeStatus({ version: '0.15.0' }))
      .mockResolvedValueOnce(makeStatus({ version: '0.16.0' }));
    await useReleaseStore.getState().loadStatus('user-a');
    await useReleaseStore.getState().loadStatus('user-a');
    expect(sw.request).not.toHaveBeenCalled();
    expect(useReleaseStore.getState().serverUpdatedTo).toBeNull();
    await useReleaseStore.getState().loadStatus('user-a');
    expect(sw.request).toHaveBeenCalledTimes(1);
    expect(useReleaseStore.getState().serverUpdatedTo).toBe('0.16.0');
  });
});

describe('shouldAutoOpenReleaseNotes', () => {
  it('opens for unread notes the account wants shown, once per release', () => {
    const status = makeStatus();
    expect(shouldAutoOpenReleaseNotes(status, 'user-a')).toBe(true);
    markReleaseNotesOffered('user-a', status.version);
    expect(shouldAutoOpenReleaseNotes(status, 'user-a')).toBe(false);
    // Another account, or another release, is its own decision.
    expect(shouldAutoOpenReleaseNotes(status, 'user-b')).toBe(true);
    expect(shouldAutoOpenReleaseNotes(makeStatus({ version: '0.16.0' }), 'user-a')).toBe(true);
  });

  it('does not open with nothing unread, or when the account turned it off', () => {
    expect(shouldAutoOpenReleaseNotes(makeStatus({ releaseNotes: { unseenCount: 0 } }), 'u')).toBe(
      false,
    );
    expect(
      shouldAutoOpenReleaseNotes(makeStatus({ releaseNotes: { showOnUpdate: false } }), 'u'),
    ).toBe(false);
  });
});

describe('openDialog', () => {
  it('starts one session per opening, and a repeat while open is not a new one', () => {
    useReleaseStore.getState().openDialog();
    useReleaseStore.getState().openDialog();
    expect(useReleaseStore.getState()).toMatchObject({ dialogOpen: true, dialogSession: 1 });
    useReleaseStore.getState().closeDialog('user-a', undefined);
    useReleaseStore.getState().openDialog();
    expect(useReleaseStore.getState()).toMatchObject({ dialogOpen: true, dialogSession: 2 });
  });
});

describe('the dialog', () => {
  async function loaded(status = makeStatus()) {
    api.status.mockResolvedValue(status);
    await useReleaseStore.getState().loadStatus('user-a');
    useReleaseStore.getState().openDialog();
    expect(useReleaseStore.getState().dialogOpen).toBe(true);
  }

  it('acknowledges the shown release: at once on screen, then as the server stored it', async () => {
    await loaded();
    const saved = deferred<{ seenVersion: string; unseenCount: number }>();
    api.seen.mockReturnValue(saved.promise);
    useReleaseStore.getState().closeDialog('user-a', '0.15.0');
    expect(api.seen).toHaveBeenCalledWith('0.15.0');
    let state = useReleaseStore.getState();
    expect(state.dialogOpen).toBe(false);
    expect(state.status?.releaseNotes).toEqual({
      seenVersion: '0.15.0',
      unseenCount: 0,
      showOnUpdate: true,
    });
    saved.resolve({ seenVersion: '0.15.0', unseenCount: 0 });
    await saved.promise;
    await Promise.resolve();
    state = useReleaseStore.getState();
    expect(state.status?.releaseNotes.seenVersion).toBe('0.15.0');
    expect(shouldAutoOpenReleaseNotes(makeStatus(), 'user-a')).toBe(false);
  });

  it('acknowledges nothing when the notes were never shown', async () => {
    await loaded();
    useReleaseStore.getState().closeDialog('user-a', undefined);
    expect(useReleaseStore.getState().dialogOpen).toBe(false);
    expect(api.seen).not.toHaveBeenCalled();
    expect(useReleaseStore.getState().status?.releaseNotes.unseenCount).toBe(1);
    expect(shouldAutoOpenReleaseNotes(makeStatus(), 'user-a')).toBe(true);
  });

  it('does not ask the server when nothing was unread, but still counts the release as offered', async () => {
    await loaded(makeStatus({ releaseNotes: { unseenCount: 0 } }));
    useReleaseStore.getState().closeDialog('user-a', '0.15.0');
    expect(api.seen).not.toHaveBeenCalled();
    expect(shouldAutoOpenReleaseNotes(makeStatus(), 'user-a')).toBe(false);
  });

  it('keeps the notes read on screen when the save fails, and does not retry', async () => {
    await loaded();
    api.seen.mockRejectedValue(new Error('offline'));
    useReleaseStore.getState().closeDialog('user-a', '0.15.0');
    await Promise.resolve();
    await Promise.resolve();
    expect(api.seen).toHaveBeenCalledTimes(1);
    expect(useReleaseStore.getState().status?.releaseNotes.unseenCount).toBe(0);
  });

  it('never acknowledges on behalf of an account whose status is not loaded', async () => {
    await loaded();
    useReleaseStore.getState().closeDialog('user-b', '0.15.0');
    expect(api.seen).not.toHaveBeenCalled();
  });

  it('ignores a save answer that arrives after another account signed in', async () => {
    await loaded();
    const saved = deferred<{ seenVersion: string; unseenCount: number }>();
    api.seen.mockReturnValue(saved.promise);
    useReleaseStore.getState().closeDialog('user-a', '0.15.0');
    api.status.mockResolvedValue(makeStatus({ releaseNotes: { unseenCount: 4 } }));
    await useReleaseStore.getState().loadStatus('user-b');
    saved.resolve({ seenVersion: '0.15.0', unseenCount: 0 });
    await saved.promise;
    await Promise.resolve();
    expect(useReleaseStore.getState().status?.releaseNotes.unseenCount).toBe(4);
  });
});

describe('applyUpdateStatus', () => {
  it('replaces the update block for the loaded account only', async () => {
    api.status.mockResolvedValue(makeStatus({ update: makeUpdate() }));
    await useReleaseStore.getState().loadStatus('user-a');
    const available = makeUpdate({ state: 'available', latestVersion: '0.16.0' });
    useReleaseStore.getState().applyUpdateStatus('user-b', available);
    expect(useReleaseStore.getState().status?.update?.state).toBe('current');
    useReleaseStore.getState().applyUpdateStatus('user-a', available);
    expect(useReleaseStore.getState().status?.update).toEqual(available);
  });

  it('does nothing before any status has loaded', () => {
    useReleaseStore.getState().applyUpdateStatus('user-a', makeUpdate());
    expect(useReleaseStore.getState().status).toBeNull();
  });
});
