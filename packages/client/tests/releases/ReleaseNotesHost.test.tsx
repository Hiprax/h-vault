/**
 * When "What's new" opens by itself, and when it must not: once per unlocked
 * mount, never over another modal, never while the first-run guide is showing,
 * never from a later refresh, and never again after a failed load.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { makeStatus, makeUpdate } from './fixtures';

const api = vi.hoisted(() => ({ status: vi.fn(), seen: vi.fn(), check: vi.fn() }));
const dialog = vi.hoisted(() => ({ fail: false }));

vi.mock('../../src/services/api/releaseStatusApi', () => ({
  getReleaseStatusApi: api.status,
  markReleaseNotesSeenApi: api.seen,
  checkForUpdateNowApi: api.check,
}));
// The auth store persists through encryptedStorage, which encrypts
// asynchronously: a write started by the last setState of this file could land
// after the environment is gone and fail with "localStorage is not defined".
// Persistence is not what these cases pin, so it resolves at once.
vi.mock('../../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
  isStorageDegraded: vi.fn().mockReturnValue(false),
}));
vi.mock('../../src/components/releases/WhatsNewDialog', () => ({
  default: ({ userId, version }: { userId: string; version: string }) => {
    if (dialog.fail) throw new Error('chunk failed');
    return (
      <div role="dialog" aria-modal="true" data-testid="whats-new">{`${userId}:${version}`}</div>
    );
  },
}));

import { ReleaseNotesHost } from '../../src/components/releases/ReleaseNotesHost';
import { _resetReleaseStoreForTests, useReleaseStore } from '../../src/stores/releaseStore';
import { useAuthStore } from '../../src/stores/authStore';
import { useUIStore } from '../../src/stores/uiStore';

function signIn(userId = 'user-a') {
  useAuthStore.setState({ user: { userId, email: `${userId}@example.com` } });
}

/**
 * Renders the host and waits for ITS status request to settle. Called straight
 * after `render`, `loadStatus` returns the request the mount effect already
 * started (the store de-duplicates per account), so this waits on the host's
 * own read rather than issuing a second one.
 */
async function mount() {
  const view = render(
    <MemoryRouter>
      <ReleaseNotesHost />
    </MemoryRouter>,
  );
  const userId = useAuthStore.getState().user?.userId;
  if (userId !== undefined) {
    const pending = useReleaseStore.getState().loadStatus(userId);
    await act(async () => {
      await pending;
    });
  }
  return view;
}

beforeEach(() => {
  _resetReleaseStoreForTests();
  api.status.mockReset();
  api.seen.mockReset();
  dialog.fail = false;
  localStorage.clear();
  useUIStore.setState({ onboardingActive: false });
  signIn();
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  useAuthStore.setState({ user: null });
});

describe('ReleaseNotesHost', () => {
  it('reads the status for the signed-in account when it mounts', async () => {
    api.status.mockResolvedValue(makeStatus({ releaseNotes: { unseenCount: 0 } }));
    await mount();
    expect(api.status).toHaveBeenCalledTimes(1);
    expect(useReleaseStore.getState().statusUserId).toBe('user-a');
  });

  it('opens by itself when there are unread notes the account wants shown', async () => {
    api.status.mockResolvedValue(makeStatus());
    await mount();
    expect(await screen.findByTestId('whats-new')).toHaveTextContent('user-a:0.15.0');
  });

  it('judges the status THIS mount read, not the one left from before a lock', async () => {
    // The store still holds the answer from before the lock: nothing unread.
    useReleaseStore.setState({
      status: makeStatus({ releaseNotes: { unseenCount: 0 } }),
      statusUserId: 'user-a',
    });
    api.status.mockResolvedValue(makeStatus({ releaseNotes: { unseenCount: 2 } }));
    await mount();
    expect(await screen.findByTestId('whats-new')).toBeInTheDocument();
  });

  it.each([
    ['nothing is unread', makeStatus({ releaseNotes: { unseenCount: 0 } })],
    ['the account turned it off', makeStatus({ releaseNotes: { showOnUpdate: false } })],
  ])('stays closed when %s', async (_label, status) => {
    api.status.mockResolvedValue(status);
    await mount();
    expect(screen.queryByTestId('whats-new')).toBeNull();
    expect(useReleaseStore.getState().dialogOpen).toBe(false);
  });

  it('never opens over another modal', async () => {
    const other = document.createElement('div');
    other.setAttribute('aria-modal', 'true');
    document.body.append(other);
    api.status.mockResolvedValue(makeStatus());
    await mount();
    expect(useReleaseStore.getState().dialogOpen).toBe(false);
    other.remove();
  });

  it('waits for the first-run guide, then opens once it closes', async () => {
    useUIStore.setState({ onboardingActive: true });
    api.status.mockResolvedValue(makeStatus());
    await mount();
    expect(useReleaseStore.getState().dialogOpen).toBe(false);
    act(() => {
      useUIStore.setState({ onboardingActive: false });
    });
    expect(await screen.findByTestId('whats-new')).toBeInTheDocument();
  });

  it('opens at most once per mount, so a later refresh does not reopen it', async () => {
    api.status.mockResolvedValue(makeStatus());
    await mount();
    await screen.findByTestId('whats-new');
    act(() => {
      useReleaseStore.getState().closeDialog('user-a', undefined);
    });
    // A newer status arrives (for instance from the visibility refresh).
    api.status.mockResolvedValue(
      makeStatus({ version: '0.15.1', releaseNotes: { unseenCount: 2 } }),
    );
    await act(async () => {
      await useReleaseStore.getState().loadStatus('user-a');
    });
    expect(useReleaseStore.getState().dialogOpen).toBe(false);
  });

  it('refreshes on becoming visible only after five minutes', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-09-28T12:00:00Z'));
    api.status.mockResolvedValue(makeStatus({ releaseNotes: { unseenCount: 0 } }));
    await mount();
    expect(api.status).toHaveBeenCalledTimes(1);
    const becomeVisible = async () => {
      Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
      await act(async () => {
        document.dispatchEvent(new Event('visibilitychange'));
        await Promise.resolve();
      });
    };
    vi.setSystemTime(new Date('2026-09-28T12:04:59Z'));
    await becomeVisible();
    expect(api.status).toHaveBeenCalledTimes(1);
    vi.setSystemTime(new Date('2026-09-28T12:05:01Z'));
    await becomeVisible();
    expect(api.status).toHaveBeenCalledTimes(2);
    vi.useRealTimers();
  });

  it('ignores the tab becoming hidden', async () => {
    api.status.mockResolvedValue(makeStatus({ releaseNotes: { unseenCount: 0 } }));
    await mount();
    Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
    useReleaseStore.setState({ statusLoadedAt: 0 });
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'));
      await Promise.resolve();
    });
    expect(api.status).toHaveBeenCalledTimes(1);
    Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
  });

  it('closes, without acknowledging, when the dialog fails to load', async () => {
    dialog.fail = true;
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    api.status.mockResolvedValue(makeStatus());
    await mount();
    await waitFor(() => {
      expect(useReleaseStore.getState().dialogOpen).toBe(false);
    });
    expect(api.seen).not.toHaveBeenCalled();
    expect(screen.queryByTestId('whats-new')).toBeNull();
  });

  it('shows administrators a newer release until they dismiss it, per release', async () => {
    api.status.mockResolvedValue(
      makeStatus({
        releaseNotes: { unseenCount: 0 },
        update: makeUpdate({ state: 'available', latestVersion: '0.16.0' }),
      }),
    );
    await mount();
    expect(await screen.findByText('H-Vault 0.16.0 is available.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /View release/ })).toHaveAttribute(
      'href',
      'https://github.com/Hiprax/h-vault/releases/tag/v0.15.0',
    );
    fireEvent.click(
      screen.getByRole('button', { name: 'Dismiss the notice about H-Vault 0.16.0' }),
    );
    expect(screen.queryByText('H-Vault 0.16.0 is available.')).toBeNull();
    expect(localStorage.getItem('hvault_dismissed_update')).toBe('0.16.0');
  });

  it('does not show a notice already dismissed for that release', async () => {
    localStorage.setItem('hvault_dismissed_update', '0.16.0');
    api.status.mockResolvedValue(
      makeStatus({
        releaseNotes: { unseenCount: 0 },
        update: makeUpdate({ state: 'available', latestVersion: '0.16.0' }),
      }),
    );
    await mount();
    expect(screen.queryByText('H-Vault 0.16.0 is available.')).toBeNull();
  });

  it('hides the release link when the server sends one that is not GitHub', async () => {
    api.status.mockResolvedValue(
      makeStatus({
        releaseNotes: { unseenCount: 0 },
        update: makeUpdate({
          state: 'available',
          latestVersion: '0.16.0',
          releaseUrl: 'https://example.com/fake',
        }),
      }),
    );
    await mount();
    await screen.findByText('H-Vault 0.16.0 is available.');
    expect(screen.queryByRole('link', { name: /View release/ })).toBeNull();
  });

  it('closes with the shell on a lock, acknowledging nothing, and stays closed on unlock', async () => {
    api.status.mockResolvedValue(makeStatus());
    const view = await mount();
    expect(await screen.findByTestId('whats-new')).toBeInTheDocument();

    // Locking replaces the whole shell with the unlock screen.
    view.unmount();
    expect(useReleaseStore.getState().dialogOpen).toBe(false);
    expect(api.seen).not.toHaveBeenCalled();

    // Unlocking mounts it again; this release was already offered once.
    await mount();
    expect(screen.queryByTestId('whats-new')).toBeNull();
    expect(useReleaseStore.getState().dialogOpen).toBe(false);
  });

  it('never carries an open dialog over to the next account to sign in', async () => {
    api.status.mockResolvedValue(makeStatus());
    const view = await mount();
    expect(await screen.findByTestId('whats-new')).toHaveTextContent('user-a:0.15.0');

    view.unmount();
    signIn('user-b');
    api.status.mockResolvedValue(makeStatus({ releaseNotes: { unseenCount: 0 } }));
    await mount();
    expect(useReleaseStore.getState().statusUserId).toBe('user-b');
    expect(screen.queryByTestId('whats-new')).toBeNull();
    expect(useReleaseStore.getState().dialogOpen).toBe(false);
    expect(api.seen).not.toHaveBeenCalled();
  });

  it('does nothing without a signed-in account', async () => {
    useAuthStore.setState({ user: null });
    await mount();
    expect(api.status).not.toHaveBeenCalled();
  });
});
