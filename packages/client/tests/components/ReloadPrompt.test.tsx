import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup, act } from '@testing-library/react';
import React from 'react';

// Override the virtual module alias mock to capture onRegisteredSW
let mockNeedRefresh = false;
const mockSetNeedRefresh = vi.fn();
const mockUpdateServiceWorker = vi.fn();
let capturedOnRegisteredSW: ((url: string, reg: { update: () => void }) => void) | undefined;

vi.mock('virtual:pwa-register/react', () => ({
  useRegisterSW: (opts?: {
    onRegisteredSW?: (url: string, reg: { update: () => void }) => void;
  }) => {
    capturedOnRegisteredSW = opts?.onRegisteredSW;
    return {
      needRefresh: [mockNeedRefresh, mockSetNeedRefresh] as [boolean, (v: boolean) => void],
      offlineReady: [false, vi.fn()] as [boolean, (v: boolean) => void],
      updateServiceWorker: mockUpdateServiceWorker,
    };
  },
}));

const releaseApi = vi.hoisted(() => ({ status: vi.fn() }));
vi.mock('../../src/services/api/releaseStatusApi', () => ({
  getReleaseStatusApi: releaseApi.status,
  markReleaseNotesSeenApi: vi.fn(),
  checkForUpdateNowApi: vi.fn(),
}));

describe('ReloadPrompt', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockNeedRefresh = false;
    mockSetNeedRefresh.mockReset();
    mockUpdateServiceWorker.mockReset();
    capturedOnRegisteredSW = undefined;
  });

  afterEach(() => {
    vi.useRealTimers();
    cleanup();
  });

  it('returns null when no refresh is needed', async () => {
    mockNeedRefresh = false;
    const { ReloadPrompt } = await import('../../src/components/layout/ReloadPrompt');
    const { container } = render(<ReloadPrompt />);
    expect(container.innerHTML).toBe('');
  });

  it('shows update banner when refresh is needed', async () => {
    mockNeedRefresh = true;
    const { ReloadPrompt } = await import('../../src/components/layout/ReloadPrompt');
    render(<ReloadPrompt />);
    expect(screen.getByText('Update available')).toBeDefined();
    expect(screen.getByText('A new version of H-Vault is ready.')).toBeDefined();
  });

  it('dismiss button calls setNeedRefresh(false)', async () => {
    mockNeedRefresh = true;
    const { ReloadPrompt } = await import('../../src/components/layout/ReloadPrompt');
    render(<ReloadPrompt />);
    fireEvent.click(screen.getByText('Dismiss'));
    expect(mockSetNeedRefresh).toHaveBeenCalledWith(false);
  });

  it('update button calls updateServiceWorker', async () => {
    mockNeedRefresh = true;
    const { ReloadPrompt } = await import('../../src/components/layout/ReloadPrompt');
    render(<ReloadPrompt />);
    fireEvent.click(screen.getByText('Update'));
    expect(mockUpdateServiceWorker).toHaveBeenCalledWith(true);
  });

  it('clears interval on unmount', async () => {
    const clearSpy = vi.spyOn(globalThis, 'clearInterval');
    const { ReloadPrompt } = await import('../../src/components/layout/ReloadPrompt');
    render(<ReloadPrompt />);

    if (capturedOnRegisteredSW) {
      act(() => {
        capturedOnRegisteredSW!('sw.js', { update: vi.fn() });
      });
    }

    cleanup();
    expect(clearSpy).toHaveBeenCalled();
    clearSpy.mockRestore();
  });

  it('interval calls registration.update periodically', async () => {
    const mockUpdate = vi.fn();
    const { ReloadPrompt } = await import('../../src/components/layout/ReloadPrompt');
    render(<ReloadPrompt />);

    if (capturedOnRegisteredSW) {
      act(() => {
        capturedOnRegisteredSW!('sw.js', { update: mockUpdate });
      });
    }

    vi.advanceTimersByTime(60 * 60 * 1000);
    expect(mockUpdate).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(60 * 60 * 1000);
    expect(mockUpdate).toHaveBeenCalledTimes(2);
  });
});

describe('ReloadPrompt and the server version', () => {
  beforeEach(async () => {
    mockNeedRefresh = false;
    capturedOnRegisteredSW = undefined;
    releaseApi.status.mockReset();
    releaseApi.status.mockReturnValue(new Promise(() => undefined));
    const { _resetReleaseStoreForTests } = await import('../../src/stores/releaseStore');
    _resetReleaseStoreForTests();
  });

  afterEach(async () => {
    cleanup();
    const { useAuthStore } = await import('../../src/stores/authStore');
    useAuthStore.setState({ user: null, isLocked: true });
  });

  it('names the version the waiting build belongs to, once the server is known to have moved', async () => {
    mockNeedRefresh = true;
    const { useReleaseStore } = await import('../../src/stores/releaseStore');
    useReleaseStore.setState({ serverUpdatedTo: '0.16.0' });
    const { ReloadPrompt } = await import('../../src/components/layout/ReloadPrompt');
    render(<ReloadPrompt />);
    expect(screen.getByText('H-Vault 0.16.0 is ready. Update to start using it.')).toBeDefined();
    expect(screen.queryByText('A new version of H-Vault is ready.')).toBeNull();
  });

  it('re-reads the server version for an unlocked session when a new build is waiting', async () => {
    mockNeedRefresh = true;
    const { useAuthStore } = await import('../../src/stores/authStore');
    useAuthStore.setState({ user: { userId: 'user-a', email: 'a@example.com' }, isLocked: false });
    const { ReloadPrompt } = await import('../../src/components/layout/ReloadPrompt');
    render(<ReloadPrompt />);
    expect(releaseApi.status).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['a locked session', { user: { userId: 'user-a', email: 'a@example.com' }, isLocked: true }],
    ['no session', { user: null, isLocked: false }],
  ])('does not read the server version for %s', async (_label, auth) => {
    mockNeedRefresh = true;
    const { useAuthStore } = await import('../../src/stores/authStore');
    useAuthStore.setState(auth);
    const { ReloadPrompt } = await import('../../src/components/layout/ReloadPrompt');
    render(<ReloadPrompt />);
    expect(releaseApi.status).not.toHaveBeenCalled();
  });

  it('does not read the server version while no new build is waiting', async () => {
    mockNeedRefresh = false;
    const { useAuthStore } = await import('../../src/stores/authStore');
    useAuthStore.setState({ user: { userId: 'user-a', email: 'a@example.com' }, isLocked: false });
    const { ReloadPrompt } = await import('../../src/components/layout/ReloadPrompt');
    render(<ReloadPrompt />);
    expect(releaseApi.status).not.toHaveBeenCalled();
  });

  it('hands the registration to the release store, so a server update fetches the new build at once', async () => {
    const { ReloadPrompt } = await import('../../src/components/layout/ReloadPrompt');
    render(<ReloadPrompt />);
    const update = vi.fn().mockResolvedValue(undefined);
    act(() => {
      capturedOnRegisteredSW!('sw.js', { update });
    });
    const { requestServiceWorkerUpdate } = await import('../../src/lib/serviceWorkerUpdate');
    requestServiceWorkerUpdate();
    expect(update).toHaveBeenCalledTimes(1);
  });
});
