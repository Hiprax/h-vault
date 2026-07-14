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
