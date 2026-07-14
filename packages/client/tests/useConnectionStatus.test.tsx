import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { useConnectionStatus } from '../src/hooks/useConnectionStatus';

function Probe() {
  const { isOnline } = useConnectionStatus();
  return <div>{isOnline ? 'ONLINE' : 'OFFLINE'}</div>;
}

function setOnLine(value: boolean) {
  Object.defineProperty(navigator, 'onLine', { configurable: true, value });
}

describe('useConnectionStatus', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    setOnLine(true);
    fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    setOnLine(true);
  });

  it('reports online and probes the health endpoint when the server responds', async () => {
    render(<Probe />);
    expect(await screen.findByText('ONLINE')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/health',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('reports offline when the health probe throws (server down)', async () => {
    fetchMock.mockRejectedValue(new Error('connection refused'));
    render(<Probe />);
    expect(await screen.findByText('OFFLINE')).toBeInTheDocument();
  });

  it('reports offline when the server returns a non-ok status', async () => {
    fetchMock.mockResolvedValue({ ok: false });
    render(<Probe />);
    expect(await screen.findByText('OFFLINE')).toBeInTheDocument();
  });

  it('reports offline without probing when the browser itself is offline', async () => {
    setOnLine(false);
    render(<Probe />);
    expect(await screen.findByText('OFFLINE')).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('recovers to online when the browser reconnects and the server responds', async () => {
    fetchMock.mockRejectedValueOnce(new Error('down')); // initial probe fails
    render(<Probe />);
    await screen.findByText('OFFLINE');

    fetchMock.mockResolvedValue({ ok: true }); // server is back
    act(() => {
      window.dispatchEvent(new Event('online'));
    });
    expect(await screen.findByText('ONLINE')).toBeInTheDocument();
  });

  it('ignores a stale probe that resolves after a newer probe (latest wins)', async () => {
    let resolveStale!: (v: { ok: boolean }) => void;
    const stalePromise = new Promise<{ ok: boolean }>((r) => {
      resolveStale = r;
    });
    // Mount probe stays pending; the 'online'-triggered probe resolves ok first.
    fetchMock.mockReturnValueOnce(stalePromise).mockResolvedValue({ ok: true });

    render(<Probe />);
    act(() => {
      window.dispatchEvent(new Event('online'));
    });
    expect(await screen.findByText('ONLINE')).toBeInTheDocument();

    // The earlier (stale) probe now resolves with a WORSE result — it must be
    // ignored because a newer probe has already superseded it.
    await act(async () => {
      resolveStale({ ok: false });
      await Promise.resolve();
    });
    expect(screen.getByText('ONLINE')).toBeInTheDocument();
  });
});
