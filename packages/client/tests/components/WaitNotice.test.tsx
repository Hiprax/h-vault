/**
 * The countdown a full backup or a full restore shows while the server asked for
 * a pause: counted down each second, and gone once the time has passed.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import { WaitNotice } from '../../src/components/backup/WaitNotice';

const START = new Date('2026-10-23T10:00:00.000Z').getTime();

afterEach(() => {
  vi.useRealTimers();
});

describe('WaitNotice', () => {
  it('counts the pause down each second, then disappears when it has passed', () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'], now: START });
    render(<WaitNotice until={START + 2_500} />);
    expect(
      screen.getByText('Waiting 3 s, as the server asked. It carries on by itself.'),
    ).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(1_000);
    });
    expect(
      screen.getByText('Waiting 2 s, as the server asked. It carries on by itself.'),
    ).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(2_000);
    });
    expect(screen.queryByText(/as the server asked/)).toBeNull();
  });

  it('shows nothing for a pause that already ended, and leaves no timer behind', () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'], now: START });
    const { unmount } = render(<WaitNotice until={START - 1} />);
    expect(screen.queryByText(/as the server asked/)).toBeNull();
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});
