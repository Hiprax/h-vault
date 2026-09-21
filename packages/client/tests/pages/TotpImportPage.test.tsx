import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router';

/**
 * The tool page shell.
 *
 * It owns two things and nothing else: the heading a person arrives at, and the
 * remount that "Start over" uses to throw away every decoded key. The flow
 * underneath is lazy so the scanner driver, the camera module and the migration
 * reader stay out of the initial payload.
 */

const flowRenders = vi.fn();
vi.mock('../../src/components/tools/TotpImportFlow', () => ({
  TotpImportFlow: ({ onStartOver }: { onStartOver: () => void }) => {
    flowRenders();
    return (
      <button type="button" onClick={onStartOver}>
        start over
      </button>
    );
  },
}));

const { default: TotpImportPage } = await import('../../src/pages/TotpImportPage');

describe('TotpImportPage', () => {
  it('names itself and says plainly that nothing is attached automatically', async () => {
    await act(async () => {
      render(
        <MemoryRouter>
          <TotpImportPage />
        </MemoryRouter>,
      );
    });

    expect(
      await screen.findByRole('heading', { name: /import from authenticator/i }),
    ).toBeInTheDocument();
    // The product rule belongs on the page, not only in the code.
    expect(screen.getByText(/Nothing is attached to a login automatically/)).toBeInTheDocument();
  });

  it('remounts the flow on "Start over", which is what discards the keys', async () => {
    await act(async () => {
      render(
        <MemoryRouter>
          <TotpImportPage />
        </MemoryRouter>,
      );
    });
    await screen.findByText('start over');
    const before = flowRenders.mock.calls.length;

    await act(async () => {
      fireEvent.click(screen.getByText('start over'));
    });

    // A fresh mount, not a reset of state in place: the unmount is what tears
    // the scan session down.
    await waitFor(() => {
      expect(flowRenders.mock.calls.length).toBeGreaterThan(before);
    });
  });
});
