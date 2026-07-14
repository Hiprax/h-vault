import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ErrorBoundary } from '../../src/components/layout/ErrorBoundary';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const reloadMock = vi.fn();

beforeEach(() => {
  Object.defineProperty(window, 'location', {
    value: { reload: reloadMock },
    writable: true,
  });
  reloadMock.mockClear();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** A component that throws on render, used to trigger the error boundary. */
function ThrowingComponent({ message }: { message: string }) {
  throw new Error(message);
}

/** A simple child that renders normally. */
function GoodChild() {
  return <div>All is well</div>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ErrorBoundary', () => {
  // -------------------------------------------------------------------------
  // 1. Renders children when no error
  // -------------------------------------------------------------------------
  it('renders children when no error occurs', () => {
    render(
      <ErrorBoundary>
        <GoodChild />
      </ErrorBoundary>,
    );

    expect(screen.getByText('All is well')).toBeInTheDocument();
  });

  // -------------------------------------------------------------------------
  // 2. Shows error fallback when child throws
  // -------------------------------------------------------------------------
  it('shows error fallback UI when a child throws', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    render(
      <ErrorBoundary>
        <ThrowingComponent message="Boom!" />
      </ErrorBoundary>,
    );

    expect(screen.getByText('Something went wrong')).toBeInTheDocument();

    spy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // 3. Displays the error message
  // -------------------------------------------------------------------------
  it('displays the error message', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    render(
      <ErrorBoundary>
        <ThrowingComponent message="Decryption failed" />
      </ErrorBoundary>,
    );

    expect(screen.getByText('Decryption failed')).toBeInTheDocument();

    spy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // 4. Shows "Something went wrong" heading
  // -------------------------------------------------------------------------
  it('shows "Something went wrong" heading', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    render(
      <ErrorBoundary>
        <ThrowingComponent message="test error" />
      </ErrorBoundary>,
    );

    const heading = screen.getByText('Something went wrong');
    expect(heading).toBeInTheDocument();
    expect(heading.tagName).toBe('H2');

    spy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // 5. Shows "Reload" button
  // -------------------------------------------------------------------------
  it('shows a "Reload" button', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    render(
      <ErrorBoundary>
        <ThrowingComponent message="error" />
      </ErrorBoundary>,
    );

    const reloadButton = screen.getByRole('button', { name: 'Reload' });
    expect(reloadButton).toBeInTheDocument();

    spy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // 6. console.error is called with the error info
  // -------------------------------------------------------------------------
  it('calls console.error via componentDidCatch', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    render(
      <ErrorBoundary>
        <ThrowingComponent message="caught error" />
      </ErrorBoundary>,
    );

    // componentDidCatch calls console.error with the prefix, error, and errorInfo
    expect(spy).toHaveBeenCalled();
    const matchingCall = spy.mock.calls.find(
      (args) => typeof args[0] === 'string' && args[0].includes('[ErrorBoundary]'),
    );
    expect(matchingCall).toBeDefined();

    spy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // 7. Reload button calls window.location.reload
  // -------------------------------------------------------------------------
  it('calls window.location.reload when Reload button is clicked', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    render(
      <ErrorBoundary>
        <ThrowingComponent message="needs reload" />
      </ErrorBoundary>,
    );

    const reloadButton = screen.getByRole('button', { name: 'Reload' });
    fireEvent.click(reloadButton);

    expect(reloadMock).toHaveBeenCalledTimes(1);

    spy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // 8. Shows safety message
  // -------------------------------------------------------------------------
  it('shows the "Your data is safe" reassurance message', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    render(
      <ErrorBoundary>
        <ThrowingComponent message="oops" />
      </ErrorBoundary>,
    );

    expect(screen.getByText(/your data is safe/i)).toBeInTheDocument();

    spy.mockRestore();
  });
});
