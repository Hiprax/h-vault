/**
 * `lazyOptional`: a component loaded after the first render that renders nothing,
 * instead of reaching the error boundary, when its chunk cannot be fetched.
 */
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Component, Suspense, type ReactNode } from 'react';
import { lazyOptional } from '../src/lib/lazyOptional';

class Boundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  override state = { failed: false };
  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }
  override render(): ReactNode {
    return this.state.failed ? <p>the app was replaced</p> : this.props.children;
  }
}

function mount(Optional: ReturnType<typeof lazyOptional>) {
  return render(
    <Boundary>
      <p>the page</p>
      <Suspense fallback={null}>
        <Optional />
      </Suspense>
    </Boundary>,
  );
}

describe('lazyOptional', () => {
  it('renders the component once its chunk has loaded', async () => {
    mount(lazyOptional(() => Promise.resolve({ default: () => <p>update available</p> })));
    expect(await screen.findByText('update available')).toBeInTheDocument();
    expect(screen.getByText('the page')).toBeInTheDocument();
  });

  it('renders nothing, and leaves the page alone, when its chunk cannot be fetched', async () => {
    mount(
      lazyOptional(() => Promise.reject(new Error('Failed to fetch dynamically imported module'))),
    );
    expect(await screen.findByText('the page')).toBeInTheDocument();
    // Let the rejected load settle.
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(screen.queryByText('the app was replaced')).toBeNull();
    expect(screen.getByText('the page')).toBeInTheDocument();
  });
});
