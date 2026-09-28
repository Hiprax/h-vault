/**
 * The version at the foot of the sidebar: what it shows, what it says to a
 * screen reader, and that it holds its place before the status arrives.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { VersionBadge, versionBadgeLabel } from '../../src/components/releases/VersionBadge';
import { makeStatus, makeUpdate } from './fixtures';

afterEach(cleanup);

describe('VersionBadge', () => {
  it('holds its place, with nothing to press, before the status has loaded', () => {
    const { container } = render(<VersionBadge expanded status={null} onOpen={vi.fn()} />);
    expect(screen.queryByRole('button')).toBeNull();
    expect(container.firstElementChild).toHaveAttribute('aria-hidden', 'true');
    expect(container.firstElementChild).toHaveClass('h-9');
  });

  it('shows the version and opens what is new', () => {
    const onOpen = vi.fn();
    render(
      <VersionBadge
        expanded
        status={makeStatus({ releaseNotes: { unseenCount: 0 } })}
        onOpen={onOpen}
      />,
    );
    const button = screen.getByRole('button', { name: "H-Vault 0.15.0. Open what's new" });
    expect(button).toHaveTextContent('v0.15.0');
    expect(button).not.toHaveAttribute('title');
    expect(screen.queryByTestId('release-unseen-dot')).toBeNull();
    fireEvent.click(button);
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it('marks unread notes with a dot and says how many there are', () => {
    render(
      <VersionBadge
        expanded
        status={makeStatus({ releaseNotes: { unseenCount: 3 } })}
        onOpen={vi.fn()}
      />,
    );
    expect(screen.getByTestId('release-unseen-dot')).toHaveClass('release-unseen-dot');
    expect(
      screen.getByRole('button', {
        name: "H-Vault 0.15.0. 3 new releases to read. Open what's new",
      }),
    ).toBeInTheDocument();
  });

  it('shows administrators a newer release, and only when one is available', () => {
    const available = makeStatus({
      releaseNotes: { unseenCount: 1 },
      update: makeUpdate({ state: 'available', latestVersion: '0.16.0' }),
    });
    const { rerender } = render(<VersionBadge expanded status={available} onOpen={vi.fn()} />);
    expect(screen.getByText('New release')).toBeInTheDocument();
    expect(screen.getByRole('button')).toHaveAccessibleName(
      "H-Vault 0.15.0. 1 new release to read. Version 0.16.0 is available. Open what's new",
    );
    rerender(
      <VersionBadge expanded status={makeStatus({ update: makeUpdate() })} onOpen={vi.fn()} />,
    );
    expect(screen.queryByText('New release')).toBeNull();
    rerender(
      <VersionBadge
        expanded
        status={makeStatus({ update: makeUpdate({ state: 'available', latestVersion: null }) })}
        onOpen={vi.fn()}
      />,
    );
    expect(screen.queryByText('New release')).toBeNull();
  });

  it('carries its label as a tooltip while the sidebar is collapsed', () => {
    const status = makeStatus();
    render(<VersionBadge expanded={false} status={status} onOpen={vi.fn()} />);
    expect(screen.getByRole('button')).toHaveAttribute('title', versionBadgeLabel(status));
  });
});
