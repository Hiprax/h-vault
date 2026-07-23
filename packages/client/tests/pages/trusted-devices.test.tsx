/**
 * Behavior tests for the "Trusted devices" section of the Sessions page.
 *
 * Covers: list render (with and without a last-used date), the empty state,
 * the load-error + retry path, the unsuccessful-envelope path, a per-row
 * revoke (success + failure), the "Revoke all" confirmation dialog (open,
 * cancel, confirm-success, confirm-failure) and the in-flight disabled state.
 *
 * Toasts are asserted through the REAL ToastProvider so the assertions match
 * what the user actually sees. Sessions are stubbed empty so the assertions
 * target the trusted-devices controls unambiguously.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';
import type { ITrustedDeviceInfo } from '@hvault/shared';

vi.hoisted(() => {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    configurable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
});

// ---------------------------------------------------------------------------
// Hoisted API mocks
// ---------------------------------------------------------------------------

const {
  mockListSessionsApi,
  mockRevokeSessionApi,
  mockLogoutAllApi,
  mockListTrustedDevicesApi,
  mockRevokeTrustedDeviceApi,
  mockRevokeAllTrustedDevicesApi,
} = vi.hoisted(() => ({
  mockListSessionsApi: vi.fn(),
  mockRevokeSessionApi: vi.fn(),
  mockLogoutAllApi: vi.fn(),
  mockListTrustedDevicesApi: vi.fn(),
  mockRevokeTrustedDeviceApi: vi.fn(),
  mockRevokeAllTrustedDevicesApi: vi.fn(),
}));

vi.mock('../../src/services/api/userApi', () => ({
  listSessionsApi: (...args: unknown[]) => mockListSessionsApi(...args),
  revokeSessionApi: (...args: unknown[]) => mockRevokeSessionApi(...args),
  listTrustedDevicesApi: (...args: unknown[]) => mockListTrustedDevicesApi(...args),
  revokeTrustedDeviceApi: (...args: unknown[]) => mockRevokeTrustedDeviceApi(...args),
  revokeAllTrustedDevicesApi: (...args: unknown[]) => mockRevokeAllTrustedDevicesApi(...args),
}));

vi.mock('../../src/services/api/authApi', () => ({
  logoutAllApi: (...args: unknown[]) => mockLogoutAllApi(...args),
}));

// ---------------------------------------------------------------------------
// Imports AFTER mocks
// ---------------------------------------------------------------------------

import { ToastProvider } from '../../src/components/ui/Toast';
import { _resetScrollLockCount } from '../../src/components/ui/Dialog';
import SessionsPage from '../../src/pages/SessionsPage';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/settings/sessions']}>
      <ToastProvider>
        <SessionsPage />
      </ToastProvider>
    </MemoryRouter>,
  );
}

function device(overrides: Partial<ITrustedDeviceInfo> = {}): ITrustedDeviceInfo {
  return {
    _id: overrides._id ?? 'td1',
    deviceInfo: overrides.deviceInfo ?? {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/120',
      ip: '1.2.3.4',
      fingerprint: 'fp',
    },
    createdAt: overrides.createdAt ?? '2025-01-01T00:00:00.000Z',
    ...(overrides.lastUsedAt !== undefined ? { lastUsedAt: overrides.lastUsedAt } : {}),
    expiresAt: overrides.expiresAt ?? '2025-02-01T00:00:00.000Z',
  };
}

function trustedOk(data: ITrustedDeviceInfo[]) {
  return { data: { success: true, data } };
}

beforeEach(() => {
  for (const m of [
    mockListSessionsApi,
    mockRevokeSessionApi,
    mockLogoutAllApi,
    mockListTrustedDevicesApi,
    mockRevokeTrustedDeviceApi,
    mockRevokeAllTrustedDevicesApi,
  ]) {
    m.mockReset();
  }
  // Sessions are irrelevant to these tests: keep the list empty.
  mockListSessionsApi.mockResolvedValue({ data: { success: true, data: [] } });
  _resetScrollLockCount();
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ===========================================================================
// Rendering
// ===========================================================================

describe('Trusted devices - rendering', () => {
  it('lists each device with browser/OS, IP, trusted, last-used and expiry dates', async () => {
    mockListTrustedDevicesApi.mockResolvedValue(
      trustedOk([
        device({ _id: 'td1', lastUsedAt: '2025-01-15T00:00:00.000Z' }),
        device({
          _id: 'td2',
          deviceInfo: {
            userAgent: 'Mozilla/5.0 (iPhone) Safari',
            ip: '5.6.7.8',
            fingerprint: 'fp2',
          },
        }),
      ]),
    );

    renderPage();

    expect(await screen.findByText('Chrome on Windows')).toBeInTheDocument();
    expect(screen.getByText('Safari on iOS')).toBeInTheDocument();
    // First device carries a last-used date, second does not.
    expect(screen.getByText(/Last used/)).toBeInTheDocument();
    // One "Trusted <date>" per row (the heading "Trusted Devices" has no date).
    expect(screen.getAllByText(/Trusted \d/).length).toBe(2);
    expect(screen.getAllByText(/Expires/).length).toBe(2);
    // Two per-row revoke buttons.
    expect(screen.getAllByRole('button', { name: 'Revoke' })).toHaveLength(2);
  });

  it('shows the empty state when there are no trusted devices', async () => {
    mockListTrustedDevicesApi.mockResolvedValue(trustedOk([]));
    renderPage();
    expect(await screen.findByText(/No trusted devices/)).toBeInTheDocument();
    // No revoke-all control when the list is empty.
    expect(
      screen.queryByRole('button', { name: /revoke all trusted devices/i }),
    ).not.toBeInTheDocument();
  });

  it('shows an error with a working retry when the list fails to load', async () => {
    mockListTrustedDevicesApi.mockRejectedValueOnce(new Error('network'));
    mockListTrustedDevicesApi.mockResolvedValue(trustedOk([device()]));

    renderPage();

    expect(await screen.findByText('Failed to load trusted devices')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /retry/i }));
    expect(await screen.findByText('Chrome on Windows')).toBeInTheDocument();
  });

  it('treats an unsuccessful envelope as an error', async () => {
    mockListTrustedDevicesApi.mockResolvedValue({ data: { success: false } });
    renderPage();
    expect(await screen.findByText('Failed to load trusted devices')).toBeInTheDocument();
  });
});

// ===========================================================================
// Single revoke
// ===========================================================================

describe('Trusted devices - single revoke', () => {
  it('removes the revoked row and confirms with a success toast', async () => {
    mockListTrustedDevicesApi.mockResolvedValue(
      trustedOk([
        device({ _id: 'td1' }),
        device({
          _id: 'td2',
          deviceInfo: { userAgent: 'Mozilla/5.0 (iPhone) Safari', ip: '5.6.7.8', fingerprint: 'f' },
        }),
      ]),
    );
    mockRevokeTrustedDeviceApi.mockResolvedValue({ data: { success: true, data: null } });

    renderPage();
    await screen.findByText('Chrome on Windows');

    // Revoke the Chrome/Windows device (td1).
    const revokeButtons = screen.getAllByRole('button', { name: 'Revoke' });
    fireEvent.click(revokeButtons[0]!);

    await waitFor(() => expect(mockRevokeTrustedDeviceApi).toHaveBeenCalledWith('td1'));
    expect(await screen.findByText('Trusted device revoked')).toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByRole('button', { name: 'Revoke' })).toHaveLength(1));
  });

  it('keeps the row and shows an error toast when revoke fails', async () => {
    mockListTrustedDevicesApi.mockResolvedValue(trustedOk([device({ _id: 'td1' })]));
    mockRevokeTrustedDeviceApi.mockRejectedValue(new Error('boom'));

    renderPage();
    await screen.findByText('Chrome on Windows');

    fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));

    expect(await screen.findByText('Failed to revoke trusted device')).toBeInTheDocument();
    // Row survives a failed revoke.
    expect(screen.getByText('Chrome on Windows')).toBeInTheDocument();
  });
});

// ===========================================================================
// Revoke all (confirmation dialog)
// ===========================================================================

describe('Trusted devices - revoke all', () => {
  it('cancelling the confirmation dialog performs no revocation', async () => {
    mockListTrustedDevicesApi.mockResolvedValue(trustedOk([device()]));
    renderPage();
    await screen.findByText('Chrome on Windows');

    fireEvent.click(screen.getByRole('button', { name: /revoke all trusted devices/i }));

    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Revoke all trusted devices?')).toBeInTheDocument();

    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(mockRevokeAllTrustedDevicesApi).not.toHaveBeenCalled();
    // Devices remain.
    expect(screen.getByText('Chrome on Windows')).toBeInTheDocument();
  });

  it('dismisses the confirmation dialog on Escape without revoking', async () => {
    mockListTrustedDevicesApi.mockResolvedValue(trustedOk([device()]));
    renderPage();
    await screen.findByText('Chrome on Windows');

    fireEvent.click(screen.getByRole('button', { name: /revoke all trusted devices/i }));
    await screen.findByRole('dialog');

    fireEvent.keyDown(document, { key: 'Escape' });

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(mockRevokeAllTrustedDevicesApi).not.toHaveBeenCalled();
    expect(screen.getByText('Chrome on Windows')).toBeInTheDocument();
  });

  it('dismisses the confirmation dialog via the close (X) button without revoking', async () => {
    mockListTrustedDevicesApi.mockResolvedValue(trustedOk([device()]));
    renderPage();
    await screen.findByText('Chrome on Windows');

    fireEvent.click(screen.getByRole('button', { name: /revoke all trusted devices/i }));
    const dialog = await screen.findByRole('dialog');

    fireEvent.click(within(dialog).getByRole('button', { name: 'Close' }));

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(mockRevokeAllTrustedDevicesApi).not.toHaveBeenCalled();
  });

  it('confirming clears the list and shows a success toast', async () => {
    mockListTrustedDevicesApi.mockResolvedValue(
      trustedOk([
        device({ _id: 'td1' }),
        device({
          _id: 'td2',
          deviceInfo: { userAgent: 'Mozilla/5.0 (iPhone) Safari', ip: '5.6.7.8', fingerprint: 'f' },
        }),
      ]),
    );
    mockRevokeAllTrustedDevicesApi.mockResolvedValue({ data: { success: true, data: null } });

    renderPage();
    await screen.findByText('Chrome on Windows');

    fireEvent.click(screen.getByRole('button', { name: /revoke all trusted devices/i }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke all' }));

    await waitFor(() => expect(mockRevokeAllTrustedDevicesApi).toHaveBeenCalledTimes(1));
    expect(await screen.findByText('All trusted devices revoked')).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(await screen.findByText(/No trusted devices/)).toBeInTheDocument();
  });

  it('keeps the devices and shows an error toast when revoke-all fails', async () => {
    mockListTrustedDevicesApi.mockResolvedValue(trustedOk([device()]));
    mockRevokeAllTrustedDevicesApi.mockRejectedValue(new Error('nope'));

    renderPage();
    await screen.findByText('Chrome on Windows');

    fireEvent.click(screen.getByRole('button', { name: /revoke all trusted devices/i }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke all' }));

    expect(await screen.findByText('Failed to revoke trusted devices')).toBeInTheDocument();
    // Devices survive a failed revoke-all.
    expect(screen.getByText('Chrome on Windows')).toBeInTheDocument();
  });

  it('shows an in-flight state and disables the confirm button while revoking', async () => {
    mockListTrustedDevicesApi.mockResolvedValue(trustedOk([device()]));
    let resolveRevoke: (() => void) | undefined;
    mockRevokeAllTrustedDevicesApi.mockReturnValue(
      new Promise<{ data: { success: true; data: null } }>((resolve) => {
        resolveRevoke = () => resolve({ data: { success: true, data: null } });
      }),
    );

    renderPage();
    await screen.findByText('Chrome on Windows');

    fireEvent.click(screen.getByRole('button', { name: /revoke all trusted devices/i }));
    const dialog = await screen.findByRole('dialog');
    const confirm = within(dialog).getByRole('button', { name: 'Revoke all' });
    fireEvent.click(confirm);

    // While the promise is pending the confirm button shows the busy label.
    expect(await within(dialog).findByText('Revoking...')).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Revoking...' })).toBeDisabled();

    // Dismissal is a no-op while a revoke is in flight: Escape and the close (X)
    // button must not close the dialog until the operation settles.
    fireEvent.keyDown(document, { key: 'Escape' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close' }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(mockRevokeAllTrustedDevicesApi).toHaveBeenCalledTimes(1);

    resolveRevoke?.();
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });
});
