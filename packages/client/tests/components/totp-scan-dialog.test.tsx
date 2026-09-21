import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';

/**
 * Scanning ONE code for the item form's TOTP field.
 *
 * The rule worth pinning is the refusal: a full export holds many codes and this
 * field holds one, so picking one for the user would be a guess with a wrong
 * answer available. It names the tool that does handle it instead.
 */

vi.mock('../../src/services/totpImport/qrSandbox', () => ({
  openQrScanner: vi.fn(() => ({ scan: vi.fn(), close: vi.fn() })),
}));

const { TotpScanDialog } = await import('../../src/components/tools/TotpScanDialog');

function renderDialog() {
  const onScanned = vi.fn();
  const onCancel = vi.fn();
  render(<TotpScanDialog onScanned={onScanned} onCancel={onCancel} />);
  return { onScanned, onCancel };
}

async function paste(value: string) {
  fireEvent.click(screen.getByText(/paste an export link instead/i));
  fireEvent.change(screen.getByLabelText('Export link'), { target: { value } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: /read link/i }));
  });
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('TotpScanDialog', () => {
  it('hands a single account code straight to the field', async () => {
    const { onScanned } = renderDialog();
    await paste('otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP');
    // The whole link, not just its secret: it carries the algorithm, digit count
    // and period, and a bare secret would silently lose them.
    expect(onScanned).toHaveBeenCalledWith('otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP');
  });

  it('refuses a full export and names the tool that handles it', async () => {
    const { onScanned } = renderDialog();
    await paste('otpauth-migration://offline?data=CjAKCkhlbGxv');

    expect(onScanned).not.toHaveBeenCalled();
    expect(screen.getByText(/Use Import from Authenticator for it/)).toBeInTheDocument();
  });

  it('says so when the code is not an authenticator code at all', async () => {
    const { onScanned } = renderDialog();
    await paste('otpauth://totp/a?secret=not-base32!!');

    expect(onScanned).not.toHaveBeenCalled();
    expect(screen.getByText(/not an authenticator code this app can read/)).toBeInTheDocument();
  });

  it('cancels without scanning anything', () => {
    const { onCancel, onScanned } = renderDialog();
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalled();
    expect(onScanned).not.toHaveBeenCalled();
  });
});
