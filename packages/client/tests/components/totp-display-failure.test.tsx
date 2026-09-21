import { describe, it, expect, vi } from 'vitest';
import { render, screen, act } from '@testing-library/react';

/**
 * What the code tile does when generation itself fails.
 *
 * Separated from the main detail suite because it has to make `otpauth` throw,
 * and that suite deliberately drives the REAL library everywhere else. The
 * branch matters: a tile that silently showed dashes would look like a code that
 * had not refreshed yet.
 */

vi.mock('otpauth', () => ({
  get TOTP(): never {
    throw new Error('the library could not be loaded');
  },
}));

vi.mock('../../src/hooks/useUserSettings', () => ({
  useUserSettings: () => ({ clipboardClearTimeout: 30 }),
}));

vi.mock('../../src/components/ui/Toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

const { TotpDisplay } = await import('../../src/components/vault/TotpDisplay');

describe('TotpDisplay when generation fails', () => {
  it('says it could not generate, and offers no copy button', async () => {
    await act(async () => {
      render(<TotpDisplay secret="JBSWY3DPEHPK3PXP" />);
    });

    expect(await screen.findByText('Failed to generate TOTP code')).toBeInTheDocument();
    // No button, because there is nothing to copy: a copy control beside an
    // error would put a row of dashes on the clipboard.
    expect(screen.queryByLabelText('Copy TOTP code')).not.toBeInTheDocument();
  });
});
