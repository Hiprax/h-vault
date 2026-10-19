/**
 * Phase 3 fix tests:
 *
 * Task 22 - Luhn card number validation (cardLuhnWarning in VaultItemForm)
 *
 * `isValidBase32` and `isValidLuhn` are module-scoped (not exported), so they are
 * exercised through the REAL components rather than a copied re-implementation:
 *   - Luhn: the "VaultItemForm - Card Luhn warning" integration tests below drive
 *     the real VaultItemForm (which calls the real isValidLuhn).
 *   - TOTP base32: covered behaviorally through TotpDisplay in
 *     coverage-vault-item-detail.test.tsx (valid secret renders a live code;
 *     non-multiple-of-8 / non-base32 secrets surface the error panel), which
 *     tracks the real regex + %8 rule. The former in-file replicated unit blocks
 *     were removed: they tested a stale COPY of the source (its `/^[A-Z2-7]+=*$/`
 *     regex lacked the production `% 8 === 0` check) and asserted behavior the
 *     real function contradicts, so they exercised zero production code.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

// ---------------------------------------------------------------------------
// Polyfill matchMedia (needed for stores that reference it at module load)
// ---------------------------------------------------------------------------

const { mockToast } = vi.hoisted(() => {
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

  return {
    mockToast: vi.fn(),
  };
});

// ---------------------------------------------------------------------------
// Mocks - VaultItemForm dependencies
// ---------------------------------------------------------------------------

const mockCreateItem = vi.fn().mockResolvedValue(undefined);
const mockUpdateItem = vi.fn().mockResolvedValue(undefined);

vi.mock('../src/stores/vaultStore', () => ({
  useVaultStore: vi.fn((selector: (state: Record<string, unknown>) => unknown) => {
    const state = {
      createItem: mockCreateItem,
      updateItem: mockUpdateItem,
      folders: [{ id: 'folder-1', name: 'Work', sortOrder: 0, createdAt: '', updatedAt: '' }],
      // Mirrors the real store's initial value; the form reads it to offer
      // identity addresses for a card's billing address.
      items: [],
    };
    return selector(state);
  }),
}));

vi.mock('../src/components/ui/Toast', () => ({
  useToast: () => ({
    toast: mockToast,
    dismiss: vi.fn(),
    update: vi.fn(),
  }),
}));

vi.mock('../src/hooks/useUserSettings', () => ({
  useUserSettings: () => ({
    autoLockTimeout: 15,
    clipboardClearTimeout: 30,
    theme: 'system',
  }),
}));

vi.mock('../src/hooks/useClipboardCountdown', () => ({
  useClipboardCountdown: () => ({
    startCountdown: vi.fn(),
    stopCountdown: vi.fn(),
  }),
}));

// zxcvbn mock removed: the password generator now measures strength via exact entropy
// (src/utils/passwordEntropy.ts), so nothing in this render tree imports zxcvbn.

// ---------------------------------------------------------------------------
// Imports for component integration tests
// ---------------------------------------------------------------------------

import { VaultItemForm } from '../src/components/vault/VaultItemForm';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const defaultFormProps = {
  onSaved: vi.fn(),
  onCancel: vi.fn(),
};

function renderForm(overrides: Partial<Parameters<typeof VaultItemForm>[0]> = {}) {
  return render(<VaultItemForm {...defaultFormProps} {...overrides} />);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
});

// ===========================================================================
// Task 22 - Luhn warning integration test via VaultItemForm component
// ===========================================================================

describe('VaultItemForm - Card Luhn warning', () => {
  // The checksum is a WARNING, never a refusal (some brands carry no check digit),
  // and it is shown once the field has been LEFT, never mid-typing: a 16-digit
  // number fails the checksum at every length from 12 to 15 while it is typed.
  const LUHN_WARNING = /fails the standard card check/;

  function typeAndLeave(value: string): HTMLElement {
    const input = screen.getByPlaceholderText('1234 5678 9012 3456');
    fireEvent.change(input, { target: { value } });
    fireEvent.blur(input);
    return input;
  }

  it('shows the Luhn warning for an invalid card number once the field is left', async () => {
    renderForm({ defaultType: 'card' });

    const input = screen.getByPlaceholderText('1234 5678 9012 3456');
    fireEvent.change(input, { target: { value: '1234567890123456' } });
    // Not while typing.
    expect(screen.queryByText(LUHN_WARNING)).not.toBeInTheDocument();

    fireEvent.blur(input);

    const warning = await screen.findByText(LUHN_WARNING);
    expect(warning).toHaveAttribute('id', 'field-number-warning');
    expect(input.getAttribute('aria-describedby')).toContain('field-number-warning');
    // A warning, not an error: the control is not marked invalid.
    expect(input).not.toHaveAttribute('aria-invalid');
  });

  it('does not show Luhn warning for valid card number', async () => {
    renderForm({ defaultType: 'card' });

    typeAndLeave('4111111111111111');

    await waitFor(() => {
      expect(screen.queryByText(LUHN_WARNING)).not.toBeInTheDocument();
    });
  });

  it('does not show Luhn warning when card number is too short', async () => {
    renderForm({ defaultType: 'card' });

    typeAndLeave('1234');

    await waitFor(() => {
      expect(screen.queryByText(LUHN_WARNING)).not.toBeInTheDocument();
    });
  });

  it('does not show Luhn warning when card number is empty', () => {
    renderForm({ defaultType: 'card' });

    // Don't type anything - card number should be empty by default
    expect(screen.queryByText(LUHN_WARNING)).not.toBeInTheDocument();
  });

  it('does not show Luhn warning for non-card item types', () => {
    renderForm({ defaultType: 'login' });

    // Login type should not show card number input at all
    expect(screen.queryByPlaceholderText('1234 5678 9012 3456')).not.toBeInTheDocument();
    expect(screen.queryByText(LUHN_WARNING)).not.toBeInTheDocument();
  });

  it('shows Luhn warning for formatted invalid numbers with spaces', async () => {
    renderForm({ defaultType: 'card' });

    typeAndLeave('1234 5678 9012 3456');

    expect(await screen.findByText(LUHN_WARNING)).toBeInTheDocument();
  });

  it('does not show Luhn warning for formatted valid numbers', async () => {
    renderForm({ defaultType: 'card' });

    typeAndLeave('4111-1111-1111-1111');

    await waitFor(() => {
      expect(screen.queryByText(LUHN_WARNING)).not.toBeInTheDocument();
    });
  });

  it('does not show Luhn warning for non-numeric input', async () => {
    renderForm({ defaultType: 'card' });

    // Letters are stripped by the formatter, so nothing remains to check.
    const input = typeAndLeave('abcdefghijklmnop');

    expect(input).toHaveValue('');
    await waitFor(() => {
      expect(screen.queryByText(LUHN_WARNING)).not.toBeInTheDocument();
    });
  });
});
