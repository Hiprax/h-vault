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
  it('shows Luhn warning for invalid card number', async () => {
    renderForm({ defaultType: 'card' });

    const cardNumberInput = screen.getByPlaceholderText('1234 5678 9012 3456');
    expect(cardNumberInput).toBeInTheDocument();

    // Type an invalid card number (fails Luhn check, but >= 13 digits)
    fireEvent.change(cardNumberInput, { target: { value: '1234567890123456' } });

    await waitFor(() => {
      expect(screen.getByText('Card number does not pass Luhn check')).toBeInTheDocument();
    });
  });

  it('does not show Luhn warning for valid card number', async () => {
    renderForm({ defaultType: 'card' });

    const cardNumberInput = screen.getByPlaceholderText('1234 5678 9012 3456');

    // Type a valid Visa test number
    fireEvent.change(cardNumberInput, { target: { value: '4111111111111111' } });

    await waitFor(() => {
      expect(screen.queryByText('Card number does not pass Luhn check')).not.toBeInTheDocument();
    });
  });

  it('does not show Luhn warning when card number is too short', async () => {
    renderForm({ defaultType: 'card' });

    const cardNumberInput = screen.getByPlaceholderText('1234 5678 9012 3456');

    // Type a short number (fewer than 13 digits)
    fireEvent.change(cardNumberInput, { target: { value: '1234' } });

    await waitFor(() => {
      expect(screen.queryByText('Card number does not pass Luhn check')).not.toBeInTheDocument();
    });
  });

  it('does not show Luhn warning when card number is empty', async () => {
    renderForm({ defaultType: 'card' });

    // Don't type anything - card number should be empty by default
    expect(screen.queryByText('Card number does not pass Luhn check')).not.toBeInTheDocument();
  });

  it('does not show Luhn warning for non-card item types', async () => {
    renderForm({ defaultType: 'login' });

    // Login type should not show card number input at all
    expect(screen.queryByPlaceholderText('1234 5678 9012 3456')).not.toBeInTheDocument();
    expect(screen.queryByText('Card number does not pass Luhn check')).not.toBeInTheDocument();
  });

  it('shows Luhn warning for formatted invalid numbers with spaces', async () => {
    renderForm({ defaultType: 'card' });

    const cardNumberInput = screen.getByPlaceholderText('1234 5678 9012 3456');

    // Type formatted but invalid number
    fireEvent.change(cardNumberInput, { target: { value: '1234 5678 9012 3456' } });

    await waitFor(() => {
      expect(screen.getByText('Card number does not pass Luhn check')).toBeInTheDocument();
    });
  });

  it('does not show Luhn warning for formatted valid numbers', async () => {
    renderForm({ defaultType: 'card' });

    const cardNumberInput = screen.getByPlaceholderText('1234 5678 9012 3456');

    // Type formatted valid Visa number
    fireEvent.change(cardNumberInput, { target: { value: '4111-1111-1111-1111' } });

    await waitFor(() => {
      expect(screen.queryByText('Card number does not pass Luhn check')).not.toBeInTheDocument();
    });
  });

  it('does not show Luhn warning for non-numeric input', async () => {
    renderForm({ defaultType: 'card' });

    const cardNumberInput = screen.getByPlaceholderText('1234 5678 9012 3456');

    // Type letters - should not trigger Luhn check (non-digit guard)
    fireEvent.change(cardNumberInput, { target: { value: 'abcdefghijklmnop' } });

    await waitFor(() => {
      expect(screen.queryByText('Card number does not pass Luhn check')).not.toBeInTheDocument();
    });
  });
});
