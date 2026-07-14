import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { PasswordGenerator } from '../../src/components/vault/PasswordGenerator';
import { buildCharset, AMBIGUOUS } from '../../src/utils/passwordEntropy';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock('../../src/components/ui/Toast', () => ({
  useToast: () => ({
    toast: vi.fn(),
    dismiss: vi.fn(),
    update: vi.fn(),
  }),
}));

vi.mock('../../src/hooks/useUserSettings', () => ({
  useUserSettings: () => ({
    autoLockTimeout: 15,
    clipboardClearTimeout: 30,
    theme: 'system',
  }),
}));

vi.mock('../../src/hooks/useClipboardCountdown', () => ({
  useClipboardCountdown: () => ({
    startCountdown: vi.fn(),
    stopCountdown: vi.fn(),
  }),
}));

// NOTE: the generator no longer uses zxcvbn — generated-password strength is measured
// by exact information-theoretic entropy (see src/utils/passwordEntropy.ts), so there is
// nothing to mock here. zxcvbn remains in use for human-chosen master passwords elsewhere.

// ---------------------------------------------------------------------------
// Clipboard mock
// ---------------------------------------------------------------------------

const mockWriteText = vi.fn().mockResolvedValue(undefined);
const mockReadText = vi.fn().mockResolvedValue('');

Object.defineProperty(navigator, 'clipboard', {
  value: {
    writeText: mockWriteText,
    readText: mockReadText,
  },
  writable: true,
  configurable: true,
});

// ---------------------------------------------------------------------------
// Helper: render and wait for initial password generation
// ---------------------------------------------------------------------------

async function renderAndWait(props: Parameters<typeof PasswordGenerator>[0] = {}) {
  vi.useFakeTimers();

  let result: ReturnType<typeof render>;
  await act(async () => {
    result = render(<PasswordGenerator {...props} />);
  });

  // Advance past the 50ms setTimeout used by regenerate()
  await act(async () => {
    vi.advanceTimersByTime(100);
  });

  return result!;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('PasswordGenerator', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockWriteText.mockResolvedValue(undefined);
    mockReadText.mockResolvedValue('');
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // -------------------------------------------------------------------------
  // 1. Rendering
  // -------------------------------------------------------------------------

  describe('Rendering', () => {
    it('renders with a generated password', async () => {
      await renderAndWait();

      // The password display is inside a <code> element.
      // After the timer fires the password should be non-empty.
      const codeEl = screen
        .getByRole('button', { name: 'Copy password' })
        .closest('div')!
        .querySelector('code')!;

      expect(codeEl.textContent).toBeTruthy();
      expect(codeEl.textContent!.length).toBeGreaterThan(0);
    });

    it('shows password mode options by default', async () => {
      await renderAndWait();

      // Password mode is default, so we should see the length slider and character toggles
      expect(screen.getByLabelText('Length')).toBeInTheDocument();
      expect(screen.getByLabelText('Uppercase (A-Z)')).toBeInTheDocument();
      expect(screen.getByLabelText('Lowercase (a-z)')).toBeInTheDocument();
      expect(screen.getByLabelText('Numbers (0-9)')).toBeInTheDocument();
      expect(screen.getByLabelText('Symbols (!@#$)')).toBeInTheDocument();
      expect(screen.getByText(/Exclude ambiguous/)).toBeInTheDocument();
    });

    it('renders mode toggle buttons for Password and Passphrase', async () => {
      await renderAndWait();

      expect(screen.getByRole('button', { name: 'Password' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Passphrase' })).toBeInTheDocument();
    });

    it('renders Copy, Regenerate, and Show/Hide buttons', async () => {
      await renderAndWait();

      expect(screen.getByRole('button', { name: 'Copy password' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Regenerate password' })).toBeInTheDocument();
      // Default is showPassword=true, so the toggle should say "Hide password"
      expect(screen.getByRole('button', { name: 'Hide password' })).toBeInTheDocument();
    });
  });

  // -------------------------------------------------------------------------
  // 2. Mode switching
  // -------------------------------------------------------------------------

  describe('Mode switching', () => {
    it('switches to passphrase mode and shows word count and separator', async () => {
      await renderAndWait();

      // Click Passphrase button
      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: 'Passphrase' }));
      });

      // Advance timers for regenerate after mode switch
      await act(async () => {
        vi.advanceTimersByTime(100);
      });

      expect(screen.getByLabelText('Word Count')).toBeInTheDocument();
      expect(screen.getByLabelText('Separator')).toBeInTheDocument();

      // Password mode options should be hidden
      expect(screen.queryByLabelText('Length')).not.toBeInTheDocument();
      expect(screen.queryByLabelText('Uppercase (A-Z)')).not.toBeInTheDocument();
    });

    it('switches back to password mode and shows length slider and toggles', async () => {
      await renderAndWait();

      // Switch to passphrase
      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: 'Passphrase' }));
      });
      await act(async () => {
        vi.advanceTimersByTime(100);
      });

      // Switch back to password
      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: 'Password' }));
      });
      await act(async () => {
        vi.advanceTimersByTime(100);
      });

      expect(screen.getByLabelText('Length')).toBeInTheDocument();
      expect(screen.getByLabelText('Uppercase (A-Z)')).toBeInTheDocument();
      expect(screen.getByLabelText('Lowercase (a-z)')).toBeInTheDocument();
      expect(screen.getByLabelText('Numbers (0-9)')).toBeInTheDocument();
      expect(screen.getByLabelText('Symbols (!@#$)')).toBeInTheDocument();

      // Passphrase options should be hidden
      expect(screen.queryByLabelText('Word Count')).not.toBeInTheDocument();
      expect(screen.queryByLabelText('Separator')).not.toBeInTheDocument();
    });
  });

  // -------------------------------------------------------------------------
  // 3. Password generation with character sets
  // -------------------------------------------------------------------------

  describe('Password generation', () => {
    it('generates a password of the default length (20)', async () => {
      await renderAndWait();

      const codeEl = screen
        .getByRole('button', { name: 'Copy password' })
        .closest('div')!
        .querySelector('code')!;

      expect(codeEl.textContent!.length).toBe(20);
    });

    it('generates password containing only lowercase when other toggles are off', async () => {
      await renderAndWait();

      // Uncheck uppercase, numbers, symbols
      await act(async () => {
        fireEvent.click(screen.getByLabelText('Uppercase (A-Z)'));
      });
      await act(async () => {
        fireEvent.click(screen.getByLabelText('Numbers (0-9)'));
      });
      await act(async () => {
        fireEvent.click(screen.getByLabelText('Symbols (!@#$)'));
      });

      // Advance timers for each regeneration
      await act(async () => {
        vi.advanceTimersByTime(200);
      });

      const codeEl = screen
        .getByRole('button', { name: 'Copy password' })
        .closest('div')!
        .querySelector('code')!;

      const password = codeEl.textContent!;
      expect(password).toMatch(/^[a-z]+$/);
    });

    it('generates password containing only uppercase when other toggles are off', async () => {
      await renderAndWait();

      // Uncheck lowercase, numbers, symbols
      await act(async () => {
        fireEvent.click(screen.getByLabelText('Lowercase (a-z)'));
      });
      await act(async () => {
        fireEvent.click(screen.getByLabelText('Numbers (0-9)'));
      });
      await act(async () => {
        fireEvent.click(screen.getByLabelText('Symbols (!@#$)'));
      });
      await act(async () => {
        vi.advanceTimersByTime(200);
      });

      const codeEl = screen
        .getByRole('button', { name: 'Copy password' })
        .closest('div')!
        .querySelector('code')!;

      const password = codeEl.textContent!;
      expect(password).toMatch(/^[A-Z]+$/);
    });

    it('generates password containing only digits when other toggles are off', async () => {
      await renderAndWait();

      // Uncheck uppercase, lowercase, symbols
      await act(async () => {
        fireEvent.click(screen.getByLabelText('Uppercase (A-Z)'));
      });
      await act(async () => {
        fireEvent.click(screen.getByLabelText('Lowercase (a-z)'));
      });
      await act(async () => {
        fireEvent.click(screen.getByLabelText('Symbols (!@#$)'));
      });
      await act(async () => {
        vi.advanceTimersByTime(200);
      });

      const codeEl = screen
        .getByRole('button', { name: 'Copy password' })
        .closest('div')!
        .querySelector('code')!;

      const password = codeEl.textContent!;
      expect(password).toMatch(/^[0-9]+$/);
    });

    it('respects length slider changes', async () => {
      await renderAndWait();

      const slider = screen.getByLabelText('Length');
      await act(async () => {
        fireEvent.change(slider, { target: { value: '32' } });
      });
      await act(async () => {
        vi.advanceTimersByTime(100);
      });

      const codeEl = screen
        .getByRole('button', { name: 'Copy password' })
        .closest('div')!
        .querySelector('code')!;

      expect(codeEl.textContent!.length).toBe(32);
    });

    it('excludes ambiguous characters from the generation pool', () => {
      // Deterministic pool check on the SAME production function the generator
      // draws from (buildCharset). Asserting only that ONE random 20-char sample
      // avoids l/I/1/O/0 is flaky: with the 88-char pool that happens ~31% of the
      // time even if excludeAmbiguous is completely broken, so it carries no
      // guaranteed-fail signal. The pool assertion cannot pass if the exclusion
      // branch is removed.
      const full = buildCharset({
        uppercase: true,
        lowercase: true,
        numbers: true,
        symbols: true,
        excludeAmbiguous: false,
      });
      const excluded = buildCharset({
        uppercase: true,
        lowercase: true,
        numbers: true,
        symbols: true,
        excludeAmbiguous: true,
      });

      // Baseline: the full pool DOES contain every ambiguous char (otherwise the
      // exclusion assertion below would be vacuously true).
      for (const char of AMBIGUOUS) {
        expect(full).toContain(char);
        expect(excluded).not.toContain(char);
      }
      expect(excluded.length).toBe(full.length - AMBIGUOUS.length);
    });

    it('shrinks the displayed entropy when the exclude-ambiguous toggle is enabled', async () => {
      // Component-wiring guard: enabling the toggle must feed excludeAmbiguous
      // into the shared charset builder, shrinking the effective pool and thus
      // the reported entropy (88 → 83 symbols at length 20: 129 → 127 bits).
      // If the toggle were not wired (or the exclusion branch removed) the pool
      // would not shrink and the bit count would not change.
      await renderAndWait();

      const readBits = () => parseInt(screen.getByText(/^\d+ bits$/).textContent!, 10);
      const bitsBefore = readBits();

      await act(async () => {
        fireEvent.click(screen.getByRole('checkbox', { name: /Exclude ambiguous/ }));
      });
      await act(async () => {
        vi.advanceTimersByTime(100);
      });

      const bitsAfter = readBits();
      expect(bitsAfter).toBeLessThan(bitsBefore);
    });
  });

  // -------------------------------------------------------------------------
  // 4. Passphrase generation
  // -------------------------------------------------------------------------

  describe('Passphrase generation', () => {
    it('generates words separated by the default separator (hyphen)', async () => {
      await renderAndWait();

      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: 'Passphrase' }));
      });
      await act(async () => {
        vi.advanceTimersByTime(100);
      });

      const codeEl = screen
        .getByRole('button', { name: 'Copy password' })
        .closest('div')!
        .querySelector('code')!;

      const passphrase = codeEl.textContent!;
      // Default word count is 5, separated by hyphens
      const words = passphrase.split('-');
      expect(words.length).toBe(5);
      words.forEach((word) => {
        expect(word.length).toBeGreaterThan(0);
      });
    });

    it('uses custom separator when changed', async () => {
      await renderAndWait();

      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: 'Passphrase' }));
      });
      await act(async () => {
        vi.advanceTimersByTime(100);
      });

      const separatorInput = screen.getByLabelText('Separator');
      await act(async () => {
        fireEvent.change(separatorInput, { target: { value: '.' } });
      });
      await act(async () => {
        vi.advanceTimersByTime(100);
      });

      const codeEl = screen
        .getByRole('button', { name: 'Copy password' })
        .closest('div')!
        .querySelector('code')!;

      const passphrase = codeEl.textContent!;
      const words = passphrase.split('.');
      expect(words.length).toBe(5);
    });

    it('respects word count slider changes', async () => {
      await renderAndWait();

      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: 'Passphrase' }));
      });
      await act(async () => {
        vi.advanceTimersByTime(100);
      });

      const wordCountSlider = screen.getByLabelText('Word Count');
      await act(async () => {
        fireEvent.change(wordCountSlider, { target: { value: '8' } });
      });
      await act(async () => {
        vi.advanceTimersByTime(100);
      });

      const codeEl = screen
        .getByRole('button', { name: 'Copy password' })
        .closest('div')!
        .querySelector('code')!;

      const passphrase = codeEl.textContent!;
      const words = passphrase.split('-');
      expect(words.length).toBe(8);
    });
  });

  // -------------------------------------------------------------------------
  // 5. Password visibility toggle
  // -------------------------------------------------------------------------

  describe('Password visibility', () => {
    it('shows password by default (showPassword starts as true)', async () => {
      await renderAndWait();

      const codeEl = screen
        .getByRole('button', { name: 'Copy password' })
        .closest('div')!
        .querySelector('code')!;

      // The password should not be masked bullets
      expect(codeEl.textContent).not.toMatch(/^\u2022+$/);
      expect(screen.getByRole('button', { name: 'Hide password' })).toBeInTheDocument();
    });

    it('hides password when hide button is clicked', async () => {
      await renderAndWait();

      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: 'Hide password' }));
      });

      const codeEl = screen
        .getByRole('button', { name: 'Copy password' })
        .closest('div')!
        .querySelector('code')!;

      // Should show bullet characters
      expect(codeEl.textContent).toMatch(/^\u2022+$/);
      expect(screen.getByRole('button', { name: 'Show password' })).toBeInTheDocument();
    });

    it('toggles back to showing password', async () => {
      await renderAndWait();

      // Hide
      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: 'Hide password' }));
      });

      // Show again
      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: 'Show password' }));
      });

      expect(screen.getByRole('button', { name: 'Hide password' })).toBeInTheDocument();

      const codeEl = screen
        .getByRole('button', { name: 'Copy password' })
        .closest('div')!
        .querySelector('code')!;

      expect(codeEl.textContent).not.toMatch(/^\u2022+$/);
    });
  });

  // -------------------------------------------------------------------------
  // 6. Copy functionality
  // -------------------------------------------------------------------------

  describe('Copy functionality', () => {
    it('copies password to clipboard when copy button is clicked', async () => {
      await renderAndWait();

      const codeEl = screen
        .getByRole('button', { name: 'Copy password' })
        .closest('div')!
        .querySelector('code')!;

      const currentPassword = codeEl.textContent!;

      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: 'Copy password' }));
      });

      expect(mockWriteText).toHaveBeenCalledWith(currentPassword);
    });
  });

  // -------------------------------------------------------------------------
  // 7. Regenerate
  // -------------------------------------------------------------------------

  describe('Regenerate', () => {
    it('generates a new password when regenerate button is clicked', async () => {
      await renderAndWait();

      const codeEl = screen
        .getByRole('button', { name: 'Copy password' })
        .closest('div')!
        .querySelector('code')!;

      const firstPassword = codeEl.textContent!;
      expect(firstPassword.length).toBe(20); // default length — sanity

      // Click regenerate
      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: 'Regenerate password' }));
      });

      // Advance timers for the 50ms setTimeout
      await act(async () => {
        vi.advanceTimersByTime(100);
      });

      const newPassword = codeEl.textContent!;

      // Regeneration MUST produce a fresh value. A 20-char password over the
      // 88-char default pool collides with the previous one with probability
      // ~88^-20 (≈2^-129) — effectively impossible — so a genuine regeneration
      // always changes the string. If the Regenerate button were a no-op the
      // <code> would still hold the mount-time password and this assertion fails.
      expect(newPassword).not.toBe(firstPassword);
      expect(newPassword.length).toBe(20);
    });
  });

  // -------------------------------------------------------------------------
  // 8. History
  // -------------------------------------------------------------------------

  describe('History', () => {
    it('shows history button with count', async () => {
      await renderAndWait();

      const historyBtn = screen.getByRole('button', { name: /History/ });
      expect(historyBtn).toBeInTheDocument();
      // After initial generation, history should have 1 entry
      expect(historyBtn.textContent).toContain('History (1)');
    });

    it('shows history list when history button is clicked', async () => {
      await renderAndWait();

      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: /History/ }));
      });

      expect(screen.getByText('Recent passwords')).toBeInTheDocument();
    });

    it('hides history list when history button is clicked again', async () => {
      await renderAndWait();

      // Open history
      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: /History/ }));
      });
      expect(screen.getByText('Recent passwords')).toBeInTheDocument();

      // Close history
      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: /History/ }));
      });
      expect(screen.queryByText('Recent passwords')).not.toBeInTheDocument();
    });

    it('accumulates history entries when password is regenerated', async () => {
      await renderAndWait();

      // Regenerate a few times to build history
      for (let i = 0; i < 3; i++) {
        await act(async () => {
          fireEvent.click(screen.getByRole('button', { name: 'Regenerate password' }));
        });
        await act(async () => {
          vi.advanceTimersByTime(100);
        });
      }

      const historyBtn = screen.getByRole('button', { name: /History/ });
      // 1 initial + 3 regenerations = 4 distinct entries (cap 5, dedup'd). The
      // random 20-char passwords never collide, so the count is exactly 4.
      // A regex like /History \(\d+\)/ would also match the un-accumulated
      // "History (1)" — the exact count is what gives this test teeth.
      expect(historyBtn.textContent).toContain('History (4)');

      // Open history and verify exactly four distinct password rows render.
      await act(async () => {
        fireEvent.click(historyBtn);
      });
      const panel = screen.getByText('Recent passwords').closest('div')!;
      const rows = panel.querySelectorAll('code');
      expect(rows).toHaveLength(4);
      const rendered = Array.from(rows, (r) => r.textContent);
      expect(new Set(rendered).size).toBe(4); // all four are distinct
    });
  });

  // -------------------------------------------------------------------------
  // 9. onSelect callback
  // -------------------------------------------------------------------------

  describe('onSelect callback', () => {
    it('shows "Use Password" button when onSelect prop is provided', async () => {
      const onSelect = vi.fn();
      await renderAndWait({ onSelect });

      expect(screen.getByRole('button', { name: 'Use Password' })).toBeInTheDocument();
    });

    it('does not show "Use Password" button when onSelect is not provided', async () => {
      await renderAndWait();

      expect(screen.queryByRole('button', { name: 'Use Password' })).not.toBeInTheDocument();
    });

    it('calls onSelect with current password when "Use Password" is clicked', async () => {
      const onSelect = vi.fn();
      await renderAndWait({ onSelect });

      const codeEl = screen
        .getByRole('button', { name: 'Copy password' })
        .closest('div')!
        .querySelector('code')!;

      const currentPassword = codeEl.textContent!;

      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: 'Use Password' }));
      });

      expect(onSelect).toHaveBeenCalledTimes(1);
      expect(onSelect).toHaveBeenCalledWith(currentPassword);
    });
  });

  // -------------------------------------------------------------------------
  // 10. Strength indicator
  // -------------------------------------------------------------------------

  describe('Strength indicator (exact entropy)', () => {
    it('shows the exact entropy in bits for the default 20-char full charset (≈129 bits)', async () => {
      await renderAndWait();

      // 20 * log2(88) ≈ 129.19 → rounded to 129; 129 bits ≥ 112 → Very Strong.
      expect(screen.getByText('129 bits')).toBeInTheDocument();
      expect(screen.getByText('Very Strong')).toBeInTheDocument();
    });

    it('labels the crack time with the honest offline-GPU attacker model', async () => {
      await renderAndWait();

      expect(screen.getByText(/Time to crack \(offline GPU/)).toBeInTheDocument();
    });

    it('honestly downgrades a short password (length 8 ≈ 52 bits → Weak)', async () => {
      await renderAndWait();

      const slider = screen.getByLabelText('Length');
      await act(async () => {
        fireEvent.change(slider, { target: { value: '8' } });
      });
      await act(async () => {
        vi.advanceTimersByTime(100);
      });

      // 8 * log2(88) ≈ 51.68 → floored to 51 bits (display never rounds up), in the
      // 40–63 Weak band. Previously zxcvbn under-/over-stated this; the exact figure is honest.
      expect(screen.getByText('51 bits')).toBeInTheDocument();
      expect(screen.getByText('Weak')).toBeInTheDocument();
    });

    it('renders exactly 5 strength bars', async () => {
      await renderAndWait();

      const bars = document.querySelectorAll('.rounded-full.transition-colors');
      expect(bars.length).toBe(5);
    });

    it('fills the meter proportionally to the entropy band (no saturation)', async () => {
      await renderAndWait();

      // Default length 20 ≈ 129 bits → Very Strong (level 4) → all 5 bars emerald.
      expect(document.querySelectorAll('.rounded-full.transition-colors').length).toBe(5);
      expect(document.querySelectorAll('.bg-emerald-500').length).toBe(5);

      // Length 12 ≈ 78 bits → Fair (level 2) → 3 yellow bars, 2 muted.
      const slider = screen.getByLabelText('Length');
      await act(async () => {
        fireEvent.change(slider, { target: { value: '12' } });
      });
      await act(async () => {
        vi.advanceTimersByTime(100);
      });

      expect(screen.getByText('Fair')).toBeInTheDocument();
      expect(document.querySelectorAll('.bg-yellow-500').length).toBe(3);
      const mutedBars = document.querySelectorAll(
        '.rounded-full.transition-colors:not(.bg-green-500):not(.bg-emerald-500):not(.bg-red-500):not(.bg-orange-500):not(.bg-yellow-500)',
      );
      expect(mutedBars.length).toBe(2);
    });

    it('shows exact passphrase entropy (default 5 words = 55 bits → Weak)', async () => {
      await renderAndWait();

      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: 'Passphrase' }));
      });
      await act(async () => {
        vi.advanceTimersByTime(100);
      });

      // 5 words * log2(2048) = 5 * 11 = 55 bits. The 2048-word list yields 11 bits/word,
      // so a 5-word passphrase is honestly rated Weak (not a saturated "Very Strong").
      expect(screen.getByText('55 bits')).toBeInTheDocument();
      expect(screen.getByText('Weak')).toBeInTheDocument();
    });
  });

  // -------------------------------------------------------------------------
  // L16: Timer cleanup on unmount.
  //
  // The component's OWN timers (copied-badge, regenerate) are cancelled on
  // unmount. The clipboard auto-clear deliberately is NOT: it belongs to the
  // shared module-level scheduler in useClipboardGuard, so the copied password
  // is still wiped after the user navigates away from the generator. Vault lock
  // and logout wipe it immediately instead (clearClipboardIfDirty).
  // -------------------------------------------------------------------------
  describe('timer cleanup on unmount', () => {
    it('cancels its own timers when the component unmounts', async () => {
      vi.useFakeTimers();
      const clearTimeoutSpy = vi.spyOn(globalThis, 'clearTimeout');

      let unmountFn: () => void;
      await act(async () => {
        const result = render(<PasswordGenerator />);
        unmountFn = result.unmount;
      });
      await act(async () => {
        vi.advanceTimersByTime(100);
      });

      // Copy password (arms the copied-badge timer and the shared clipboard clear)
      const copyButton = screen.getByRole('button', { name: 'Copy password' });
      await act(async () => {
        fireEvent.click(copyButton);
      });

      clearTimeoutSpy.mockClear();
      await act(async () => {
        unmountFn();
      });

      // clearTimeout runs for copyTimeoutRef and regenerateTimerRef
      expect(clearTimeoutSpy).toHaveBeenCalled();

      clearTimeoutSpy.mockRestore();
      vi.useRealTimers();
    });

    it('still wipes the clipboard after unmount, and does not throw', async () => {
      vi.useFakeTimers();
      mockWriteText.mockClear();

      let unmountFn: () => void;
      await act(async () => {
        const result = render(<PasswordGenerator />);
        unmountFn = result.unmount;
      });
      await act(async () => {
        vi.advanceTimersByTime(100);
      });

      // Copy password
      const copyButton = screen.getByRole('button', { name: 'Copy password' });
      await act(async () => {
        fireEvent.click(copyButton);
      });
      expect(mockWriteText).toHaveBeenCalledTimes(1); // the password itself

      // Unmount before the 30s clipboard-clear deadline
      await act(async () => {
        unmountFn();
      });

      expect(() => {
        vi.advanceTimersByTime(60000);
      }).not.toThrow();

      // The shared scheduler outlives the component: the password is wiped.
      expect(mockWriteText).toHaveBeenCalledTimes(2);
      expect(mockWriteText).toHaveBeenLastCalledWith('');

      vi.useRealTimers();
    });

    // Every control that puts a secret on the clipboard must go through the
    // shared guard. The history list's copy button used to write the password
    // directly: no dirty flag, so no auto-clear AND no wipe on vault lock —
    // the generated password stayed on the OS clipboard indefinitely.
    it('copying from the password history arms the shared clipboard clear', async () => {
      vi.useFakeTimers();

      await act(async () => {
        render(<PasswordGenerator />);
      });
      await act(async () => {
        vi.advanceTimersByTime(100);
      });

      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: /^History \(/ }));
      });

      mockWriteText.mockClear();

      // The history rows render their own copy buttons after the main one.
      const copyButtons = screen.getAllByRole('button', { name: 'Copy password' });
      expect(copyButtons.length).toBeGreaterThan(1);

      await act(async () => {
        fireEvent.click(copyButtons[copyButtons.length - 1]!);
      });

      expect(mockWriteText).toHaveBeenCalledTimes(1);

      // Wiped at the configured 30s deadline, like any other copy.
      await act(async () => {
        vi.advanceTimersByTime(30_000);
      });
      expect(mockWriteText).toHaveBeenCalledTimes(2);
      expect(mockWriteText).toHaveBeenLastCalledWith('');

      vi.useRealTimers();
    });
  });

  // -------------------------------------------------------------------------
  // M4: Rejection sampling eliminates modular bias
  // -------------------------------------------------------------------------
  describe('rejection sampling in getSecureRandom', () => {
    it('rejects modular-bias values instead of taking them modulo the charset', async () => {
      // getSecureRandom rejects any 32-bit value >= floor(2^32/max)*max so that
      // no residue class is over-represented. Feed the generator a first RNG
      // draw of 0xFFFFFFFF — which lies in the rejection region for any non-
      // power-of-two charset size (the whole 88-char default pool) — followed by
      // zeros. Correct code discards 0xFFFFFFFF, draws again (0), and maps EVERY
      // character to charset[0]; the biased `arr[0] % max` variant would instead
      // map the first character to charset[0xFFFFFFFF % max] (a different index),
      // making the first character differ from the rest and using one fewer draw.
      vi.useRealTimers();
      vi.useFakeTimers();

      let calls = 0;
      const spy = vi
        .spyOn(globalThis.crypto, 'getRandomValues')
        .mockImplementation(<T extends ArrayBufferView | null>(arr: T): T => {
          if (arr instanceof Uint32Array) {
            arr[0] = calls === 0 ? 0xffffffff : 0;
          }
          calls += 1;
          return arr;
        });

      try {
        await act(async () => {
          render(<PasswordGenerator />);
        });
        await act(async () => {
          vi.advanceTimersByTime(100);
        });

        const codeEl = screen
          .getByRole('button', { name: 'Copy password' })
          .closest('div')!
          .querySelector('code')!;
        const password = codeEl.textContent!;

        expect(password.length).toBe(20);
        // Rejection-sampled result: 0xFFFFFFFF discarded, all draws resolve to
        // index 0, so every character is charset[0] — a single distinct char.
        // The biased variant would leave the first character different.
        expect(new Set(password).size).toBe(1);
        // One extra draw happened for the rejected value: 21 draws for 20 chars.
        expect(calls).toBeGreaterThan(password.length);
      } finally {
        spy.mockRestore();
      }
    });
  });
});
