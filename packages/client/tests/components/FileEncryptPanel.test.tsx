/**
 * Tests for FileEncryptPanel.
 *
 * Covers:
 *  - the password gate (weak / short / mismatched passwords keep submit disabled;
 *    a strong, matching password with a selected file enables it)
 *  - the irrecoverable-password warning is present
 *  - the happy path drives `fileCryptoService.encryptFile` and triggers a
 *    Blob+anchor download (spies on URL.createObjectURL and anchor click)
 *  - an encrypt failure surfaces `describeFileCryptoError(err).message` as a toast
 *  - the component does NOT directly import `authStore`
 *
 * `fileCryptoService` is partially mocked: `encryptFile` is a spy while the real
 * `isValidPassword`, `describeFileCryptoError`, and `FileTooLargeError` are kept
 * (so the gate and error mapping exercise production logic). `configApi` and
 * `lazyZxcvbn` are fully mocked so no network/axios (and no transitive authStore)
 * runs and the zxcvbn score is deterministic.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { CryptoError, CryptoErrorType } from '@hiprax/crypto';

const { mockToast, mockEncryptFile, mockGetMaxBytes } = vi.hoisted(() => ({
  mockToast: vi.fn(),
  mockEncryptFile: vi.fn(),
  mockGetMaxBytes: vi.fn(),
}));

vi.mock('../../src/components/ui/Toast', async () => {
  const React = await import('react');
  return {
    useToast: () => ({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() }),
    ToastProvider: ({ children }: { children: React.ReactNode }) =>
      React.createElement(React.Fragment, null, children),
  };
});

vi.mock('../../src/services/api/configApi', () => ({
  getFileEncryptionMaxBytes: mockGetMaxBytes,
}));

vi.mock('../../src/lib/lazyZxcvbn', () => ({
  getZxcvbn: () =>
    Promise.resolve((pw: string) => ({
      score: pw.length >= 20 ? 4 : pw.length >= 12 ? 3 : 1,
      feedback: { warning: '', suggestions: [] },
    })),
}));

vi.mock('../../src/services/crypto/fileCryptoService', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../../src/services/crypto/fileCryptoService')>();
  return { ...actual, encryptFile: mockEncryptFile };
});

import { FileEncryptPanel } from '../../src/components/tools/FileEncryptPanel';

const BIG_LIMIT = 100 * 1024 * 1024;
// >= 20 chars AND mixed classes: passes both isValidPassword and zxcvbn >= 3.
const STRONG_PASSWORD = 'Correct-Horse-Battery-9!!';

function selectFile(name = 'report.pdf', bytes = 4): void {
  const input = screen.getByLabelText('File to encrypt');
  const file = new File([new Uint8Array(bytes)], name, { type: 'application/pdf' });
  fireEvent.change(input, { target: { files: [file] } });
}

function typePasswords(pw: string, confirm = pw): void {
  fireEvent.change(screen.getByLabelText('Encryption password'), { target: { value: pw } });
  fireEvent.change(screen.getByLabelText('Confirm encryption password'), {
    target: { value: confirm },
  });
}

describe('FileEncryptPanel', () => {
  beforeEach(() => {
    mockToast.mockReset();
    mockEncryptFile.mockReset();
    mockGetMaxBytes.mockReset();
    mockGetMaxBytes.mockResolvedValue(BIG_LIMIT);
  });

  it('renders the irrecoverable-password warning', () => {
    render(<FileEncryptPanel />);
    expect(screen.getByText(/no password recovery/i)).toBeInTheDocument();
    expect(screen.getByText(/never be opened again/i)).toBeInTheDocument();
  });

  it('keeps submit disabled until a file + strong, matching password are provided', async () => {
    render(<FileEncryptPanel />);
    const button = screen.getByRole('button', { name: /encrypt & download/i });

    // Nothing entered.
    expect(button).toBeDisabled();

    // File + weak/short password: still disabled (rejected by isValidPassword).
    selectFile();
    typePasswords('short');
    await waitFor(() => {
      expect(screen.getByText(/Use at least 20 characters/)).toBeInTheDocument();
    });
    expect(button).toBeDisabled();

    // Strong password but mismatched confirmation: still disabled.
    typePasswords(STRONG_PASSWORD, 'different-but-also-long-enough-XX');
    await waitFor(() => {
      expect(screen.getByText('Passwords do not match.')).toBeInTheDocument();
    });
    expect(button).toBeDisabled();

    // Strong + matching: enabled.
    typePasswords(STRONG_PASSWORD);
    await waitFor(() => {
      expect(button).not.toBeDisabled();
    });
  });

  it('encrypts on the happy path and triggers a download', async () => {
    const blob = new Blob(['ciphertext'], { type: 'application/octet-stream' });
    mockEncryptFile.mockResolvedValue({ blob, filename: 'report.pdf.enc' });

    const createObjectURL = vi.fn(() => 'blob:mock-url');
    const revokeObjectURL = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL, revokeObjectURL });
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

    try {
      render(<FileEncryptPanel />);
      selectFile();
      typePasswords(STRONG_PASSWORD);
      const button = screen.getByRole('button', { name: /encrypt & download/i });
      await waitFor(() => {
        expect(button).not.toBeDisabled();
      });

      fireEvent.click(button);

      await waitFor(() => {
        expect(mockEncryptFile).toHaveBeenCalledTimes(1);
      });
      // Passed the picked File, the password, and the resolved size limit.
      const [passedFile, passedPassword, passedOpts] = mockEncryptFile.mock.calls[0] as [
        File,
        string,
        { maxSizeBytes?: number },
      ];
      expect(passedFile).toBeInstanceOf(File);
      expect(passedPassword).toBe(STRONG_PASSWORD);
      expect(passedOpts.maxSizeBytes).toBe(BIG_LIMIT);

      expect(createObjectURL).toHaveBeenCalledWith(blob);
      expect(clickSpy).toHaveBeenCalledTimes(1);
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:mock-url');
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ type: 'success', title: 'File encrypted' }),
      );
    } finally {
      clickSpy.mockRestore();
      vi.unstubAllGlobals();
    }
  });

  it('surfaces a mapped error message as a toast when encryption fails', async () => {
    // KEY_DERIVATION_FAILED → engine-unavailable message (keyed on .code).
    mockEncryptFile.mockRejectedValue(
      new CryptoError('boom', CryptoErrorType.ENCRYPTION_FAILED, 'KEY_DERIVATION_FAILED'),
    );
    vi.stubGlobal('URL', { ...URL, createObjectURL: vi.fn(), revokeObjectURL: vi.fn() });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

    try {
      render(<FileEncryptPanel />);
      selectFile();
      typePasswords(STRONG_PASSWORD);
      const button = screen.getByRole('button', { name: /encrypt & download/i });
      await waitFor(() => {
        expect(button).not.toBeDisabled();
      });

      fireEvent.click(button);

      await waitFor(() => {
        expect(mockToast).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'error',
            title: expect.stringContaining('encryption engine could not start'),
          }),
        );
      });
    } finally {
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });

  it('does not directly import authStore (account-agnostic)', () => {
    const src = readFileSync(
      path.resolve(__dirname, '../../src/components/tools/FileEncryptPanel.tsx'),
      'utf8',
    );
    // Assert on import specifiers, not prose — the docstring intentionally names
    // authStore to state the account-agnostic invariant it must not violate.
    expect(src).not.toMatch(/from\s+['"][^'"]*authStore/);
  });
});
