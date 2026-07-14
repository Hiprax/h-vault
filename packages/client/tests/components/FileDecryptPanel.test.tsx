/**
 * Tests for FileDecryptPanel.
 *
 * Covers:
 *  - the happy path drives `fileCryptoService.decryptFile` and triggers a
 *    Blob+anchor download of the restored filename
 *  - a wrong password / corrupt file surfaces the honest, oracle-free
 *    "Incorrect password, or the file is corrupted." toast
 *  - a non-container file surfaces the distinct "not a valid file" toast
 *  - the component does NOT directly import `authStore`
 *
 * `fileCryptoService` is partially mocked: `decryptFile` is a spy while the real
 * `describeFileCryptoError` (which maps the distinct failure kinds to distinct
 * messages) is kept. `configApi` is fully mocked so no network/axios (and no
 * transitive authStore) runs.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { CryptoError, CryptoErrorType } from '@hiprax/crypto';

const { mockToast, mockDecryptFile, mockGetMaxBytes } = vi.hoisted(() => ({
  mockToast: vi.fn(),
  mockDecryptFile: vi.fn(),
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

vi.mock('../../src/services/crypto/fileCryptoService', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../../src/services/crypto/fileCryptoService')>();
  return { ...actual, decryptFile: mockDecryptFile };
});

import { FileDecryptPanel } from '../../src/components/tools/FileDecryptPanel';
// Real constant (the vi.mock below spreads `...actual`, keeping the true value).
import { MAX_CONTAINER_OVERHEAD_BYTES } from '../../src/services/crypto/fileCryptoService';

const BIG_LIMIT = 100 * 1024 * 1024;

function selectFile(name = 'report.pdf.enc', bytes = 200): void {
  const input = screen.getByLabelText('Encrypted file');
  const file = new File([new Uint8Array(bytes)], name, { type: 'application/octet-stream' });
  fireEvent.change(input, { target: { files: [file] } });
}

function typePassword(pw: string): void {
  fireEvent.change(screen.getByLabelText('Decryption password'), { target: { value: pw } });
}

describe('FileDecryptPanel', () => {
  beforeEach(() => {
    mockToast.mockReset();
    mockDecryptFile.mockReset();
    mockGetMaxBytes.mockReset();
    mockGetMaxBytes.mockResolvedValue(BIG_LIMIT);
  });

  it('keeps submit disabled until a file and a password are provided', () => {
    render(<FileDecryptPanel />);
    const button = screen.getByRole('button', { name: /decrypt & download/i });
    expect(button).toBeDisabled();

    selectFile();
    expect(button).toBeDisabled();

    typePassword('anything');
    expect(button).not.toBeDisabled();
  });

  it('decrypts on the happy path and downloads the restored file', async () => {
    const blob = new Blob(['plaintext'], { type: 'application/pdf' });
    mockDecryptFile.mockResolvedValue({ blob, filename: 'report.pdf', mime: 'application/pdf' });

    const createObjectURL = vi.fn(() => 'blob:mock-url');
    const revokeObjectURL = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL, revokeObjectURL });
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

    try {
      render(<FileDecryptPanel />);
      selectFile();
      typePassword('Correct-Horse-Battery-9!!');
      const button = screen.getByRole('button', { name: /decrypt & download/i });
      fireEvent.click(button);

      await waitFor(() => {
        expect(mockDecryptFile).toHaveBeenCalledTimes(1);
      });
      const [, , passedOpts] = mockDecryptFile.mock.calls[0] as [
        File,
        string,
        { maxSizeBytes?: number },
      ];
      expect(passedOpts.maxSizeBytes).toBe(BIG_LIMIT);
      expect(createObjectURL).toHaveBeenCalledWith(blob);
      expect(clickSpy).toHaveBeenCalledTimes(1);
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:mock-url');
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ type: 'success', title: 'File decrypted' }),
      );
    } finally {
      clickSpy.mockRestore();
      vi.unstubAllGlobals();
    }
  });

  it('surfaces the oracle-free "incorrect password or corrupt" toast on a wrong password', async () => {
    mockDecryptFile.mockRejectedValue(
      new CryptoError('nope', CryptoErrorType.DECRYPTION_FAILED, 'DECRYPTION_FAILED'),
    );
    vi.stubGlobal('URL', { ...URL, createObjectURL: vi.fn(), revokeObjectURL: vi.fn() });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

    try {
      render(<FileDecryptPanel />);
      selectFile();
      typePassword('wrong-password-but-long-enough');
      fireEvent.click(screen.getByRole('button', { name: /decrypt & download/i }));

      await waitFor(() => {
        expect(mockToast).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'error',
            title: 'Incorrect password, or the file is corrupted.',
          }),
        );
      });
    } finally {
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });

  it('surfaces the distinct "not a valid file" toast for a non-container file', async () => {
    mockDecryptFile.mockRejectedValue(
      new CryptoError('bad magic', CryptoErrorType.INVALID_INPUT, 'CONTAINER_INVALID_MAGIC'),
    );
    vi.stubGlobal('URL', { ...URL, createObjectURL: vi.fn(), revokeObjectURL: vi.fn() });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

    try {
      render(<FileDecryptPanel />);
      selectFile('not-really.enc');
      typePassword('some-password-long-enough');
      fireEvent.click(screen.getByRole('button', { name: /decrypt & download/i }));

      await waitFor(() => {
        expect(mockToast).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'error',
            title: "This isn't a valid H-Vault encrypted file.",
          }),
        );
      });
    } finally {
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });

  it('surfaces the distinct "integrity check failed" toast on a post-auth integrity failure', async () => {
    mockDecryptFile.mockRejectedValue(
      new CryptoError('bad hash', CryptoErrorType.DECRYPTION_FAILED, 'CONTAINER_INTEGRITY_FAILED'),
    );
    vi.stubGlobal('URL', { ...URL, createObjectURL: vi.fn(), revokeObjectURL: vi.fn() });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

    try {
      render(<FileDecryptPanel />);
      selectFile();
      typePassword('correct-password-long-enough');
      fireEvent.click(screen.getByRole('button', { name: /decrypt & download/i }));

      await waitFor(() => {
        expect(mockToast).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'error',
            title: "The file's integrity check failed. The file may be damaged.",
          }),
        );
      });
    } finally {
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });

  it('accepts a .enc just over the plaintext cap (container-overhead allowance)', async () => {
    // A file encrypted at the cap yields a container slightly larger than the cap.
    // The panel must NOT reject it: the ceiling is cap + MAX_CONTAINER_OVERHEAD_BYTES.
    const cap = 1024 * 1024; // 1 MB plaintext cap
    mockGetMaxBytes.mockReset();
    mockGetMaxBytes.mockResolvedValue(cap);
    const blob = new Blob(['plaintext'], { type: 'application/pdf' });
    mockDecryptFile.mockResolvedValue({ blob, filename: 'report.pdf', mime: 'application/pdf' });
    vi.stubGlobal('URL', {
      ...URL,
      createObjectURL: vi.fn(() => 'blob:x'),
      revokeObjectURL: vi.fn(),
    });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

    try {
      render(<FileDecryptPanel />);
      // One byte over the plaintext cap but well within cap + overhead — a legit container.
      selectFile('report.pdf.enc', cap + 1);
      typePassword('any-password-here');

      const button = screen.getByRole('button', { name: /decrypt & download/i });
      await waitFor(() => {
        expect(button).not.toBeDisabled();
      });
      expect(screen.queryByText(/too large/i)).not.toBeInTheDocument();

      fireEvent.click(button);
      await waitFor(() => {
        expect(mockDecryptFile).toHaveBeenCalledTimes(1);
      });
    } finally {
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });

  it('rejects a .enc larger than the plaintext cap plus the container overhead', async () => {
    const cap = 1024 * 1024; // 1 MB plaintext cap
    mockGetMaxBytes.mockReset();
    mockGetMaxBytes.mockResolvedValue(cap);

    render(<FileDecryptPanel />);
    // Beyond cap + overhead → genuinely too large; submit stays disabled.
    selectFile('big.enc', cap + MAX_CONTAINER_OVERHEAD_BYTES + 1);
    typePassword('any-password-here');

    await waitFor(() => {
      expect(screen.getByText(/too large/i)).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: /decrypt & download/i })).toBeDisabled();
  });

  it('does not directly import authStore (account-agnostic)', () => {
    const src = readFileSync(
      path.resolve(__dirname, '../../src/components/tools/FileDecryptPanel.tsx'),
      'utf8',
    );
    // Assert on import specifiers, not prose — the docstring intentionally names
    // authStore to state the account-agnostic invariant it must not violate.
    expect(src).not.toMatch(/from\s+['"][^'"]*authStore/);
  });
});
