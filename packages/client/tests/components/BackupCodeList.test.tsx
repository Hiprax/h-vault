/**
 * The shared backup-code list: masking, per-row copy through the real clipboard
 * guard, per-row delete, and the focus move after a row disappears.
 *
 * The clipboard service is NOT mocked. The real guard runs against a stubbed
 * `navigator.clipboard.writeText`, the way the detail-view suite drives it, so a
 * copy that bypassed the guard would show up as a missing write.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { useRef, useState } from 'react';
import { BackupCodeList } from '../../src/components/vault/BackupCodeList';
import { __resetClipboardGuardForTests } from '../../src/services/clipboard/clipboardService';

const mockToast = vi.fn();

vi.mock('../../src/components/ui/Toast', () => ({
  useToast: () => ({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() }),
}));

vi.mock('../../src/hooks/useUserSettings', () => ({
  useUserSettings: () => ({ autoLockTimeout: 15, clipboardClearTimeout: 30, theme: 'system' }),
}));

const mockWriteText = vi.fn().mockResolvedValue(undefined);
const mockDownloadText = vi.fn();

vi.mock('../../src/lib/download', () => ({
  downloadText: (...args: unknown[]) => mockDownloadText(...args),
  downloadBlob: vi.fn(),
}));

Object.defineProperty(navigator, 'clipboard', {
  value: { writeText: mockWriteText, readText: vi.fn().mockResolvedValue('') },
  writable: true,
  configurable: true,
});

const CODES = ['AAAA-1111', 'BBBB-2222', 'CCCC-3333'];

/**
 * Drives the list the way production does: the host owns the array, so a delete
 * produces a NEW reference and the reveal reset can be observed.
 */
function Harness({
  initial = CODES,
  readOnly = false,
  busy = false,
  allowDownload = false,
  withFallback = false,
  withoutItemName = false,
}: {
  initial?: string[];
  readOnly?: boolean;
  busy?: boolean;
  allowDownload?: boolean;
  withFallback?: boolean;
  withoutItemName?: boolean;
}) {
  const [codes, setCodes] = useState<readonly string[]>(initial);
  const fallbackRef = useRef<HTMLTextAreaElement>(null);
  return (
    <div>
      <button type="button" onClick={() => setCodes([...initial])}>
        Replace codes
      </button>
      <BackupCodeList
        codes={codes}
        onDelete={readOnly ? undefined : (index) => setCodes(codes.filter((_, i) => i !== index))}
        busy={busy}
        allowDownload={allowDownload}
        {...(withoutItemName ? {} : { itemName: 'GitHub / work' })}
        {...(withFallback ? { emptyFocusRef: fallbackRef } : {})}
      />
      {withFallback && <textarea ref={fallbackRef} aria-label="fallback" />}
    </div>
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  mockWriteText.mockResolvedValue(undefined);
  __resetClipboardGuardForTests();
});

afterEach(() => {
  __resetClipboardGuardForTests();
});

describe('BackupCodeList rendering and masking', () => {
  it('renders one row per code inside a labelled list', () => {
    render(<Harness />);
    expect(screen.getByRole('list', { name: 'Backup codes' })).toBeInTheDocument();
    expect(screen.getAllByRole('listitem')).toHaveLength(3);
  });

  it('shows no code text at all while the rows are masked', () => {
    render(<Harness />);
    for (const code of CODES) expect(screen.queryByText(code)).toBeNull();
  });

  it('masks every code to the same fixed width, so the mask cannot leak a length', () => {
    const { container } = render(<Harness initial={['a', 'a'.repeat(40)]} />);
    const cells = [...container.querySelectorAll('code')].map((el) => el.textContent);
    expect(cells).toEqual(['••••••••', '••••••••']);
  });

  it('reveals one row without revealing its neighbours', () => {
    render(<Harness />);
    fireEvent.click(screen.getByLabelText('Reveal backup code 2'));
    expect(screen.getByText('BBBB-2222')).toBeInTheDocument();
    expect(screen.queryByText('AAAA-1111')).toBeNull();
    expect(screen.getByLabelText('Hide backup code 2')).toBeInTheDocument();
  });

  it('hides a revealed row again', () => {
    render(<Harness />);
    fireEvent.click(screen.getByLabelText('Reveal backup code 2'));
    fireEvent.click(screen.getByLabelText('Hide backup code 2'));
    expect(screen.queryByText('BBBB-2222')).toBeNull();
  });

  it('reveals and hides every row from the header', () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole('button', { name: 'Reveal all' }));
    for (const code of CODES) expect(screen.getByText(code)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Hide all' }));
    expect(screen.queryByText('AAAA-1111')).toBeNull();
  });

  it('re-masks every row when the codes array is replaced', () => {
    // Otherwise a revealed row index would keep showing a DIFFERENT code after a
    // delete shifted the list under it.
    render(<Harness />);
    fireEvent.click(screen.getByLabelText('Reveal backup code 1'));
    expect(screen.getByText('AAAA-1111')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Replace codes' }));
    expect(screen.queryByText('AAAA-1111')).toBeNull();
  });

  it('warns when only a few codes are left', () => {
    render(<Harness initial={['AAAA-1111', 'BBBB-2222']} />);
    expect(screen.getByText(/Only 2 codes left/)).toBeInTheDocument();
  });

  it('uses the singular for a single remaining code', () => {
    render(<Harness initial={['AAAA-1111']} />);
    expect(screen.getByText(/Only one code left/)).toBeInTheDocument();
  });

  it('does not warn while there are plenty of codes', () => {
    render(<Harness initial={Array.from({ length: 8 }, (_, i) => `code-${i}`)} />);
    expect(screen.queryByText(/left\. Generate a fresh set/)).toBeNull();
  });

  it('renders nothing but the heading when there are no codes', () => {
    render(<Harness initial={[]} />);
    expect(screen.queryByRole('list')).toBeNull();
    expect(screen.getByRole('heading', { name: 'Backup codes' })).toBeInTheDocument();
  });
});

describe('BackupCodeList copying', () => {
  it('copies one code through the clipboard guard', async () => {
    render(<Harness />);
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Copy backup code 2'));
    });
    expect(mockWriteText.mock.calls[0]?.[0]).toBe('BBBB-2222');
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Backup code 2 copied', type: 'success' }),
    );
  });

  it('renames the copy control to confirm which code was copied', async () => {
    render(<Harness />);
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Copy backup code 1'));
    });
    expect(screen.getByLabelText('Backup code 1 copied')).toBeInTheDocument();
    expect(screen.getByLabelText('Copy backup code 2')).toBeInTheDocument();
  });

  it('copies every code newline-joined', async () => {
    render(<Harness />);
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Copy all backup codes'));
    });
    expect(mockWriteText.mock.calls[0]?.[0]).toBe(CODES.join('\n'));
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Backup codes copied' }),
    );
  });

  it('surfaces a clipboard write the browser refused', async () => {
    mockWriteText.mockRejectedValueOnce(new Error('Document is not focused.'));
    render(<Harness />);
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Copy backup code 1'));
    });
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Failed to copy', type: 'error' }),
    );
  });
});

describe('BackupCodeList downloading', () => {
  it('offers no download control unless the host allows it', () => {
    render(<Harness />);
    expect(screen.queryByRole('button', { name: /Download/ })).toBeNull();
  });

  it('requires a confirmation that names the file as unencrypted', () => {
    render(<Harness allowDownload />);
    fireEvent.click(screen.getByRole('button', { name: 'Download' }));
    expect(screen.getByText(/not encrypted/)).toBeInTheDocument();
    expect(mockDownloadText).not.toHaveBeenCalled();
  });

  it('writes the codes to a slug-named text file once confirmed', () => {
    render(<Harness allowDownload />);
    fireEvent.click(screen.getByRole('button', { name: 'Download' }));
    fireEvent.click(screen.getByRole('button', { name: 'Download anyway' }));
    const [body, filename, mime] = mockDownloadText.mock.calls[0] ?? [];
    expect(body).toContain(CODES.join('\n'));
    expect(body).toContain('GitHub / work');
    // The item name reaches an anchor's download attribute, so only lowercase
    // alphanumerics and single dashes may survive it.
    expect(filename).toMatch(/^hvault-backup-codes-github-work-\d{4}-\d{2}-\d{2}\.txt$/);
    expect(mime).toBe('text/plain');
  });

  it('names the file without an item fragment when the host supplies no name', () => {
    render(<Harness allowDownload withoutItemName />);
    fireEvent.click(screen.getByRole('button', { name: 'Download' }));
    fireEvent.click(screen.getByRole('button', { name: 'Download anyway' }));
    const [body, filename] = mockDownloadText.mock.calls[0] ?? [];
    expect(filename).toMatch(/^hvault-backup-codes-\d{4}-\d{2}-\d{2}\.txt$/);
    expect(body).toContain('H-Vault backup codes\n');
  });

  it('can be cancelled without writing anything', () => {
    render(<Harness allowDownload />);
    fireEvent.click(screen.getByRole('button', { name: 'Download' }));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(mockDownloadText).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Download' })).toBeInTheDocument();
  });
});

describe('BackupCodeList deleting', () => {
  it('renders no delete control for a read-only list', () => {
    render(<Harness readOnly />);
    expect(screen.queryByLabelText('Remove backup code 1')).toBeNull();
    expect(screen.getByLabelText('Copy backup code 1')).toBeInTheDocument();
  });

  it('removes the row the user pressed', () => {
    render(<Harness />);
    fireEvent.click(screen.getByLabelText('Remove backup code 2'));
    expect(screen.getAllByRole('listitem')).toHaveLength(2);
  });

  it('marks deletes as disabled while a save is in flight but keeps them focusable', () => {
    // `disabled` would remove the element from the tab order, and a save still in
    // flight is exactly when the post-delete focus move needs a target.
    render(<Harness busy />);
    const button = screen.getByLabelText('Remove backup code 1');
    expect(button).toHaveAttribute('aria-disabled', 'true');
    expect(button).not.toBeDisabled();
  });

  it('ignores a click on a delete control while a save is in flight', () => {
    render(<Harness busy />);
    fireEvent.click(screen.getByLabelText('Remove backup code 1'));
    expect(screen.getAllByRole('listitem')).toHaveLength(3);
  });

  it('moves focus to whichever delete now occupies the deleted row', () => {
    render(<Harness />);
    fireEvent.click(screen.getByLabelText('Remove backup code 2'));
    expect(document.activeElement).toBe(screen.getByLabelText('Remove backup code 2'));
  });

  it('moves focus to the new last row when the last row is deleted', () => {
    render(<Harness />);
    fireEvent.click(screen.getByLabelText('Remove backup code 3'));
    expect(document.activeElement).toBe(screen.getByLabelText('Remove backup code 2'));
  });

  it('moves focus to the heading when the last code is deleted', () => {
    render(<Harness initial={['AAAA-1111']} />);
    fireEvent.click(screen.getByLabelText('Remove backup code 1'));
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Backup codes' }));
  });

  it('moves focus to the host fallback when one is supplied and the list empties', () => {
    render(<Harness initial={['AAAA-1111']} withFallback />);
    fireEvent.click(screen.getByLabelText('Remove backup code 1'));
    expect(document.activeElement).toBe(screen.getByLabelText('fallback'));
  });

  it('leaves focus alone when the codes change for some other reason', () => {
    render(<Harness />);
    const replace = screen.getByRole('button', { name: 'Replace codes' });
    replace.focus();
    fireEvent.click(replace);
    expect(document.activeElement).toBe(replace);
  });
});
