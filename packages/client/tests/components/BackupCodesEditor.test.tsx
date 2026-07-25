/**
 * The backup-codes editor: format selection, live parse feedback, and what Add /
 * Clear all / Remove actually hand back to the host.
 *
 * The REAL shared parser runs here (the house style for `otpauth`, `react-markdown`
 * and `zod` alike). Where a test asserts the error prose it derives the expectation
 * by calling `parseBackupCodes` itself, so the two suites stay decoupled and a
 * wording change cannot make this file assert stale text.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { useState } from 'react';
import { parseBackupCodes } from '@hvault/shared';
import { BackupCodesEditor } from '../../src/components/vault/BackupCodesEditor';
import { __resetClipboardGuardForTests } from '../../src/services/clipboard/clipboardService';

const mockToast = vi.fn();

vi.mock('../../src/components/ui/Toast', () => ({
  useToast: () => ({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() }),
}));

vi.mock('../../src/hooks/useUserSettings', () => ({
  useUserSettings: () => ({ autoLockTimeout: 15, clipboardClearTimeout: 30, theme: 'system' }),
}));

vi.mock('../../src/lib/download', () => ({ downloadText: vi.fn(), downloadBlob: vi.fn() }));

Object.defineProperty(navigator, 'clipboard', {
  value: { writeText: vi.fn().mockResolvedValue(undefined), readText: vi.fn() },
  writable: true,
  configurable: true,
});

const mockRemove = vi.fn();
let lastCodes: string[] | null = null;

function Harness({ initial = [] as string[] }) {
  const [codes, setCodes] = useState<readonly string[]>(initial);
  return (
    <BackupCodesEditor
      codes={codes}
      onChangeCodes={(next) => {
        lastCodes = next;
        setCodes(next);
      }}
      onRemoveSection={mockRemove}
    />
  );
}

function paste(text: string) {
  fireEvent.change(screen.getByPlaceholderText('Paste your backup codes'), {
    target: { value: text },
  });
}

function chooseFormat(value: string) {
  fireEvent.change(screen.getByLabelText('Format'), { target: { value } });
}

function add() {
  fireEvent.click(screen.getByRole('button', { name: 'Add codes' }));
}

beforeEach(() => {
  vi.clearAllMocks();
  lastCodes = null;
  __resetClipboardGuardForTests();
});

afterEach(() => {
  __resetClipboardGuardForTests();
});

describe('BackupCodesEditor empty state', () => {
  it('shows the paste box with Add disabled and no list', () => {
    render(<Harness />);
    expect(screen.getByPlaceholderText('Paste your backup codes')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add codes' })).toBeDisabled();
    expect(screen.queryByRole('list')).toBeNull();
  });

  it('offers Remove rather than Clear all while the list is empty', () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole('button', { name: 'Remove' }));
    expect(mockRemove).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: 'Clear all' })).toBeNull();
  });

  it('gives the paste box an accessible name of its own', () => {
    // It is not inside a FormField, so without one its name falls back to the
    // placeholder.
    render(<Harness />);
    expect(screen.getByLabelText('Paste your backup codes')).toBeInTheDocument();
  });

  it('defaults the format picker to auto-detection', () => {
    render(<Harness />);
    expect(screen.getByLabelText('Format')).toHaveValue('auto');
  });
});

describe('BackupCodesEditor parse feedback', () => {
  it('reports the detected format and the code count as the user pastes', () => {
    render(<Harness />);
    paste('A-1\nB-2\nC-3');
    expect(screen.getByText(/Detected: one per line/)).toBeInTheDocument();
    expect(screen.getByText(/3 codes found/)).toBeInTheDocument();
  });

  it('uses the singular for one code', () => {
    render(<Harness />);
    paste('A-1');
    expect(screen.getByText(/1 code found/)).toBeInTheDocument();
  });

  it('omits the "Detected" prefix when the user pinned a format', () => {
    render(<Harness />);
    chooseFormat('comma');
    paste('A-1,B-2');
    expect(screen.queryByText(/Detected:/)).toBeNull();
    expect(screen.getByText(/2 codes found/)).toBeInTheDocument();
  });

  it('validates strictly against a pinned format', () => {
    render(<Harness />);
    // Auto-detection accepts this as comma-separated...
    paste('dsjfkkj,fdsffs');
    expect(screen.getByText(/2 codes found/)).toBeInTheDocument();
    // ...and pinning "space" is what turns the comma into an error. That is the
    // entire reason the picker exists alongside auto-detection.
    chooseFormat('space');
    expect(screen.getByText(/cannot contain a comma/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add codes' })).toBeDisabled();
  });

  it('surfaces the parser message and its hint verbatim', () => {
    const bad = 'jfdsjkh, dhfsk,fdsf,';
    const result = parseBackupCodes(bad, { format: 'comma' });
    expect(result.ok).toBe(false);
    render(<Harness />);
    chooseFormat('comma');
    paste(bad);
    if (!result.ok) {
      expect(
        screen.getByText(new RegExp(escapeForRegExp(result.issue.message))),
      ).toBeInTheDocument();
      const hint = result.issue.hint;
      expect(hint).toBeDefined();
      if (hint !== undefined) {
        expect(screen.getByText(new RegExp(escapeForRegExp(hint)))).toBeInTheDocument();
      }
    }
  });

  it('points at the offending character with a line and column', () => {
    render(<Harness />);
    chooseFormat('newline');
    paste('AAAA-1\nBB*B-2');
    expect(screen.getByText(/Line 2, character 3\./)).toBeInTheDocument();
  });

  it('renders the offending line as a marked-up excerpt', () => {
    const { container } = render(<Harness />);
    chooseFormat('newline');
    paste('AAAA-1\nBB*B-2');
    // `p[...]` and not `[...]`: the warning icon is aria-hidden too.
    const excerpt = container.querySelector('p[aria-hidden="true"]');
    expect(excerpt?.textContent).toBe('BB*B-2');
  });

  it('marks the textarea invalid only while the paste is rejected', () => {
    render(<Harness />);
    const textarea = screen.getByPlaceholderText('Paste your backup codes');
    expect(textarea).not.toHaveAttribute('aria-invalid');
    paste('a b,c');
    chooseFormat('comma');
    expect(textarea).toHaveAttribute('aria-invalid', 'true');
    paste('a,c');
    expect(textarea).not.toHaveAttribute('aria-invalid');
  });

  it('says nothing at all for an empty box', () => {
    render(<Harness />);
    paste('A-1');
    paste('');
    expect(screen.queryByText(/codes found/)).toBeNull();
    expect(screen.getByRole('button', { name: 'Add codes' })).toBeDisabled();
  });

  it('warns before committing that duplicates in the paste will be skipped', () => {
    render(<Harness />);
    paste('A-1,A-1,B-2');
    expect(screen.getByText(/1 duplicate will be skipped/)).toBeInTheDocument();
  });

  it('warns before committing that some codes will not fit', () => {
    render(<Harness initial={Array.from({ length: 49 }, (_, i) => `existing-${i}`)} />);
    paste('X-1 X-2 X-3');
    expect(screen.getByText(/2 will not fit \(limit 50\)/)).toBeInTheDocument();
  });
});

describe('BackupCodesEditor committing', () => {
  it('hands the merged codes to the host, clears the box and returns focus to it', () => {
    render(<Harness />);
    paste('AAAA-1111\nBBBB-2222');
    add();
    expect(lastCodes).toEqual(['AAAA-1111', 'BBBB-2222']);
    const textarea = screen.getByPlaceholderText('Paste your backup codes');
    expect(textarea).toHaveValue('');
    // Add is disabled the moment the box empties, and a focused element that becomes
    // disabled blurs to document.body in Chromium.
    expect(document.activeElement).toBe(textarea);
  });

  it('appends a second batch rather than replacing the first', () => {
    render(<Harness />);
    paste('AAAA-1111');
    add();
    paste('BBBB-2222');
    add();
    expect(lastCodes).toEqual(['AAAA-1111', 'BBBB-2222']);
  });

  it('reports only what was added when nothing was skipped', () => {
    render(<Harness />);
    paste('AAAA-1111 BBBB-2222');
    add();
    expect(screen.getByText('Added 2 codes.')).toBeInTheDocument();
  });

  it('uses the singular for a single added code', () => {
    render(<Harness />);
    paste('AAAA-1111');
    add();
    expect(screen.getByText('Added 1 code.')).toBeInTheDocument();
  });

  it('reports duplicates skipped and codes that did not fit', () => {
    render(<Harness initial={Array.from({ length: 48 }, (_, i) => `e-${i}`)} />);
    paste('e-0 X-1 X-2 X-3');
    add();
    expect(
      screen.getByText('Added 2 codes. 1 duplicate skipped. 1 not added (limit 50 reached).'),
    ).toBeInTheDocument();
  });

  it('pluralises the duplicate count, before and after committing', () => {
    render(<Harness initial={['AAAA-1111', 'BBBB-2222']} />);
    paste('AAAA-1111 BBBB-2222 CCCC-3333');
    expect(screen.getByText(/2 duplicates will be skipped/)).toBeInTheDocument();
    add();
    expect(screen.getByText('Added 1 code. 2 duplicates skipped.')).toBeInTheDocument();
  });

  it('reports a paste that could not be added at all because the list is full', () => {
    render(<Harness initial={Array.from({ length: 50 }, (_, i) => `e-${i}`)} />);
    paste('X-1 X-2');
    add();
    expect(screen.getByText('Added 0 codes. 2 not added (limit 50 reached).')).toBeInTheDocument();
  });

  it('says so plainly when every pasted code was already stored', () => {
    render(<Harness initial={['AAAA-1111', 'BBBB-2222']} />);
    paste('AAAA-1111 BBBB-2222');
    add();
    expect(screen.getByText('All 2 codes are already in the list.')).toBeInTheDocument();
  });

  it('uses the singular when the one pasted code was already stored', () => {
    render(<Harness initial={['AAAA-1111']} />);
    paste('AAAA-1111');
    add();
    expect(screen.getByText('That code is already in the list.')).toBeInTheDocument();
  });
});

describe('BackupCodesEditor list management', () => {
  it('removes one code and announces which', () => {
    render(<Harness initial={['AAAA-1111', 'BBBB-2222', 'CCCC-3333']} />);
    fireEvent.click(screen.getByLabelText('Remove backup code 2'));
    expect(lastCodes).toEqual(['AAAA-1111', 'CCCC-3333']);
    expect(screen.getByText('Backup code 2 removed. 2 remaining.')).toBeInTheDocument();
  });

  it('asks before clearing every code, and can be cancelled', () => {
    render(<Harness initial={['AAAA-1111', 'BBBB-2222']} />);
    fireEvent.click(screen.getByRole('button', { name: 'Clear all' }));
    expect(screen.getByText('Remove all 2 codes?')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(lastCodes).toBeNull();
    expect(screen.getByRole('button', { name: 'Clear all' })).toBeInTheDocument();
  });

  it('clears every code on confirmation and returns focus to the paste box', () => {
    render(<Harness initial={['AAAA-1111', 'BBBB-2222']} />);
    fireEvent.click(screen.getByRole('button', { name: 'Clear all' }));
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    expect(lastCodes).toEqual([]);
    expect(screen.getByText('All backup codes removed.')).toBeInTheDocument();
    expect(document.activeElement).toBe(screen.getByPlaceholderText('Paste your backup codes'));
  });

  it('offers a copy control for each stored code', async () => {
    render(<Harness initial={['AAAA-1111']} />);
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Copy backup code 1'));
    });
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('AAAA-1111');
  });

  it('offers no download from the form, where the codes are not saved yet', () => {
    // Downloading unsaved codes and then cancelling the form would leave recovery
    // secrets on disk that are in no vault.
    render(<Harness initial={['AAAA-1111']} />);
    expect(screen.queryByRole('button', { name: /Download/ })).toBeNull();
  });
});

function escapeForRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
