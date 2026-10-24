/**
 * The Documents page's bulk-download panel: one ZIP archive per run.
 *
 * ## How this suite is wired, and why
 *
 * `archiveDocuments` and `openArchiveTarget` are stubbed and NOTHING else is.
 * The run itself is exercised for real — real crypto, real transport stub, real
 * writer and targets — in `tests/documents-download.test.ts`, which is where "a
 * document comes back byte for byte" belongs. What is left is the panel's own
 * job, and it is about states a real run cannot be asked to produce on demand: a
 * save dialog still open, a run held half way, a run that ended early, a summary
 * naming refusals.
 *
 * Both stubs are DEFERRED where it matters, so every test decides when the
 * dialog answers, when the run reports progress and when it finishes. The types
 * and constants are the shipped ones (`importOriginal`), so a fixture cannot go
 * on passing after the real shape changed.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup, act } from '@testing-library/react';
import React from 'react';

const harness = vi.hoisted(() => ({
  archiveDocuments: vi.fn(),
  openArchiveTarget: vi.fn(),
}));

vi.mock('../../src/services/documents/downloadAll', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/services/documents/downloadAll')>();
  return { ...actual, archiveDocuments: harness.archiveDocuments };
});

vi.mock('../../src/services/documents/archiveTarget', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../../src/services/documents/archiveTarget')>();
  return { ...actual, openArchiveTarget: harness.openArchiveTarget };
});

import type { DocumentMeta, DocumentResponse } from '@hvault/shared';
import { DocumentBulkDownload } from '../../src/components/documents/DocumentBulkDownload';
import { ArchivePathAllocator } from '../../src/services/documents/archiveNames';
import type { ArchiveTarget } from '../../src/services/documents/archiveTarget';
import { UNOPENABLE_DOCUMENT_NAME } from '../../src/services/documents/documentNames';
import type {
  ArchiveDocumentsOptions,
  BulkDownloadCandidate,
  DocumentArchiveResult,
  DocumentDownloadProgress,
} from '../../src/services/documents/downloadAll';
import { useVaultStore, type DecryptedFolder } from '../../src/stores/vaultStore';

/* -------------------------------------------------------------------------- */
/*  Fixtures                                                                   */
/* -------------------------------------------------------------------------- */

function meta(name: string): DocumentMeta {
  return {
    name,
    mime: 'text/plain',
    ext: 'txt',
    plaintextBytes: 20,
    sha256: '0'.repeat(64),
    chunkPlaintextBytes: 1024,
    chunkCount: 1,
    tags: [],
    capturedAt: '2026-01-01T00:00:00.000Z',
  };
}

function candidate(id: string, name: string): BulkDownloadCandidate {
  return { id, meta: meta(name), _raw: { _id: id } as unknown as DocumentResponse };
}

const THREE: BulkDownloadCandidate[] = [
  candidate('doc-1', 'alpha.txt'),
  candidate('doc-2', 'beta.txt'),
  candidate('doc-3', 'gamma.txt'),
];

const ARCHIVE_NAME = /^hvault-documents-\d{4}-\d{2}-\d{2}\.zip$/;
const PART_TWO_NAME = /^hvault-documents-\d{4}-\d{2}-\d{2}-part-2\.zip$/;

/** A target as `openArchiveTarget` would resolve one, recording its discard. */
function fakeTarget(kind: ArchiveTarget['kind'] = 'download', name = 'first.zip') {
  const discard = vi.fn(() => Promise.resolve());
  const target: ArchiveTarget = {
    kind,
    name,
    limitBytes: 1024,
    write: () => Promise.resolve(),
    commit: () => Promise.resolve(),
    discard,
  };
  return { target, discard };
}

function result(overrides: Partial<DocumentArchiveResult> = {}): DocumentArchiveResult {
  return {
    total: 3,
    savedCount: 3,
    failures: [],
    stopped: 'complete',
    archive: { name: 'first.zip', kind: 'download' },
    ...overrides,
  };
}

/** One held-open run: what it was handed, and the handles to drive it. */
interface HeldRun {
  targets: readonly BulkDownloadCandidate[];
  target: ArchiveTarget;
  options: ArchiveDocumentsOptions;
  report: (progress: DocumentDownloadProgress) => void;
  finishing: () => void;
  finish: (value: DocumentArchiveResult) => void;
}

let runs: HeldRun[] = [];

function currentRun(): HeldRun {
  const run = runs[runs.length - 1];
  if (!run) throw new Error('no run has been started');
  return run;
}

beforeEach(() => {
  runs = [];
  useVaultStore.setState({ folders: [] });
  harness.openArchiveTarget.mockImplementation(() => Promise.resolve(fakeTarget().target));
  harness.archiveDocuments.mockImplementation(
    (
      targets: readonly BulkDownloadCandidate[],
      target: ArchiveTarget,
      options: ArchiveDocumentsOptions,
    ) =>
      new Promise<DocumentArchiveResult>((resolve) => {
        runs.push({
          targets,
          target,
          options,
          report: (progress) => {
            act(() => {
              options.onProgress?.(progress);
            });
          },
          finishing: () => {
            act(() => {
              options.onFinishing?.();
            });
          },
          finish: resolve,
        });
      }),
  );
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

/* -------------------------------------------------------------------------- */
/*  Driving the panel                                                          */
/* -------------------------------------------------------------------------- */

function renderPanel(
  documents: readonly BulkDownloadCandidate[] = THREE,
  invalidCount = 0,
): ReturnType<typeof render> {
  return render(
    <DocumentBulkDownload documents={documents} invalidCount={invalidCount} />,
  ) as ReturnType<typeof render>;
}

/** Open the confirmation and agree to it, letting the save target settle. */
async function startRun(): Promise<void> {
  fireEvent.click(screen.getByRole('button', { name: 'Download all' }));
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Start download' }));
  });
}

/** Finish the held run with `value` and let React commit the summary. */
async function finishWith(value: DocumentArchiveResult): Promise<void> {
  const run = currentRun();
  await act(async () => {
    run.finish(value);
    await Promise.resolve();
  });
}

/** Press a button whose click opens a save target, letting it settle. */
async function press(name: string): Promise<void> {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function status(): HTMLElement {
  return screen.getByTestId('documents-download-all-status');
}

/** A deferred save target, for a dialog that stays open until the test says. */
function deferredTarget() {
  let settle!: (target: ArchiveTarget | null) => void;
  let refuse!: (error: unknown) => void;
  harness.openArchiveTarget.mockImplementationOnce(
    () =>
      new Promise<ArchiveTarget | null>((resolve, reject) => {
        settle = resolve;
        refuse = reject;
      }),
  );
  return {
    settle: (target: ArchiveTarget | null) => act(async () => settle(target)),
    refuse: (error: unknown) => act(async () => refuse(error)),
  };
}

/** Whether the page currently asks before it is closed. */
function asksBeforeClosing(): boolean {
  const event = new Event('beforeunload', { cancelable: true });
  window.dispatchEvent(event);
  return event.defaultPrevented;
}

/* ========================================================================== */
/*  At rest                                                                    */
/* ========================================================================== */

describe('DocumentBulkDownload — at rest', () => {
  it('renders nothing at all when the list it sits above is empty', () => {
    renderPanel([]);

    expect(screen.queryByTestId('documents-download-all')).not.toBeInTheDocument();
  });

  it('names the count it would act on, as one ZIP archive, and offers one control', () => {
    renderPanel();

    expect(screen.getByRole('heading', { name: 'Download your documents' })).toBeInTheDocument();
    expect(
      screen.getByText(
        /Saves the 3 document\(s\) listed below to this device as one ZIP archive\./,
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Download all' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Stop' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Dismiss' })).not.toBeInTheDocument();
    expect(asksBeforeClosing()).toBe(false);
  });

  it('mounts the live region empty rather than inserting it with its message', () => {
    renderPanel();

    expect(status()).toHaveTextContent('');
    expect(status().className).toContain('sr-only');
  });

  it('says how many rows this view could not read at all, so the count is not read as complete', () => {
    renderPanel(THREE, 2);

    expect(
      screen.getByText(/2 row\(s\) in this view could not be read at all and are not included/),
    ).toBeInTheDocument();
  });

  it('says nothing about unreadable rows when there are none', () => {
    renderPanel(THREE, 0);

    expect(screen.queryByText(/could not be read at all/)).not.toBeInTheDocument();
  });

  it('opens nothing and starts nothing until the confirmation is agreed to', () => {
    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Download all' }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(harness.openArchiveTarget).not.toHaveBeenCalled();
    expect(harness.archiveDocuments).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Download all' })).toBeInTheDocument();
  });

  it('explains the archive, the checks and what an early end keeps, in the confirmation', () => {
    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Download all' }));

    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveTextContent(/They are saved as one ZIP archive\./);
    expect(dialog).toHaveTextContent(
      /checked against the checksum sealed inside it before it is added/,
    );
    expect(dialog).toHaveTextContent(/nothing is compressed and nothing is sent anywhere/);
    expect(dialog).toHaveTextContent(
      /Folders become folders in the archive, so their names appear in it/,
    );
    expect(dialog).toHaveTextContent(/Continue saves the rest in another one/);
    expect(dialog).toHaveTextContent(
      /Stop, a lock or leaving the page saves the documents already verified/,
    );
    expect(dialog).not.toHaveTextContent(/Nothing is combined into an archive/);
  });
});

/* ========================================================================== */
/*  Opening the archive                                                        */
/* ========================================================================== */

describe('DocumentBulkDownload — concealed while the upload form is open', () => {
  it('is hidden while it would only offer its button, and comes back when the form closes', () => {
    const { rerender } = render(
      <DocumentBulkDownload documents={THREE} invalidCount={0} concealed />,
    );
    const section = screen.getByTestId('documents-download-all');
    expect(section).not.toBeVisible();
    expect(screen.queryByRole('button', { name: 'Download all' })).toBeNull();

    rerender(<DocumentBulkDownload documents={THREE} invalidCount={0} />);
    expect(section).toBeVisible();
    expect(screen.getByRole('button', { name: 'Download all' })).toBeVisible();
  });

  it('keeps a running export and its summary on screen, and never aborts it', async () => {
    const { rerender } = renderPanel();
    await startRun();
    rerender(<DocumentBulkDownload documents={THREE} invalidCount={0} concealed />);

    expect(screen.getByTestId('documents-download-all')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Stop' })).toBeVisible();
    expect(currentRun().options.signal.aborted).toBe(false);

    await finishWith(result());
    expect(status()).toBeVisible();
    expect(status()).toHaveTextContent('3 of 3 document(s) verified');

    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(screen.getByTestId('documents-download-all')).not.toBeVisible();
  });

  it('points to Full Backup for a copy a restore brings back', () => {
    renderPanel();
    expect(
      screen.getByText(/for an encrypted copy that a restore brings back, use Full Backup/),
    ).toBeInTheDocument();
  });
});

describe('DocumentBulkDownload — opening the archive', () => {
  it('opens the save target inside the Start click itself, under the dated archive name', async () => {
    renderPanel();
    fireEvent.click(screen.getByRole('button', { name: 'Download all' }));

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Start download' }));
      // Asserted INSIDE the click's turn, before anything is awaited: the save
      // dialog opens only on the click's own transient activation.
      expect(harness.openArchiveTarget).toHaveBeenCalledTimes(1);
    });

    expect(harness.openArchiveTarget).toHaveBeenCalledWith(expect.stringMatching(ARCHIVE_NAME));
    expect(harness.archiveDocuments).toHaveBeenCalledTimes(1);
    expect(currentRun().target.name).toBe('first.zip');
  });

  it('starts nothing, and changes nothing, when the save dialog is dismissed', async () => {
    harness.openArchiveTarget.mockImplementationOnce(() => Promise.resolve(null));
    renderPanel();

    await startRun();

    expect(harness.archiveDocuments).not.toHaveBeenCalled();
    expect(status()).toHaveTextContent('');
    expect(screen.getByRole('button', { name: 'Download all' })).toBeInTheDocument();
    // ...and a second attempt is not blocked by the first.
    await startRun();
    expect(harness.archiveDocuments).toHaveBeenCalledTimes(1);
  });

  it('reports a save dialog the browser refused, with its reason, and offers to try again', async () => {
    harness.openArchiveTarget.mockImplementationOnce(() =>
      Promise.reject(new Error('Must be handling a user gesture to show a file picker.')),
    );
    renderPanel();

    await startRun();

    expect(harness.archiveDocuments).not.toHaveBeenCalled();
    expect(status()).toHaveTextContent(
      'Your browser could not save the archive. Nothing was saved. 3 not reached. Must be handling a user gesture to show a file picker.',
    );
    await press('Try again');
    expect(currentRun().targets).toEqual(THREE);
  });

  it('drops the target, unused, when the page goes away while the dialog is open', async () => {
    const dialog = deferredTarget();
    const { unmount } = renderPanel();
    fireEvent.click(screen.getByRole('button', { name: 'Download all' }));
    fireEvent.click(screen.getByRole('button', { name: 'Start download' }));

    unmount();
    const { target, discard } = fakeTarget('file', 'chosen.zip');
    await dialog.settle(target);

    expect(discard).toHaveBeenCalledTimes(1);
    expect(harness.archiveDocuments).not.toHaveBeenCalled();
  });

  it('starts one leg however many times Continue is pressed while its dialog is open', async () => {
    renderPanel();
    await startRun();
    await finishWith(result({ savedCount: 1, stopped: 'archive-full' }));

    const dialog = deferredTarget();
    fireEvent.click(screen.getByRole('button', { name: 'Continue in a new archive' }));
    fireEvent.click(screen.getByRole('button', { name: 'Continue in a new archive' }));
    await dialog.settle(fakeTarget('download', 'second.zip').target);

    expect(harness.openArchiveTarget).toHaveBeenCalledTimes(2);
    expect(harness.openArchiveTarget).toHaveBeenLastCalledWith(
      expect.stringMatching(PART_TWO_NAME),
    );
    expect(harness.archiveDocuments).toHaveBeenCalledTimes(2);
  });
});

/* ========================================================================== */
/*  In flight                                                                  */
/* ========================================================================== */

describe('DocumentBulkDownload — in flight', () => {
  it('runs over a COPY of the list, so the array it was handed cannot be edited underneath it', async () => {
    const listed = [...THREE];
    const { rerender } = renderPanel(listed);
    await startRun();

    listed.length = 1;
    rerender(<DocumentBulkDownload documents={listed} invalidCount={0} />);

    expect(currentRun().targets).toEqual(THREE);
    expect(status()).toHaveTextContent(
      'Archiving 3 document(s). Keep this page open: Stop, or leaving it, saves the documents already verified.',
    );
  });

  it('keeps the live region coarse and puts the per-document line outside it', async () => {
    renderPanel();
    await startRun();
    currentRun().report({ index: 2, total: 3, name: 'beta.txt' });

    expect(status()).not.toHaveTextContent('beta.txt');
    expect(screen.getByTestId('documents-download-all-current')).toHaveTextContent(
      'Reading 2 of 3: beta.txt',
    );
  });

  it('draws the bar over the documents already behind it, never the one being read', async () => {
    renderPanel();
    await startRun();
    currentRun().report({ index: 3, total: 3, name: 'gamma.txt' });

    const bar = screen.getByRole('progressbar', { name: 'Download progress' });
    expect(bar).toHaveAttribute('aria-valuenow', '2');
    expect(bar).toHaveAttribute('aria-valuemax', '3');
    expect(bar).toHaveAttribute('aria-valuetext', '2 of 3 documents');
  });

  it('shows the finishing state, and refuses Stop while the archive is being finished', async () => {
    renderPanel();
    await startRun();

    expect(currentRun().options.signal.aborted).toBe(false);
    currentRun().finishing();
    expect(screen.getByTestId('documents-download-all-current')).toHaveTextContent(
      'Finishing the archive…',
    );
    expect(screen.getByRole('button', { name: 'Stop' })).toBeDisabled();
  });

  it('aborts the run when Stop is pressed', async () => {
    renderPanel();
    await startRun();

    fireEvent.click(screen.getByRole('button', { name: 'Stop' }));

    expect(currentRun().options.signal.aborted).toBe(true);
  });

  it('aborts the run when the page it lives on goes away', async () => {
    const { unmount } = renderPanel();
    await startRun();
    const { options } = currentRun();

    unmount();

    expect(options.signal.aborted).toBe(true);
  });

  it('asks before the tab is closed only while a run is active', async () => {
    renderPanel();
    expect(asksBeforeClosing()).toBe(false);

    await startRun();
    expect(asksBeforeClosing()).toBe(true);

    await finishWith(result());
    expect(asksBeforeClosing()).toBe(false);
  });

  it('names paths against the folders the vault holds when the run starts', async () => {
    const work: DecryptedFolder = {
      id: '66c0f1a2b3c4d5e6f7a8b901',
      name: 'Work',
      sortOrder: 0,
      createdAt: '',
      updatedAt: '',
      _raw: {} as DecryptedFolder['_raw'],
    };
    useVaultStore.setState({ folders: [work] });
    renderPanel();
    await startRun();

    const { allocator } = currentRun().options;
    expect(allocator).toBeInstanceOf(ArchivePathAllocator);
    expect(allocator.place('a.txt', work.id).path).toBe('Work/a.txt');
  });
});

/* ========================================================================== */
/*  The summary                                                                */
/* ========================================================================== */

describe('DocumentBulkDownload — the summary', () => {
  it('names the archive the browser was handed, and where to look for it', async () => {
    renderPanel();
    await startRun();
    await finishWith(result());

    expect(status()).toHaveTextContent(
      "3 of 3 document(s) verified and handed to your browser's downloads as first.zip.",
    );
    expect(screen.getByText(/its downloads list shows where it went/)).toBeInTheDocument();
    expect(screen.queryByTestId('documents-download-all-failures')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Continue|Try again/ })).not.toBeInTheDocument();
  });

  it('names the file an archive was saved as through the save dialog, with no downloads note', async () => {
    renderPanel();
    await startRun();
    await finishWith(result({ archive: { name: 'chosen.zip', kind: 'file' } }));

    expect(status()).toHaveTextContent('3 of 3 document(s) verified and saved as chosen.zip.');
    expect(screen.queryByText(/downloads list/)).not.toBeInTheDocument();
  });

  it('names every document it could not save, with its own reason, outside the live region', async () => {
    renderPanel();
    await startRun();
    await finishWith(
      result({
        savedCount: 1,
        failures: [
          { id: 'doc-2', name: 'beta.txt', reason: 'The stored file is no longer available.' },
          {
            id: 'doc-3',
            name: UNOPENABLE_DOCUMENT_NAME,
            reason: 'Its details could not be opened with this vault key.',
          },
        ],
      }),
    );

    expect(status()).toHaveTextContent('1 of 3 document(s)');
    expect(status()).toHaveTextContent('2 could not be saved.');
    const failures = screen.getByTestId('documents-download-all-failures');
    expect(failures).toHaveTextContent('beta.txt — The stored file is no longer available.');
    expect(failures).toHaveTextContent(
      `${UNOPENABLE_DOCUMENT_NAME} — Its details could not be opened with this vault key.`,
    );
    expect(status()).not.toContainElement(failures);
  });

  it('says nothing was saved when no archive was, and drops the downloads note', async () => {
    renderPanel();
    await startRun();
    await finishWith(
      result({
        savedCount: 0,
        failures: [
          { id: 'doc-1', name: 'alpha.txt', reason: 'nope' },
          { id: 'doc-2', name: 'beta.txt', reason: 'nope' },
          { id: 'doc-3', name: 'gamma.txt', reason: 'nope' },
        ],
        archive: null,
      }),
    );

    expect(status()).toHaveTextContent('Nothing was saved. 3 could not be saved.');
    expect(screen.queryByText(/downloads list/)).not.toBeInTheDocument();
    // Every row was settled, so there is nothing to continue.
    expect(screen.queryByRole('button', { name: /Continue|Try again/ })).not.toBeInTheDocument();
  });

  it.each([
    ['stopped', 'Stopped.'],
    ['vault-locked', 'The vault locked, so the archive was finished early.'],
    [
      'rate-limited',
      'The server limited how quickly documents could be read, so the archive was finished early.',
    ],
    ['archive-full', 'The archive reached its size limit.'],
  ] as const)(
    'says WHICH early a run ending as %s stopped, and how much is left',
    async (stopped, lead) => {
      renderPanel();
      await startRun();
      await finishWith(result({ savedCount: 1, stopped }));

      expect(status()).toHaveTextContent(lead);
      expect(status()).toHaveTextContent('2 not reached.');
      expect(screen.getByRole('button', { name: 'Continue in a new archive' })).toBeInTheDocument();
    },
  );

  it.each([
    [
      'rate-limited',
      'The server limited how quickly documents could be read, so nothing more was archived.',
    ],
    ['vault-locked', 'The vault locked, so nothing more was archived.'],
  ] as const)(
    'never claims an archive was finished when a leg ending as %s archived nothing',
    async (stopped, lead) => {
      renderPanel();
      await startRun();
      await finishWith(result({ savedCount: 0, stopped, archive: null }));

      expect(status()).toHaveTextContent(`${lead} Nothing was saved. 3 not reached.`);
      expect(status()).not.toHaveTextContent('finished early');
      expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
    },
  );

  it('continues the rest in a new archive, from the row the limit interrupted, quoting the wait', async () => {
    renderPanel();
    await startRun();
    const firstAllocator = currentRun().options.allocator;
    await finishWith(
      result({
        savedCount: 1,
        stopped: 'rate-limited',
        stoppedDetail: 'Too many attempts. Please try again in 15 minutes.',
      }),
    );
    expect(status()).toHaveTextContent('Too many attempts. Please try again in 15 minutes.');

    harness.openArchiveTarget.mockImplementationOnce(() =>
      Promise.resolve(fakeTarget('download', 'second.zip').target),
    );
    await press('Continue in a new archive');

    expect(harness.openArchiveTarget).toHaveBeenLastCalledWith(
      expect.stringMatching(PART_TWO_NAME),
    );
    expect(currentRun().targets).toEqual([THREE[1], THREE[2]]);
    // One allocator for the whole run, so the second archive's names never
    // collide with the first's.
    expect(currentRun().options.allocator).toBe(firstAllocator);
    // The bar counts the whole export.
    const bar = screen.getByRole('progressbar', { name: 'Download progress' });
    expect(bar).toHaveAttribute('aria-valuenow', '1');
    expect(bar).toHaveAttribute('aria-valuemax', '3');
    currentRun().report({ index: 1, total: 2, name: 'beta.txt' });
    expect(screen.getByTestId('documents-download-all-current')).toHaveTextContent(
      'Reading 2 of 3: beta.txt',
    );

    await finishWith({
      total: 2,
      savedCount: 1,
      failures: [{ id: 'doc-3', name: 'gamma.txt', reason: 'The stored file is missing.' }],
      stopped: 'complete',
      archive: { name: 'second.zip', kind: 'download' },
    });

    // Merged: the export as a whole, both archives named, this leg's ending.
    expect(status()).toHaveTextContent(
      "2 of 3 document(s) verified and handed to your browser's downloads as first.zip, second.zip. 1 could not be saved.",
    );
    expect(status()).not.toHaveTextContent('15 minutes');
    expect(screen.queryByRole('button', { name: /Continue|Try again/ })).not.toBeInTheDocument();
  });

  it('offers to TRY AGAIN when the latest archive could not be saved, and names the part by saved archives only', async () => {
    renderPanel();
    await startRun();
    await finishWith(
      result({
        savedCount: 0,
        stopped: 'save-failed',
        stoppedDetail: 'There is not enough space on the disk.',
        archive: null,
      }),
    );

    expect(status()).toHaveTextContent(
      'Your browser could not save the archive. Nothing was saved. 3 not reached. There is not enough space on the disk.',
    );
    await press('Try again');

    // Nothing was saved, so the retry is still the FIRST archive, over every row.
    expect(harness.openArchiveTarget).toHaveBeenLastCalledWith(expect.stringMatching(ARCHIVE_NAME));
    expect(currentRun().targets).toEqual(THREE);
  });

  it('says nothing extra when the stop had nothing to add', async () => {
    renderPanel();
    await startRun();
    await finishWith(result({ savedCount: 1, stopped: 'vault-locked' }));

    expect(status()).toHaveTextContent(
      "The vault locked, so the archive was finished early. 1 of 3 document(s) verified and handed to your browser's downloads as first.zip. 2 not reached.",
    );
    expect(status()).not.toHaveTextContent('undefined');
  });

  it('keeps the summary on screen after the list underneath it empties', async () => {
    const { rerender } = renderPanel();
    await startRun();
    await finishWith(result());

    rerender(<DocumentBulkDownload documents={[]} invalidCount={0} />);

    expect(status()).toHaveTextContent('3 of 3 document(s)');
  });

  it('returns to rest when the summary is dismissed', async () => {
    renderPanel();
    await startRun();
    await finishWith(result());

    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));

    expect(status()).toHaveTextContent('');
    expect(status().className).toContain('sr-only');
    expect(screen.getByRole('button', { name: 'Download all' })).toBeInTheDocument();
  });

  it('keeps ONE live region across every state rather than replacing it', async () => {
    renderPanel();
    const region = status();

    await startRun();
    expect(status()).toBe(region);

    await finishWith(result());
    expect(status()).toBe(region);
  });
});
