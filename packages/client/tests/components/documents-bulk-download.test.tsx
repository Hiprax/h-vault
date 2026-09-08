/**
 * The Documents page's bulk-download panel.
 *
 * ## How this suite is wired, and why
 *
 * `saveAllDocuments` is stubbed and NOTHING else is. That is the one seam this
 * tier is allowed: the run itself is exercised for real — real crypto, real
 * transport stub, real `saveDocument` — in `tests/documents-download.test.ts`,
 * which is where "a document comes back byte for byte" belongs. What is left
 * over is the panel's own job, and it is entirely about states a real run cannot
 * be asked to produce on demand: a run held open half way, a run that ended
 * because the vault locked, a summary carrying three named refusals. Driving
 * those through a real transport would mean building three failure modes per
 * assertion and would still test the panel through a keyhole.
 *
 * The stub is a DEFERRED promise, not a resolved value, so every test decides
 * when its run reports progress and when it finishes. That is what makes the
 * in-flight assertions — the bar, the current line, the Cancel button and the
 * signal it aborts — reachable at all.
 *
 * The type re-exported from the real module is kept (`importOriginal`), so
 * `UNOPENABLE_DOCUMENT_NAME` and the result shape below are the shipped ones: a
 * fixture that invented its own would go on passing after the real one changed.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup, act } from '@testing-library/react';
import React from 'react';

const harness = vi.hoisted(() => ({
  saveAllDocuments: vi.fn(),
}));

vi.mock('../../src/services/documents/downloadAll', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/services/documents/downloadAll')>();
  return { ...actual, saveAllDocuments: harness.saveAllDocuments };
});

import type { DocumentMeta } from '@hvault/shared';
import { DocumentBulkDownload } from '../../src/components/documents/DocumentBulkDownload';
import {
  UNOPENABLE_DOCUMENT_NAME,
  type BulkDownloadCandidate,
  type DocumentDownloadAllResult,
  type DocumentDownloadProgress,
  type SaveAllDocumentsOptions,
} from '../../src/services/documents/downloadAll';

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
  return { id, meta: meta(name) };
}

const THREE: BulkDownloadCandidate[] = [
  candidate('doc-1', 'alpha.txt'),
  candidate('doc-2', 'beta.txt'),
  candidate('doc-3', 'gamma.txt'),
];

function result(overrides: Partial<DocumentDownloadAllResult> = {}): DocumentDownloadAllResult {
  return { total: 3, savedCount: 3, failures: [], stopped: 'complete', ...overrides };
}

/** One held-open run: what it was handed, and the handles to drive it. */
interface HeldRun {
  targets: readonly BulkDownloadCandidate[];
  options: SaveAllDocumentsOptions;
  report: (progress: DocumentDownloadProgress) => void;
  finish: (value: DocumentDownloadAllResult) => void;
}

let runs: HeldRun[] = [];

/** The most recent run, which is what every assertion below means by "the run". */
function currentRun(): HeldRun {
  const run = runs[runs.length - 1];
  if (!run) throw new Error('no run has been started');
  return run;
}

beforeEach(() => {
  runs = [];
  harness.saveAllDocuments.mockImplementation(
    (targets: readonly BulkDownloadCandidate[], options: SaveAllDocumentsOptions) =>
      new Promise<DocumentDownloadAllResult>((resolve) => {
        runs.push({
          targets,
          options,
          report: (progress) => {
            act(() => {
              options.onProgress?.(progress);
            });
          },
          finish: (value) => {
            resolve(value);
          },
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

/** Open the confirmation and agree to it, which is the only way a run starts. */
function startRun(): void {
  fireEvent.click(screen.getByRole('button', { name: 'Download all' }));
  fireEvent.click(screen.getByRole('button', { name: 'Start download' }));
}

/** Finish the held run with `value` and let React commit the summary. */
async function finishWith(value: DocumentDownloadAllResult): Promise<void> {
  const run = currentRun();
  await act(async () => {
    run.finish(value);
    await Promise.resolve();
  });
}

function status(): HTMLElement {
  return screen.getByTestId('documents-download-all-status');
}

/* ========================================================================== */
/*  At rest                                                                    */
/* ========================================================================== */

describe('DocumentBulkDownload — at rest', () => {
  it('renders nothing at all when the list it sits above is empty', () => {
    renderPanel([]);

    expect(screen.queryByTestId('documents-download-all')).not.toBeInTheDocument();
  });

  it('names the count it would act on, and offers one control', () => {
    renderPanel();

    expect(screen.getByRole('heading', { name: 'Download your documents' })).toBeInTheDocument();
    expect(screen.getByText(/Saves the 3 document\(s\) listed below/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Download all' })).toBeInTheDocument();
    // No run has happened, so there is nothing to cancel and nothing to dismiss.
    expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Dismiss' })).not.toBeInTheDocument();
  });

  it('mounts the live region empty rather than inserting it with its message', () => {
    renderPanel();

    // A `role="status"` inserted into the document already holding its text is
    // frequently never announced — the handling that survives that shape is
    // defined for `role="alert"`, which is the wrong politeness here. So the
    // region exists from the first render, carrying nothing.
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

  it('starts nothing until the confirmation is agreed to', () => {
    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Download all' }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(harness.saveAllDocuments).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(harness.saveAllDocuments).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Download all' })).toBeInTheDocument();
  });

  it('warns in the confirmation that the browser may refuse several downloads', () => {
    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Download all' }));

    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveTextContent(/Nothing is combined into an archive/);
    expect(dialog).toHaveTextContent(/may first ask permission to download several files at once/);
  });
});

/* ========================================================================== */
/*  In flight                                                                  */
/* ========================================================================== */

describe('DocumentBulkDownload — in flight', () => {
  it('runs over a COPY of the list, so the array it was handed cannot be edited underneath it', () => {
    const listed = [...THREE];
    const { rerender } = renderPanel(listed);
    startRun();

    expect(currentRun().targets).toEqual(THREE);
    // The list the panel was handed, emptied in place while the run is in
    // flight. Without the copy the run would be iterating this very array and
    // would silently stop after one document, having told the reader three.
    listed.length = 1;
    rerender(<DocumentBulkDownload documents={listed} invalidCount={0} />);

    expect(currentRun().targets).toHaveLength(3);
    expect(status()).toHaveTextContent('Downloading 3 document(s). This page must stay open.');
  });

  it('keeps the live region coarse and puts the per-document line outside it', () => {
    renderPanel();
    startRun();
    currentRun().report({ index: 2, total: 3, name: 'beta.txt' });

    // One sentence for the whole run. A region naming each document would queue
    // one polite announcement per document, which on a large account is not a
    // progress report.
    expect(status()).toHaveTextContent('Downloading 3 document(s). This page must stay open.');
    expect(status()).not.toHaveTextContent('beta.txt');
    expect(screen.getByTestId('documents-download-all-current')).toHaveTextContent(
      'Reading 2 of 3: beta.txt',
    );
  });

  it('draws the bar over the documents already behind it, never the one being read', () => {
    renderPanel();
    startRun();
    currentRun().report({ index: 3, total: 3, name: 'gamma.txt' });

    const bar = screen.getByRole('progressbar', { name: 'Download progress' });
    expect(bar).toHaveAttribute('aria-valuenow', '2');
    expect(bar).toHaveAttribute('aria-valuemax', '3');
    // The count is on the bar for anyone who asks for it, which is what lets the
    // live region stay quiet.
    expect(bar).toHaveAttribute('aria-valuetext', '2 of 3 documents');
  });

  it('aborts the run when Cancel is pressed', () => {
    renderPanel();
    startRun();

    expect(currentRun().options.signal?.aborted).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(currentRun().options.signal?.aborted).toBe(true);
  });

  it('aborts the run when the page it lives on goes away', () => {
    const { unmount } = renderPanel();
    startRun();
    const { options } = currentRun();

    unmount();

    // A download is page-scoped: navigating away, or locking the vault (which
    // swaps this whole route out), must stop it rather than let it decrypt on
    // into a closed vault.
    expect(options.signal?.aborted).toBe(true);
  });
});

/* ========================================================================== */
/*  The summary                                                                */
/* ========================================================================== */

describe('DocumentBulkDownload — the summary', () => {
  it('reports what was verified and sent, never what was "saved"', async () => {
    renderPanel();
    startRun();
    await finishWith(result());

    // The wording is the honest one: an anchor-and-object-URL download reports
    // nothing back, so the panel claims only what it can observe.
    expect(status()).toHaveTextContent(
      "3 of 3 document(s) verified and sent to your browser's downloads.",
    );
    expect(screen.getByText(/can refuse several downloads from one action/)).toBeInTheDocument();
    expect(screen.queryByTestId('documents-download-all-failures')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Continue' })).not.toBeInTheDocument();
  });

  it('names every document it could not save, with its own reason', async () => {
    renderPanel();
    startRun();
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
    // Outside the live region, so a summary of twelve refusals is read on demand
    // rather than announced over the sentence that says how the run ended.
    expect(status()).not.toContainElement(failures);
  });

  it('drops the browser note when nothing reached the browser at all', async () => {
    renderPanel();
    startRun();
    await finishWith(
      result({
        savedCount: 0,
        failures: [{ id: 'doc-1', name: 'alpha.txt', reason: 'nope' }],
      }),
    );

    expect(screen.queryByText(/can refuse several downloads/)).not.toBeInTheDocument();
  });

  it.each([
    ['cancelled', 'Download cancelled.'],
    ['rate-limited', 'The server limited how quickly documents could be read'],
    ['vault-locked', 'The vault locked, so the download stopped.'],
  ] as const)('says WHICH early a run ending as %s stopped', async (stopped, lead) => {
    renderPanel();
    startRun();
    await finishWith(result({ savedCount: 1, stopped }));

    expect(status()).toHaveTextContent(lead);
    // And how much of the library is still on the server, which is the number a
    // reader actually needs.
    expect(status()).toHaveTextContent('2 not reached.');
  });

  it('offers the rate-limited document itself to Continue, and quotes the wait', async () => {
    // The resume point is `savedCount + failures.length` rows in, so a 429 that
    // was recorded as a failure CONSUMED its own row and Continue skipped it —
    // the one refusal that is purely transient was the one a resume could not
    // reach. `saveAllDocuments` now leaves that row unreached and puts the wait
    // on `stoppedDetail`; this is the panel half of that contract.
    renderPanel();
    startRun();
    await finishWith(
      result({
        savedCount: 1,
        failures: [],
        stopped: 'rate-limited',
        stoppedDetail: 'Too many attempts. Please try again in 30 seconds.',
      }),
    );

    // The wait reaches the reader, on the summary rather than on a row.
    expect(status()).toHaveTextContent('Too many attempts. Please try again in 30 seconds.');
    expect(status()).toHaveTextContent('2 not reached.');
    expect(screen.queryByTestId('documents-download-all-failures')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));

    // BOTH remaining documents, starting with the one the limit interrupted.
    expect(currentRun().targets).toEqual([THREE[1], THREE[2]]);
  });

  it('carries THIS leg’s stop detail, never the one the previous leg reported', async () => {
    renderPanel();
    startRun();
    await finishWith(
      result({
        savedCount: 1,
        failures: [],
        stopped: 'rate-limited',
        stoppedDetail: 'Too many attempts. Please try again in 30 seconds.',
      }),
    );
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));

    await finishWith({
      total: 2,
      savedCount: 1,
      failures: [],
      stopped: 'rate-limited',
      stoppedDetail: 'Too many attempts. Please try again in 5 minutes.',
    });

    // The second leg's wait, which is the one in front of the reader. A merge
    // that kept the carried value would make every later rate limit quieter than
    // the first, on the leg where the wait matters most.
    expect(status()).toHaveTextContent('Too many attempts. Please try again in 5 minutes.');
    expect(status()).not.toHaveTextContent('30 seconds');
  });

  it('says nothing extra when the stop had nothing to add', async () => {
    // The negative: `stoppedDetail` is absent for the other three endings, and an
    // absent one must not render as a stray space or the word "undefined".
    renderPanel();
    startRun();
    await finishWith(result({ savedCount: 1, stopped: 'vault-locked' }));

    expect(status()).toHaveTextContent(
      "The vault locked, so the download stopped. 1 of 3 document(s) verified and sent to your browser's downloads. 2 not reached.",
    );
    expect(status()).not.toHaveTextContent('undefined');
  });

  it('resumes from where a stopped run got to, counting the whole export', async () => {
    renderPanel();
    startRun();
    await finishWith(result({ savedCount: 1, stopped: 'rate-limited' }));

    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));

    // Only what the first leg never reached.
    expect(currentRun().targets).toEqual([THREE[1], THREE[2]]);
    // And the bar still counts the whole export, not the leg: "1 of 3", never
    // "0 of 2".
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
    });

    // Merged, so the summary describes the export rather than its last leg.
    expect(status()).toHaveTextContent(
      "2 of 3 document(s) verified and sent to your browser's downloads. 1 could not be saved.",
    );
    expect(screen.getByTestId('documents-download-all-failures')).toHaveTextContent('gamma.txt');
    expect(screen.queryByRole('button', { name: 'Continue' })).not.toBeInTheDocument();
  });

  it('keeps the summary on screen after the list underneath it empties', async () => {
    const { rerender } = renderPanel();
    startRun();
    await finishWith(result());

    rerender(<DocumentBulkDownload documents={[]} invalidCount={0} />);

    // The panel disappears when there is nothing to offer AND nothing to report.
    // A finished run is something to report, and a reader who filtered the list
    // afterwards has not withdrawn their interest in how it went.
    expect(status()).toHaveTextContent('3 of 3 document(s)');
  });

  it('returns to rest when the summary is dismissed', async () => {
    renderPanel();
    startRun();
    await finishWith(result());

    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));

    expect(status()).toHaveTextContent('');
    expect(status().className).toContain('sr-only');
    expect(screen.getByRole('button', { name: 'Download all' })).toBeInTheDocument();
  });

  it('keeps ONE live region across every state rather than replacing it', async () => {
    renderPanel();
    const region = status();

    startRun();
    expect(status()).toBe(region);

    await finishWith(result());
    // The node identity is the assertion, not the attribute: a region re-created
    // for each message is the defect this shape exists to avoid, and it looks
    // right in every screenshot.
    expect(status()).toBe(region);
  });
});
