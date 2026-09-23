/**
 * The viewer, mounted into the detail view.
 *
 * ## What this suite is for, and what it is NOT for
 *
 * The renderers are tested in `tests/sandbox-renderers.test.ts` and
 * `tests/sandbox-markup.test.ts`; the frame's own protocol is tested in
 * `tests/document-sandbox.test.tsx`; a real `/sandbox.html` rendering a real
 * document is Playwright's job, because jsdom never loads an iframe's `src`.
 *
 * What is left, and what is here, is the DECISION: whether a frame is created at
 * all, what the reader is told when it is not, and where the chrome is drawn.
 *
 * ## The negative that matters most
 *
 * A document this application declines to preview must create NO IFRAME ELEMENT,
 * rather than a hidden one. `display: none` prevents nothing: a hidden frame
 * still loads `/sandbox.html`, still runs its script, still completes a
 * handshake and still holds a live port. So the assertion is the element's
 * ABSENCE — and, beside it, that no window `message` listener was registered for
 * that document, since the host's listener is the exploitable half.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup, act } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';
import { _resetScrollLockCount } from '../../src/components/ui/Dialog';
import React from 'react';
import {
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  MAX_PREVIEW_BYTES,
  previewModeForName,
} from '@hvault/shared';
import type { DocumentMeta, DocumentResponse } from '@hvault/shared';

/* -------------------------------------------------------------------------- */
/*  Hoisted mock state                                                         */
/* -------------------------------------------------------------------------- */

const harness = vi.hoisted(() => ({
  toast: vi.fn(),
  saveDocument: vi.fn(),
  readDocumentPlaintext: vi.fn(),
}));

/* -------------------------------------------------------------------------- */
/*  Module mocks                                                               */
/* -------------------------------------------------------------------------- */

vi.mock('../../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
}));

vi.mock('../../src/lib/logger', () => ({
  logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

vi.mock('../../src/components/ui/Toast', () => ({
  useToast: () => ({ toast: harness.toast, dismiss: vi.fn(), update: vi.fn() }),
  ToastProvider: ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
  Toaster: () => null,
}));

// The READ is replaced and nothing else. It is cryptography over a network, it
// has its own suite that drives the real thing end to end
// (`tests/documents-download.test.ts`), and what belongs here is the decision
// about whether it is called at all. The error types stay real, because the
// view's "a cancellation is not a failure" rule is an `instanceof` check.
vi.mock('../../src/services/documents/download', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/services/documents/download')>()),
  saveDocument: harness.saveDocument,
  readDocumentPlaintext: harness.readDocumentPlaintext,
}));

/* -------------------------------------------------------------------------- */
/*  Imports (after the mocks)                                                  */
/* -------------------------------------------------------------------------- */

import { useDocumentsStore, type DecryptedDocument } from '../../src/stores/documentsStore';
import { useVaultStore } from '../../src/stores/vaultStore';
import { DocumentDetail } from '../../src/components/documents/DocumentDetail';

/* -------------------------------------------------------------------------- */
/*  Fixtures                                                                   */
/* -------------------------------------------------------------------------- */

const DOC_ID = '66c0f1a2b3c4d5e6f7a8b9c0';
/** A second document, for the case that navigates from one detail view to another. */
const OTHER_ID = '66c0f1a2b3c4d5e6f7a8b9ff';

const pristineDocuments = useDocumentsStore.getState();
const pristineVault = useVaultStore.getState();

function makeRawDocument(id: string): DocumentResponse {
  return {
    _id: id,
    favorite: false,
    encryptedDek: 'ZGVr',
    dekIv: 'aXY=',
    dekTag: 'dGFn',
    streamSalt: 'c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHQ=',
    noncePrefix: 'AQIDBAUGBw==',
    encryptedMeta: 'bWV0YQ==',
    metaIv: 'bWV0YWl2',
    metaTag: 'bWV0YXRhZw==',
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount: 1,
    ciphertextBytes: 2048 + 16,
    plaintextBytes: 2048,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-02-03T00:00:00.000Z',
  };
}

function makeMeta(overrides: Partial<DocumentMeta> = {}): DocumentMeta {
  return {
    name: 'notes.md',
    mime: 'text/markdown',
    ext: 'md',
    plaintextBytes: 2048,
    sha256: 'a'.repeat(64),
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount: 1,
    tags: [],
    capturedAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

function makeDocument(overrides: Partial<DecryptedDocument> = {}): DecryptedDocument {
  const id = overrides.id ?? DOC_ID;
  return {
    id,
    favorite: false,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-02-03T00:00:00.000Z',
    meta: makeMeta(),
    _raw: makeRawDocument(id),
    ...overrides,
  };
}

function renderDetail(document: DecryptedDocument, isTrashed = false) {
  return render(
    <MemoryRouter initialEntries={[`/documents/${document.id}`]}>
      <Routes>
        <Route
          path="/documents/:id"
          element={<DocumentDetail document={document} isTrashed={isTrashed} />}
        />
        <Route path="/documents" element={<div data-testid="documents-list-route" />} />
      </Routes>
    </MemoryRouter>,
  );
}

const frame = (): HTMLIFrameElement | null => document.querySelector('iframe');

beforeEach(() => {
  vi.clearAllMocks();
  harness.readDocumentPlaintext.mockResolvedValue({
    meta: makeMeta(),
    bytes: new Uint8Array(new TextEncoder().encode('# Hello')),
  });
  useDocumentsStore.setState(pristineDocuments, true);
  useVaultStore.setState(pristineVault, true);
});

afterEach(() => {
  cleanup();
});

/* ========================================================================== */
/*  Whether a frame is created at all                                          */
/* ========================================================================== */

describe('DocumentDetail — the decision to preview', () => {
  it('mounts the frame for a markdown document, and reads it exactly once', async () => {
    renderDetail(makeDocument());

    await waitFor(() => {
      expect(frame()).not.toBeNull();
    });
    expect(harness.readDocumentPlaintext).toHaveBeenCalledTimes(1);
    expect(harness.readDocumentPlaintext.mock.calls[0]?.[0]).toBe(DOC_ID);
    // Through the SAME verified read the save path uses, with an abort signal so
    // navigating away or locking the vault ends it.
    expect(harness.readDocumentPlaintext.mock.calls[0]?.[1]?.signal).toBeInstanceOf(AbortSignal);
    // And it goes to the frame with the mode the ONE shared rule resolves, never
    // a second local predicate.
    expect(frame()?.getAttribute('sandbox')).toBe('allow-scripts');
    expect(previewModeForName('notes.md')).toBe('markdown');
  });

  it('creates NO iframe element for a PDF, and registers no listener for it', async () => {
    // The element's ABSENCE, not its visibility: a hidden frame still loads
    // `/sandbox.html`, still runs its script, still completes a handshake and
    // still holds a live port, and `display:none` prevents none of it. The
    // listener is asserted too, because the host's window listener is the
    // exploitable half of the protocol.
    const addEventListener = vi.spyOn(window, 'addEventListener');

    renderDetail(makeDocument({ meta: makeMeta({ name: 'statement.pdf', ext: 'pdf' }) }));

    expect(frame()).toBeNull();
    expect(document.querySelectorAll('iframe, embed, object')).toHaveLength(0);
    expect(addEventListener.mock.calls.filter(([type]) => type === 'message')).toHaveLength(0);
    // And nothing was decrypted on the way to that decision.
    expect(harness.readDocumentPlaintext).not.toHaveBeenCalled();
    addEventListener.mockRestore();
  });

  it('says a PDF is a decision rather than an unrecognised type', async () => {
    renderDetail(makeDocument({ meta: makeMeta({ name: 'statement.pdf', ext: 'pdf' }) }));
    const panel = screen.getByTestId('document-download-to-view');
    expect(panel).toHaveTextContent(/PDFs are download-only here, deliberately/i);
    // The reason a reader would actually want: what the risk is, not that it is
    // unsupported.
    expect(panel).toHaveTextContent(/vault key/i);
  });

  it('creates no frame for an extension it has no viewer for, and names it', async () => {
    renderDetail(makeDocument({ meta: makeMeta({ name: 'archive.zip', ext: 'zip' }) }));
    expect(frame()).toBeNull();
    expect(screen.getByTestId('document-download-to-view')).toHaveTextContent(/\.zip/);
    expect(harness.readDocumentPlaintext).not.toHaveBeenCalled();
  });

  it('creates no frame for a name with no extension, and says why', async () => {
    // `Dockerfile`, `Makefile` and `.bashrc` have no extension under the one
    // derivation rule, which is a decision the interface has to be able to state.
    renderDetail(makeDocument({ meta: makeMeta({ name: 'Dockerfile', ext: '' }) }));
    expect(frame()).toBeNull();
    expect(screen.getByTestId('document-download-to-view')).toHaveTextContent(/no extension/i);
  });

  it('creates no frame for a name whose extension is an inherited property name', async () => {
    // A document name is whatever the person who handed the user the file chose,
    // and the extension rule hands the segment after the last dot straight to a
    // lookup. `constructor` and `__proto__` are the two that survive the
    // lowercasing, and on an ordinary object literal they resolve THROUGH the
    // prototype to the `Object` function and to `Object.prototype` — neither
    // nullish, so the `?? 'none'` fallback never fires and this view offers a
    // preview whose `mode` is a value structured clone refuses. The `postMessage`
    // then throws inside the host's handshake handler, after the window listener
    // and the ten-second deadline have already been removed, and the reader is
    // left with a spinner that never resolves and no download offered.
    for (const name of ['notes.constructor', 'notes.__proto__']) {
      renderDetail(makeDocument({ meta: makeMeta({ name, ext: name.split('.')[1] ?? '' }) }));
      expect(frame(), name).toBeNull();
      expect(screen.getByTestId('document-download-to-view')).toBeInTheDocument();
      expect(harness.readDocumentPlaintext).not.toHaveBeenCalled();
      cleanup();
    }
  });

  it('declines a document over the preview budget, showing its size', async () => {
    // Decided from the METADATA, before a single segment is fetched. Reversed,
    // this document would be downloaded and decrypted in full and only then
    // turned away.
    renderDetail(
      makeDocument({
        meta: makeMeta({ name: 'huge.md', plaintextBytes: MAX_PREVIEW_BYTES + 1 }),
      }),
    );

    expect(frame()).toBeNull();
    expect(harness.readDocumentPlaintext).not.toHaveBeenCalled();
    const panel = screen.getByTestId('document-download-to-view');
    expect(panel).toHaveTextContent(/25 MB/);
    expect(panel).toHaveTextContent(/larger than/i);
  });

  it('previews a document sitting exactly on the budget', async () => {
    // The boundary, in the direction that must still work: the cap is a
    // maximum, not a threshold one byte below it.
    renderDetail(
      makeDocument({ meta: makeMeta({ name: 'exact.md', plaintextBytes: MAX_PREVIEW_BYTES }) }),
    );
    await waitFor(() => {
      expect(frame()).not.toBeNull();
    });
  });

  it('keeps the Phase 16 affordance, and no frame, for a document that will not open', async () => {
    // A document whose key will not unwrap has no name, no type and no digest —
    // they are all inside the one blob — so there is nothing to decide a mode
    // from and nothing to verify a preview against.
    renderDetail(makeDocument({ meta: null }));

    expect(frame()).toBeNull();
    expect(screen.getByTestId('document-undecodable')).toBeInTheDocument();
    expect(harness.readDocumentPlaintext).not.toHaveBeenCalled();
    // And still no download, because the key that opens the blob is the key the
    // segments are sealed under.
    expect(screen.queryByRole('button', { name: /download/i })).toBeNull();
  });
});

/* ========================================================================== */
/*  The chrome, and where it is drawn                                          */
/* ========================================================================== */

describe('DocumentDetail — the chrome around the frame', () => {
  it('draws the title and the download button OUTSIDE the frame', async () => {
    renderDetail(makeDocument());
    await waitFor(() => {
      expect(frame()).not.toBeNull();
    });

    const iframe = frame()!;
    const heading = screen.getByRole('heading', { level: 2, name: 'notes.md' });
    const download = screen.getByRole('button', { name: /download/i });

    // The assertion is CONTAINMENT, in the direction that matters: a renderer
    // that could draw the document's name or a button labelled "Download" could
    // draw a different name and a different destination.
    expect(iframe.contains(heading)).toBe(false);
    expect(iframe.contains(download)).toBe(false);
    expect(iframe.children).toHaveLength(0);
  });

  it('shows that it is decrypting and verifying rather than an empty panel', async () => {
    let release: (value: { meta: DocumentMeta; bytes: Uint8Array }) => void = () => undefined;
    harness.readDocumentPlaintext.mockReturnValue(
      new Promise<{ meta: DocumentMeta; bytes: Uint8Array }>((resolve) => {
        release = resolve;
      }),
    );

    renderDetail(makeDocument());
    expect(screen.getByRole('status')).toHaveTextContent(/decrypting and verifying/i);
    expect(frame()).toBeNull();

    await act(async () => {
      release({ meta: makeMeta(), bytes: new Uint8Array([0x23]) });
      await Promise.resolve();
    });
    await waitFor(() => {
      expect(frame()).not.toBeNull();
    });
  });

  it('degrades to the download affordance when the read fails', async () => {
    harness.readDocumentPlaintext.mockRejectedValue(new Error('segment 2 did not verify'));

    renderDetail(makeDocument());

    await waitFor(() => {
      expect(screen.getByTestId('document-download-to-view')).toHaveTextContent(
        /segment 2 did not verify/,
      );
    });
    expect(frame()).toBeNull();
    // The download button is still there: the panel that failed is a preview,
    // not the file.
    expect(screen.getByRole('button', { name: /download/i })).toBeInTheDocument();
  });

  it('degrades to the download affordance when the frame never handshakes', async () => {
    // A CSP or CORS mistake makes the frame blank with no error anyone can read,
    // so the host times out and reports it. An empty rectangle that never
    // resolves is the one outcome that is never acceptable.
    //
    // The clock is frozen rather than merely faked (`shouldAdvanceTime` is NOT
    // set) and the pending read is flushed by hand rather than through
    // `waitFor`. Both are deliberate: `waitFor` advances a faked clock itself
    // while it polls, which would fire the very timer under test at a moment
    // this test did not choose — a pass that depends on how long the polling
    // loop happened to take is not a pass.
    vi.useFakeTimers();
    try {
      renderDetail(makeDocument());
      // Drain the read promise so the frame mounts and the host arms its timer.
      await act(async () => {
        await Promise.resolve();
        await Promise.resolve();
      });

      expect(frame()).not.toBeNull();
      // Exactly one pending timer: the host's give-up deadline. Asserted rather
      // than assumed, because a component that armed none would otherwise let
      // this test pass by advancing a clock nobody was waiting on.
      expect(vi.getTimerCount()).toBe(1);

      // `advanceTimersByTimeAsync`, not the synchronous form: the give-up path
      // runs React state updates, and the async variant drains the microtask
      // queue between timers so those updates land inside this `act`.
      await act(async () => {
        await vi.advanceTimersByTimeAsync(11_000);
      });

      expect(frame()).toBeNull();
      expect(screen.getByTestId('document-download-to-view')).toHaveTextContent(
        /did not load|download the file instead/i,
      );
      // And the download button is still offered, because what failed is the
      // preview and not the file.
      expect(screen.getByRole('button', { name: /download/i })).toBeInTheDocument();
    } finally {
      vi.runOnlyPendingTimers();
      vi.useRealTimers();
    }
  });

  it('does not carry one document’s failure banner to the next', async () => {
    // `DocumentPage` renders this component WITHOUT a `key`, so React reuses the
    // instance across a detail-to-detail navigation. Without an explicit reset,
    // the previous document's "could not be opened" banner — and, worse, a link
    // dialog still offering the previous document's destination — would follow
    // the reader to the next file, which reads as a fault in a document that is
    // perfectly fine.
    harness.readDocumentPlaintext.mockRejectedValueOnce(new Error('segment 2 did not verify'));
    const view = renderDetail(makeDocument());
    await waitFor(() => {
      expect(screen.getByTestId('document-download-to-view')).toHaveTextContent(
        /segment 2 did not verify/,
      );
    });

    harness.readDocumentPlaintext.mockResolvedValue({
      meta: makeMeta({ name: 'other.md' }),
      bytes: new Uint8Array(new TextEncoder().encode('# Other')),
    });
    view.rerender(
      <MemoryRouter initialEntries={['/documents/other']}>
        <Routes>
          <Route
            path="/documents/:id"
            element={
              <DocumentDetail
                document={makeDocument({
                  id: '66c0f1a2b3c4d5e6f7a8b9c1',
                  meta: makeMeta({ name: 'other.md' }),
                })}
                isTrashed={false}
              />
            }
          />
        </Routes>
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(frame()).not.toBeNull();
    });
    expect(screen.queryByTestId('document-download-to-view')).toBeNull();
  });

  it('does not re-read the whole document when only its name changed', async () => {
    // A rename re-seals the small metadata blob and touches no stored byte, but
    // `updateDocumentMeta` builds a fresh `meta` OBJECT — so a read keyed on that
    // object would download and decrypt up to 25 MiB again for a field the
    // preview does not even read.
    const view = renderDetail(makeDocument());
    await waitFor(() => {
      expect(frame()).not.toBeNull();
    });
    expect(harness.readDocumentPlaintext).toHaveBeenCalledTimes(1);

    view.rerender(
      <MemoryRouter initialEntries={[`/documents/${DOC_ID}`]}>
        <Routes>
          <Route
            path="/documents/:id"
            element={
              <DocumentDetail
                document={makeDocument({ meta: makeMeta({ name: 'renamed.md' }) })}
                isTrashed={false}
              />
            }
          />
        </Routes>
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: 'renamed.md' })).toBeInTheDocument();
    });
    expect(harness.readDocumentPlaintext).toHaveBeenCalledTimes(1);
  });

  it('gives a second document a NEW iframe element', async () => {
    const view = renderDetail(makeDocument());
    await waitFor(() => {
      expect(frame()).not.toBeNull();
    });
    const first = frame();

    harness.readDocumentPlaintext.mockResolvedValue({
      meta: makeMeta({ name: 'other.md' }),
      bytes: new Uint8Array(new TextEncoder().encode('# Other')),
    });
    view.rerender(
      <MemoryRouter initialEntries={['/documents/other']}>
        <Routes>
          <Route
            path="/documents/:id"
            element={
              <DocumentDetail
                document={makeDocument({
                  id: '66c0f1a2b3c4d5e6f7a8b9c1',
                  meta: makeMeta({ name: 'other.md' }),
                })}
                isTrashed={false}
              />
            }
          />
        </Routes>
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(frame()).not.toBeNull();
      // ELEMENT IDENTITY, so one document can never observe the next: a reused
      // element would keep the previous document's live port.
      expect(frame()).not.toBe(first);
    });
  });
});

/* ========================================================================== */
/*  The link-confirmation dialog                                               */
/* ========================================================================== */

/**
 * Complete the host's handshake the way a real frame would, and return the
 * frame's end of the channel.
 *
 * The stub is what makes this possible at all: jsdom never loads an iframe's
 * `src`, so `contentWindow` is a real about:blank window that will never run
 * the sandbox — and a `MessageEvent` constructed in a test cannot name a
 * cross-document window as its `source`, which is exactly the identity the
 * host compares against.
 */
function handshake(): MessagePort {
  const iframe = frame()!;
  const stub = { postMessage: vi.fn() };
  Object.defineProperty(iframe, 'contentWindow', { configurable: true, get: () => stub });

  const event = new MessageEvent('message', { data: { kind: 'ready' }, origin: 'null' });
  Object.defineProperty(event, 'source', { configurable: true, get: () => stub });
  act(() => {
    window.dispatchEvent(event);
  });

  const port = stub.postMessage.mock.calls[0]?.[2]?.[0] as MessagePort | undefined;
  expect(port, 'the host transferred no port').toBeDefined();
  return port!;
}

/**
 * A known-good link, posted BEHIND the one under test.
 *
 * `MessagePort` delivery is asynchronous and FIFO. A test that posted one
 * message and then slept would be asserting on whatever had happened by an
 * arbitrary deadline — which is a flake, and it was one here before this
 * helper existed. Posting a second, valid link and waiting for ITS dialog is a
 * deterministic proof that the first was delivered and processed, which is
 * what turns "no dialog yet" into "no dialog, ever".
 */
const TRAILER = 'https://trailer.example/after';

/** The destination the trailer's own dialog shows. */
const TRAILER_DESTINATION = 'https://trailer.example';

/**
 * Posts `href`, which must be REFUSED, and then the trailer, and waits for the
 * TRAILER'S dialog.
 *
 * Waiting for any dialog would not do: had `href` opened one, it would be
 * replaced by the trailer's a moment later, and a check made after that would
 * pass. So every destination the dialog shows while the two are processed is
 * recorded as it appears, and the one thing ever shown must be the trailer's.
 */
async function postAndSettle(port: MessagePort, href: string): Promise<void> {
  const shown = new Set<string>();
  const record = (): void => {
    const origin = document.querySelector('[data-testid="document-link-origin"]');
    if (origin?.textContent) shown.add(origin.textContent);
  };
  const observer = new MutationObserver(record);
  observer.observe(document.body, { childList: true, subtree: true, characterData: true });
  try {
    // Each message gets an event-loop turn of its own before the next is posted.
    // Posted together, both arrive in one task and React renders only the last
    // state, so a dialog `href` did open would never reach the page at all and
    // this helper could not see it. Two `setImmediate` turns, because a port's
    // messages are delivered in the poll phase and one turn may land before it.
    await act(async () => {
      port.postMessage({ kind: 'link', href });
      await new Promise<void>((resolve) => setImmediate(resolve));
      await new Promise<void>((resolve) => setImmediate(resolve));
    });
    await act(async () => {
      port.postMessage({ kind: 'link', href: TRAILER });
      await Promise.resolve();
    });
    await waitFor(() => {
      expect(screen.getByTestId('document-link-origin').textContent).toBe(TRAILER_DESTINATION);
    });
  } finally {
    observer.disconnect();
  }
  record();
  expect([...shown]).toEqual([TRAILER_DESTINATION]);
}

/** Posts a link the host must OFFER, and waits for its dialog to show where it goes. */
async function openLinkDialog(port: MessagePort, href: string, destination: string): Promise<void> {
  await act(async () => {
    port.postMessage({ kind: 'link', href });
    await Promise.resolve();
  });
  await waitFor(() => {
    expect(screen.getByTestId('document-link-origin').textContent).toBe(destination);
  });
}

describe('DocumentDetail — a link clicked inside the frame', () => {
  beforeEach(async () => {
    renderDetail(makeDocument());
    await waitFor(() => {
      expect(frame()).not.toBeNull();
    });
    // The iframe ELEMENT exists as soon as React commits, but the effect that
    // registers the host's window listener is a PASSIVE one and runs afterwards.
    // Handshaking against a host that is not listening yet is a race — measured
    // here as an intermittent "the host transferred no port" — so the pending
    // passive effects are flushed before any test speaks to the frame.
    await act(async () => {
      await Promise.resolve();
    });
  });

  it('asks before opening, and shows the destination’s ORIGIN prominently', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    const port = handshake();
    const href = 'https://example.com/a/very/long/path?with=query#and-a-fragment';

    await act(async () => {
      port.postMessage({ kind: 'link', href });
      await Promise.resolve();
    });
    await waitFor(() => {
      expect(screen.getByTestId('document-link-origin')).toBeInTheDocument();
    });

    // Nothing has been opened. The dialog is the whole point.
    expect(open).not.toHaveBeenCalled();
    // The ORIGIN alone, on its own line, because a long path with a lookalike
    // host buried in it is the oldest trick there is and reading the whole URL
    // as one string is exactly how someone misses it.
    expect(screen.getByTestId('document-link-origin').textContent).toBe('https://example.com');

    fireEvent.click(screen.getByRole('button', { name: /open link/i }));
    expect(open).toHaveBeenCalledWith(href, '_blank', 'noopener,noreferrer');
    open.mockRestore();
  });

  it('opens nothing when the reader cancels', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    const port = handshake();

    await act(async () => {
      port.postMessage({ kind: 'link', href: 'https://example.com/' });
      await Promise.resolve();
    });
    await waitFor(() => {
      expect(screen.getByTestId('document-link-origin')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    await waitFor(() => {
      expect(screen.queryByTestId('document-link-origin')).toBeNull();
    });
    expect(open).not.toHaveBeenCalled();
    open.mockRestore();
  });

  it('opens nothing and shows no dialog for a javascript: href', async () => {
    // The entire compromise in one message: a `javascript:` URL opened by the
    // application runs in the application's origin, with the vault key in it.
    // It is refused at the MESSAGE BOUNDARY, before any dialog and before it
    // reaches this presentation layer at all.
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    await postAndSettle(handshake(), 'javascript:window.__pwned=1');

    // The trailer's dialog is showing, which proves the hostile href ahead of it
    // was delivered and answered with nothing.
    expect(screen.getByTestId('document-link-origin').textContent).toBe('https://trailer.example');
    expect(open).not.toHaveBeenCalled();
    open.mockRestore();
  });

  it('opens nothing and shows no dialog for a data: href', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    await postAndSettle(handshake(), 'data:text/html,<script>1</script>');
    expect(screen.getByTestId('document-link-origin').textContent).toBe('https://trailer.example');
    expect(open).not.toHaveBeenCalled();
    open.mockRestore();
  });

  it('opens nothing and shows no dialog for a blob: href', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    await postAndSettle(handshake(), 'blob:https://example.com/abc');
    expect(screen.getByTestId('document-link-origin').textContent).toBe('https://trailer.example');
    expect(open).not.toHaveBeenCalled();
    open.mockRestore();
  });

  it('offers nothing for a destination that will not parse, so its raw text is never shown', async () => {
    // `isSafeUrl` is a PREFIX test, so the bare string `https://` passes it and
    // then throws in `new URL()`. This dialog used to show such a string raw,
    // and a compromised frame could therefore put any sentence it liked in the
    // application's own dialog. A string that does not parse is not a link: it
    // is refused at the message boundary, before any dialog exists.
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    await postAndSettle(handshake(), 'https://');
    // The trailer's dialog is the one showing, so the unparseable href ahead of it
    // was delivered and answered with nothing.
    expect(screen.getByTestId('document-link-origin').textContent).toBe('https://trailer.example');
    expect(open).not.toHaveBeenCalled();
    open.mockRestore();
  });

  it('shows the parsed address, never the string the frame sent', async () => {
    // A space and a text-reversing control well inside the part of the address
    // that is shown: the dialog must carry the parser's encoding of both, and
    // neither raw character.
    const port = handshake();
    await act(async () => {
      port.postMessage({ kind: 'link', href: 'https://example.com/re-enter password\u202Etxt' });
      await Promise.resolve();
    });
    await waitFor(() => {
      expect(screen.getByTestId('document-link-origin')).toHaveTextContent('https://example.com');
    });
    expect(screen.getByTestId('document-link-address').textContent).toBe(
      'https://example.com/re-enter%20password%E2%80%AEtxt',
    );
    expect(screen.queryByText(/re-enter password/)).toBeNull();
  });

  it.each([
    [200, 'in full', false],
    [201, 'cut to 200 characters', true],
  ])('shows an address of %i characters %s', async (length, _label, cut) => {
    // `https://example.com/` is 20 characters; the path makes up the rest.
    const href = `https://example.com/${'a'.repeat(length - 20)}`;
    const port = handshake();
    await act(async () => {
      port.postMessage({ kind: 'link', href });
      await Promise.resolve();
    });
    await waitFor(() => {
      expect(screen.getByTestId('document-link-origin')).toHaveTextContent('https://example.com');
    });
    const address = screen.getByTestId('document-link-address').textContent ?? '';
    expect(address).toBe(cut ? `${href.slice(0, 199)}\u2026` : href);
    expect(address).toHaveLength(200);
  });

  it('closes on Escape without opening anything', async () => {
    // The dialog's own dismissal path, which is not the Cancel button: Escape
    // and an overlay click both arrive through `onOpenChange(false)`. A
    // confirmation a reader cannot back out of with Escape is a trap.
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    const port = handshake();
    await act(async () => {
      port.postMessage({ kind: 'link', href: 'https://example.com/' });
      await Promise.resolve();
    });
    await waitFor(() => {
      expect(screen.getByTestId('document-link-origin')).toBeInTheDocument();
    });

    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() => {
      expect(screen.queryByTestId('document-link-origin')).toBeNull();
    });
    expect(open).not.toHaveBeenCalled();
    open.mockRestore();
  });

  it('shows a mailto address rather than the string "null" as its origin', async () => {
    // `new URL('mailto:a@b').origin` is literally `"null"`, which is the one
    // thing a confirmation dialog must never show where the destination goes.
    const port = handshake();
    await act(async () => {
      port.postMessage({ kind: 'link', href: 'mailto:someone@example.com' });
      await Promise.resolve();
    });
    await waitFor(() => {
      expect(screen.getByTestId('document-link-origin')).toHaveTextContent(
        'mailto:someone@example.com',
      );
    });
  });
});

/* ========================================================================== */
/*  Full screen                                                                */
/* ========================================================================== */

describe('DocumentDetail — full screen', () => {
  const section = (): HTMLElement => screen.getByTestId('document-content');
  const toggle = (): HTMLElement => screen.getByRole('button', { name: /full screen/i });

  async function renderExpandable() {
    renderDetail(makeDocument());
    await waitFor(() => {
      expect(frame()).not.toBeNull();
    });
    // The same flush the link describe's `beforeEach` performs, and for the same
    // reason: the iframe ELEMENT is in the DOM as soon as React commits, but the
    // effect that registers the host's window listener is a PASSIVE one, and the
    // commit that mounts the frame happens when the plaintext read resolves —
    // outside `act` — so its passive effects are still queued when `waitFor`
    // first sees the element. Four tests below handshake against the host, and
    // without this they were speaking to a window nothing was listening on.
    //
    // It presents as `handshake`'s "the host transferred no port": the listener
    // has not been registered, so the ready message is dropped and no channel is
    // posted, while the frame is plainly there. It only shows up when this file
    // runs inside the whole suite, because the in-file shuffle order is drawn
    // from a run-wide seeded sequence and so differs from the order this file
    // takes on its own — which is what made it look like an anecdote rather than
    // the race it is.
    await act(async () => {
      await Promise.resolve();
    });
  }

  afterEach(() => {
    _resetScrollLockCount();
  });

  it('keeps the very same frame element, and re-reads nothing, across the toggle', async () => {
    await renderExpandable();
    const before = frame();
    expect(harness.readDocumentPlaintext).toHaveBeenCalledTimes(1);

    fireEvent.click(toggle());
    // THE regression this feature could most easily introduce. A portal, a
    // wrapper element that exists in only one branch, or two `<section>` branches
    // would each move the iframe in the React tree — detaching it, discarding its
    // browsing context, restarting the ten-second handshake and re-posting the
    // whole verified plaintext.
    expect(frame()).toBe(before);
    expect(harness.readDocumentPlaintext).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: /exit full screen/i }));
    expect(frame()).toBe(before);
    expect(harness.readDocumentPlaintext).toHaveBeenCalledTimes(1);
  });

  it('keeps the live channel open, so the frame can still speak after expanding', async () => {
    await renderExpandable();
    const port = handshake();

    fireEvent.click(toggle());

    // The stronger form of the case above: a remount would have taken the port
    // with it, and this message would reach nothing at all. Posted directly
    // rather than through `postAndSettle`, whose trailing message exists to prove
    // a NEGATIVE and would be the one on screen at the end.
    await act(async () => {
      port.postMessage({ kind: 'link', href: 'https://example.com/after-expanding' });
      await Promise.resolve();
    });
    await waitFor(() => {
      expect(screen.getByTestId('document-link-origin')).toHaveTextContent('https://example.com');
    });
  });

  it('fills the viewport and claims a dialog only while expanded', async () => {
    await renderExpandable();

    expect(section().className).toContain('rounded-lg');
    expect(section()).not.toHaveAttribute('role');
    expect(frame()!.className).toContain('h-[70vh]');

    fireEvent.click(toggle());

    expect(section().className).toContain('fixed');
    expect(section().className).toContain('inset-0');
    expect(section().className).not.toContain('rounded-lg');
    expect(section()).toHaveAttribute('role', 'dialog');
    expect(section()).toHaveAttribute('aria-modal', 'true');
    // `min-h-0` defeats a flex item's default `min-height: auto`, which an
    // iframe's intrinsic 150px would otherwise use to push the box open.
    expect(frame()!.className).toContain('flex-1');
    expect(frame()!.className).toContain('min-h-0');
    expect(frame()!.className).not.toContain('h-[70vh]');

    fireEvent.click(screen.getByRole('button', { name: /exit full screen/i }));
    expect(section()).not.toHaveAttribute('role');
    expect(frame()!.className).toContain('h-[70vh]');
  });

  it('names the dialog after the document, from the application’s own DOM', async () => {
    await renderExpandable();
    fireEvent.click(toggle());

    // The accessible name of a full-screen surface hosting an untrusted document
    // must come from the application, never from anything the document rendered.
    expect(section()).toHaveAttribute('aria-labelledby', 'document-open-heading');
    expect(screen.getByRole('dialog')).toHaveAccessibleName('notes.md');
  });

  it('puts focus on the way out, and leaves it there on the way back', async () => {
    await renderExpandable();
    fireEvent.click(toggle());

    // `useInlineDialog` focuses the FIRST focusable element in the panel, so the
    // toggle has to be the first control in the header. Moving it after Download
    // is a one-line reorder that this is the only thing to catch.
    await waitFor(() => {
      expect(document.activeElement).toBe(
        screen.getByRole('button', { name: /exit full screen/i }),
      );
    });

    const exitButton = screen.getByRole('button', { name: /exit full screen/i });
    fireEvent.click(exitButton);
    // The same DOM node in both states, so no focus restoration is needed.
    expect(document.activeElement).toBe(screen.getByRole('button', { name: /^full screen$/i }));
  });

  it('collapses on Escape, and locks then releases the body scroll', async () => {
    await renderExpandable();
    fireEvent.click(toggle());
    expect(document.body.style.overflow).toBe('hidden');

    fireEvent.keyDown(document, { key: 'Escape' });

    expect(section()).not.toHaveAttribute('role');
    expect(document.body.style.overflow).toBe('');
  });

  it('releases the scroll lock when the view goes away while still expanded', async () => {
    await renderExpandable();
    fireEvent.click(toggle());
    expect(document.body.style.overflow).toBe('hidden');

    cleanup();
    // A lock swaps this whole subtree out; a lock counter left held would freeze
    // scrolling on the unlock screen with nothing on screen to explain it.
    expect(document.body.style.overflow).toBe('');
  });

  it('stops claiming modality while a dialog is open above it', async () => {
    await renderExpandable();
    const port = handshake();
    fireEvent.click(toggle());
    expect(section()).toHaveAttribute('aria-modal', 'true');

    await openLinkDialog(port, 'https://example.com/somewhere', 'https://example.com');

    // `Dialog` portals to <body>, OUTSIDE this section, and `aria-modal="true"`
    // declares everything outside its container inert — so leaving it on would
    // tell a screen reader to ignore the very confirmation the link-safety design
    // rests on. The ROLE stays; only the modality is dropped.
    expect(section()).toHaveAttribute('role', 'dialog');
    expect(section()).not.toHaveAttribute('aria-modal');

    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() => {
      expect(section()).toHaveAttribute('aria-modal', 'true');
    });
  });

  it('gives Escape to a dialog opened on top, and only then to the panel', async () => {
    await renderExpandable();
    const port = handshake();
    fireEvent.click(toggle());
    await openLinkDialog(port, 'https://example.com/somewhere', 'https://example.com');
    expect(screen.getByTestId('document-link-origin')).toBeInTheDocument();

    fireEvent.keyDown(document, { key: 'Escape' });

    // Both listeners are on `document` and neither stops propagation, so without
    // the guard this ONE keypress closes the dialog and collapses the panel
    // underneath it — leaving the reader two steps back from where they were.
    await waitFor(() => {
      expect(screen.queryByTestId('document-link-origin')).not.toBeInTheDocument();
    });
    expect(section()).toHaveAttribute('role', 'dialog');

    fireEvent.keyDown(document, { key: 'Escape' });
    expect(section()).not.toHaveAttribute('role');
  });

  it('offers no toggle for a document it is not going to draw', async () => {
    // A PDF is download-only by decision, so there is no frame to enlarge and a
    // control that filled the screen with one paragraph would be worse than none.
    renderDetail(makeDocument({ meta: makeMeta({ name: 'handbook.pdf', ext: 'pdf' }) }));
    await screen.findByTestId('document-download-to-view');
    expect(screen.queryByRole('button', { name: /full screen/i })).not.toBeInTheDocument();
  });

  it('drops out of full screen when the frame it was showing dies', async () => {
    await renderExpandable();
    fireEvent.click(toggle());
    expect(section()).toHaveAttribute('role', 'dialog');

    // A renderer that reports failure. Stored rather than derived, `expanded`
    // would leave the refusal paragraph stranded on a full-viewport canvas.
    const port = handshake();
    await act(async () => {
      port.postMessage({ kind: 'failed', code: 'renderFailed' });
      await Promise.resolve();
    });

    await waitFor(() => {
      expect(screen.getByTestId('document-download-to-view')).toBeInTheDocument();
    });
    expect(section()).not.toHaveAttribute('role');
    expect(document.body.style.overflow).toBe('');
  });

  it('puts the APPLICATION’s sentence beside the Download button, never the frame’s', async () => {
    // The chrome this whole design protects: the refusal paragraph sits next to
    // the real Download button, in the application's voice. A frame that could
    // choose its words could ask for the master password right there.
    await renderExpandable();
    const port = handshake();
    await act(async () => {
      port.postMessage({
        kind: 'failed',
        code: 'renderFailed',
        reason: 'Preview blocked. Re-enter your master password at https://evil.example',
      });
      await Promise.resolve();
    });

    const refusal = await screen.findByTestId('document-download-to-view');
    expect(refusal).toHaveTextContent(
      'The document could not be displayed. You can download the file instead.',
    );
    expect(document.body.textContent).not.toContain('master password');
    expect(screen.getByRole('button', { name: /^Download\b/ })).toBeInTheDocument();
  });

  it('does not carry full screen from one document to the next', async () => {
    const view = renderDetail(makeDocument());
    await waitFor(() => {
      expect(frame()).not.toBeNull();
    });
    fireEvent.click(toggle());
    expect(section()).toHaveAttribute('role', 'dialog');

    const next = makeDocument({ id: OTHER_ID, meta: makeMeta({ name: 'other.md' }) });
    view.rerender(
      <MemoryRouter initialEntries={[`/documents/${next.id}`]}>
        <Routes>
          <Route
            path="/documents/:id"
            element={<DocumentDetail document={next} isTrashed={false} />}
          />
        </Routes>
      </MemoryRouter>,
    );

    // The next file must not open filling the viewport without anyone asking —
    // over a spinner, at that, because its bytes have just been cleared.
    expect(screen.getByTestId('document-content')).not.toHaveAttribute('role');

    // The rerender above starts a read of the SECOND document, which lands its
    // plaintext in a `.then` after this body has finished and outside `act(...)`.
    // Settled rather than left to fall outside, which React reports and which is
    // the shape that lets an assertion read a DOM one render behind. The frame is
    // waited for so the settle covers the whole read rather than one tick of it.
    await waitFor(() => {
      expect(frame()).not.toBeNull();
    });
  });
});
