/**
 * The document detail route and its view.
 *
 * ## How this suite is wired, and why
 *
 * The STORE is real. `useDocumentsStore` is imported as it ships and each test
 * replaces the one or two ACTIONS it wants to observe through `setState` —
 * zustand keeps actions in the state tree, so that is a seam the store already
 * has rather than one this suite invents. What it buys is that the view reads
 * the real `DecryptedDocument`, with its real `meta: null` degradation, rather
 * than a hand-rolled shape that would drift.
 *
 * The one collaborator that IS replaced is `saveDocument`. Reading a document
 * back is cryptography over a network, it has its own suite
 * (`tests/documents-download.test.ts`) which drives the real thing end to end,
 * and what belongs HERE is the chrome around it: which control is offered, what
 * the user is told, and what is torn down when the page goes away. The error
 * TYPES are imported for real through `importOriginal`, because the view's rule
 * that a cancellation is not a failure turns on `instanceof`.
 *
 * ## The negative this suite exists to hold
 *
 * Phase 16 ships no renderer of any kind. A stored document is arbitrary input
 * and this origin holds the unlocked vault key, so the view must not put a
 * document's bytes — or anything derived from them — into the page. There is a
 * test below that asserts the rendered tree contains no element capable of
 * fetching or rendering content, and another that a name and a note full of
 * markup arrive as text. Both go red the moment somebody adds a preview here
 * instead of inside the isolated document that Phase 18 builds.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup, act } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';
import React from 'react';
import {
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  MAX_DOCUMENT_META_JSON_BYTES,
  MAX_DOCUMENT_TAGS,
  MAX_TAG_LENGTH,
  documentMetaJsonByteLength,
} from '@hvault/shared';
import type { DocumentMeta, DocumentResponse } from '@hvault/shared';

/* -------------------------------------------------------------------------- */
/*  Hoisted mock state                                                         */
/* -------------------------------------------------------------------------- */

const harness = vi.hoisted(() => ({
  toast: vi.fn(),
  getDocumentsConfig: vi.fn(),
  saveDocument: vi.fn(),
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

vi.mock('../../src/services/api/configApi', () => ({
  getDocumentsConfig: harness.getDocumentsConfig,
}));

vi.mock('../../src/components/ui/Toast', () => ({
  useToast: () => ({ toast: harness.toast, dismiss: vi.fn(), update: vi.fn() }),
  ToastProvider: ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
  Toaster: () => null,
}));

// Only `saveDocument`. The error classes stay real, because the view's
// "a cancellation is not a failure" rule is an `instanceof` check.
vi.mock('../../src/services/documents/download', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/services/documents/download')>()),
  saveDocument: harness.saveDocument,
}));

/* -------------------------------------------------------------------------- */
/*  Imports (after the mocks)                                                  */
/* -------------------------------------------------------------------------- */

import {
  DocumentDownloadCancelledError,
  DocumentIntegrityError,
} from '../../src/services/documents/download';
import { useDocumentsStore, type DecryptedDocument } from '../../src/stores/documentsStore';
import { useVaultStore } from '../../src/stores/vaultStore';
import { DocumentDetail } from '../../src/components/documents/DocumentDetail';
import DocumentPage from '../../src/pages/DocumentPage';
import type { DocumentsConfig } from '../../src/services/api/configApi';

/* -------------------------------------------------------------------------- */
/*  Fixtures                                                                   */
/* -------------------------------------------------------------------------- */

const DOC_ID = '66c0f1a2b3c4d5e6f7a8b9c0';

const pristineDocuments = useDocumentsStore.getState();
const pristineVault = useVaultStore.getState();

const ENABLED_CONFIG: DocumentsConfig = {
  enabled: true,
  maxSizeMB: 100,
  chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  maxDocuments: 5000,
  quotaMB: 2048,
  allowedExtensions: [],
};

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
    name: 'report.pdf',
    mime: 'application/pdf',
    ext: 'pdf',
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

function makeFolder(overrides: Partial<{ id: string; name: string }> = {}) {
  return {
    id: overrides.id ?? 'folder-1',
    name: overrides.name ?? 'Taxes',
    sortOrder: 0,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    _raw: {} as never,
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

function renderPage(id = DOC_ID) {
  return render(
    <MemoryRouter initialEntries={[`/documents/${id}`]}>
      <Routes>
        <Route path="/documents/:id" element={<DocumentPage />} />
        <Route path="/documents" element={<div data-testid="documents-list-route" />} />
      </Routes>
    </MemoryRouter>,
  );
}

/** Open the edit dialog on a document that can be edited. */
function openEditor(): void {
  fireEvent.click(screen.getByRole('button', { name: /edit details/i }));
}

beforeEach(() => {
  vi.clearAllMocks();
  harness.getDocumentsConfig.mockResolvedValue(ENABLED_CONFIG);
  harness.saveDocument.mockResolvedValue('report.pdf');
  useDocumentsStore.setState(pristineDocuments, true);
  useVaultStore.setState(pristineVault, true);
});

afterEach(() => {
  cleanup();
});

/* ========================================================================== */
/*  What the view shows                                                        */
/* ========================================================================== */

describe('DocumentDetail — what a document says about itself', () => {
  it('shows the decrypted name, type, size, tags, note and the sealed checksum', () => {
    renderDetail(
      makeDocument({
        meta: makeMeta({
          name: 'quarterly.pdf',
          tags: ['finance', 'q4'],
          note: 'Signed copy',
          sha256: 'b'.repeat(64),
        }),
      }),
    );

    expect(screen.getByRole('heading', { level: 1, name: 'quarterly.pdf' })).toBeInTheDocument();
    expect(screen.getByText('application/pdf')).toBeInTheDocument();
    expect(screen.getAllByText('2 KB').length).toBeGreaterThan(0);
    expect(screen.getByText('finance')).toBeInTheDocument();
    expect(screen.getByText('q4')).toBeInTheDocument();
    expect(screen.getByText('Signed copy')).toBeInTheDocument();
    expect(screen.getByText('b'.repeat(64))).toBeInTheDocument();
  });

  it('says "Unknown" rather than nothing for a file whose type the browser never learned', () => {
    renderDetail(makeDocument({ meta: makeMeta({ mime: '' }) }));

    expect(screen.getByText('Unknown')).toBeInTheDocument();
  });

  it('offers download-to-view, with the reason, for every document that opens', () => {
    renderDetail(makeDocument());

    const panel = screen.getByTestId('document-download-to-view');
    expect(panel).toHaveTextContent(/does not open a document inside the app/i);
    expect(screen.getByRole('button', { name: /download/i })).toBeInTheDocument();
  });
});

/* ========================================================================== */
/*  The isolation invariant                                                    */
/* ========================================================================== */

describe('DocumentDetail — no document content is rendered in this origin', () => {
  it('renders no element that could fetch or display a document', () => {
    const { container } = renderDetail(
      makeDocument({ meta: makeMeta({ name: 'photo.png', mime: 'image/png' }) }),
    );

    // Phase 16 ships no renderer. A preview belongs inside the isolated document
    // of Phase 18, whose opaque origin holds no key; one added HERE would run a
    // parser beside the unlocked vault key, which is the single thing this
    // feature's design exists to prevent.
    expect(container.querySelectorAll('iframe, embed, object, video, audio, img')).toHaveLength(0);
  });

  it('renders a name and a note that contain markup as text, never as markup', () => {
    const hostile = '<img src=x onerror="alert(1)"><script>alert(2)</script>';
    const { container } = renderDetail(
      makeDocument({ meta: makeMeta({ name: hostile, note: hostile, tags: [hostile] }) }),
    );

    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('img')).toBeNull();
    // Present, and present as characters: the string a user can read is the
    // string that was stored.
    expect(screen.getAllByText(hostile).length).toBeGreaterThan(0);
  });
});

/* ========================================================================== */
/*  Download                                                                   */
/* ========================================================================== */

describe('DocumentDetail — downloading', () => {
  it('asks for the document by id and metadata, and names the file it saved', async () => {
    const document = makeDocument();
    harness.saveDocument.mockResolvedValue('report (1).pdf');
    renderDetail(document);

    fireEvent.click(screen.getByRole('button', { name: /download/i }));

    await waitFor(() => {
      expect(harness.toast).toHaveBeenCalledWith({
        title: 'Saved as report (1).pdf',
        type: 'success',
      });
    });
    expect(harness.saveDocument).toHaveBeenCalledWith(
      { id: document.id, meta: document.meta },
      { signal: expect.any(AbortSignal) },
    );
  });

  it('reports a verification failure differently from any other failure', async () => {
    harness.saveDocument.mockRejectedValue(
      new DocumentIntegrityError('digest', 'the checksum did not match'),
    );
    renderDetail(makeDocument());

    fireEvent.click(screen.getByRole('button', { name: /download/i }));

    await waitFor(() => {
      expect(harness.toast).toHaveBeenCalledWith({
        title: 'This document did not verify',
        description: 'the checksum did not match',
        type: 'error',
      });
    });
  });

  it('reports an ordinary failure as a failed download', async () => {
    harness.saveDocument.mockRejectedValue(new Error('the connection dropped'));
    renderDetail(makeDocument());

    fireEvent.click(screen.getByRole('button', { name: /download/i }));

    await waitFor(() => {
      expect(harness.toast).toHaveBeenCalledWith({
        title: 'The download failed',
        description: 'the connection dropped',
        type: 'error',
      });
    });
  });

  it('says nothing at all when the save dialog was dismissed or the vault locked', async () => {
    harness.saveDocument.mockRejectedValue(new DocumentDownloadCancelledError());
    renderDetail(makeDocument());

    fireEvent.click(screen.getByRole('button', { name: /download/i }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /download/i })).not.toBeDisabled();
    });
    // The whole point: a user who cancelled is not told their download broke.
    expect(harness.toast).not.toHaveBeenCalled();
  });

  it('aborts a download in flight when the view goes away', async () => {
    let captured: AbortSignal | undefined;
    harness.saveDocument.mockImplementation(
      (_document: unknown, options: { signal: AbortSignal }) => {
        captured = options.signal;
        return new Promise<string>(() => undefined);
      },
    );
    const { unmount } = renderDetail(makeDocument());

    fireEvent.click(screen.getByRole('button', { name: /download/i }));
    await waitFor(() => {
      expect(captured).toBeDefined();
    });
    expect(captured?.aborted).toBe(false);

    // A lock swaps this whole subtree out for the unlock screen, so unmounting
    // is how a lock reaches a download in progress. Without this the decryption
    // would run to completion and put a file on disk after the vault closed.
    unmount();

    expect(captured?.aborted).toBe(true);
  });
});

/* ========================================================================== */
/*  Editing the metadata                                                       */
/* ========================================================================== */

describe('DocumentDetail — editing name, tags and note', () => {
  it('re-seals the metadata with the edited values, sending no other field', async () => {
    const updateDocumentMeta = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ updateDocumentMeta });
    renderDetail(makeDocument({ meta: makeMeta({ tags: ['old'], note: 'was here' }) }));

    openEditor();
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'renamed.pdf' } });
    fireEvent.change(screen.getByLabelText('Tags'), { target: { value: ' a , b , a ' } });
    fireEvent.change(screen.getByLabelText('Note'), { target: { value: 'now this' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(updateDocumentMeta).toHaveBeenCalledWith(DOC_ID, {
        name: 'renamed.pdf',
        // Trimmed and de-duplicated, the way the shared schema stores a tag.
        tags: ['a', 'b'],
        note: 'now this',
      });
    });
    expect(harness.toast).toHaveBeenCalledWith({
      title: 'Document details updated',
      type: 'success',
    });
  });

  it('removes a note by sending null, which is what a cleared field has to mean', async () => {
    const updateDocumentMeta = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ updateDocumentMeta });
    renderDetail(makeDocument({ meta: makeMeta({ note: 'was here' }) }));

    openEditor();
    fireEvent.change(screen.getByLabelText('Note'), { target: { value: '   ' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(updateDocumentMeta).toHaveBeenCalledWith(DOC_ID, {
        name: 'report.pdf',
        tags: [],
        // `undefined` would leave the old note in place, which is the one way an
        // emptied field could silently keep its value.
        note: null,
      });
    });
  });

  it('refuses more tags than a document may carry, before anything is sealed', async () => {
    const updateDocumentMeta = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ updateDocumentMeta });
    renderDetail(makeDocument());

    openEditor();
    const tooMany = Array.from({ length: MAX_DOCUMENT_TAGS + 1 }, (_, i) => `t${String(i)}`);
    fireEvent.change(screen.getByLabelText('Tags'), { target: { value: tooMany.join(',') } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    expect(await screen.findByTestId('document-edit-refusal')).toHaveTextContent(
      `at most ${String(MAX_DOCUMENT_TAGS)} tags`,
    );
    expect(updateDocumentMeta).not.toHaveBeenCalled();
  });

  it('refuses a tag longer than a tag may be, naming the one that is', async () => {
    const updateDocumentMeta = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ updateDocumentMeta });
    renderDetail(makeDocument());

    openEditor();
    const overlong = 'x'.repeat(MAX_TAG_LENGTH + 1);
    fireEvent.change(screen.getByLabelText('Tags'), { target: { value: `fine, ${overlong}` } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    const refusal = await screen.findByTestId('document-edit-refusal');
    expect(refusal).toHaveTextContent(`at most ${String(MAX_TAG_LENGTH)} characters`);
    // Names the offending tag, so a user with twenty of them does not have to
    // find it themselves.
    expect(refusal).toHaveTextContent(overlong);
    expect(updateDocumentMeta).not.toHaveBeenCalled();
  });

  it('refuses an empty name rather than storing a document nobody can find', async () => {
    const updateDocumentMeta = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ updateDocumentMeta });
    renderDetail(makeDocument());

    openEditor();
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: '   ' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    expect(await screen.findByTestId('document-edit-refusal')).toHaveTextContent(
      'A document needs a name',
    );
    expect(updateDocumentMeta).not.toHaveBeenCalled();
  });

  it('does not charge the byte budget for a note the save is about to remove', async () => {
    const updateDocumentMeta = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ updateDocumentMeta });
    // A stored note that is small in CHARACTERS and enormous in BYTES, because
    // `JSON.stringify` escapes a control character to six ASCII bytes — the one
    // case `MAX_DOCUMENT_META_JSON_BYTES` is deliberately not provisioned for,
    // and therefore the only one where a stale note actually breaks the budget.
    const heavy = '\u0001'.repeat(7_000);
    expect(documentMetaJsonByteLength({ note: heavy })).toBeGreaterThan(
      MAX_DOCUMENT_META_JSON_BYTES,
    );
    renderDetail(makeDocument({ meta: makeMeta({ note: heavy }) }));

    openEditor();
    fireEvent.change(screen.getByLabelText('Note'), { target: { value: '' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    // The pre-flight has to measure the object that will be SEALED, not the one
    // it started from: the store removes the note, so charging the budget for it
    // would refuse a save that fits, with the words "Shorten the note" beside an
    // empty note field.
    await waitFor(() => {
      expect(updateDocumentMeta).toHaveBeenCalledWith(DOC_ID, {
        name: 'report.pdf',
        tags: [],
        note: null,
      });
    });
    expect(screen.queryByTestId('document-edit-refusal')).not.toBeInTheDocument();
  });

  it('still refuses when the note the save WILL store is over the byte budget', async () => {
    const updateDocumentMeta = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ updateDocumentMeta });
    renderDetail(makeDocument());

    openEditor();
    fireEvent.change(screen.getByLabelText('Note'), {
      target: { value: '\u0001'.repeat(7_000) },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    expect(await screen.findByTestId('document-edit-refusal')).toHaveTextContent('once encoded');
    expect(updateDocumentMeta).not.toHaveBeenCalled();
  });

  it('closes the editor without writing when the edit is cancelled', async () => {
    const updateDocumentMeta = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ updateDocumentMeta });
    renderDetail(makeDocument());

    openEditor();
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'discarded.pdf' } });
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
    expect(updateDocumentMeta).not.toHaveBeenCalled();
  });

  it('keeps the dialog open and shows why when the store refuses the write', async () => {
    const updateDocumentMeta = vi.fn().mockRejectedValue(new Error('rotation in progress'));
    useDocumentsStore.setState({ updateDocumentMeta });
    renderDetail(makeDocument());

    openEditor();
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    expect(await screen.findByTestId('document-edit-refusal')).toHaveTextContent(
      'rotation in progress',
    );
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });
});

/* ========================================================================== */
/*  Organising                                                                 */
/* ========================================================================== */

describe('DocumentDetail — favorite, folder and trash', () => {
  it('toggles the favorite flag without touching anything encrypted', async () => {
    const setFavorite = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ setFavorite });
    renderDetail(makeDocument());

    fireEvent.click(screen.getByRole('button', { name: /favorite/i }));

    await waitFor(() => {
      expect(setFavorite).toHaveBeenCalledWith(DOC_ID, true);
    });
  });

  it('reports a failed favorite toggle instead of showing it as done', async () => {
    const setFavorite = vi.fn().mockRejectedValue(new Error('the vault is rotating'));
    useDocumentsStore.setState({ setFavorite });
    renderDetail(makeDocument());

    fireEvent.click(screen.getByRole('button', { name: /favorite/i }));

    await waitFor(() => {
      expect(harness.toast).toHaveBeenCalledWith({
        title: 'the vault is rotating',
        type: 'error',
      });
    });
  });

  it('moves the document into a folder, and back out of one', async () => {
    const moveToFolder = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ moveToFolder });
    useVaultStore.setState({ folders: [makeFolder()] });
    renderDetail(makeDocument({ folderId: 'folder-1' }));

    fireEvent.click(screen.getByRole('button', { name: /move to folder/i }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'No folder' }));

    await waitFor(() => {
      expect(moveToFolder).toHaveBeenCalledWith(DOC_ID, null);
    });
  });

  it('closes the folder menu on Escape and on a click elsewhere, without moving anything', async () => {
    const moveToFolder = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ moveToFolder });
    useVaultStore.setState({ folders: [makeFolder()] });
    renderDetail(makeDocument());

    const trigger = screen.getByRole('button', { name: /move to folder/i });

    fireEvent.click(trigger);
    expect(screen.getByRole('menuitem', { name: 'Taxes' })).toBeInTheDocument();
    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() => {
      expect(screen.queryByRole('menuitem', { name: 'Taxes' })).not.toBeInTheDocument();
    });

    fireEvent.click(trigger);
    expect(screen.getByRole('menuitem', { name: 'Taxes' })).toBeInTheDocument();
    // `role="menu"` promises that a click elsewhere dismisses it. A hand-rolled
    // div carrying the role and no listener announces a menu and then behaves
    // like a list of buttons that never closes.
    fireEvent.mouseDown(document.body);
    await waitFor(() => {
      expect(screen.queryByRole('menuitem', { name: 'Taxes' })).not.toBeInTheDocument();
    });

    expect(moveToFolder).not.toHaveBeenCalled();
  });

  it('moves an unfiled document into a folder', async () => {
    const moveToFolder = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ moveToFolder });
    useVaultStore.setState({ folders: [makeFolder()] });
    renderDetail(makeDocument());

    fireEvent.click(screen.getByRole('button', { name: /move to folder/i }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Taxes' }));

    await waitFor(() => {
      expect(moveToFolder).toHaveBeenCalledWith(DOC_ID, 'folder-1');
    });
  });

  it('sends an active document to the trash and returns to the list', async () => {
    const deleteDocument = vi.fn().mockResolvedValue(undefined);
    const purgeDocument = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ deleteDocument, purgeDocument });
    renderDetail(makeDocument());

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    fireEvent.click(screen.getByRole('button', { name: 'Move to trash' }));

    await waitFor(() => {
      expect(screen.getByTestId('documents-list-route')).toBeInTheDocument();
    });
    expect(deleteDocument).toHaveBeenCalledWith(DOC_ID);
    // The trash is recoverable; nothing was destroyed.
    expect(purgeDocument).not.toHaveBeenCalled();
  });

  it('reports a failed move rather than leaving the menu looking successful', async () => {
    const moveToFolder = vi.fn().mockRejectedValue(new Error('that folder is gone'));
    useDocumentsStore.setState({ moveToFolder });
    renderDetail(makeDocument());

    fireEvent.click(screen.getByRole('button', { name: /move to folder/i }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'No folder' }));

    await waitFor(() => {
      expect(harness.toast).toHaveBeenCalledWith({ title: 'that folder is gone', type: 'error' });
    });
  });

  it('closes the delete dialog without deleting when it is cancelled', async () => {
    const deleteDocument = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ deleteDocument });
    renderDetail(makeDocument());

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
    expect(deleteDocument).not.toHaveBeenCalled();
    expect(screen.queryByTestId('documents-list-route')).not.toBeInTheDocument();
  });

  it('stays on the page and says so when a delete fails', async () => {
    const deleteDocument = vi.fn().mockRejectedValue(new Error('storage is unavailable'));
    useDocumentsStore.setState({ deleteDocument });
    renderDetail(makeDocument());

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    fireEvent.click(screen.getByRole('button', { name: 'Move to trash' }));

    await waitFor(() => {
      expect(harness.toast).toHaveBeenCalledWith({
        title: 'storage is unavailable',
        type: 'error',
      });
    });
    expect(screen.queryByTestId('documents-list-route')).not.toBeInTheDocument();
  });
});

describe('DocumentDetail — a document in the trash', () => {
  it('offers restore and permanent deletion, and neither edit nor move', () => {
    renderDetail(makeDocument(), true);

    expect(screen.getByRole('button', { name: /restore/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /delete forever/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /edit details/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^favorite$/i })).not.toBeInTheDocument();
    expect(screen.getByTestId('document-trashed-note')).toHaveTextContent(
      /still occupies storage/i,
    );
  });

  it('can still be downloaded, which is the only way to get the file back out', () => {
    renderDetail(makeDocument(), true);

    expect(screen.getByTestId('document-download-to-view')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /download/i })).toBeInTheDocument();
  });

  it('restores the document and returns to the list', async () => {
    const restoreDocument = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ restoreDocument });
    renderDetail(makeDocument(), true);

    fireEvent.click(screen.getByRole('button', { name: /restore/i }));

    await waitFor(() => {
      expect(screen.getByTestId('documents-list-route')).toBeInTheDocument();
    });
    expect(restoreDocument).toHaveBeenCalledWith(DOC_ID);
  });

  it('destroys the document permanently, and says the key goes with it', async () => {
    const purgeDocument = vi.fn().mockResolvedValue(undefined);
    const deleteDocument = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ purgeDocument, deleteDocument });
    renderDetail(makeDocument(), true);

    fireEvent.click(screen.getByRole('button', { name: /delete forever/i }));
    expect(screen.getByRole('dialog')).toHaveTextContent(/only copy of the key/i);
    fireEvent.click(screen.getByRole('button', { name: 'Delete forever' }));

    await waitFor(() => {
      expect(purgeDocument).toHaveBeenCalledWith(DOC_ID);
    });
    expect(deleteDocument).not.toHaveBeenCalled();
  });

  it('reports a failed restore rather than pretending it worked', async () => {
    const restoreDocument = vi.fn().mockRejectedValue(new Error('quota exceeded'));
    useDocumentsStore.setState({ restoreDocument });
    renderDetail(makeDocument(), true);

    fireEvent.click(screen.getByRole('button', { name: /restore/i }));

    await waitFor(() => {
      expect(harness.toast).toHaveBeenCalledWith({ title: 'quota exceeded', type: 'error' });
    });
    expect(screen.queryByTestId('documents-list-route')).not.toBeInTheDocument();
  });
});

/* ========================================================================== */
/*  The degraded document                                                      */
/* ========================================================================== */

describe('DocumentDetail — a document this vault key cannot open', () => {
  it('explains the state in an alert and names what is still possible', () => {
    renderDetail(makeDocument({ meta: null }));

    const notice = screen.getByTestId('document-undecodable');
    expect(notice).toHaveAttribute('role', 'alert');
    expect(notice).toHaveTextContent(/cannot be renamed, edited or downloaded/i);
    expect(notice).toHaveTextContent(/move it to another folder/i);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Unopenable document');
  });

  it('offers no download at all, because the key that opens the blob seals the segments', () => {
    renderDetail(makeDocument({ meta: null }));

    expect(screen.queryByTestId('document-download-to-view')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /download/i })).not.toBeInTheDocument();
    expect(harness.saveDocument).not.toHaveBeenCalled();
  });

  it('leaves Edit focusable but inert, describing itself with the alert', () => {
    const updateDocumentMeta = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ updateDocumentMeta });
    renderDetail(makeDocument({ meta: null }));

    const edit = screen.getByRole('button', { name: /edit details/i });
    // `aria-disabled`, never `disabled`: a `disabled` control leaves the tab
    // order, so the people who most need the explanation could not reach the
    // control that points at it.
    expect(edit).toHaveAttribute('aria-disabled', 'true');
    expect(edit).not.toBeDisabled();
    const describedBy = edit.getAttribute('aria-describedby');
    expect(describedBy).not.toBeNull();
    expect(document.getElementById(describedBy!)).toHaveTextContent(/cannot be renamed/i);

    fireEvent.click(edit);

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(updateDocumentMeta).not.toHaveBeenCalled();
  });

  it('offers no separate rename control, because a document has no name outside the blob', () => {
    renderDetail(makeDocument({ meta: null }));

    expect(screen.queryByRole('button', { name: /^rename$/i })).not.toBeInTheDocument();
  });

  it('still moves, favorites and deletes, which is how a user gets rid of one', async () => {
    const setFavorite = vi.fn().mockResolvedValue(undefined);
    const deleteDocument = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ setFavorite, deleteDocument });
    renderDetail(makeDocument({ meta: null }));

    fireEvent.click(screen.getByRole('button', { name: /favorite/i }));
    await waitFor(() => {
      expect(setFavorite).toHaveBeenCalledWith(DOC_ID, true);
    });

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    fireEvent.click(screen.getByRole('button', { name: 'Move to trash' }));
    await waitFor(() => {
      expect(deleteDocument).toHaveBeenCalledWith(DOC_ID);
    });
  });
});

/* ========================================================================== */
/*  The route                                                                  */
/* ========================================================================== */

describe('DocumentPage — the feature flag decides before anything is fetched', () => {
  it('fetches nothing while the server has not answered', () => {
    const fetchDocuments = vi.fn().mockResolvedValue(undefined);
    const fetchTrash = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ fetchDocuments, fetchTrash });
    harness.getDocumentsConfig.mockReturnValue(new Promise<DocumentsConfig>(() => undefined));

    renderPage();

    expect(screen.getByRole('status', { name: 'Loading' })).toBeInTheDocument();
    expect(fetchDocuments).not.toHaveBeenCalled();
    expect(fetchTrash).not.toHaveBeenCalled();
  });

  it('says the feature is unavailable, and asks for nothing, on a server without storage', async () => {
    const fetchDocuments = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ fetchDocuments });
    harness.getDocumentsConfig.mockResolvedValue({ enabled: false });

    renderPage();

    expect(await screen.findByTestId('documents-unavailable')).toBeInTheDocument();
    expect(fetchDocuments).not.toHaveBeenCalled();
  });
});

describe('DocumentPage — finding the document', () => {
  it('sends a request with no id back to the list rather than rendering nothing', async () => {
    const fetchDocuments = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ fetchDocuments });

    render(
      <MemoryRouter initialEntries={['/mounted-without-an-id']}>
        <Routes>
          <Route path="/mounted-without-an-id" element={<DocumentPage />} />
          <Route path="/documents" element={<div data-testid="documents-list-route" />} />
        </Routes>
      </MemoryRouter>,
    );

    // The route that mounts this page always supplies an `:id`, so this guards a
    // future caller rather than a reachable URL — but a guard that rendered
    // nothing would be a blank page, so what it does is pinned. And it reads
    // nothing: an effect runs whatever the render returned, so without the same
    // check in the effect a mount with no id would decrypt both whole lists on
    // its way to the redirect.
    await waitFor(() => {
      expect(screen.getByTestId('documents-list-route')).toBeInTheDocument();
    });
    expect(fetchDocuments).not.toHaveBeenCalled();
  });

  it('renders a document the store already holds without reading the list again', async () => {
    const fetchDocuments = vi.fn().mockResolvedValue(undefined);
    const fetchTrash = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({
      fetchDocuments,
      fetchTrash,
      documents: [makeDocument({ meta: makeMeta({ name: 'already-here.pdf' }) })],
    });

    renderPage();

    expect(
      await screen.findByRole('heading', { level: 1, name: 'already-here.pdf' }),
    ).toBeInTheDocument();
    // Opening the list is a decrypt of every row the account holds; repeating it
    // for each document a user opens would be that work over again.
    expect(fetchDocuments).not.toHaveBeenCalled();
    expect(fetchTrash).not.toHaveBeenCalled();
  });

  it('reads both lists when the document was reached by URL', async () => {
    const fetchDocuments = vi.fn().mockResolvedValue(undefined);
    const fetchTrash = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ fetchDocuments, fetchTrash });

    renderPage();

    await waitFor(() => {
      expect(fetchDocuments).toHaveBeenCalledTimes(1);
    });
    // The trash too: a trashed document has no other list to be found in, and
    // nothing in this application has loaded it yet.
    expect(fetchTrash).toHaveBeenCalledTimes(1);
  });

  it('renders a trashed document as trashed', async () => {
    useDocumentsStore.setState({
      fetchDocuments: vi.fn().mockResolvedValue(undefined),
      fetchTrash: vi.fn().mockResolvedValue(undefined),
      trashDocuments: [makeDocument()],
    });

    renderPage();

    expect(await screen.findByTestId('document-trashed-note')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /delete forever/i })).toBeInTheDocument();
  });

  it('says the document was not found once both reads have settled', async () => {
    useDocumentsStore.setState({
      fetchDocuments: vi.fn().mockResolvedValue(undefined),
      fetchTrash: vi.fn().mockResolvedValue(undefined),
    });

    renderPage();

    expect(await screen.findByTestId('document-not-found')).toBeInTheDocument();
  });

  it('shows a spinner rather than "not found" while a read is still running', async () => {
    useDocumentsStore.setState({
      fetchDocuments: vi.fn().mockResolvedValue(undefined),
      fetchTrash: vi.fn().mockResolvedValue(undefined),
      documentsLoading: true,
    });

    renderPage();

    await waitFor(() => {
      expect(screen.getByRole('status', { name: 'Loading' })).toBeInTheDocument();
    });
    // The one reading a user must never be given when the truth is "still
    // loading".
    expect(screen.queryByTestId('document-not-found')).not.toBeInTheDocument();
  });

  it('reports a failed read on the page instead of as an empty account', async () => {
    useDocumentsStore.setState({
      fetchDocuments: vi.fn().mockRejectedValue(new Error('storage is unavailable')),
      fetchTrash: vi.fn().mockResolvedValue(undefined),
    });

    renderPage();

    const error = await screen.findByTestId('document-load-error');
    expect(error).toHaveAttribute('role', 'alert');
    expect(error).toHaveTextContent('storage is unavailable');
    expect(screen.queryByTestId('document-not-found')).not.toBeInTheDocument();
  });

  it('loads the folder names the move menu needs, once', async () => {
    const fetchFolders = vi.fn().mockResolvedValue(undefined);
    useVaultStore.setState({ fetchFolders, folders: [] });
    useDocumentsStore.setState({
      fetchDocuments: vi.fn().mockResolvedValue(undefined),
      fetchTrash: vi.fn().mockResolvedValue(undefined),
      documents: [makeDocument()],
    });

    renderPage();

    await waitFor(() => {
      expect(fetchFolders).toHaveBeenCalledTimes(1);
    });
  });

  it('does not re-read folders it already has', async () => {
    const fetchFolders = vi.fn().mockResolvedValue(undefined);
    useVaultStore.setState({ fetchFolders, folders: [makeFolder()] });
    useDocumentsStore.setState({
      fetchDocuments: vi.fn().mockResolvedValue(undefined),
      fetchTrash: vi.fn().mockResolvedValue(undefined),
      documents: [makeDocument()],
    });

    renderPage();

    await act(async () => {
      await Promise.resolve();
    });
    expect(fetchFolders).not.toHaveBeenCalled();
  });

  it('survives a folder read that fails, because a missing menu is not a broken page', async () => {
    const fetchFolders = vi.fn().mockRejectedValue(new Error('offline'));
    useVaultStore.setState({ fetchFolders, folders: [] });
    useDocumentsStore.setState({
      fetchDocuments: vi.fn().mockResolvedValue(undefined),
      fetchTrash: vi.fn().mockResolvedValue(undefined),
      documents: [makeDocument()],
    });

    renderPage();

    expect(
      await screen.findByRole('heading', { level: 1, name: 'report.pdf' }),
    ).toBeInTheDocument();
    await waitFor(() => {
      expect(fetchFolders).toHaveBeenCalled();
    });
    expect(screen.queryByTestId('document-load-error')).not.toBeInTheDocument();
  });
});
