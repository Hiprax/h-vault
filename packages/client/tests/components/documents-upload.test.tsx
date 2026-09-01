/**
 * The Documents page, its list and its upload panel.
 *
 * ## How this suite is wired, and why
 *
 * The STORE is real. `useDocumentsStore` is imported as it ships, and each test
 * replaces the one or two ACTIONS it wants to observe through `setState` —
 * zustand keeps actions in the state tree, so that is a seam the store already
 * has rather than one this suite invents. What it buys is that everything the UI
 * reads is the real shape: the real `uploads` registry with its three statuses
 * and no `completed`, the real `DecryptedDocument` with its `meta: null`
 * degradation, and the real `UploadCancelledError` whose identity the panel's
 * "do not report a cancellation as a failure" rule turns on. A hand-rolled fake
 * store would have let every one of those drift.
 *
 * What is mocked is only what a component test has no business running: the
 * public-config request, the profile request behind `useUserSettings`, the
 * `/health` poll behind `useConnectionStatus`, the toast surface, and
 * `react-window` — which measures a viewport jsdom does not have, so without the
 * stand-in the virtualized branch renders nothing and an assertion about its ARIA
 * attributes would pass over an empty tree.
 *
 * The transfer machinery below the store is never reached: no test here calls a
 * real `startUpload`, so no part is sealed and no request is made. That path has
 * its own suite (`documents-store.test.ts`), which drives it through a stub
 * transport with the real crypto in place.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import React from 'react';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES } from '@hvault/shared';
import type { DocumentResponse, DocumentUsageResponse } from '@hvault/shared';

/* -------------------------------------------------------------------------- */
/*  Hoisted mock state                                                         */
/* -------------------------------------------------------------------------- */

const harness = vi.hoisted(() => ({
  toast: vi.fn(),
  getDocumentsConfig: vi.fn(),
  isOnline: true,
  settings: {
    autoLockTimeout: 15,
    lockOnHidden: false,
    lockOnHiddenDelay: 1,
    clipboardClearTimeout: 30,
    theme: 'system',
  },
  /**
   * Extra rows the `react-window` stand-in renders past the end of the array.
   *
   * Zero for every test but one. A virtualized list can genuinely ask for an
   * index the data no longer has — a row is removed while a window is being
   * painted — and the row component answers `null` rather than throwing. That
   * guard has no other way to be reached from a test.
   */
  extraVirtualRows: 0,
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

vi.mock('../../src/hooks/useUserSettings', () => ({
  useUserSettings: () => harness.settings,
}));

vi.mock('../../src/hooks/useConnectionStatus', () => ({
  useConnectionStatus: () => ({ isOnline: harness.isOnline }),
}));

vi.mock('../../src/components/ui/Toast', () => ({
  useToast: () => ({ toast: harness.toast, dismiss: vi.fn(), update: vi.fn() }),
  ToastProvider: ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
  Toaster: () => null,
}));

vi.mock('react-window', () => ({
  List: ({
    rowComponent: Row,
    rowCount,
    rowProps,
    role,
    'aria-label': ariaLabel,
  }: {
    rowComponent: React.ComponentType<Record<string, unknown>>;
    rowCount: number;
    rowProps: Record<string, unknown>;
    role?: string;
    'aria-label'?: string;
  }) =>
    React.createElement(
      'div',
      { role, 'aria-label': ariaLabel },
      Array.from({ length: rowCount + harness.extraVirtualRows }, (_, index) =>
        React.createElement(Row, {
          key: index,
          index,
          style: {},
          ariaAttributes: {
            role: 'listitem',
            'aria-posinset': index + 1,
            'aria-setsize': rowCount,
          },
          ...rowProps,
        }),
      ),
    ),
}));

/* -------------------------------------------------------------------------- */
/*  Imports (after the mocks)                                                  */
/* -------------------------------------------------------------------------- */

import {
  UploadCancelledError,
  useDocumentsStore,
  type DecryptedDocument,
  type DocumentUploadProgress,
} from '../../src/stores/documentsStore';
import { useUploadUnloadGuard } from '../../src/hooks/useUploadUnloadGuard';
import DocumentsPage from '../../src/pages/DocumentsPage';
import { DocumentList } from '../../src/components/documents/DocumentList';
import { DocumentUploadPanel } from '../../src/components/documents/DocumentUploadPanel';
import type { DocumentsConfig } from '../../src/services/api/configApi';

/* -------------------------------------------------------------------------- */
/*  Fixtures                                                                   */
/* -------------------------------------------------------------------------- */

const pristineState = useDocumentsStore.getState();

const ENABLED_CONFIG: DocumentsConfig = {
  enabled: true,
  maxSizeMB: 100,
  chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  maxDocuments: 5000,
  quotaMB: 2048,
  allowedExtensions: [],
};

/**
 * A row in the shape the API sends, with readable ids.
 *
 * Written out in full rather than cast from `{}`: nothing in THIS phase reads
 * `_raw`, but a fixture that lies about its type stops being harmless the moment
 * something does, and a reader cannot tell a deliberately empty stub from an
 * oversight. The sizes and the framing satisfy `documentResponseSchema`'s
 * refinements (one chunk, and `plaintextBytes === ciphertextBytes - 16`), and the
 * two base64 fields decode to the exact 32 and 7 bytes it requires.
 *
 * The one field that would NOT survive that schema is `_id`, which is
 * 24 characters of hex on the wire and a readable `doc-1` here — deliberately,
 * because these ids appear in the rendered links the tests assert on and nothing
 * in this suite parses a row.
 */
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

function makeDocument(overrides: Partial<DecryptedDocument> = {}): DecryptedDocument {
  const id = overrides.id ?? 'doc-1';
  return {
    id,
    favorite: false,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-02-03T00:00:00.000Z',
    meta: {
      name: 'report.pdf',
      mime: 'application/pdf',
      ext: 'pdf',
      plaintextBytes: 2048,
      sha256: '0'.repeat(64),
      chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      chunkCount: 1,
      tags: [],
      capturedAt: '2026-01-01T00:00:00.000Z',
    },
    _raw: makeRawDocument(id),
    ...overrides,
  };
}

function makeUpload(overrides: Partial<DocumentUploadProgress> = {}): DocumentUploadProgress {
  return {
    id: 'up-1',
    fileName: 'holiday.zip',
    totalBytes: 1000,
    sentBytes: 0,
    status: 'uploading',
    ...overrides,
  };
}

function makeUsage(overrides: Partial<DocumentUsageResponse> = {}): DocumentUsageResponse {
  return {
    documentCount: 3,
    usedBytes: 512 * 1024 * 1024,
    quotaBytes: 2048 * 1024 * 1024,
    maxDocumentSizeBytes: 100 * 1024 * 1024,
    ...overrides,
  };
}

/**
 * A `File` that records every attempt to READ it.
 *
 * The guardrails' whole claim is that a refused file is never opened, and the
 * only honest way to assert that is on the handle itself: a spy on the store's
 * `startUpload` proves the transfer did not start, but not that nothing read the
 * bytes on the way to deciding. `size` is redefined rather than filled with real
 * bytes so a "300 MB" file costs nothing.
 */
function makeFile(name: string, size: number, type = 'application/pdf') {
  const file = new File([new Uint8Array(1)], name, { type });
  Object.defineProperty(file, 'size', { value: size });
  const reads: string[] = [];
  for (const method of ['slice', 'arrayBuffer', 'stream', 'text'] as const) {
    const original = Reflect.get(file, method) as (...args: unknown[]) => unknown;
    Object.defineProperty(file, method, {
      value: (...args: unknown[]) => {
        reads.push(method);
        return original.apply(file, args);
      },
    });
  }
  return { file, reads };
}

function renderPage() {
  return render(
    <MemoryRouter>
      <DocumentsPage />
    </MemoryRouter>,
  );
}

function renderPanel(config: DocumentsConfig = ENABLED_CONFIG) {
  return render(
    <MemoryRouter>
      <DocumentUploadPanel config={config} />
    </MemoryRouter>,
  );
}

function pick(name: string, size: number, type?: string): string[] {
  const { file, reads } = makeFile(name, size, type);
  fireEvent.change(screen.getByLabelText('File to upload'), { target: { files: [file] } });
  return reads;
}

beforeEach(() => {
  vi.clearAllMocks();
  harness.isOnline = true;
  harness.extraVirtualRows = 0;
  harness.settings = {
    autoLockTimeout: 15,
    lockOnHidden: false,
    lockOnHiddenDelay: 1,
    clipboardClearTimeout: 30,
    theme: 'system',
  };
  harness.getDocumentsConfig.mockResolvedValue(ENABLED_CONFIG);
  useDocumentsStore.setState(pristineState, true);
});

afterEach(() => {
  cleanup();
});

/* ========================================================================== */
/*  DocumentsPage — the three top-level states                                 */
/* ========================================================================== */

describe('DocumentsPage — the feature flag decides before anything is fetched', () => {
  it('shows a loading state, and fetches nothing, while the server has not answered', () => {
    const fetchDocuments = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({
      fetchDocuments,
      fetchUsage: vi.fn().mockResolvedValue(undefined),
    });
    harness.getDocumentsConfig.mockReturnValue(new Promise<DocumentsConfig>(() => undefined));

    renderPage();

    expect(screen.getByRole('status', { name: 'Loading' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Documents' })).not.toBeInTheDocument();
    expect(fetchDocuments).not.toHaveBeenCalled();
  });

  it('explains that the feature is unavailable, without asking the server for a list', async () => {
    const fetchDocuments = vi.fn().mockResolvedValue(undefined);
    const fetchUsage = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ fetchDocuments, fetchUsage });
    harness.getDocumentsConfig.mockResolvedValue({ enabled: false });

    renderPage();

    expect(await screen.findByTestId('documents-unavailable')).toHaveTextContent(
      /not available on this server/i,
    );
    expect(fetchDocuments).not.toHaveBeenCalled();
    expect(fetchUsage).not.toHaveBeenCalled();
    expect(screen.queryByLabelText('File to upload')).not.toBeInTheDocument();
  });

  it('loads the list and the usage once the feature is advertised as available', async () => {
    const fetchDocuments = vi.fn().mockResolvedValue(undefined);
    const fetchUsage = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ fetchDocuments, fetchUsage });

    renderPage();

    expect(await screen.findByRole('heading', { name: 'Documents' })).toBeInTheDocument();
    expect(fetchDocuments).toHaveBeenCalledTimes(1);
    expect(fetchUsage).toHaveBeenCalledTimes(1);
    expect(screen.queryByTestId('documents-unavailable')).not.toBeInTheDocument();
    expect(screen.queryByTestId('documents-offline')).not.toBeInTheDocument();
  });
});

describe('DocumentsPage — the surrounding notices', () => {
  beforeEach(() => {
    useDocumentsStore.setState({
      fetchDocuments: vi.fn().mockResolvedValue(undefined),
      fetchUsage: vi.fn().mockResolvedValue(undefined),
    });
  });

  it('says documents are not cached offline when the server is unreachable', async () => {
    harness.isOnline = false;
    renderPage();
    expect(await screen.findByTestId('documents-offline')).toHaveTextContent(
      /not kept in the offline cache/i,
    );
  });

  it('reports the quota, the document count against the advertised ceiling, and the trash rule', async () => {
    useDocumentsStore.setState({ usage: makeUsage() });
    renderPage();

    const bar = await screen.findByRole('progressbar', { name: 'Document storage used' });
    expect(bar).toHaveAttribute('aria-valuenow', '25');
    expect(screen.getByText(/3 of 5000 documents/)).toBeInTheDocument();
    expect(screen.getByText(/still occupies storage/i)).toBeInTheDocument();
  });

  it('omits the ceiling when the server advertises none, and never draws past 100%', async () => {
    useDocumentsStore.setState({
      usage: makeUsage({ usedBytes: 4096 * 1024 * 1024, documentCount: 7 }),
    });
    harness.getDocumentsConfig.mockResolvedValue({ enabled: true, maxSizeMB: 100 });

    renderPage();

    const bar = await screen.findByRole('progressbar', { name: 'Document storage used' });
    expect(bar).toHaveAttribute('aria-valuenow', '100');
    expect(screen.getByText(/7 documents/)).toBeInTheDocument();
    expect(screen.queryByText(/of 5000 documents/)).not.toBeInTheDocument();
  });

  it('names the documents that could not be opened, and says they are still listed', async () => {
    useDocumentsStore.setState({ degradedCount: 2, invalidCount: 0 });
    renderPage();

    const notice = await screen.findByTestId('documents-degraded');
    expect(notice).toHaveTextContent(/2 document\(s\) could not be opened/);
    expect(notice).toHaveTextContent(/listed without their details/);
    expect(notice).not.toHaveTextContent(/left out of the list/);
  });

  it('names the rows that were rejected outright, separately from the degraded ones', async () => {
    useDocumentsStore.setState({ degradedCount: 0, invalidCount: 4 });
    renderPage();

    const notice = await screen.findByTestId('documents-degraded');
    expect(notice).toHaveTextContent(/4 row\(s\).*left out of the list entirely/);
    expect(notice).not.toHaveTextContent(/could not be opened/);
  });

  it('shows no notice at all when every row opened', async () => {
    renderPage();
    await screen.findByRole('heading', { name: 'Documents' });
    expect(screen.queryByTestId('documents-degraded')).not.toBeInTheDocument();
  });

  it('reports a failed load on the list itself, and retries it on demand', async () => {
    const fetchDocuments = vi.fn().mockRejectedValue(new Error('Storage is unreachable'));
    useDocumentsStore.setState({ fetchDocuments });

    renderPage();

    const error = await screen.findByTestId('documents-error');
    expect(error).toHaveTextContent('Storage is unreachable');
    // The failure must not be dressed as an empty account.
    expect(screen.queryByText('No documents yet')).not.toBeInTheDocument();

    fetchDocuments.mockResolvedValue(undefined);
    fireEvent.click(screen.getByRole('button', { name: /try again/i }));

    await waitFor(() => {
      expect(screen.queryByTestId('documents-error')).not.toBeInTheDocument();
    });
    expect(fetchDocuments).toHaveBeenCalledTimes(2);
  });

  it('re-reads the allowance when a transfer leaves the registry, so the bar cannot go stale', async () => {
    const fetchUsage = vi.fn().mockResolvedValue(undefined);
    useDocumentsStore.setState({ fetchUsage, usage: makeUsage(), uploads: {} });
    renderPage();
    await screen.findByRole('heading', { name: 'Documents' });
    expect(fetchUsage).toHaveBeenCalledTimes(1);

    act(() => {
      useDocumentsStore.setState({ uploads: { 'up-1': makeUpload() } });
    });
    // A transfer STARTING moves no bytes into storage, so it must not cost a read.
    expect(fetchUsage).toHaveBeenCalledTimes(1);

    act(() => {
      useDocumentsStore.setState({ uploads: {} });
    });
    // It either committed its bytes or released them; both move this number.
    await waitFor(() => {
      expect(fetchUsage).toHaveBeenCalledTimes(2);
    });
  });

  it('keeps the list usable when only the usage request fails', async () => {
    useDocumentsStore.setState({ fetchUsage: vi.fn().mockRejectedValue(new Error('no usage')) });

    renderPage();

    await screen.findByRole('heading', { name: 'Documents' });
    await waitFor(() => {
      expect(screen.queryByTestId('documents-error')).not.toBeInTheDocument();
    });
    expect(
      screen.queryByRole('progressbar', { name: 'Document storage used' }),
    ).not.toBeInTheDocument();
  });
});

/* ========================================================================== */
/*  DocumentList                                                               */
/* ========================================================================== */

describe('DocumentList — its four states', () => {
  function renderList(props: Partial<React.ComponentProps<typeof DocumentList>> = {}) {
    return render(
      <MemoryRouter>
        <DocumentList documents={[]} loading={false} error={null} onRetry={vi.fn()} {...props} />
      </MemoryRouter>,
    );
  }

  it('shows a skeleton while loading, and neither the empty state nor a row', () => {
    renderList({ loading: true, documents: [makeDocument()] });
    expect(screen.getByTestId('documents-skeleton')).toBeInTheDocument();
    expect(screen.queryByTestId('document-row')).not.toBeInTheDocument();
    expect(screen.queryByText('No documents yet')).not.toBeInTheDocument();
  });

  it('offers to try again when the load failed', () => {
    const onRetry = vi.fn();
    renderList({ error: 'The list could not be read.', onRetry });

    expect(screen.getByRole('alert')).toHaveTextContent('The list could not be read.');
    fireEvent.click(screen.getByRole('button', { name: /try again/i }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('invites a first upload when the account holds nothing', () => {
    renderList();
    expect(screen.getByText('No documents yet')).toBeInTheDocument();
    expect(screen.queryByRole('list')).not.toBeInTheDocument();
  });

  it('renders a plain list with the ARIA position of every row below the threshold', () => {
    const documents = [
      makeDocument({ id: 'a', meta: { ...makeDocument().meta!, name: 'alpha.md', ext: 'md' } }),
      makeDocument({ id: 'b', meta: { ...makeDocument().meta!, name: 'beta.png', ext: 'png' } }),
    ];
    renderList({ documents });

    expect(screen.getByRole('list', { name: 'Documents list' })).toBeInTheDocument();
    const rows = screen.getAllByRole('listitem');
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveAttribute('aria-posinset', '1');
    expect(rows[0]).toHaveAttribute('aria-setsize', '2');
    expect(rows[1]).toHaveAttribute('aria-posinset', '2');
    expect(screen.getByText('alpha.md')).toBeInTheDocument();
    expect(screen.getByText('MD')).toBeInTheDocument();
  });

  it('links each row to that document', () => {
    renderList({ documents: [makeDocument({ id: 'doc-42' })] });
    expect(screen.getByRole('link', { name: /report\.pdf/ })).toHaveAttribute(
      'href',
      '/documents/doc-42',
    );
  });

  it('labels a document with no extension rather than leaving the badge blank', () => {
    const base = makeDocument();
    renderList({
      documents: [makeDocument({ meta: { ...base.meta!, name: 'Dockerfile', ext: '' } })],
    });
    expect(screen.getByText('FILE')).toBeInTheDocument();
  });

  it('lists a document whose metadata would not open, without inventing a name or a size', () => {
    renderList({ documents: [makeDocument({ meta: null })] });

    expect(screen.getByText('Unopenable document')).toBeInTheDocument();
    expect(screen.getByText('Unopenable')).toBeInTheDocument();
    // 2 KB is the fixture's size: a degraded row must not report the size of the
    // metadata it could not read.
    expect(screen.queryByText('2 KB')).not.toBeInTheDocument();
  });

  it('marks a favorite row and leaves an ordinary one unmarked', () => {
    const { container } = renderList({
      documents: [makeDocument({ id: 'a', favorite: true }), makeDocument({ id: 'b' })],
    });
    expect(container.querySelectorAll('.fill-yellow-400')).toHaveLength(1);
  });

  it('virtualizes above the threshold, keeping the list semantics intact', () => {
    const documents = Array.from({ length: 60 }, (_, index) =>
      makeDocument({ id: `doc-${String(index)}` }),
    );
    renderList({ documents });

    expect(screen.getByRole('list', { name: 'Documents list' })).toBeInTheDocument();
    const rows = screen.getAllByRole('listitem');
    expect(rows).toHaveLength(60);
    expect(rows[59]).toHaveAttribute('aria-posinset', '60');
    expect(rows[59]).toHaveAttribute('aria-setsize', '60');
  });

  it('renders nothing for a virtualized index the data no longer has', () => {
    harness.extraVirtualRows = 1;
    const documents = Array.from({ length: 60 }, (_, index) =>
      makeDocument({ id: `doc-${String(index)}` }),
    );
    renderList({ documents });

    expect(screen.getAllByRole('listitem')).toHaveLength(60);
    expect(screen.getAllByTestId('document-row')).toHaveLength(60);
  });
});

/* ========================================================================== */
/*  DocumentUploadPanel — the guardrails                                       */
/* ========================================================================== */

describe('DocumentUploadPanel — guardrails applied before the file is read', () => {
  let startUpload = vi.fn().mockResolvedValue('up-1');

  beforeEach(() => {
    startUpload = vi.fn().mockResolvedValue('up-1');
    useDocumentsStore.setState({ startUpload });
  });

  it('refuses a file over the advertised cap, reading none of it', () => {
    renderPanel();
    const reads = pick('huge.pdf', 200 * 1024 * 1024);

    expect(screen.getByTestId('upload-refusal')).toHaveTextContent(
      /This server accepts documents up to 100 MB/,
    );
    expect(startUpload).not.toHaveBeenCalled();
    expect(reads).toEqual([]);
    expect(screen.queryByRole('button', { name: /^Upload$/ })).not.toBeInTheDocument();
  });

  it('refuses a file type the server asks not to receive, reading none of it', () => {
    renderPanel({ ...ENABLED_CONFIG, allowedExtensions: ['pdf', 'md'] });
    const reads = pick('archive.zip', 1024);

    expect(screen.getByTestId('upload-refusal')).toHaveTextContent(
      'This server asks for these file types only: pdf, md.',
    );
    expect(startUpload).not.toHaveBeenCalled();
    expect(reads).toEqual([]);
  });

  it('admits a listed type, and says the type list is applied by the browser alone', () => {
    renderPanel({ ...ENABLED_CONFIG, allowedExtensions: ['pdf', 'md'] });
    pick('notes.md', 1024, 'text/markdown');

    expect(screen.queryByTestId('upload-refusal')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Upload$/ })).toBeInTheDocument();
    expect(screen.getByTestId('upload-guardrail-note')).toHaveTextContent(
      /never learns a file's name/,
    );
  });

  it('admits any extension when the allowlist is empty, and mentions no type rule', () => {
    renderPanel();
    pick('archive.zip', 1024);

    expect(screen.queryByTestId('upload-refusal')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Upload$/ })).toBeInTheDocument();
    expect(screen.getByTestId('upload-guardrail-note')).not.toHaveTextContent(/file types/);
    expect(screen.getByTestId('upload-guardrail-note')).toHaveTextContent(/Up to 100 MB/);
  });

  it('applies no size rule of its own when the server advertises no cap', () => {
    renderPanel({ enabled: true });
    pick('huge.pdf', 900 * 1024 * 1024);

    expect(screen.queryByTestId('upload-refusal')).not.toBeInTheDocument();
    expect(screen.getByTestId('upload-guardrail-note')).not.toHaveTextContent(/Up to/);
    expect(screen.getByRole('button', { name: /^Upload$/ })).toBeInTheDocument();
  });

  it('clears the selection when the picker is dismissed without choosing a file', () => {
    renderPanel();
    pick('report.pdf', 4096);
    expect(screen.getByRole('button', { name: /^Upload$/ })).toBeInTheDocument();

    const input = screen.getByLabelText('File to upload');
    // Two shapes a browser produces for "nothing chosen": an empty list, and —
    // on an input that has never held a file — no list at all.
    fireEvent.change(input, { target: { files: [] } });
    expect(screen.queryByRole('button', { name: /^Upload$/ })).not.toBeInTheDocument();

    pick('report.pdf', 4096);
    Object.defineProperty(input, 'files', { value: null, configurable: true });
    fireEvent.change(input);
    expect(screen.queryByRole('button', { name: /^Upload$/ })).not.toBeInTheDocument();
    expect(screen.queryByTestId('upload-refusal')).not.toBeInTheDocument();
  });

  it('clears a refusal when the selection is emptied', () => {
    renderPanel();
    pick('huge.pdf', 200 * 1024 * 1024);
    expect(screen.getByTestId('upload-refusal')).toBeInTheDocument();

    fireEvent.drop(screen.getByTestId('document-dropzone'), { dataTransfer: { files: [] } });

    expect(screen.queryByTestId('upload-refusal')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Upload$/ })).not.toBeInTheDocument();
  });
});

describe('DocumentUploadPanel — drag and drop', () => {
  beforeEach(() => {
    useDocumentsStore.setState({ startUpload: vi.fn().mockResolvedValue('up-1') });
  });

  it('highlights the target while a file is over it and stops when it leaves', () => {
    renderPanel();
    const zone = screen.getByTestId('document-dropzone');

    fireEvent.dragOver(zone);
    expect(zone.className).toContain('border-[hsl(var(--primary))]');

    fireEvent.dragLeave(zone);
    expect(zone.className).not.toContain('border-[hsl(var(--primary))]');
  });

  it('selects a dropped file and runs the same guardrails on it', () => {
    renderPanel({ ...ENABLED_CONFIG, allowedExtensions: ['pdf'] });
    const zone = screen.getByTestId('document-dropzone');

    const { file: refused, reads } = makeFile('notes.txt', 10);
    fireEvent.drop(zone, { dataTransfer: { files: [refused] } });
    expect(screen.getByTestId('upload-refusal')).toBeInTheDocument();
    expect(reads).toEqual([]);
    expect(zone.className).not.toContain('border-[hsl(var(--primary))]');

    const { file: accepted } = makeFile('report.pdf', 10);
    fireEvent.drop(zone, { dataTransfer: { files: [accepted] } });
    expect(screen.queryByTestId('upload-refusal')).not.toBeInTheDocument();
    expect(screen.getByText('report.pdf (10 B)')).toBeInTheDocument();
  });
});

/* ========================================================================== */
/*  DocumentUploadPanel — starting, cancelling and retrying                    */
/* ========================================================================== */

describe('DocumentUploadPanel — starting a transfer', () => {
  it('hands the store the file itself, its name and its type, and clears the picker', async () => {
    const startUpload = vi.fn().mockResolvedValue('up-1');
    useDocumentsStore.setState({ startUpload });
    renderPanel();
    pick('report.pdf', 4096, 'application/pdf');

    fireEvent.click(screen.getByRole('button', { name: /^Upload$/ }));

    expect(startUpload).toHaveBeenCalledTimes(1);
    const [input] = startUpload.mock.calls[0] as [{ source: File; name: string; mime: string }];
    expect(input.name).toBe('report.pdf');
    expect(input.mime).toBe('application/pdf');
    expect(input.source.size).toBe(4096);
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /^Upload$/ })).not.toBeInTheDocument();
    });
  });

  it('reports a refusal that never became a transfer, because nothing else would', async () => {
    useDocumentsStore.setState({
      startUpload: vi.fn().mockRejectedValue(new Error('Storage quota exceeded')),
    });
    renderPanel();
    pick('report.pdf', 4096);

    fireEvent.click(screen.getByRole('button', { name: /^Upload$/ }));

    await waitFor(() => {
      expect(harness.toast).toHaveBeenCalledWith({
        title: 'Storage quota exceeded',
        type: 'error',
      });
    });
    // Nothing registered, so the notice is the only place it could be seen.
    expect(screen.queryByTestId('upload-row')).not.toBeInTheDocument();
  });

  it('still reports a failure while another transfer is registering, rather than inferring it was seen', async () => {
    // The shape this pins: a SECOND upload refused at initiation while a FIRST is
    // registering. A rule that decided "has this already been reported?" from
    // whether a new row had appeared would see the first upload's brand-new row,
    // conclude the second was on screen, and say nothing at all about a file that
    // went nowhere.
    useDocumentsStore.setState({
      startUpload: vi.fn().mockImplementation(() => {
        useDocumentsStore.setState({
          uploads: { 'up-other': makeUpload({ id: 'up-other', fileName: 'other.bin' }) },
        });
        return Promise.reject(new Error('Storage quota exceeded'));
      }),
    });
    renderPanel();
    pick('report.pdf', 4096);

    fireEvent.click(screen.getByRole('button', { name: /^Upload$/ }));

    await waitFor(() => {
      expect(harness.toast).toHaveBeenCalledWith({
        title: 'Storage quota exceeded',
        type: 'error',
      });
    });
    // Reported exactly once, and the other transfer is untouched: still listed,
    // still running.
    expect(harness.toast).toHaveBeenCalledTimes(1);
    expect(screen.getByText('other.bin')).toBeInTheDocument();
  });

  it('never reports a cancellation as a failure', async () => {
    useDocumentsStore.setState({
      startUpload: vi.fn().mockRejectedValue(new UploadCancelledError()),
    });
    renderPanel();
    pick('report.pdf', 4096);

    fireEvent.click(screen.getByRole('button', { name: /^Upload$/ }));

    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /^Upload$/ })).not.toBeInTheDocument();
    });
    expect(harness.toast).not.toHaveBeenCalled();
  });

  it('drops the selection on demand without starting anything', () => {
    const startUpload = vi.fn();
    useDocumentsStore.setState({ startUpload });
    renderPanel();
    pick('report.pdf', 4096);

    fireEvent.click(screen.getByRole('button', { name: 'Clear selected file' }));

    expect(screen.queryByRole('button', { name: /^Upload$/ })).not.toBeInTheDocument();
    expect(startUpload).not.toHaveBeenCalled();
  });
});

describe('DocumentUploadPanel — a transfer in progress', () => {
  it('names the part that is moving and advances as the parts land', () => {
    const totalBytes = DOCUMENT_PLAINTEXT_CHUNK_BYTES * 2 + 100;
    useDocumentsStore.setState({ uploads: { 'up-1': makeUpload({ totalBytes, sentBytes: 0 }) } });
    renderPanel();

    expect(screen.getByText(/Part 1 of 3/)).toBeInTheDocument();

    act(() => {
      useDocumentsStore.setState({
        uploads: {
          'up-1': makeUpload({ totalBytes, sentBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES }),
        },
      });
    });

    expect(screen.getByText(/Part 2 of 3/)).toBeInTheDocument();
    expect(
      screen.getByRole('progressbar', { name: /Upload progress for holiday\.zip/ }),
    ).toHaveAttribute('aria-valuenow', '50');
  });

  it('reports a document with no bytes as finished rather than as not-a-number', () => {
    useDocumentsStore.setState({
      uploads: { 'up-1': makeUpload({ totalBytes: 0, sentBytes: 0 }) },
    });
    renderPanel();

    expect(screen.getByRole('progressbar', { name: /holiday\.zip/ })).toHaveAttribute(
      'aria-valuenow',
      '100',
    );
    expect(screen.getByText(/Part 1 of 1/)).toBeInTheDocument();
  });

  it('says when a transfer has moved past its parts and is being committed', () => {
    useDocumentsStore.setState({ uploads: { 'up-1': makeUpload({ status: 'finalizing' }) } });
    renderPanel();

    expect(screen.getByText(/Sealing the file details/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /retry/i })).not.toBeInTheDocument();
  });

  it('cancels the transfer the user asked about, and no other', () => {
    const cancelUpload = vi.fn();
    useDocumentsStore.setState({
      cancelUpload,
      uploads: {
        'up-1': makeUpload({ id: 'up-1', fileName: 'one.bin' }),
        'up-2': makeUpload({ id: 'up-2', fileName: 'two.bin' }),
      },
    });
    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Cancel upload of two.bin' }));

    expect(cancelUpload).toHaveBeenCalledTimes(1);
    expect(cancelUpload).toHaveBeenCalledWith('up-2');
  });

  it('offers a resume for a failed transfer, and explains what a resume re-sends', () => {
    const retryUpload = vi.fn().mockResolvedValue('up-1');
    useDocumentsStore.setState({
      retryUpload,
      uploads: { 'up-1': makeUpload({ status: 'failed' }) },
    });
    renderPanel();

    expect(
      screen.getByText(/Retry to send only the parts the server does not already hold/),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /retry/i }));
    expect(retryUpload).toHaveBeenCalledWith('up-1');
  });

  it('reports why a resume could not start, and stays silent when it was cancelled', async () => {
    const retryUpload = vi.fn().mockRejectedValue(new Error('That upload has expired.'));
    useDocumentsStore.setState({
      retryUpload,
      uploads: { 'up-1': makeUpload({ status: 'failed', error: 'the socket dropped' }) },
    });
    renderPanel();

    expect(screen.getByText(/Upload failed\. the socket dropped/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /retry/i }));
    await waitFor(() => {
      expect(harness.toast).toHaveBeenCalledWith({
        title: 'That upload has expired.',
        type: 'error',
      });
    });

    harness.toast.mockClear();
    retryUpload.mockRejectedValue(new UploadCancelledError());
    fireEvent.click(screen.getByRole('button', { name: /retry/i }));
    await waitFor(() => {
      expect(retryUpload).toHaveBeenCalledTimes(2);
    });
    expect(harness.toast).not.toHaveBeenCalled();
  });
});

/* ========================================================================== */
/*  DocumentUploadPanel — leaving the page, and the lock                       */
/* ========================================================================== */

describe('useUploadUnloadGuard — the confirmation outlives the page that started the transfer', () => {
  /**
   * The guard as `App` mounts it: no markup, just the hook. Testing it here
   * rather than through the whole application keeps the assertion about the
   * listener rather than about a router.
   */
  function GuardHarness() {
    useUploadUnloadGuard();
    return null;
  }

  function dispatchUnload(): Event {
    const event = new Event('beforeunload', { cancelable: true });
    window.dispatchEvent(event);
    return event;
  }

  it('asks the browser to confirm while a transfer is live', () => {
    useDocumentsStore.setState({ uploads: { 'up-1': makeUpload() } });
    render(<GuardHarness />);

    expect(dispatchUnload().defaultPrevented).toBe(true);
  });

  it('does not ask when the only transfer has already stopped', () => {
    useDocumentsStore.setState({ uploads: { 'up-1': makeUpload({ status: 'failed' }) } });
    render(<GuardHarness />);

    expect(dispatchUnload().defaultPrevented).toBe(false);
  });

  it('stops asking once nothing is being transferred any more', () => {
    useDocumentsStore.setState({ uploads: { 'up-1': makeUpload() } });
    render(<GuardHarness />);
    expect(dispatchUnload().defaultPrevented).toBe(true);

    act(() => {
      useDocumentsStore.setState({ uploads: {} });
    });

    expect(dispatchUnload().defaultPrevented).toBe(false);
  });

  it('keeps asking after the Documents page is left, which is why it does not live there', () => {
    useDocumentsStore.setState({ uploads: { 'up-1': makeUpload() } });
    render(<GuardHarness />);
    const panel = renderPanel();

    // The store is module-level, so navigating away does not stop the transfer.
    // A guard armed inside the panel would be disarmed by exactly that move.
    panel.unmount();

    expect(dispatchUnload().defaultPrevented).toBe(true);
  });

  it('is not armed by the Documents panel on its own, which is the rule that puts it in App', () => {
    useDocumentsStore.setState({ uploads: { 'up-1': makeUpload() } });
    renderPanel();

    // No `GuardHarness` here. If the panel armed its own listener, this would be
    // prevented — and the guard would then die with the panel on navigation.
    expect(dispatchUnload().defaultPrevented).toBe(false);
  });

  it('leaves no listener behind when the application itself unmounts', () => {
    useDocumentsStore.setState({ uploads: { 'up-1': makeUpload() } });
    const view = render(<GuardHarness />);
    view.unmount();

    expect(dispatchUnload().defaultPrevented).toBe(false);
  });

  it('tells the user on the page that leaving keeps the transfer and closing does not', () => {
    useDocumentsStore.setState({ uploads: { 'up-1': makeUpload() } });
    renderPanel();

    expect(screen.getByText(/closing the tab does not/i)).toBeInTheDocument();
  });

  it('says nothing about leaving when the only transfer has stopped', () => {
    useDocumentsStore.setState({ uploads: { 'up-1': makeUpload({ status: 'failed' }) } });
    renderPanel();

    expect(screen.queryByText(/closing the tab does not/i)).not.toBeInTheDocument();
  });
});

describe('DocumentUploadPanel — the auto-lock warning', () => {
  it('always states that a lock cancels an upload, before anything is chosen', () => {
    renderPanel();
    expect(screen.getByTestId('upload-lock-note')).toHaveTextContent(
      /Locking the vault cancels an upload in progress/,
    );
    expect(screen.queryByTestId('upload-lock-warning')).not.toBeInTheDocument();
  });

  it('stays quiet for a file the idle budget comfortably covers', () => {
    renderPanel();
    pick('small.pdf', 2 * 1024 * 1024);
    expect(screen.queryByTestId('upload-lock-warning')).not.toBeInTheDocument();
  });

  it('warns when the transfer is likely to outlast the idle timeout, and reads as English at one', () => {
    harness.settings = { ...harness.settings, autoLockTimeout: 1 };
    renderPanel();
    pick('big.pdf', 90 * 1024 * 1024);

    const warning = screen.getByTestId('upload-lock-warning');
    expect(warning).toHaveTextContent(/about 6 minutes/);
    expect(warning).toHaveTextContent(
      /the vault locks after 1 minute without activity\. Keep using the app while it runs, or raise the auto-lock timeout in Settings/,
    );
    // Naming the hidden-tab delay here would send the user to a setting that
    // does not govern this account's deadline.
    expect(warning).not.toHaveTextContent(/switch away/);
  });

  it('names the hidden-tab deadline, and the setting that moves it, when that one binds', () => {
    harness.settings = {
      ...harness.settings,
      autoLockTimeout: 60,
      lockOnHidden: true,
      lockOnHiddenDelay: 5,
    };
    renderPanel();
    pick('big.pdf', 90 * 1024 * 1024);

    const warning = screen.getByTestId('upload-lock-warning');
    expect(warning).toHaveTextContent(/about 6 minutes/);
    expect(warning).toHaveTextContent(
      /the vault locks 5 minutes after you switch away from this tab\. Keep this tab in front while it runs, or raise the hidden-tab delay in Settings/,
    );
    // The idle wording would be false here: this account does not lock after
    // five minutes of inactivity, it locks five minutes after the tab is hidden.
    expect(warning).not.toHaveTextContent(/without activity/);
  });

  it('keeps the idle wording when hidden-tab locking is on but not the binding deadline', () => {
    harness.settings = {
      ...harness.settings,
      autoLockTimeout: 1,
      lockOnHidden: true,
      lockOnHiddenDelay: 30,
    };
    renderPanel();
    pick('big.pdf', 90 * 1024 * 1024);

    const warning = screen.getByTestId('upload-lock-warning');
    expect(warning).toHaveTextContent(/locks after 1 minute without activity/);
    expect(warning).not.toHaveTextContent(/switch away/);
  });

  it('treats the idle timeout as the binding deadline when the two settings are equal', () => {
    // The boundary of the strict `<`. Hiding the tab is deliberately not
    // activity, so the idle clock is always at or ahead of the hidden one and
    // `lastActivity + timeout` can never be the later of the two: at equality the
    // idle deadline is the one that fires, and naming the hidden-tab delay here
    // would send the user to a setting that changes nothing.
    harness.settings = {
      ...harness.settings,
      autoLockTimeout: 5,
      lockOnHidden: true,
      lockOnHiddenDelay: 5,
    };
    renderPanel();
    pick('big.pdf', 90 * 1024 * 1024);

    const warning = screen.getByTestId('upload-lock-warning');
    expect(warning).toHaveTextContent(/locks after 5 minutes without activity/);
    expect(warning).not.toHaveTextContent(/switch away/);
    expect(warning).not.toHaveTextContent(/hidden-tab delay/);
  });

  it('names both settings when the transfer will outrun the idle timeout as well', () => {
    // Hidden delay 1, idle timeout 2, estimate 6 minutes: BOTH deadlines fire, so
    // "keep this tab in front and raise the hidden-tab delay" is advice the user
    // could follow exactly and still lose the upload.
    harness.settings = {
      ...harness.settings,
      autoLockTimeout: 2,
      lockOnHidden: true,
      lockOnHiddenDelay: 1,
    };
    renderPanel();
    pick('big.pdf', 90 * 1024 * 1024);

    const warning = screen.getByTestId('upload-lock-warning');
    expect(warning).toHaveTextContent(/the vault locks 1 minute after you switch away/);
    expect(warning).toHaveTextContent(/the idle timeout runs out in 2 minutes too/);
    expect(warning).toHaveTextContent(/raise both settings first/);
  });

  it('does not add a lock warning on top of a refusal for a file that is not going anywhere', () => {
    harness.settings = { ...harness.settings, autoLockTimeout: 1 };
    renderPanel();
    pick('huge.pdf', 200 * 1024 * 1024);

    expect(screen.getByTestId('upload-refusal')).toBeInTheDocument();
    expect(screen.queryByTestId('upload-lock-warning')).not.toBeInTheDocument();
  });
});
