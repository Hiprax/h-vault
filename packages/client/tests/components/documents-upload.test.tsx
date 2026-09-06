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
import { render, screen, fireEvent, waitFor, cleanup, act, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import React from 'react';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES, MAX_FORMATTABLE_SIZE_BYTES } from '@hvault/shared';
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
  /**
   * The isolated document's driver, stubbed at THIS tier and only at this tier.
   *
   * The panel's job is the state machine around a transform — when the Upload
   * button is offered, what a review blocks, what a failure falls back to — and
   * driving a real hidden iframe through jsdom would test none of it. The driver
   * itself has a suite that runs every line of it (`document-transform.test.ts`),
   * and the engine has one that runs the real Prettier and the real repairer
   * (`document-format.test.ts`), so nothing here is the only cover for anything.
   */
  transformDocument: vi.fn(),
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

vi.mock('../../src/services/documents/transform', () => ({
  transformDocument: harness.transformDocument,
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
import { useVaultStore } from '../../src/stores/vaultStore';
import { useUploadUnloadGuard } from '../../src/hooks/useUploadUnloadGuard';
import DocumentsPage from '../../src/pages/DocumentsPage';
import { DocumentList } from '../../src/components/documents/DocumentList';
import { DocumentUploadPanel } from '../../src/components/documents/DocumentUploadPanel';
import type { DocumentsConfig } from '../../src/services/api/configApi';

/* -------------------------------------------------------------------------- */
/*  Fixtures                                                                   */
/* -------------------------------------------------------------------------- */

const pristineState = useDocumentsStore.getState();
const pristineVault = useVaultStore.getState();

/** The one folder the rail's tree is built from in these cases. */
const FOLDER_ID = 'folder-1';

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

/**
 * Choose a file, and hand back both the handle and its read log.
 *
 * The HANDLE matters as much as the log: several cases below assert that what
 * was uploaded is the very `File` that is selected — object identity, not a
 * matching name — because a name can agree while the bytes belong to a file the
 * user replaced.
 */
function pick(name: string, size: number, type?: string): { file: File; reads: string[] } {
  const { file, reads } = makeFile(name, size, type);
  fireEvent.change(screen.getByLabelText('File to upload'), { target: { files: [file] } });
  return { file, reads };
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
  // Seeded rather than fetched: `useVaultFolders` short-circuits on a non-empty
  // list, so the rail renders its tree without this suite needing the vault API.
  useVaultStore.setState(pristineVault, true);
  useVaultStore.setState({
    folders: [
      { id: FOLDER_ID, name: 'Taxes', sortOrder: 0, createdAt: 'x', updatedAt: 'x' },
    ] as never,
  });
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
    // AWAITED, because the heading is not a signal that the effect behind it has
    // run. The load is a passive effect, so React schedules it after the commit
    // that painted this heading, and asserting the call count the instant the
    // heading appears is a race with the effect flush — measured, as a single
    // "expected 1, got 0" inside a pipeline run on a machine that had no free
    // memory left, passing in isolation every time.
    //
    // It is the same claim, not a weaker one: `waitFor` retries until the
    // callback stops throwing, so a load that never happens still fails on the
    // deadline, and a load that happens TWICE fails immediately and keeps
    // failing — `toHaveBeenCalledTimes(1)` can never be satisfied by a second
    // call arriving later.
    await waitFor(() => {
      expect(fetchDocuments).toHaveBeenCalledTimes(1);
      expect(fetchUsage).toHaveBeenCalledTimes(1);
    });
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

  it('names the documents that could not be opened, and which list it counted', async () => {
    useDocumentsStore.setState({ degradedCount: 2, invalidCount: 0 });
    renderPage();

    const notice = await screen.findByTestId('documents-degraded');
    expect(notice).toHaveTextContent(/2 document\(s\) in your documents could not be opened/);
    expect(notice).toHaveTextContent(/shown without their details/);
    expect(notice).not.toHaveTextContent(/left out/);
  });

  it('counts the TRASH’s unopenable rows when the trash is what is on screen', async () => {
    // The two lists are fetched separately and fail separately. A banner that
    // reported the active list's numbers over a trash view would be counting rows
    // the reader cannot see — and `fetchTrash` used to discard its own counts
    // entirely, so an unopenable trashed row vanished with nothing said about it.
    useDocumentsStore.setState({
      degradedCount: 2,
      invalidCount: 0,
      trashDegradedCount: 1,
      trashInvalidCount: 0,
      showTrash: true,
    });
    renderPage();

    const notice = await screen.findByTestId('documents-degraded');
    expect(notice).toHaveTextContent(/1 document\(s\) in the trash could not be opened/);
    expect(notice).not.toHaveTextContent(/2 document/);
  });

  it('names the rows that were rejected outright, separately from the degraded ones', async () => {
    useDocumentsStore.setState({ degradedCount: 0, invalidCount: 4 });
    renderPage();

    const notice = await screen.findByTestId('documents-degraded');
    expect(notice).toHaveTextContent(/4 row\(s\).*left out entirely/);
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
    // AWAITED, for the reason spelled out on `loads the list and the usage once the
    // feature is advertised as available`, at the end of this file's first block: the heading
    // is not a signal that the passive effect behind it has run. This was the one
    // place that reasoning had not reached, and the flake gate found it: one
    // "expected 1, got 0" here at order seed 1338, green in the other nine runs.
    await waitFor(() => {
      expect(fetchUsage).toHaveBeenCalledTimes(1);
    });

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
        <DocumentList
          documents={[]}
          loading={false}
          error={null}
          onRetry={vi.fn()}
          mode={{ kind: 'all' }}
          folderNames={new Map()}
          searching={false}
          {...props}
        />
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
    const { reads } = pick('huge.pdf', 200 * 1024 * 1024);

    expect(screen.getByTestId('upload-refusal')).toHaveTextContent(
      /This server accepts documents up to 100 MB/,
    );
    expect(startUpload).not.toHaveBeenCalled();
    expect(reads).toEqual([]);
    expect(screen.queryByRole('button', { name: /^Upload$/ })).not.toBeInTheDocument();
  });

  it('refuses a file type the server asks not to receive, reading none of it', () => {
    renderPanel({ ...ENABLED_CONFIG, allowedExtensions: ['pdf', 'md'] });
    const { reads } = pick('archive.zip', 1024);

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
    // The WHOLE sentence, not just its first half, because the part numbers are
    // where a zero-byte document goes wrong. `documentChunkCountFor` floors its
    // answer at 1 — a file with no bytes is still one segment, holding a tag and no
    // plaintext — and this row states that floor rather than re-applying one of its
    // own. A local clamp would keep printing "Part 1 of 1" even if the framing rule
    // were removed from the shared helper, so the assertion here is the only thing
    // that can notice.
    expect(screen.getByText('Part 1 of 1 — 0 B of 0 B')).toBeInTheDocument();
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

  it('offers a resume for a failed transfer, and explains what a resume re-sends', async () => {
    const retryUpload = vi.fn().mockResolvedValue('up-1');
    useDocumentsStore.setState({
      retryUpload,
      uploads: { 'up-1': makeUpload({ status: 'failed' }) },
    });
    renderPanel();

    expect(
      screen.getByText(/Retry to send only the parts the server does not already hold/),
    ).toBeInTheDocument();
    // Awaited, because the click now settles a pending state on the way back:
    // firing it bare leaves that update outside `act` and React says so.
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Retry upload of holiday.zip' }));
    });
    expect(retryUpload).toHaveBeenCalledWith('up-1');
  });

  it('will not start a second resume while the first is still being prepared', async () => {
    // The store refuses a second resume outright — a second transfer over the same
    // parts ends with a document sealed under a key nobody holds. This is the
    // affordance in front of that refusal: the button must say what is happening
    // and must not hand the store a click it is going to reject.
    //
    // The resume is DEFERRED here, and that is the whole test: the real window is
    // one round trip to the staging ledger, and a mock that resolves at once would
    // never leave the button in the state being asserted.
    let release = (): void => {};
    const retryUpload = vi.fn().mockImplementation(
      () =>
        new Promise<string>((resolve) => {
          release = () => {
            resolve('up-1');
          };
        }),
    );
    useDocumentsStore.setState({
      retryUpload: retryUpload as unknown as ReturnType<
        typeof useDocumentsStore.getState
      >['retryUpload'],
      uploads: { 'up-1': makeUpload({ status: 'failed' }) },
    });
    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Retry upload of holiday.zip' }));

    // The accessible name changes with the state and still names the file: two
    // failed transfers otherwise offer two controls both called "Retry".
    const pendingRetry = await screen.findByRole('button', {
      name: 'Retrying upload of holiday.zip',
    });
    expect(pendingRetry).toBeDisabled();
    expect(pendingRetry).toHaveTextContent('Retrying');

    fireEvent.click(pendingRetry);
    fireEvent.click(pendingRetry);

    // THE NEGATIVE: the two further clicks never reached the handler, so the store
    // was never asked to start a resume it would have had to refuse.
    expect(retryUpload).toHaveBeenCalledTimes(1);
    expect(retryUpload).toHaveBeenCalledWith('up-1');
    // And a refused click is not an error: nothing was said to the user about it.
    expect(harness.toast).not.toHaveBeenCalled();

    // The pending state settles rather than sticking: this row is still `failed`
    // in the store, so the control comes back offering the resume again.
    await act(async () => {
      release();
      await Promise.resolve();
    });
    expect(screen.getByRole('button', { name: 'Retry upload of holiday.zip' })).toBeEnabled();
  });

  it('reports why a resume could not start, and stays silent when it was cancelled', async () => {
    const retryUpload = vi.fn().mockRejectedValue(new Error('That upload has expired.'));
    useDocumentsStore.setState({
      retryUpload,
      uploads: { 'up-1': makeUpload({ status: 'failed', error: 'the socket dropped' }) },
    });
    renderPanel();

    expect(screen.getByText(/Upload failed\. the socket dropped/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry upload of holiday.zip' }));
    await waitFor(() => {
      expect(harness.toast).toHaveBeenCalledWith({
        title: 'That upload has expired.',
        type: 'error',
      });
    });

    harness.toast.mockClear();
    retryUpload.mockRejectedValue(new UploadCancelledError());
    // The button is DISABLED while a resume is pending, and `/retry/i` matches
    // "Retrying" as well as "Retry" — so a second click issued against the
    // pending name would silently no-op and this test would report a mystery.
    // Waiting for the IDLE name is what makes the refusal it settled into
    // observable, instead of resting on the order two microtask chains happen to
    // land in.
    const idleRetry = await screen.findByRole('button', {
      name: 'Retry upload of holiday.zip',
    });
    expect(idleRetry).toBeEnabled();
    fireEvent.click(idleRetry);
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

/* -------------------------------------------------------------------------- */
/*  The optional in-browser transforms                                          */
/* -------------------------------------------------------------------------- */

/**
 * The two checkboxes, and the promise the panel makes around them: NOTHING this
 * panel rewrites is uploaded without the user having seen what changed.
 *
 * The assertions that matter most here are negatives. A transform that has run
 * and not been confirmed must leave `startUpload` untouched; a transform that
 * FAILED must leave it untouched too, and must not quietly fall back to sending
 * the original as though the checkbox had never been ticked.
 */
describe('DocumentUploadPanel — format and repair', () => {
  let startUpload = vi.fn().mockResolvedValue('up-1');

  beforeEach(() => {
    startUpload = vi.fn().mockResolvedValue('up-1');
    useDocumentsStore.setState({ startUpload });
  });

  /** A review the driver would return for a formatted JSON document. */
  function reviewOf(text: string, bytesBefore = 7) {
    return {
      status: 'ready' as const,
      review: {
        blob: new Blob([text]),
        transform: {
          formatted: true,
          repaired: false,
          tool: 'prettier',
          toolVersion: '3.9.5',
          originalSha256: '0'.repeat(64),
        },
        diff: {
          identical: false,
          linesBefore: 1,
          linesAfter: 2,
          linesAdded: 2,
          linesRemoved: 1,
          hunks: [
            {
              beforeStart: 1,
              beforeCount: 1,
              afterStart: 1,
              afterCount: 2,
              lines: [
                { kind: 'removed' as const, text: '{"a":1}' },
                { kind: 'added' as const, text: '{ "a": 1 }' },
              ],
            },
          ],
        },
        bytesBefore,
        bytesAfter: new Blob([text]).size,
      },
    };
  }

  /**
   * A transform that has STARTED and has not yet answered.
   *
   * The pending window is the whole subject of the cases below, and it is the
   * one thing `mockResolvedValue` cannot give: a promise that is already
   * settled closes the window before a second file can be picked. That is why
   * "forgets a review when a different file is picked" above does not cover
   * any of this — it awaits the review first, so the window is already shut by
   * the time it acts, and it passed throughout the period the panel was wrong.
   */
  function deferTransform(): {
    settle: (attempt: unknown) => Promise<void>;
    fail: (error: unknown) => Promise<void>;
  } {
    let settleInner!: (attempt: unknown) => void;
    let failInner!: (error: unknown) => void;
    harness.transformDocument.mockReturnValue(
      new Promise<unknown>((resolve, reject) => {
        settleInner = resolve;
        failInner = reject;
      }),
    );
    return {
      settle: async (attempt: unknown) => {
        await act(async () => {
          settleInner(attempt);
          await Promise.resolve();
        });
      },
      fail: async (error: unknown) => {
        await act(async () => {
          failInner(error);
          await Promise.resolve();
        });
      },
    };
  }

  /** Start a transform of `config.json` that will not answer until told to. */
  function startPendingTransform(): {
    settle: (attempt: unknown) => Promise<void>;
    fail: (error: unknown) => Promise<void>;
  } {
    const pending = deferTransform();
    pick('config.json', 500);
    fireEvent.click(screen.getByLabelText(/Format this document/));
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));
    expect(screen.getByTestId('transform-running')).toBeInTheDocument();
    return pending;
  }

  it('offers both transforms for a JSON file', () => {
    renderPanel();
    pick('config.json', 500);

    expect(screen.getByTestId('transform-controls')).toBeInTheDocument();
    expect(screen.getByLabelText(/Format this document/)).toBeEnabled();
    expect(screen.getByLabelText(/Repair syntax errors/)).toBeEnabled();
  });

  it('keeps both disabled, with the reason shown, for a type neither supports', () => {
    renderPanel();
    pick('report.pdf', 500);

    const format = screen.getByLabelText(/Format this document/);
    const repair = screen.getByLabelText(/Repair syntax errors/);
    expect(format).toBeDisabled();
    expect(repair).toBeDisabled();
    // A disabled control with no explanation is indistinguishable from a broken
    // one, and the reason is wired to the control rather than merely printed
    // near it.
    const reason = document.getElementById(String(format.getAttribute('aria-describedby')));
    expect(reason).toHaveTextContent(/JSON, JSON Lines, Markdown and YAML/);
    expect(
      document.getElementById(String(repair.getAttribute('aria-describedby'))),
    ).toHaveTextContent(/JSON family only/);
  });

  it('offers formatting but not repair for Markdown, and says why', () => {
    renderPanel();
    pick('README.md', 500);

    expect(screen.getByLabelText(/Format this document/)).toBeEnabled();
    const repair = screen.getByLabelText(/Repair syntax errors/);
    expect(repair).toBeDisabled();
    expect(
      document.getElementById(String(repair.getAttribute('aria-describedby'))),
    ).toHaveTextContent(/Markdown has no syntax error to repair/);
  });

  it('disables both past the size ceiling, naming the ceiling rather than the type', () => {
    renderPanel();
    // Comfortably over MAX_FORMATTABLE_SIZE_BYTES (5 MiB) and comfortably under
    // the server's own 100 MB cap, so the ONLY refusal in play is this one.
    pick('huge.json', 6 * 1024 * 1024);

    const format = screen.getByLabelText(/Format this document/);
    expect(format).toBeDisabled();
    expect(
      document.getElementById(String(format.getAttribute('aria-describedby'))),
    ).toHaveTextContent(/files up to/);
    // The file itself is still perfectly uploadable.
    expect(screen.queryByTestId('upload-refusal')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Upload$/ })).toBeInTheDocument();
  });

  it('draws the size ceiling AT the bound, not near it', () => {
    // n and n+1. The comparison is `size > MAX_FORMATTABLE_SIZE_BYTES`, so a
    // file of exactly the ceiling must still be offered both transforms and one
    // byte more must be offered neither — the pair of cases an off-by-one lives
    // in, and the one a "comfortably over" test cannot see.
    const { unmount } = renderPanel();
    pick('exactly.json', MAX_FORMATTABLE_SIZE_BYTES);
    expect(screen.getByLabelText(/Format this document/)).toBeEnabled();
    expect(screen.getByLabelText(/Repair syntax errors/)).toBeEnabled();
    unmount();

    renderPanel();
    pick('one-over.json', MAX_FORMATTABLE_SIZE_BYTES + 1);
    expect(screen.getByLabelText(/Format this document/)).toBeDisabled();
    expect(screen.getByLabelText(/Repair syntax errors/)).toBeDisabled();
  });

  it('uploads straight away, with no provenance, when neither box is ticked', async () => {
    renderPanel();
    pick('config.json', 500);
    fireEvent.click(screen.getByRole('button', { name: /^Upload$/ }));

    await waitFor(() => {
      expect(startUpload).toHaveBeenCalledTimes(1);
    });
    expect(harness.transformDocument).not.toHaveBeenCalled();
    const [input] = startUpload.mock.calls[0] as [Record<string, unknown>];
    expect(input.name).toBe('config.json');
    expect(input).not.toHaveProperty('transform');
  });

  it('does NOT start an upload while a transform is unconfirmed', async () => {
    harness.transformDocument.mockResolvedValue(reviewOf('{ "a": 1 }\n'));
    renderPanel();
    pick('config.json', 500);
    fireEvent.click(screen.getByLabelText(/Format this document/));

    // The button says what it will do, and what it does is NOT upload.
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));

    const review = await screen.findByTestId('transform-review');
    expect(startUpload).not.toHaveBeenCalled();
    // And the Upload button is GONE while the review is open, rather than
    // sitting disabled beside it looking like a second way forward.
    expect(screen.queryByRole('button', { name: /Prepare and review/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Upload$/ })).not.toBeInTheDocument();

    // The comparison is shown before anything is sent.
    expect(within(review).getByTestId('transform-summary')).toHaveTextContent(
      /2 lines added, 1 removed/,
    );
    expect(within(review).getByTestId('transform-summary')).toHaveTextContent(/prettier 3.9.5/);
  });

  it('uploads the transformed bytes, under the original name, once confirmed', async () => {
    harness.transformDocument.mockResolvedValue(reviewOf('{ "a": 1 }\n'));
    renderPanel();
    pick('config.json', 500);
    fireEvent.click(screen.getByLabelText(/Format this document/));
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));
    await screen.findByTestId('transform-review');

    fireEvent.click(screen.getByRole('button', { name: /Upload the formatted file/ }));

    await waitFor(() => {
      expect(startUpload).toHaveBeenCalledTimes(1);
    });
    const [input] = startUpload.mock.calls[0] as [Record<string, unknown>];
    // The transformed BLOB, but the picked file's NAME: the store deliberately
    // never reads `File.name`, so a rewritten document cannot end up named after
    // the file it no longer is.
    expect(input.source).toBeInstanceOf(Blob);
    expect(input.source).not.toBeInstanceOf(File);
    expect(input.name).toBe('config.json');
    expect(input.transform).toEqual({
      formatted: true,
      repaired: false,
      tool: 'prettier',
      toolVersion: '3.9.5',
      originalSha256: '0'.repeat(64),
    });
  });

  it('lets the user take the original instead, and records no provenance for it', async () => {
    harness.transformDocument.mockResolvedValue(reviewOf('{ "a": 1 }\n'));
    renderPanel();
    pick('config.json', 500);
    fireEvent.click(screen.getByLabelText(/Repair syntax errors/));
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));
    await screen.findByTestId('transform-review');

    fireEvent.click(screen.getByRole('button', { name: /Upload the original unchanged/ }));

    await waitFor(() => {
      expect(startUpload).toHaveBeenCalledTimes(1);
    });
    const [input] = startUpload.mock.calls[0] as [Record<string, unknown>];
    expect(input.source).toBeInstanceOf(File);
    // A file that was NOT transformed must carry no record saying it was.
    expect(input).not.toHaveProperty('transform');
  });

  it('stops the upload on a failure, naming the line, the column and the offending text', async () => {
    harness.transformDocument.mockResolvedValue({
      status: 'failed',
      failure: {
        message: 'Unexpected character "{" at position 7',
        line: 1,
        column: 8,
        excerpt: '{"a":1}{"b":2}',
      },
    });
    renderPanel();
    pick('config.json', 500);
    fireEvent.click(screen.getByLabelText(/Repair syntax errors/));
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));

    const failure = await screen.findByTestId('transform-failure');
    expect(startUpload).not.toHaveBeenCalled();
    expect(within(failure).getByTestId('transform-failure-message')).toHaveTextContent(
      'Unexpected character "{" at position 7',
    );
    expect(within(failure).getByTestId('transform-failure-position')).toHaveTextContent(
      'Line 1, column 8',
    );
    expect(within(failure).getByTestId('transform-failure-excerpt')).toHaveTextContent(
      '{"a":1}{"b":2}',
    );
    // It is an alert, because the upload the user asked for did not happen.
    expect(failure).toHaveAttribute('role', 'alert');

    // …and the one way forward from here still works.
    fireEvent.click(screen.getByRole('button', { name: /Upload the original unchanged/ }));
    await waitFor(() => {
      expect(startUpload).toHaveBeenCalledTimes(1);
    });
    expect((startUpload.mock.calls[0] as [Record<string, unknown>])[0]).not.toHaveProperty(
      'transform',
    );
  });

  it('lets the user back out of a failure without uploading anything at all', async () => {
    // The OTHER way out of the failure panel, and the one that must upload
    // nothing: Cancel returns the panel to the state it was in before the
    // transform ran, with the file still selected and the Upload button back.
    // Without it a failed transform would be a dead end offering only "upload
    // the original", which is a choice the user has not been left.
    harness.transformDocument.mockResolvedValue({
      status: 'failed',
      failure: { message: 'Flow sequence never closed', line: 3, column: 1, excerpt: 'b: [1, 2' },
    });
    renderPanel();
    pick('compose.yaml', 500);
    fireEvent.click(screen.getByLabelText(/Format this document/));
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));

    const failure = await screen.findByTestId('transform-failure');
    fireEvent.click(within(failure).getByRole('button', { name: /^Cancel$/ }));

    await waitFor(() => {
      expect(screen.queryByTestId('transform-failure')).not.toBeInTheDocument();
    });
    // Back to idle: the file is still chosen, the checkbox is usable again, and
    // the button reads as a transform run rather than a plain upload because the
    // tick survived.
    expect(screen.getByText(/compose\.yaml/)).toBeInTheDocument();
    expect(screen.getByLabelText(/Format this document/)).toBeEnabled();
    expect(screen.getByRole('button', { name: /Prepare and review/ })).toBeInTheDocument();
    // And the negative that is the whole point of a Cancel.
    expect(startUpload).not.toHaveBeenCalled();
  });

  it('reports a driver that rejected outright rather than uploading in silence', async () => {
    // `transformDocument` resolves on every failure it can name; a rejection is
    // one it could not — the file could not be read at all. Sending the original
    // anyway would be a rewrite the user asked for, silently not happening.
    harness.transformDocument.mockRejectedValue(new Error('unreadable'));
    renderPanel();
    pick('config.json', 500);
    fireEvent.click(screen.getByLabelText(/Format this document/));
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));

    const failure = await screen.findByTestId('transform-failure');
    expect(within(failure).getByTestId('transform-failure-message')).toHaveTextContent(
      /could not be read/,
    );
    expect(startUpload).not.toHaveBeenCalled();
  });

  it('passes the extension and both flags to the driver, and nothing else', async () => {
    harness.transformDocument.mockResolvedValue(reviewOf('x'));
    renderPanel();
    pick('data.NDJSON', 500);
    fireEvent.click(screen.getByLabelText(/Format this document/));
    fireEvent.click(screen.getByLabelText(/Repair syntax errors/));
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));
    await screen.findByTestId('transform-review');

    expect(harness.transformDocument).toHaveBeenCalledTimes(1);
    const [source, options] = harness.transformDocument.mock.calls[0] as [File, unknown];
    expect(source.name).toBe('data.NDJSON');
    // Lowercased, because that is the key every extension table in this
    // application is looked up by.
    expect(options).toEqual({ ext: 'ndjson', format: true, repair: true });
  });

  it('forgets a review when a different file is picked', async () => {
    harness.transformDocument.mockResolvedValue(reviewOf('{ "a": 1 }\n'));
    renderPanel();
    pick('config.json', 500);
    fireEvent.click(screen.getByLabelText(/Format this document/));
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));
    await screen.findByTestId('transform-review');

    // A review of the file before must never be confirmable against the file
    // after, and a `.png` must not inherit a ticked Format box.
    pick('picture.png', 500);
    expect(screen.queryByTestId('transform-review')).not.toBeInTheDocument();
    expect(screen.getByLabelText(/Format this document/)).not.toBeChecked();
    expect(screen.getByRole('button', { name: /^Upload$/ })).toBeInTheDocument();
  });

  it('locks the checkboxes while a review is open, so the reviewed run cannot be edited', async () => {
    harness.transformDocument.mockResolvedValue(reviewOf('{ "a": 1 }\n'));
    renderPanel();
    pick('config.json', 500);
    fireEvent.click(screen.getByLabelText(/Format this document/));
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));
    await screen.findByTestId('transform-review');

    expect(screen.getByLabelText(/Format this document/)).toBeDisabled();
    expect(screen.getByLabelText(/Repair syntax errors/)).toBeDisabled();

    // Cancelling returns the panel to where it started, with the file still picked.
    fireEvent.click(screen.getByRole('button', { name: /^Cancel$/ }));
    expect(screen.queryByTestId('transform-review')).not.toBeInTheDocument();
    expect(screen.getByLabelText(/Format this document/)).toBeEnabled();
    expect(screen.getByRole('button', { name: /Prepare and review/ })).toBeInTheDocument();
  });

  it('says so plainly when a transform changed nothing at all', async () => {
    const identical = reviewOf('{"a":1}');
    harness.transformDocument.mockResolvedValue({
      status: 'ready',
      review: {
        ...identical.review,
        diff: {
          identical: true,
          linesBefore: 1,
          linesAfter: 1,
          linesAdded: 0,
          linesRemoved: 0,
          hunks: [],
        },
      },
    });
    renderPanel();
    pick('config.json', 500);
    fireEvent.click(screen.getByLabelText(/Repair syntax errors/));
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));

    const review = await screen.findByTestId('transform-review');
    expect(review).toHaveTextContent(/Nothing changed/);
    // No diff to open when there is nothing to show.
    expect(within(review).queryByText(/Show what changed/)).not.toBeInTheDocument();
  });

  it('says the line-by-line comparison was skipped rather than showing an empty one', async () => {
    const base = reviewOf('x');
    harness.transformDocument.mockResolvedValue({
      status: 'ready',
      review: {
        ...base.review,
        diff: {
          identical: false,
          linesBefore: 2000,
          linesAfter: 2000,
          linesAdded: 2000,
          linesRemoved: 2000,
          hunks: null,
        },
      },
    });
    renderPanel();
    pick('config.json', 500);
    fireEvent.click(screen.getByLabelText(/Format this document/));
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));

    const review = await screen.findByTestId('transform-review');
    fireEvent.click(within(review).getByText(/Show what changed/));
    expect(review).toHaveTextContent(/too large to compare line by line/);
    expect(within(review).queryByTestId('transform-diff')).not.toBeInTheDocument();
  });

  /* ------------------------------------------------------------------------ */
  /*  A review belongs to ONE file, and to the selection that produced it      */
  /* ------------------------------------------------------------------------ */

  it('drops a review whose file was replaced while its transform was still running', async () => {
    // `select` resets the phase but CANCELS NOTHING, so the promise for the
    // first file is still in flight when the second is chosen and it lands
    // afterwards. Shown against the second file, its confirm would upload the
    // FIRST file's bytes under the SECOND file's name, sealed with the first
    // file's `originalSha256` — a provenance block that then describes a
    // document nobody uploaded.
    renderPanel();
    const pending = startPendingTransform();

    const second = pick('other.json', 400).file;
    await pending.settle(reviewOf('{ "a": 1 }\n'));

    // Not the review, and not the spinner either: the panel belongs to the file
    // selected now, and nothing about the file before it survives.
    expect(screen.queryByTestId('transform-review')).not.toBeInTheDocument();
    expect(screen.queryByTestId('transform-running')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: /Upload the formatted file/ }),
    ).not.toBeInTheDocument();
    // …and the panel is usable for the file that IS selected: the Upload button
    // is back and the checkboxes are not locked by a run this file never had.
    expect(screen.getByText(/other\.json/)).toBeInTheDocument();
    expect(screen.getByLabelText(/Format this document/)).toBeEnabled();
    expect(screen.getByLabelText(/Format this document/)).not.toBeChecked();

    // The only upload this panel can now start is the selected file's own
    // bytes, under its own name, carrying no provenance from a run it never had.
    fireEvent.click(screen.getByRole('button', { name: /^Upload$/ }));
    await waitFor(() => {
      expect(startUpload).toHaveBeenCalledTimes(1);
    });
    const [input] = startUpload.mock.calls[0] as [Record<string, unknown>];
    expect(input.source).toBe(second);
    expect(input.name).toBe('other.json');
    expect(input).not.toHaveProperty('transform');
  });

  it('drops a review whose file was CLEARED while its transform was still running', async () => {
    // The other way the selection moves on. Clearing is not picking, so a
    // binding that only watched the file input would let this one through and
    // the review would reappear against whatever is chosen next.
    renderPanel();
    const pending = startPendingTransform();

    fireEvent.click(screen.getByRole('button', { name: 'Clear selected file' }));
    pick('other.json', 400);
    await pending.settle(reviewOf('{ "a": 1 }\n'));

    expect(screen.queryByTestId('transform-review')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Upload$/ })).toBeInTheDocument();
    expect(startUpload).not.toHaveBeenCalled();
  });

  it('drops a FAILURE whose file was replaced while its transform was still running', async () => {
    // The other arm of the same `.then`. A syntax error in the file the user
    // has just moved on from must not be reported against the file they moved
    // on TO — which has not been read, let alone parsed.
    renderPanel();
    const pending = startPendingTransform();

    pick('other.json', 400);
    await pending.settle({
      status: 'failed',
      failure: { message: 'Unexpected end of JSON input', line: 4, column: 1, excerpt: '{"a":' },
    });

    expect(screen.queryByTestId('transform-failure')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Upload$/ })).toBeInTheDocument();
    expect(startUpload).not.toHaveBeenCalled();
  });

  it('drops a driver REJECTION whose file was replaced while it was still running', async () => {
    // And the rejection arm, which reports "this file could not be read" — a
    // sentence that would be flatly untrue about the file now on screen.
    renderPanel();
    const pending = startPendingTransform();

    pick('other.json', 400);
    await pending.fail(new Error('unreadable'));

    expect(screen.queryByTestId('transform-failure')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Upload$/ })).toBeInTheDocument();
    expect(startUpload).not.toHaveBeenCalled();
  });

  it('does not let a late answer take the screen from the run that is on now', async () => {
    // Two files, two runs, and the FIRST one answers last. Dropping the stale
    // answer is only half of it: it must also not take the spinner away from
    // the run the user is actually waiting on, which an unguarded write did.
    renderPanel();
    const first = startPendingTransform();
    pick('other.json', 400);
    const second = deferTransform();
    fireEvent.click(screen.getByLabelText(/Format this document/));
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));
    expect(screen.getByTestId('transform-running')).toBeInTheDocument();

    await first.settle(reviewOf('{ "a": 1 }\n'));

    expect(screen.getByTestId('transform-running')).toBeInTheDocument();
    expect(screen.queryByTestId('transform-review')).not.toBeInTheDocument();

    await second.settle(reviewOf('{\n  "b": 2\n}\n'));
    expect(screen.getByTestId('transform-review')).toBeInTheDocument();
  });

  it('does not let a late answer replace a review that is already open', async () => {
    // The same overlap, resolved the other way round. Replacing an open review
    // discards a comparison the user is in the middle of reading AND puts a
    // different file's bytes behind a confirmation they had already reached.
    renderPanel();
    const first = startPendingTransform();
    pick('other.json', 400);
    const second = deferTransform();
    fireEvent.click(screen.getByLabelText(/Format this document/));
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));

    await second.settle(reviewOf('{\n  "b": 2\n}\n'));
    await screen.findByTestId('transform-review');

    await first.settle(reviewOf('{ "a": 1 }\n'));

    // Still the review that was open, and confirming it sends ITS bytes.
    expect(screen.getByTestId('transform-review')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Upload the formatted file/ }));
    await waitFor(() => {
      expect(startUpload).toHaveBeenCalledTimes(1);
    });
    const [input] = startUpload.mock.calls[0] as [Record<string, unknown>];
    expect(input.name).toBe('other.json');
    expect(await (input.source as Blob).text()).toBe('{\n  "b": 2\n}\n');
  });

  /* ------------------------------------------------------------------------ */
  /*  The size cap is checked on what will be UPLOADED, not on what was picked */
  /* ------------------------------------------------------------------------ */

  /** A review whose result is `size` bytes, from a picked file of 500. */
  function reviewOfSize(size: number) {
    const blob = new Blob([new Uint8Array(size)]);
    const base = reviewOf('x');
    return {
      status: 'ready' as const,
      review: { ...base.review, blob, bytesBefore: 500, bytesAfter: blob.size },
    };
  }

  it('refuses a transform that grew the file past the cap, naming the limit', async () => {
    // `refusalFor` measured the file that was PICKED; what `send` uploads is the
    // blob the transform produced. A formatter that expands a minified document
    // past the cap left the SERVER to notice, which it did — with its own size
    // message, but only after the confirmation and after `send` had cleared the
    // selection, so the answer landed beside no file and no comparison.
    harness.transformDocument.mockResolvedValue(reviewOfSize(2 * 1024 * 1024));
    renderPanel({ ...ENABLED_CONFIG, maxSizeMB: 1 });
    pick('config.json', 500);
    fireEvent.click(screen.getByLabelText(/Format this document/));
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));

    const review = await screen.findByTestId('transform-review');
    // The confirm is not OFFERED, rather than offered and then refused: the
    // review is still shown, because what changed is exactly what the user
    // needs to see to decide what to do instead.
    expect(
      within(review).queryByRole('button', { name: /Upload the formatted file/ }),
    ).not.toBeInTheDocument();
    // The same actionable sentence the picked-file guardrail uses, naming the
    // limit rather than merely refusing — and naming the RESULT as its subject,
    // because the summary directly above it reads `500 B → 2 MB` and "that file
    // is 2 MB" would point at the one the reader chose.
    const refusal = within(review).getByTestId('transform-refusal');
    expect(refusal).toHaveTextContent(
      'The formatted file is 2 MB. This server accepts documents up to 1 MB.',
    );
    // The picked-file guardrail still says what it always said.
    expect(screen.getByTestId('upload-guardrail-note')).toHaveTextContent(
      'Up to 1 MB per document, checked here before the file is read.',
    );
    expect(refusal).toHaveAttribute('role', 'alert');

    // …and the way forward is the one that was always going to work: the file
    // as it was picked, which passed the cap before a byte of it was read.
    fireEvent.click(screen.getByRole('button', { name: /Upload the original unchanged/ }));
    await waitFor(() => {
      expect(startUpload).toHaveBeenCalledTimes(1);
    });
    const [input] = startUpload.mock.calls[0] as [Record<string, unknown>];
    expect(input.source).toBeInstanceOf(File);
    expect(input).not.toHaveProperty('transform');
  });

  it('draws the transformed-size ceiling AT the bound, not near it', async () => {
    // n and n+1 on the blob the transform produced. The comparison is
    // `size > maxSizeBytes`, the same one `refusalFor` makes, so a result of
    // exactly the cap is still offered and one byte more is not.
    const cap = 1024 * 1024;
    harness.transformDocument.mockResolvedValue(reviewOfSize(cap));
    const { unmount } = renderPanel({ ...ENABLED_CONFIG, maxSizeMB: 1 });
    pick('config.json', 500);
    fireEvent.click(screen.getByLabelText(/Format this document/));
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));
    let review = await screen.findByTestId('transform-review');
    expect(
      within(review).getByRole('button', { name: /Upload the formatted file/ }),
    ).toBeInTheDocument();
    expect(within(review).queryByTestId('transform-refusal')).not.toBeInTheDocument();
    unmount();

    harness.transformDocument.mockResolvedValue(reviewOfSize(cap + 1));
    renderPanel({ ...ENABLED_CONFIG, maxSizeMB: 1 });
    pick('config.json', 500);
    fireEvent.click(screen.getByLabelText(/Format this document/));
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));
    review = await screen.findByTestId('transform-review');
    expect(
      within(review).queryByRole('button', { name: /Upload the formatted file/ }),
    ).not.toBeInTheDocument();
    expect(within(review).getByTestId('transform-refusal')).toBeInTheDocument();
  });

  it('offers the confirm as usual when the server advertises no cap at all', async () => {
    // `maxSizeMB` is optional, and a server that does not advertise one has no
    // number to compare against — the transformed blob must not be refused by a
    // comparison against `null`.
    harness.transformDocument.mockResolvedValue(reviewOfSize(4 * 1024 * 1024));
    const noCap: DocumentsConfig = { ...ENABLED_CONFIG };
    delete noCap.maxSizeMB;
    renderPanel(noCap);
    // The guardrail note says so too, rather than quoting a limit that is not there.
    expect(screen.getByTestId('upload-guardrail-note')).toHaveTextContent(
      'Every file is encrypted in your browser before any of it is sent.',
    );
    pick('config.json', 500);
    fireEvent.click(screen.getByLabelText(/Format this document/));
    fireEvent.click(screen.getByRole('button', { name: /Prepare and review/ }));

    const review = await screen.findByTestId('transform-review');
    expect(
      within(review).getByRole('button', { name: /Upload the formatted file/ }),
    ).toBeInTheDocument();
    expect(within(review).queryByTestId('transform-refusal')).not.toBeInTheDocument();
  });
});

/* ========================================================================== */
/*  DocumentsPage — the rail, the four modes, and the trash                    */
/* ========================================================================== */

describe('DocumentsPage — the surface the folder, the favorite and the trash lead to', () => {
  const filed = () =>
    makeDocument({
      id: 'doc-filed',
      folderId: FOLDER_ID,
      meta: { ...makeDocument().meta!, name: 'return.pdf' },
    });
  const starred = () =>
    makeDocument({
      id: 'doc-star',
      favorite: true,
      meta: { ...makeDocument().meta!, name: 'payslip.pdf' },
    });
  const loose = () =>
    makeDocument({ id: 'doc-loose', meta: { ...makeDocument().meta!, name: 'notes.pdf' } });
  const binned = () =>
    makeDocument({
      id: 'doc-binned',
      deletedAt: '2026-03-01T00:00:00.000Z',
      meta: { ...makeDocument().meta!, name: 'old.pdf' },
    });

  /**
   * Seed the store, then render.
   *
   * The three fetches are stubbed because the page calls them on mount and the
   * REAL `fetchDocuments` starts by emptying the list — which would wipe the rows
   * these cases are about before the first paint.
   */
  async function renderWith(state: Partial<ReturnType<typeof useDocumentsStore.getState>>) {
    useDocumentsStore.setState({
      fetchDocuments: vi.fn().mockResolvedValue(undefined),
      fetchTrash: vi.fn().mockResolvedValue(undefined),
      fetchUsage: vi.fn().mockResolvedValue(undefined),
      ...state,
    });
    renderPage();
    await screen.findByRole('heading', { name: 'Documents' });
  }

  const names = () => screen.queryAllByTestId('document-name').map((n) => n.textContent);

  it('counts every entry in the rail, and counts a folder by ACTIVE rows only', async () => {
    await renderWith({
      documents: [filed(), starred(), loose()],
      // The second trashed row still NAMES the folder, exactly as the server
      // leaves it: `deleteFolder`'s member filter excludes rows that already
      // carry `deletedAt`, so a trashed document keeps a folder id that may no
      // longer exist. That is what makes the badge's "active rows only" claim
      // testable rather than incidental.
      trashDocuments: [binned(), makeDocument({ id: 'x', deletedAt: 'y', folderId: FOLDER_ID })],
      trashLoaded: true,
    });

    expect(screen.getByRole('button', { name: /^All Documents/ })).toHaveTextContent('3');
    expect(screen.getByRole('button', { name: /^Favorites/ })).toHaveTextContent('1');
    expect(screen.getByRole('button', { name: /^Trash/ })).toHaveTextContent('2');
    // A badge that counted the trash would promise more than the folder shows.
    expect(screen.getByRole('button', { name: /^Taxes/ })).toHaveTextContent('1');
  });

  it('shows the right rows in each of the four modes', async () => {
    await renderWith({
      documents: [filed(), starred(), loose()],
      trashDocuments: [binned()],
      trashLoaded: true,
    });
    expect(names()).toHaveLength(3);

    fireEvent.click(screen.getByRole('button', { name: /^Favorites/ }));
    expect(names()).toEqual(['payslip.pdf']);

    fireEvent.click(screen.getByRole('button', { name: /^Taxes/ }));
    expect(names()).toEqual(['return.pdf']);
    // Exclusive: choosing a folder turns Favorites off, so nothing is filtered twice.
    expect(screen.getByRole('button', { name: /^Favorites/ })).not.toHaveAttribute('aria-current');

    fireEvent.click(screen.getByRole('button', { name: /^Trash/ }));
    expect(names()).toEqual(['old.pdf']);

    fireEvent.click(screen.getByRole('button', { name: /^All Documents/ }));
    expect(names()).toHaveLength(3);
  });

  it('shows where a document is filed, and nothing when it is filed nowhere', async () => {
    await renderWith({ documents: [filed(), loose()] });

    const chips = screen.getAllByTestId('document-folder');
    expect(chips).toHaveLength(1);
    expect(chips[0]).toHaveTextContent('Taxes');
  });

  it('dates an active row by when it changed and a trashed one by when it went', async () => {
    await renderWith({ documents: [loose()], trashDocuments: [binned()], trashLoaded: true });
    // Both directions, so an implementation keyed on the MODE rather than on the
    // row's own `deletedAt` fails here.
    expect(screen.getByTestId('document-row')).not.toHaveTextContent('Deleted');

    fireEvent.click(screen.getByRole('button', { name: /^Trash/ }));
    expect(screen.getByTestId('document-row')).toHaveTextContent(/Deleted/);
  });

  it('says a row already being destroyed is being destroyed', async () => {
    await renderWith({
      trashDocuments: [{ ...binned(), purgePending: true }],
      trashLoaded: true,
      showTrash: true,
    });
    expect(screen.getByTestId('document-row')).toHaveTextContent('Being deleted');
  });

  it('keeps every row a single link with no other control, in every mode', async () => {
    await renderWith({ documents: [loose()], trashDocuments: [binned()], trashLoaded: true });

    for (const mode of [/^All Documents/, /^Trash/]) {
      fireEvent.click(screen.getByRole('button', { name: mode }));
      const row = screen.getByTestId('document-row');
      // The row is an anchor precisely so it gets keyboard activation,
      // middle-click and open-in-a-new-tab for free; a control inside it would
      // nest one interactive element in another and cost all three.
      expect(within(row).getAllByRole('link')).toHaveLength(1);
      expect(within(row).queryAllByRole('button')).toHaveLength(0);
    }
  });

  it('explains an empty list differently in each mode', async () => {
    await renderWith({ documents: [], trashDocuments: [], trashLoaded: true });
    expect(screen.getByText('No documents yet')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Favorites/ }));
    expect(screen.getByText('No favorite documents')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Taxes/ }));
    expect(screen.getByText('Nothing in “Taxes”')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Trash/ }));
    expect(screen.getByText('The trash is empty')).toBeInTheDocument();
    expect(screen.getByText(/permanently removed after 30 days/)).toBeInTheDocument();
  });

  it('filters by name, tag and note, and finds nothing in a document it cannot open', async () => {
    const tagged = makeDocument({
      id: 'doc-tag',
      meta: { ...makeDocument().meta!, name: 'invoice.pdf', tags: ['hmrc'], note: 'paid in April' },
    });
    await renderWith({
      documents: [loose(), tagged, makeDocument({ id: 'doc-dead', meta: null })],
    });
    expect(names()).toHaveLength(3);

    const search = screen.getByRole('searchbox', { name: 'Search documents' });
    fireEvent.change(search, { target: { value: 'hmrc' } });
    await waitFor(() => {
      expect(names()).toEqual(['invoice.pdf']);
    });

    fireEvent.change(search, { target: { value: 'april' } });
    await waitFor(() => {
      expect(names()).toEqual(['invoice.pdf']);
    });

    // A document whose metadata will not open has no text to match — and says so
    // through the count, rather than being quietly absent.
    fireEvent.change(search, { target: { value: 'zzz' } });
    await waitFor(() => {
      expect(screen.getByText('No documents match')).toBeInTheDocument();
    });
  });

  it('offers Empty trash only in the trash, and only when there is something in it', async () => {
    await renderWith({ documents: [loose()], trashDocuments: [binned()], trashLoaded: true });
    expect(screen.queryByRole('button', { name: 'Empty trash' })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Trash/ }));
    expect(screen.getByRole('button', { name: 'Empty trash' })).toBeInTheDocument();

    act(() => {
      useDocumentsStore.setState({ trashDocuments: [] });
    });
    expect(screen.queryByRole('button', { name: 'Empty trash' })).not.toBeInTheDocument();
  });

  it('does not draw the picker over the trash, but never hides a live transfer', async () => {
    await renderWith({
      documents: [loose()],
      trashDocuments: [binned()],
      trashLoaded: true,
      uploads: {
        u1: { id: 'u1', fileName: 'big.bin', totalBytes: 100, sentBytes: 50, status: 'uploading' },
      },
    });
    expect(screen.getByLabelText('File to upload')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Trash/ }));

    // Uploading into a view of deleted files is incoherent, so the picker goes.
    expect(screen.queryByLabelText('File to upload')).not.toBeInTheDocument();
    // But a transfer outlives the page that started it, and one that vanished
    // here would read as a cancelled upload.
    expect(screen.getByRole('list', { name: 'Uploads in progress' })).toBeInTheDocument();
    expect(screen.getByText('big.bin')).toBeInTheDocument();
  });

  it('mounts the transfer list exactly once, whichever mode is showing', async () => {
    // `DocumentTransfers` has TWO mount points — inside the upload panel, and on
    // its own in trash mode — and it self-hides when the registry is empty, so a
    // ternary that became an unconditional render would double it silently. The
    // end-to-end suite counts `upload-row`, so the symptom there would be a
    // confusing number rather than a named failure.
    await renderWith({
      documents: [loose()],
      trashDocuments: [binned()],
      trashLoaded: true,
      uploads: {
        u1: { id: 'u1', fileName: 'big.bin', totalBytes: 100, sentBytes: 50, status: 'uploading' },
      },
    });

    for (const mode of [/^All Documents/, /^Favorites/, /^Taxes/, /^Trash/]) {
      fireEvent.click(screen.getByRole('button', { name: mode }));
      expect(screen.getAllByRole('list', { name: 'Uploads in progress' })).toHaveLength(1);
      expect(screen.getAllByTestId('upload-row')).toHaveLength(1);
    }
  });

  it('empties the trash, then re-reads the allowance it just released', async () => {
    const emptyTrash = vi.fn().mockResolvedValue({ deletedCount: 2, failedCount: 0 });
    const fetchUsage = vi.fn().mockResolvedValue(undefined);
    await renderWith({
      trashDocuments: [binned()],
      trashLoaded: true,
      showTrash: true,
      emptyTrash: emptyTrash as unknown as ReturnType<
        typeof useDocumentsStore.getState
      >['emptyTrash'],
      fetchUsage,
    });

    fireEvent.click(screen.getByRole('button', { name: 'Empty trash' }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent('Nothing can bring them back');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete all forever' }));

    await waitFor(() => {
      expect(emptyTrash).toHaveBeenCalledTimes(1);
    });
    // The quota bar's own sentence says a trashed document still counts against
    // the allowance, so leaving that number stale would contradict the text
    // printed beside it.
    await waitFor(() => {
      expect(fetchUsage).toHaveBeenCalled();
    });
    await waitFor(() => {
      expect(harness.toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: '2 document(s) permanently deleted', type: 'success' }),
      );
    });
    // And the dialog closes rather than sitting over an emptied list.
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
  });

  it('destroys nothing when the reader backs out of the confirmation', async () => {
    const emptyTrash = vi.fn().mockResolvedValue({ deletedCount: 0, failedCount: 0 });
    await renderWith({
      trashDocuments: [binned()],
      trashLoaded: true,
      showTrash: true,
      emptyTrash: emptyTrash as unknown as ReturnType<
        typeof useDocumentsStore.getState
      >['emptyTrash'],
    });

    fireEvent.click(screen.getByRole('button', { name: 'Empty trash' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));

    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
    // The negative that matters on an irreversible action: backing out of the
    // dialog destroys nothing, and the row is still listed afterwards.
    expect(emptyTrash).not.toHaveBeenCalled();
    expect(screen.getAllByTestId('document-name')).toHaveLength(1);
  });

  it('says how many survived when the storage engine could not remove them all', async () => {
    const emptyTrash = vi.fn().mockResolvedValue({ deletedCount: 1, failedCount: 1 });
    await renderWith({
      trashDocuments: [binned()],
      trashLoaded: true,
      showTrash: true,
      emptyTrash: emptyTrash as unknown as ReturnType<
        typeof useDocumentsStore.getState
      >['emptyTrash'],
    });

    fireEvent.click(screen.getByRole('button', { name: 'Empty trash' }));
    fireEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', {
        name: 'Delete all forever',
      }),
    );

    // A partial run reported as a clean one is the dishonesty the server's own
    // `failedCount` exists to prevent — the rows it could not remove are still
    // there, still listed and still occupying storage.
    //
    // The sentence promises nothing about the residue, and that is the assertion.
    // The server's walk gives up once storage has refused several deletes in a
    // row, so `failedCount` counts only what it ATTEMPTED; the rows past that
    // point carry no `purgePending` marker and the hourly collector will never
    // look at them. A message saying they "will be cleaned up automatically"
    // would be a promise this system does not keep, told to a user who is at that
    // moment looking at a refreshed list that still holds every one of them.
    await waitFor(() => {
      expect(harness.toast).toHaveBeenCalledWith(
        expect.objectContaining({
          title:
            '1 deleted. 1 could not be removed — the trash has been refreshed to show what is still there.',
          type: 'warning',
        }),
      );
    });
    expect(harness.toast).not.toHaveBeenCalledWith(
      expect.objectContaining({ title: expect.stringContaining('cleaned up automatically') }),
    );
  });

  it('reports a refused empty rather than leaving the button spinning', async () => {
    // Rejected with something carrying no usable message, so the page's own
    // fallback is what is asserted rather than `getApiErrorMessage`'s passthrough.
    const emptyTrash = vi.fn().mockRejectedValue({});
    await renderWith({
      trashDocuments: [binned()],
      trashLoaded: true,
      showTrash: true,
      emptyTrash: emptyTrash as unknown as ReturnType<
        typeof useDocumentsStore.getState
      >['emptyTrash'],
    });

    fireEvent.click(screen.getByRole('button', { name: 'Empty trash' }));
    fireEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', {
        name: 'Delete all forever',
      }),
    );

    await waitFor(() => {
      expect(harness.toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'The trash could not be emptied', type: 'error' }),
      );
    });
    // The `finally` runs on this path too: the dialog closes and the confirm
    // button is not left disabled for ever.
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
  });

  it('names the list after the mode it is showing', async () => {
    // One row in EVERY mode, so each assertion is about the list's name rather
    // than about an empty state that happens to have no list at all.
    await renderWith({
      documents: [loose(), starred(), filed()],
      trashDocuments: [binned()],
      trashLoaded: true,
    });
    expect(screen.getByRole('list', { name: 'Documents list' })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Favorites/ }));
    expect(screen.getByRole('list', { name: 'Favorite documents' })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Taxes/ }));
    expect(screen.getByRole('list', { name: 'Documents in Taxes' })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Trash/ }));
    expect(screen.getByRole('list', { name: 'Documents in the trash' })).toBeInTheDocument();
  });

  it('tells the uploader which folder a file will be filed in, and sends it', async () => {
    const startUpload = vi.fn().mockResolvedValue('u1');
    await renderWith({
      documents: [],
      startUpload: startUpload as unknown as ReturnType<
        typeof useDocumentsStore.getState
      >['startUpload'],
    });

    fireEvent.click(screen.getByRole('button', { name: /^Taxes/ }));
    expect(screen.getByTestId('upload-target-folder')).toHaveTextContent('Taxes');

    pick('return.pdf', 1024);
    fireEvent.click(screen.getByRole('button', { name: /^Upload$/ }));

    await waitFor(() => {
      expect(startUpload).toHaveBeenCalledWith(expect.objectContaining({ folderId: FOLDER_ID }));
    });
  });
});
