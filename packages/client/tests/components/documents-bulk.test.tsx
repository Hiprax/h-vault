/**
 * The Documents page's multi-select and bulk actions (`DocumentSelectionBar`,
 * `useDocumentSelection`, `lib/documentBulk.ts`).
 *
 * ## How this suite is wired, and why
 *
 * The page renders for real, and so do the documents store's per-row actions
 * (`deleteDocument`, `restoreDocument`, `purgeDocument`, `moveToFolder`): only
 * the HTTP functions under them are replaced, so each bulk action is observed
 * doing what the store does for one row, with its list moves and its lock
 * generation intact, and `sendPaced` paces it for real. The one action replaced
 * through the store's own seam is `updateDocumentMeta`, which re-seals a blob
 * under a document's own key: its crypto has its own suite
 * (`documents-store.test.ts`), and what matters here is which rows the bulk tag
 * asks it to change, with what.
 *
 * Every pace is real and short: the stub answers after a microtask, or after a
 * 5 ms timer where an ordering between a refusal and the rows already in flight
 * is what a case is about. The list fetches are stubbed as in
 * `documents-upload.test.tsx`, because the rows are seeded.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import React from 'react';
import { AxiosError, AxiosHeaders } from 'axios';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES, MAX_DOCUMENT_TAGS } from '@hvault/shared';
import type { DocumentMeta, DocumentResponse } from '@hvault/shared';

const harness = vi.hoisted(() => ({
  toast: vi.fn(),
  getDocumentsConfig: vi.fn(),
  /** Answers each per-row request; replaced per case. */
  answer: null as null | ((call: { kind: string; id: string; body?: unknown }) => Promise<unknown>),
  calls: [] as { kind: string; id: string; body?: unknown }[],
  inFlight: 0,
  peak: 0,
}));

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
vi.mock('../../src/stores/heldVaultKey', () => ({
  checkHeldVaultKey: vi.fn(),
  resetHeldVaultKeyChecks: vi.fn(),
}));
vi.mock('../../src/services/api/configApi', () => ({
  getDocumentsConfig: harness.getDocumentsConfig,
}));
vi.mock('../../src/hooks/useUserSettings', () => ({
  useUserSettings: () => ({
    autoLockTimeout: 15,
    lockOnHidden: false,
    lockOnHiddenDelay: 1,
    clipboardClearTimeout: 30,
    theme: 'system',
  }),
}));
vi.mock('../../src/hooks/useConnectionStatus', () => ({
  useConnectionStatus: () => ({ isOnline: true }),
}));
vi.mock('../../src/components/ui/Toast', () => ({
  useToast: () => ({ toast: harness.toast, dismiss: vi.fn(), update: vi.fn() }),
}));
vi.mock('../../src/lib/lazyUploadRecovery', () => ({
  loadUploadRecovery: () => new Promise(() => undefined),
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
      Array.from({ length: rowCount }, (_, index) =>
        React.createElement(Row, {
          key: index,
          index,
          style: {},
          ariaAttributes: { role: 'listitem' },
          ...rowProps,
        }),
      ),
    ),
}));

/** One per-row request through the stubbed transport, counting what is in flight. */
async function request(kind: string, id: string, body?: unknown): Promise<unknown> {
  const call = body === undefined ? { kind, id } : { kind, id, body };
  harness.calls.push(call);
  harness.inFlight += 1;
  harness.peak = Math.max(harness.peak, harness.inFlight);
  try {
    return await harness.answer!(call);
  } finally {
    harness.inFlight -= 1;
  }
}

vi.mock('../../src/services/api/documentsApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/services/api/documentsApi')>()),
  deleteDocumentApi: (id: string) => request('delete', id),
  restoreDocumentApi: (id: string) => request('restore', id),
  purgeDocumentApi: (id: string) => request('purge', id),
  updateDocumentApi: (id: string, body: unknown) => request('update', id, body),
}));

import DocumentsPage from '../../src/pages/DocumentsPage';
import { useDocumentsStore, type DecryptedDocument } from '../../src/stores/documentsStore';
import { BULK_REQUEST_CONCURRENCY, useVaultStore } from '../../src/stores/vaultStore';
import { useAuthStore } from '../../src/stores/authStore';
import {
  BEING_DELETED_MESSAGE,
  BULK_REPORT_DURATION_MS,
  ROW_GONE_MESSAGE,
  SERVER_STOPPED_MESSAGE,
  UNOPENABLE_TAG_MESSAGE,
  describeBulkOutcome,
} from '../../src/lib/documentBulk';
import { BULK_ABANDONED_MESSAGE } from '../../src/stores/vaultStore';

/* -------------------------------------------------------------------------- */
/*  Fixtures                                                                   */
/* -------------------------------------------------------------------------- */

const pristineDocuments = useDocumentsStore.getState();
const pristineVault = useVaultStore.getState();
const pristineAuth = useAuthStore.getState();

const hex = (n: number): string => n.toString(16).padStart(24, '0');
const FOLDER_ID = 'f'.repeat(24);

function raw(id: string, extra: Partial<DocumentResponse> = {}): DocumentResponse {
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
    ...extra,
  };
}

function meta(name: string, tags: string[] = []): DocumentMeta {
  return {
    name,
    mime: 'application/pdf',
    ext: 'pdf',
    plaintextBytes: 2048,
    sha256: '0'.repeat(64),
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount: 1,
    tags,
    capturedAt: '2026-01-01T00:00:00.000Z',
  };
}

function doc(
  n: number,
  options: {
    tags?: string[];
    degraded?: boolean;
    folderId?: string;
    favorite?: boolean;
    trashed?: boolean;
    purgePending?: boolean;
  } = {},
): DecryptedDocument {
  const id = hex(n);
  return {
    id,
    favorite: options.favorite ?? false,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-02-03T00:00:00.000Z',
    ...(options.folderId === undefined ? {} : { folderId: options.folderId }),
    ...(options.trashed === true ? { deletedAt: '2026-03-01T00:00:00.000Z' } : {}),
    ...(options.purgePending === undefined ? {} : { purgePending: options.purgePending }),
    meta: options.degraded === true ? null : meta(`doc-${String(n)}.pdf`, options.tags),
    _raw: raw(id, {
      ...(options.folderId === undefined ? {} : { folderId: options.folderId }),
      ...(options.trashed === true ? { deletedAt: '2026-03-01T00:00:00.000Z' } : {}),
    }),
  };
}

const range = (count: number, from = 1): number[] =>
  Array.from({ length: count }, (_, i) => from + i);

/** An answer that succeeds after a microtask, the way each route answers. */
function succeed(call: { kind: string; id: string; body?: unknown }): Promise<unknown> {
  return Promise.resolve().then(() => {
    if (call.kind === 'update') {
      const body = call.body as { folderId?: string | null };
      return {
        data: {
          success: true,
          data: raw(call.id, body.folderId ? { folderId: body.folderId } : {}),
        },
      };
    }
    if (call.kind === 'restore') return { data: { success: true, data: raw(call.id) } };
    return { data: { success: true, data: null } };
  });
}

function httpError(status: number, message: string, headers: Record<string, string> = {}) {
  const error = new AxiosError(`Request failed with status code ${String(status)}`);
  error.response = {
    status,
    statusText: '',
    data: { success: false, message, statusCode: status, statusText: '' },
    headers: new AxiosHeaders(headers),
    config: { headers: new AxiosHeaders() },
  };
  return error;
}

const later = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

async function renderWith(state: Partial<ReturnType<typeof useDocumentsStore.getState>>) {
  useDocumentsStore.setState({
    fetchDocuments: vi.fn().mockResolvedValue(undefined),
    fetchTrash: vi.fn().mockResolvedValue(undefined),
    fetchUsage: vi.fn().mockResolvedValue(undefined),
    ...state,
  });
  render(
    <MemoryRouter>
      <DocumentsPage />
    </MemoryRouter>,
  );
  await screen.findByRole('heading', { name: 'Documents' });
  // One microtask for the config hook's `.then`, as `documents-upload.test.tsx`
  // records at length.
  await act(async () => {
    await Promise.resolve();
  });
}

const rows = (): HTMLElement[] => screen.queryAllByTestId('document-row');
const checkbox = (name: string): HTMLInputElement =>
  screen.getByRole('checkbox', { name: `Select ${name}` });
const bar = (): HTMLElement => screen.getByTestId('documents-selection-bar');
const lastToast = (): Record<string, unknown> =>
  harness.toast.mock.calls.at(-1)![0] as Record<string, unknown>;

function selectAll(): void {
  fireEvent.click(checkbox(within(rows()[0]!).getByTestId('document-name').textContent!));
  fireEvent.click(screen.getByRole('checkbox', { name: 'Select all' }));
}

/**
 * Searches as the search box does once its debounce fires: through the store's
 * own setter, so a case reads the narrowed list without waiting on a timer.
 */
function search(query: string): void {
  act(() => useDocumentsStore.getState().setSearchQuery(query));
}

/**
 * Confirms with `setTimeout` faked from the press on, so a case can drive
 * `sendPaced`'s waits with the clock instead of sleeping. Restored by the caller.
 */
async function confirmOnFakeClock(label: string): Promise<void> {
  const dialog = await screen.findByRole('dialog');
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  await act(async () => {
    fireEvent.click(within(dialog).getByRole('button', { name: label }));
  });
}

async function advance(ms: number): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

async function confirm(label: string): Promise<void> {
  const dialog = await screen.findByRole('dialog');
  await act(async () => {
    fireEvent.click(within(dialog).getByRole('button', { name: label }));
  });
}

beforeEach(async () => {
  vi.clearAllMocks();
  harness.calls = [];
  harness.inFlight = 0;
  harness.peak = 0;
  harness.answer = succeed;
  harness.getDocumentsConfig.mockResolvedValue({
    enabled: true,
    maxSizeMB: 100,
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    maxDocuments: 5000,
    quotaMB: 2048,
    allowedExtensions: [],
  });
  useDocumentsStore.setState(pristineDocuments, true);
  useVaultStore.setState(pristineVault, true);
  useVaultStore.setState({
    folders: [
      { id: FOLDER_ID, name: 'Taxes', sortOrder: 0, createdAt: 'x', updatedAt: 'x' },
    ] as never,
  });
  const vaultKey = await globalThis.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
  useAuthStore.setState({ vaultKey, vaultKeyVersion: 0 });
});

afterEach(() => {
  cleanup();
  useAuthStore.setState(pristineAuth, true);
});

/* ========================================================================== */
/*  Delete, restore, delete forever                                           */
/* ========================================================================== */

describe('bulk delete to the trash', () => {
  it('sends one request per selected document, at most the paced number at once, and moves each to the trash', async () => {
    const documents = range(9).map((n) => doc(n));
    await renderWith({ documents, trashDocuments: [], trashLoaded: true });
    selectAll();
    expect(within(bar()).getByText('9 selected')).toBeInTheDocument();

    fireEvent.click(within(bar()).getByRole('button', { name: 'Delete' }));
    expect(await screen.findByRole('dialog')).toHaveTextContent('Move 9 documents to the trash');
    await confirm('Move to trash');

    await waitFor(() =>
      expect(lastToast()).toMatchObject({
        title: '9 documents moved to the trash',
        type: 'success',
      }),
    );
    expect(harness.calls.map((call) => call.id).sort()).toEqual(documents.map((d) => d.id).sort());
    expect(harness.calls.every((call) => call.kind === 'delete')).toBe(true);
    expect(harness.peak).toBe(BULK_REQUEST_CONCURRENCY);
    expect(useDocumentsStore.getState().documents).toEqual([]);
    expect(useDocumentsStore.getState().trashDocuments).toHaveLength(9);
    expect(screen.queryByTestId('documents-selection-bar')).not.toBeInTheDocument();
  });

  it('sends each document once when the confirm button is pressed twice in one frame, and keeps the dialog up until the run ends', async () => {
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    harness.answer = async (call) => {
      await held;
      return succeed(call);
    };
    await renderWith({ documents: range(3).map((n) => doc(n)) });
    selectAll();
    fireEvent.click(within(bar()).getByRole('button', { name: 'Delete' }));
    const dialog = await screen.findByRole('dialog');
    const button = within(dialog).getByRole('button', { name: 'Move to trash' });

    await act(async () => {
      button.click();
      button.click();
    });
    // The refused second press does not close the dialog the running one owns.
    expect(screen.getByRole('dialog')).toBeInTheDocument();

    await act(async () => {
      release();
      await later(5);
    });
    await waitFor(() => expect(harness.toast).toHaveBeenCalledTimes(1));
    expect(harness.calls).toHaveLength(3);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('keeps a running action guarded when the bar is closed and opened again mid-run', async () => {
    // The guard lives on the page: Clear unmounts the bar, a new tick mounts a
    // fresh one, and that one must still know a run is going.
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    harness.answer = async (call) => {
      await held;
      return succeed(call);
    };
    await renderWith({
      documents: [],
      trashDocuments: range(3).map((n) => doc(n, { trashed: true })),
      trashLoaded: true,
    });
    fireEvent.click(screen.getByRole('button', { name: /^Trash/ }));
    fireEvent.click(checkbox('doc-1.pdf'));
    fireEvent.click(checkbox('doc-2.pdf'));
    await act(async () => {
      fireEvent.click(within(bar()).getByRole('button', { name: 'Restore' }));
    });

    fireEvent.click(within(bar()).getByRole('button', { name: 'Clear' }));
    expect(screen.queryByTestId('documents-selection-bar')).not.toBeInTheDocument();
    fireEvent.click(checkbox('doc-3.pdf'));
    const restore = within(bar()).getByRole('button', { name: 'Restore' });
    expect(restore).toBeDisabled();
    fireEvent.click(restore);
    expect(harness.calls.map((call) => call.id)).toEqual([hex(1), hex(2)]);

    await act(async () => {
      release();
      await later(5);
    });
    await waitFor(() => expect(lastToast()).toMatchObject({ title: '2 documents restored' }));
    expect(within(bar()).getByRole('button', { name: 'Restore' })).toBeEnabled();
    expect(harness.calls).toHaveLength(2);
  });

  it('reports a refused row by its reason, keeps it selected and still sends the rest', async () => {
    harness.answer = (call) =>
      call.id === hex(2) ? Promise.reject(httpError(404, 'Document not found')) : succeed(call);
    await renderWith({ documents: range(3).map((n) => doc(n)) });
    selectAll();
    fireEvent.click(within(bar()).getByRole('button', { name: 'Delete' }));
    await confirm('Move to trash');

    await waitFor(() =>
      expect(lastToast()).toMatchObject({
        title: '2 of 3 documents moved to the trash; 1 could not be.',
        description: 'Document not found',
        type: 'warning',
      }),
    );
    expect(harness.calls).toHaveLength(3);
    expect(within(bar()).getByText('1 selected')).toBeInTheDocument();
    expect(checkbox('doc-2.pdf')).toBeChecked();
  });
});

describe('the confirmations', () => {
  for (const [mode, open, confirmLabel] of [
    ['active', 'Delete', 'Move to trash'],
    ['trash', 'Delete forever', 'Delete forever'],
  ] as const) {
    it(`${open}: Cancel and Escape send nothing and keep the selection`, async () => {
      await renderWith({
        documents: mode === 'active' ? [doc(1), doc(2)] : [],
        trashDocuments:
          mode === 'trash' ? [doc(1, { trashed: true }), doc(2, { trashed: true })] : [],
        trashLoaded: true,
      });
      if (mode === 'trash') fireEvent.click(screen.getByRole('button', { name: /^Trash/ }));
      selectAll();

      fireEvent.click(within(bar()).getByRole('button', { name: open }));
      fireEvent.click(
        within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }),
      );
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

      fireEvent.click(within(bar()).getByRole('button', { name: open }));
      await screen.findByRole('dialog');
      fireEvent.keyDown(document, { key: 'Escape' });
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

      expect(harness.calls).toEqual([]);
      expect(within(bar()).getByText('2 selected')).toBeInTheDocument();
    });

    it(`${open}: stays up while it runs, with Cancel and Escape held, then hands focus to the heading`, async () => {
      let release!: () => void;
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      harness.answer = async (call) => {
        await held;
        return succeed(call);
      };
      await renderWith({
        documents: mode === 'active' ? [doc(1), doc(2)] : [],
        trashDocuments:
          mode === 'trash' ? [doc(1, { trashed: true }), doc(2, { trashed: true })] : [],
        trashLoaded: true,
      });
      if (mode === 'trash') fireEvent.click(screen.getByRole('button', { name: /^Trash/ }));
      selectAll();
      fireEvent.click(within(bar()).getByRole('button', { name: open }));
      await confirm(confirmLabel);

      const dialog = screen.getByRole('dialog');
      expect(within(dialog).getByRole('button', { name: 'Cancel' })).toBeDisabled();
      fireEvent.keyDown(document, { key: 'Escape' });
      expect(screen.getByRole('dialog')).toBeInTheDocument();

      await act(async () => {
        release();
        await later(5);
      });
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
      expect(harness.calls).toHaveLength(2);
      expect(screen.getByRole('heading', { name: 'Documents' })).toHaveFocus();
    });
  }
});

describe('the confirmations for one document', () => {
  it('speak of it, not them', async () => {
    await renderWith({
      documents: [doc(1)],
      trashDocuments: [doc(2, { trashed: true })],
      trashLoaded: true,
    });
    fireEvent.click(checkbox('doc-1.pdf'));
    fireEvent.click(within(bar()).getByRole('button', { name: 'Delete' }));
    const trash = await screen.findByRole('dialog');
    expect(trash).toHaveTextContent('Move 1 document to the trash');
    expect(trash).toHaveTextContent('It stays in the trash');
    expect(trash).toHaveTextContent('it still occupies storage and still counts');
    fireEvent.click(within(trash).getByRole('button', { name: 'Cancel' }));

    fireEvent.click(screen.getByRole('button', { name: /^Trash/ }));
    fireEvent.click(checkbox('doc-2.pdf'));
    fireEvent.click(within(bar()).getByRole('button', { name: 'Delete forever' }));
    const purge = await screen.findByRole('dialog');
    expect(purge).toHaveTextContent('Delete 1 document for good');
    expect(purge).toHaveTextContent(
      'Nothing on the server can bring it back; only a full backup saved before it went to the trash still holds it. The storage it occupies is released.',
    );
  });
});

describe('focus when selection mode ends', () => {
  it('is left where the person is typing, not moved to the heading', async () => {
    await renderWith({ documents: [doc(1), doc(2)] });
    fireEvent.click(checkbox('doc-1.pdf'));
    const searchBox = screen.getByRole('searchbox', { name: 'Search documents' });
    searchBox.focus();

    search('doc-2');

    expect(screen.queryByTestId('documents-selection-bar')).not.toBeInTheDocument();
    expect(searchBox).toHaveFocus();
  });
});

describe('in the trash', () => {
  it('restores the selected documents, skipping one already being deleted with the reason', async () => {
    const trash = [
      doc(1, { trashed: true }),
      doc(2, { trashed: true, purgePending: true }),
      doc(3, { trashed: true }),
    ];
    await renderWith({ documents: [], trashDocuments: trash, trashLoaded: true });
    fireEvent.click(screen.getByRole('button', { name: /^Trash/ }));
    selectAll();

    await act(async () => {
      fireEvent.click(within(bar()).getByRole('button', { name: 'Restore' }));
    });

    await waitFor(() =>
      expect(lastToast()).toMatchObject({
        title: '2 of 3 documents restored; 1 could not be.',
        description: BEING_DELETED_MESSAGE,
        type: 'warning',
      }),
    );
    // The row being destroyed was never sent: the server would only answer 404.
    expect(harness.calls.map((call) => [call.kind, call.id])).toEqual([
      ['restore', hex(1)],
      ['restore', hex(3)],
    ]);
    expect(useDocumentsStore.getState().trashDocuments.map((d) => d.id)).toEqual([hex(2)]);
    expect(within(bar()).getByText('1 selected')).toBeInTheDocument();
  });

  it('reports a restore the server refused (404) by its reason, and keeps that one selected', async () => {
    harness.answer = (call) =>
      call.id === hex(2) ? Promise.reject(httpError(404, 'Document not found')) : succeed(call);
    await renderWith({
      documents: [],
      trashDocuments: [doc(1, { trashed: true }), doc(2, { trashed: true })],
      trashLoaded: true,
    });
    fireEvent.click(screen.getByRole('button', { name: /^Trash/ }));
    selectAll();
    await act(async () => {
      fireEvent.click(within(bar()).getByRole('button', { name: 'Restore' }));
    });

    await waitFor(() =>
      expect(lastToast()).toMatchObject({
        title: '1 of 2 documents restored; 1 could not be.',
        description: 'Document not found',
        type: 'warning',
      }),
    );
    expect(within(bar()).getByText('1 selected')).toBeInTheDocument();
  });

  it('deletes the selected documents for good after a confirmation that says so, then re-reads the storage used', async () => {
    const fetchUsage = vi.fn().mockResolvedValue(undefined);
    await renderWith({
      documents: [],
      trashDocuments: range(5).map((n) => doc(n, { trashed: true })),
      trashLoaded: true,
      fetchUsage,
    });
    fireEvent.click(screen.getByRole('button', { name: /^Trash/ }));
    selectAll();
    fetchUsage.mockClear();

    fireEvent.click(within(bar()).getByRole('button', { name: 'Delete forever' }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent('Delete 5 documents for good');
    expect(dialog).toHaveTextContent(
      'Nothing on the server can bring them back; only a full backup saved before they went to the trash still holds them.',
    );
    await confirm('Delete forever');

    await waitFor(() =>
      expect(lastToast()).toMatchObject({
        title: '5 documents permanently deleted',
        type: 'success',
      }),
    );
    expect(harness.calls.every((call) => call.kind === 'purge')).toBe(true);
    expect(harness.calls).toHaveLength(5);
    expect(useDocumentsStore.getState().trashDocuments).toEqual([]);
    expect(fetchUsage).toHaveBeenCalledTimes(1);
  });

  it('does not re-read the storage used when nothing was deleted', async () => {
    harness.answer = () => Promise.reject(httpError(404, 'Document not found'));
    const fetchUsage = vi.fn().mockResolvedValue(undefined);
    await renderWith({
      documents: [],
      trashDocuments: [doc(1, { trashed: true })],
      trashLoaded: true,
      fetchUsage,
    });
    fireEvent.click(screen.getByRole('button', { name: /^Trash/ }));
    fireEvent.click(checkbox('doc-1.pdf'));
    fetchUsage.mockClear();
    fireEvent.click(within(bar()).getByRole('button', { name: 'Delete forever' }));
    await confirm('Delete forever');

    await waitFor(() =>
      expect(lastToast()).toMatchObject({
        title: '0 of 1 document permanently deleted; 1 could not be.',
        type: 'error',
      }),
    );
    expect(fetchUsage).not.toHaveBeenCalled();
  });
});

/* ========================================================================== */
/*  When the server stops answering, or the vault locks                        */
/* ========================================================================== */

describe('stopping a run', () => {
  const UNAVAILABLE = 'The server is temporarily unavailable. Please try again in a moment.';
  const stoppers: [string, () => unknown, string][] = [
    ['a 500', () => httpError(500, 'Internal'), UNAVAILABLE],
    ['a 503', () => httpError(503, 'Service unavailable'), UNAVAILABLE],
    [
      'no answer at all',
      () => new AxiosError('Network Error', 'ERR_NETWORK'),
      'Could not reach the server. Check your connection and try again.',
    ],
    [
      'a 429 asking for fifteen minutes',
      () => httpError(429, 'Too many', { 'retry-after': '900' }),
      'Too many attempts. Please try again in 15 minutes.',
    ],
    [
      'a 429 naming no wait at all',
      () => httpError(429, 'Too many'),
      'Too many attempts. Please wait a moment and try again.',
    ],
  ];

  for (const [label, refusal, reason] of stoppers) {
    it(`stops sending after ${label}, reports the rest as not sent, and never resends it`, async () => {
      // The refusal lands at once, while the other requests already sent are
      // still on the wire; nothing after it may go out.
      harness.answer = async (call) => {
        if (call.id === hex(1)) throw refusal();
        await later(5);
        return succeed(call);
      };
      await renderWith({
        documents: [],
        trashDocuments: range(6).map((n) => doc(n, { trashed: true })),
        trashLoaded: true,
      });
      fireEvent.click(screen.getByRole('button', { name: /^Trash/ }));
      selectAll();
      fireEvent.click(within(bar()).getByRole('button', { name: 'Delete forever' }));
      await confirm('Delete forever');

      await waitFor(() =>
        expect(lastToast()).toMatchObject({
          title: '3 of 6 documents permanently deleted; 1 could not be and 2 were not sent.',
          // The refused row's reason in the app's words, then why the rest were held.
          description: `${reason} ${SERVER_STOPPED_MESSAGE}`,
          type: 'warning',
        }),
      );
      expect(harness.calls.filter((call) => call.id === hex(1))).toHaveLength(1);
      expect(harness.calls).toHaveLength(BULK_REQUEST_CONCURRENCY);
      expect(within(bar()).getByText('3 selected')).toBeInTheDocument();
    });
  }

  it('carries on past a 4xx below 500: the row is refused, the server is fine', async () => {
    harness.answer = (call) =>
      call.id === hex(1) ? Promise.reject(httpError(499, 'Client closed')) : succeed(call);
    await renderWith({ documents: range(6).map((n) => doc(n)) });
    selectAll();
    fireEvent.click(within(bar()).getByRole('button', { name: 'Delete' }));
    await confirm('Move to trash');

    await waitFor(() =>
      expect(lastToast()).toMatchObject({
        title: '5 of 6 documents moved to the trash; 1 could not be.',
        description: 'Client closed',
      }),
    );
    expect(harness.calls).toHaveLength(6);
  });

  it("waits out a short 429 (a proxy's Retry-After of a few seconds) and finishes the run", async () => {
    // The golden host nginx answers a burst past its limit with 429 and
    // `Retry-After: 5`; `sendPaced` waits that out by itself, so it must not stop
    // the run the way a long wait does.
    let refused = false;
    harness.answer = (call) => {
      if (call.id === hex(2) && !refused) {
        refused = true;
        return Promise.reject(httpError(429, 'Slow down', { 'retry-after': '1' }));
      }
      return succeed(call);
    };
    await renderWith({ documents: range(5).map((n) => doc(n)) });
    selectAll();
    fireEvent.click(within(bar()).getByRole('button', { name: 'Delete' }));
    try {
      await confirmOnFakeClock('Move to trash');
      // Not yet: the refused row is waiting out its second.
      expect(harness.toast).not.toHaveBeenCalled();
      await advance(1000);

      expect(lastToast()).toMatchObject({
        title: '5 documents moved to the trash',
        type: 'success',
      });
      expect(harness.calls.filter((call) => call.id === hex(2))).toHaveLength(2);
      expect(harness.calls).toHaveLength(6);
    } finally {
      vi.useRealTimers();
    }
  });

  it('stops the run once short 429s have been retried as often as pacing allows', async () => {
    // Every request keeps being asked to wait a second. The first row is sent
    // once and retried MAX_BULK_RETRIES (3) times; when its last retry is refused
    // the run stops, so the other rows in flight, which reach their last retry a
    // moment later, are not sent again, and nothing still queued is sent at all.
    harness.answer = () => Promise.reject(httpError(429, 'Slow down', { 'retry-after': '1' }));
    await renderWith({ documents: range(8).map((n) => doc(n)) });
    selectAll();
    fireEvent.click(within(bar()).getByRole('button', { name: 'Delete' }));
    try {
      await confirmOnFakeClock('Move to trash');
      for (let wait = 0; wait < 3; wait++) await advance(1000);
    } finally {
      vi.useRealTimers();
    }

    expect(harness.toast).toHaveBeenCalledTimes(1);
    expect(harness.calls.filter((call) => call.id === hex(1))).toHaveLength(4);
    for (const n of range(BULK_REQUEST_CONCURRENCY - 1, 2)) {
      expect(harness.calls.filter((call) => call.id === hex(n))).toHaveLength(3);
    }
    expect(
      harness.calls.some((call) => Number.parseInt(call.id, 16) > BULK_REQUEST_CONCURRENCY),
    ).toBe(false);
    expect(lastToast()).toMatchObject({
      title: '0 of 8 documents moved to the trash; 1 could not be and 7 were not sent.',
      description: `Too many attempts. Please try again in 1 second. ${SERVER_STOPPED_MESSAGE}`,
      type: 'error',
    });
  });

  it('describes a lost connection in words, not as "Network Error"', async () => {
    harness.answer = async (call) => {
      if (call.id === hex(1)) throw new AxiosError('Network Error', 'ERR_NETWORK');
      await later(5);
      return succeed(call);
    };
    await renderWith({ documents: range(6).map((n) => doc(n)) });
    selectAll();
    fireEvent.click(within(bar()).getByRole('button', { name: 'Delete' }));
    await confirm('Move to trash');

    await waitFor(() => expect(lastToast()).toMatchObject({ type: 'warning' }));
    // The refused row's reason, in the app's words rather than "Network Error",
    // then why the rest were held back.
    expect(lastToast().description).toBe(
      `Could not reach the server. Check your connection and try again. ${SERVER_STOPPED_MESSAGE}`,
    );
    expect(lastToast().title).toBe(
      '3 of 6 documents moved to the trash; 1 could not be and 2 were not sent.',
    );
  });

  it('sends nothing more once the vault locks (the documents store is cleared), and a vault-store clear alone does not stop it', async () => {
    let cleared = false;
    harness.answer = (call) => {
      if (!cleared) {
        cleared = true;
        useVaultStore.getState().clearStore();
      }
      return succeed(call);
    };
    await renderWith({ documents: range(5).map((n) => doc(n)) });
    selectAll();
    fireEvent.click(within(bar()).getByRole('button', { name: 'Delete' }));
    await confirm('Move to trash');
    await waitFor(() => expect(lastToast()).toMatchObject({ type: 'success' }));
    expect(harness.calls).toHaveLength(5);

    // Now the store the action belongs to is cleared by the first request.
    cleanup();
    harness.toast.mockClear();
    harness.calls = [];
    cleared = false;
    harness.answer = (call) => {
      if (!cleared) {
        cleared = true;
        useDocumentsStore.getState().clearStore();
      }
      return succeed(call);
    };
    useVaultStore.setState({
      folders: [
        { id: FOLDER_ID, name: 'Taxes', sortOrder: 0, createdAt: 'x', updatedAt: 'x' },
      ] as never,
    });
    await renderWith({ documents: range(5).map((n) => doc(n)) });
    selectAll();
    fireEvent.click(within(bar()).getByRole('button', { name: 'Delete' }));
    await confirm('Move to trash');

    await waitFor(() => expect(harness.toast).toHaveBeenCalled());
    expect(harness.calls).toHaveLength(1);
    expect(lastToast()).toMatchObject({
      title: '1 of 5 documents moved to the trash; 4 were not sent.',
      description: BULK_ABANDONED_MESSAGE,
    });
  });
});

/* ========================================================================== */
/*  Move and tag                                                               */
/* ========================================================================== */

describe('pacing', () => {
  async function select(documents: DecryptedDocument[], trash = false): Promise<void> {
    await renderWith(
      trash
        ? { documents: [], trashDocuments: documents, trashLoaded: true }
        : {
            documents,
            updateDocumentMeta: (id: string) => request('meta', id).then(() => undefined),
          },
    );
    if (trash) fireEvent.click(screen.getByRole('button', { name: /^Trash/ }));
    selectAll();
  }

  it('restores at most the paced number at once', async () => {
    await select(
      range(8).map((n) => doc(n, { trashed: true })),
      true,
    );
    await act(async () => {
      fireEvent.click(within(bar()).getByRole('button', { name: 'Restore' }));
    });
    await waitFor(() => expect(lastToast()).toMatchObject({ title: '8 documents restored' }));
    expect(harness.peak).toBe(BULK_REQUEST_CONCURRENCY);
  });

  it('deletes for good at most the paced number at once', async () => {
    await select(
      range(8).map((n) => doc(n, { trashed: true })),
      true,
    );
    fireEvent.click(within(bar()).getByRole('button', { name: 'Delete forever' }));
    await confirm('Delete forever');
    await waitFor(() =>
      expect(lastToast()).toMatchObject({ title: '8 documents permanently deleted' }),
    );
    expect(harness.peak).toBe(BULK_REQUEST_CONCURRENCY);
  });

  it('moves at most the paced number at once', async () => {
    await select(range(8).map((n) => doc(n)));
    fireEvent.click(within(bar()).getByRole('button', { name: 'Move' }));
    await act(async () => {
      fireEvent.click(screen.getByRole('menuitem', { name: 'Taxes' }));
    });
    await waitFor(() => expect(lastToast()).toMatchObject({ title: '8 documents moved to Taxes' }));
    expect(harness.peak).toBe(BULK_REQUEST_CONCURRENCY);
  });

  it('tags at most the paced number at once', async () => {
    await select(range(8).map((n) => doc(n)));
    fireEvent.click(within(bar()).getByRole('button', { name: 'Tag' }));
    fireEvent.change(screen.getByPlaceholderText('Enter tag name'), { target: { value: 'x' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
    });
    await waitFor(() =>
      expect(lastToast()).toMatchObject({ title: 'Tag "x" added to 8 documents' }),
    );
    expect(harness.peak).toBe(BULK_REQUEST_CONCURRENCY);
  });
});

describe('bulk move', () => {
  it('moves the selection into a folder through the shared menu, sending nothing for a row already there', async () => {
    await renderWith({ documents: [doc(1), doc(2, { folderId: FOLDER_ID }), doc(3)] });
    selectAll();

    fireEvent.click(within(bar()).getByRole('button', { name: 'Move' }));
    const menu = screen.getByRole('menu', { name: 'Move to folder' });
    expect(
      within(menu)
        .getAllByRole('menuitem')
        .map((item) => item.textContent),
    ).toEqual(['No folder', 'Taxes']);
    await act(async () => {
      fireEvent.click(within(menu).getByRole('menuitem', { name: 'Taxes' }));
    });

    await waitFor(() =>
      expect(lastToast()).toMatchObject({
        title: '2 documents moved to Taxes, 1 already in Taxes',
        type: 'success',
      }),
    );
    expect(harness.calls).toEqual([
      { kind: 'update', id: hex(1), body: { folderId: FOLDER_ID } },
      { kind: 'update', id: hex(3), body: { folderId: FOLDER_ID } },
    ]);
    expect(useDocumentsStore.getState().documents.every((d) => d.folderId === FOLDER_ID)).toBe(
      true,
    );
    expect(screen.queryByTestId('documents-selection-bar')).not.toBeInTheDocument();
  });

  it('takes the selection out of its folders with No folder', async () => {
    await renderWith({ documents: [doc(1, { folderId: FOLDER_ID }), doc(2)] });
    selectAll();
    fireEvent.click(within(bar()).getByRole('button', { name: 'Move' }));
    await act(async () => {
      fireEvent.click(screen.getByRole('menuitem', { name: 'No folder' }));
    });

    await waitFor(() =>
      expect(lastToast()).toMatchObject({
        title: '1 document moved out of any folder, 1 already had no folder',
        type: 'success',
      }),
    );
    expect(harness.calls).toEqual([{ kind: 'update', id: hex(1), body: { folderId: null } }]);
    expect(
      useDocumentsStore.getState().documents.find((d) => d.id === hex(1))?.folderId,
    ).toBeUndefined();
  });

  it('says so, and sends nothing, when every selected document is already in that folder', async () => {
    await renderWith({
      documents: [doc(1, { folderId: FOLDER_ID }), doc(2, { folderId: FOLDER_ID })],
    });
    selectAll();
    fireEvent.click(within(bar()).getByRole('button', { name: 'Move' }));
    await act(async () => {
      fireEvent.click(screen.getByRole('menuitem', { name: 'Taxes' }));
    });

    await waitFor(() =>
      expect(lastToast()).toMatchObject({
        title: 'Every selected document is already in Taxes',
        type: 'success',
      }),
    );
    expect(harness.calls).toEqual([]);
  });

  it('reports a folder deleted meanwhile as an error and keeps the selection', async () => {
    harness.answer = () => Promise.reject(httpError(404, 'Folder not found'));
    await renderWith({ documents: [doc(1), doc(2)] });
    selectAll();
    fireEvent.click(within(bar()).getByRole('button', { name: 'Move' }));
    await act(async () => {
      fireEvent.click(screen.getByRole('menuitem', { name: 'Taxes' }));
    });

    await waitFor(() =>
      expect(lastToast()).toMatchObject({
        title: '0 of 2 documents moved to Taxes; 2 could not be.',
        description: 'Folder not found',
        type: 'error',
      }),
    );
    expect(within(bar()).getByText('2 selected')).toBeInTheDocument();
  });
});

describe('bulk tag', () => {
  async function tag(value: string): Promise<void> {
    fireEvent.click(within(bar()).getByRole('button', { name: 'Tag' }));
    fireEvent.change(screen.getByPlaceholderText('Enter tag name'), { target: { value } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
    });
  }

  it('adds the tag where it is missing, and says why it could not for an unopenable or full document', async () => {
    const updateDocumentMeta = vi.fn().mockResolvedValue(undefined);
    await renderWith({
      updateDocumentMeta,
      documents: [
        doc(1),
        doc(2, { tags: ['x'] }),
        doc(3, { degraded: true }),
        doc(4, { tags: Array.from({ length: MAX_DOCUMENT_TAGS }, (_, i) => `t${String(i)}`) }),
        doc(5, { tags: Array.from({ length: MAX_DOCUMENT_TAGS - 1 }, (_, i) => `t${String(i)}`) }),
      ],
    });
    selectAll();

    await tag('  x  ');

    await waitFor(() =>
      expect(lastToast()).toMatchObject({
        title: '2 of 5 documents tagged "x", 1 already had it; 2 could not be.',
        description: UNOPENABLE_TAG_MESSAGE,
        type: 'warning',
      }),
    );
    expect(updateDocumentMeta.mock.calls).toEqual([
      [hex(1), { tags: ['x'] }],
      [
        hex(5),
        {
          tags: [...Array.from({ length: MAX_DOCUMENT_TAGS - 1 }, (_, i) => `t${String(i)}`), 'x'],
        },
      ],
    ]);
    // The two that could not be tagged stay selected; the tagged and the
    // already-tagged leave the selection.
    expect(within(bar()).getByText('2 selected')).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Select doc-4.pdf' })).toBeChecked();
  });

  it('counts the tagged and the already-tagged apart on a full success', async () => {
    const updateDocumentMeta = vi.fn().mockResolvedValue(undefined);
    await renderWith({ updateDocumentMeta, documents: [doc(1), doc(2, { tags: ['x'] })] });
    selectAll();

    await tag('x');

    await waitFor(() =>
      expect(lastToast()).toMatchObject({
        title: 'Tag "x" added to 1 document; 1 already had it',
        type: 'success',
      }),
    );
    expect(updateDocumentMeta.mock.calls).toEqual([[hex(1), { tags: ['x'] }]]);
  });

  it('refuses a document that left the list before its turn', async () => {
    // The first re-seal removes the last document, as another tab's delete would.
    const updateDocumentMeta = vi.fn().mockImplementation(() => {
      useDocumentsStore.setState((state) => ({
        documents: state.documents.filter((d) => d.id !== hex(6)),
      }));
      return Promise.resolve();
    });
    await renderWith({ updateDocumentMeta, documents: range(6).map((n) => doc(n)) });
    selectAll();

    await tag('x');

    await waitFor(() =>
      expect(lastToast()).toMatchObject({
        title: '5 of 6 documents tagged "x"; 1 could not be.',
        description: ROW_GONE_MESSAGE,
        type: 'warning',
      }),
    );
    expect(updateDocumentMeta).toHaveBeenCalledTimes(5);
    expect(updateDocumentMeta.mock.calls.some(([id]) => id === hex(6))).toBe(false);
  });

  it('does not apply on the Enter that ends an input-method composition', async () => {
    const updateDocumentMeta = vi.fn().mockResolvedValue(undefined);
    await renderWith({ updateDocumentMeta, documents: [doc(1)] });
    fireEvent.click(checkbox('doc-1.pdf'));
    fireEvent.click(within(bar()).getByRole('button', { name: 'Tag' }));
    const input = screen.getByRole('textbox', { name: 'Tag to add to the selection' });
    fireEvent.change(input, { target: { value: '東京' } });

    fireEvent.keyDown(input, { key: 'Enter', isComposing: true });
    expect(updateDocumentMeta).not.toHaveBeenCalled();
    expect(input).toBeInTheDocument();

    await act(async () => {
      fireEvent.keyDown(input, { key: 'Enter' });
    });
    await waitFor(() =>
      expect(updateDocumentMeta).toHaveBeenCalledWith(hex(1), { tags: ['東京'] }),
    );
  });

  it('keeps the typed tag when tagging failed, for another try', async () => {
    const updateDocumentMeta = vi.fn().mockRejectedValue(httpError(400, 'No'));
    await renderWith({ updateDocumentMeta, documents: [doc(1)] });
    fireEvent.click(checkbox('doc-1.pdf'));

    await tag('keep');

    await waitFor(() => expect(lastToast()).toMatchObject({ type: 'error' }));
    fireEvent.click(within(bar()).getByRole('button', { name: 'Tag' }));
    expect(screen.getByPlaceholderText('Enter tag name')).toHaveValue('keep');
  });

  it('refuses a tag longer than a tag may be for every document, naming it, before sealing anything', async () => {
    // jsdom does not enforce `maxLength`, so this reaches the pre-flight a pasted
    // value would in a browser that did not cut it.
    const updateDocumentMeta = vi.fn().mockResolvedValue(undefined);
    await renderWith({ updateDocumentMeta, documents: [doc(1), doc(2)] });
    selectAll();
    const overlong = 'q'.repeat(51);

    await tag(overlong);

    await waitFor(() =>
      expect(lastToast()).toMatchObject({
        title: `0 of 2 documents tagged "${overlong}"; 2 could not be.`,
        description: `Tags can be at most 50 characters; "${overlong}" is longer.`,
        type: 'error',
      }),
    );
    expect(updateDocumentMeta).not.toHaveBeenCalled();
  });

  it('sends nothing, and says so, when every selected document already has the tag', async () => {
    const updateDocumentMeta = vi.fn().mockResolvedValue(undefined);
    await renderWith({
      updateDocumentMeta,
      documents: [doc(1, { tags: ['x'] }), doc(2, { tags: ['x'] })],
    });
    selectAll();

    await tag('x');

    await waitFor(() =>
      expect(lastToast()).toMatchObject({
        title: 'Every selected document already has the tag "x"',
        type: 'success',
      }),
    );
    expect(updateDocumentMeta).not.toHaveBeenCalled();
    expect(screen.queryByTestId('documents-selection-bar')).not.toBeInTheDocument();
  });
});

/* ========================================================================== */
/*  The selection itself                                                       */
/* ========================================================================== */

describe('the selection', () => {
  it('outlives a search that hides some of it, and acts only on what is visible', async () => {
    await renderWith({ documents: [doc(1), doc(2), doc(3), doc(4), doc(5)] });
    for (const n of [1, 2, 3]) fireEvent.click(checkbox(`doc-${String(n)}.pdf`));
    expect(within(bar()).getByText('3 selected')).toBeInTheDocument();

    search('doc-1');
    expect(within(bar()).getByText('1 selected')).toBeInTheDocument();

    search('');
    expect(within(bar()).getByText('3 selected')).toBeInTheDocument();

    // Hidden again, then acted on: only the visible selected row is sent.
    search('doc-2');
    fireEvent.click(within(bar()).getByRole('button', { name: 'Delete' }));
    await confirm('Move to trash');
    await waitFor(() => expect(harness.toast).toHaveBeenCalled());
    expect(harness.calls.map((call) => call.id)).toEqual([hex(2)]);
  });

  it('shows normal links and no bar while a search hides every selected row, and the download panel lists what is shown', async () => {
    await renderWith({ documents: [doc(1), doc(2), doc(3)] });
    fireEvent.click(checkbox('doc-1.pdf'));
    expect(screen.getByRole('button', { name: 'Download selected' })).toBeInTheDocument();
    expect(screen.getByText(/Saves the 1 selected document\(s\)/)).toBeInTheDocument();

    search('doc-2');

    expect(screen.queryByTestId('documents-selection-bar')).not.toBeInTheDocument();
    expect(within(rows()[0]!).getByRole('link')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Download all' })).toBeInTheDocument();
    expect(screen.getByText(/Saves the 1 document\(s\) listed below/)).toBeInTheDocument();
  });

  it('selects exactly the visible rows with Select all, and empties with Deselect all', async () => {
    await renderWith({ documents: [doc(1, { tags: ['red'] }), doc(2, { tags: ['red'] }), doc(3)] });
    search('red');
    fireEvent.click(checkbox('doc-1.pdf'));
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select all' }));
    expect(within(bar()).getByText('2 selected')).toBeInTheDocument();

    // The hidden row was not selected by it.
    search('');
    expect(within(bar()).getByText('2 selected')).toBeInTheDocument();
    expect(checkbox('doc-3.pdf')).not.toBeChecked();

    search('red');
    fireEvent.click(screen.getByRole('checkbox', { name: 'Deselect all' }));
    expect(screen.queryByTestId('documents-selection-bar')).not.toBeInTheDocument();
    search('');
    expect(
      rows().map((row) => (within(row).getByRole('checkbox') as HTMLInputElement).checked),
    ).toEqual([false, false, false]);
  });

  it('unticks one row at a time, and leaves selection mode with the last', async () => {
    await renderWith({ documents: [doc(1), doc(2)] });
    fireEvent.click(checkbox('doc-1.pdf'));
    fireEvent.click(checkbox('doc-2.pdf'));
    expect(within(bar()).getByText('2 selected')).toBeInTheDocument();

    fireEvent.click(checkbox('doc-1.pdf'));
    expect(within(bar()).getByText('1 selected')).toBeInTheDocument();
    expect(checkbox('doc-1.pdf')).not.toBeChecked();

    fireEvent.click(checkbox('doc-2.pdf'));
    expect(screen.queryByTestId('documents-selection-bar')).not.toBeInTheDocument();
    expect(rows().map((row) => within(row).queryAllByRole('link').length)).toEqual([1, 1]);
  });

  it('is cleared by moving from one folder to another', async () => {
    const RECEIPTS = 'e'.repeat(24);
    useVaultStore.setState({
      folders: [
        { id: FOLDER_ID, name: 'Taxes', sortOrder: 0, createdAt: 'x', updatedAt: 'x' },
        { id: RECEIPTS, name: 'Receipts', sortOrder: 1, createdAt: 'x', updatedAt: 'x' },
      ] as never,
    });
    await renderWith({
      documents: [doc(1, { folderId: FOLDER_ID }), doc(2, { folderId: RECEIPTS })],
    });
    fireEvent.click(screen.getByRole('button', { name: /^Taxes/ }));
    fireEvent.click(checkbox('doc-1.pdf'));
    expect(within(bar()).getByText('1 selected')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Receipts/ }));
    fireEvent.click(screen.getByRole('button', { name: /^Taxes/ }));
    expect(screen.queryByTestId('documents-selection-bar')).not.toBeInTheDocument();
    expect(checkbox('doc-1.pdf')).not.toBeChecked();
  });

  it('survives the list being read again, but not a change of list', async () => {
    await renderWith({ documents: [doc(1), doc(2)] });
    fireEvent.click(checkbox('doc-1.pdf'));
    fireEvent.click(checkbox('doc-2.pdf'));

    // A re-read empties the list, then refills it.
    act(() => useDocumentsStore.setState({ documents: [] }));
    act(() => useDocumentsStore.setState({ documents: [doc(1), doc(2)] }));
    expect(within(bar()).getByText('2 selected')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Favorites/ }));
    fireEvent.click(screen.getByRole('button', { name: /^All Documents/ }));
    expect(screen.queryByTestId('documents-selection-bar')).not.toBeInTheDocument();
    expect(checkbox('doc-1.pdf')).not.toBeChecked();
  });

  it('does not bring a selection back when a run finishes after the list was changed', async () => {
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    harness.answer = async (call) => {
      await held;
      return call.id === hex(2) ? Promise.reject(httpError(404, 'gone')) : succeed(call);
    };
    await renderWith({ documents: [doc(1), doc(2)], trashDocuments: [], trashLoaded: true });
    selectAll();
    fireEvent.click(within(bar()).getByRole('button', { name: 'Delete' }));
    await confirm('Move to trash');

    fireEvent.click(screen.getByRole('button', { name: /^Trash/ }));
    await act(async () => {
      release();
      await later(5);
    });
    fireEvent.click(screen.getByRole('button', { name: /^All Documents/ }));

    expect(screen.queryByTestId('documents-selection-bar')).not.toBeInTheDocument();
    expect(checkbox('doc-2.pdf')).not.toBeChecked();
  });

  it('selects across a virtualized list of more than fifty rows', async () => {
    await renderWith({ documents: range(55).map((n) => doc(n)) });
    selectAll();
    expect(within(bar()).getByText('55 selected')).toBeInTheDocument();
    expect(rows()).toHaveLength(55);
    expect(
      rows().every((row) => (within(row).getByRole('checkbox') as HTMLInputElement).checked),
    ).toBe(true);
  });
});

/* ========================================================================== */
/*  What the person is told                                                    */
/* ========================================================================== */

describe('describeBulkOutcome', () => {
  const outcome = (done: number, failed: number, notSent = 0, reason = 'No.') => ({
    done: range(done).map(hex),
    unchanged: [],
    failed: range(failed, 100).map((n) => ({ id: hex(n), reason })),
    notSent: range(notSent, 200).map(hex),
    stopReason: notSent > 0 ? SERVER_STOPPED_MESSAGE : null,
  });

  it('counts a full success, in the singular for one', () => {
    expect(describeBulkOutcome(outcome(3, 0), 'restored')).toEqual({
      title: '3 documents restored',
      type: 'success',
    });
    expect(describeBulkOutcome(outcome(1, 0), 'restored')).toEqual({
      title: '1 document restored',
      type: 'success',
    });
  });

  it('warns at N-1 of N and errs at 0 of N, with the first reason and a longer stay', () => {
    expect(describeBulkOutcome(outcome(2, 1), 'restored')).toEqual({
      title: '2 of 3 documents restored; 1 could not be.',
      description: 'No.',
      type: 'warning',
      duration: BULK_REPORT_DURATION_MS,
    });
    expect(describeBulkOutcome(outcome(0, 3), 'restored')).toMatchObject({
      title: '0 of 3 documents restored; 3 could not be.',
      type: 'error',
    });
  });

  it('names rows already as asked, and never reports a run that changed nothing as "0 moved"', () => {
    const already = { some: 'in Taxes', all: 'Every selected document is already in Taxes' };
    const base = { failed: [], notSent: [], stopReason: null };
    expect(
      describeBulkOutcome(
        { ...base, done: [hex(1)], unchanged: [hex(2), hex(3)] },
        'moved to Taxes',
        already,
      ),
    ).toEqual({ title: '1 document moved to Taxes, 2 already in Taxes', type: 'success' });
    expect(
      describeBulkOutcome({ ...base, done: [], unchanged: [hex(1)] }, 'moved to Taxes', already),
    ).toEqual({ title: 'Every selected document is already in Taxes', type: 'success' });
    // Every row is accounted for in a partial result: 1 + 1 + 1 of 3.
    expect(
      describeBulkOutcome(
        {
          done: [hex(1)],
          unchanged: [hex(2)],
          failed: [{ id: hex(3), reason: 'No.' }],
          notSent: [],
          stopReason: null,
        },
        'moved to Taxes',
        already,
      ),
    ).toMatchObject({
      title: '1 of 3 documents moved to Taxes, 1 already in Taxes; 1 could not be.',
    });
  });

  it('adds the stop reason to a refusal only when it says something new', () => {
    const base = { done: [hex(1)], unchanged: [], failed: [{ id: hex(2), reason: 'Same.' }] };
    expect(
      describeBulkOutcome({ ...base, notSent: [hex(3)], stopReason: 'Same.' }, 'restored'),
    ).toMatchObject({ description: 'Same.' });
    expect(
      describeBulkOutcome({ ...base, notSent: [hex(3)], stopReason: null }, 'restored'),
    ).toMatchObject({ description: 'Same.' });
    expect(
      describeBulkOutcome({ ...base, notSent: [], stopReason: null }, 'restored'),
    ).toMatchObject({
      title: '1 of 2 documents restored; 1 could not be.',
      description: 'Same.',
    });
  });

  it('names rows never sent, and the reason the run stopped when no row was refused', () => {
    expect(describeBulkOutcome(outcome(1, 0, 2), 'restored')).toMatchObject({
      title: '1 of 3 documents restored; 2 were not sent.',
      description: SERVER_STOPPED_MESSAGE,
      type: 'warning',
    });
  });

  it('shows a long server message cut to the length a toast shows whole', async () => {
    const long = `${'w'.repeat(480)} remedy`;
    harness.answer = () => Promise.reject(httpError(400, long));
    await renderWith({ documents: [doc(1)] });
    fireEvent.click(checkbox('doc-1.pdf'));
    fireEvent.click(within(bar()).getByRole('button', { name: 'Delete' }));
    await confirm('Move to trash');

    await waitFor(() => expect(harness.toast).toHaveBeenCalled());
    expect(lastToast().title).toBe('0 of 1 document moved to the trash; 1 could not be.');
    expect(lastToast().description).toBe(long.slice(0, 200));
  });
});
