/**
 * Tests for ExportDataPage (Phase 10 — the standalone plaintext-export page).
 *
 * The page is a DELIBERATELY separate surface from the encrypted export/import
 * (PLAN §1.2 principle 11): its own route, its own dialog, its own code path.
 * These tests pin the safety-critical behavior:
 *
 *  - the master password is verified (server `POST /tools/export`) BEFORE any
 *    plaintext is produced — a wrong password surfaces the server's 401 and no
 *    Blob is ever built;
 *  - the confirmation dialog is a hard gate: no file is downloaded until the user
 *    confirms, and cancelling produces no download;
 *  - the produced Blob carries the serialized plaintext (asserted by decoding the
 *    Blob handed to `URL.createObjectURL`);
 *  - undecodable / omitted items are REPORTED, never silently dropped;
 *  - the page is reachable at its own route, independent of the Settings card.
 *
 * The decryption bridge (`decryptExportResponse`) and normalizer
 * (`toPortableItems`) are mocked — they have their own dedicated tests and pull
 * in real Web Crypto; here we drive the page with controlled portable records.
 * The serializer (`serializePortableExport`) and the download helper
 * (`downloadText`/`downloadBlob`) are REAL, so the Blob inspection is genuine.
 */

import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { PortableItem, SkippedItem } from '../../src/services/export/portableItem';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockExportVaultApi = vi.fn();
vi.mock('../../src/services/api/userApi', () => ({
  exportVaultApi: (...args: unknown[]) => mockExportVaultApi(...args),
}));

const mockDecryptExportResponse = vi.fn();
vi.mock('../../src/stores/vaultStore', () => ({
  decryptExportResponse: (...args: unknown[]) => mockDecryptExportResponse(...args),
}));

const mockToPortableItems = vi.fn();
vi.mock('../../src/services/export/portableItem', () => ({
  toPortableItems: (...args: unknown[]) => mockToPortableItems(...args),
}));

const mockDeriveKeys = vi.fn();
const mockGetAuthHash = vi.fn();
const mockClearKey = vi.fn();
vi.mock('../../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: (...args: unknown[]) => mockDeriveKeys(...args),
    getAuthHash: (...args: unknown[]) => mockGetAuthHash(...args),
    clearKey: (...args: unknown[]) => mockClearKey(...args),
  },
}));

const mockToast = vi.fn();
vi.mock('../../src/components/ui/Toast', () => ({
  useToast: () => ({ toast: mockToast, dismiss: vi.fn() }),
}));

vi.mock('../../src/stores/authStore', () => ({
  useAuthStore: Object.assign(vi.fn(), { getState: vi.fn(), setState: vi.fn() }),
}));

import ExportDataPage from '../../src/pages/ExportDataPage';
import { useAuthStore } from '../../src/stores/authStore';

const mockUseAuthStore = vi.mocked(useAuthStore);

// ---------------------------------------------------------------------------
// Fixtures & helpers
// ---------------------------------------------------------------------------

const VAULT_KEY = { fake: 'vault-key' } as unknown as CryptoKey;

const LOGIN_ITEM: PortableItem = {
  type: 'login',
  name: 'Example',
  folderPath: '',
  favorite: false,
  notes: '',
  tags: [],
  login: { username: 'alice', password: 'hunter2-secret-pw' },
  uris: ['https://example.com'],
};

const CARD_ITEM: PortableItem = {
  type: 'card',
  name: 'My Card',
  folderPath: '',
  favorite: false,
  notes: '',
  tags: [],
  card: {
    cardholderName: 'Alice',
    number: '4111111111111111',
    expMonth: '01',
    expYear: '2030',
    cvv: '123',
  },
};

function setupAuthStore(
  overrides: { user?: { userId: string; email: string } | null; vaultKey?: CryptoKey | null } = {},
) {
  const state = {
    user: 'user' in overrides ? overrides.user : { userId: 'u1', email: 'alice@example.com' },
    vaultKey: 'vaultKey' in overrides ? overrides.vaultKey : VAULT_KEY,
  };
  mockUseAuthStore.mockImplementation((selector?: unknown) => {
    if (typeof selector === 'function') {
      return (selector as (s: typeof state) => unknown)(state);
    }
    return state as unknown;
  });
}

/** Make the server re-auth succeed and the bridge/normalizer yield `portable`. */
function primeSuccess(portable: PortableItem[], skipped: SkippedItem[] = []) {
  mockDeriveKeys.mockResolvedValue({ authKey: 'auth-key' });
  mockGetAuthHash.mockReturnValue('derived-auth-hash');
  mockExportVaultApi.mockResolvedValue({
    data: { success: true, data: { items: [], folders: [], metadata: {} } },
  });
  mockDecryptExportResponse.mockResolvedValue({ items: [], folders: [] });
  mockToPortableItems.mockResolvedValue({ portable, skipped });
}

let createObjectURL: ReturnType<typeof vi.fn>;
let revokeObjectURL: ReturnType<typeof vi.fn>;
let clickSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.clearAllMocks();
  setupAuthStore();

  createObjectURL = vi.fn(() => 'blob:mock-url');
  revokeObjectURL = vi.fn();
  vi.stubGlobal('URL', { ...URL, createObjectURL, revokeObjectURL });
  clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function typePasswordAndPrepare(pw = 'correct horse') {
  fireEvent.change(screen.getByLabelText('Confirm master password'), { target: { value: pw } });
  fireEvent.click(screen.getByRole('button', { name: /prepare plaintext export/i }));
}

/** Decode the Blob handed to URL.createObjectURL back to text. */
async function downloadedText(): Promise<string> {
  expect(createObjectURL).toHaveBeenCalledTimes(1);
  const blob = createObjectURL.mock.calls[0]![0] as Blob;
  return blob.text();
}

// ---------------------------------------------------------------------------
// Render / warnings
// ---------------------------------------------------------------------------

describe('ExportDataPage — surface', () => {
  it('renders the danger banner, all three formats, and the password field', () => {
    render(<ExportDataPage />, { wrapper: MemoryRouter });

    expect(screen.getByRole('heading', { name: /leave h-vault/i })).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent(/UNENCRYPTED plaintext/i);
    expect(screen.getByRole('alert')).toHaveTextContent(/do not open it in a spreadsheet/i);

    expect(screen.getByRole('radio', { name: /Bitwarden \(\.json\)/i })).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /Bitwarden \(\.csv\)/i })).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /Chrome \/ Edge \(\.csv\)/i })).toBeInTheDocument();
    expect(screen.getByLabelText('Confirm master password')).toBeInTheDocument();
  });

  it('is reachable at its own route, independent of the Settings export card', () => {
    render(
      <MemoryRouter initialEntries={['/settings/export-data']}>
        <Routes>
          <Route path="/settings" element={<div data-testid="settings">Settings</div>} />
          <Route path="/settings/export-data" element={<ExportDataPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByRole('heading', { name: /leave h-vault/i })).toBeInTheDocument();
    expect(screen.queryByTestId('settings')).not.toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Guards (no plaintext produced)
// ---------------------------------------------------------------------------

describe('ExportDataPage — guards', () => {
  it('rejects an empty master password without calling the server', async () => {
    render(<ExportDataPage />, { wrapper: MemoryRouter });

    fireEvent.click(screen.getByRole('button', { name: /prepare plaintext export/i }));

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: expect.stringMatching(/master password/i),
          type: 'error',
        }),
      ),
    );
    expect(mockExportVaultApi).not.toHaveBeenCalled();
    expect(createObjectURL).not.toHaveBeenCalled();
  });

  it('refuses when the vault is locked (no vault key)', async () => {
    setupAuthStore({ vaultKey: null });
    render(<ExportDataPage />, { wrapper: MemoryRouter });

    await typePasswordAndPrepare();

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: expect.stringMatching(/unlock/i), type: 'error' }),
      ),
    );
    expect(mockExportVaultApi).not.toHaveBeenCalled();
  });

  it('refuses when there is no signed-in user', async () => {
    setupAuthStore({ user: null });
    render(<ExportDataPage />, { wrapper: MemoryRouter });

    await typePasswordAndPrepare();

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: expect.stringMatching(/signed in/i), type: 'error' }),
      ),
    );
    expect(mockExportVaultApi).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Wrong password (server 401) — no plaintext
// ---------------------------------------------------------------------------

describe('ExportDataPage — re-auth gate', () => {
  it('surfaces the server 401 and produces no plaintext on a wrong password', async () => {
    mockDeriveKeys.mockResolvedValue({ authKey: 'auth-key' });
    mockGetAuthHash.mockReturnValue('wrong-hash');
    // Axios-style rejection carrying the server message.
    mockExportVaultApi.mockRejectedValue({
      isAxiosError: true,
      response: { status: 401, data: { message: 'Invalid password' } },
      message: 'Request failed with status code 401',
    });

    render(<ExportDataPage />, { wrapper: MemoryRouter });
    await typePasswordAndPrepare('wrong-pw');

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Invalid password', type: 'error' }),
      ),
    );
    // No decryption, no dialog, no download.
    expect(mockDecryptExportResponse).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(createObjectURL).not.toHaveBeenCalled();
  });

  it('surfaces a non-success envelope as an error and produces no plaintext', async () => {
    mockDeriveKeys.mockResolvedValue({ authKey: 'auth-key' });
    mockGetAuthHash.mockReturnValue('h');
    mockExportVaultApi.mockResolvedValue({ data: { success: false } });

    render(<ExportDataPage />, { wrapper: MemoryRouter });
    await typePasswordAndPrepare();

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({ type: 'error' })),
    );
    expect(mockDecryptExportResponse).not.toHaveBeenCalled();
    expect(createObjectURL).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Confirmation gate + download
// ---------------------------------------------------------------------------

describe('ExportDataPage — confirmation gate', () => {
  it('does not download until the confirmation is accepted', async () => {
    primeSuccess([LOGIN_ITEM]);
    render(<ExportDataPage />, { wrapper: MemoryRouter });

    await typePasswordAndPrepare();

    // Dialog opens; still no download.
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent(/unencrypted plaintext/i);
    expect(dialog).toHaveTextContent(/Bitwarden \(\.json\)/i);
    expect(createObjectURL).not.toHaveBeenCalled();
    // The verified auth hash was sent with the chosen portable format.
    expect(mockExportVaultApi).toHaveBeenCalledWith({
      format: 'json',
      authHash: 'derived-auth-hash',
      portableFormat: 'bitwarden-json',
    });
  });

  it('downloads the serialized plaintext only after confirming', async () => {
    primeSuccess([LOGIN_ITEM]);
    render(<ExportDataPage />, { wrapper: MemoryRouter });

    await typePasswordAndPrepare();
    fireEvent.click(await screen.findByRole('button', { name: /download plaintext file/i }));

    await waitFor(() => expect(createObjectURL).toHaveBeenCalledTimes(1));
    const text = await downloadedText();
    expect(text).toContain('hunter2-secret-pw');
    expect(clickSpy).toHaveBeenCalledTimes(1);
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:mock-url');

    // Success reported; dialog closed.
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.getByText(/export complete/i)).toBeInTheDocument();
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: expect.stringMatching(/downloaded/i), type: 'success' }),
    );
  });

  it('cancelling the confirmation produces no download', async () => {
    primeSuccess([LOGIN_ITEM]);
    render(<ExportDataPage />, { wrapper: MemoryRouter });

    await typePasswordAndPrepare();
    fireEvent.click(await screen.findByRole('button', { name: /^cancel$/i }));

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(createObjectURL).not.toHaveBeenCalled();
    expect(screen.queryByText(/export complete/i)).not.toBeInTheDocument();
  });

  it('reports an error and no result when building the file throws', async () => {
    primeSuccess([LOGIN_ITEM]);
    // Force the anchor click to throw so downloadBlob rethrows into the confirm
    // handler's catch (finally still clears the dialog).
    clickSpy.mockImplementation(() => {
      throw new Error('click failed');
    });
    render(<ExportDataPage />, { wrapper: MemoryRouter });

    await typePasswordAndPrepare();
    fireEvent.click(await screen.findByRole('button', { name: /download plaintext file/i }));

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({ type: 'error' }));
    expect(screen.queryByText(/export complete/i)).not.toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Reporting: skipped + omitted
// ---------------------------------------------------------------------------

describe('ExportDataPage — reporting', () => {
  it('reports undecodable items as skipped, never silently dropping them', async () => {
    const skipped: SkippedItem[] = [
      { id: 'x1', name: 'Broken Login', reason: 'Item data could not be decoded' },
    ];
    primeSuccess([LOGIN_ITEM], skipped);
    render(<ExportDataPage />, { wrapper: MemoryRouter });

    await typePasswordAndPrepare();
    // The dialog warns about the skipped item before download.
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent(/could not be decoded/i);

    fireEvent.click(screen.getByRole('button', { name: /download plaintext file/i }));

    await waitFor(() => expect(screen.getByText(/export complete/i)).toBeInTheDocument());
    expect(screen.getByText(/Broken Login/)).toBeInTheDocument();
    expect(screen.getByText(/1 item skipped/i)).toBeInTheDocument();
  });

  it('counts items the chosen format cannot represent as omitted', async () => {
    // Chrome CSV keeps only logins; the card is omitted by the real serializer.
    primeSuccess([LOGIN_ITEM, CARD_ITEM]);
    render(<ExportDataPage />, { wrapper: MemoryRouter });

    fireEvent.click(screen.getByRole('radio', { name: /Chrome \/ Edge \(\.csv\)/i }));
    await typePasswordAndPrepare();
    fireEvent.click(await screen.findByRole('button', { name: /download plaintext file/i }));

    await waitFor(() => expect(screen.getByText(/export complete/i)).toBeInTheDocument());
    // 2 portable items, 1 omitted (the card) → 1 exported.
    expect(screen.getByText(/1 item exported/i)).toBeInTheDocument();
    expect(screen.getByText(/1 item omitted/i)).toBeInTheDocument();

    const text = await downloadedText();
    expect(text).toContain('hunter2-secret-pw');
    expect(text).not.toContain('4111111111111111');
  });
});
