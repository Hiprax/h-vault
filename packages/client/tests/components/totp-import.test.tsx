import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router';

/**
 * The import flow, driven through the PASTE path.
 *
 * jsdom has no camera and no QR decoder, and neither is what this file is about:
 * the decoder has its own cross-library test and the camera has its own suite.
 * What belongs here is everything AFTER a code is read, which is where the
 * product rules live. Above all: nothing is attached to a login automatically.
 */

vi.mock('../../src/hooks/useUserSettings', () => ({
  useUserSettings: () => ({
    autoLockTimeout: 15,
    clipboardClearTimeout: 30,
    theme: 'system',
    defaultPasswordOptions: {
      length: 20,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true,
      excludeAmbiguous: false,
      minUppercase: 0,
      minLowercase: 0,
      minNumbers: 1,
      minSymbols: 1,
    },
  }),
  clearSettingsCache: vi.fn(),
}));

const mockCopySecret = vi.fn().mockResolvedValue(undefined);
vi.mock('../../src/services/clipboard/clipboardService', () => ({
  copySecretToClipboard: (...args: unknown[]) => mockCopySecret(...args),
  eraseCopiedSecretNow: vi.fn(),
}));

const mockNavigate = vi.fn();
vi.mock('react-router', async () => {
  const actual = await vi.importActual<typeof import('react-router')>('react-router');
  return { ...actual, useNavigate: () => mockNavigate };
});

const mockToast = vi.fn();
vi.mock('../../src/components/ui/Toast', () => ({
  useToast: () => ({ toast: mockToast }),
}));

const mockCreateItem = vi.fn().mockResolvedValue(undefined);
const mockUpdateItem = vi.fn().mockResolvedValue(undefined);
const mockFetchItems = vi.fn().mockResolvedValue(undefined);
const vaultState = {
  items: [] as unknown[],
  createItem: mockCreateItem,
  updateItem: mockUpdateItem,
  fetchItems: mockFetchItems,
};
vi.mock('../../src/stores/vaultStore', () => ({
  useVaultStore: Object.assign(
    (selector: (state: typeof vaultState) => unknown) => selector(vaultState),
    { getState: () => vaultState },
  ),
}));

const mockStartUpload = vi.fn().mockResolvedValue('doc-1');
vi.mock('../../src/stores/documentsStore', () => ({
  useDocumentsStore: { getState: () => ({ startUpload: mockStartUpload }) },
}));

const mockFreshConfig = vi.fn().mockResolvedValue({ enabled: true });
vi.mock('../../src/services/api/configApi', () => ({
  readDocumentsConfigFresh: () => mockFreshConfig(),
}));

// The camera never starts in these tests; the paste path needs no frame at all.
vi.mock('../../src/services/totpImport/qrSandbox', () => ({
  openQrScanner: vi.fn(() => ({ scan: vi.fn(), close: vi.fn() })),
}));

const { TotpImportFlow } = await import('../../src/components/tools/TotpImportFlow');
const { endScanSession, heldSecretCount } =
  await import('../../src/services/totpImport/scanSession');

/**
 * A two-account export, produced by the independent encoder rather than by the
 * reader under test.
 */
const { encodeMigrationUri } = await import('../support/migrationEncoder');
const EXPORT_URI = encodeMigrationUri({
  entries: [
    {
      secret: Uint8Array.from([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef]),
      name: 'Acme:alice@example.com',
      issuer: 'Acme',
      algorithm: 1,
      digits: 1,
      type: 2,
    },
    {
      secret: Uint8Array.from([0x21, 0xde, 0xad, 0xbe, 0xef, 0x48, 0x65, 0x6c, 0x6c, 0x6f]),
      name: 'Globex:bob@example.com',
      issuer: 'Globex',
      algorithm: 2,
      digits: 2,
      type: 2,
    },
  ],
  version: 1,
  batchSize: 1,
  batchIndex: 0,
  batchId: 1234,
});

async function renderFlow() {
  const result = render(
    <MemoryRouter>
      <TotpImportFlow onStartOver={vi.fn()} />
    </MemoryRouter>,
  );
  await act(async () => {
    await Promise.resolve();
  });
  return result;
}

async function readExportRaw(uri: string) {
  const disclosure = screen.queryByText(/Paste an export link instead/i);
  if (disclosure !== null) fireEvent.click(disclosure);
  fireEvent.change(screen.getByLabelText('Export link'), { target: { value: uri } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: /read link/i }));
  });
}

async function readExport(uri = EXPORT_URI) {
  fireEvent.click(screen.getByText(/Paste an export link instead/i));
  fireEvent.change(screen.getByLabelText('Export link'), { target: { value: uri } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: /read link/i }));
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  vaultState.items = [];
  endScanSession();
});

afterEach(() => {
  endScanSession();
});

describe('reading an export', () => {
  it('shows every account it read, by issuer and account name', async () => {
    await renderFlow();
    await readExport();

    expect(await screen.findByText('Acme')).toBeInTheDocument();
    expect(screen.getByText('alice@example.com')).toBeInTheDocument();
    expect(screen.getByText('Globex')).toBeInTheDocument();
    expect(screen.getByText(/2 accounts read from your export/)).toBeInTheDocument();
  });

  it('badges only what is not the default, so a badge means something', async () => {
    await renderFlow();
    await readExport();

    // The second account is SHA256 with eight digits; the first is the plain
    // default and carries no badge at all.
    expect(await screen.findByText('SHA256')).toBeInTheDocument();
    expect(screen.getByText('8 digits')).toBeInTheDocument();
    expect(screen.queryByText('SHA1')).not.toBeInTheDocument();
  });

  it('warns that nothing is saved and that the phone should keep its accounts', async () => {
    await renderFlow();
    await readExport();

    expect(await screen.findByText(/Nothing here is saved yet/)).toBeInTheDocument();
    expect(screen.getByText(/until a code here matches the one on your phone/)).toBeInTheDocument();
  });

  it('says so when the link cannot be read, rather than failing silently', async () => {
    await renderFlow();
    await readExport('otpauth-migration://offline?data=!!!!');

    expect(await screen.findByText(/not a readable export link/i)).toBeInTheDocument();
  });

  it('keeps no secret anywhere in the rendered DOM while the keys are hidden', async () => {
    // The keys live in a module-level map and are rendered only on request, so
    // the tree a devtools panel would show carries none of them.
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    // The first account's key, base32 of `Hello!` + DEADBEEF.
    expect(document.body.textContent).not.toContain('JBSWY3DPEHPK3PXP');
    expect(document.body.innerHTML).not.toContain('JBSWY3DPEHPK3PXP');
  });

  it('reveals a key only when asked', async () => {
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    const [reveal] = screen.getAllByRole('button', { name: /show key/i });
    await act(async () => {
      fireEvent.click(reveal!);
    });
    expect(document.body.textContent).toContain('JBSWY3DPEHPK3PXP');
  });
});

describe('a batched export', () => {
  function partUri(index: number, name: string) {
    return encodeMigrationUri({
      entries: [
        {
          secret: Uint8Array.from([index, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
          name: `${name}:user@example.com`,
          issuer: name,
        },
      ],
      version: 1,
      batchSize: 2,
      batchIndex: index,
      batchId: 99,
    });
  }

  it('collects both parts and only then shows the accounts', async () => {
    // The regression this guards: the decode handler is captured ONCE by the
    // camera loop, so reading the collected set out of a closure would judge
    // part two against an empty set and the export would never complete.
    await renderFlow();
    await readExportRaw(partUri(0, 'First'));

    expect(screen.getByText(/Part 1 of 2 captured/)).toBeInTheDocument();
    expect(screen.queryByText(/Nothing here is saved yet/)).not.toBeInTheDocument();

    await readExportRaw(partUri(1, 'Second'));

    expect(await screen.findByText(/Nothing here is saved yet/)).toBeInTheDocument();
    expect(screen.getByText('First')).toBeInTheDocument();
    expect(screen.getByText('Second')).toBeInTheDocument();
  });

  it('counts a re-scan of the same part as no progress', async () => {
    await renderFlow();
    await readExportRaw(partUri(0, 'First'));
    await readExportRaw(partUri(0, 'First'));

    expect(screen.getByText(/Already read that one\. 1 of 2 captured/)).toBeInTheDocument();
  });

  it('refuses a part from a different export rather than mixing two sets', async () => {
    await renderFlow();
    await readExportRaw(partUri(0, 'First'));

    const foreign = encodeMigrationUri({
      entries: [{ secret: Uint8Array.from([9, 9, 9, 9, 9, 9, 9, 9, 9, 9]), name: 'Other' }],
      version: 1,
      batchSize: 2,
      batchIndex: 1,
      batchId: 4242,
    });
    await readExportRaw(foreign);

    expect(screen.getByText(/belongs to a different export/)).toBeInTheDocument();
  });
});

describe('placing a code', () => {
  it('creates a new login carrying the full otpauth URI, not a bare secret', async () => {
    // A bare secret would silently lose the algorithm and digit count, and for
    // the SHA256 account that means codes that never match.
    await renderFlow();
    await readExport();
    await screen.findByText('Globex');

    const buttons = screen.getAllByRole('button', { name: /new login/i });
    await act(async () => {
      fireEvent.click(buttons[1]!);
    });

    expect(mockCreateItem).toHaveBeenCalledTimes(1);
    const [itemType, name, data] = mockCreateItem.mock.calls[0] as [
      string,
      string,
      Record<string, unknown>,
    ];
    expect(itemType).toBe('login');
    expect(name).toBe('Globex');
    expect(String(data.totp)).toContain('algorithm=SHA256');
    expect(String(data.totp)).toContain('digits=8');
  });

  it('never attaches anything to an existing login on its own', async () => {
    // The product rule this feature is shaped around: a code on the wrong
    // account is worse than a code not imported.
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    expect(mockUpdateItem).not.toHaveBeenCalled();
  });
});

describe('the key itself', () => {
  it('copies the KEY only when that button is pressed, through the shared guard', async () => {
    // The default copy on a card is the six-digit code. Copying the key is a
    // separate, deliberate action, and it still goes through the one erase
    // deadline rather than touching the clipboard directly.
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    await act(async () => {
      fireEvent.click(screen.getAllByRole('button', { name: /Copy secret key for Acme/ })[0]!);
    });

    expect(mockCopySecret).toHaveBeenCalledTimes(1);
    expect(String(mockCopySecret.mock.calls[0]?.[0])).toMatch(/^[A-Z2-7]+$/);
    // The configured clear timeout, in milliseconds, not a hardcoded default.
    expect(mockCopySecret.mock.calls[0]?.[1]).toBe(30_000);
  });

  it('reports a refused clipboard write rather than claiming the key was copied', async () => {
    mockCopySecret.mockRejectedValueOnce(new Error('refused'));
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    await act(async () => {
      fireEvent.click(screen.getAllByRole('button', { name: /Copy secret key for Acme/ })[0]!);
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to copy', type: 'error' }) as unknown as Record<
          string,
          unknown
        >,
      );
    });
  });

  it('says so when the key has already been torn down', async () => {
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    endScanSession();
    await act(async () => {
      fireEvent.click(screen.getAllByRole('button', { name: /Copy secret key for Acme/ })[0]!);
    });

    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'error' }) as unknown as Record<string, unknown>,
    );
    expect(mockCopySecret).not.toHaveBeenCalled();
  });

  it('hides the key again once revealed', async () => {
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    const reveal = screen.getAllByRole('button', { name: /show key/i })[0]!;
    await act(async () => {
      fireEvent.click(reveal);
    });
    expect(document.body.textContent).toContain('JBSWY3DPEHPK3PXP');

    await act(async () => {
      fireEvent.click(screen.getAllByRole('button', { name: /hide key/i })[0]!);
    });
    expect(document.body.textContent).not.toContain('JBSWY3DPEHPK3PXP');
  });
});

describe('a single account code, not a full export', () => {
  it('reads an ordinary otpauth link and lists it', async () => {
    // Worth accepting: the decoder is already here, and it is what a user tries
    // next once they have scanned their Google export.
    await renderFlow();
    await readExportRaw(
      'otpauth://totp/GitHub:dev@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub',
    );

    expect(await screen.findByText('GitHub')).toBeInTheDocument();
    expect(screen.getByText('dev@example.com')).toBeInTheDocument();
  });

  it('keeps an eight-digit link at eight digits', async () => {
    await renderFlow();
    await readExportRaw('otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP&digits=8&algorithm=SHA512');
    expect(await screen.findByText('8 digits')).toBeInTheDocument();
    expect(screen.getByText('SHA512')).toBeInTheDocument();
  });

  it('says so when the code is not an authenticator code at all', async () => {
    await renderFlow();
    await readExportRaw('https://example.com/not-a-code');
    expect(screen.getByText(/not an authenticator code this app can read/)).toBeInTheDocument();
  });
});

describe('attaching to a login the user picks', () => {
  const EXISTING = {
    id: 'item-1',
    name: 'Acme account',
    itemType: 'login',
    data: { username: 'alice@example.com', password: 'p', uris: [], customFields: [] },
  };

  async function openPickerAndChoose() {
    await act(async () => {
      fireEvent.click(screen.getAllByRole('button', { name: /add to a login/i })[0]!);
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('option', { name: /Acme account/ }));
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /add code/i }));
    });
  }

  it('writes the code onto the chosen item and nowhere else', async () => {
    vaultState.items = [EXISTING];
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    await openPickerAndChoose();

    expect(mockUpdateItem).toHaveBeenCalledTimes(1);
    const [id, itemType, name, data] = mockUpdateItem.mock.calls[0] as [
      string,
      string,
      string,
      Record<string, unknown>,
    ];
    expect(id).toBe('item-1');
    expect(itemType).toBe('login');
    expect(name).toBe('Acme account');
    expect(String(data.totp)).toContain('otpauth://totp/');
    // Everything else on the item survives: this is a merge, not a replacement.
    expect(data.username).toBe('alice@example.com');
    expect(data.password).toBe('p');
    expect(await screen.findByText('Added to Acme account')).toBeInTheDocument();
  });

  it('preserves an existing code in a custom field, which is the undo', async () => {
    vaultState.items = [
      { ...EXISTING, data: { ...EXISTING.data, totp: 'JBSWY3DPEHPK3PXPJBSWY3DPEB' } },
    ];
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    await openPickerAndChoose();

    const data = (mockUpdateItem.mock.calls[0] as unknown[])[3] as Record<string, unknown>;
    const fields = data.customFields as { name: string; value: string; type: string }[];
    expect(fields).toContainEqual({
      name: 'Previous TOTP',
      value: 'JBSWY3DPEHPK3PXPJBSWY3DPEB',
      type: 'hidden',
    });
  });

  it('reports a write that failed rather than claiming success', async () => {
    vaultState.items = [EXISTING];
    mockUpdateItem.mockRejectedValueOnce(new Error('nope'));
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    await openPickerAndChoose();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ type: 'error' }) as unknown as Record<string, unknown>,
      );
    });
    expect(screen.queryByText('Added to Acme account')).not.toBeInTheDocument();
  });

  it('closes the picker when the dialog itself is dismissed', async () => {
    // Escape is the dialog's own close, which goes through a different path than
    // the Cancel button: the dialog tells the page it closed, rather than the
    // page deciding to close it.
    vaultState.items = [EXISTING];
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    await act(async () => {
      fireEvent.click(screen.getAllByRole('button', { name: /add to a login/i })[0]!);
    });
    expect(screen.getByText(/Choose the login that/)).toBeInTheDocument();

    await act(async () => {
      fireEvent.keyDown(document, { key: 'Escape' });
    });

    expect(screen.queryByText(/Choose the login that/)).not.toBeInTheDocument();
    expect(mockUpdateItem).not.toHaveBeenCalled();
  });

  it('closes the picker without writing anything on cancel', async () => {
    vaultState.items = [EXISTING];
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    await act(async () => {
      fireEvent.click(screen.getAllByRole('button', { name: /add to a login/i })[0]!);
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }));
    });

    expect(mockUpdateItem).not.toHaveBeenCalled();
  });
});

describe('when a write fails', () => {
  it('reports a failed login creation rather than marking the card done', async () => {
    mockCreateItem.mockRejectedValueOnce(new Error('nope'));
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    await act(async () => {
      fireEvent.click(screen.getAllByRole('button', { name: /new login/i })[0]!);
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ type: 'error' }) as unknown as Record<string, unknown>,
      );
    });
    expect(screen.queryByText('Added to Acme')).not.toBeInTheDocument();
  });

  it('reports a failed document save', async () => {
    mockStartUpload.mockRejectedValueOnce(new Error('nope'));
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /save all to documents/i }));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ type: 'error' }) as unknown as Record<string, unknown>,
      );
    });
  });
});

describe('leaving the page', () => {
  it('discards every decoded key on "Start over"', async () => {
    const onStartOver = vi.fn();
    render(
      <MemoryRouter>
        <TotpImportFlow onStartOver={onStartOver} />
      </MemoryRouter>,
    );
    await act(async () => {
      await Promise.resolve();
    });
    await readExport();
    await screen.findByText('Acme');
    expect(heldSecretCount()).toBeGreaterThan(0);

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /start over/i }));
    });

    // The keys are zeroed BEFORE the page is told to remount, so there is no
    // window in which the old set is still readable.
    expect(heldSecretCount()).toBe(0);
    expect(onStartOver).toHaveBeenCalled();
  });

  it('leaves the vault when done', async () => {
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /^done$/i }));
    });
    expect(mockNavigate).toHaveBeenCalledWith('/vault');
  });

  it('zeroes the keys when the page unmounts, however it is left', async () => {
    const { unmount } = render(
      <MemoryRouter>
        <TotpImportFlow onStartOver={vi.fn()} />
      </MemoryRouter>,
    );
    await act(async () => {
      await Promise.resolve();
    });
    await readExport();
    await screen.findByText('Acme');

    await act(async () => {
      unmount();
    });

    // An in-SPA route change away from the tool unmounts it, so this is the path
    // that covers navigating away as well as closing the tab.
    expect(heldSecretCount()).toBe(0);
  });

  it('refuses a part that clashes with one already read', async () => {
    await renderFlow();
    const first = encodeMigrationUri({
      entries: [{ secret: Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]), name: 'A:a' }],
      batchSize: 2,
      batchIndex: 0,
      batchId: 55,
    });
    const clashing = encodeMigrationUri({
      entries: [{ secret: Uint8Array.from([9, 9, 9, 9, 9, 9, 9, 9, 9, 9]), name: 'B:b' }],
      batchSize: 2,
      batchIndex: 0,
      batchId: 55,
    });
    await readExportRaw(first);
    await readExportRaw(clashing);

    expect(screen.getByText(/does not match the ones already read/)).toBeInTheDocument();
  });

  it('zeroes the keys when the tab goes away', async () => {
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');
    expect(heldSecretCount()).toBeGreaterThan(0);

    // `pagehide` is the terminal event a browser guarantees, where `unload` is
    // not fired at all on a mobile tab discard.
    await act(async () => {
      window.dispatchEvent(new Event('pagehide'));
    });
    expect(heldSecretCount()).toBe(0);
  });

  it('says so when a key has gone between opening the picker and confirming', async () => {
    vaultState.items = [
      {
        id: 'item-1',
        name: 'Acme account',
        itemType: 'login',
        data: { username: 'a', password: 'p', uris: [], customFields: [] },
      },
    ];
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    await act(async () => {
      fireEvent.click(screen.getAllByRole('button', { name: /add to a login/i })[0]!);
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('option', { name: /Acme account/ }));
    });

    // A lock landing while the picker is open is the realistic way here.
    endScanSession();
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /add code/i }));
    });

    expect(mockUpdateItem).not.toHaveBeenCalled();
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'That key is no longer available' }) as unknown as Record<
        string,
        unknown
      >,
    );
  });

  it('says so when a key has gone before an action uses it', async () => {
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    endScanSession();
    await act(async () => {
      fireEvent.click(screen.getAllByRole('button', { name: /new login/i })[0]!);
    });
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'That key is no longer available' }) as unknown as Record<
        string,
        unknown
      >,
    );
    expect(mockCreateItem).not.toHaveBeenCalled();
  });
});

describe('saving to Documents', () => {
  it('writes one otpauth URI per line, as plain text', async () => {
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /save all to documents/i }));
    });

    await waitFor(() => {
      expect(mockStartUpload).toHaveBeenCalledTimes(1);
    });
    const call = mockStartUpload.mock.calls[0]?.[0] as { source: Blob; mime: string; name: string };
    expect(call.mime).toBe('text/plain');
    expect(call.name).toMatch(/^google-authenticator-import-\d{4}-\d{2}-\d{2}\.txt$/);
    const text = await call.source.text();
    expect(text).toContain('otpauth://totp/');
    expect(text.split('\n').filter((line) => line.startsWith('otpauth://'))).toHaveLength(2);
    // The file says what it is, in the file.
    expect(text).toContain('Anyone who reads this file can generate');
  });

  it('refuses rather than pretending, when the server has no document storage', async () => {
    mockFreshConfig.mockResolvedValueOnce(null);
    await renderFlow();
    await readExport();
    await screen.findByText('Acme');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /save all to documents/i }));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ type: 'error' }) as unknown as Record<string, unknown>,
      );
    });
    expect(mockStartUpload).not.toHaveBeenCalled();
  });
});
