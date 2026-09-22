/**
 * SettingsPage — branch / error-path coverage.
 *
 * Complements tests/settings-pages.test.tsx (happy paths) by driving the
 * behaviors that only surface on the failure and edge branches:
 *  - master password change: locked vault guard, and the exact crypto wiring
 *    (authHash from the CURRENT password, vault key re-wrapped with the NEW MEK)
 *  - 2FA: wrong verify code, wrong disable code, Enter-to-submit, cancel,
 *    secret + backup-code clipboard copy
 *  - vault key rotation: the real re-encryption loop (paginated items + trash +
 *    password history + folders), the per-item / per-folder abort paths, the
 *    locked-vault guard and the server-failure path
 *  - import/export: CSV mapping payload, duplicate reporting, failure toasts
 *  - the settings form: edited values reach the API and the settings cache is
 *    invalidated
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Mock } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import React from 'react';
// Imported rather than written out as a decimal literal. The framing sizes have
// ONE definition, and `packages/shared/tests/constants.test.ts` scans this whole
// repository for a second copy of either of them — including inside comments,
// which is why this note does not quote the number — because a fixture that
// drifts from the real value is a test asserting against a document layout that
// does not exist.
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES, MAX_DOCUMENTS_PER_ROTATION } from '@hvault/shared';

vi.hoisted(() => {
  if (typeof globalThis.window !== 'undefined') {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      configurable: true,
      value: (query: string) => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: () => {},
        removeListener: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => false,
      }),
    });
  }
});

const {
  mockGetProfileApi,
  mockUpdateSettingsApi,
  mockChangePasswordApi,
  mockSetup2faApi,
  mockVerify2faApi,
  mockDisable2faApi,
  mockRegenerateBackupCodesApi,
  mockExportVaultApi,
  mockImportVaultApi,
  mockToast,
  mockSetTheme,
  mockApiPost,
  mockClearSettingsCache,
  mockWriteText,
  mockReadDocumentsConfigFresh,
  mockListDocuments,
  mockListDocumentTrash,
  mockDeriveWrapKey,
  mockUnwrapDek,
  mockWrapDek,
  mockZeroDek,
  mockDeriveMetaKey,
  mockDecryptMeta,
  mockDeriveStreamKey,
} = vi.hoisted(() => ({
  mockGetProfileApi: vi.fn(),
  mockUpdateSettingsApi: vi.fn(),
  mockChangePasswordApi: vi.fn(),
  mockSetup2faApi: vi.fn(),
  mockVerify2faApi: vi.fn(),
  mockDisable2faApi: vi.fn(),
  mockRegenerateBackupCodesApi: vi.fn(),
  mockExportVaultApi: vi.fn(),
  mockImportVaultApi: vi.fn(),
  mockToast: vi.fn(),
  mockSetTheme: vi.fn(),
  mockApiPost: vi.fn(),
  mockClearSettingsCache: vi.fn(),
  mockWriteText: vi.fn(),
  mockReadDocumentsConfigFresh: vi.fn(),
  mockListDocuments: vi.fn(),
  mockListDocumentTrash: vi.fn(),
  mockDeriveWrapKey: vi.fn(),
  mockUnwrapDek: vi.fn(),
  mockWrapDek: vi.fn(),
  mockZeroDek: vi.fn(),
  mockDeriveMetaKey: vi.fn(),
  mockDecryptMeta: vi.fn(),
  mockDeriveStreamKey: vi.fn(),
}));

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
  isStorageDegraded: vi.fn().mockReturnValue(false),
}));

vi.mock('../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn(),
    getAuthHash: vi.fn(),
    encryptVaultKey: vi.fn(),
    decryptVaultKey: vi.fn(),
    importVaultKey: vi.fn(),
    encryptData: vi.fn(),
    decryptData: vi.fn(),
    generateSearchHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn(),
    rotateVaultKey: vi.fn(),
    deriveBEK: vi.fn(),
    decryptBWK: vi.fn(),
    encryptVaultKeyWithBWK: vi.fn(),
    base64ToArrayBuffer: vi.fn(),
  },
}));

vi.mock('../src/services/api/authApi', () => ({
  registerApi: vi.fn(),
  loginApi: vi.fn(),
  login2faApi: vi.fn(),
  logoutApi: vi.fn().mockResolvedValue({ data: { success: true } }),
  lockApi: vi.fn().mockResolvedValue({ data: { success: true } }),
}));

vi.mock('../src/services/api/vaultApi', () => ({
  listItemsApi: vi.fn(),
  listTrashApi: vi.fn(),
  listFoldersApi: vi.fn(),
  bulkReEncryptApi: vi.fn(),
}));

/**
 * The document store's two list endpoints, and nothing else in the module.
 *
 * `importActual` rather than a full replacement, deliberately: `DOCUMENT_PAGE_SIZE`
 * and `MAX_DOCUMENT_PAGES` stay REAL, so the assertion that the rotation asks for
 * `limit: DOCUMENT_PAGE_SIZE` is an assertion about the shared page size rather than
 * about a number this file invented. It also keeps `documentsStore`, which imports a
 * dozen other members of this module, loadable — `authStore` pulls it in.
 */
vi.mock('../src/services/api/documentsApi', async () => {
  const actual = await vi.importActual<typeof import('../src/services/api/documentsApi')>(
    '../src/services/api/documentsApi',
  );
  return {
    ...actual,
    listDocumentsApi: (...args: unknown[]) => mockListDocuments(...args),
    listDocumentTrashApi: (...args: unknown[]) => mockListDocumentTrash(...args),
  };
});

/**
 * Whether this server has a document store, as the rotation asks it.
 *
 * The rotation reads `readDocumentsConfigFresh`, NOT the memoised
 * `getDocumentsConfig` beside it: the memo caches its own failure fallback for the
 * life of the tab, and one transient `/config` blip must not be able to decide
 * whether every document key gets re-wrapped. The distinction is the subject of one
 * of the tests below, so the stub is on the fresh reader and the memoised one is
 * deliberately left real and unused — a rotation that reached for it would go to
 * the network here and fail loudly rather than quietly answering `{ enabled: false }`.
 *
 * Stubbed at all because a real resolver would still be uncached but would issue a
 * request this suite has no server for; the value is the knob each test turns.
 */
vi.mock('../src/services/api/configApi', async () => {
  const actual = await vi.importActual<typeof import('../src/services/api/configApi')>(
    '../src/services/api/configApi',
  );
  return {
    ...actual,
    readDocumentsConfigFresh: (...args: unknown[]) => mockReadDocumentsConfigFresh(...args),
  };
});

/**
 * Document crypto, stubbed in the same distinguishable style as `cryptoService`
 * above: every derived value carries the key and the document it came from, so a
 * test can prove WHICH vault key wrapped WHICH document rather than merely that
 * something was wrapped. The real primitives have their own suites
 * (`document-crypto.test.ts` and the committed known-answer vectors); what is under
 * test here is `SettingsPage`'s wiring of them.
 *
 * `importActual` again, because `documentsStore` imports nine other members of this
 * module and a partial factory would leave them undefined at import time. The three
 * METADATA functions are overridden too, even though the rotation must never reach
 * them: that is exactly what makes "no metadata is decrypted" assertable.
 */
vi.mock('../src/services/crypto/documentCryptoService', async () => {
  const actual = await vi.importActual<
    typeof import('../src/services/crypto/documentCryptoService')
  >('../src/services/crypto/documentCryptoService');
  return {
    ...actual,
    deriveWrapKey: (...args: unknown[]) => mockDeriveWrapKey(...args),
    unwrapDek: (...args: unknown[]) => mockUnwrapDek(...args),
    wrapDek: (...args: unknown[]) => mockWrapDek(...args),
    zeroDek: (...args: unknown[]) => mockZeroDek(...args),
    deriveMetaKey: (...args: unknown[]) => mockDeriveMetaKey(...args),
    decryptMeta: (...args: unknown[]) => mockDecryptMeta(...args),
    deriveStreamKey: (...args: unknown[]) => mockDeriveStreamKey(...args),
  };
});

vi.mock('../src/services/api/userApi', () => ({
  getProfileApi: (...args: unknown[]) => mockGetProfileApi(...args),
  updateSettingsApi: (...args: unknown[]) => mockUpdateSettingsApi(...args),
  changePasswordApi: (...args: unknown[]) => mockChangePasswordApi(...args),
  setup2faApi: (...args: unknown[]) => mockSetup2faApi(...args),
  verify2faApi: (...args: unknown[]) => mockVerify2faApi(...args),
  disable2faApi: (...args: unknown[]) => mockDisable2faApi(...args),
  regenerateBackupCodesApi: (...args: unknown[]) => mockRegenerateBackupCodesApi(...args),
  exportVaultApi: (...args: unknown[]) => mockExportVaultApi(...args),
  importVaultApi: (...args: unknown[]) => mockImportVaultApi(...args),
}));

vi.mock('../src/services/offlineCache', async (importOriginal) => ({
  // Spread the real module so exports it grows (the error class, the
  // classifier) stay real; only the IndexedDB-backed singleton is faked.
  ...(await importOriginal<typeof import('../src/services/offlineCache')>()),
  offlineCache: {
    // `setUser` is not optional plumbing and the double must carry it. `authStore`
    // awaits it as the FIRST statement of the try/catch that scopes the offline
    // database to the account signing in — the control that stops one account
    // reading another's cached ciphertext — so a double without it calls
    // `undefined(...)`, throws synchronously, and takes the catch branch before
    // `clear()` is reached either. Nothing here asserts that branch; what it cost
    // was a `TypeError` in the run's output and a login path quietly exercising its
    // failure arm. The real scoping behaviour is tested against the unmocked module
    // in `offlineCache.test.ts`.
    setUser: vi.fn().mockResolvedValue(undefined),
    cacheItems: vi.fn().mockResolvedValue(undefined),
    cacheFolders: vi.fn().mockResolvedValue(undefined),
    getCachedItems: vi.fn().mockResolvedValue([]),
    getCachedFolders: vi.fn().mockResolvedValue([]),
    clear: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/api/client', () => ({
  clearCsrfToken: vi.fn(),
  api: {
    get: vi.fn(),
    post: (...args: unknown[]) => mockApiPost(...args),
    put: vi.fn(),
    delete: vi.fn(),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
    defaults: { headers: { common: {} } },
  },
}));

vi.mock('../src/hooks/useUserSettings', () => ({
  useUserSettings: vi.fn().mockReturnValue({
    autoLockTimeout: 15,
    clipboardClearTimeout: 30,
    theme: 'system',
  }),
  clearSettingsCache: (...args: unknown[]) => mockClearSettingsCache(...args),
}));

vi.mock('../src/components/ui/Toast', () => ({
  useToast: vi.fn().mockReturnValue({
    toast: (...args: unknown[]) => mockToast(...args),
    dismiss: vi.fn(),
    update: vi.fn(),
  }),
  ToastProvider: ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
  Toaster: () => null,
}));

vi.mock('qrcode', () => ({
  default: {
    toDataURL: vi.fn().mockResolvedValue('data:image/png;base64,mockqr'),
  },
}));

// Mock the LAZY LOADER as well as the library, delegating to whatever this file
// mocked `zxcvbn` to be. `lazyZxcvbn` caches the resolved library in a
// module-level binding, and the pages that gate on strength call `getZxcvbn()`
// from both a mount effect and a submit handler — two concurrent cold dynamic
// imports racing for one cache slot, where a win by the unmocked module makes
// every later assertion in the file score against the REAL zxcvbn. Order used to
// hide it; `sequence.shuffle` does not.
vi.mock('../src/lib/lazyZxcvbn', async () => {
  const zxcvbn = await import('zxcvbn');
  return { getZxcvbn: () => Promise.resolve(zxcvbn.default) };
});

vi.mock('zxcvbn', () => ({
  default: (password?: string) => {
    if (!password) return { score: 0, feedback: { warning: '', suggestions: [] } };
    if (password.length <= 8) return { score: 2, feedback: { warning: 'Fair', suggestions: [] } };
    return { score: 4, feedback: { warning: '', suggestions: [] } };
  },
}));

/**
 * A seam on ONE function of the real import service, for one test.
 *
 * `SettingsPage` reports WHICH item was skipped and why, not just how many, and
 * that promise lives in a spread at `SettingsPage.tsx:958-962`. Until Task 20.5
 * it was reachable from a real file — a card number past its bound discarded the
 * whole card — but clamping those eleven scalars removed the last input any
 * parser can turn into an item its own schema rejects, so nothing in the
 * application can produce a skip any more. That is the better state, and it left
 * the promise with no test: deleting the `description` spread would have gone
 * unnoticed.
 *
 * Everything else in the module stays REAL (`importActual`), and the override is
 * null for every other test in this file, so no other assertion is affected. The
 * unit under test is `SettingsPage`; `validateImportItems` is a collaborator, and
 * standing in for a collaborator whose real inputs no longer exist is the honest
 * way to keep testing the caller's own behaviour.
 */
let mockValidateImportOverride: ((parsed: unknown[]) => unknown) | null = null;

vi.mock('../src/services/import', async () => {
  const actual =
    await vi.importActual<typeof import('../src/services/import')>('../src/services/import');
  return {
    ...actual,
    validateImportItems: (parsed: never) =>
      mockValidateImportOverride
        ? mockValidateImportOverride(parsed as unknown[])
        : actual.validateImportItems(parsed),
  };
});

import { useAuthStore } from '../src/stores/authStore';
import { useUIStore } from '../src/stores/uiStore';
import { cryptoService } from '../src/services/crypto/cryptoService';
import {
  listItemsApi,
  listTrashApi,
  listFoldersApi,
  bulkReEncryptApi,
} from '../src/services/api/vaultApi';
import { DOCUMENT_PAGE_SIZE, MAX_DOCUMENT_PAGES } from '../src/services/api/documentsApi';

// ---------------------------------------------------------------------------
// Typed handles on the mocks
// ---------------------------------------------------------------------------

/**
 * The whole module is `vi.mock`ed, so every member is a Mock. Mapping over the
 * real key set (rather than a `Record<string, Mock>` index signature) keeps a
 * typo in a stub name a compile error instead of `possibly undefined`.
 */
type MockedCryptoService = { [K in keyof typeof cryptoService]: Mock };

const cs = cryptoService as unknown as MockedCryptoService;
const mockListItems = listItemsApi as unknown as Mock;
const mockListTrash = listTrashApi as unknown as Mock;
const mockListFolders = listFoldersApi as unknown as Mock;
const mockBulkReEncrypt = bulkReEncryptApi as unknown as Mock;

/** Sentinel objects standing in for opaque CryptoKeys. */
const OLD_VAULT_KEY = { key: 'old-vault-key' } as unknown as CryptoKey;
const NEW_VAULT_KEY = { key: 'new-vault-key' } as unknown as CryptoKey;
/**
 * The key a session holding a SUPERSEDED one recovers from the profile after a
 * stale-generation refusal. Distinct from all three above, so "the retry
 * re-wrapped the LIVE key" is assertable rather than merely "something was
 * re-wrapped".
 */
const LIVE_VAULT_KEY = { key: 'live-vault-key' } as unknown as CryptoKey;
/**
 * The key a CRASHED rotation was moving to, recovered from the profile's pending
 * wrapper. Distinct from `NEW_VAULT_KEY` (which `rotateVaultKey` mints) precisely
 * so "the finish path re-used the in-flight key" is assertable rather than merely
 * "some key was used": minting a fresh one there would strand every row the crash
 * had already re-sealed.
 */
const PENDING_VAULT_KEY = { key: 'pending-vault-key' } as unknown as CryptoKey;
const MEK = { key: 'mek' } as unknown as CryptoKey;

/**
 * The interrupted rotation's wrapper, exactly as `GET /user/profile` reports it
 * once login recovery has lowered the fence and KEPT the key.
 */
const PENDING_WRAPPER = {
  interruptedRotation: true,
  pendingEncryptedVaultKey: 'pending-wrapped-vault-key',
  pendingVaultKeyIv: 'pending-vk-iv',
  pendingVaultKeyTag: 'pending-vk-tag',
} as const;

/**
 * Deterministic, *distinguishable* crypto stubs: every derived value carries the
 * input it came from, so a test can prove WHICH password / WHICH key was used.
 */
function installCryptoStubs() {
  cs.deriveKeys.mockImplementation((password: string) =>
    Promise.resolve({
      masterEncryptionKey: { mek: password },
      authKey: { ak: password },
    }),
  );
  cs.getAuthHash.mockImplementation((k: { ak: string }) => `hash:${k.ak}`);
  cs.encryptVaultKey.mockImplementation((_vk: unknown, mek: { mek: string }) =>
    Promise.resolve({ encrypted: `vk-wrapped-with:${mek.mek}`, iv: 'vkIv', tag: 'vkTag' }),
  );
  cs.decryptData.mockImplementation((enc: string) => Promise.resolve(`plain:${enc}`));
  cs.encryptData.mockImplementation((plain: string, key: { key: string }) =>
    Promise.resolve({ encrypted: `enc:${plain}`, iv: `iv:${key.key}`, tag: `tag:${key.key}` }),
  );
  cs.generateSearchHash.mockImplementation((name: string) => Promise.resolve(`sh:${name}`));
  cs.rotateVaultKey.mockResolvedValue({
    newVaultKey: NEW_VAULT_KEY,
    encrypted: 'newEnc',
    iv: 'newIv',
    tag: 'newTag',
  });
  cs.clearKey.mockReturnValue(undefined);
  cs.clearCryptoKey.mockResolvedValue(undefined);
  cs.deriveBEK.mockResolvedValue({ key: 'bek' });
  cs.decryptBWK.mockResolvedValue(new Uint8Array(32));
  cs.encryptVaultKeyWithBWK.mockResolvedValue({
    encrypted: 'bwkEncVK',
    iv: 'bwkVKIv',
    tag: 'bwkVKTag',
  });
  cs.base64ToArrayBuffer.mockReturnValue(new Uint8Array(16));
  // The wrapped-key round trip the stale-generation retry performs. `decryptVaultKey`
  // names the wrapper AND the MEK it opened it with, and `importVaultKey` refuses
  // anything else, so a retry that unwrapped the session's own stale wrapper — or
  // unwrapped the live one under the wrong MEK — fails here rather than passing with
  // a plausible-looking payload.
  cs.decryptVaultKey.mockImplementation(
    (encrypted: string, _iv: string, _tag: string, mek: { key: string }) =>
      Promise.resolve(`raw:${encrypted}:under:${mek.key}`),
  );
  cs.importVaultKey.mockImplementation((raw: string) => {
    if (raw === `raw:${LIVE_PROFILE_WRAPPER.encryptedVaultKey}:under:mek`) {
      return Promise.resolve(LIVE_VAULT_KEY);
    }
    // The same round trip for the interrupted rotation's pending wrapper: the
    // finish path must open THAT wrapper, under the account's MEK, and nothing else.
    if (raw === `raw:${PENDING_WRAPPER.pendingEncryptedVaultKey}:under:mek`) {
      return Promise.resolve(PENDING_VAULT_KEY);
    }
    return Promise.reject(new Error(`unexpected raw vault key: ${String(raw)}`));
  });
}

/**
 * The account's LIVE wrapped vault key, as `GET /user/profile` reports it.
 *
 * Deliberately different from anything this session holds: the store's
 * `encryptedVaultKeyData` moves with the key the session has, so on a session
 * holding a superseded key it is exactly as stale as the wrapper that was just
 * refused — which is why the retry has to re-read the profile rather than reuse it.
 */
const LIVE_PROFILE_WRAPPER = {
  encryptedVaultKey: 'live-wrapped-vault-key',
  vaultKeyIv: 'live-vk-iv',
  vaultKeyTag: 'live-vk-tag',
  // DELIBERATELY not the number the refusal below carries. The profile read
  // happens after the refusal, so a further rotation can have landed in between,
  // and the retry must name the generation that goes with the wrapper it actually
  // unwrapped. With the two equal, a retry that echoed the refusal's number would
  // be indistinguishable from one that read the profile's.
  vaultKeyVersion: 6,
} as const;

const defaultProfile = {
  email: 'test@example.com',
  emailVerified: true,
  twoFactorEnabled: false,
  // Present because the real response carries them: they are required on
  // `IUserProfile` and are how a cold-start resume — and the stale-generation
  // retry below — recover the live wrapped vault key.
  ...LIVE_PROFILE_WRAPPER,
  // The real response always carries it, and `false` is what an account with no
  // half-finished rotation gets. Spelled out rather than left absent so that a
  // test overriding it to `true` is overriding a value rather than inventing one.
  interruptedRotation: false,
  kdfIterations: 600_000,
  settings: {
    autoLockTimeout: 15,
    // Mirrors the real profile response, which carries both hidden-tab lock
    // fields. (The page still `??`-defaults them, for accounts created before
    // they existed.)
    lockOnHidden: false,
    lockOnHiddenDelay: 1,
    clipboardClearTimeout: 30,
    theme: 'system' as const,
    backup: {
      enabled: false,
      scheduleHour: 3,
      backupEmails: [],
      isConfigured: false,
    },
  },
};

function setProfile(overrides: Record<string, unknown> = {}) {
  mockGetProfileApi.mockResolvedValue({
    data: { success: true, data: { ...defaultProfile, ...overrides } },
  });
}

async function renderSettings() {
  const { default: SettingsPage } = await import('../src/pages/SettingsPage');
  await act(async () => {
    render(
      <MemoryRouter>
        <SettingsPage />
      </MemoryRouter>,
    );
  });
  await waitFor(() => {
    expect(screen.getByText('Settings')).toBeInTheDocument();
  });
}

/** Rotation with an empty vault, unless a test overrides these. */
function installEmptyVaultRotationApis() {
  mockListItems.mockResolvedValue({
    data: { success: true, data: [], pagination: { totalPages: 1 } },
  });
  mockListTrash.mockResolvedValue({
    data: { success: true, data: [], pagination: { totalPages: 1 } },
  });
  mockListFolders.mockResolvedValue({ data: { success: true, data: [] } });
  mockBulkReEncrypt.mockResolvedValue({ data: { success: true } });
  mockListDocuments.mockResolvedValue({
    data: { success: true, data: [], pagination: { totalPages: 1 } },
  });
  mockListDocumentTrash.mockResolvedValue({
    data: { success: true, data: [], pagination: { totalPages: 1 } },
  });
}

/**
 * The DEK handed out for each document, keyed by document id, so a test can prove
 * every one of them was zeroed by the time the rotation finished or aborted.
 */
const issuedDeks = new Map<string, Uint8Array>();

/**
 * Distinguishable document-crypto stubs.
 *
 * A "wrap key" here is `{ wrapFor: <documentId>, under: <vault key name> }`, which
 * is the pair the real `deriveWrapKey` binds together; `unwrapDek` REFUSES a key
 * that is not the old one and `wrapDek` stamps both into its output, so a payload
 * entry names the key it was wrapped under and the document it was bound to.
 */
function installDocumentCryptoStubs() {
  issuedDeks.clear();
  mockReadDocumentsConfigFresh.mockResolvedValue({ enabled: false });

  mockDeriveWrapKey.mockImplementation((vaultKey: { key: string }, documentId: string) =>
    Promise.resolve({ wrapFor: documentId, under: vaultKey.key }),
  );

  mockUnwrapDek.mockImplementation(
    (wrapped: { encryptedDek: string }, wrapKey: { wrapFor: string; under: string }) => {
      // The stored wrapped key only ever opens under the key it was wrapped with.
      if (wrapKey.under !== 'old-vault-key') {
        return Promise.reject(new Error(`cannot unwrap ${wrapped.encryptedDek} under a new key`));
      }
      const dek = new Uint8Array(32).fill(7);
      issuedDeks.set(wrapKey.wrapFor, dek);
      return Promise.resolve(dek);
    },
  );

  mockWrapDek.mockImplementation((_dek: Uint8Array, wrapKey: { wrapFor: string; under: string }) =>
    Promise.resolve({
      encryptedDek: `dek@${wrapKey.under}:${wrapKey.wrapFor}`,
      dekIv: `dekIv:${wrapKey.under}`,
      dekTag: `dekTag:${wrapKey.under}`,
    }),
  );

  // The real one overwrites the buffer; so does this, because "every DEK was
  // zeroed" is asserted on the buffers themselves rather than on a call count.
  mockZeroDek.mockImplementation((dek: Uint8Array) => {
    dek.fill(0);
  });
}

/**
 * A 24-hex ObjectId ending in the given number.
 *
 * Real-shaped rather than `'d1'`, because `deriveWrapKey` parses the id it is given
 * and refuses anything that is not an ObjectId; a fixture the real function would
 * reject would make every assertion here true of a request that cannot happen.
 */
function docId(n: number): string {
  return `66c0f1a2b3c4d5e6f7a8b9${String(n).padStart(2, '0')}`;
}

/**
 * One document row, carrying the four fields a rotation reads and the rest of the
 * columns for shape.
 *
 * Deliberately NOT a row `documentResponseSchema` would accept: `streamSalt` and
 * `noncePrefix` are not base64 of their exact byte counts. That is the stronger
 * statement, and it is the invariant under test — a rotation validates nothing,
 * because it needs only the id and the wrapped key, and refusing a row the DISPLAY
 * path would refuse is exactly how a document gets left behind under a vault key
 * that is about to stop existing.
 */
function documentRow(id: string) {
  return {
    _id: id,
    favorite: false,
    encryptedDek: `${id}-dek`,
    dekIv: `${id}-dekIv`,
    dekTag: `${id}-dekTag`,
    streamSalt: `${id}-salt`,
    noncePrefix: `${id}-prefix`,
    encryptedMeta: `${id}-meta`,
    metaIv: `${id}-metaIv`,
    metaTag: `${id}-metaTag`,
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount: 1,
    ciphertextBytes: 16,
    plaintextBytes: 0,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  };
}

/** One page of a document list response. */
function documentPage(rows: ReturnType<typeof documentRow>[], totalPages = 1) {
  return { data: { success: true, data: rows, pagination: { totalPages } } };
}

describe('SettingsPage — error paths and branches', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // The seam is inert unless a test opts in, so no other assertion in this
    // file runs against anything but the real import service.
    mockValidateImportOverride = null;
    installCryptoStubs();
    installDocumentCryptoStubs();
    installEmptyVaultRotationApis();
    setProfile();

    useAuthStore.setState({
      accessToken: 'test-token',
      user: { userId: 'u1', email: 'test@example.com' },
      isAuthenticated: true,
      isLocked: false,
      vaultKey: OLD_VAULT_KEY,
      mek: MEK,
      encryptedVaultKeyData: null,
      // Deliberately NOT zero: the generation this session records has to move
      // WITH its key, and a base of 0 would let an off-by-one pass as a default.
      vaultKeyVersion: 4,
    } as never);
    // `staleVaultKeyVersion` is app-wide state that no mock reset clears, so it
    // is reset here: a case that leaves it set would decide the next one's.
    useUIStore.setState({ theme: 'dark', setTheme: mockSetTheme, staleVaultKeyVersion: null });

    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: mockWriteText.mockResolvedValue(undefined) },
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // Master password change
  // -------------------------------------------------------------------------

  async function openChangePassword(current: string, next: string, confirm = next) {
    fireEvent.click(screen.getByText('Change'));
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: current },
    });
    fireEvent.change(screen.getByPlaceholderText('New master password'), {
      target: { value: next },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), {
      target: { value: confirm },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Change Password'));
    });
  }

  it('sends the authHash of the CURRENT password and a vault key re-wrapped with the NEW MEK', async () => {
    mockChangePasswordApi.mockResolvedValue({ data: { success: true } });
    await renderSettings();

    await openChangePassword('OldMasterPassword1!', 'NewMasterPassword1!');

    await waitFor(() => {
      expect(mockChangePasswordApi).toHaveBeenCalledWith({
        currentAuthHash: 'hash:OldMasterPassword1!',
        newAuthHash: 'hash:NewMasterPassword1!',
        newEncryptedVaultKey: 'vk-wrapped-with:NewMasterPassword1!',
        newVaultKeyIv: 'vkIv',
        newVaultKeyTag: 'vkTag',
        // WHICH vault key that wrapper was built from. This request REPLACES the
        // stored wrapper, so without the generation the server cannot tell a
        // wrapper for the live key from one for a key a rotation elsewhere has
        // already superseded — and storing the latter costs the whole vault.
        // Asserted as the store's own value (4, set in `beforeEach`), not zero,
        // so a hard-coded or defaulted number fails here.
        vaultKeyVersion: 4,
      });
    });
    // The existing vault key (not a freshly generated one) is re-wrapped.
    expect(cs.encryptVaultKey).toHaveBeenCalledWith(OLD_VAULT_KEY, { mek: 'NewMasterPassword1!' });
  });

  // ── The stale-generation refusal, and the one retry it earns ────────────

  /**
   * The recoverable refusal, exactly as the server renders it: a 409 whose body
   * carries the account's CURRENT generation in `data`.
   */
  function staleGenerationRefusal(current: number): unknown {
    return {
      isAxiosError: true,
      response: {
        status: 409,
        data: {
          success: false,
          message: `The vault key was rotated elsewhere. Reload to pick up vault key version ${String(current)}, then retry this change.`,
          data: { vaultKeyVersion: current },
        },
      },
    };
  }

  it('recovers from a stale-generation refusal by re-wrapping the LIVE key, once', async () => {
    // The whole point of sending the generation: the refusal is recoverable
    // without the user retyping anything. The session is holding a superseded
    // vault key, so the retry must fetch the live wrapper, open it with the MEK
    // it already has, re-wrap THAT under the new MEK, and name the generation the
    // profile reports.
    mockChangePasswordApi
      .mockRejectedValueOnce(staleGenerationRefusal(5))
      .mockResolvedValueOnce({ data: { success: true } });
    await renderSettings();
    const profileReadsBeforeSubmit = mockGetProfileApi.mock.calls.length;

    await openChangePassword('OldMasterPassword1!', 'NewMasterPassword1!');

    await waitFor(() => {
      expect(mockChangePasswordApi).toHaveBeenCalledTimes(2);
    });
    // Exactly ONE profile re-read, driven by the refusal — not a poll and not a
    // second attempt's worth.
    expect(mockGetProfileApi.mock.calls.length - profileReadsBeforeSubmit).toBe(1);
    expect(cs.decryptVaultKey).toHaveBeenCalledWith(
      LIVE_PROFILE_WRAPPER.encryptedVaultKey,
      LIVE_PROFILE_WRAPPER.vaultKeyIv,
      LIVE_PROFILE_WRAPPER.vaultKeyTag,
      MEK,
    );
    expect(cs.encryptVaultKey).toHaveBeenLastCalledWith(LIVE_VAULT_KEY, {
      mek: 'NewMasterPassword1!',
    });
    expect(mockChangePasswordApi).toHaveBeenLastCalledWith({
      currentAuthHash: 'hash:OldMasterPassword1!',
      newAuthHash: 'hash:NewMasterPassword1!',
      newEncryptedVaultKey: 'vk-wrapped-with:NewMasterPassword1!',
      newVaultKeyIv: 'vkIv',
      newVaultKeyTag: 'vkTag',
      // The generation the PROFILE reports, which names the wrapper just
      // unwrapped — not the number the refusal carried, which is older by
      // however long the profile read took.
      vaultKeyVersion: LIVE_PROFILE_WRAPPER.vaultKeyVersion,
    });
    // The recovered key is plaintext-capable material this handler minted, so it
    // does not outlive the handler.
    expect(cs.clearCryptoKey).toHaveBeenCalledWith(LIVE_VAULT_KEY);
    // And the change really went through: the session is torn down.
    await waitFor(() => {
      expect(useAuthStore.getState().isAuthenticated).toBe(false);
    });
  });

  it('stops after the one retry, surfacing the server sentence and logging nobody out', async () => {
    // A second refusal means the account moved again, or this session cannot
    // reach the live key at all. There is nothing further to try, and the 4xx
    // sentence is the one written for this user: it names the generation to
    // reload to, which a flat "Failed to change password" would throw away.
    mockChangePasswordApi
      .mockRejectedValueOnce(staleGenerationRefusal(5))
      .mockRejectedValueOnce(staleGenerationRefusal(7));
    await renderSettings();

    await openChangePassword('OldMasterPassword1!', 'NewMasterPassword1!');

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: expect.stringContaining('vault key version 7') as unknown as string,
          type: 'error',
        }),
      );
    });
    // NO third attempt, and no logout: the password did not change, so tearing
    // the session down would strand a user who is still on the old one.
    expect(mockChangePasswordApi).toHaveBeenCalledTimes(2);
    expect(useAuthStore.getState().isAuthenticated).toBe(true);
    expect(useAuthStore.getState().vaultKey).toBe(OLD_VAULT_KEY);
  });

  it('gives up when the profile re-read cannot supply the live key', async () => {
    // The retry has two prerequisites it does not control: a profile response it
    // can read, and the MEK still in memory. Either missing means there is no
    // live key to re-wrap, and the honest outcome is the refusal itself rather
    // than a second attempt with the same stale wrapper.
    mockChangePasswordApi.mockRejectedValueOnce(staleGenerationRefusal(5));
    await renderSettings();
    // Queued AFTER the render, because the page reads the profile on mount and a
    // one-shot queued before it would be spent there instead of on the retry.
    mockGetProfileApi.mockResolvedValueOnce({ data: { success: false } });

    await openChangePassword('OldMasterPassword1!', 'NewMasterPassword1!');

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: expect.stringContaining('vault key version 5') as unknown as string,
          type: 'error',
        }),
      );
    });
    expect(mockChangePasswordApi).toHaveBeenCalledTimes(1);
    expect(cs.decryptVaultKey).not.toHaveBeenCalled();
    expect(useAuthStore.getState().isAuthenticated).toBe(true);
  });

  it('gives up when the vault locked itself while the refusal was in flight', async () => {
    // A locked vault has no MEK, and nothing about a retry unlocks it.
    mockChangePasswordApi.mockRejectedValueOnce(staleGenerationRefusal(5));
    await renderSettings();
    mockGetProfileApi.mockImplementationOnce(() => {
      useAuthStore.setState({ mek: null });
      return Promise.resolve({ data: { success: true, data: { ...defaultProfile } } });
    });

    await openChangePassword('OldMasterPassword1!', 'NewMasterPassword1!');

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: expect.stringContaining('vault key version 5') as unknown as string,
          type: 'error',
        }),
      );
    });
    expect(mockChangePasswordApi).toHaveBeenCalledTimes(1);
    expect(cs.decryptVaultKey).not.toHaveBeenCalled();
  });

  it('zeroes the raw live vault key even when importing it fails', async () => {
    // The 32 plaintext bytes of the account's LIVE vault key exist between the
    // unwrap and the import. If the import throws, a `clearKey` placed after it
    // never runs and those bytes sit in the heap until the collector gets to
    // them — so it is in a `finally`, and this is what says so.
    mockChangePasswordApi.mockRejectedValueOnce(staleGenerationRefusal(5));
    await renderSettings();
    cs.importVaultKey.mockRejectedValueOnce(new Error('not a 32-byte key'));

    await openChangePassword('OldMasterPassword1!', 'NewMasterPassword1!');

    await waitFor(() => {
      expect(cs.clearKey).toHaveBeenCalledWith(
        `raw:${LIVE_PROFILE_WRAPPER.encryptedVaultKey}:under:mek`,
      );
    });
    // And the failure is still a failure: no second attempt, no logout.
    expect(mockChangePasswordApi).toHaveBeenCalledTimes(1);
    expect(useAuthStore.getState().isAuthenticated).toBe(true);
  });

  it('names generation 0 on the retry when the account has no stored generation', async () => {
    // An account created before the generation column existed reports none at
    // all. It has therefore never rotated, so zero is the right claim — and it
    // must be an explicit zero rather than an omitted field, which the server
    // refuses outright on any account that HAS rotated.
    mockChangePasswordApi
      .mockRejectedValueOnce(staleGenerationRefusal(5))
      .mockResolvedValueOnce({ data: { success: true } });
    const { vaultKeyVersion: _omitted, ...legacyProfile } = defaultProfile;
    mockGetProfileApi.mockResolvedValue({ data: { success: true, data: legacyProfile } });
    await renderSettings();

    await openChangePassword('OldMasterPassword1!', 'NewMasterPassword1!');

    await waitFor(() => {
      expect(mockChangePasswordApi).toHaveBeenCalledTimes(2);
    });
    expect(mockChangePasswordApi).toHaveBeenLastCalledWith(
      expect.objectContaining({ vaultKeyVersion: 0 }),
    );
  });

  it('shows the generic message for a failure that carried no 4xx sentence', async () => {
    // The other arm of the message rule. A 5xx body is redacted to its status
    // text in production, and a transport failure has no body at all, so quoting
    // either would put "Internal Server Error" or "Network Error" in front of
    // someone as though it were advice.
    mockChangePasswordApi.mockRejectedValue(new Error('Network Error'));
    await renderSettings();

    await openChangePassword('OldMasterPassword1!', 'NewMasterPassword1!');

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to change password', type: 'error' }),
      );
    });
    expect(mockChangePasswordApi).toHaveBeenCalledTimes(1);
    expect(useAuthStore.getState().isAuthenticated).toBe(true);
  });

  it('does not spend the retry on a rotation-in-progress 409', async () => {
    // The same status for a different fault. A rotation still running carries no
    // number, and no amount of re-wrapping helps until it finishes — so this one
    // is reported, not retried. Keyed on the NUMBER rather than on the status,
    // which is what makes the two distinguishable.
    mockChangePasswordApi.mockRejectedValue({
      isAxiosError: true,
      response: {
        status: 409,
        data: {
          success: false,
          message: 'Vault key rotation is in progress. Please wait and retry.',
          statusCode: 409,
          statusText: 'Conflict',
        },
      },
    });
    await renderSettings();

    await openChangePassword('OldMasterPassword1!', 'NewMasterPassword1!');

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Vault key rotation is in progress. Please wait and retry.',
          type: 'error',
        }),
      );
    });
    expect(mockChangePasswordApi).toHaveBeenCalledTimes(1);
    expect(cs.decryptVaultKey).not.toHaveBeenCalled();
    expect(useAuthStore.getState().isAuthenticated).toBe(true);
  });

  it('disables the Change Password control while a rotation is running', async () => {
    // The same-tab half of the race, closed before the user can earn a refusal:
    // a password change started during a rotation uploads a wrapper for the very
    // key the rotation is replacing.
    await renderSettings();
    fireEvent.click(screen.getByText('Change'));
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: 'OldMasterPassword1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('New master password'), {
      target: { value: 'NewMasterPassword1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), {
      target: { value: 'NewMasterPassword1!' },
    });

    // The negative first: with every field filled and no rotation running the
    // control is live, so the assertion below is about the rotation and not about
    // some unrelated guard.
    expect(screen.getByText('Change Password')).not.toBeDisabled();

    // A REAL rotation, held mid-flight by an item page that never resolves,
    // rather than a poked state flag: `rotatingVaultKey` is local component state
    // and the only honest way to observe it true is to have one running.
    let releaseRotation: () => void = () => {};
    mockListItems.mockReturnValueOnce(
      new Promise((resolve) => {
        releaseRotation = () =>
          resolve({ data: { success: true, data: [], pagination: { totalPages: 1 } } });
      }),
    );
    fireEvent.click(screen.getByText('Rotate Key'));
    await waitFor(() => screen.getByPlaceholderText('Master password'));
    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'MasterPassword1!' },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Confirm Rotation'));
    });

    await waitFor(() => {
      expect(screen.getByText('Change Password')).toBeDisabled();
    });
    // And the other direction, so neither control can start while the other runs.
    expect(screen.getByText(/^Rotating\.\.\./)).toBeDisabled();

    // Released so the rotation does not outlive the test and leave an unhandled
    // promise for whichever file runs next in this worker.
    await act(async () => {
      releaseRotation();
    });
  });

  it('logs the session out after a successful master-password change', async () => {
    // The server revokes every refresh token when the password changes, and the
    // MEK in memory no longer opens the vault key that was just re-wrapped — so
    // a session that survived the change would be a stale-key session that fails
    // on its next read. This is asserted here rather than as a source-text check
    // for `navigate('/login'` in `client-security.test.ts`, which could not
    // survive the mutation gate's instrumentation of that route literal.
    mockChangePasswordApi.mockResolvedValue({ data: { success: true } });
    await renderSettings();

    expect(useAuthStore.getState().isAuthenticated).toBe(true);
    await openChangePassword('OldMasterPassword1!', 'NewMasterPassword1!');

    await waitFor(() => {
      expect(useAuthStore.getState().isAuthenticated).toBe(false);
    });
    // The keys go with it: an authenticated flag flipped without clearing the
    // vault key would leave the plaintext-capable material resident.
    expect(useAuthStore.getState().vaultKey).toBeNull();
    expect(mockChangePasswordApi).toHaveBeenCalledTimes(1);
  });

  it('refuses to change the master password while the vault is locked', async () => {
    mockChangePasswordApi.mockResolvedValue({ data: { success: true } });
    await renderSettings();

    act(() => {
      useAuthStore.setState({ vaultKey: null });
    });

    await openChangePassword('OldMasterPassword1!', 'NewMasterPassword1!');

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Vault is locked', type: 'error' }),
      );
    });
    expect(mockChangePasswordApi).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // 2FA
  // -------------------------------------------------------------------------

  async function startSetup2fa() {
    mockSetup2faApi.mockResolvedValue({
      data: {
        success: true,
        data: { secret: 'JBSWY3DPEHPK3PXP', qrCodeDataUrl: 'otpauth://totp/test' },
      },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Enable'));
    });
    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'MasterPassword1!' },
    });
  }

  it('starts 2FA setup when Enter is pressed in the password prompt', async () => {
    await renderSettings();
    await startSetup2fa();

    await act(async () => {
      fireEvent.keyDown(screen.getByPlaceholderText('Master password'), { key: 'Enter' });
    });

    await waitFor(() => {
      expect(screen.getByPlaceholderText('6-digit code')).toBeInTheDocument();
    });
    // The server is re-authenticated with the derived hash, never the raw password.
    expect(mockSetup2faApi).toHaveBeenCalledWith({ password: 'hash:MasterPassword1!' });
  });

  it('dismisses the 2FA prompt without calling the API, and re-opens it with an empty password', async () => {
    await renderSettings();
    await startSetup2fa();

    fireEvent.click(screen.getByText('Cancel'));

    expect(screen.queryByPlaceholderText('Master password')).not.toBeInTheDocument();
    expect(mockSetup2faApi).not.toHaveBeenCalled();

    await act(async () => {
      fireEvent.click(screen.getByText('Enable'));
    });
    expect((screen.getByPlaceholderText('Master password') as HTMLInputElement).value).toBe('');
  });

  it('copies the manual-entry 2FA secret to the clipboard', async () => {
    await renderSettings();
    await startSetup2fa();
    await act(async () => {
      fireEvent.click(screen.getByText('Continue'));
    });
    await waitFor(() => screen.getByText('JBSWY3DPEHPK3PXP'));

    await act(async () => {
      fireEvent.click(screen.getByText('JBSWY3DPEHPK3PXP'));
    });

    expect(mockWriteText).toHaveBeenCalledWith('JBSWY3DPEHPK3PXP');
    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Secret copied', type: 'success' }),
      );
    });
  });

  it('keeps the setup form open and reports "Invalid code" when 2FA verification is rejected', async () => {
    mockVerify2faApi.mockRejectedValue(new Error('bad code'));
    await renderSettings();
    await startSetup2fa();
    await act(async () => {
      fireEvent.click(screen.getByText('Continue'));
    });
    await waitFor(() => screen.getByPlaceholderText('6-digit code'));

    fireEvent.change(screen.getByPlaceholderText('6-digit code'), { target: { value: '000000' } });
    await act(async () => {
      fireEvent.click(screen.getByText('Verify'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Invalid code', type: 'error' }),
      );
    });
    // No backup codes are revealed and the user can retry.
    expect(screen.queryByText('Save Your Backup Codes')).not.toBeInTheDocument();
    expect(screen.getByPlaceholderText('6-digit code')).toBeInTheDocument();
  });

  it('hides the 2FA setup form when its Cancel is clicked', async () => {
    await renderSettings();
    await startSetup2fa();
    await act(async () => {
      fireEvent.click(screen.getByText('Continue'));
    });
    await waitFor(() => screen.getByPlaceholderText('6-digit code'));

    const cancels = screen.getAllByText('Cancel');
    fireEvent.click(cancels[cancels.length - 1]!);

    expect(screen.queryByPlaceholderText('6-digit code')).not.toBeInTheDocument();
  });

  it('copies all backup codes as newline-separated text and hides them once acknowledged', async () => {
    mockVerify2faApi.mockResolvedValue({
      data: { success: true, data: { backupCodes: ['aaaa1111', 'bbbb2222'] } },
    });
    await renderSettings();
    await startSetup2fa();
    await act(async () => {
      fireEvent.click(screen.getByText('Continue'));
    });
    await waitFor(() => screen.getByPlaceholderText('6-digit code'));
    fireEvent.change(screen.getByPlaceholderText('6-digit code'), { target: { value: '123456' } });
    await act(async () => {
      fireEvent.click(screen.getByText('Verify'));
    });
    await waitFor(() => screen.getByText('Save Your Backup Codes'));

    await act(async () => {
      fireEvent.click(screen.getByText('Copy All'));
    });
    expect(mockWriteText).toHaveBeenCalledWith('aaaa1111\nbbbb2222');

    fireEvent.click(screen.getByText("I've Saved These Codes"));
    await waitFor(() => {
      expect(screen.queryByText('Save Your Backup Codes')).not.toBeInTheDocument();
    });
  });

  it('reports "Invalid code or password" and leaves 2FA enabled when disabling is rejected', async () => {
    setProfile({ twoFactorEnabled: true });
    mockDisable2faApi.mockRejectedValue(new Error('wrong code'));
    await renderSettings();

    fireEvent.click(screen.getByText('Disable'));
    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'MasterPassword1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('6-digit code'), { target: { value: '000000' } });
    await act(async () => {
      fireEvent.click(screen.getByText('Disable 2FA'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Invalid code or password', type: 'error' }),
      );
    });
    expect(screen.getByText('Enabled')).toBeInTheDocument();
    // The form stays open so the user can correct the code.
    expect(screen.getByText('Disable 2FA')).toBeInTheDocument();
  });

  // -------------------------------------------------------------------------
  // Vault key rotation
  // -------------------------------------------------------------------------

  function vaultItem(id: string, withHistory = false) {
    return {
      _id: id,
      encryptedName: `${id}-name`,
      nameIv: `${id}-nameIv`,
      nameTag: `${id}-nameTag`,
      encryptedData: `${id}-data`,
      dataIv: `${id}-dataIv`,
      dataTag: `${id}-dataTag`,
      ...(withHistory
        ? {
            passwordHistory: [
              {
                encryptedPassword: `${id}-pw`,
                iv: `${id}-pwIv`,
                tag: `${id}-pwTag`,
                changedAt: '2026-01-01T00:00:00.000Z',
              },
            ],
          }
        : {}),
    };
  }

  async function confirmRotation(password = 'MasterPassword1!') {
    fireEvent.click(screen.getByText('Rotate Key'));
    await waitFor(() => screen.getByPlaceholderText('Master password'));
    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: password },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Confirm Rotation'));
    });
  }

  it('re-encrypts every paginated item, trash item, password-history entry and folder under the NEW key', async () => {
    mockListItems
      .mockResolvedValueOnce({
        data: { success: true, data: [vaultItem('i1', true)], pagination: { totalPages: 2 } },
      })
      .mockResolvedValueOnce({
        data: { success: true, data: [vaultItem('i2')], pagination: { totalPages: 2 } },
      });
    mockListTrash.mockResolvedValue({
      data: { success: true, data: [vaultItem('t1')], pagination: { totalPages: 1 } },
    });
    mockListFolders.mockResolvedValue({
      data: {
        success: true,
        data: [{ _id: 'f1', encryptedName: 'f1-name', nameIv: 'f1-iv', nameTag: 'f1-tag' }],
      },
    });

    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockBulkReEncrypt).toHaveBeenCalledTimes(1);
    });
    const payload = mockBulkReEncrypt.mock.calls[0]![0] as {
      authHash: string;
      idempotencyKey: string;
      newEncryptedVaultKey: string;
      newVaultKeyIv: string;
      newVaultKeyTag: string;
      items: Record<string, unknown>[];
      folders: Record<string, unknown>[];
    };

    expect(payload.authHash).toBe('hash:MasterPassword1!');
    expect(payload.idempotencyKey).toEqual(expect.any(String));
    expect(payload.newEncryptedVaultKey).toBe('newEnc');
    expect(payload.newVaultKeyIv).toBe('newIv');
    expect(payload.newVaultKeyTag).toBe('newTag');

    // Page 2 and the trash are both enumerated.
    expect(payload.items.map((i) => i.id)).toEqual(['i1', 'i2', 't1']);
    expect(payload.items[0]).toEqual({
      id: 'i1',
      encryptedName: 'enc:plain:i1-name',
      nameIv: 'iv:new-vault-key',
      nameTag: 'tag:new-vault-key',
      encryptedData: 'enc:plain:i1-data',
      dataIv: 'iv:new-vault-key',
      dataTag: 'tag:new-vault-key',
      searchHash: 'sh:plain:i1-name',
      passwordHistory: [
        {
          encryptedPassword: 'enc:plain:i1-pw',
          iv: 'iv:new-vault-key',
          tag: 'tag:new-vault-key',
          changedAt: '2026-01-01T00:00:00.000Z',
        },
      ],
    });
    expect(payload.folders).toEqual([
      {
        id: 'f1',
        encryptedName: 'enc:plain:f1-name',
        nameIv: 'iv:new-vault-key',
        nameTag: 'tag:new-vault-key',
      },
    ]);

    // Ciphertext is read with the OLD key and written with the NEW one.
    expect(cs.decryptData).toHaveBeenCalledWith(
      'i1-name',
      'i1-nameIv',
      'i1-nameTag',
      OLD_VAULT_KEY,
    );
    expect(cs.encryptData).toHaveBeenCalledWith('plain:i1-name', NEW_VAULT_KEY);

    // The client now holds the new key.
    await waitFor(() => {
      expect(useAuthStore.getState().vaultKey).toBe(NEW_VAULT_KEY);
    });
    expect(useAuthStore.getState().encryptedVaultKeyData).toEqual({
      encrypted: 'newEnc',
      iv: 'newIv',
      tag: 'newTag',
    });
    // …and says WHICH key it now holds. The number travels with the key or it is
    // a lie: an upload from this session sends it so the server can tell a
    // superseded key from the current one, and a session left claiming the
    // generation it has just replaced would have every completion refused.
    expect(useAuthStore.getState().vaultKeyVersion).toBe(5);
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Vault key rotated successfully', type: 'success' }),
    );
  });

  it('skips and reports an item that will not decrypt, and rotates every other row', async () => {
    // One poisoned row must not wedge rotation for ever. The row is ALREADY
    // unreadable under the key this vault holds, so carrying its ciphertext across
    // verbatim loses nothing that was not lost before the rotation started — while
    // aborting leaves every other row sealed under a key the user is trying to
    // replace, permanently, on every future attempt.
    mockListItems.mockResolvedValue({
      data: {
        success: true,
        data: [vaultItem('good'), vaultItem('bad')],
        pagination: { totalPages: 1 },
      },
    });
    cs.decryptData.mockImplementation((enc: string) =>
      enc.startsWith('bad')
        ? Promise.reject(new Error('GCM tag mismatch'))
        : Promise.resolve(`plain:${enc}`),
    );

    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockBulkReEncrypt).toHaveBeenCalledTimes(1);
    });
    const payload = mockBulkReEncrypt.mock.calls[0]![0] as {
      items: Record<string, unknown>[];
    };

    // BOTH rows are named. A skipped row is passed through, never OMITTED: the
    // server's completeness check refuses a payload that does not cover every row
    // the account holds, so omitting it would refuse the whole rotation instead.
    expect(payload.items.map((i) => i.id)).toEqual(['good', 'bad']);
    expect(payload.items[0]).toMatchObject({
      encryptedName: 'enc:plain:good-name',
      nameIv: 'iv:new-vault-key',
    });
    // The poisoned row's ciphertext crosses BYTE FOR BYTE — not re-encrypted, not
    // replaced by a placeholder, not dropped.
    expect(payload.items[1]).toEqual({
      id: 'bad',
      encryptedName: 'bad-name',
      nameIv: 'bad-nameIv',
      nameTag: 'bad-nameTag',
      encryptedData: 'bad-data',
      dataIv: 'bad-dataIv',
      dataTag: 'bad-dataTag',
    });

    // And the user is told, by count and by kind, rather than left to discover it.
    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title:
            'Vault key rotated successfully. 1 entry could not be decrypted and was left unchanged.',
          description: expect.stringContaining('1 item'),
          type: 'warning',
        }),
      );
    });
    // The plain success toast must NOT also have been shown: two toasts for one
    // outcome, one of them silent about the loss, is how a skip goes unnoticed.
    expect(mockToast).not.toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Vault key rotated successfully', type: 'success' }),
    );
    expect(useAuthStore.getState().vaultKey).toBe(NEW_VAULT_KEY);
  });

  it('skips and reports a folder that will not decrypt, and rotates every other row', async () => {
    mockListItems.mockResolvedValue({
      data: { success: true, data: [vaultItem('good')], pagination: { totalPages: 1 } },
    });
    mockListFolders.mockResolvedValue({
      data: {
        success: true,
        data: [{ _id: 'f1', encryptedName: 'f1-name', nameIv: 'f1-iv', nameTag: 'f1-tag' }],
      },
    });
    cs.decryptData.mockImplementation((enc: string) =>
      enc.startsWith('f1')
        ? Promise.reject(new Error('GCM tag mismatch'))
        : Promise.resolve(`plain:${enc}`),
    );

    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockBulkReEncrypt).toHaveBeenCalledTimes(1);
    });
    const payload = mockBulkReEncrypt.mock.calls[0]![0] as {
      folders: Record<string, unknown>[];
    };
    expect(payload.folders).toEqual([
      { id: 'f1', encryptedName: 'f1-name', nameIv: 'f1-iv', nameTag: 'f1-tag' },
    ]);
    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          description: expect.stringContaining('1 folder'),
          type: 'warning',
        }),
      );
    });
  });

  it('carries a skipped row’s search hash and password history across untouched, and counts several skips by kind', async () => {
    // Two rows, in two different legs, so the report has to name each kind rather
    // than pluralise one count — and the item carries the two OPTIONAL fields a
    // pass-through must not drop: its search hash (an HMAC of a name nothing can
    // read, so there is no plaintext to recompute it from) and its password
    // history (ciphertext under the same superseded key).
    const poisoned = {
      ...vaultItem('bad', true),
      searchHash: 'a'.repeat(64),
    };
    mockListItems.mockResolvedValue({
      data: { success: true, data: [vaultItem('good'), poisoned], pagination: { totalPages: 1 } },
    });
    mockListFolders.mockResolvedValue({
      data: {
        success: true,
        data: [{ _id: 'f1', encryptedName: 'f1-name', nameIv: 'f1-iv', nameTag: 'f1-tag' }],
      },
    });
    cs.decryptData.mockImplementation((enc: string) =>
      enc.startsWith('bad') || enc.startsWith('f1')
        ? Promise.reject(new Error('GCM tag mismatch'))
        : Promise.resolve(`plain:${enc}`),
    );

    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockBulkReEncrypt).toHaveBeenCalledTimes(1);
    });
    const payload = mockBulkReEncrypt.mock.calls[0]![0] as {
      items: Record<string, unknown>[];
    };
    expect(payload.items[1]).toEqual({
      id: 'bad',
      encryptedName: 'bad-name',
      nameIv: 'bad-nameIv',
      nameTag: 'bad-nameTag',
      encryptedData: 'bad-data',
      dataIv: 'bad-dataIv',
      dataTag: 'bad-dataTag',
      searchHash: 'a'.repeat(64),
      passwordHistory: poisoned.passwordHistory,
    });
    // Neither optional field was re-encrypted on the way through.
    expect(cs.generateSearchHash).not.toHaveBeenCalledWith(expect.stringContaining('bad'), MEK);
    expect(cs.encryptData).not.toHaveBeenCalledWith('plain:bad-pw', NEW_VAULT_KEY);

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title:
            'Vault key rotated successfully. 2 entries could not be decrypted and were left unchanged.',
          description: expect.stringContaining('1 item, 1 folder'),
          type: 'warning',
        }),
      );
    });
  });

  it('aborts, sending nothing, when NOT ONE row could be decrypted', async () => {
    // The safety valve that keeps skip-and-report from becoming a data-loss path.
    // A single poisoned row is a poisoned row; EVERY row failing means the key this
    // session holds is not the account's — a session left behind by a rotation
    // elsewhere — and committing a payload of pass-throughs there would swap the
    // vault key for one that opens nothing at all.
    mockListItems.mockResolvedValue({
      data: { success: true, data: [vaultItem('i1')], pagination: { totalPages: 1 } },
    });
    mockListFolders.mockResolvedValue({
      data: {
        success: true,
        data: [{ _id: 'f1', encryptedName: 'f1-name', nameIv: 'iv', nameTag: 'tag' }],
      },
    });
    cs.decryptData.mockRejectedValue(new Error('GCM tag mismatch'));

    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title:
            'Rotation aborted: none of the 2 entries in this vault could be decrypted, so the key this session holds is not this account’s. Reload and try again.',
          type: 'error',
        }),
      );
    });
    expect(mockBulkReEncrypt).not.toHaveBeenCalled();
    // The key that will now never be used is destroyed, and the session keeps the
    // one it started with.
    expect(cs.clearCryptoKey).toHaveBeenCalledWith(NEW_VAULT_KEY);
    expect(useAuthStore.getState().vaultKey).toBe(OLD_VAULT_KEY);
  });

  // -------------------------------------------------------------------------
  // Vault key rotation — the document leg
  // -------------------------------------------------------------------------

  it('rewraps every active AND trashed document key under the new vault key, in one request', async () => {
    mockReadDocumentsConfigFresh.mockResolvedValue({ enabled: true });
    mockListDocuments
      .mockResolvedValueOnce(documentPage([documentRow(docId(1))], 2))
      .mockResolvedValueOnce(documentPage([documentRow(docId(2))], 2));
    mockListDocumentTrash.mockResolvedValue(documentPage([documentRow(docId(3))]));

    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockBulkReEncrypt).toHaveBeenCalledTimes(1);
    });
    const payload = mockBulkReEncrypt.mock.calls[0]![0] as {
      documents: Record<string, unknown>[];
    };

    // Page 2 of the active list AND the trash are both enumerated. A trashed
    // document is sealed under the same vault key and can still be restored, so
    // leaving it out would restore a permanently unreadable file.
    expect(payload.documents.map((d) => d.id)).toEqual([docId(1), docId(2), docId(3)]);

    // Every entry carries EXACTLY the four rotation fields. The framing, the sizes
    // and the sealed metadata blob on the row are not a rotation's to send.
    for (const entry of payload.documents) {
      expect(Object.keys(entry).sort()).toEqual(['dekIv', 'dekTag', 'encryptedDek', 'id']);
    }
    expect(payload.documents[0]).toEqual({
      id: docId(1),
      // Wrapped under the NEW key and bound to THIS document's id.
      encryptedDek: `dek@new-vault-key:${docId(1)}`,
      dekIv: 'dekIv:new-vault-key',
      dekTag: 'dekTag:new-vault-key',
    });

    // Read with the old key, written with the new one — and the wrapped key that
    // went in is the one that came off the row.
    expect(mockDeriveWrapKey).toHaveBeenCalledWith(OLD_VAULT_KEY, docId(1));
    expect(mockDeriveWrapKey).toHaveBeenCalledWith(NEW_VAULT_KEY, docId(1));
    expect(mockUnwrapDek).toHaveBeenCalledWith(
      expect.objectContaining({
        encryptedDek: `${docId(1)}-dek`,
        dekIv: `${docId(1)}-dekIv`,
        dekTag: `${docId(1)}-dekTag`,
      }),
      { wrapFor: docId(1), under: 'old-vault-key' },
    );

    // Both lists are walked with the shared page size, so a >200-document account
    // is paged rather than truncated at the server default.
    expect(mockListDocuments).toHaveBeenCalledWith({ page: 1, limit: DOCUMENT_PAGE_SIZE });
    expect(mockListDocuments).toHaveBeenCalledWith({ page: 2, limit: DOCUMENT_PAGE_SIZE });
    expect(mockListDocumentTrash).toHaveBeenCalledWith({ page: 1, limit: DOCUMENT_PAGE_SIZE });

    // No file was read: a rotation moves 32 bytes per document and never touches a
    // stored object, which is the whole reason the store wraps its keys.
    expect(mockDeriveStreamKey).not.toHaveBeenCalled();

    // No metadata was decrypted. The blob is sealed under a key derived from the
    // document's OWN key, which a rotation only rewraps, so opening it would be
    // reading user plaintext for nothing.
    expect(mockDeriveMetaKey).not.toHaveBeenCalled();
    expect(mockDecryptMeta).not.toHaveBeenCalled();

    // Every DEK the rotation held is zeroed by the time it finishes.
    expect(issuedDeks.size).toBe(3);
    for (const dek of issuedDeks.values()) {
      expect(Array.from(dek)).toEqual(new Array(32).fill(0));
    }

    await waitFor(() => {
      expect(useAuthStore.getState().vaultKey).toBe(NEW_VAULT_KEY);
    });
  });

  it('walks no more than the document page ceiling when the server inflates totalPages', async () => {
    mockReadDocumentsConfigFresh.mockResolvedValue({ enabled: true });
    // A server that keeps claiming there is another page. Without the clamp this
    // walk never ends and the rotation never reaches the request at all.
    mockListDocuments.mockResolvedValue(documentPage([documentRow(docId(1))], 99));

    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockBulkReEncrypt).toHaveBeenCalledTimes(1);
    });
    expect(mockListDocuments).toHaveBeenCalledTimes(MAX_DOCUMENT_PAGES);
    // Read to the ceiling and no further: an account cannot hold more documents
    // than the ceiling is derived from, so a `totalPages` past it is an inflated
    // number rather than more rows.
    expect(mockListDocuments).toHaveBeenCalledWith({
      page: MAX_DOCUMENT_PAGES,
      limit: DOCUMENT_PAGE_SIZE,
    });
    expect(mockListDocuments).not.toHaveBeenCalledWith({
      page: MAX_DOCUMENT_PAGES + 1,
      limit: DOCUMENT_PAGE_SIZE,
    });
  });

  it('reads every page an account that is really at its ceiling would report', async () => {
    mockReadDocumentsConfigFresh.mockResolvedValue({ enabled: true });
    // The ceiling this walk clamps to has to be derived from how many rows an
    // account can ACTUALLY hold, which is not the advertised per-user limit: the
    // server checks the document count only when a transfer is opened, so three
    // concurrent transfers can all pass the same reading and all commit. An
    // account sitting at that real maximum reports one more page than a ceiling
    // derived from the advertised limit allows, and the walk would stop a page
    // short — dropping rows silently, in the one enumeration whose entire purpose
    // is that it must never drop one, and leaving the account unable to rotate its
    // vault key for ever.
    const realPages = Math.ceil(MAX_DOCUMENTS_PER_ROTATION / DOCUMENT_PAGE_SIZE);
    mockListDocuments.mockResolvedValue(documentPage([documentRow(docId(1))], realPages));

    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockBulkReEncrypt).toHaveBeenCalledTimes(1);
    });
    expect(mockListDocuments).toHaveBeenCalledTimes(realPages);
    expect(mockListDocuments).toHaveBeenCalledWith({
      page: realPages,
      limit: DOCUMENT_PAGE_SIZE,
    });
  });

  it('advances the progress bar across the document leg rather than stalling on the folders', async () => {
    mockReadDocumentsConfigFresh.mockResolvedValue({ enabled: true });
    mockListDocuments.mockResolvedValue(
      documentPage([documentRow(docId(1)), documentRow(docId(2))]),
    );

    // The rotation is PARKED inside the document leg — after the first document is
    // rewrapped, before the second — so React has actually rendered by the time the
    // bar is read. Sampling from inside the loop without parking reads the value
    // from before the handler started, because nothing has flushed yet.
    let release!: () => void;
    const parked = new Promise<void>((resolve) => {
      release = resolve;
    });
    let releaseCommit!: () => void;
    const commitParked = new Promise<void>((resolve) => {
      releaseCommit = resolve;
    });
    mockBulkReEncrypt.mockImplementation(async () => {
      await commitParked;
      return { data: { success: true } };
    });
    const wrap = mockWrapDek.getMockImplementation()!;
    let wrapped = 0;
    mockWrapDek.mockImplementation(
      async (dek: Uint8Array, wrapKey: { wrapFor: string; under: string }) => {
        wrapped += 1;
        if (wrapped === 2) await parked;
        return wrap(dek, wrapKey);
      },
    );

    await renderSettings();
    await confirmRotation();

    // What the button says while two documents are being re-keyed: the folder leg
    // hands over at 60 and each document moves the bar by its share of the 30 the
    // leg owns, so one of two documents reads 75. A leg that did no accounting
    // would still read 60 here, and one that had been folded into the commit step
    // would already read 95.
    const midway = /Rotating\.\.\. (\d+)%/.exec(document.body.textContent ?? '');
    expect(midway?.[1]).toBe('75');

    // Released, the leg finishes and the handler parks again — this time inside the
    // one request — so the commit marker is readable the same way.
    await act(async () => {
      release();
    });
    const atCommit = /Rotating\.\.\. (\d+)%/.exec(document.body.textContent ?? '');
    // 95, not the 90 the last document left behind and not the 60 the folder leg
    // handed over at: the bar has to move once more when the enumeration is done
    // and the single atomic request goes out, or a large account looks stalled for
    // the whole round trip.
    expect(atCommit?.[1]).toBe('95');

    await act(async () => {
      releaseCommit();
    });
    await waitFor(() => {
      expect(mockBulkReEncrypt).toHaveBeenCalledTimes(1);
    });
    expect(mockWrapDek).toHaveBeenCalledTimes(2);
  });

  it('skips and reports a document key that will not unwrap, and rotates every other row', async () => {
    mockReadDocumentsConfigFresh.mockResolvedValue({ enabled: true });
    mockListDocuments.mockResolvedValue(
      documentPage([documentRow(docId(1)), documentRow(docId(2))]),
    );
    const unwrap = mockUnwrapDek.getMockImplementation()!;
    mockUnwrapDek.mockImplementation(
      (wrapped: { encryptedDek: string }, wrapKey: { wrapFor: string; under: string }) =>
        wrapKey.wrapFor === docId(2)
          ? Promise.reject(new Error('GCM tag mismatch'))
          : unwrap(wrapped, wrapKey),
    );

    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockBulkReEncrypt).toHaveBeenCalledTimes(1);
    });
    const payload = mockBulkReEncrypt.mock.calls[0]![0] as {
      documents: Record<string, unknown>[];
    };

    // The one that DID unwrap is rewrapped under the new key; the one that did not
    // carries its existing wrapper across verbatim, so the payload still names
    // every document the account holds and the completeness check passes.
    expect(payload.documents).toEqual([
      {
        id: docId(1),
        encryptedDek: `dek@new-vault-key:${docId(1)}`,
        dekIv: 'dekIv:new-vault-key',
        dekTag: 'dekTag:new-vault-key',
      },
      {
        id: docId(2),
        encryptedDek: `${docId(2)}-dek`,
        dekIv: `${docId(2)}-dekIv`,
        dekTag: `${docId(2)}-dekTag`,
      },
    ]);

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          description: expect.stringContaining('1 document'),
          type: 'warning',
        }),
      );
    });

    // The DEK the first document DID yield is still zeroed on the way out.
    expect(issuedDeks.size).toBe(1);
    expect(Array.from(issuedDeks.get(docId(1))!)).toEqual(new Array(32).fill(0));
  });

  it('aborts before sending anything when a document list cannot be read', async () => {
    mockReadDocumentsConfigFresh.mockResolvedValue({ enabled: true });
    mockListDocumentTrash.mockRejectedValue(new Error('network'));

    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to rotate vault key', type: 'error' }),
      );
    });
    // A half-enumerated account must never be committed: the documents this
    // request did not name would be left under the superseded key.
    expect(mockBulkReEncrypt).not.toHaveBeenCalled();
    expect(useAuthStore.getState().vaultKey).toBe(OLD_VAULT_KEY);
  });

  it('sends an empty document leg, and asks the document store nothing, on a server without one', async () => {
    // The default from `installDocumentCryptoStubs`, restated here because it is
    // the subject: an older server, or one with no object storage configured.
    mockReadDocumentsConfigFresh.mockResolvedValue({ enabled: false });

    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockBulkReEncrypt).toHaveBeenCalledTimes(1);
    });
    const payload = mockBulkReEncrypt.mock.calls[0]![0] as { documents: unknown[] };
    // The leg is still named. The server refuses a payload that does not cover
    // every row it holds, and it holds no documents, so an empty leg agrees.
    expect(payload.documents).toEqual([]);

    // Every document route sits behind `requireStorage`, whose 503 is redacted to
    // its status text in production — so the client must learn the feature is
    // absent from `GET /config` rather than by provoking an error it cannot read.
    expect(mockListDocuments).not.toHaveBeenCalled();
    expect(mockListDocumentTrash).not.toHaveBeenCalled();
    expect(mockDeriveWrapKey).not.toHaveBeenCalled();
  });

  it('aborts, rather than sending an empty leg, when the server will not say whether it stores documents', async () => {
    // `null` is the third answer, and the one an empty leg must never be built
    // from. "This server holds no documents" and "I could not find out" look
    // identical the moment they are collapsed, and the consequence of collapsing
    // them is not a cosmetic one: the payload would name no documents, the server
    // would refuse it with a completeness 409, and its diagnosis would blame a
    // pending purge or absent storage — two causes that did not happen and that
    // the account cannot act on. Every rotation for the rest of the tab's life
    // used to behave this way after ONE transient `/config` failure, because the
    // memoised reader cached the failure and nothing invalidated it.
    mockReadDocumentsConfigFresh.mockResolvedValue(null);

    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title:
            'Rotation aborted: could not confirm whether this server stores documents. Check your connection and try again.',
          type: 'error',
        }),
      );
    });

    // Nothing was sent, nothing was enumerated, and the account still holds the key
    // it started with — so the reader can simply try again once the server answers.
    expect(mockBulkReEncrypt).not.toHaveBeenCalled();
    expect(mockListDocuments).not.toHaveBeenCalled();
    expect(mockListDocumentTrash).not.toHaveBeenCalled();
    expect(mockDeriveWrapKey).not.toHaveBeenCalled();
    expect(useAuthStore.getState().vaultKey).toBe(OLD_VAULT_KEY);
    // The key that will now never be used is zeroed on the way out, exactly as it
    // is on the other two abort paths.
    expect(cs.clearCryptoKey).toHaveBeenCalledWith(NEW_VAULT_KEY);
  });

  it('refuses to rotate while the vault is locked', async () => {
    await renderSettings();

    act(() => {
      useAuthStore.setState({ vaultKey: null, mek: null });
    });
    await confirmRotation();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Vault is locked', type: 'error' }),
      );
    });
    expect(cs.rotateVaultKey).not.toHaveBeenCalled();
    expect(mockBulkReEncrypt).not.toHaveBeenCalled();
  });

  it('keeps the old vault key when the server rejects the bulk re-encrypt', async () => {
    mockBulkReEncrypt.mockRejectedValue(new Error('500'));
    await renderSettings();

    await confirmRotation();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to rotate vault key', type: 'error' }),
      );
    });
    expect(useAuthStore.getState().vaultKey).toBe(OLD_VAULT_KEY);
    // The dialog stays open so the user can retry.
    expect(screen.getByText('Confirm Rotation')).toBeInTheDocument();
  });

  it("shows the server's own 4xx refusal, so a completeness 409 is not collapsed into a generic failure", async () => {
    // The completeness check names which leg fell short and, for documents, that a
    // permanent deletion still awaiting the hourly cleanup keeps its row counted.
    // A user who cannot read that retries for ever; the answer is to wait.
    //
    // Shortened here rather than quoted in full: the real one runs to 481
    // characters and `getApiErrorMessage` caps a title at 200, so a verbatim copy
    // would pin the TRUNCATION rather than the behaviour. What has to hold is that
    // the server's own words reach the user; the leg and the counts, which are the
    // part that identifies the failure, sit inside the first 200 either way.
    const message =
      'Vault key rotation failed: the request does not cover every row this account holds ' +
      '(documents: 2 supplied, 3 stored).';
    mockBulkReEncrypt.mockRejectedValue(
      Object.assign(new Error('Request failed with status code 409'), {
        isAxiosError: true,
        response: { status: 409, data: { success: false, message, statusCode: 409 } },
      }),
    );

    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: message, type: 'error' }),
      );
    });
    // The generic title must NOT also have been shown: two toasts for one failure,
    // one of them wrong, is worse than the message it was meant to replace.
    expect(mockToast).not.toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Failed to rotate vault key' }),
    );
    expect(useAuthStore.getState().vaultKey).toBe(OLD_VAULT_KEY);
  });

  it('keeps the generic failure for a 5xx, whose body is redacted to its status text', async () => {
    // `createErrorMiddleware({ exposeServerErrors: false })` redacts a 5xx to its
    // status text in production, so echoing one would replace a sentence a user can
    // act on with "Internal Server Error".
    mockBulkReEncrypt.mockRejectedValue(
      Object.assign(new Error('Request failed with status code 500'), {
        isAxiosError: true,
        response: { status: 500, data: { success: false, message: 'Internal Server Error' } },
      }),
    );

    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to rotate vault key', type: 'error' }),
      );
    });
    expect(mockToast).not.toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Internal Server Error' }),
    );
  });

  // -------------------------------------------------------------------------
  // Vault key rotation — finishing one a crash interrupted
  //
  // A crashed sequential rotation leaves rows on BOTH sides of the swap: some
  // sealed under the key the account still uses, some under the key the rotation
  // was moving to. That second key exists in exactly one place — the pending
  // wrapper on the user document, under the account's MEK — so finishing the
  // rotation means unwrapping THAT key and driving `bulkReEncrypt` with it.
  // Minting a fresh one instead would leave every already-re-sealed row under a
  // key nothing stores any more, and the commit `$unset`s the wrapper, so there
  // would be no second chance.
  // -------------------------------------------------------------------------

  /** Opens the rotation dialog through the interrupted-rotation control. */
  async function confirmFinishRotation(password = 'MasterPassword1!') {
    fireEvent.click(screen.getByText('Finish Rotation'));
    await waitFor(() => screen.getByPlaceholderText('Master password'));
    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: password },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Confirm Rotation'));
    });
  }

  /**
   * A vault half-way through a crashed rotation: `old-row` is still sealed under
   * the key the account uses, `pending-row` was already re-sealed under the key
   * the crash interrupted. Only a driver that tries BOTH keys can carry both
   * across.
   */
  function installHalfRotatedVault() {
    setProfile(PENDING_WRAPPER);
    mockListItems.mockResolvedValue({
      data: {
        success: true,
        data: [vaultItem('old-row'), vaultItem('pending-row')],
        pagination: { totalPages: 1 },
      },
    });
    cs.decryptData.mockImplementation(
      (enc: string, _iv: string, _tag: string, key: { key: string }) => {
        const sealedUnder = enc.startsWith('pending-row') ? 'pending-vault-key' : 'old-vault-key';
        return key.key === sealedUnder
          ? Promise.resolve(`plain:${enc}`)
          : Promise.reject(new Error('GCM tag mismatch'));
      },
    );
  }

  it('finishes an interrupted rotation with the PENDING key, never a freshly minted one', async () => {
    installHalfRotatedVault();

    await renderSettings();
    await confirmFinishRotation();

    await waitFor(() => {
      expect(mockBulkReEncrypt).toHaveBeenCalledTimes(1);
    });
    const payload = mockBulkReEncrypt.mock.calls[0]![0] as {
      newEncryptedVaultKey: string;
      newVaultKeyIv: string;
      newVaultKeyTag: string;
      items: Record<string, unknown>[];
    };

    // THE negative that defines this path: no third key was ever generated.
    expect(cs.rotateVaultKey).not.toHaveBeenCalled();

    // The committed wrapper is the pending one, byte for byte, so the key the
    // server stores is the key the crashed rotation had already sealed rows under.
    expect(payload.newEncryptedVaultKey).toBe(PENDING_WRAPPER.pendingEncryptedVaultKey);
    expect(payload.newVaultKeyIv).toBe(PENDING_WRAPPER.pendingVaultKeyIv);
    expect(payload.newVaultKeyTag).toBe(PENDING_WRAPPER.pendingVaultKeyTag);
    // ...and it was opened with the account's MEK, not with anything this session
    // happened to be holding.
    expect(cs.decryptVaultKey).toHaveBeenCalledWith(
      PENDING_WRAPPER.pendingEncryptedVaultKey,
      PENDING_WRAPPER.pendingVaultKeyIv,
      PENDING_WRAPPER.pendingVaultKeyTag,
      MEK,
    );

    // Both sides of the interrupted swap are carried across, under the pending key.
    expect(payload.items.map((i) => i.id)).toEqual(['old-row', 'pending-row']);
    for (const item of payload.items) {
      expect(item).toMatchObject({ nameIv: 'iv:pending-vault-key' });
    }
    // Nothing was skipped, so the report says so by staying silent about skips.
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: 'Interrupted vault key rotation finished',
        type: 'success',
      }),
    );

    // The session now holds the pending key and says which generation it is.
    await waitFor(() => {
      expect(useAuthStore.getState().vaultKey).toBe(PENDING_VAULT_KEY);
    });
    expect(useAuthStore.getState().encryptedVaultKeyData).toEqual({
      encrypted: PENDING_WRAPPER.pendingEncryptedVaultKey,
      iv: PENDING_WRAPPER.pendingVaultKeyIv,
      tag: PENDING_WRAPPER.pendingVaultKeyTag,
    });
    expect(useAuthStore.getState().vaultKeyVersion).toBe(5);
  });

  it('tries the pending key on the folder and document legs too, not only on items', async () => {
    // The second candidate has to reach EVERY leg. A crash re-seals whatever rows
    // the sequential loop had reached, in its own order — items, then folders,
    // then documents — so a leg that only ever tries the live key would pass
    // through exactly the rows the crash had already moved and report them as
    // lost, permanently, on a path that was supposed to recover them.
    installHalfRotatedVault();
    mockListFolders.mockResolvedValue({
      data: {
        success: true,
        data: [{ _id: 'f1', encryptedName: 'pending-row-f1', nameIv: 'f1-iv', nameTag: 'f1-tag' }],
      },
    });
    mockReadDocumentsConfigFresh.mockResolvedValue({ enabled: true });
    mockListDocuments.mockResolvedValue(documentPage([documentRow(docId(1))]));
    mockUnwrapDek.mockImplementation((_wrapped: unknown, wrapKey: { under: string }) =>
      // This document was already re-sealed before the crash.
      wrapKey.under === 'pending-vault-key'
        ? Promise.resolve(new Uint8Array(32).fill(7))
        : Promise.reject(new Error('GCM tag mismatch')),
    );

    await renderSettings();
    await confirmFinishRotation();

    await waitFor(() => {
      expect(mockBulkReEncrypt).toHaveBeenCalledTimes(1);
    });
    const payload = mockBulkReEncrypt.mock.calls[0]![0] as {
      folders: Record<string, unknown>[];
      documents: Record<string, unknown>[];
    };
    // Both were OPENED and rewritten, not passed through: a pass-through would
    // carry the original ciphertext, which these do not.
    expect(payload.folders).toEqual([
      {
        id: 'f1',
        encryptedName: 'enc:plain:pending-row-f1',
        nameIv: 'iv:pending-vault-key',
        nameTag: 'tag:pending-vault-key',
      },
    ]);
    expect(payload.documents).toEqual([
      {
        id: docId(1),
        encryptedDek: `dek@pending-vault-key:${docId(1)}`,
        dekIv: 'dekIv:pending-vault-key',
        dekTag: 'dekTag:pending-vault-key',
      },
    ]);
    // Nothing was reported as left behind.
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: 'Interrupted vault key rotation finished',
        type: 'success',
      }),
    );
  });

  it('zeroes the pending key’s plaintext bytes once it has been imported', async () => {
    // The unwrapped wrapper is 32 bytes of a live vault key. It is handed to
    // `importVaultKey` and must not be left in the heap afterwards — the same
    // invariant the change-password retry holds for the key it recovers.
    installHalfRotatedVault();

    await renderSettings();
    await confirmFinishRotation();

    await waitFor(() => {
      expect(mockBulkReEncrypt).toHaveBeenCalledTimes(1);
    });
    expect(cs.clearKey).toHaveBeenCalledWith(
      `raw:${PENDING_WRAPPER.pendingEncryptedVaultKey}:under:mek`,
    );
  });

  it('sends nothing when the profile read that would name the pending key fails', async () => {
    installHalfRotatedVault();
    await renderSettings();

    mockGetProfileApi.mockResolvedValue({ data: { success: false, message: 'nope' } });
    await confirmFinishRotation();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to rotate vault key', type: 'error' }),
      );
    });
    expect(mockBulkReEncrypt).not.toHaveBeenCalled();
    expect(cs.rotateVaultKey).not.toHaveBeenCalled();
    expect(useAuthStore.getState().vaultKey).toBe(OLD_VAULT_KEY);
  });

  it('replaces the ordinary rotation control while a rotation is outstanding', async () => {
    // The plain "Rotate Key" must not be one click away here: it would commit a
    // THIRD key, and every row the crash had already re-sealed would go with the
    // wrapper. Abandoning the interrupted rotation stays REACHABLE, because the
    // wrapper can be unopenable and the server refuses every other rotation while
    // it is outstanding — but it is a secondary control with its own confirmation.
    setProfile(PENDING_WRAPPER);

    await renderSettings();

    expect(screen.getByText('Finish Rotation')).toBeInTheDocument();
    expect(screen.queryByText('Rotate Key')).not.toBeInTheDocument();
    expect(screen.getByText(/interrupted vault key rotation is outstanding/i)).toBeInTheDocument();
    expect(screen.getByText(/abandoning the interrupted one/i)).toBeInTheDocument();
  });

  it('abandons the interrupted rotation only when told to, and says what that costs', async () => {
    // The escape for a wrapper that can no longer be opened. It mints a fresh key,
    // names the discard on the wire so the server stops refusing, and reports the
    // rows it could not carry across as LOST rather than as already-lost.
    installHalfRotatedVault();

    await renderSettings();
    fireEvent.click(screen.getByText(/abandoning the interrupted one/i));
    await waitFor(() => screen.getByPlaceholderText('Master password'));
    expect(screen.getByText('Abandon the Interrupted Rotation')).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'MasterPassword1!' },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Confirm Rotation'));
    });

    await waitFor(() => {
      expect(mockBulkReEncrypt).toHaveBeenCalledTimes(1);
    });
    const payload = mockBulkReEncrypt.mock.calls[0]![0] as {
      discardPendingVaultKey?: boolean;
      newEncryptedVaultKey: string;
      items: Record<string, unknown>[];
    };
    // A FRESH key, and the discard said out loud: without the flag the server
    // refuses this request rather than stranding the rows silently.
    expect(cs.rotateVaultKey).toHaveBeenCalledTimes(1);
    expect(payload.newEncryptedVaultKey).toBe('newEnc');
    expect(payload.discardPendingVaultKey).toBe(true);
    // The row that was already re-sealed cannot be read with the live key, so it
    // crosses unchanged — and is reported.
    expect(payload.items[1]).toMatchObject({
      id: 'pending-row',
      encryptedName: 'pending-row-name',
    });
    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          description: expect.stringContaining('sealed under the abandoned rotation'),
          type: 'warning',
        }),
      );
    });
    // The consolation that would be FALSE here must not be shown.
    expect(mockToast).not.toHaveBeenCalledWith(
      expect.objectContaining({
        description: expect.stringContaining('nothing was lost here'),
      }),
    );
  });

  it('does not name a discard on an ordinary rotation', async () => {
    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockBulkReEncrypt).toHaveBeenCalledTimes(1);
    });
    const payload = mockBulkReEncrypt.mock.calls[0]![0] as Record<string, unknown>;
    expect(payload).not.toHaveProperty('discardPendingVaultKey');
  });

  it('refuses to finish, and sends nothing, when the pending key will not open', async () => {
    // What a master-password change between the crash and the finish looks like:
    // the wrapper is sealed under the OLD MEK and this session holds the new one.
    // Retrying cannot help, so the message must not suggest it.
    installHalfRotatedVault();
    cs.decryptVaultKey.mockRejectedValue(new Error('Failed to decrypt vault key.'));

    await renderSettings();
    await confirmFinishRotation();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title:
            'Cannot finish the rotation: the stored in-flight vault key will not open with this account’s master password.',
          type: 'error',
        }),
      );
    });
    expect(mockBulkReEncrypt).not.toHaveBeenCalled();
    expect(cs.rotateVaultKey).not.toHaveBeenCalled();
    expect(useAuthStore.getState().vaultKey).toBe(OLD_VAULT_KEY);
  });

  it('says there is nothing to finish when the rotation completed elsewhere first', async () => {
    // The decision is re-read at the moment of acting, not taken from the profile
    // this page loaded on mount: another tab may have finished it in between, and
    // driving a rotation from a wrapper the server has already cleared would
    // re-commit a superseded key.
    installHalfRotatedVault();
    await renderSettings();

    setProfile({ interruptedRotation: false });
    await confirmFinishRotation();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'There is no interrupted rotation left to finish.',
        }),
      );
    });
    expect(mockBulkReEncrypt).not.toHaveBeenCalled();
    expect(cs.rotateVaultKey).not.toHaveBeenCalled();
    expect(useAuthStore.getState().vaultKey).toBe(OLD_VAULT_KEY);
  });

  it('discards the typed passwords when the rotation dialog is cancelled', async () => {
    setProfile({
      settings: {
        ...defaultProfile.settings,
        backup: {
          enabled: true,
          scheduleHour: 3,
          backupEmails: [],
          isConfigured: true,
          encryptedBWK: 'bwk',
          bwkIv: 'iv',
          bwkTag: 'tag',
          bwkSalt: 'salt',
        },
      },
    });
    await renderSettings();

    fireEvent.click(screen.getByText('Rotate Key'));
    await waitFor(() => screen.getByPlaceholderText('Backup password'));
    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'MasterPassword1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Backup password'), {
      target: { value: 'BackupPassword1!' },
    });

    const cancels = screen.getAllByText('Cancel');
    fireEvent.click(cancels[cancels.length - 1]!);

    fireEvent.click(screen.getByText('Rotate Key'));
    await waitFor(() => screen.getByPlaceholderText('Backup password'));
    expect((screen.getByPlaceholderText('Master password') as HTMLInputElement).value).toBe('');
    expect((screen.getByPlaceholderText('Backup password') as HTMLInputElement).value).toBe('');
  });

  // -------------------------------------------------------------------------
  // Export / import
  // -------------------------------------------------------------------------

  it('does not export when the account email is unavailable', async () => {
    await renderSettings();
    fireEvent.click(screen.getByText('Export Vault'));
    fireEvent.change(screen.getByPlaceholderText('Enter your master password'), {
      target: { value: 'MasterPassword1!' },
    });

    act(() => {
      useAuthStore.setState({ user: null });
    });
    await act(async () => {
      fireEvent.click(screen.getByText('I Understand, Export'));
    });

    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Password is required to export', type: 'error' }),
    );
    expect(mockExportVaultApi).not.toHaveBeenCalled();
  });

  // A native H-Vault item carrying all six ciphertext fields. The mocked
  // decryptData never throws, so it passes the client-side decryptability check.
  const nativeItem = {
    itemType: 'login',
    encryptedData: 'ed',
    dataIv: 'di',
    dataTag: 'dt',
    encryptedName: 'en',
    nameIv: 'ni',
    nameTag: 'nt',
  };
  const JSON_FORMAT_LABEL = 'H-Vault (.enc / JSON)';

  it('reports a failed import and leaves the import panel open', async () => {
    mockImportVaultApi.mockRejectedValue(new Error('server said no'));
    await renderSettings();

    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: JSON.stringify({ items: [nativeItem] }) },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Import'));
    });

    await waitFor(() => {
      expect(mockImportVaultApi).toHaveBeenCalled();
      expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({ type: 'error' }));
    });
    expect(screen.getByPlaceholderText('Paste exported data here...')).toBeInTheDocument();
  });

  it('names the generation every batch was sealed under', async () => {
    // Without it the server cannot tell a row sealed under the live key from one
    // sealed under a key it replaced days ago, and the second kind lands
    // stranded: the rotation enumerated the vault before the row existed, and no
    // later rotation can decrypt it either.
    mockImportVaultApi.mockResolvedValue({
      data: { success: true, data: { insertedCount: 1, updatedCount: 0 } },
    });
    await renderSettings();

    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: JSON.stringify({ items: [nativeItem] }) },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Import'));
    });

    await waitFor(() => expect(mockImportVaultApi).toHaveBeenCalled());
    // 4 is what this session holds (see the auth harness above), NOT zero and
    // NOT the number any response carries.
    expect(mockImportVaultApi).toHaveBeenCalledWith(
      expect.objectContaining({ vaultKeyVersion: 4 }),
    );
  });

  it('raises the reload notice when a batch is refused for a superseded key', async () => {
    // The same refusal shape the master-password change recovers from, reused
    // here deliberately: it is ONE server-side renderer, so a divergence between
    // what these two tests expect would be a divergence in the fixture, not in
    // the product.
    mockImportVaultApi.mockRejectedValue(staleGenerationRefusal(9));
    await renderSettings();

    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: JSON.stringify({ items: [nativeItem] }) },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Import'));
    });

    await waitFor(() => {
      expect(useUIStore.getState().staleVaultKeyVersion).toBe(9);
    });
    // The negatives: the refusal is reported rather than swallowed, it is not
    // retried, and this session's own generation is untouched — adopting the
    // number the server named would move the whole session onto a key it chose.
    expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({ type: 'error' }));
    expect(mockImportVaultApi).toHaveBeenCalledTimes(1);
    expect(useAuthStore.getState().vaultKeyVersion).toBe(4);
  });

  it('collapses byte-identical rows in one file and reports the full accounting', async () => {
    // Two rows carrying the same ciphertext decrypt to the same content, so they
    // are the same item listed twice: one is imported and the other is reported
    // rather than silently duplicated. Every row is accounted for, and the
    // counts sum to the number of rows the file held.
    mockImportVaultApi.mockResolvedValue({
      data: { success: true, data: { insertedCount: 1, updatedCount: 0 } },
    });
    await renderSettings();

    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: JSON.stringify({ items: [nativeItem, { ...nativeItem }] }) },
    });
    fireEvent.change(screen.getByDisplayValue('Skip duplicates'), {
      target: { value: 'overwrite' },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Import'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Imported 1 items, 1 duplicate rows in file (2 rows)',
        type: 'success',
      });
    });
    // The strategy is audit metadata now; it rides along unchanged.
    expect(mockImportVaultApi).toHaveBeenCalledWith(
      expect.objectContaining({ conflictStrategy: 'overwrite' }),
    );
    // Panel closes on success.
    expect(screen.queryByPlaceholderText('Paste exported data here...')).not.toBeInTheDocument();
  });

  it('auto-maps a 2FA recovery-codes column to backup codes, not to the TOTP secret', async () => {
    // Regression: the auto-map chain is if/else-if and the TOTP branch matches "2fa",
    // so this header used to land in `totp`, where the codes were truncated at 500
    // characters and rendered as though they were an authenticator seed.
    await renderSettings();

    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByDisplayValue(JSON_FORMAT_LABEL), { target: { value: 'csv' } });
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: 'Title,2FA recovery codes\nGithub,"aaaa-1111 bbbb-2222"' },
    });

    await waitFor(() => screen.getByText('Map CSV Columns'));
    expect(screen.getByDisplayValue('2FA Recovery Codes')).toBeInTheDocument();
    expect(screen.queryByDisplayValue('TOTP Secret')).toBeNull();
  });

  it('leaves a backup-email column alone rather than reading it as recovery codes', async () => {
    // The guard requires BOTH a backup/recovery word AND "code", so it cannot steal a
    // column that merely mentions backups.
    await renderSettings();

    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByDisplayValue(JSON_FORMAT_LABEL), { target: { value: 'csv' } });
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: 'Title,Backup email\nGithub,me@example.com' },
    });

    await waitFor(() => screen.getByText('Map CSV Columns'));
    expect(screen.queryByDisplayValue('2FA Recovery Codes')).toBeNull();
  });

  it('parses a CSV via column mapping, encrypts client-side, and sends encrypted items (never plaintext or a mapping)', async () => {
    mockImportVaultApi.mockResolvedValue({
      data: { success: true, data: { insertedCount: 1, updatedCount: 0 } },
    });
    await renderSettings();

    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByDisplayValue(JSON_FORMAT_LABEL), { target: { value: 'csv' } });
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: 'Title,Website,Secret\nGithub,https://gh.com,p@ss' },
    });

    await waitFor(() => screen.getByText('Map CSV Columns'));
    // Auto-detection: title→name, website→url. "Secret" matches nothing → Skip.
    expect(screen.getByDisplayValue('Name')).toBeInTheDocument();
    expect(screen.getByDisplayValue('URL')).toBeInTheDocument();
    // The user maps the unmapped "Secret" column to Password.
    fireEvent.change(screen.getByDisplayValue('-- Skip --'), { target: { value: 'password' } });

    await act(async () => {
      fireEvent.click(screen.getByText('Import'));
    });

    await waitFor(() => expect(mockImportVaultApi).toHaveBeenCalled());
    const payload = mockImportVaultApi.mock.calls[0]?.[0] as {
      format: string;
      operations: { inserts: Record<string, string>[]; updates: unknown[] };
      conflictStrategy: string;
      csvMapping?: unknown;
      data?: unknown;
    };
    expect(payload.format).toBe('csv');
    // The mapping is a client-side concern now; it is NOT sent to the server.
    expect(payload.csvMapping).toBeUndefined();
    // The retired `data` envelope is gone: operations are explicit.
    expect(payload.data).toBeUndefined();
    expect(payload.operations.inserts).toHaveLength(1);
    expect(payload.operations.updates).toEqual([]);
    // Client-side encryption ran (mocked encryptData → `enc:<plain>`): the wire
    // payload carries ciphertext fields + a search hash, not raw columns.
    expect(payload.operations.inserts[0]?.encryptedData).toMatch(/^enc:/);
    expect(payload.operations.inserts[0]?.encryptedName).toMatch(/^enc:/);
    expect(payload.operations.inserts[0]?.searchHash).toMatch(/^sh:/);
    // The zero-knowledge property itself is asserted in settings-import-flow,
    // where the crypto stub does not embed its input in its output — here the
    // `enc:<plain>` stub would make such a check meaningless.
  });

  it('parses quoted CSV fields containing commas and escaped quotes as single cells', async () => {
    await renderSettings();

    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByDisplayValue(JSON_FORMAT_LABEL), { target: { value: 'csv' } });
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: 'Name,Notes\nAcme,"one, two ""quoted"""' },
    });

    await waitFor(() => screen.getByText('Map CSV Columns'));
    // A naive split(',') would render "one" and " two" as two cells.
    expect(screen.getByText('one, two "quoted"')).toBeInTheDocument();
    expect(screen.getByText('Preview (1 of 1 rows)')).toBeInTheDocument();
  });

  // An item that fails the shared schema is dropped at the validation step.
  /**
   * This test used to assert the OPPOSITE, and the change is deliberate.
   *
   * A card `number` far past the shared 30-character cap was the last field a
   * source file could carry that no clamp bounded, so it failed
   * `vaultItemDataSchemas` and `validateImportItems` discarded the whole card —
   * every other field of it, and any password-equivalent value with them —
   * reported to the user as "1 could not be converted". This test pinned that
   * behaviour, including the requirement that the reason at least name the item
   * and the field.
   *
   * Clamping those eleven card and identity scalars removed the last path by
   * which a parser can emit an item its own schema rejects, so the case this
   * test was written around is no longer reachable from any import format, and
   * the stronger property is worth pinning in its place: the card ARRIVES rather
   * than being dropped, and no "could not be converted" toast fires at all. The
   * clamped LENGTH is not asserted here and cannot be — what reaches the API is
   * ciphertext — so it is pinned in `tests/fuzz/parsers.fuzz.test.ts`, against
   * the parser's plaintext output.
   *
   * The per-item reason itself is still pinned, at the tier where it remains
   * reachable without a parser defect: `tests/import/encrypt.test.ts` drives
   * `validateImportItems` with a synthetic invalid item and asserts both the
   * skip count and the warning text.
   */
  it('names WHICH item was skipped and why, not just how many', async () => {
    // The wiring at `SettingsPage.tsx:958-962`: the per-item reasons must reach
    // the toast's `description`. Reporting only a count leaves the user unable to
    // tell which entry was lost, and re-running the import cannot reveal it —
    // the same rows are skipped again, just as silently.
    //
    // Driven through the collaborator seam because no real file can produce a
    // skipped item any more (see the seam's own note). What is asserted is
    // entirely `SettingsPage`'s own behaviour: it renders the reasons it is
    // given, and it does not send an import when nothing survived.
    mockValidateImportOverride = () => ({
      items: [],
      skipped: 2,
      warnings: ['Skipped "Payroll": number: Too big', 'Skipped "Passport": ssn: Too big'],
    });

    await renderSettings();

    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByDisplayValue(JSON_FORMAT_LABEL), {
      target: { value: 'bitwarden' },
    });
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: {
        value: JSON.stringify({ items: [{ type: 3, name: 'Payroll', card: { number: '4' } }] }),
      },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Import'));
    });

    const call = await waitFor(() => {
      const found = mockToast.mock.calls
        .map(([arg]) => arg as { title: string; description?: string })
        .find((arg) => /could not be converted/i.test(arg.title));
      expect(found).toBeDefined();
      return found!;
    });
    expect(call.title).toContain('2');
    // The reasons themselves, both of them, each naming its item and its field.
    expect(call.description).toContain('Payroll');
    expect(call.description).toContain('number');
    expect(call.description).toContain('Passport');
    // And the negative: nothing was sent to the server for an import in which
    // nothing survived validation.
    expect(mockImportVaultApi).not.toHaveBeenCalled();
  });

  it('imports a card whose number is past the cap, clamped, instead of dropping the card', async () => {
    mockImportVaultApi.mockResolvedValue({
      data: { success: true, data: { insertedCount: 1, updatedCount: 0 } },
    });
    await renderSettings();

    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByDisplayValue(JSON_FORMAT_LABEL), {
      target: { value: 'bitwarden' },
    });
    const overlong = JSON.stringify({
      items: [{ type: 3, name: 'Overlong', card: { number: '4'.repeat(60) } }],
    });
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: overlong },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Import'));
    });

    await waitFor(() => expect(mockImportVaultApi).toHaveBeenCalled());
    const payload = mockImportVaultApi.mock.calls[0]?.[0] as {
      operations: { inserts: unknown[] };
    };
    expect(payload.operations.inserts).toHaveLength(1);
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Imported 1 items', type: 'success' }),
    );
    // The negative half, and the one that matters: nothing was skipped, so the
    // user is never told an item vanished.
    for (const [arg] of mockToast.mock.calls) {
      expect((arg as { title: string }).title).not.toMatch(/could not be converted/i);
    }
  });

  // The mirror of the case above: an over-long free-text field (here a URL well
  // past the 2048 cap) is CLAMPED and the item still imports, rather than being
  // dropped wholesale — the fidelity-clamp guarantee at the SettingsPage level.
  it('imports an item with an over-long URL instead of dropping it (fidelity clamp)', async () => {
    mockImportVaultApi.mockResolvedValue({
      data: { success: true, data: { insertedCount: 1, updatedCount: 0 } },
    });
    await renderSettings();

    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByDisplayValue(JSON_FORMAT_LABEL), { target: { value: 'csv' } });
    const longUrl = `https://example.com/${'a'.repeat(2100)}`;
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: `Name,URL\nOverlong,${longUrl}` },
    });

    await waitFor(() => screen.getByText('Map CSV Columns'));
    await act(async () => {
      // A string `name` is matched against the full accessible name, so this
      // still resolves the "Import" submit button and never "Import Vault".
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });

    await waitFor(() => expect(mockImportVaultApi).toHaveBeenCalled());
    // One encrypted item was sent (not skipped), and the success toast reports it.
    const payload = mockImportVaultApi.mock.calls[0]?.[0] as {
      operations: { inserts: unknown[] };
    };
    expect(payload.operations.inserts).toHaveLength(1);
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Imported 1 items', type: 'success' }),
    );
  });

  // The preview shows 3 sample rows out of the file's true total. That total is
  // captured from the single parse in the effect, not re-derived during render —
  // an 8 MiB import file re-tokenized on every mapping change would block the
  // main thread. Changing a mapping dropdown must not disturb the count.
  it('reports the full row count in the preview and keeps it across a mapping change', async () => {
    await renderSettings();

    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByDisplayValue(JSON_FORMAT_LABEL), { target: { value: 'csv' } });
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: 'Name,Secret\na,1\nb,2\nc,3\nd,4\ne,5' },
    });

    await waitFor(() => screen.getByText('Map CSV Columns'));
    expect(screen.getByText('Preview (3 of 5 rows)')).toBeInTheDocument();

    const mappingSelect = screen.getAllByDisplayValue('-- Skip --')[0]!;
    fireEvent.change(mappingSelect, { target: { value: 'notes' } });

    await waitFor(() => expect(screen.getByText('Preview (3 of 5 rows)')).toBeInTheDocument());
  });

  it('treats an uploaded .enc export as JSON and loads its contents', async () => {
    await renderSettings();
    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByDisplayValue(JSON_FORMAT_LABEL), { target: { value: 'csv' } });

    const fileInput = document.querySelector('input[type="file"]')!;
    const content = JSON.stringify({ items: [{ encryptedData: 'abc' }] });
    const file = new File([content], 'hvault-export.enc', { type: '' });

    await act(async () => {
      fireEvent.change(fileInput, { target: { files: [file] } });
    });

    // Waited on the OBSERVABLE RESULT, not on a fixed delay. A `FileReader`
    // resolves on its own schedule, and the 50 ms sleep this replaces was enough
    // on an idle machine and not enough inside a full parallel run — which is a
    // race reported as a mystery, not a slow test. The condition is the same
    // assertion either way, so nothing here is weaker than it was.
    await waitFor(() =>
      expect(
        (screen.getByPlaceholderText('Paste exported data here...') as HTMLTextAreaElement).value,
      ).toBe(content),
    );
    expect(screen.getByDisplayValue(JSON_FORMAT_LABEL)).toBeInTheDocument();
  });

  // -------------------------------------------------------------------------
  // Settings form
  // -------------------------------------------------------------------------

  it('saves the edited timeouts with the active theme and invalidates the settings cache', async () => {
    mockUpdateSettingsApi.mockResolvedValue({ data: { success: true } });
    await renderSettings();

    fireEvent.change(screen.getByDisplayValue('15'), { target: { value: '45' } });
    fireEvent.change(screen.getByDisplayValue('30'), { target: { value: '90' } });

    await act(async () => {
      fireEvent.click(screen.getByText('Save Settings'));
    });

    await waitFor(() => {
      expect(mockUpdateSettingsApi).toHaveBeenCalledWith({
        autoLockTimeout: 45,
        // Every save sends the whole settings object, so the untouched
        // hidden-tab fields ride along at their loaded values rather than being
        // dropped (the server would leave them alone either way, but a payload
        // that silently omits half the form is how one control starts clobbering
        // another's value).
        lockOnHidden: false,
        lockOnHiddenDelay: 1,
        clipboardClearTimeout: 90,
        theme: 'dark',
      });
    });
    // Without this, every other consumer keeps the stale cached timeouts.
    expect(mockClearSettingsCache).toHaveBeenCalled();
  });

  // The hidden-tab lock is the one setting whose OFF state is as load-bearing as
  // its ON state: it must be possible to turn back off. A payload built with a
  // truthiness guard (`...(lockOnHidden && { lockOnHidden })`, or an `||`
  // default) would send `true` fine and then silently omit the `false`, leaving
  // the server on the old value — a setting that can be enabled and never
  // disabled. So both directions are asserted, and the OFF payload is compared
  // whole so an omitted key cannot pass as a falsy one.
  it('round-trips the hidden-tab lock and its delay in both directions', async () => {
    mockUpdateSettingsApi.mockResolvedValue({ data: { success: true } });
    await renderSettings();

    const lockOnHidden = screen.getByLabelText('Lock when the tab is hidden') as HTMLInputElement;
    expect(lockOnHidden.checked).toBe(false);
    // The delay only matters while the lock is on, so it stays hidden until then.
    expect(screen.queryByLabelText(/after this many minutes hidden/)).not.toBeInTheDocument();

    fireEvent.click(lockOnHidden);
    expect(lockOnHidden.checked).toBe(true);

    const delay = screen.getByLabelText(/after this many minutes hidden/) as HTMLInputElement;
    // Seeded from the profile, not from a blank control.
    expect(delay.value).toBe('1');
    fireEvent.change(delay, { target: { value: '5' } });

    await act(async () => {
      fireEvent.click(screen.getByText('Save Settings'));
    });

    await waitFor(() => {
      expect(mockUpdateSettingsApi).toHaveBeenCalledWith({
        autoLockTimeout: 15,
        lockOnHidden: true,
        lockOnHiddenDelay: 5,
        clipboardClearTimeout: 30,
        theme: 'dark',
      });
    });

    // Now switch it back off and save again.
    fireEvent.click(screen.getByLabelText('Lock when the tab is hidden'));
    expect((screen.getByLabelText('Lock when the tab is hidden') as HTMLInputElement).checked).toBe(
      false,
    );
    expect(screen.queryByLabelText(/after this many minutes hidden/)).not.toBeInTheDocument();

    await act(async () => {
      fireEvent.click(screen.getByText('Save Settings'));
    });

    await waitFor(() => {
      expect(mockUpdateSettingsApi).toHaveBeenCalledTimes(2);
    });
    expect(mockUpdateSettingsApi.mock.calls[1]![0]).toEqual({
      autoLockTimeout: 15,
      lockOnHidden: false,
      // The edited delay survives the toggle, so re-enabling does not silently
      // reset it to the default.
      lockOnHiddenDelay: 5,
      clipboardClearTimeout: 30,
      theme: 'dark',
    });
  });
});
