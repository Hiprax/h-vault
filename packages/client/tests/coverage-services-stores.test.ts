/**
 * Coverage-raising behavioral tests for the client services / stores layer.
 *
 * Focus is on the ERROR and EDGE branches that the existing suites never
 * reach:
 *   - offlineCache: IndexedDB open failure, transaction abort, quota exceeded,
 *     permission denied, read failure, IndexedDB entirely unavailable, and the
 *     connection-close guarantee on the failure path.
 *   - encryptedStorage: the degraded-mode strip for non-persist / malformed
 *     payloads, the encryption-failure fallback, and the session-key re-import
 *     path across a page reload.
 *   - uiStore: sidebarCollapsed persistence + partialize, the persisted-theme
 *     rehydration hook, and the OS `prefers-color-scheme` change listener.
 *   - logger: the production no-op branch (secrets must never reach the
 *     console in a production build).
 *   - App: the lazy route table (each path maps to the right page, behind the
 *     right route wrapper).
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import { createElement } from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import 'fake-indexeddb/auto';

// ---------------------------------------------------------------------------
// offlineCache — IndexedDB failure paths
// ---------------------------------------------------------------------------

interface FakeRequest {
  onsuccess: (() => void) | null;
  onerror: (() => void) | null;
  onupgradeneeded: (() => void) | null;
  result: unknown;
  error: unknown;
}

interface FakeTransaction {
  oncomplete: (() => void) | null;
  onerror: (() => void) | null;
  error: unknown;
  objectStore: () => { clear: () => void; put: () => void; getAll: () => FakeRequest };
}

function makeStore(getAllRequest?: FakeRequest) {
  return {
    clear: () => undefined,
    put: () => undefined,
    getAll: () => getAllRequest as FakeRequest,
  };
}

/** A fake IDBDatabase whose transactions fail with `error` on the given attempt. */
function makeFailingDb(error: unknown, failOnTransaction = 1) {
  let calls = 0;
  const close = vi.fn();
  const db = {
    close,
    transaction: (): FakeTransaction => {
      calls += 1;
      const shouldFail = calls === failOnTransaction;
      const tx: FakeTransaction = {
        oncomplete: null,
        onerror: null,
        error: shouldFail ? error : null,
        objectStore: () => makeStore(),
      };
      queueMicrotask(() => {
        if (shouldFail) tx.onerror?.();
        else tx.oncomplete?.();
      });
      return tx;
    },
  };
  return { db, close };
}

/** Stub indexedDB.open so it resolves with `db` (or rejects with `openError`). */
function stubOpen(opts: { db?: unknown; openError?: unknown }) {
  return vi.spyOn(indexedDB, 'open').mockImplementation(() => {
    const request: FakeRequest = {
      onsuccess: null,
      onerror: null,
      onupgradeneeded: null,
      result: opts.db,
      error: opts.openError ?? null,
    };
    queueMicrotask(() => {
      if (opts.db) request.onsuccess?.();
      else request.onerror?.();
    });
    return request as unknown as IDBOpenDBRequest;
  });
}

async function importOfflineCache() {
  vi.resetModules();
  return import('../src/services/offlineCache');
}

describe('offlineCache — IndexedDB failure paths', () => {
  // Per WebIDL, `DOMException` inherits from `Error` in every real browser
  // (`new DOMException(...) instanceof Error === true`). jsdom's DOMException
  // sits on a prototype chain that does NOT satisfy the global `instanceof
  // Error`, which would make the production code's `error instanceof Error`
  // guard behave differently here than in a browser. Align the environment
  // with the spec so these tests exercise the real branch.
  const originalDomExceptionProto: unknown = Object.getPrototypeOf(DOMException.prototype);

  beforeAll(() => {
    Object.setPrototypeOf(DOMException.prototype, Error.prototype);
  });

  afterAll(() => {
    Object.setPrototypeOf(DOMException.prototype, originalDomExceptionProto as object);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('surfaces a failed database open as an OfflineCacheError rather than a raw event', async () => {
    const { offlineCache, OfflineCacheError } = await importOfflineCache();
    stubOpen({});

    await expect(offlineCache.getCachedItems()).rejects.toBeInstanceOf(OfflineCacheError);
    await expect(offlineCache.getCachedItems()).rejects.toMatchObject({
      type: 'unknown',
      message: 'IndexedDB open failed',
    });
  });

  it('classifies a quota-exceeded transaction failure as type "quota_exceeded"', async () => {
    const { offlineCache, OfflineCacheError } = await importOfflineCache();
    const quota = new DOMException('out of space', 'QuotaExceededError');
    const { db } = makeFailingDb(quota);
    stubOpen({ db });

    const err: unknown = await offlineCache.cacheItems([{ _id: 'a' }]).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OfflineCacheError);
    expect((err as InstanceType<typeof OfflineCacheError>).type).toBe('quota_exceeded');
    expect((err as InstanceType<typeof OfflineCacheError>).cause).toBe(quota);
  });

  it('classifies a blocked (SecurityError) transaction as type "permission_denied"', async () => {
    const { offlineCache, OfflineCacheError } = await importOfflineCache();
    const denied = new DOMException('blocked', 'SecurityError');
    const { db } = makeFailingDb(denied);
    stubOpen({ db });

    const err: unknown = await offlineCache.cacheFolders([{ _id: 'f' }]).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OfflineCacheError);
    expect((err as InstanceType<typeof OfflineCacheError>).type).toBe('permission_denied');
  });

  it('classifies a NotAllowedError open failure as type "permission_denied"', async () => {
    const { offlineCache, OfflineCacheError } = await importOfflineCache();
    stubOpen({ openError: new DOMException('nope', 'NotAllowedError') });

    const err: unknown = await offlineCache.clear().catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OfflineCacheError);
    expect((err as InstanceType<typeof OfflineCacheError>).type).toBe('permission_denied');
  });

  it('closes the database connection even when the write transaction aborts', async () => {
    const { offlineCache } = await importOfflineCache();
    const { db, close } = makeFailingDb(new Error('aborted'));
    stubOpen({ db });

    await expect(offlineCache.cacheItems([{ _id: 'a' }])).rejects.toThrow('aborted');

    expect(close).toHaveBeenCalledTimes(1);
  });

  it('fails cacheItems when the metadata (lastSync) transaction aborts after the items write', async () => {
    const { offlineCache, OfflineCacheError } = await importOfflineCache();
    // First transaction (items) succeeds; the second (meta) aborts.
    const { db, close } = makeFailingDb(new DOMException('gone', 'QuotaExceededError'), 2);
    stubOpen({ db });

    const err: unknown = await offlineCache.cacheItems([{ _id: 'a' }]).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OfflineCacheError);
    expect((err as InstanceType<typeof OfflineCacheError>).type).toBe('quota_exceeded');
    expect(close).toHaveBeenCalledTimes(1);
  });

  it('surfaces a failed read (getAll) as an OfflineCacheError instead of hanging', async () => {
    const { offlineCache, OfflineCacheError } = await importOfflineCache();
    const getAllRequest: FakeRequest = {
      onsuccess: null,
      onerror: null,
      onupgradeneeded: null,
      result: undefined,
      error: new DOMException('read blew up', 'InvalidStateError'),
    };
    const db = {
      close: vi.fn(),
      transaction: () => ({
        objectStore: () => {
          queueMicrotask(() => getAllRequest.onerror?.());
          return makeStore(getAllRequest);
        },
      }),
    };
    stubOpen({ db });

    const err: unknown = await offlineCache.getCachedFolders().catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OfflineCacheError);
    // An InvalidStateError DOMException is neither quota nor permission.
    expect((err as InstanceType<typeof OfflineCacheError>).type).toBe('unknown');
  });

  it('surfaces a failed getLastSync read as an OfflineCacheError', async () => {
    const { offlineCache, OfflineCacheError } = await importOfflineCache();
    const getRequest: FakeRequest = {
      onsuccess: null,
      onerror: null,
      onupgradeneeded: null,
      result: undefined,
      error: null,
    };
    const db = {
      close: vi.fn(),
      transaction: () => ({
        objectStore: () => ({
          get: () => {
            queueMicrotask(() => getRequest.onerror?.());
            return getRequest;
          },
        }),
      }),
    };
    stubOpen({ db });

    const err: unknown = await offlineCache.getLastSync('items').catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OfflineCacheError);
    expect((err as InstanceType<typeof OfflineCacheError>).message).toBe('IndexedDB read failed');
  });

  it('reports type "unavailable" when IndexedDB does not exist in the environment', async () => {
    const { offlineCache, OfflineCacheError } = await importOfflineCache();
    vi.stubGlobal('indexedDB', undefined);

    const err: unknown = await offlineCache.getCachedItems().catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OfflineCacheError);
    expect((err as InstanceType<typeof OfflineCacheError>).type).toBe('unavailable');
    expect((err as InstanceType<typeof OfflineCacheError>).message).toBe(
      'IndexedDB is not available',
    );
  });

  it('does not re-wrap an OfflineCacheError that has already been classified', async () => {
    const { offlineCache, OfflineCacheError } = await importOfflineCache();
    const original = new OfflineCacheError('already classified', 'quota_exceeded');
    // classifyError is exercised through the public surface: an open that throws
    // an OfflineCacheError synchronously must come back out unchanged.
    vi.spyOn(indexedDB, 'open').mockImplementation(() => {
      throw original;
    });

    const err: unknown = await offlineCache.clear().catch((e: unknown) => e);

    expect(err).toBe(original);
  });
});

// ---------------------------------------------------------------------------
// encryptedStorage — degraded mode and key lifecycle
// ---------------------------------------------------------------------------

const STORAGE_DEGRADED_KEY = '__hv_storage_degraded';
const SESSION_KEY_NAME = 'hvault_storage_key';

async function importEncryptedStorage() {
  vi.resetModules();
  return import('../src/stores/encryptedStorage');
}

/** Run `fn` with the Web Crypto SubtleCrypto API removed. */
async function withoutSubtleCrypto(fn: () => Promise<void>): Promise<void> {
  const originalSubtle = crypto.subtle;
  Object.defineProperty(crypto, 'subtle', { value: undefined, configurable: true });
  try {
    await fn();
  } finally {
    Object.defineProperty(crypto, 'subtle', { value: originalSubtle, configurable: true });
  }
}

describe('encryptedStorage — degraded mode and key lifecycle', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('persists an empty logged-out state (not the raw value) when a non-JSON payload is written in degraded mode', async () => {
    await withoutSubtleCrypto(async () => {
      const { encryptedStorage } = await importEncryptedStorage();

      await encryptedStorage.setItem('auth-store', 'not-json-at-all{{{');

      const stored = localStorage.getItem('auth-store');
      expect(stored).not.toContain('not-json-at-all');
      expect(JSON.parse(stored ?? '{}')).toEqual({ state: { isAuthenticated: false } });
      expect(localStorage.getItem(STORAGE_DEGRADED_KEY)).toBe('true');
    });
  });

  it('coerces a missing isAuthenticated to false in degraded mode rather than persisting undefined', async () => {
    await withoutSubtleCrypto(async () => {
      const { encryptedStorage } = await importEncryptedStorage();

      await encryptedStorage.setItem(
        'auth-store',
        JSON.stringify({ state: { user: { email: 'a@b.co' } }, version: 3 }),
      );

      const parsed = JSON.parse(localStorage.getItem('auth-store') ?? '{}') as {
        state: Record<string, unknown>;
        version: number;
      };
      expect(parsed.state).toEqual({ isAuthenticated: false });
      // Non-state metadata (version) is preserved so persist can still rehydrate.
      expect(parsed.version).toBe(3);
    });
  });

  it('falls back to degraded mode when encryption itself fails, and strips the sensitive state', async () => {
    const { encryptedStorage, isStorageDegraded } = await importEncryptedStorage();
    // A working key, but the encrypt call blows up (e.g. hostile/broken engine).
    vi.spyOn(crypto.subtle, 'encrypt').mockRejectedValue(new Error('engine failure'));

    await encryptedStorage.setItem(
      'auth-store',
      JSON.stringify({ state: { isAuthenticated: true, mek: 'super-secret-master-key' } }),
    );

    const stored = localStorage.getItem('auth-store') ?? '';
    expect(stored).not.toContain('super-secret-master-key');
    expect(JSON.parse(stored)).toEqual({ state: { isAuthenticated: true } });
    expect(isStorageDegraded()).toBe(true);
  });

  it('re-imports the session key after a page reload so persisted state survives within the session', async () => {
    const { encryptedStorage } = await importEncryptedStorage();
    const payload = JSON.stringify({ state: { isAuthenticated: true } });
    await encryptedStorage.setItem('auth-store', payload);
    expect(sessionStorage.getItem(SESSION_KEY_NAME)).not.toBeNull();

    // Simulate a page reload: fresh module instance (empty in-memory key cache),
    // but sessionStorage (and therefore the raw key) survives.
    const { encryptedStorage: afterReload } = await importEncryptedStorage();

    expect(await afterReload.getItem('auth-store')).toBe(payload);
  });

  it('returns null (and does not throw) when decryption fails on a well-formed but foreign ciphertext', async () => {
    const { encryptedStorage } = await importEncryptedStorage();
    await encryptedStorage.setItem('auth-store', '"seed"');

    // 12-byte IV + 20 bytes of garbage: passes the length check, fails the GCM tag.
    const bogus = new Uint8Array(32);
    crypto.getRandomValues(bogus);
    let binary = '';
    for (const b of bogus) binary += String.fromCharCode(b);
    localStorage.setItem('auth-store', btoa(binary));

    expect(await encryptedStorage.getItem('auth-store')).toBeNull();
    expect(localStorage.getItem('auth-store')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// uiStore — persistence and OS theme tracking
// ---------------------------------------------------------------------------

interface MatchMediaHarness {
  setPrefersDark: (v: boolean) => void;
  fireChange: () => void;
}

/** Install a controllable matchMedia and return a handle to drive it. */
function installMatchMedia(): MatchMediaHarness {
  const listeners: (() => void)[] = [];
  let prefersDark = false;
  const factory = (query: string): MediaQueryList =>
    ({
      get matches() {
        return prefersDark && query === '(prefers-color-scheme: dark)';
      },
      media: query,
      onchange: null,
      addListener: () => undefined,
      removeListener: () => undefined,
      addEventListener: (_event: string, listener: () => void) => {
        listeners.push(listener);
      },
      removeEventListener: () => undefined,
      dispatchEvent: () => false,
    }) as unknown as MediaQueryList;
  window.matchMedia = factory as unknown as typeof window.matchMedia;
  return {
    setPrefersDark: (v: boolean) => {
      prefersDark = v;
    },
    fireChange: () => {
      for (const l of listeners) l();
    },
  };
}

async function importUIStore() {
  vi.resetModules();
  return import('../src/stores/uiStore');
}

describe('uiStore — persistence and OS theme tracking', () => {
  const originalMatchMedia = window.matchMedia;

  beforeEach(() => {
    localStorage.clear();
    document.documentElement.classList.remove('dark');
    document.documentElement.removeAttribute('data-theme');
  });

  afterEach(() => {
    window.matchMedia = originalMatchMedia;
  });

  it('persists sidebarCollapsed and theme, but not the transient sidebarOpen / commandPalette state', async () => {
    installMatchMedia();
    const { useUIStore } = await importUIStore();

    useUIStore.getState().toggleSidebarCollapsed();
    useUIStore.getState().toggleSidebar();
    useUIStore.getState().toggleCommandPalette();
    useUIStore.getState().setTheme('dark');

    expect(useUIStore.getState().sidebarCollapsed).toBe(true);

    const persisted = JSON.parse(localStorage.getItem('hvault-ui') ?? '{}') as {
      state: Record<string, unknown>;
    };
    expect(persisted.state).toEqual({ theme: 'dark', sidebarCollapsed: true });
    expect(persisted.state).not.toHaveProperty('sidebarOpen');
    expect(persisted.state).not.toHaveProperty('commandPaletteOpen');
  });

  it('toggleSidebarCollapsed flips back to expanded on a second call', async () => {
    installMatchMedia();
    const { useUIStore } = await importUIStore();

    useUIStore.getState().toggleSidebarCollapsed();
    useUIStore.getState().toggleSidebarCollapsed();

    expect(useUIStore.getState().sidebarCollapsed).toBe(false);
  });

  it('applies the persisted theme to <html> on rehydration, before any user interaction', async () => {
    installMatchMedia();
    localStorage.setItem(
      'hvault-ui',
      JSON.stringify({ state: { theme: 'dark', sidebarCollapsed: true }, version: 0 }),
    );

    const { useUIStore } = await importUIStore();

    await waitFor(() => {
      expect(useUIStore.getState().theme).toBe('dark');
    });
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    expect(useUIStore.getState().sidebarCollapsed).toBe(true);
  });

  it('follows an OS dark-mode switch while the theme is "system"', async () => {
    const media = installMatchMedia();
    const { useUIStore } = await importUIStore();
    useUIStore.getState().setTheme('system');
    expect(document.documentElement.classList.contains('dark')).toBe(false);

    media.setPrefersDark(true);
    media.fireChange();

    expect(document.documentElement.classList.contains('dark')).toBe(true);
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
  });

  it('ignores an OS dark-mode switch when the user has explicitly chosen "light"', async () => {
    const media = installMatchMedia();
    const { useUIStore } = await importUIStore();
    useUIStore.getState().setTheme('light');

    media.setPrefersDark(true);
    media.fireChange();

    expect(document.documentElement.classList.contains('dark')).toBe(false);
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
  });
});

// ---------------------------------------------------------------------------
// logger — the production no-op branch
// ---------------------------------------------------------------------------

describe('logger', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it('forwards to the console in development', async () => {
    vi.stubEnv('DEV', true);
    const spies = {
      error: vi.spyOn(console, 'error').mockImplementation(() => undefined),
      warn: vi.spyOn(console, 'warn').mockImplementation(() => undefined),
      info: vi.spyOn(console, 'info').mockImplementation(() => undefined),
      debug: vi.spyOn(console, 'debug').mockImplementation(() => undefined),
    };
    vi.resetModules();
    const { logger } = await import('../src/lib/logger');

    logger.error('boom', 1);
    logger.warn('warn');
    logger.info('info');
    logger.debug('debug');

    expect(spies.error).toHaveBeenCalledWith('boom', 1);
    expect(spies.warn).toHaveBeenCalledWith('warn');
    expect(spies.info).toHaveBeenCalledWith('info');
    expect(spies.debug).toHaveBeenCalledWith('debug');
  });

  it('emits nothing at all in a production build (no secrets leak to the console)', async () => {
    vi.stubEnv('DEV', false);
    const spies = {
      error: vi.spyOn(console, 'error').mockImplementation(() => undefined),
      warn: vi.spyOn(console, 'warn').mockImplementation(() => undefined),
      info: vi.spyOn(console, 'info').mockImplementation(() => undefined),
      debug: vi.spyOn(console, 'debug').mockImplementation(() => undefined),
    };
    vi.resetModules();
    const { logger } = await import('../src/lib/logger');

    logger.error('vault key', 'secret');
    logger.warn('w');
    logger.info('i');
    logger.debug('d');

    expect(spies.error).not.toHaveBeenCalled();
    expect(spies.warn).not.toHaveBeenCalled();
    expect(spies.info).not.toHaveBeenCalled();
    expect(spies.debug).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// favicon — memoisation of the applied state
// ---------------------------------------------------------------------------

describe('favicon setFaviconState', () => {
  it('skips the DOM write when the state has not changed since the last call', async () => {
    const { setFaviconState, resetFaviconStateForTests, FAVICON_HREFS } =
      await import('../src/utils/favicon');
    resetFaviconStateForTests();

    setFaviconState('unlocked');
    const link = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
    expect(link?.getAttribute('href')).toBe(FAVICON_HREFS.unlocked);

    // An external actor rewrites the href; a repeat call with the SAME state is
    // memoised and must not touch the DOM again.
    link?.setAttribute('href', '/tampered.svg');
    setFaviconState('unlocked');
    expect(link?.getAttribute('href')).toBe('/tampered.svg');

    // A genuine state change still writes.
    setFaviconState('locked');
    expect(link?.getAttribute('href')).toBe(FAVICON_HREFS.locked);

    resetFaviconStateForTests();
  });
});

// ---------------------------------------------------------------------------
// utils — hasValidEmailTld (zero-knowledge typo lockout guard)
// ---------------------------------------------------------------------------

describe('hasValidEmailTld', () => {
  it('accepts a normal address and a multi-label domain', async () => {
    const { hasValidEmailTld } = await import('../src/lib/utils');
    expect(hasValidEmailTld('user@example.com')).toBe(true);
    expect(hasValidEmailTld('user@mail.co.uk')).toBe(true);
    // The LAST @ delimits the domain.
    expect(hasValidEmailTld('weird@name@example.com')).toBe(true);
  });

  it('rejects addresses whose domain cannot resolve to a TLD (unrecoverable master-password salt typos)', async () => {
    const { hasValidEmailTld } = await import('../src/lib/utils');
    expect(hasValidEmailTld('user@localhost')).toBe(false);
    expect(hasValidEmailTld('no-at-sign.com')).toBe(false);
    expect(hasValidEmailTld('user@')).toBe(false);
    expect(hasValidEmailTld('user@.com')).toBe(false);
    expect(hasValidEmailTld('user@example.')).toBe(false);
    expect(hasValidEmailTld('user@exam ple.com')).toBe(false);
    expect(hasValidEmailTld('user@a..com')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// App — the lazy route table
// ---------------------------------------------------------------------------

vi.mock('../src/hooks/useFavicon', () => ({ useFavicon: () => undefined }));
vi.mock('../src/components/layout/ReloadPrompt', () => ({
  ReloadPrompt: () => createElement('div', { 'data-testid': 'reload-prompt' }),
}));
vi.mock('../src/components/layout/ProtectedRoute', async () => {
  const { Outlet } = await import('react-router-dom');
  return {
    ProtectedRoute: () =>
      createElement('div', { 'data-testid': 'protected' }, createElement(Outlet)),
  };
});
vi.mock('../src/components/layout/PublicOnlyRoute', async () => {
  const { Outlet } = await import('react-router-dom');
  return {
    PublicOnlyRoute: () =>
      createElement('div', { 'data-testid': 'public-only' }, createElement(Outlet)),
  };
});
vi.mock('../src/components/layout/AppLayout', async () => {
  const { Outlet } = await import('react-router-dom');
  return {
    AppLayout: () => createElement('div', { 'data-testid': 'app-layout' }, createElement(Outlet)),
  };
});

function pageStub(name: string) {
  return { default: () => createElement('div', { 'data-testid': `page-${name}` }, name) };
}

vi.mock('../src/pages/LoginPage', () => pageStub('login'));
vi.mock('../src/pages/RegisterPage', () => pageStub('register'));
vi.mock('../src/pages/ForgotPasswordPage', () => pageStub('forgot'));
vi.mock('../src/pages/VaultPage', () => pageStub('vault'));
vi.mock('../src/pages/VaultItemPage', () => pageStub('vault-item'));
vi.mock('../src/pages/VaultHealthPage', () => pageStub('vault-health'));
vi.mock('../src/pages/GeneratorPage', () => pageStub('generator'));
vi.mock('../src/pages/FileEncryptionPage', () => pageStub('file-encryption'));
vi.mock('../src/pages/SettingsPage', () => pageStub('settings'));
vi.mock('../src/pages/BackupSettingsPage', () => pageStub('backup'));
vi.mock('../src/pages/SessionsPage', () => pageStub('sessions'));
vi.mock('../src/pages/AuditLogPage', () => pageStub('audit'));
vi.mock('../src/pages/VerifyEmailPage', () => pageStub('verify-email'));
vi.mock('../src/pages/ResetPasswordPage', () => pageStub('reset-password'));
vi.mock('../src/pages/UnlockAccountPage', () => pageStub('unlock-account'));
vi.mock('../src/pages/NotFoundPage', () => pageStub('not-found'));

async function renderAppAt(path: string): Promise<void> {
  window.history.pushState({}, '', path);
  const { App } = await import('../src/App');
  render(createElement(App));
}

describe('App route table', () => {
  afterEach(() => {
    window.history.pushState({}, '', '/');
  });

  it.each([
    ['/vault', 'page-vault'],
    ['/vault/health', 'page-vault-health'],
    ['/vault/abc123', 'page-vault-item'],
    ['/generator', 'page-generator'],
    ['/tools/file-encryption', 'page-file-encryption'],
    ['/settings', 'page-settings'],
    ['/settings/backup', 'page-backup'],
    ['/settings/sessions', 'page-sessions'],
    ['/settings/audit', 'page-audit'],
  ])('renders %s behind ProtectedRoute + AppLayout', async (path, testId) => {
    await renderAppAt(path);

    expect(await screen.findByTestId(testId)).toBeInTheDocument();
    expect(screen.getByTestId('protected')).toBeInTheDocument();
    expect(screen.getByTestId('app-layout')).toBeInTheDocument();
    expect(screen.queryByTestId('public-only')).not.toBeInTheDocument();
  });

  it.each([
    ['/login', 'page-login'],
    ['/register', 'page-register'],
    ['/forgot-password', 'page-forgot'],
  ])('renders %s behind PublicOnlyRoute (never the protected shell)', async (path, testId) => {
    await renderAppAt(path);

    expect(await screen.findByTestId(testId)).toBeInTheDocument();
    expect(screen.getByTestId('public-only')).toBeInTheDocument();
    expect(screen.queryByTestId('protected')).not.toBeInTheDocument();
    expect(screen.queryByTestId('app-layout')).not.toBeInTheDocument();
  });

  it.each([
    ['/verify-email', 'page-verify-email'],
    ['/reset-password', 'page-reset-password'],
    ['/unlock-account', 'page-unlock-account'],
  ])('renders the token-link route %s with no auth wrapper at all', async (path, testId) => {
    await renderAppAt(path);

    expect(await screen.findByTestId(testId)).toBeInTheDocument();
    expect(screen.queryByTestId('protected')).not.toBeInTheDocument();
    expect(screen.queryByTestId('public-only')).not.toBeInTheDocument();
  });

  it('redirects "/" to the vault', async () => {
    await renderAppAt('/');

    expect(await screen.findByTestId('page-vault')).toBeInTheDocument();
    expect(window.location.pathname).toBe('/vault');
  });

  it('renders the NotFound page for an unknown path', async () => {
    await renderAppAt('/does-not-exist');

    expect(await screen.findByTestId('page-not-found')).toBeInTheDocument();
    expect(screen.queryByTestId('app-layout')).not.toBeInTheDocument();
  });

  it('always mounts the ReloadPrompt (PWA update surface) outside the router', async () => {
    await renderAppAt('/login');

    expect(await screen.findByTestId('reload-prompt')).toBeInTheDocument();
  });
});
