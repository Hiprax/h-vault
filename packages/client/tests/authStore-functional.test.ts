/**
 * Functional tests for authStore actions: register, login, verify2fa, unlock.
 *
 * These tests exercise the actual store actions (not just state shape) by
 * calling the action methods and verifying the resulting state transitions
 * and mock call sequences.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Polyfill matchMedia -- jsdom does not implement it but the uiStore module
// references it at the top level when first imported.
// ---------------------------------------------------------------------------

vi.hoisted(() => {
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
});

// ---------------------------------------------------------------------------
// Mocks -- must be declared before importing the stores
// ---------------------------------------------------------------------------

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
}));

vi.mock('../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn(),
    getAuthHash: vi.fn().mockReturnValue('mock-auth-hash'),
    generateVaultKey: vi.fn(),
    importVaultKey: vi.fn(),
    encryptVaultKey: vi.fn(),
    decryptVaultKey: vi.fn(),
    encryptData: vi.fn(),
    decryptData: vi.fn(),
    generateSearchHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/api/authApi', () => ({
  registerApi: vi.fn(),
  loginApi: vi.fn(),
  login2faApi: vi.fn(),
  logoutApi: vi.fn(),
  lockApi: vi.fn().mockResolvedValue({ data: { success: true } }),
}));

vi.mock('../src/services/api/vaultApi', () => ({
  listItemsApi: vi.fn(),
  createItemApi: vi.fn(),
  updateItemApi: vi.fn(),
  deleteItemApi: vi.fn(),
  permanentDeleteApi: vi.fn(),
  emptyTrashApi: vi.fn(),
  restoreItemApi: vi.fn(),
  listFoldersApi: vi.fn(),
  createFolderApi: vi.fn(),
  updateFolderApi: vi.fn(),
  deleteFolderApi: vi.fn(),
  listTrashApi: vi.fn(),
}));

vi.mock('../src/services/offlineCache', () => ({
  offlineCache: {
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
}));

const mockLoggerWarn = vi.fn();
vi.mock('../src/lib/logger', () => ({
  logger: {
    error: vi.fn(),
    warn: (...args: unknown[]) => mockLoggerWarn(...args),
    info: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock('../src/hooks/useUserSettings', () => ({
  clearSettingsCache: vi.fn(),
}));

vi.mock('@hvault/shared', async () => {
  const actual = await vi.importActual<Record<string, unknown>>('@hvault/shared');
  return {
    ...actual,
    KDF_ITERATIONS: 600_000,
    KDF_ALGORITHM: 'PBKDF2',
    ENCRYPTION_VERSION: 1,
  };
});

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import { useAuthStore } from '../src/stores/authStore.js';
import { cryptoService } from '../src/services/crypto/cryptoService.js';
import {
  registerApi,
  loginApi,
  login2faApi,
  lockApi,
  logoutApi,
} from '../src/services/api/authApi.js';
import { offlineCache } from '../src/services/offlineCache.js';
import { markClipboardDirty, markClipboardClean } from '../src/hooks/useClipboardGuard.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const mockMek = {} as CryptoKey;
const mockAuthKey = new ArrayBuffer(32);
const mockVaultKeyBuffer = new ArrayBuffer(32);
const mockVaultKeyCK = {} as CryptoKey;

const authInitialState = {
  accessToken: null,
  user: null,
  isAuthenticated: false,
  isLocked: false,
  vaultKey: null,
  mek: null,
  encryptedVaultKeyData: null,
  kdfIterations: 600_000,
  twoFactorRequired: false,
  tempToken: null,
  _2faTimeoutId: null,
  isLoading: false,
};

/** Build a valid JWT-like string with a given `sub` claim. */
function buildMockJwt(sub: string): string {
  const header = btoa(JSON.stringify({ alg: 'HS256' }));
  const payload = btoa(JSON.stringify({ sub }));
  return `${header}.${payload}.mock-signature`;
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
  useAuthStore.setState({ ...authInitialState });

  // Default mock implementations
  vi.mocked(cryptoService.deriveKeys).mockResolvedValue({
    masterEncryptionKey: mockMek,
    authKey: mockAuthKey,
  });
  vi.mocked(cryptoService.generateVaultKey).mockReturnValue(mockVaultKeyBuffer);
  vi.mocked(cryptoService.importVaultKey).mockResolvedValue(mockVaultKeyCK);
  vi.mocked(cryptoService.encryptVaultKey).mockResolvedValue({
    encrypted: 'encrypted-vk',
    iv: 'vk-iv',
    tag: 'vk-tag',
  });
  vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(new ArrayBuffer(32));
});

// ===========================================================================
// register
// ===========================================================================

describe('authStore.register', () => {
  it('should derive keys, generate vault key, encrypt it, and call registerApi', async () => {
    vi.mocked(registerApi).mockResolvedValue({
      data: { success: true, data: { emailSent: true } },
    } as never);

    const result = await useAuthStore.getState().register('user@example.com', 'Master123!');

    // Should return emailSent status
    expect(result).toEqual({ emailSent: true });

    // deriveKeys called with password and email
    expect(cryptoService.deriveKeys).toHaveBeenCalledWith('Master123!', 'user@example.com');

    // getAuthHash called with the authKey
    expect(cryptoService.getAuthHash).toHaveBeenCalledWith(mockAuthKey);

    // generateVaultKey called
    expect(cryptoService.generateVaultKey).toHaveBeenCalled();

    // importVaultKey called with generated raw vault key
    expect(cryptoService.importVaultKey).toHaveBeenCalledWith(mockVaultKeyBuffer);
    // Raw vault key cleared after import
    expect(cryptoService.clearKey).toHaveBeenCalledWith(mockVaultKeyBuffer);
    // encryptVaultKey called with imported CryptoKey and MEK
    expect(cryptoService.encryptVaultKey).toHaveBeenCalledWith(mockVaultKeyCK, mockMek);

    // registerApi called with full payload
    expect(registerApi).toHaveBeenCalledWith({
      email: 'user@example.com',
      authHash: 'mock-auth-hash',
      encryptedVaultKey: 'encrypted-vk',
      vaultKeyIv: 'vk-iv',
      vaultKeyTag: 'vk-tag',
      kdfIterations: 600_000,
      kdfAlgorithm: 'PBKDF2',
      encryptionVersion: 1,
    });
  });

  it('should return emailSent: false when server reports email failure', async () => {
    vi.mocked(registerApi).mockResolvedValue({
      data: { success: true, data: { emailSent: false } },
    } as never);

    const result = await useAuthStore.getState().register('user@example.com', 'Master123!');
    expect(result).toEqual({ emailSent: false });
  });

  it('should clear vault key and auth key after successful registration', async () => {
    vi.mocked(registerApi).mockResolvedValue({
      data: { success: true, data: { emailSent: true } },
    } as never);

    await useAuthStore.getState().register('user@example.com', 'Master123!');

    // clearKey should have been called for raw vaultKey and authKey
    expect(cryptoService.clearKey).toHaveBeenCalledWith(mockVaultKeyBuffer);
    expect(cryptoService.clearKey).toHaveBeenCalledWith(mockAuthKey);
    // clearCryptoKey should have been called for imported vault CryptoKey and MEK
    expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(mockVaultKeyCK);
    expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(mockMek);
  });

  it('should NOT set authenticated state after registration', async () => {
    vi.mocked(registerApi).mockResolvedValue({
      data: { success: true, data: { emailSent: true } },
    } as never);

    await useAuthStore.getState().register('user@example.com', 'Master123!');

    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.user).toBeNull();
    expect(state.accessToken).toBeNull();
    expect(state.vaultKey).toBeNull();
    expect(state.mek).toBeNull();
  });

  it('should propagate errors from deriveKeys', async () => {
    vi.mocked(cryptoService.deriveKeys).mockRejectedValue(new Error('Derive failed'));

    await expect(
      useAuthStore.getState().register('user@example.com', 'Master123!'),
    ).rejects.toThrow('Derive failed');

    // registerApi should NOT have been called
    expect(registerApi).not.toHaveBeenCalled();
  });

  it('should propagate errors from registerApi', async () => {
    vi.mocked(registerApi).mockRejectedValue(new Error('Network error'));

    await expect(
      useAuthStore.getState().register('user@example.com', 'Master123!'),
    ).rejects.toThrow('Network error');
  });

  it('should propagate errors from encryptVaultKey', async () => {
    vi.mocked(cryptoService.encryptVaultKey).mockRejectedValue(new Error('Encrypt failed'));

    await expect(
      useAuthStore.getState().register('user@example.com', 'Master123!'),
    ).rejects.toThrow('Encrypt failed');

    expect(registerApi).not.toHaveBeenCalled();
  });
});

// ===========================================================================
// login
// ===========================================================================

describe('authStore.login', () => {
  const mockAccessToken = buildMockJwt('user-123');

  const mockLoginResponse = {
    data: {
      success: true,
      data: {
        accessToken: mockAccessToken,
        encryptedVaultKey: 'enc-vk',
        vaultKeyIv: 'vk-iv',
        vaultKeyTag: 'vk-tag',
        kdfIterations: 600_000,
        kdfAlgorithm: 'PBKDF2-SHA256',
      },
    },
  };

  it('should derive keys, call loginApi, decrypt vault key, and set authenticated state', async () => {
    vi.mocked(loginApi).mockResolvedValue(mockLoginResponse as never);
    const decryptedVaultKey = new ArrayBuffer(32);
    vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(decryptedVaultKey);

    await useAuthStore.getState().login('user@example.com', 'Master123!');

    // Verify key derivation
    expect(cryptoService.deriveKeys).toHaveBeenCalledWith('Master123!', 'user@example.com');
    expect(cryptoService.getAuthHash).toHaveBeenCalledWith(mockAuthKey);

    // Auth key should be cleared after getting the hash
    expect(cryptoService.clearKey).toHaveBeenCalledWith(mockAuthKey);

    // loginApi called with correct payload (fingerprint is a 16-char hex hash)
    expect(loginApi).toHaveBeenCalledWith({
      email: 'user@example.com',
      authHash: 'mock-auth-hash',
      deviceInfo: {
        userAgent: navigator.userAgent,
        fingerprint: expect.stringMatching(/^[0-9a-f]{16}$/) as string,
      },
    });

    // Vault key decryption and import
    expect(cryptoService.decryptVaultKey).toHaveBeenCalledWith(
      'enc-vk',
      'vk-iv',
      'vk-tag',
      mockMek,
    );
    expect(cryptoService.importVaultKey).toHaveBeenCalledWith(decryptedVaultKey);
    expect(cryptoService.clearKey).toHaveBeenCalledWith(decryptedVaultKey);

    // Verify final state — vaultKey is the imported CryptoKey, not the raw ArrayBuffer
    const state = useAuthStore.getState();
    expect(state.accessToken).toBe(mockAccessToken);
    expect(state.user).toEqual({ userId: 'user-123', email: 'user@example.com' });
    expect(state.isAuthenticated).toBe(true);
    expect(state.isLocked).toBe(false);
    expect(state.vaultKey).toBe(mockVaultKeyCK);
    expect(state.mek).toBe(mockMek);
    expect(state.encryptedVaultKeyData).toEqual({
      encrypted: 'enc-vk',
      iv: 'vk-iv',
      tag: 'vk-tag',
    });
    expect(state.kdfIterations).toBe(600_000);
    expect(state.twoFactorRequired).toBe(false);
    expect(state.tempToken).toBeNull();
    expect(state.isLoading).toBe(false);
  });

  it('should handle 2FA required flow', async () => {
    const mock2faResponse = {
      data: {
        success: true,
        data: {
          twoFactorRequired: true,
          tempToken: 'temp-token-123',
        },
      },
    };
    vi.mocked(loginApi).mockResolvedValue(mock2faResponse as never);

    await useAuthStore.getState().login('user@example.com', 'Master123!');

    const state = useAuthStore.getState();
    expect(state.twoFactorRequired).toBe(true);
    expect(state.tempToken).toBe('temp-token-123');
    expect(state.mek).toBe(mockMek);
    expect(state.isLoading).toBe(false);

    // Should store email for the 2FA verification flow
    expect(state.user).toEqual({ userId: '', email: 'user@example.com' });

    // Should NOT set authenticated state
    expect(state.isAuthenticated).toBe(false);
    expect(state.accessToken).toBeNull();
    expect(state.vaultKey).toBeNull();

    // decryptVaultKey should NOT have been called (no vault key data yet)
    expect(cryptoService.decryptVaultKey).not.toHaveBeenCalled();
  });

  it('should prevent concurrent login calls via isLoading guard', async () => {
    // Set isLoading to true to simulate an in-progress login
    useAuthStore.setState({ isLoading: true });

    vi.mocked(loginApi).mockResolvedValue(mockLoginResponse as never);

    await useAuthStore.getState().login('user@example.com', 'Master123!');

    // deriveKeys should NOT have been called because the guard returned early
    expect(cryptoService.deriveKeys).not.toHaveBeenCalled();
    expect(loginApi).not.toHaveBeenCalled();
  });

  it('should clear isLoading on error', async () => {
    vi.mocked(loginApi).mockRejectedValue(new Error('Login failed'));

    await expect(useAuthStore.getState().login('user@example.com', 'Master123!')).rejects.toThrow(
      'Login failed',
    );

    expect(useAuthStore.getState().isLoading).toBe(false);
  });

  it('should clear isLoading on deriveKeys error', async () => {
    vi.mocked(cryptoService.deriveKeys).mockRejectedValue(new Error('Derive failed'));

    await expect(useAuthStore.getState().login('user@example.com', 'Master123!')).rejects.toThrow(
      'Derive failed',
    );

    expect(useAuthStore.getState().isLoading).toBe(false);
    expect(loginApi).not.toHaveBeenCalled();
  });

  it('should clear isLoading on decryptVaultKey error', async () => {
    vi.mocked(loginApi).mockResolvedValue(mockLoginResponse as never);
    vi.mocked(cryptoService.decryptVaultKey).mockRejectedValue(new Error('Decrypt failed'));

    await expect(useAuthStore.getState().login('user@example.com', 'Master123!')).rejects.toThrow(
      'Decrypt failed',
    );

    expect(useAuthStore.getState().isLoading).toBe(false);
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });

  it('should parse userId from JWT sub claim', async () => {
    const customToken = buildMockJwt('custom-user-456');
    const responseWithCustomToken = {
      data: {
        success: true,
        data: {
          ...mockLoginResponse.data.data,
          accessToken: customToken,
        },
      },
    };
    vi.mocked(loginApi).mockResolvedValue(responseWithCustomToken as never);

    await useAuthStore.getState().login('test@example.com', 'Password1!');

    expect(useAuthStore.getState().user?.userId).toBe('custom-user-456');
    expect(useAuthStore.getState().user?.email).toBe('test@example.com');
  });

  it('should store the 2FA MEK cleanup timeout ID when 2FA is required', async () => {
    const mock2faResponse = {
      data: {
        success: true,
        data: {
          twoFactorRequired: true,
          tempToken: 'temp-token-123',
        },
      },
    };
    vi.mocked(loginApi).mockResolvedValue(mock2faResponse as never);

    await useAuthStore.getState().login('user@example.com', 'Master123!');

    const state = useAuthStore.getState();
    expect(state._2faTimeoutId).not.toBeNull();
  });

  it('should set isLoading to true during execution', async () => {
    let loadingDuringExecution = false;

    vi.mocked(loginApi).mockImplementation(async () => {
      // Check isLoading state during API call
      loadingDuringExecution = useAuthStore.getState().isLoading;
      return mockLoginResponse as never;
    });

    await useAuthStore.getState().login('user@example.com', 'Master123!');

    expect(loadingDuringExecution).toBe(true);
    expect(useAuthStore.getState().isLoading).toBe(false);
  });
});

// ===========================================================================
// verify2fa
// ===========================================================================

describe('authStore.verify2fa', () => {
  const mockAccessToken = buildMockJwt('user-2fa-789');

  const mock2faSuccessResponse = {
    data: {
      success: true,
      data: {
        accessToken: mockAccessToken,
        encryptedVaultKey: 'enc-vk-2fa',
        vaultKeyIv: 'vk-iv-2fa',
        vaultKeyTag: 'vk-tag-2fa',
        kdfIterations: 600_000,
        kdfAlgorithm: 'PBKDF2-SHA256',
      },
    },
  };

  beforeEach(() => {
    // Simulate the state after login returned a 2FA-required response:
    // tempToken and mek are set, but user is not authenticated.
    useAuthStore.setState({
      ...authInitialState,
      twoFactorRequired: true,
      tempToken: 'temp-token-123',
      mek: mockMek,
      user: { userId: '', email: 'user@example.com' },
    });
  });

  it('should call login2faApi and set authenticated state on success', async () => {
    vi.mocked(login2faApi).mockResolvedValue(mock2faSuccessResponse as never);
    const decryptedVaultKey = new ArrayBuffer(32);
    vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(decryptedVaultKey);

    await useAuthStore.getState().verify2fa('123456');

    // login2faApi called with correct payload (fingerprint is a 16-char hex hash)
    expect(login2faApi).toHaveBeenCalledWith({
      tempToken: 'temp-token-123',
      code: '123456',
      deviceInfo: {
        userAgent: navigator.userAgent,
        fingerprint: expect.stringMatching(/^[0-9a-f]{16}$/) as string,
      },
    });

    // Vault key decryption
    expect(cryptoService.decryptVaultKey).toHaveBeenCalledWith(
      'enc-vk-2fa',
      'vk-iv-2fa',
      'vk-tag-2fa',
      mockMek,
    );

    // Verify final state
    const state = useAuthStore.getState();
    expect(state.accessToken).toBe(mockAccessToken);
    expect(state.user).toEqual({ userId: 'user-2fa-789', email: 'user@example.com' });
    expect(state.isAuthenticated).toBe(true);
    expect(state.isLocked).toBe(false);
    expect(state.vaultKey).toBe(mockVaultKeyCK);
    expect(state.mek).toBe(mockMek);
    expect(state.encryptedVaultKeyData).toEqual({
      encrypted: 'enc-vk-2fa',
      iv: 'vk-iv-2fa',
      tag: 'vk-tag-2fa',
    });
    expect(state.twoFactorRequired).toBe(false);
    expect(state.tempToken).toBeNull();
    expect(state.isLoading).toBe(false);
  });

  it('should throw if no tempToken is available', async () => {
    useAuthStore.setState({ tempToken: null });

    await expect(useAuthStore.getState().verify2fa('123456')).rejects.toThrow(
      'No pending 2FA session',
    );

    expect(login2faApi).not.toHaveBeenCalled();
    expect(useAuthStore.getState().isLoading).toBe(false);
  });

  it('should throw if no mek is available', async () => {
    useAuthStore.setState({ mek: null });

    await expect(useAuthStore.getState().verify2fa('123456')).rejects.toThrow(
      'Master encryption key is not available',
    );

    expect(login2faApi).not.toHaveBeenCalled();
    expect(useAuthStore.getState().isLoading).toBe(false);
  });

  it('should prevent concurrent 2FA verification calls via isLoading guard', async () => {
    useAuthStore.setState({ isLoading: true });

    await useAuthStore.getState().verify2fa('123456');

    // login2faApi should NOT have been called
    expect(login2faApi).not.toHaveBeenCalled();
  });

  it('should clear isLoading on login2faApi error', async () => {
    vi.mocked(login2faApi).mockRejectedValue(new Error('Invalid TOTP'));

    await expect(useAuthStore.getState().verify2fa('000000')).rejects.toThrow('Invalid TOTP');

    expect(useAuthStore.getState().isLoading).toBe(false);
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });

  it('should clear isLoading on decryptVaultKey error', async () => {
    vi.mocked(login2faApi).mockResolvedValue(mock2faSuccessResponse as never);
    vi.mocked(cryptoService.decryptVaultKey).mockRejectedValue(new Error('Decrypt error'));

    await expect(useAuthStore.getState().verify2fa('123456')).rejects.toThrow('Decrypt error');

    expect(useAuthStore.getState().isLoading).toBe(false);
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });

  it('should use the user email from state when setting authenticated user', async () => {
    useAuthStore.setState({
      user: { userId: '', email: 'specific-user@example.com' },
    });
    vi.mocked(login2faApi).mockResolvedValue(mock2faSuccessResponse as never);

    await useAuthStore.getState().verify2fa('123456');

    expect(useAuthStore.getState().user?.email).toBe('specific-user@example.com');
    expect(useAuthStore.getState().user?.userId).toBe('user-2fa-789');
  });

  it('should handle missing user in state gracefully (empty email)', async () => {
    useAuthStore.setState({ user: null });
    vi.mocked(login2faApi).mockResolvedValue(mock2faSuccessResponse as never);

    await useAuthStore.getState().verify2fa('123456');

    // When user is null, email defaults to empty string via user?.email ?? ''
    expect(useAuthStore.getState().user?.email).toBe('');
    expect(useAuthStore.getState().isAuthenticated).toBe(true);
  });

  it('should cancel the 2FA MEK cleanup timeout on successful verification', async () => {
    vi.mocked(login2faApi).mockResolvedValue(mock2faSuccessResponse as never);

    // Simulate a pending 2FA timeout (as set by the login action)
    const mockTimeoutId = setTimeout(() => {}, 300_000);
    useAuthStore.setState({ _2faTimeoutId: mockTimeoutId });

    const clearTimeoutSpy = vi.spyOn(globalThis, 'clearTimeout');

    await useAuthStore.getState().verify2fa('123456');

    expect(clearTimeoutSpy).toHaveBeenCalledWith(mockTimeoutId);
    expect(useAuthStore.getState()._2faTimeoutId).toBeNull();

    clearTimeoutSpy.mockRestore();
    clearTimeout(mockTimeoutId);
  });

  it('should set _2faTimeoutId to null after successful verification', async () => {
    vi.mocked(login2faApi).mockResolvedValue(mock2faSuccessResponse as never);

    useAuthStore.setState({ _2faTimeoutId: setTimeout(() => {}, 300_000) });

    await useAuthStore.getState().verify2fa('123456');

    expect(useAuthStore.getState()._2faTimeoutId).toBeNull();
  });

  it('should clear MEK immediately on non-retryable 2FA failure (TOKEN_EXPIRED)', async () => {
    const { AxiosError } = await import('axios');
    const axiosError = new AxiosError('Token expired', '401', undefined, undefined, {
      status: 401,
      data: { success: false, error: { code: 'TOKEN_EXPIRED', message: 'Token expired' } },
      statusText: 'Unauthorized',
      headers: {},
      config: {} as never,
    });
    vi.mocked(login2faApi).mockRejectedValue(axiosError);

    const mockTimeoutId = setTimeout(() => {}, 300_000);
    useAuthStore.setState({ _2faTimeoutId: mockTimeoutId });

    await expect(useAuthStore.getState().verify2fa('123456')).rejects.toThrow();

    // MEK should be cleared immediately
    expect(useAuthStore.getState().mek).toBeNull();
    expect(useAuthStore.getState().twoFactorRequired).toBe(false);
    expect(useAuthStore.getState().tempToken).toBeNull();
    expect(useAuthStore.getState()._2faTimeoutId).toBeNull();
    expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(mockMek);

    clearTimeout(mockTimeoutId);
  });

  it('should clear MEK immediately on non-retryable 2FA failure (ACCOUNT_LOCKED)', async () => {
    const { AxiosError } = await import('axios');
    const axiosError = new AxiosError('Account locked', '403', undefined, undefined, {
      status: 403,
      data: { success: false, error: { code: 'ACCOUNT_LOCKED', message: 'Account locked' } },
      statusText: 'Forbidden',
      headers: {},
      config: {} as never,
    });
    vi.mocked(login2faApi).mockRejectedValue(axiosError);

    await expect(useAuthStore.getState().verify2fa('123456')).rejects.toThrow();

    expect(useAuthStore.getState().mek).toBeNull();
    expect(useAuthStore.getState().twoFactorRequired).toBe(false);
  });

  it('should NOT clear MEK on retryable 2FA failure (TWO_FA_INVALID)', async () => {
    const { AxiosError } = await import('axios');
    const axiosError = new AxiosError('Invalid code', '401', undefined, undefined, {
      status: 401,
      data: { success: false, error: { code: 'TWO_FA_INVALID', message: 'Invalid code' } },
      statusText: 'Unauthorized',
      headers: {},
      config: {} as never,
    });
    vi.mocked(login2faApi).mockRejectedValue(axiosError);

    await expect(useAuthStore.getState().verify2fa('123456')).rejects.toThrow();

    // MEK should still be available for retry
    expect(useAuthStore.getState().mek).toBe(mockMek);
    expect(useAuthStore.getState().isLoading).toBe(false);
  });

  it('should clear MEK and cancel the timer when post-verification crypto fails (non-Axios)', async () => {
    // Drive login() into the 2FA-required branch so a REAL abandon-cleanup
    // timer is scheduled and MEK is stored (mirrors production).
    vi.mocked(loginApi).mockResolvedValue({
      data: { success: true, data: { twoFactorRequired: true, tempToken: 'temp-token-123' } },
    } as never);
    await useAuthStore.getState().login('user@example.com', 'Master123!');
    expect(useAuthStore.getState()._2faTimeoutId).not.toBeNull();
    expect(useAuthStore.getState().mek).toBe(mockMek);

    // Server accepts the code, but the post-verification vault-key decrypt
    // throws a plain (non-Axios) Error — e.g. AES-GCM tag mismatch.
    vi.mocked(login2faApi).mockResolvedValue(mock2faSuccessResponse as never);
    vi.mocked(cryptoService.decryptVaultKey).mockRejectedValue(
      new Error('Failed to decrypt vault key.'),
    );

    await expect(useAuthStore.getState().verify2fa('123456')).rejects.toThrow(
      'Failed to decrypt vault key.',
    );

    // MEK must not linger with the reaper already gone.
    const state = useAuthStore.getState();
    expect(state.mek).toBeNull();
    expect(state._2faTimeoutId).toBeNull();
    expect(state.twoFactorRequired).toBe(false);
    expect(state.tempToken).toBeNull();
    expect(state.isLoading).toBe(false);
    expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(mockMek);
  });

  it('should clear MEK when the access-token JWT is malformed (non-Axios parse error)', async () => {
    vi.mocked(loginApi).mockResolvedValue({
      data: { success: true, data: { twoFactorRequired: true, tempToken: 'temp-token-123' } },
    } as never);
    await useAuthStore.getState().login('user@example.com', 'Master123!');

    // Decrypt succeeds, but the returned access token has no payload segment,
    // so parseAccessTokenUserId throws a plain Error.
    vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(new ArrayBuffer(32));
    vi.mocked(login2faApi).mockResolvedValue({
      data: {
        success: true,
        data: { ...mock2faSuccessResponse.data.data, accessToken: 'not-a-jwt' },
      },
    } as never);

    await expect(useAuthStore.getState().verify2fa('123456')).rejects.toThrow();

    const state = useAuthStore.getState();
    expect(state.mek).toBeNull();
    expect(state._2faTimeoutId).toBeNull();
    expect(state.isAuthenticated).toBe(false);
    expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(mockMek);
  });
});

// ===========================================================================
// unlock
// ===========================================================================

describe('authStore.unlock', () => {
  const encryptedVaultKeyData = {
    encrypted: 'enc-vk-stored',
    iv: 'vk-iv-stored',
    tag: 'vk-tag-stored',
  };

  beforeEach(() => {
    // Simulate locked state after a session reload:
    // user and encryptedVaultKeyData are persisted, but vaultKey and mek are gone.
    useAuthStore.setState({
      ...authInitialState,
      user: { userId: 'user-123', email: 'user@example.com' },
      isAuthenticated: true,
      isLocked: true,
      encryptedVaultKeyData,
    });
  });

  it('should derive keys from stored email and decrypt vault key', async () => {
    const decryptedVaultKey = new ArrayBuffer(32);
    vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(decryptedVaultKey);

    await useAuthStore.getState().unlock('Master123!');

    // deriveKeys called with the master password and the stored user email
    expect(cryptoService.deriveKeys).toHaveBeenCalledWith('Master123!', 'user@example.com');

    // Auth key should be cleared immediately after derivation
    expect(cryptoService.clearKey).toHaveBeenCalledWith(mockAuthKey);

    // decryptVaultKey called with stored encrypted data and derived MEK
    expect(cryptoService.decryptVaultKey).toHaveBeenCalledWith(
      'enc-vk-stored',
      'vk-iv-stored',
      'vk-tag-stored',
      mockMek,
    );
  });

  it('should set vaultKey and mek but NOT change isLocked', async () => {
    const decryptedVaultKey = new ArrayBuffer(32);
    vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(decryptedVaultKey);

    await useAuthStore.getState().unlock('Master123!');

    const state = useAuthStore.getState();
    expect(state.vaultKey).toBe(mockVaultKeyCK);
    expect(state.mek).toBe(mockMek);

    // isLocked should remain true -- ProtectedRoute handles clearing it
    // after the access token has been refreshed.
    expect(state.isLocked).toBe(true);
  });

  it('should throw if user email is not available', async () => {
    useAuthStore.setState({ user: null });

    await expect(useAuthStore.getState().unlock('Master123!')).rejects.toThrow(
      'Cannot unlock: user email is not available',
    );

    expect(cryptoService.deriveKeys).not.toHaveBeenCalled();
  });

  it('should throw if user exists but email is empty', async () => {
    useAuthStore.setState({ user: { userId: 'user-123', email: '' } });

    await expect(useAuthStore.getState().unlock('Master123!')).rejects.toThrow(
      'Cannot unlock: user email is not available',
    );

    expect(cryptoService.deriveKeys).not.toHaveBeenCalled();
  });

  it('should throw if encryptedVaultKeyData is not available', async () => {
    useAuthStore.setState({ encryptedVaultKeyData: null });

    await expect(useAuthStore.getState().unlock('Master123!')).rejects.toThrow(
      'Cannot unlock: encrypted vault key data is not available',
    );

    expect(cryptoService.deriveKeys).not.toHaveBeenCalled();
  });

  it('should propagate decryptVaultKey errors (e.g., wrong password)', async () => {
    vi.mocked(cryptoService.decryptVaultKey).mockRejectedValue(
      new Error('Decryption failed: invalid key'),
    );

    await expect(useAuthStore.getState().unlock('WrongPassword!')).rejects.toThrow(
      'Decryption failed: invalid key',
    );
  });

  it('should propagate deriveKeys errors', async () => {
    vi.mocked(cryptoService.deriveKeys).mockRejectedValue(new Error('Key derivation error'));

    await expect(useAuthStore.getState().unlock('Master123!')).rejects.toThrow(
      'Key derivation error',
    );

    expect(cryptoService.decryptVaultKey).not.toHaveBeenCalled();
  });

  it('should not modify other state fields', async () => {
    const decryptedVaultKey = new ArrayBuffer(32);
    vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(decryptedVaultKey);

    await useAuthStore.getState().unlock('Master123!');

    const state = useAuthStore.getState();
    // These should remain from the pre-unlock state
    expect(state.user).toEqual({ userId: 'user-123', email: 'user@example.com' });
    expect(state.isAuthenticated).toBe(true);
    expect(state.accessToken).toBeNull();
    expect(state.encryptedVaultKeyData).toEqual(encryptedVaultKeyData);
    expect(state.twoFactorRequired).toBe(false);
    expect(state.tempToken).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// L29: Swallowed catch blocks log in dev mode
// ---------------------------------------------------------------------------

describe('L29 — swallowed catch blocks log warnings in dev mode', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useAuthStore.setState(authInitialState);
  });

  it('logs a warning when offlineCache.clear fails during lock', async () => {
    const cacheError = new Error('IndexedDB error');
    vi.mocked(offlineCache.clear).mockRejectedValueOnce(cacheError);

    useAuthStore.setState({
      isAuthenticated: true,
      isLocked: false,
      vaultKey: {} as CryptoKey,
      mek: {} as CryptoKey,
    });

    await useAuthStore.getState().lock();

    expect(mockLoggerWarn).toHaveBeenCalledWith(
      'Failed to clear offline cache during lock',
      cacheError,
    );
    // Lock should still succeed
    expect(useAuthStore.getState().isLocked).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// T24: lock() / logout() wipe the OS clipboard when a secret was copied.
// useClipboardGuard's visibility/pagehide listeners never fire while the lock
// screen is shown in a still-visible tab, so the store must wipe imperatively.
// ---------------------------------------------------------------------------

describe('T24 — clipboard is wiped on lock / logout', () => {
  const writeText = vi.fn().mockResolvedValue(undefined);

  beforeEach(() => {
    vi.clearAllMocks();
    useAuthStore.setState({ ...authInitialState });
    markClipboardClean();
    writeText.mockClear();
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      writable: true,
      configurable: true,
    });
  });

  it('lock() clears the clipboard when sensitive data was copied', async () => {
    markClipboardDirty();
    useAuthStore.setState({
      isAuthenticated: true,
      isLocked: false,
      vaultKey: {} as CryptoKey,
      mek: {} as CryptoKey,
    });

    await useAuthStore.getState().lock();

    expect(writeText).toHaveBeenCalledWith('');
    expect(useAuthStore.getState().isLocked).toBe(true);
  });

  it('lock() does NOT touch the clipboard when nothing was copied', async () => {
    // clipboard left clean
    useAuthStore.setState({
      isAuthenticated: true,
      isLocked: false,
      vaultKey: {} as CryptoKey,
      mek: {} as CryptoKey,
    });

    await useAuthStore.getState().lock();

    expect(writeText).not.toHaveBeenCalled();
  });

  it('logout() clears the clipboard when sensitive data was copied', async () => {
    markClipboardDirty();
    useAuthStore.setState({
      isAuthenticated: true,
      isLocked: false,
      vaultKey: {} as CryptoKey,
      mek: {} as CryptoKey,
    });

    await useAuthStore.getState().logout();

    expect(writeText).toHaveBeenCalledWith('');
  });
});

// ---------------------------------------------------------------------------
// Phase 5.2: bounded timeout + secure-first ordering for lock() / logout().
// A stalled/black-holed lock or logout network call must NOT leave the vault
// unlocked with resident key material.
// ---------------------------------------------------------------------------

describe('Phase 5.2 — lock/logout secure state before the network call', () => {
  const writeText = vi.fn().mockResolvedValue(undefined);

  beforeEach(() => {
    vi.clearAllMocks();
    useAuthStore.setState({ ...authInitialState });
    markClipboardClean();
    writeText.mockClear();
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      writable: true,
      configurable: true,
    });
    // Restore the default resolving lock/logout mocks (cleared above).
    vi.mocked(lockApi).mockResolvedValue({ data: { success: true } } as never);
    vi.mocked(logoutApi).mockResolvedValue(undefined as never);
  });

  it('lock() secures local state even when lockApi never resolves', async () => {
    // A stalled network call: lockApi hangs forever.
    vi.mocked(lockApi).mockReturnValue(new Promise<never>(() => {}) as never);
    markClipboardDirty();

    useAuthStore.setState({
      accessToken: 'access-token',
      isAuthenticated: true,
      isLocked: false,
      vaultKey: {} as CryptoKey,
      mek: {} as CryptoKey,
    });

    // lock() resolves without awaiting the hung network call.
    await useAuthStore.getState().lock();

    const state = useAuthStore.getState();
    expect(state.isLocked).toBe(true);
    expect(state.vaultKey).toBeNull();
    expect(state.mek).toBeNull();
    // Clipboard wiped, key material zeroed, offline cache cleared.
    expect(writeText).toHaveBeenCalledWith('');
    expect(cryptoService.clearCryptoKey).toHaveBeenCalledTimes(2);
    expect(offlineCache.clear).toHaveBeenCalled();
  });

  it('lock() fires lockApi best-effort with a bounded per-call timeout', async () => {
    useAuthStore.setState({
      accessToken: 'access-token',
      isAuthenticated: true,
      isLocked: false,
      vaultKey: {} as CryptoKey,
      mek: {} as CryptoKey,
    });

    await useAuthStore.getState().lock();

    // Called with the bounded 5s timeout (not zero/undefined).
    expect(lockApi).toHaveBeenCalledWith(5000);
  });

  it('lock() does NOT call lockApi when there is no access token', async () => {
    useAuthStore.setState({
      accessToken: null,
      isAuthenticated: true,
      isLocked: false,
      vaultKey: {} as CryptoKey,
      mek: {} as CryptoKey,
    });

    await useAuthStore.getState().lock();

    expect(lockApi).not.toHaveBeenCalled();
    expect(useAuthStore.getState().isLocked).toBe(true);
  });

  it('logout() passes a bounded per-call timeout to logoutApi', async () => {
    useAuthStore.setState({
      accessToken: 'access-token',
      isAuthenticated: true,
      isLocked: false,
      vaultKey: {} as CryptoKey,
      mek: {} as CryptoKey,
    });

    await useAuthStore.getState().logout();

    expect(logoutApi).toHaveBeenCalledWith(5000);
    expect(useAuthStore.getState().accessToken).toBeNull();
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });

  it('logout() still clears state when logoutApi rejects (timeout/abort)', async () => {
    vi.mocked(logoutApi).mockRejectedValue(new Error('timeout of 5000ms exceeded') as never);

    useAuthStore.setState({
      accessToken: 'access-token',
      isAuthenticated: true,
      isLocked: false,
      vaultKey: {} as CryptoKey,
      mek: {} as CryptoKey,
    });

    await useAuthStore.getState().logout();

    const state = useAuthStore.getState();
    expect(state.accessToken).toBeNull();
    expect(state.isAuthenticated).toBe(false);
    expect(state.vaultKey).toBeNull();
    expect(state.mek).toBeNull();
  });
});
