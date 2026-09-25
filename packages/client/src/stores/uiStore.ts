/**
 * UI Zustand store.
 *
 * Manages theme preference, sidebar visibility, and the command palette.
 * The theme preference is persisted to localStorage. On every theme change,
 * the appropriate CSS class is applied to <html> so Tailwind's `dark:` variant
 * and any other theme selectors work correctly.
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { OfflineCacheErrorType } from '../services/offlineCache';
import { staleVaultKeyVersion } from '../services/api/staleVaultKey';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type ThemeValue = 'light' | 'dark' | 'system';

interface UIState {
  theme: ThemeValue;
  sidebarOpen: boolean;
  sidebarCollapsed: boolean;
  commandPaletteOpen: boolean;
  /**
   * `null` while the offline cache is healthy; otherwise WHY it is not, so the
   * warning can say something the user can act on. A bare boolean was the
   * previous shape and it threw away the only part of the failure that differs
   * between "free some storage" and "your browser is blocking this".
   *
   * ONE slot, written by BOTH of `vaultStore`'s cache writes (items and folders),
   * last write wins. That is deliberate rather than unnoticed: every cause this
   * discriminant carries is a condition of the ORIGIN or of the one database both
   * writes share (quota, blocked site data, no IndexedDB at all, another tab
   * holding it on a different version), and both writes go through one
   * `openDatabase()` against that database, whose stores are created together, so
   * there is no steady state in which one succeeds and the other fails. The
   * reachable cost is a banner that clears one fetch early during a transient
   * failure and returns on the next write; the alternative is two banners for one
   * condition.
   */
  offlineCacheError: OfflineCacheErrorType | null;
  /**
   * The vault-key generation the SERVER last reported when it refused a write
   * from this session, or `null` while no such refusal has been seen.
   *
   * It is the number the server said it is on, never the number this session
   * holds. Whether the session is still stale is DERIVED by comparing the two —
   * see {@link isHoldingSupersededVaultKey} — so nothing has to remember to
   * clear this: a re-login or a rotation driven from this tab moves
   * `authStore.vaultKeyVersion` onto the same number and the notice goes away
   * on its own. A flag would have needed a clear at every one of those points,
   * and the one that got missed would leave a permanent "reload" banner in
   * front of a session that was perfectly healthy.
   *
   * Not persisted (`partialize` keeps theme and sidebar only): a reload is the
   * remedy, so surviving one would be exactly wrong.
   */
  staleVaultKeyVersion: number | null;

  setTheme: (theme: ThemeValue) => void;
  toggleSidebar: () => void;
  toggleSidebarCollapsed: () => void;
  toggleCommandPalette: () => void;
  setOfflineCacheError: (error: OfflineCacheErrorType | null) => void;
  setStaleVaultKeyVersion: (vaultKeyVersion: number | null) => void;
}

// ---------------------------------------------------------------------------
// Theme helpers
// ---------------------------------------------------------------------------

/**
 * Resolve the effective theme (light or dark) taking into account the
 * operating system preference when the user has chosen "system".
 *
 * Exported because the document sandbox needs the RESOLVED value and cannot
 * derive it: it is a separate document with an opaque origin, it is told the
 * theme over a message port, and it must not resolve `'system'` for itself in
 * some way this application would disagree with — a preview that disagreed with
 * the chrome around it would look broken rather than themed.
 */
export function resolveEffectiveTheme(theme: ThemeValue): 'light' | 'dark' {
  if (theme !== 'system') {
    return theme;
  }
  if (typeof window === 'undefined') {
    return 'light';
  }
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

/**
 * Apply the resolved theme to the document root element by toggling the
 * `dark` class and setting a `data-theme` attribute.
 */
function applyThemeToDocument(theme: ThemeValue): void {
  if (typeof document === 'undefined') {
    return;
  }
  const effective = resolveEffectiveTheme(theme);
  const root = document.documentElement;

  if (effective === 'dark') {
    root.classList.add('dark');
  } else {
    root.classList.remove('dark');
  }
  root.setAttribute('data-theme', effective);
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      theme: 'system',
      sidebarOpen: true,
      sidebarCollapsed: false,
      commandPaletteOpen: false,
      offlineCacheError: null,
      staleVaultKeyVersion: null,

      setTheme: (theme: ThemeValue): void => {
        applyThemeToDocument(theme);
        set({ theme });
      },

      toggleSidebar: (): void => {
        set((state) => ({ sidebarOpen: !state.sidebarOpen }));
      },

      toggleSidebarCollapsed: (): void => {
        set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed }));
      },

      toggleCommandPalette: (): void => {
        set((state) => ({ commandPaletteOpen: !state.commandPaletteOpen }));
      },

      setOfflineCacheError: (error: OfflineCacheErrorType | null): void => {
        set({ offlineCacheError: error });
      },

      setStaleVaultKeyVersion: (vaultKeyVersion: number | null): void => {
        set({ staleVaultKeyVersion: vaultKeyVersion });
      },
    }),
    {
      name: 'hvault-ui',
      partialize: (state) => ({
        theme: state.theme,
        sidebarCollapsed: state.sidebarCollapsed,
      }),
      onRehydrateStorage: () => {
        return (state) => {
          // Apply the persisted theme on initial load
          if (state) {
            applyThemeToDocument(state.theme);
          }
        };
      },
    },
  ),
);

// ---------------------------------------------------------------------------
// Listen for OS theme changes when user has selected "system"
// ---------------------------------------------------------------------------

if (typeof window !== 'undefined') {
  const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
  mediaQuery.addEventListener('change', () => {
    const { theme } = useUIStore.getState();
    if (theme === 'system') {
      applyThemeToDocument('system');
    }
  });
}

// ---------------------------------------------------------------------------
// The superseded-vault-key notice
// ---------------------------------------------------------------------------

/**
 * Records a write refused because this session's vault key has been superseded,
 * and reports whether that is what the rejection was.
 *
 * Called from the catch of every write that seals ciphertext under the vault
 * key. The rejection is RE-THROWN by those callers: this only notes the
 * condition for the application chrome, and a caller that swallowed the error
 * would be telling the user their change was saved when it was refused.
 *
 * ## What it must never do
 *
 * It must never adopt the number as this session's own generation, and it must
 * never trigger a re-read of the vault key. This application is built on the
 * premise that the server is untrusted, so a 409 carrying a number is the
 * server ASKING this session to move to a key it did not choose. Everything in
 * memory was decrypted under the current key, and re-deriving mid-session is a
 * decision about the whole session rather than about one save — which is the
 * same reason `documentsStore` uses its one rewrap key for a single completion
 * and throws it away. The remedy offered to the user is therefore a reload,
 * which re-reads everything from a single consistent starting point.
 *
 * Returns `true` when the rejection was this refusal, so a caller can tell it
 * apart from an ordinary failure without parsing the error twice.
 */
export function noteStaleVaultKey(error: unknown): boolean {
  const version = staleVaultKeyVersion(error);
  if (version === null) return false;
  useUIStore.getState().setStaleVaultKeyVersion(version);
  return true;
}

/**
 * Whether this session is still holding a vault key the account has replaced.
 *
 * `recorded` is what the server last said it was on; `current` is what this
 * session believes it holds (`authStore.vaultKeyVersion`). Equal means the
 * session has since caught up — by logging in again, or by driving a rotation
 * of its own — and there is nothing left to warn about.
 *
 * Exported rather than inlined into the layout so the notice's CONDITION is one
 * testable expression rather than a fragment of JSX.
 */
export function isHoldingSupersededVaultKey(recorded: number | null, current: number): boolean {
  return recorded !== null && recorded !== current;
}
