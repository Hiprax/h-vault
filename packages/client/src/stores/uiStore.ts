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
   */
  offlineCacheError: OfflineCacheErrorType | null;

  setTheme: (theme: ThemeValue) => void;
  toggleSidebar: () => void;
  toggleSidebarCollapsed: () => void;
  toggleCommandPalette: () => void;
  setOfflineCacheError: (error: OfflineCacheErrorType | null) => void;
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
