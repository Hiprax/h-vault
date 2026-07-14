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

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type ThemeValue = 'light' | 'dark' | 'system';

interface UIState {
  theme: ThemeValue;
  sidebarOpen: boolean;
  sidebarCollapsed: boolean;
  commandPaletteOpen: boolean;
  offlineCacheAvailable: boolean;

  setTheme: (theme: ThemeValue) => void;
  toggleSidebar: () => void;
  toggleSidebarCollapsed: () => void;
  toggleCommandPalette: () => void;
  setOfflineCacheAvailable: (available: boolean) => void;
}

// ---------------------------------------------------------------------------
// Theme helpers
// ---------------------------------------------------------------------------

/**
 * Resolve the effective theme (light or dark) taking into account the
 * operating system preference when the user has chosen "system".
 */
function resolveEffectiveTheme(theme: ThemeValue): 'light' | 'dark' {
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
      offlineCacheAvailable: true,

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

      setOfflineCacheAvailable: (available: boolean): void => {
        set({ offlineCacheAvailable: available });
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
