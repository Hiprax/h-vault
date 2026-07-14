import { useEffect } from 'react';

type ShortcutMap = Record<string, () => void>;

/**
 * Register global keyboard shortcuts.
 *
 * Each key in `shortcuts` should be a lowercase letter (e.g. `'n'`, `'l'`).
 * The callback fires on `Ctrl+<key>` (or `Cmd+<key>` on Mac).
 * Shortcuts are suppressed when the user is typing in an input, textarea,
 * or content-editable element.
 */
export function useKeyboardShortcuts(shortcuts: ShortcutMap) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Only trigger with Ctrl (or Cmd on Mac)
      const modifier = e.ctrlKey || e.metaKey;
      if (!modifier) return;

      // Don't fire when user is typing in an input
      const target = e.target as HTMLElement | null;
      if (target) {
        const tag = target.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target.isContentEditable) {
          return;
        }
      }

      const key = e.key.toLowerCase();
      const callback = shortcuts[key];
      if (callback) {
        e.preventDefault();
        callback();
      }
    };

    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [shortcuts]);
}
