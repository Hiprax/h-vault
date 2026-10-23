import { useEffect } from 'react';

/**
 * Ask the browser to confirm before the tab is closed or reloaded, for as long
 * as `active` is true.
 *
 * `preventDefault()` alone, deliberately: the legacy `returnValue` assignment is
 * marked deprecated by the DOM typings this project compiles against, and every
 * browser it targets honours the standard call on its own.
 */
export function useBeforeUnloadWarning(active: boolean): void {
  useEffect(() => {
    if (!active) return;
    const warn = (event: BeforeUnloadEvent): void => {
      event.preventDefault();
    };
    window.addEventListener('beforeunload', warn);
    return () => {
      window.removeEventListener('beforeunload', warn);
    };
  }, [active]);
}
