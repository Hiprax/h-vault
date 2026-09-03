import { useEffect } from 'react';
import { isLiveTransfer, useDocumentsStore } from '../stores/documentsStore';

/**
 * Ask the browser to confirm before a tab holding a live upload is closed.
 *
 * ## Why this is a hook mounted in `App`, and not an effect inside the panel
 *
 * The documents store is module-level on purpose: a transfer survives the panel
 * being unmounted, so navigating from Documents to the vault keeps it running.
 * A guard living inside the panel would therefore be removed by exactly the
 * navigation the design promises is safe — start a 500 MB upload, open another
 * page, close the tab, and the transfer dies with no warning at all, which is
 * the one moment a warning is worth anything.
 *
 * `useClipboardGuard` is mounted in `App` for the same shape of reason, one level
 * further out: a guard has to outlive the route or layout that happened to arm
 * it. This one lives beside it.
 *
 * ## What counts as live, and why the selector answers a BOOLEAN
 *
 * `isLiveTransfer` is the store's own definition, shared with the panel so the
 * two cannot disagree about whether closing the tab costs anything.
 *
 * The selector reduces to a boolean rather than handing back the `uploads` map,
 * and that is not a style choice: zustand compares a selector's result with
 * `Object.is`, and the store replaces the whole map on every
 * `onUploadProgress` tick — dozens of times per 8 MiB part. Selecting the map
 * here would re-render `App`, and therefore the router and every provider under
 * it, on each of those ticks. A boolean changes only when liveness itself flips.
 *
 * `preventDefault()` alone, deliberately: the legacy `returnValue` assignment is
 * marked deprecated by the DOM typings this project compiles against, and every
 * browser it targets honours the standard call on its own.
 */
export function useUploadUnloadGuard(): void {
  const anyLive = useDocumentsStore((state) => Object.values(state.uploads).some(isLiveTransfer));

  useEffect(() => {
    if (!anyLive) return;
    const warn = (event: BeforeUnloadEvent): void => {
      event.preventDefault();
    };
    window.addEventListener('beforeunload', warn);
    return () => {
      window.removeEventListener('beforeunload', warn);
    };
  }, [anyLive]);
}
