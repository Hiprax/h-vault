import { useCallback, useEffect, useMemo, useState } from 'react';
import type { DecryptedDocument } from '../stores/documentsStore';
import type { DocumentListMode } from './useDocumentsFilterView';

const NOTHING: ReadonlySet<string> = new Set();

/** Which list the selection belongs to: changing it is the one thing that clears it. */
function modeKeyOf(mode: DocumentListMode): string {
  return mode.kind === 'folder' ? `folder:${mode.id}` : mode.kind;
}

export interface DocumentSelection {
  /** The selected rows that are in the list on screen, in its order. */
  readonly rows: readonly DecryptedDocument[];
  /** At least one selected row is on screen. */
  readonly active: boolean;
  /** Every row on screen is selected (and there is at least one). */
  readonly allSelected: boolean;
  isSelected: (id: string) => boolean;
  toggle: (id: string) => void;
  /** Selects exactly the rows on screen. */
  selectAll: () => void;
  clear: () => void;
  /** Drops rows from the selection, e.g. the ones an action has just changed. */
  remove: (ids: Iterable<string>) => void;
}

/**
 * The documents page's multi-select.
 *
 * The selected ids are kept as a set and are NOT pruned to the rows on screen.
 * The lists empty themselves while they are re-read (a Retry, a folder delete,
 * another tab's change), and a search narrows them a keystroke at a time; pruning
 * would throw a selection away on either. Instead, everything that counts or acts
 * uses the selected rows that are VISIBLE, so a row a search has hidden is never
 * acted on, and clearing the search shows it selected again.
 *
 * Changing the list itself (all, favorites, a folder, the trash) clears it: a
 * selection made in one view must not be acted on from another.
 */
export function useDocumentSelection(
  rows: readonly DecryptedDocument[],
  mode: DocumentListMode,
): DocumentSelection {
  const modeKey = modeKeyOf(mode);
  const [state, setState] = useState<{ key: string; ids: ReadonlySet<string> }>(() => ({
    key: modeKey,
    ids: NOTHING,
  }));
  // Read through the key, so the render that follows a mode change already shows
  // nothing selected; the effect then makes that the stored state, so returning
  // to the earlier list does not bring its selection back.
  const ids = state.key === modeKey ? state.ids : NOTHING;
  useEffect(() => {
    setState((prev) => (prev.key === modeKey ? prev : { key: modeKey, ids: NOTHING }));
  }, [modeKey]);

  const selectedRows = useMemo(() => rows.filter((row) => ids.has(row.id)), [rows, ids]);

  const update = useCallback(
    (next: (current: ReadonlySet<string>) => ReadonlySet<string>) => {
      setState((prev) => ({
        key: modeKey,
        ids: next(prev.key === modeKey ? prev.ids : NOTHING),
      }));
    },
    [modeKey],
  );

  const toggle = useCallback(
    (id: string) => {
      update((current) => {
        const next = new Set(current);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        return next;
      });
    },
    [update],
  );

  const selectAll = useCallback(() => {
    update(() => new Set(rows.map((row) => row.id)));
  }, [rows, update]);

  const clear = useCallback(() => {
    update(() => NOTHING);
  }, [update]);

  // Against whatever is selected NOW, never a list captured when an action began:
  // a run that finishes after the view changed must not bring an old selection
  // back, and rows selected meanwhile stay selected.
  const remove = useCallback((drop: Iterable<string>) => {
    const dropped = new Set(drop);
    setState((prev) => ({
      key: prev.key,
      ids: new Set([...prev.ids].filter((id) => !dropped.has(id))),
    }));
  }, []);

  const isSelected = useCallback((id: string) => ids.has(id), [ids]);

  return {
    rows: selectedRows,
    active: selectedRows.length > 0,
    allSelected: rows.length > 0 && selectedRows.length === rows.length,
    isSelected,
    toggle,
    selectAll,
    clear,
    remove,
  };
}
