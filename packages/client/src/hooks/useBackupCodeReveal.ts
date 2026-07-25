import { useCallback, useRef, useState } from 'react';

/**
 * Reveal state for a list of backup codes: which rows are shown in the clear.
 *
 * Kept in a hook rather than inside the list component because the "reveal all"
 * control lives in the section HEADER, which each host renders, while the per-row
 * eye lives in the list. One hook keeps both halves reading the same state.
 */
export interface BackupCodeReveal {
  /** True when the whole list is shown in the clear. */
  readonly revealAll: boolean;
  readonly toggleAll: () => void;
  readonly isRevealed: (index: number) => boolean;
  readonly toggleRow: (index: number) => void;
}

/**
 * Track which backup codes are revealed, re-masking everything whenever the
 * `codes` array is replaced.
 *
 * The reset happens DURING RENDER, not in an effect. An effect would paint one
 * frame with the old reveal set applied to the new codes, so deleting row 2 while
 * it was revealed would briefly show what is now row 2 — a code the user never
 * asked to see. Comparing a ref to the incoming array and adjusting state before
 * returning is React's documented pattern for exactly this, and it also skips the
 * wasted extra render an effect would cause.
 *
 * This relies on `codes` being referentially stable between renders while its
 * contents are unchanged, which holds for both hosts: the form reads it from
 * react-hook-form's stored form value, and the detail view from the vault store.
 */
export function useBackupCodeReveal(codes: readonly string[]): BackupCodeReveal {
  const [revealAll, setRevealAll] = useState(false);
  const [revealedRows, setRevealedRows] = useState<readonly number[]>([]);
  const previousCodes = useRef(codes);

  if (previousCodes.current !== codes) {
    previousCodes.current = codes;
    setRevealAll(false);
    setRevealedRows([]);
  }

  const toggleAll = useCallback(() => {
    setRevealAll((previous) => !previous);
    setRevealedRows([]);
  }, []);

  const toggleRow = useCallback((index: number) => {
    setRevealedRows((previous) =>
      previous.includes(index) ? previous.filter((row) => row !== index) : [...previous, index],
    );
  }, []);

  const isRevealed = useCallback(
    (index: number) => revealAll || revealedRows.includes(index),
    [revealAll, revealedRows],
  );

  return { revealAll, toggleAll, isRevealed, toggleRow };
}
