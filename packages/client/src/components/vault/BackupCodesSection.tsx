/**
 * The backup-codes block on a login's detail view.
 *
 * This is where a code is actually USED: you open the item, copy a code, and then
 * want the burned code gone. So the delete here persists immediately rather than
 * sending the user through the edit form, and an inline Undo covers the mis-click
 * that an immediate write would otherwise make permanent.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Loader2 } from 'lucide-react';
import type { ILoginData } from '@hvault/shared';
import { getApiErrorMessage } from '../../lib/utils';
import { useVaultStore } from '../../stores/vaultStore';
import { useToast } from '../ui/Toast';
import { BackupCodeList } from './BackupCodeList';

/**
 * What the section is doing to the list right now.
 *
 * `code` is held only for the duration of an undoable removal, so the value the
 * user might want back is in memory and nowhere else; it never reaches the DOM.
 */
type DeleteState =
  | { readonly phase: 'idle' }
  | {
      readonly phase: 'saving';
      readonly index: number;
      readonly code: string;
      readonly restoring: boolean;
    }
  | { readonly phase: 'done'; readonly index: number; readonly code: string }
  | { readonly phase: 'failed'; readonly index: number; readonly restoring: boolean };

export interface BackupCodesSectionProps {
  readonly itemId: string;
  readonly itemName: string;
  /**
   * The item's FULL decrypted payload. `updateItem` replaces the whole blob, so
   * the section owns the spread; a codes-only prop would invite a caller to write
   * a payload missing everything else the item holds.
   */
  readonly data: ILoginData;
  /** False for a trashed item: copy and reveal still work, delete does not. */
  readonly canEdit: boolean;
}

export function BackupCodesSection({ itemId, itemName, data, canEdit }: BackupCodesSectionProps) {
  const { toast } = useToast();
  const updateItem = useVaultStore((state) => state.updateItem);
  const [pending, setPending] = useState<DeleteState>({ phase: 'idle' });
  /** Optimistic view of the list while a write is in flight, or null. */
  const [override, setOverride] = useState<readonly string[] | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);
  /** True while THIS section's own write is in flight. */
  const savingRef = useRef(false);
  /** Row to focus once an undone code is back in the list, or null. */
  const restoreFocusRef = useRef<number | null>(null);

  const storedCodes = useMemo(() => data.backupCodes ?? [], [data.backupCodes]);
  const codes = override ?? storedCodes;

  // Once the store has the new item, its array is the truth again.
  //
  // Guarded on our own write: `data.backupCodes` also gets a new identity from any
  // unrelated refresh (the online-event `fetchItems()` redecrypts every item), and
  // without the guard such a refresh landing mid-write would drop the optimistic
  // view and flash the removed code back into the list. It never needs to run for a
  // FAILURE either: `updateItem` throws before it writes, so the rollback below is
  // the only thing that clears the override on that path.
  useEffect(() => {
    if (savingRef.current) return;
    setOverride(null);
  }, [storedCodes]);

  // A successful Undo unmounts the strip, and with it the Undo button that has
  // focus, so hand focus to the row that was just put back rather than letting the
  // browser drop it to <body>.
  useEffect(() => {
    const target = restoreFocusRef.current;
    if (target === null) return;
    restoreFocusRef.current = null;
    const buttons = containerRef.current?.querySelectorAll<HTMLButtonElement>(
      '[data-backup-code-delete]',
    );
    if (buttons !== undefined) buttons[Math.min(target, buttons.length - 1)]?.focus();
  }, [codes]);

  const write = useCallback(
    async (next: readonly string[], failureTitle: string): Promise<boolean> => {
      const nextData: Record<string, unknown> = {
        ...(data as unknown as Record<string, unknown>),
      };
      if (next.length > 0) nextData.backupCodes = [...next];
      else delete nextData.backupCodes;
      try {
        // No `options` argument: folder, tags and favorite are left untouched.
        // Password history is a no-op because the password is passed through
        // unchanged, and the pre-flight size check cannot newly trip because a
        // removal only ever shrinks the payload.
        //
        // `'login'` is not a guess: this section only ever renders inside
        // `LoginDetail`, and its `data` prop is typed `ILoginData`.
        await updateItem(itemId, 'login', itemName, nextData);
        return true;
      } catch (error) {
        toast({
          title: failureTitle,
          description: getApiErrorMessage(error, 'Please try again.'),
          type: 'error',
        });
        return false;
      }
    },
    [data, itemId, itemName, toast, updateItem],
  );

  const handleDelete = useCallback(
    (index: number, code: string) => {
      const next = codes.filter((_, position) => position !== index);
      setOverride(next);
      savingRef.current = true;
      setPending({ phase: 'saving', index, code, restoring: false });
      void (async () => {
        const ok = await write(next, 'Failed to remove backup code');
        savingRef.current = false;
        if (ok) {
          setPending({ phase: 'done', index, code });
        } else {
          setOverride(null);
          setPending({ phase: 'failed', index, restoring: false });
        }
      })();
    },
    [codes, write],
  );

  const handleStripAction = useCallback(() => {
    if (pending.phase === 'failed') {
      setPending({ phase: 'idle' });
      return;
    }
    // Reachable: the control stays focusable while saving (see BackupCodeList) so
    // it can be clicked, and doing so must be inert rather than queue a second
    // write against an ambiguous rollback.
    if (pending.phase !== 'done') return;
    const { index, code } = pending;
    const next = [...codes];
    // Back where it was, not appended: the order the provider issued them in is
    // the order the user reads them in.
    next.splice(index, 0, code);
    setOverride(next);
    savingRef.current = true;
    setPending({ phase: 'saving', index, code, restoring: true });
    void (async () => {
      const ok = await write(next, 'Failed to restore backup code');
      savingRef.current = false;
      if (ok) {
        restoreFocusRef.current = index;
        setPending({ phase: 'idle' });
      } else {
        setOverride(null);
        setPending({ phase: 'failed', index, restoring: true });
      }
    })();
  }, [codes, pending, write]);

  // Kept mounted through a pending removal even when that emptied the list, so the
  // Undo strip survives and the post-delete focus move still has a target.
  if (codes.length === 0 && pending.phase === 'idle') return null;

  let stripMessage = '';
  if (pending.phase === 'saving') {
    stripMessage = pending.restoring
      ? `Restoring backup code ${pending.index + 1}…`
      : `Removing backup code ${pending.index + 1}…`;
  } else if (pending.phase === 'done') {
    stripMessage = `Backup code ${pending.index + 1} removed. ${codes.length} remaining.`;
  } else if (pending.phase === 'failed') {
    stripMessage = pending.restoring
      ? `Could not restore backup code ${pending.index + 1}.`
      : `Could not remove backup code ${pending.index + 1}.`;
  }

  return (
    <div
      ref={containerRef}
      className="space-y-2 rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-3"
    >
      {pending.phase !== 'idle' && (
        // The strip IS the live region: one element serves both the announcement
        // and the affordance, so the two can never disagree. There is no expiry
        // timer, which would add a race, a cleanup path, and an Undo that vanishes
        // while the user is still reading it.
        <div
          aria-live="polite"
          aria-atomic="true"
          className="flex items-center justify-between gap-3 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--muted))] px-3 py-2 text-xs text-[hsl(var(--muted-foreground))]"
        >
          <span className="flex items-center gap-2">
            {pending.phase === 'saving' && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
            {stripMessage}
          </span>
          {/*
            Always rendered, only its label changes: a control that unmounted as the
            phase advanced would drop focus to document.body mid-interaction.
          */}
          <button
            type="button"
            onClick={handleStripAction}
            aria-disabled={pending.phase === 'saving' ? true : undefined}
            className="shrink-0 rounded px-1.5 py-0.5 font-medium text-[hsl(var(--primary))] hover:underline aria-disabled:opacity-50"
          >
            {pending.phase === 'failed' ? 'Dismiss' : 'Undo'}
          </button>
        </div>
      )}

      <BackupCodeList
        codes={codes}
        onDelete={canEdit ? handleDelete : undefined}
        busy={pending.phase === 'saving'}
        allowDownload
        itemName={itemName}
      />
    </div>
  );
}
