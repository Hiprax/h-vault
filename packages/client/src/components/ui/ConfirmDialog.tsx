import type { ReactNode } from 'react';
import { Loader2 } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from './Dialog';

interface ConfirmDialogProps {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly title: string;
  readonly description: ReactNode;
  /** The destructive button's words, which should name what it does. */
  readonly confirmLabel: string;
  readonly onConfirm: () => void;
  /** The action is running: the confirm button waits and shows a spinner. */
  readonly busy: boolean;
  /**
   * Keep the dialog up while the action runs: Cancel is disabled and Escape and
   * the overlay do nothing until it finishes, as on the vault list's bulk delete.
   * Without it a busy dialog can still be dismissed while the action goes on.
   */
  readonly holdWhileBusy?: boolean;
}

/**
 * A confirmation before an action that cannot be taken back (emptying the
 * document trash, deleting or trashing a selection of documents), on the shared
 * `Dialog`: focus is trapped and returned, and Escape and Cancel both close it.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  onConfirm,
  busy,
  holdWhileBusy = false,
}: ConfirmDialogProps) {
  const held = holdWhileBusy && busy;
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!held) onOpenChange(next);
      }}
    >
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            disabled={held}
            className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent))] disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={busy}
            className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--destructive))] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive-foreground))] transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            {busy && <Loader2 className="h-4 w-4 animate-spin" />}
            {confirmLabel}
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
