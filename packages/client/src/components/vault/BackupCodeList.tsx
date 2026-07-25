/**
 * The masked list of a login's 2FA backup codes.
 *
 * Shared by both surfaces that show codes — the item form's editor and the item
 * detail view — because the two things that are identical and easy to get wrong
 * live here: how a code is masked, and where focus goes when a row is deleted out
 * from under the user's finger.
 *
 * Copying lives here rather than in either host, so `VaultItemForm` still imports
 * no clipboard code at all, and so both surfaces route every copy through the one
 * sanctioned path (`copySecretToClipboard`) that arms the app-wide erase deadline.
 */
import { useCallback, useEffect, useRef, useState, type ReactNode, type RefObject } from 'react';
import { AlertTriangle, Check, Copy, Download, Eye, EyeOff, Trash2 } from 'lucide-react';
import { formatBackupCodes } from '@hvault/shared';
import { cn } from '../../lib/utils';
import { downloadText } from '../../lib/download';
import { useUserSettings } from '../../hooks/useUserSettings';
import { useBackupCodeReveal } from '../../hooks/useBackupCodeReveal';
import { copySecretToClipboard } from '../../services/clipboard/clipboardService';
import { useToast } from '../ui/Toast';

/**
 * At or below this many remaining codes the section warns the user to generate a
 * fresh set at the provider. Purely a nudge in this one component: it is
 * deliberately NOT a sixth Vault Health check, because a login with no stored
 * codes says nothing about whether the account has any.
 */
const LOW_BACKUP_CODES_THRESHOLD = 3;

/**
 * The masked form of every code, at a FIXED width.
 *
 * Deliberately not `'•'.repeat(code.length)` the way `CopyField` masks a password:
 * a provider issues fixed-length codes, so the length is not information the user
 * needs; a ragged column of bullets reads as an alignment bug and destroys the
 * scannability that is the point of a list; a uniform width means revealing one
 * code causes no layout shift; and it removes a small shoulder-surfing signal for
 * free.
 */
const MASK = '•'.repeat(8);

const HOW_LONG_COPIED_SHOWS_MS = 2000;

export interface BackupCodeListProps {
  /** The codes, in stored order. */
  readonly codes: readonly string[];
  /**
   * Omit for a read-only list: no delete controls are rendered at all.
   *
   * The code itself is passed alongside its index so a caller that needs the value
   * (to offer an Undo, say) does not have to index back into the array, which under
   * `noUncheckedIndexedAccess` would force an unreachable undefined check.
   */
  readonly onDelete?: ((index: number, code: string) => void) | undefined;
  /** True while a mutation is in flight; deletes become inert but stay focusable. */
  readonly busy?: boolean | undefined;
  /** Offer the plaintext `.txt` download. */
  readonly allowDownload?: boolean | undefined;
  /** Item name, used only to name the downloaded file. */
  readonly itemName?: string | undefined;
  /** Host-specific header controls, rendered after Copy all. */
  readonly headerActions?: ReactNode;
  /**
   * Where focus goes when a delete empties the list. Defaults to the section
   * heading, which is always mounted while this component is.
   */
  readonly emptyFocusRef?: RefObject<HTMLElement | null> | undefined;
}

/**
 * The section title, and the accessible name of the list.
 *
 * Fixed rather than a prop: both surfaces say the same thing, and a configurable
 * label would be an option nothing ever sets.
 */
const LABEL = 'Backup codes';

/** Kept here so both surfaces cannot drift, and so neither repeats the copy. */
const DESCRIPTION = "Single-use recovery codes for this login's two-factor sign-in.";

/**
 * Turn an item name into a filename fragment through a strict allowlist.
 *
 * The result reaches an anchor's `download` attribute, so nothing but lowercase
 * alphanumerics and single dashes may survive; the length cap keeps the filename
 * reasonable. An empty result means the download falls back to a name with no
 * item fragment at all.
 */
function slugifyForFilename(name: string): string {
  const collapsed = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+/, '')
    .replace(/-+$/, '');
  return collapsed.slice(0, 40).replace(/-+$/, '');
}

const headerButtonClass = 'text-xs text-[hsl(var(--primary))] hover:underline';
const rowIconButtonClass =
  'rounded p-1 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors';

export function BackupCodeList({
  codes,
  onDelete,
  busy = false,
  allowDownload = false,
  itemName,
  headerActions,
  emptyFocusRef,
}: BackupCodeListProps) {
  const { toast } = useToast();
  const { clipboardClearTimeout } = useUserSettings();
  const reveal = useBackupCodeReveal(codes);
  const [copied, setCopied] = useState<number | 'all' | null>(null);
  const [confirmDownload, setConfirmDownload] = useState(false);
  const copiedTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  /** Row index whose delete was just clicked, awaiting the post-delete focus move. */
  const pendingFocusRef = useRef<number | null>(null);
  const clearTimeoutMs = clipboardClearTimeout * 1000;

  useEffect(() => {
    return () => {
      if (copiedTimeoutRef.current) clearTimeout(copiedTimeoutRef.current);
    };
  }, []);

  /**
   * Move focus after a row disappears.
   *
   * Focus the delete button that now OCCUPIES the deleted row's position; if the
   * deleted row was the last one, the new last row; if the list is now empty, the
   * host's fallback. Without this, deleting a row leaves focus on a detached node
   * and the browser drops it to `document.body`.
   *
   * The buttons are read out of the live DOM rather than from a ref array (the
   * same approach `DropdownMenu` uses for its roving focus) so a row that
   * remounted when the keys shifted cannot leave a stale element behind.
   */
  useEffect(() => {
    // The tick names a ROW, and after a change that row holds a different code.
    setCopied(null);
    const target = pendingFocusRef.current;
    if (target === null) return;
    pendingFocusRef.current = null;
    const buttons = listRef.current?.querySelectorAll<HTMLButtonElement>(
      '[data-backup-code-delete]',
    );
    if (buttons !== undefined && buttons.length > 0) {
      buttons[Math.min(target, buttons.length - 1)]?.focus();
      return;
    }
    (emptyFocusRef?.current ?? headingRef.current)?.focus();
  }, [codes, emptyFocusRef]);

  const markCopied = useCallback((which: number | 'all') => {
    setCopied(which);
    if (copiedTimeoutRef.current) clearTimeout(copiedTimeoutRef.current);
    copiedTimeoutRef.current = setTimeout(() => setCopied(null), HOW_LONG_COPIED_SHOWS_MS);
  }, []);

  const handleCopy = useCallback(
    // The value is passed in rather than indexed out of `codes`, for the same
    // reason `onDelete` takes it: under `noUncheckedIndexedAccess` an index lookup
    // forces a nullish guard whose other arm is unreachable.
    async (which: number | 'all', value: string) => {
      try {
        // The guard owns the write and the single app-wide erase deadline. Copying
        // a second code re-arms that one deadline rather than starting a second.
        await copySecretToClipboard(value, clearTimeoutMs);
        markCopied(which);
        toast({
          title: which === 'all' ? 'Backup codes copied' : `Backup code ${which + 1} copied`,
          type: 'success',
          duration: HOW_LONG_COPIED_SHOWS_MS,
        });
      } catch {
        toast({ title: 'Failed to copy', type: 'error' });
      }
    },
    [clearTimeoutMs, markCopied, toast],
  );

  const handleDownload = useCallback(() => {
    const stamp = new Date().toISOString().slice(0, 10);
    const slug = slugifyForFilename(itemName ?? '');
    const filename = `hvault-backup-codes-${slug === '' ? '' : `${slug}-`}${stamp}.txt`;
    const heading =
      itemName === undefined ? 'H-Vault backup codes' : `H-Vault backup codes for ${itemName}`;
    downloadText(
      `${heading}\nSaved ${stamp}\n\n${formatBackupCodes(codes)}\n`,
      filename,
      'text/plain',
    );
    setConfirmDownload(false);
    toast({ title: 'Backup codes downloaded', type: 'success' });
  }, [codes, itemName, toast]);

  const runningLow = codes.length > 0 && codes.length <= LOW_BACKUP_CODES_THRESHOLD;

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <h3
            ref={headingRef}
            tabIndex={-1}
            className="text-sm font-medium text-[hsl(var(--foreground))]"
          >
            {LABEL}
          </h3>
          {codes.length > 0 && (
            <span
              aria-hidden="true"
              className="rounded-full bg-[hsl(var(--secondary))] px-2 py-0.5 text-xs font-medium text-[hsl(var(--secondary-foreground))]"
            >
              {codes.length}
            </span>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {codes.length > 0 && (
            <>
              <button type="button" onClick={reveal.toggleAll} className={headerButtonClass}>
                {reveal.revealAll ? 'Hide all' : 'Reveal all'}
              </button>
              <button
                type="button"
                onClick={() => void handleCopy('all', formatBackupCodes(codes))}
                aria-label="Copy all backup codes"
                className={headerButtonClass}
              >
                {copied === 'all' ? 'Copied' : 'Copy all'}
              </button>
              {allowDownload && !confirmDownload && (
                <button
                  type="button"
                  onClick={() => setConfirmDownload(true)}
                  className={cn(headerButtonClass, 'inline-flex items-center gap-1')}
                >
                  <Download className="h-3 w-3" />
                  Download
                </button>
              )}
            </>
          )}
          {headerActions}
        </div>
      </div>

      <p className="text-xs text-[hsl(var(--muted-foreground))]">{DESCRIPTION}</p>

      {allowDownload && confirmDownload && (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-yellow-300 bg-yellow-50 px-3 py-2 text-xs text-yellow-800 dark:border-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-300">
          <span className="flex items-center gap-2">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
            The downloaded file is not encrypted. Anyone who can read it can use these codes.
          </span>
          <span className="flex shrink-0 items-center gap-2">
            <button
              type="button"
              onClick={() => setConfirmDownload(false)}
              className="rounded px-1.5 py-0.5 hover:underline"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleDownload}
              className="rounded px-1.5 py-0.5 font-medium hover:underline"
            >
              Download anyway
            </button>
          </span>
        </div>
      )}

      {runningLow && (
        <p className="flex items-center gap-2 text-xs text-yellow-700 dark:text-yellow-400">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
          {codes.length === 1
            ? 'Only one code left. Generate a fresh set at the provider.'
            : `Only ${codes.length} codes left. Generate a fresh set at the provider.`}
        </p>
      )}

      {codes.length > 0 && (
        <ul
          ref={listRef}
          // Tailwind's preflight removes the list marker, which makes Safari and
          // VoiceOver drop the list role, so it is set explicitly.
          role="list"
          aria-label={LABEL}
          className="max-h-[22rem] space-y-1.5 overflow-y-auto pr-1"
        >
          {codes.map((code, index) => {
            const revealed = reveal.isRevealed(index);
            const position = index + 1;
            return (
              <li
                // Keyed by POSITION, not by content. These rows hold no local state
                // of their own, and a content key would make React unmount the row
                // that currently has focus whenever the list is replaced — which is
                // exactly what a failed delete's rollback does. With a positional
                // key the same DOM node is reused and focus survives both the
                // optimistic removal and the revert.
                key={index}
                role="listitem"
                aria-setsize={codes.length}
                aria-posinset={position}
                className="group flex items-center gap-3 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-3 py-2"
              >
                <span
                  aria-hidden="true"
                  className="w-5 shrink-0 text-right text-xs tabular-nums text-[hsl(var(--muted-foreground))]"
                >
                  {position}
                </span>
                <code
                  // The mask carries no information, so it is not announced; the
                  // revealed value is.
                  aria-hidden={revealed ? undefined : true}
                  className={cn(
                    'min-w-0 flex-1 font-mono text-sm tracking-wider',
                    revealed
                      ? 'break-all text-[hsl(var(--foreground))]'
                      : 'select-none text-[hsl(var(--muted-foreground))]',
                  )}
                >
                  {revealed ? code : MASK}
                </code>
                <button
                  type="button"
                  onClick={() => reveal.toggleRow(index)}
                  aria-label={
                    revealed ? `Hide backup code ${position}` : `Reveal backup code ${position}`
                  }
                  className={rowIconButtonClass}
                >
                  {revealed ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
                <button
                  type="button"
                  onClick={() => void handleCopy(index, code)}
                  aria-label={
                    copied === index
                      ? `Backup code ${position} copied`
                      : `Copy backup code ${position}`
                  }
                  className={rowIconButtonClass}
                >
                  {copied === index ? (
                    <Check className="h-4 w-4 text-green-500" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </button>
                {onDelete !== undefined && (
                  <button
                    type="button"
                    data-backup-code-delete=""
                    onClick={() => {
                      // Inlined inside the `onDelete !== undefined` guard above so
                      // there is no second undefined check whose other arm the
                      // render makes unreachable.
                      if (busy) return;
                      pendingFocusRef.current = index;
                      onDelete(index, code);
                    }}
                    // `aria-disabled` rather than `disabled`: a disabled element is
                    // not focusable, and a save that is still in flight is exactly
                    // when the post-delete focus move needs a target. The click
                    // handler is what actually makes it inert.
                    aria-disabled={busy ? true : undefined}
                    aria-label={`Remove backup code ${position}`}
                    className={cn(
                      'shrink-0 rounded p-1 text-[hsl(var(--destructive))] transition-colors hover:bg-[hsl(var(--destructive)/0.1)]',
                      busy && 'opacity-50',
                    )}
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
