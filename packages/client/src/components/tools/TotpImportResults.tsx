import { useCallback, useMemo, useState } from 'react';
import { Check, Copy, Eye, EyeOff, KeyRound, Plus, Link2 } from 'lucide-react';
import { TotpDisplay } from '../vault/TotpDisplay';
import { useToast } from '../ui/Toast';
import { useUserSettings } from '../../hooks/useUserSettings';
import { copySecretToClipboard } from '../../services/clipboard/clipboardService';
import { otpauthUriFor, secretFor, type ScannedEntry } from '../../services/totpImport/scanSession';

/**
 * The decoded accounts, and what a person can do with them.
 *
 * ---------------------------------------------------------------------------
 * NOTHING IS ATTACHED AUTOMATICALLY, AND THAT IS THE FEATURE
 * ---------------------------------------------------------------------------
 *
 * It would be easy to match each imported account against the vault by issuer or
 * by username and offer to wire them up. That is exactly what this must not do.
 * A TOTP attached to the WRONG login is worse than one not imported at all: it
 * is silent, it looks correct, and the user finds out when they are locked out
 * of something. So every attachment is an explicit act against a named item.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS COMPONENT IS NOT GIVEN
 * ---------------------------------------------------------------------------
 *
 * The keys. It receives {@link ScannedEntry}, which is labels and an id, and it
 * asks `scanSession` for a key at the moment one is needed. A secret is never a
 * prop, never in state, and therefore never in the React tree a devtools panel
 * can read. Copying puts the CODE on the clipboard by default, not the key, and
 * there is deliberately no "copy every key" action: one click that puts every
 * TOTP secret a person owns on the system clipboard, where any application can
 * read it, is not worth the convenience.
 */

interface TotpImportResultsProps {
  readonly entries: readonly ScannedEntry[];
  readonly onCreateLogin: (entry: ScannedEntry) => void;
  readonly onAttach: (entry: ScannedEntry) => void;
  readonly attachedTo: ReadonlyMap<string, string>;
}

function Badge({ children }: { children: React.ReactNode }) {
  return (
    <span className="rounded bg-[hsl(var(--muted))] px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-[hsl(var(--muted-foreground))]">
      {children}
    </span>
  );
}

function EntryCard({
  entry,
  onCreateLogin,
  onAttach,
  attachedTo,
}: {
  entry: ScannedEntry;
  onCreateLogin: (entry: ScannedEntry) => void;
  onAttach: (entry: ScannedEntry) => void;
  attachedTo: string | undefined;
}) {
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();
  const { clipboardClearTimeout } = useUserSettings();

  const title = entry.issuer.length > 0 ? entry.issuer : entry.account || 'Unnamed account';
  const subtitle = entry.issuer.length > 0 ? entry.account : '';

  // Built at the moment it is shown, never held: a rendered key is a string, and
  // a string cannot be zeroed.
  const secret = revealed ? secretFor(entry.id) : null;
  const totpValue = useMemo(() => otpauthUriFor(entry), [entry]);

  const copySecret = useCallback(async () => {
    const value = secretFor(entry.id);
    if (value === null) {
      toast({ title: 'That key is no longer available', type: 'error' });
      return;
    }
    try {
      await copySecretToClipboard(value, clipboardClearTimeout * 1000);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      toast({ title: 'Secret key copied', type: 'success', duration: 2000 });
    } catch {
      toast({ title: 'Failed to copy', type: 'error' });
    }
  }, [entry.id, clipboardClearTimeout, toast]);

  return (
    <li className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate font-medium text-[hsl(var(--foreground))]">{title}</p>
          {subtitle && (
            <p className="truncate text-sm text-[hsl(var(--muted-foreground))]">{subtitle}</p>
          )}
        </div>
        <div className="flex shrink-0 flex-wrap justify-end gap-1">
          {/* A badge only when something is NOT the default, so a badge means
              something rather than decorating every row. */}
          {entry.algorithm !== 'SHA1' && <Badge>{entry.algorithm}</Badge>}
          {entry.digits !== 6 && <Badge>{entry.digits} digits</Badge>}
          {entry.type === 'hotp' && <Badge>counter-based</Badge>}
          {!entry.generatable && <Badge>not supported here</Badge>}
        </div>
      </div>

      {entry.generatable && entry.type === 'totp' && totpValue !== null && (
        <TotpDisplay secret={totpValue} />
      )}

      {entry.labelTruncated && (
        <p className="text-xs text-[hsl(var(--muted-foreground))]">
          The name was shortened so the key fits. The key itself is complete.
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => setRevealed((shown) => !shown)}
          className="inline-flex items-center gap-1.5 rounded-md border border-[hsl(var(--input))] px-2.5 py-1.5 text-xs text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
        >
          {revealed ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
          {revealed ? 'Hide key' : 'Show key'}
        </button>
        <button
          type="button"
          onClick={() => void copySecret()}
          aria-label={`Copy secret key for ${title}`}
          className="inline-flex items-center gap-1.5 rounded-md border border-[hsl(var(--input))] px-2.5 py-1.5 text-xs text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
        >
          {copied ? (
            <Check className="h-3.5 w-3.5 text-green-500" />
          ) : (
            <Copy className="h-3.5 w-3.5" />
          )}
          Copy key
        </button>
        {entry.generatable && (
          <>
            <button
              type="button"
              onClick={() => onCreateLogin(entry)}
              className="inline-flex items-center gap-1.5 rounded-md border border-[hsl(var(--input))] px-2.5 py-1.5 text-xs text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
            >
              <Plus className="h-3.5 w-3.5" />
              New login
            </button>
            <button
              type="button"
              onClick={() => onAttach(entry)}
              className="inline-flex items-center gap-1.5 rounded-md border border-[hsl(var(--input))] px-2.5 py-1.5 text-xs text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
            >
              <Link2 className="h-3.5 w-3.5" />
              Add to a login
            </button>
          </>
        )}
      </div>

      {revealed && secret !== null && (
        <p className="break-all rounded bg-[hsl(var(--muted))] p-2 font-mono text-xs text-[hsl(var(--foreground))]">
          {secret}
        </p>
      )}

      {attachedTo !== undefined && (
        <p className="text-xs text-green-600 dark:text-green-400">Added to {attachedTo}</p>
      )}
    </li>
  );
}

export function TotpImportResults({
  entries,
  onCreateLogin,
  onAttach,
  attachedTo,
}: TotpImportResultsProps) {
  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-amber-500/40 bg-amber-500/5 p-3 text-sm text-[hsl(var(--foreground))]">
        <p className="font-medium">Nothing here is saved yet.</p>
        <p className="mt-1 text-[hsl(var(--muted-foreground))]">
          Closing this page, locking your vault or signing out clears these keys, and you would need
          to export from your phone again. Keep the accounts in Google Authenticator until a code
          here matches the one on your phone.
        </p>
      </div>

      <ul className="space-y-3">
        {entries.map((entry) => (
          <EntryCard
            key={entry.id}
            entry={entry}
            onCreateLogin={onCreateLogin}
            onAttach={onAttach}
            attachedTo={attachedTo.get(entry.id)}
          />
        ))}
      </ul>

      <p className="flex items-center gap-1.5 text-xs text-[hsl(var(--muted-foreground))]">
        <KeyRound className="h-3.5 w-3.5" />
        {entries.length} {entries.length === 1 ? 'account' : 'accounts'} read from your export.
      </p>
    </div>
  );
}
