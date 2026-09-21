import { useMemo, useState } from 'react';
import { AlertTriangle, Search } from 'lucide-react';
import { useVaultStore, type DecryptedVaultItem } from '../../stores/vaultStore';
import { isUndecodableData } from '../../lib/vaultData';
import { parseTotpValue } from '../../lib/totp';
import type { ScannedEntry } from '../../services/totpImport/scanSession';

/**
 * Choosing which existing login a scanned key belongs to.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS EXCLUDED FROM THE LIST, AND WHY EXCLUDING BEATS DISABLING
 * ---------------------------------------------------------------------------
 *
 * An item whose decrypted data failed validation is NOT offered at all, rather
 * than offered and disabled. Writing to one would be actively destructive:
 * `updateItem` re-encrypts `item.data`, and for such an item `data` is the
 * placeholder the store kept instead of the real content, so saving would
 * replace genuine ciphertext with a re-encrypted placeholder. Leaving it in the
 * list greyed out invites a bug report and a workaround; leaving it out, with a
 * count and a reason, is honest and safe.
 *
 * Both halves of the identity are shown, because "Google" appearing three times
 * is the normal case and the username is the only thing that tells them apart.
 *
 * ---------------------------------------------------------------------------
 * REPLACING AN EXISTING CODE KEEPS THE OLD ONE
 * ---------------------------------------------------------------------------
 *
 * When the chosen item already has a code, the default is to keep the previous
 * value in a hidden custom field rather than to overwrite it. A TOTP key is not
 * recoverable from anywhere else once it is gone, and the person doing this is
 * mid-import and moving quickly. That preserved field is the undo.
 *
 * The undo has ONE limit worth knowing rather than discovering. It is an
 * ordinary custom field, and an `overwrite` import seals a matched row wholesale
 * from the incoming record, so a later import over the same item would drop it
 * along with anything else the source file does not carry. It survives every
 * ordinary edit; it does not survive being overwritten by an import.
 */

export interface AttachChoice {
  readonly item: DecryptedVaultItem;
  readonly keepExisting: boolean;
}

interface TotpAttachDialogProps {
  readonly entry: ScannedEntry;
  readonly onCancel: () => void;
  readonly onConfirm: (choice: AttachChoice) => void;
}

/** The name a stored TOTP goes by, for the comparison the user has to make. */
function describeExisting(value: string): string {
  const parsed = parseTotpValue(value);
  if (!parsed.ok) return 'an existing code';
  const label = [parsed.value.issuer, parsed.value.account].filter((part) => part.length > 0);
  return label.length > 0 ? label.join(' · ') : 'an existing code';
}

export function TotpAttachDialog({ entry, onCancel, onConfirm }: TotpAttachDialogProps) {
  const items = useVaultStore((state) => state.items);
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [keepExisting, setKeepExisting] = useState(true);

  const { logins, excluded } = useMemo(() => {
    let skipped = 0;
    const usable: DecryptedVaultItem[] = [];
    for (const item of items) {
      if (item.itemType !== 'login') continue;
      if (isUndecodableData(item.data)) {
        skipped += 1;
        continue;
      }
      usable.push(item);
    }
    return { logins: usable, excluded: skipped };
  }, [items]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (needle === '') return logins;
    return logins.filter((item) => {
      const username = typeof item.data.username === 'string' ? item.data.username : '';
      return item.name.toLowerCase().includes(needle) || username.toLowerCase().includes(needle);
    });
  }, [logins, query]);

  const selected = filtered.find((item) => item.id === selectedId) ?? null;
  const existingTotp =
    selected !== null && typeof selected.data.totp === 'string' && selected.data.totp.length > 0
      ? selected.data.totp
      : null;

  const title = entry.issuer.length > 0 ? entry.issuer : entry.account;

  return (
    <div className="space-y-4">
      <div>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">
          Choose the login that{' '}
          <span className="font-medium text-[hsl(var(--foreground))]">{title}</span> belongs to.
          Nothing is matched for you, because a code added to the wrong account is worse than one
          not added at all.
        </p>
      </div>

      <label className="relative block">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[hsl(var(--muted-foreground))]" />
        <span className="sr-only">Search logins</span>
        <input
          type="text"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search logins"
          className="w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] py-2 pl-9 pr-3 text-sm text-[hsl(var(--foreground))]"
        />
      </label>

      <ul className="max-h-64 space-y-1 overflow-y-auto" role="listbox" aria-label="Logins">
        {filtered.map((item) => {
          const username = typeof item.data.username === 'string' ? item.data.username : '';
          return (
            <li key={item.id}>
              <button
                type="button"
                role="option"
                aria-selected={item.id === selectedId}
                onClick={() => setSelectedId(item.id)}
                className={`w-full rounded-md px-3 py-2 text-left text-sm transition-colors ${
                  item.id === selectedId
                    ? 'bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))]'
                    : 'text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]'
                }`}
              >
                <span className="block truncate font-medium">{item.name}</span>
                {/* The username is what tells three "Google" rows apart. */}
                {username && <span className="block truncate text-xs opacity-80">{username}</span>}
              </button>
            </li>
          );
        })}
        {filtered.length === 0 && (
          <li className="px-3 py-2 text-sm text-[hsl(var(--muted-foreground))]">
            No matching logins.
          </li>
        )}
      </ul>

      {excluded > 0 && (
        <p className="text-xs text-[hsl(var(--muted-foreground))]">
          {excluded} {excluded === 1 ? 'login is' : 'logins are'} not listed because they could not
          be decoded. Saving to one would overwrite its stored data.
        </p>
      )}

      {existingTotp !== null && (
        <div className="space-y-2 rounded-lg border border-amber-500/40 bg-amber-500/5 p-3">
          <p className="flex items-center gap-2 text-sm font-medium text-[hsl(var(--foreground))]">
            <AlertTriangle className="h-4 w-4 text-amber-500" />
            That login already has a code
          </p>
          <p className="text-xs text-[hsl(var(--muted-foreground))]">
            It currently holds {describeExisting(existingTotp)}.
          </p>
          <label className="flex items-start gap-2 text-xs text-[hsl(var(--foreground))]">
            <input
              type="checkbox"
              checked={keepExisting}
              onChange={(event) => setKeepExisting(event.target.checked)}
              className="mt-0.5 h-3.5 w-3.5 accent-[hsl(var(--primary))]"
            />
            <span>
              Keep the old code in a custom field. A code cannot be recovered once it is gone, so
              this is on by default.
            </span>
          </label>
        </div>
      )}

      <div className="flex justify-end gap-2">
        <button
          type="button"
          onClick={onCancel}
          className="rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
        >
          Cancel
        </button>
        <button
          type="button"
          disabled={selected === null}
          onClick={() => {
            if (selected !== null) onConfirm({ item: selected, keepExisting });
          }}
          className="rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] disabled:opacity-50"
        >
          Add code
        </button>
      </div>
    </div>
  );
}
