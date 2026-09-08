import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router';
import { ArrowLeft, FileText, Loader2, RefreshCw } from 'lucide-react';
import { cn } from '../lib/utils';
import { useToast } from '../components/ui/Toast';
import { Pagination } from '../components/ui/Pagination';
import { getAuditLogApi } from '../services/api/userApi';
import type { IAuditLogEntry } from '@hvault/shared';
import { AUDIT_ACTIONS } from '@hvault/shared';

// ---------------------------------------------------------------------------
// Action styling
// ---------------------------------------------------------------------------

/**
 * One `bg-<hue>-100` / `text-<hue>-800` pair per action, and the DARKER text
 * shade is the accessible one rather than the pretty one.
 *
 * These badges are 12px at `font-medium`, so WCAG 1.4.3 asks for 4.5:1 rather
 * than 3:1, and Tailwind's `-700` on the matching `-100` surface does not have
 * that with any margin. Measured off Chrome's own painted pixels (a canvas fill
 * of each palette value, read back byte for byte):
 *
 *     green-700   on green-100    4.496:1     amber-700  on amber-100   4.515:1
 *     orange-700  on orange-100   4.556:1     yellow-700 on yellow-100  4.590:1
 *     cyan-700    on cyan-100     4.708:1     emerald-700 on emerald-100 4.722:1
 *
 * The first of those is BELOW the floor as painted; amber, orange and yellow
 * clear it by between two and nine hundredths. Cyan and emerald have real room
 * (twenty-one and twenty-two hundredths) and are darkened only so the map stays
 * one rule rather than four exceptions.
 *
 * **`test:a11y` does not catch this, and that is why it is written down here.**
 * axe reads the colours from `getComputedStyle` and converts them itself, which
 * lands one unit of 255 away from the pixel Chrome actually paints; asked about
 * the green pair it answers "4.5" and PASSES it, because its own arithmetic puts
 * the ratio a thousandth above the threshold. So this is a measurement rather
 * than a gate finding — the audit-log view is scanned now, and it is green with
 * either shade. What is not defensible is shipping the text a reader's screen
 * shows at 4.496:1 on the strength of a rounding difference in a colour-space
 * conversion, which is the same reasoning that set `--muted-foreground` and
 * `--destructive` to their current values (see `styles/globals.css`).
 *
 * Every `-800` pair measures at least 6.36:1 on the same surface, so one shade
 * buys the whole map real headroom for a change no reader would call a redesign.
 *
 * **The boundary of this change, stated so nobody reads it as finished.** The
 * identical `-100`/`-700` pairs are still shipped by four other places, and they
 * were left alone deliberately rather than overlooked, because darkening them is
 * a design decision across five files rather than the repair this page needed:
 * `VaultList.tsx`'s item-type badges (word labels, so genuinely measured — the
 * `vault-list` view is scanned and green, since the walk's account holds no
 * `note` item and the green pair is therefore never painted there),
 * `BackupSettingsPage.tsx`'s backup-history status badges and
 * `SettingsPage.tsx`'s 2FA-enabled badge (word labels, but neither state exists
 * on the account the sweep signs in as), and `VaultHealthPage.tsx`'s count
 * badges (a single digit, which axe declines to measure at all). So a real
 * user's vault list can still show the 4.496:1 green — that is a follow-up, not
 * a claim that it is fine.
 *
 * The `dark:` half is untouched: `-400` on `-900/30` over the dark card measures
 * 5.6:1 or better for every hue here, and `test:a11y` scans the light theme only,
 * so `packages/client/tests/theme-contrast.test.ts` is what keeps that side
 * honest — it requires every `-800` text shade to ship with a `dark:text-`
 * partner, which each string below has.
 */
const ACTION_COLORS: Record<string, string> = {
  login: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  login_failed: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
  logout: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-400',
  password_change: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
  '2fa_enable': 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
  '2fa_disable': 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400',
  item_create: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-400',
  item_update: 'bg-indigo-100 text-indigo-800 dark:bg-indigo-900/30 dark:text-indigo-400',
  item_delete: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
  export: 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400',
  import: 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400',
  session_revoke: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400',
  vault_lock: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-400',
  vault_unlock: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  backup_triggered: 'bg-cyan-100 text-cyan-800 dark:bg-cyan-900/30 dark:text-cyan-400',
  backup_sent: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  backup_failed: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
  backup_restored: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
  backup_password_changed:
    'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
  // Amber, not green: spending a recovery credential is a thing to notice on a
  // page you are reading precisely to notice things. Replacing the whole batch
  // is the same kind of event, so it shares the colour rather than staying grey.
  '2fa_backup_code_used': 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400',
  '2fa_backup_codes_regenerated':
    'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400',
};

const ACTION_LABELS: Record<string, string> = {
  login: 'Login',
  login_failed: 'Failed Login',
  logout: 'Logout',
  password_change: 'Password Changed',
  '2fa_enable': '2FA Enabled',
  '2fa_disable': '2FA Disabled',
  item_create: 'Item Created',
  item_update: 'Item Updated',
  item_delete: 'Item Deleted',
  export: 'Vault Exported',
  export_plaintext: 'Plaintext Export',
  import: 'Vault Imported',
  session_revoke: 'Session Revoked',
  vault_lock: 'Vault Locked',
  vault_unlock: 'Vault Unlocked',
  backup_triggered: 'Backup Triggered',
  backup_sent: 'Backup Sent',
  backup_failed: 'Backup Failed',
  backup_restored: 'Backup Restored',
  backup_password_changed: 'Backup Password Changed',
  '2fa_backup_codes_regenerated': 'Backup Codes Regenerated',
  '2fa_backup_code_used': 'Backup Code Used',
  trusted_device_grant: 'Trusted Device Added',
  trusted_device_revoke: 'Trusted Device Revoked',
  trusted_device_rejected: 'Trusted Device Rejected',
  document_create: 'Document Uploaded',
  document_update: 'Document Updated',
  document_delete: 'Document Trashed',
  document_restore: 'Document Restored',
  document_purge: 'Document Deleted Permanently',
};

/**
 * The count of backup codes still available, for the one action that carries it.
 *
 * This page renders the action, the IP, the User-Agent and the time; `metadata`
 * is deliberately not shown, because most of it is machine context that would
 * only crowd the row. `remaining` is the exception, and the reason is that it is
 * the only part of an entry a user can act on: the row that reads "0 left" is
 * the one telling them to regenerate before the authenticator app becomes the
 * only way into the account.
 *
 * Narrow on BOTH the action and the value's type. Another action's metadata must
 * never grow a count, and an entry written before this field existed — or one
 * whose audit write lost it — must render the label alone rather than
 * "undefined left".
 */
function remainingBackupCodes(entry: IAuditLogEntry): number | null {
  if (entry.action !== '2fa_backup_code_used') return null;
  const remaining = entry.metadata?.remaining;
  return typeof remaining === 'number' ? remaining : null;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function AuditLogPage() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [entries, setEntries] = useState<IAuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [filter, setFilter] = useState('');

  const loadAuditLog = useCallback(async () => {
    setLoading(true);
    setError(false);
    try {
      const params: { page: number; limit: number; action?: string } = {
        page,
        limit: 20,
      };
      if (filter) params.action = filter;
      const res = await getAuditLogApi(params);
      const auditResult = res.data;
      if (!auditResult.success) throw new Error('Failed to load audit log');
      setEntries(auditResult.data);
      setTotalPages(auditResult.pagination.totalPages);
    } catch {
      setError(true);
      toast({ title: 'Failed to load audit log', type: 'error' });
    } finally {
      setLoading(false);
    }
  }, [page, filter, toast]);

  useEffect(() => {
    void loadAuditLog();
  }, [loadAuditLog]);

  const handleFilterChange = useCallback((value: string) => {
    setFilter(value);
    setPage(1);
  }, []);

  const inputClass =
    'rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]';

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <button
          type="button"
          onClick={() => void navigate('/settings')}
          className="rounded-md p-2 text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
          aria-label="Back to settings"
        >
          <ArrowLeft className="h-5 w-5" />
        </button>
        <h1 className="flex items-center gap-2 text-2xl font-bold text-[hsl(var(--foreground))]">
          <FileText className="h-6 w-6" /> Audit Log
        </h1>
      </div>

      {/* Filter */}
      <div>
        <select
          value={filter}
          onChange={(e) => handleFilterChange(e.target.value)}
          className={inputClass}
          aria-label="Filter by action type"
        >
          <option value="">All Actions</option>
          {AUDIT_ACTIONS.map((action) => (
            <option key={action} value={action}>
              {ACTION_LABELS[action] ?? action}
            </option>
          ))}
        </select>
      </div>

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-[hsl(var(--primary))]" />
        </div>
      )}

      {/* Error with retry */}
      {!loading && error && (
        <div className="flex flex-col items-center justify-center rounded-lg border border-[hsl(var(--destructive)/0.3)] bg-[hsl(var(--destructive)/0.05)] p-12 text-center">
          <p className="text-sm font-medium text-[hsl(var(--destructive))]">
            Failed to load audit log
          </p>
          <button
            type="button"
            onClick={() => void loadAuditLog()}
            className="mt-3 inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
            Retry
          </button>
        </div>
      )}

      {/* Empty */}
      {!loading && !error && entries.length === 0 && (
        <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-12 text-center">
          <p className="text-[hsl(var(--muted-foreground))]">No audit log entries found.</p>
        </div>
      )}

      {/* Table */}
      {!loading && entries.length > 0 && (
        <>
          <div className="overflow-hidden rounded-lg border border-[hsl(var(--border))]">
            <table className="w-full text-sm" aria-label="Audit log entries">
              <thead className="bg-[hsl(var(--muted))]">
                <tr>
                  <th className="p-3 text-left font-medium text-[hsl(var(--foreground))]">
                    Action
                  </th>
                  <th className="hidden p-3 text-left font-medium text-[hsl(var(--foreground))] md:table-cell">
                    IP Address
                  </th>
                  <th className="hidden p-3 text-left font-medium text-[hsl(var(--foreground))] lg:table-cell">
                    User Agent
                  </th>
                  <th className="p-3 text-left font-medium text-[hsl(var(--foreground))]">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[hsl(var(--border))]">
                {entries.map((entry) => {
                  const remaining = remainingBackupCodes(entry);
                  return (
                    <tr
                      key={entry._id}
                      className="hover:bg-[hsl(var(--accent)/0.3)] transition-colors"
                    >
                      <td className="p-3">
                        <span
                          className={cn(
                            'inline-block rounded px-2 py-1 text-xs font-medium',
                            ACTION_COLORS[entry.action] ??
                              'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-400',
                          )}
                        >
                          {ACTION_LABELS[entry.action] ?? entry.action}
                        </span>
                        {remaining !== null && (
                          <span className="ml-2 text-xs text-[hsl(var(--muted-foreground))]">
                            {remaining} left
                          </span>
                        )}
                      </td>
                      <td className="hidden p-3 font-mono text-xs text-[hsl(var(--muted-foreground))] md:table-cell">
                        {entry.ipAddress}
                      </td>
                      <td className="hidden max-w-[200px] truncate p-3 text-xs text-[hsl(var(--muted-foreground))] lg:table-cell">
                        {entry.userAgent}
                      </td>
                      <td className="p-3 text-xs text-[hsl(var(--muted-foreground))]">
                        {new Date(entry.timestamp).toLocaleString()}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <Pagination
            page={page}
            totalPages={totalPages}
            label="audit log entries"
            onPageChange={setPage}
          />
        </>
      )}
    </div>
  );
}
