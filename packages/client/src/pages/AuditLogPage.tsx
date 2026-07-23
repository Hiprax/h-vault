import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, FileText, ChevronLeft, ChevronRight, Loader2, RefreshCw } from 'lucide-react';
import { cn } from '../lib/utils';
import { useToast } from '../components/ui/Toast';
import { getAuditLogApi } from '../services/api/userApi';
import type { IAuditLogEntry } from '@hvault/shared';
import { AUDIT_ACTIONS } from '@hvault/shared';

// ---------------------------------------------------------------------------
// Action styling
// ---------------------------------------------------------------------------

const ACTION_COLORS: Record<string, string> = {
  login: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
  login_failed: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
  logout: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-400',
  password_change: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400',
  '2fa_enable': 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
  '2fa_disable': 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
  item_create: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400',
  item_update: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400',
  item_delete: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
  export: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400',
  import: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400',
  session_revoke: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
  vault_lock: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-400',
  vault_unlock: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
  backup_triggered: 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-400',
  backup_sent: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
  backup_failed: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
  backup_restored: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
  backup_password_changed:
    'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400',
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
};

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
                {entries.map((entry) => (
                  <tr
                    key={entry._id}
                    className="hover:bg-[hsl(var(--accent)/0.3)] transition-colors"
                  >
                    <td className="p-3">
                      <span
                        className={cn(
                          'inline-block rounded px-2 py-1 text-xs font-medium',
                          ACTION_COLORS[entry.action] ??
                            'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-400',
                        )}
                      >
                        {ACTION_LABELS[entry.action] ?? entry.action}
                      </span>
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
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between">
            <span className="text-sm text-[hsl(var(--muted-foreground))]">
              Page {page} of {totalPages}
            </span>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="inline-flex items-center gap-1 rounded-md border border-[hsl(var(--input))] px-3 py-1.5 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] disabled:opacity-50 transition-colors"
              >
                <ChevronLeft className="h-4 w-4" /> Prev
              </button>
              <button
                type="button"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="inline-flex items-center gap-1 rounded-md border border-[hsl(var(--input))] px-3 py-1.5 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] disabled:opacity-50 transition-colors"
              >
                Next <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
