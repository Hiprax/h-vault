import { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import type zxcvbnType from 'zxcvbn';
import { getZxcvbn } from '../lib/lazyZxcvbn';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Copy,
  Clock,
  Key,
  Loader2,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  ExternalLink,
} from 'lucide-react';
import { useVaultStore, type DecryptedVaultItem } from '../stores/vaultStore';
import { checkBreachApi } from '../services/api/userApi';
import { cn } from '../lib/utils';

// Health check categories
interface HealthIssue {
  item: DecryptedVaultItem;
  reason: string;
  severity: 'critical' | 'warning' | 'info';
}

// Score card component
function ScoreCard({
  label,
  count,
  total,
  color,
}: {
  label: string;
  count: number;
  total: number;
  color: string;
}) {
  return (
    <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4">
      <p className="text-sm text-[hsl(var(--muted-foreground))]">{label}</p>
      <p className={cn('text-2xl font-bold', color)}>{count}</p>
      <p className="text-xs text-[hsl(var(--muted-foreground))]">of {total} items</p>
    </div>
  );
}

// Collapsible section
function HealthSection({
  title,
  icon: Icon,
  items,
  severity,
  onItemClick,
}: {
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  items: HealthIssue[];
  severity: 'critical' | 'warning' | 'info';
  onItemClick: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState(items.length > 0);
  const prevCount = useRef(items.length);

  // Findings can arrive after the first render (the weak-password check only
  // runs once zxcvbn has lazily loaded). The `useState` initializer above does
  // not re-run, so auto-expand on the 0 -> N transition; a section the user
  // collapsed by hand keeps its state, since its count does not change.
  useEffect(() => {
    if (prevCount.current === 0 && items.length > 0) setExpanded(true);
    prevCount.current = items.length;
  }, [items.length]);

  const severityColors = {
    critical: 'text-[hsl(var(--destructive))]',
    warning: 'text-yellow-600 dark:text-yellow-400',
    info: 'text-blue-600 dark:text-blue-400',
  };

  return (
    <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))]">
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center justify-between p-4 text-left"
      >
        <div className="flex items-center gap-3">
          <Icon className={cn('h-5 w-5', severityColors[severity])} />
          <span className="font-medium text-[hsl(var(--card-foreground))]">{title}</span>
          <span
            className={cn(
              'rounded-full px-2 py-0.5 text-xs font-medium',
              items.length === 0
                ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                : severity === 'critical'
                  ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                  : severity === 'warning'
                    ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                    : 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
            )}
          >
            {items.length}
          </span>
        </div>
        {expanded ? (
          <ChevronUp className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />
        ) : (
          <ChevronDown className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />
        )}
      </button>
      {expanded && items.length > 0 && (
        <div className="border-t border-[hsl(var(--border))] p-2">
          {items.map((issue) => (
            <button
              key={issue.item.id}
              type="button"
              onClick={() => onItemClick(issue.item.id)}
              className="flex w-full items-center justify-between rounded-md px-3 py-2 text-left hover:bg-[hsl(var(--accent))] transition-colors"
            >
              <div>
                <p className="text-sm font-medium text-[hsl(var(--card-foreground))]">
                  {issue.item.name}
                </p>
                <p className="text-xs text-[hsl(var(--muted-foreground))]">{issue.reason}</p>
              </div>
              <ExternalLink className="h-4 w-4 shrink-0 text-[hsl(var(--muted-foreground))]" />
            </button>
          ))}
        </div>
      )}
      {expanded && items.length === 0 && (
        <div className="border-t border-[hsl(var(--border))] p-4">
          <p className="text-sm text-green-600 dark:text-green-400">No issues found</p>
        </div>
      )}
    </div>
  );
}

export default function VaultHealthPage() {
  const items = useVaultStore((s) => s.items);
  const loading = useVaultStore((s) => s.loading);
  const fetchItems = useVaultStore((s) => s.fetchItems);
  const navigate = useNavigate();
  const [breachedItems, setBreachedItems] = useState<HealthIssue[]>([]);
  const [checkingBreaches, setCheckingBreaches] = useState(false);
  const [breachChecked, setBreachChecked] = useState(false);
  const initialFetchDone = useRef(false);
  const breachAbortRef = useRef<AbortController | null>(null);
  const [zxcvbnFn, setZxcvbnFn] = useState<typeof zxcvbnType | null>(null);

  useEffect(() => {
    void getZxcvbn().then((fn) => setZxcvbnFn(() => fn));
  }, []);

  // Fetch items if not loaded yet
  useEffect(() => {
    if (items.length === 0 && !loading && !initialFetchDone.current) {
      initialFetchDone.current = true;
      void fetchItems();
    }
  }, [items.length, loading, fetchItems]);

  // Abort breach check on unmount
  useEffect(() => {
    return () => {
      breachAbortRef.current?.abort();
    };
  }, []);

  // Get login items only
  const loginItems = useMemo(() => items.filter((i) => i.itemType === 'login'), [items]);

  // Weak passwords (zxcvbn score < 3)
  const weakPasswords = useMemo<HealthIssue[]>(() => {
    if (!zxcvbnFn) return [];
    const labels = ['Very weak', 'Weak', 'Fair'];
    const issues: HealthIssue[] = [];
    for (const item of loginItems) {
      const password = item.data.password as string | undefined;
      if (!password) continue;
      const result = zxcvbnFn(password);
      if (result.score < 3) {
        issues.push({
          item,
          reason: `Password strength: ${labels[result.score] ?? 'Very weak'}`,
          severity: 'critical',
        });
      }
    }
    return issues;
  }, [loginItems, zxcvbnFn]);

  // Reused passwords
  const reusedPasswords = useMemo<HealthIssue[]>(() => {
    const passwordMap = new Map<string, DecryptedVaultItem[]>();
    for (const item of loginItems) {
      const password = item.data.password as string | undefined;
      if (!password) continue;
      const existing = passwordMap.get(password) ?? [];
      existing.push(item);
      passwordMap.set(password, existing);
    }
    const issues: HealthIssue[] = [];
    for (const [, duplicates] of passwordMap) {
      if (duplicates.length > 1) {
        for (const item of duplicates) {
          issues.push({
            item,
            reason: `Password shared with ${duplicates.length - 1} other item(s)`,
            severity: 'warning',
          });
        }
      }
    }
    return issues;
  }, [loginItems]);

  // Old passwords (not updated in > 90 days)
  const oldPasswords = useMemo<HealthIssue[]>(() => {
    const ninetyDaysAgo = Date.now() - 90 * 24 * 60 * 60 * 1000;
    return loginItems
      .filter((item) => {
        const password = item.data.password as string | undefined;
        if (!password) return false;
        return new Date(item.updatedAt).getTime() < ninetyDaysAgo;
      })
      .map((item) => {
        const daysAgo = Math.floor(
          (Date.now() - new Date(item.updatedAt).getTime()) / (1000 * 60 * 60 * 24),
        );
        return { item, reason: `Last updated ${daysAgo} days ago`, severity: 'warning' as const };
      });
  }, [loginItems]);

  // Items missing TOTP
  const missingTotp = useMemo<HealthIssue[]>(() => {
    return loginItems
      .filter((item) => {
        const totp = item.data.totp as string | undefined;
        return !totp;
      })
      .map((item) => ({
        item,
        reason: 'No 2FA/TOTP configured',
        severity: 'info' as const,
      }));
  }, [loginItems]);

  // Calculate overall health score
  const healthScore = useMemo(() => {
    if (loginItems.length === 0) return 100;
    const breachedCount = breachChecked ? breachedItems.length : 0;
    const categories = breachChecked ? 4 : 3;
    const totalIssues =
      weakPasswords.length + reusedPasswords.length + oldPasswords.length + breachedCount;
    const maxPossibleIssues = loginItems.length * categories;
    const score = Math.max(0, Math.round(100 - (totalIssues / maxPossibleIssues) * 100));
    return score;
  }, [
    loginItems.length,
    weakPasswords.length,
    reusedPasswords.length,
    oldPasswords.length,
    breachChecked,
    breachedItems.length,
  ]);

  const scoreColor =
    healthScore >= 80
      ? 'text-green-600 dark:text-green-400'
      : healthScore >= 50
        ? 'text-yellow-600 dark:text-yellow-400'
        : 'text-[hsl(var(--destructive))]';
  const ScoreIcon = healthScore >= 80 ? ShieldCheck : healthScore >= 50 ? Shield : ShieldAlert;

  // Helper to check abort state; prevents TypeScript from narrowing the
  // readonly `aborted` property to `false` after an earlier branch.
  const isAborted = (c: AbortController): boolean => c.signal.aborted;

  // Breach check handler using SHA-1 k-anonymity
  const checkBreaches = useCallback(async () => {
    // Abort any previous check
    breachAbortRef.current?.abort();
    const controller = new AbortController();
    breachAbortRef.current = controller;

    setCheckingBreaches(true);
    setBreachedItems([]);
    const issues: HealthIssue[] = [];

    try {
      for (const item of loginItems) {
        if (isAborted(controller)) break;

        const password = item.data.password as string | undefined;
        if (!password) continue;

        // SHA-1 hash the password
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-1', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')
          .toUpperCase();
        const prefix = hashHex.substring(0, 5);

        if (isAborted(controller)) break;

        try {
          const response = await checkBreachApi(prefix);
          const result = response.data;
          if (result.success && typeof result.data === 'string') {
            const suffix = hashHex.substring(5);
            const lines = result.data.split('\r\n');
            for (const line of lines) {
              const [hashSuffix, countStr] = line.split(':');
              if (hashSuffix?.toUpperCase() === suffix) {
                const count = parseInt(countStr ?? '0', 10);
                issues.push({
                  item,
                  reason: `Found in ${count.toLocaleString()} data breach(es)`,
                  severity: 'critical',
                });
                break;
              }
            }
          }
        } catch {
          // Skip individual failures
        }

        // Add small delay to avoid overwhelming the API
        if (!isAborted(controller)) {
          await new Promise((resolve) => setTimeout(resolve, 200));
        }
      }
    } finally {
      // Only update state if not aborted (component still mounted)
      if (!isAborted(controller)) {
        setBreachedItems(issues);
        setCheckingBreaches(false);
        setBreachChecked(true);
      }
    }
  }, [loginItems]);

  const handleItemClick = useCallback(
    (id: string) => {
      void navigate(`/vault/${id}`);
    },
    [navigate],
  );

  if (loading) {
    return (
      <div className="mx-auto max-w-4xl">
        <div className="flex flex-col items-center justify-center py-20">
          <Loader2 className="h-8 w-8 animate-spin text-[hsl(var(--primary))]" />
          <p className="mt-3 text-sm text-[hsl(var(--muted-foreground))]">Loading vault items...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[hsl(var(--foreground))]">Vault Health</h1>
        <p className="mt-1 text-sm text-[hsl(var(--muted-foreground))]">
          Security analysis of your vault items
        </p>
      </div>

      {/* Overall score */}
      <div className="flex items-center gap-6 rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-6">
        <ScoreIcon className={cn('h-12 w-12', scoreColor)} />
        <div>
          <p className={cn('text-4xl font-bold', scoreColor)}>{healthScore}</p>
          <p className="text-sm text-[hsl(var(--muted-foreground))]">Health Score</p>
        </div>
      </div>

      {/* Score cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <ScoreCard
          label="Weak"
          count={weakPasswords.length}
          total={loginItems.length}
          color="text-[hsl(var(--destructive))]"
        />
        <ScoreCard
          label="Reused"
          count={reusedPasswords.length}
          total={loginItems.length}
          color="text-yellow-600 dark:text-yellow-400"
        />
        <ScoreCard
          label="Old"
          count={oldPasswords.length}
          total={loginItems.length}
          color="text-yellow-600 dark:text-yellow-400"
        />
        <ScoreCard
          label="No 2FA"
          count={missingTotp.length}
          total={loginItems.length}
          color="text-blue-600 dark:text-blue-400"
        />
      </div>

      {/* Detail sections */}
      <div className="space-y-3">
        <HealthSection
          title="Weak Passwords"
          icon={ShieldAlert}
          items={weakPasswords}
          severity="critical"
          onItemClick={handleItemClick}
        />
        <HealthSection
          title="Reused Passwords"
          icon={Copy}
          items={reusedPasswords}
          severity="warning"
          onItemClick={handleItemClick}
        />
        <HealthSection
          title="Old Passwords"
          icon={Clock}
          items={oldPasswords}
          severity="warning"
          onItemClick={handleItemClick}
        />
        <HealthSection
          title="Missing 2FA"
          icon={Key}
          items={missingTotp}
          severity="info"
          onItemClick={handleItemClick}
        />

        {/* Breach detection section */}
        <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))]">
          <div className="flex items-center justify-between p-4">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-5 w-5 text-[hsl(var(--destructive))]" />
              <span className="font-medium text-[hsl(var(--card-foreground))]">
                Breached Passwords
              </span>
              {breachChecked && (
                <span
                  className={cn(
                    'rounded-full px-2 py-0.5 text-xs font-medium',
                    breachedItems.length === 0
                      ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                      : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
                  )}
                >
                  {breachedItems.length}
                </span>
              )}
            </div>
            <button
              type="button"
              onClick={() => void checkBreaches()}
              disabled={checkingBreaches}
              className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-3 py-1.5 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors disabled:opacity-50"
            >
              {checkingBreaches ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" /> Checking...
                </>
              ) : (
                <>
                  <RefreshCw className="h-4 w-4" /> Check for Breaches
                </>
              )}
            </button>
          </div>
          {breachChecked && breachedItems.length > 0 && (
            <div className="border-t border-[hsl(var(--border))] p-2">
              {breachedItems.map((issue) => (
                <button
                  key={issue.item.id}
                  type="button"
                  onClick={() => handleItemClick(issue.item.id)}
                  className="flex w-full items-center justify-between rounded-md px-3 py-2 text-left hover:bg-[hsl(var(--accent))] transition-colors"
                >
                  <div>
                    <p className="text-sm font-medium text-[hsl(var(--card-foreground))]">
                      {issue.item.name}
                    </p>
                    <p className="text-xs text-[hsl(var(--destructive))]">{issue.reason}</p>
                  </div>
                  <ExternalLink className="h-4 w-4 shrink-0 text-[hsl(var(--muted-foreground))]" />
                </button>
              ))}
            </div>
          )}
          {breachChecked && breachedItems.length === 0 && (
            <div className="border-t border-[hsl(var(--border))] p-4">
              <p className="text-sm text-green-600 dark:text-green-400">
                No breached passwords found
              </p>
            </div>
          )}
          {!breachChecked && !checkingBreaches && (
            <div className="border-t border-[hsl(var(--border))] p-4">
              <p className="text-sm text-[hsl(var(--muted-foreground))]">
                Click &quot;Check for Breaches&quot; to scan your passwords against known data
                breaches using the k-anonymity model.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
