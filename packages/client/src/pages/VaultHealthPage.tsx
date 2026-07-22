import { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { List } from 'react-window';
import type { RowComponentProps } from 'react-window';
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
import { useVaultStore, getHealthGeneration, type DecryptedVaultItem } from '../stores/vaultStore';
import { useAuthStore } from '../stores/authStore';
import { analyzeStrength, type StrengthEntry } from '../services/health/strengthAnalyzer';
import { WEAK_SCORE_THRESHOLD } from '../services/health/passwordStrength';
import { setScore, strengthCacheKey } from '../services/health/strengthCache';
import {
  runBreachCheck,
  type BreachCheckResult,
  type BreachFinding,
} from '../services/health/breachCheck';
import {
  loadHealthResults,
  saveBreachResults,
  saveStrengthScores,
  type HealthResultsPayload,
  type BreachSaveEntry,
  type StrengthSaveEntry,
} from '../services/health/healthResultsStore';
import { cn } from '../lib/utils';

// Health check categories
interface HealthIssue {
  item: DecryptedVaultItem;
  reason: string;
  severity: 'critical' | 'warning' | 'info';
}

// ---------------------------------------------------------------------------
// Finding lists (virtualized above a threshold, like the main vault list)
// ---------------------------------------------------------------------------

const FINDING_ROW_HEIGHT = 60;
const FINDING_ROW_GAP = 4;
const FINDING_ROW_TOTAL_HEIGHT = FINDING_ROW_HEIGHT + FINDING_ROW_GAP;
const FINDING_VIRTUALIZATION_THRESHOLD = 50;
// Cap the virtualized list height so a section with thousands of findings scrolls
// inside a bounded panel rather than growing the page unboundedly.
const FINDING_LIST_MAX_HEIGHT = 480;

const DEFAULT_REASON_CLASS = 'text-[hsl(var(--muted-foreground))]';

function FindingButton({
  issue,
  onItemClick,
  reasonClassName,
}: {
  issue: HealthIssue;
  onItemClick: (id: string) => void;
  reasonClassName: string;
}) {
  return (
    <button
      type="button"
      onClick={() => onItemClick(issue.item.id)}
      className="flex h-full w-full items-center justify-between rounded-md px-3 py-2 text-left hover:bg-[hsl(var(--accent))] transition-colors"
    >
      <div className="min-w-0">
        <p className="truncate text-sm font-medium text-[hsl(var(--card-foreground))]">
          {issue.item.name}
        </p>
        <p className={cn('truncate text-xs', reasonClassName)}>{issue.reason}</p>
      </div>
      <ExternalLink className="h-4 w-4 shrink-0 text-[hsl(var(--muted-foreground))]" />
    </button>
  );
}

interface FindingRowData {
  issues: HealthIssue[];
  onItemClick: (id: string) => void;
  reasonClassName: string;
}

function VirtualizedFindingRow(props: RowComponentProps<FindingRowData>) {
  const { index, style, ariaAttributes, issues, onItemClick, reasonClassName } = props;
  const issue = issues[index];
  if (!issue) return null;
  return (
    <div style={{ ...style, paddingBottom: FINDING_ROW_GAP }} {...ariaAttributes}>
      <FindingButton issue={issue} onItemClick={onItemClick} reasonClassName={reasonClassName} />
    </div>
  );
}

/**
 * Renders a list of findings. Above {@link FINDING_VIRTUALIZATION_THRESHOLD} it
 * windows the rows with react-window (bounded, scrollable) so a vault where most
 * passwords are flagged does not render thousands of DOM nodes at once.
 */
function FindingList({
  issues,
  onItemClick,
  reasonClassName,
}: {
  issues: HealthIssue[];
  onItemClick: (id: string) => void;
  reasonClassName?: string;
}) {
  const resolvedReasonClass = reasonClassName ?? DEFAULT_REASON_CLASS;

  if (issues.length > FINDING_VIRTUALIZATION_THRESHOLD) {
    const height = Math.min(issues.length * FINDING_ROW_TOTAL_HEIGHT, FINDING_LIST_MAX_HEIGHT);
    const rowData: FindingRowData = {
      issues,
      onItemClick,
      reasonClassName: resolvedReasonClass,
    };
    return (
      <List<FindingRowData>
        aria-label="Findings"
        style={{ height }}
        rowComponent={VirtualizedFindingRow}
        rowCount={issues.length}
        rowHeight={FINDING_ROW_TOTAL_HEIGHT}
        rowProps={rowData}
        overscanCount={5}
        role="list"
      />
    );
  }

  return (
    <div className="space-y-1" role="list">
      {issues.map((issue, index) => (
        <div
          key={issue.item.id}
          role="listitem"
          aria-setsize={issues.length}
          aria-posinset={index + 1}
        >
          <FindingButton
            issue={issue}
            onItemClick={onItemClick}
            reasonClassName={resolvedReasonClass}
          />
        </div>
      ))}
    </div>
  );
}

// Score card component
function ScoreCard({
  label,
  count,
  total,
  color,
  loading = false,
  failed = false,
}: {
  label: string;
  count: number;
  total: number;
  color: string;
  loading?: boolean;
  failed?: boolean;
}) {
  return (
    <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4">
      <p className="text-sm text-[hsl(var(--muted-foreground))]">{label}</p>
      {loading ? (
        <Loader2
          className={cn('my-1 h-6 w-6 animate-spin', color)}
          aria-label={`Analyzing ${label}`}
        />
      ) : failed ? (
        // Analysis could not complete — show a warning, never a (misleading) zero.
        <AlertTriangle
          className="my-1 h-6 w-6 text-yellow-600 dark:text-yellow-400"
          aria-label={`${label} analysis failed`}
        />
      ) : (
        <p className={cn('text-2xl font-bold', color)}>{count}</p>
      )}
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
  isAnalyzing = false,
  analysisFailed = false,
}: {
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  items: HealthIssue[];
  severity: 'critical' | 'warning' | 'info';
  onItemClick: (id: string) => void;
  isAnalyzing?: boolean;
  analysisFailed?: boolean;
}) {
  const [expanded, setExpanded] = useState(items.length > 0);
  const prevCount = useRef(items.length);

  // Findings can arrive after the first render (the weak-password check only
  // resolves once the Web Worker has scored the vault). The `useState` initializer
  // above does not re-run, so auto-expand on the 0 -> N transition; a section the
  // user collapsed by hand keeps its state, since its count does not change.
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
              analysisFailed
                ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                : items.length === 0
                  ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                  : severity === 'critical'
                    ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                    : severity === 'warning'
                      ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                      : 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
            )}
          >
            {analysisFailed ? '!' : items.length}
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
          <FindingList issues={items} onItemClick={onItemClick} />
        </div>
      )}
      {expanded && items.length === 0 && (
        <div className="border-t border-[hsl(var(--border))] p-4">
          {isAnalyzing ? (
            <p className="flex items-center gap-2 text-sm text-[hsl(var(--muted-foreground))]">
              <Loader2 className="h-4 w-4 animate-spin" /> Analyzing…
            </p>
          ) : analysisFailed ? (
            <p className="flex items-center gap-2 text-sm text-yellow-700 dark:text-yellow-400">
              <AlertTriangle className="h-4 w-4 shrink-0" /> Could not analyze password strength.
              Reload the page to try again.
            </p>
          ) : (
            <p className="text-sm text-green-600 dark:text-green-400">No issues found</p>
          )}
        </div>
      )}
    </div>
  );
}

/** Human-friendly relative time for the "Last checked" label. */
export function formatLastChecked(ts: number): string {
  const diff = Date.now() - ts;
  const MIN = 60_000;
  const HOUR = 3_600_000;
  const DAY = 86_400_000;
  if (diff < MIN) return 'just now';
  if (diff < HOUR) return `${String(Math.floor(diff / MIN))} min ago`;
  if (diff < DAY) return `${String(Math.floor(diff / HOUR))} h ago`;
  return `${String(Math.floor(diff / DAY))} d ago`;
}

/**
 * Rebuild a BreachCheckResult from a persisted snapshot, joining ONLY against the
 * current login items and only where the stored version matches the item's
 * `updatedAt` (a stale/edited item is treated as unchecked). Returns null when no
 * breach scan has ever completed, so the UI keeps the un-checked state.
 *
 * A password the snapshot does not cover — an item added or edited since the scan —
 * MUST be counted into `failedCount`, never dropped. Dropping it made a snapshot of
 * two clean logins render "No breached passwords found" after 500 more were
 * imported: the green all-clear is gated on `failedCount === 0`, and a persisted
 * `breachFailedCount` is always 0 by construction (a scan is only persisted when it
 * fully succeeded). An unchecked password must never be presented as a safe one.
 */
export function reconstructBreachResult(
  payload: HealthResultsPayload,
  items: readonly DecryptedVaultItem[],
): BreachCheckResult | null {
  if (payload.scanCompletedAt === null) return null;
  const breached: BreachFinding[] = [];
  let checkedCount = 0;
  let unverifiedCount = 0;
  for (const item of items) {
    const password = typeof item.data.password === 'string' ? item.data.password : '';
    if (!password) continue;
    const datum = payload.perItem[item.id];
    if (datum?.v !== item.updatedAt) {
      unverifiedCount++;
      continue;
    }
    checkedCount++;
    if (datum.breach !== undefined && datum.breach > 0) {
      breached.push({ item, count: datum.breach });
    }
  }
  const failedCount = payload.breachFailedCount + unverifiedCount;
  return {
    breached,
    totalCount: checkedCount + failedCount,
    checkedCount,
    failedCount,
  };
}

export default function VaultHealthPage() {
  const items = useVaultStore((s) => s.items);
  const loading = useVaultStore((s) => s.loading);
  const fetchItems = useVaultStore((s) => s.fetchItems);
  const navigate = useNavigate();

  const [weakPasswords, setWeakPasswords] = useState<HealthIssue[]>([]);
  const [analyzingStrength, setAnalyzingStrength] = useState(false);
  const [strengthFailed, setStrengthFailed] = useState(false);

  const [breachResult, setBreachResult] = useState<BreachCheckResult | null>(null);
  const [checkingBreaches, setCheckingBreaches] = useState(false);
  const [breachProgress, setBreachProgress] = useState<{ processed: number; total: number }>({
    processed: 0,
    total: 0,
  });
  const initialFetchDone = useRef(false);
  const breachAbortRef = useRef<AbortController | null>(null);

  // Persisted (encrypted) results survive refresh / browser close. `hydrated`
  // gates the weak-strength effect so the primed strength cache is read first.
  const [hydrated, setHydrated] = useState(false);
  const [lastCheckedAt, setLastCheckedAt] = useState<number | null>(null);

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

  // A ref mirror of loginItems so the hydration effect can read the current list
  // WITHOUT depending on it — hydration must run once after load, never re-run on
  // every item change (which would overwrite a fresh scan with persisted data).
  const loginItemsRef = useRef(loginItems);
  loginItemsRef.current = loginItems;

  // Hydrate the persisted, encrypted health snapshot after unlock so a refresh or
  // browser-close does not force a re-scan. Runs once the vault has finished
  // loading. Guarded by the health generation so a lock landing mid-load cannot
  // repopulate results into a cleared session.
  useEffect(() => {
    if (loading) return;
    const { user, vaultKey } = useAuthStore.getState();
    if (!user?.userId || !vaultKey) {
      setHydrated(true);
      return;
    }
    const generation = getHealthGeneration();
    let cancelled = false;
    void loadHealthResults(user.userId, vaultKey)
      .then((payload) => {
        if (cancelled || generation !== getHealthGeneration()) return;
        if (payload) {
          // Prime the in-memory strength cache so the weak-password effect
          // resolves instantly from cache instead of re-running the worker.
          for (const item of loginItemsRef.current) {
            const datum = payload.perItem[item.id];
            if (datum?.v === item.updatedAt && datum.strength !== undefined) {
              setScore(strengthCacheKey(item.id, item.updatedAt), datum.strength);
            }
          }
          const reconstructed = reconstructBreachResult(payload, loginItemsRef.current);
          if (reconstructed) setBreachResult(reconstructed);
          setLastCheckedAt(payload.scanCompletedAt);
        }
      })
      .finally(() => {
        if (!cancelled) setHydrated(true);
      });
    return () => {
      cancelled = true;
    };
  }, [loading]);

  // Weak passwords (zxcvbn score below the weak threshold), scored OFF the main
  // thread in a Web Worker so a large vault never freezes the page. Runs once the
  // vault has finished loading; the analyzer caches per item + version, so the
  // occasional re-run after an edit only rescores what changed.
  useEffect(() => {
    if (loading || !hydrated) return;

    const entries: StrengthEntry[] = [];
    for (const item of loginItems) {
      const password = typeof item.data.password === 'string' ? item.data.password : '';
      if (!password) continue;
      entries.push({ id: item.id, password, version: item.updatedAt });
    }

    if (entries.length === 0) {
      setWeakPasswords([]);
      setAnalyzingStrength(false);
      setStrengthFailed(false);
      return;
    }

    const controller = new AbortController();
    const generation = getHealthGeneration();
    setAnalyzingStrength(true);
    setStrengthFailed(false);
    void analyzeStrength(entries, { signal: controller.signal })
      .then((scores) => {
        if (controller.signal.aborted) return;
        const labels = ['Very weak', 'Weak', 'Fair'];
        const issues: HealthIssue[] = [];
        for (const item of loginItems) {
          const score = scores.get(item.id);
          if (score === undefined) continue;
          if (score < WEAK_SCORE_THRESHOLD) {
            issues.push({
              item,
              reason: `Password strength: ${labels[score] ?? 'Very weak'}`,
              severity: 'critical',
            });
          }
        }
        setWeakPasswords(issues);
        setAnalyzingStrength(false);

        // Persist the computed strength scores (encrypted) so the weak-password
        // findings survive a refresh. Guarded by the health generation so a lock
        // during analysis cannot write results into a cleared session.
        if (generation === getHealthGeneration()) {
          const { user, vaultKey } = useAuthStore.getState();
          if (user?.userId && vaultKey) {
            const strengthEntries: StrengthSaveEntry[] = [];
            for (const item of loginItems) {
              const score = scores.get(item.id);
              if (score !== undefined) {
                strengthEntries.push({ id: item.id, v: item.updatedAt, strength: score });
              }
            }
            if (strengthEntries.length > 0) {
              void saveStrengthScores(user.userId, vaultKey, strengthEntries);
            }
          }
        }
      })
      .catch(() => {
        if (controller.signal.aborted) return;
        // Analysis failed entirely (e.g. the worker AND the lazy zxcvbn fallback
        // both errored — a stale chunk hash after a deploy, offline, a blocked
        // request). Surface it as a failure, NEVER as a clean "no issues found":
        // this page is a security signal and must not report safe on no data.
        setAnalyzingStrength(false);
        setStrengthFailed(true);
      });

    return () => controller.abort();
  }, [loginItems, loading, hydrated]);

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

  const breachChecked = breachResult !== null;

  // Breached findings map back to every item sharing a breached password.
  const breachedIssues = useMemo<HealthIssue[]>(() => {
    if (!breachResult) return [];
    return breachResult.breached.map(({ item, count }) => ({
      item,
      reason: `Found in ${count.toLocaleString()} data breach(es)`,
      severity: 'critical' as const,
    }));
  }, [breachResult]);

  // Calculate overall health score
  const healthScore = useMemo(() => {
    if (loginItems.length === 0) return 100;
    const breachedCount = breachChecked ? breachedIssues.length : 0;
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
    breachedIssues.length,
  ]);

  const scoreColor =
    healthScore >= 80
      ? 'text-green-600 dark:text-green-400'
      : healthScore >= 50
        ? 'text-yellow-600 dark:text-yellow-400'
        : 'text-[hsl(var(--destructive))]';
  const ScoreIcon = healthScore >= 80 ? ShieldCheck : healthScore >= 50 ? Shield : ShieldAlert;

  // Breach check handler — deduplicates passwords, checks them in batches with a
  // determinate progress indicator, and reports any that could NOT be checked
  // rather than passing them off as safe.
  const checkBreaches = useCallback(async () => {
    breachAbortRef.current?.abort();
    const controller = new AbortController();
    breachAbortRef.current = controller;
    const generation = getHealthGeneration();

    setCheckingBreaches(true);
    setBreachProgress({ processed: 0, total: 0 });

    try {
      const result = await runBreachCheck(loginItems, {
        signal: controller.signal,
        onProgress: (processed, total) => {
          if (!controller.signal.aborted) setBreachProgress({ processed, total });
        },
      });
      if (controller.signal.aborted) return;
      setBreachResult(result);
      const completedAt = Date.now();
      setLastCheckedAt(completedAt);

      // Persist (encrypted) so results survive refresh / browser close. This runs
      // ONLY after a FULLY successful scan (no unchecked passwords), so a failed or
      // aborted run keeps the previous persisted result and we never persist a
      // not-actually-checked item as "clean". Guarded by the health generation so a
      // lock mid-scan cannot write into a cleared session.
      if (result.failedCount === 0 && generation === getHealthGeneration()) {
        const { user, vaultKey } = useAuthStore.getState();
        if (user?.userId && vaultKey) {
          const countById = new Map(result.breached.map((b) => [b.item.id, b.count]));
          const breachEntries: BreachSaveEntry[] = [];
          for (const item of loginItems) {
            const password = typeof item.data.password === 'string' ? item.data.password : '';
            if (!password) continue;
            const count = countById.get(item.id);
            breachEntries.push({
              id: item.id,
              v: item.updatedAt,
              ...(count !== undefined ? { breach: count } : {}),
            });
          }
          void saveBreachResults(
            user.userId,
            vaultKey,
            breachEntries,
            result.failedCount,
            completedAt,
          );
        }
      }
    } finally {
      if (!controller.signal.aborted) setCheckingBreaches(false);
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

  const breachProgressPct =
    breachProgress.total > 0
      ? Math.round((breachProgress.processed / breachProgress.total) * 100)
      : 0;

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
          loading={analyzingStrength}
          failed={strengthFailed}
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
          isAnalyzing={analyzingStrength}
          analysisFailed={strengthFailed}
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
                    breachedIssues.length === 0
                      ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                      : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
                  )}
                >
                  {breachedIssues.length}
                </span>
              )}
              {lastCheckedAt !== null && (
                <span className="text-xs text-[hsl(var(--muted-foreground))]">
                  Last checked {formatLastChecked(lastCheckedAt)}
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

          {/* Determinate progress while a scan runs */}
          {checkingBreaches && (
            <div className="space-y-2 border-t border-[hsl(var(--border))] p-4">
              <div className="flex items-center justify-between text-sm text-[hsl(var(--muted-foreground))]">
                <span>Checking your unique passwords…</span>
                <span className="tabular-nums">
                  {breachProgress.total > 0
                    ? `${breachProgress.processed} / ${breachProgress.total}`
                    : '…'}
                </span>
              </div>
              <div
                className="h-2 w-full overflow-hidden rounded-full bg-[hsl(var(--muted))]"
                role="progressbar"
                aria-valuemin={0}
                aria-valuemax={breachProgress.total}
                aria-valuenow={breachProgress.processed}
                aria-label="Breach check progress"
              >
                <div
                  className="h-full bg-[hsl(var(--primary))] transition-[width] duration-300"
                  style={{ width: `${breachProgressPct}%` }}
                />
              </div>
            </div>
          )}

          {/* Partial-result warning: some passwords could not be checked. Covers a
              failed lookup during a live scan AND a password the restored snapshot
              never covered (added or edited since it was taken). */}
          {!checkingBreaches && breachResult && breachResult.failedCount > 0 && (
            <div className="border-t border-[hsl(var(--border))] p-4">
              <p className="flex items-center gap-2 text-sm text-yellow-700 dark:text-yellow-400">
                <AlertTriangle className="h-4 w-4 shrink-0" />
                {breachResult.failedCount.toLocaleString()} password(s) could not be checked. Run a
                fresh check to verify them.
              </p>
            </div>
          )}

          {!checkingBreaches && breachChecked && breachedIssues.length > 0 && (
            <div className="border-t border-[hsl(var(--border))] p-2">
              <FindingList
                issues={breachedIssues}
                onItemClick={handleItemClick}
                reasonClassName="text-[hsl(var(--destructive))]"
              />
            </div>
          )}
          {!checkingBreaches &&
            breachChecked &&
            breachedIssues.length === 0 &&
            breachResult.failedCount === 0 && (
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
