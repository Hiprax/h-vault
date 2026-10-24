import { useCallback, useEffect, useRef, useState } from 'react';
import { Loader2, Save } from 'lucide-react';
import { formatBytes } from '@hvault/shared';
import { useBeforeUnloadWarning } from '../../hooks/useBeforeUnloadWarning';
import { getApiErrorMessage } from '../../lib/utils';
import { getDocumentUsageApi } from '../../services/api/documentsApi';
import { getProfileApi } from '../../services/api/userApi';
import type { FullBackupProgress, FullBackupResult } from '../../services/backup/createFullBackup';
import { loadFullBackupJob } from '../../services/backup/loadFullBackupJob';
import { completeBwkWrapper, unwrapBwk } from '../../services/crypto/backupKeyCopy';
import { cryptoService } from '../../services/crypto/cryptoService';
import { useToast } from '../ui/Toast';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/Dialog';
import { BackupPasswordPrompt } from './BackupPasswordPrompt';
import { WaitNotice } from './WaitNotice';

/**
 * The Full Backup panel: the vault and every document, saved here as one signed,
 * encrypted file (`.hvbackup`), never emailed.
 *
 * Its steps are its states: the backup password (which only derives the signing
 * key; the raw backup wrapping key is zeroed at once), ready, running, then done
 * or failed. Four things about it are load-bearing:
 *
 *   * **The save dialog opens on the Save click itself**, before any await, so the
 *     engine is loaded at Continue and the click only opens the target.
 *   * **An interrupted run saves nothing.** Stop, a lock, sign-out or leaving the
 *     page discards the file; a backup that might pass for complete is the one
 *     thing this must never write.
 *   * **The live region is mounted from the first render**, only its text
 *     changes, and it says one sentence when a run starts and one when it ends.
 *   * **The idle auto-lock waits while it runs in a visible tab** (the engine
 *     records its own progress); the panel says so before the start.
 */

type FullBackupJob = Awaited<ReturnType<typeof loadFullBackupJob>>;
type SavedBackup = Extract<FullBackupResult, { saved: true }>;

type PanelState =
  | { kind: 'password' }
  | { kind: 'ready'; estimateBytes: number | null; inMemory: boolean; lockOnHidden: boolean }
  | { kind: 'running'; progress: FullBackupProgress | null }
  | { kind: 'done'; result: SavedBackup }
  | { kind: 'failed'; message: string; ran: boolean };

/** What the panel says before a run starts, about the auto-lock and about leaving. */
const FULL_BACKUP_PAUSE_STATEMENT =
  'While it runs, this tab will not lock by itself as long as it stays open in front of you and the backup keeps making progress. Lock the vault yourself if you step away; that stops the backup and nothing is saved. Keep this page open until it finishes.';

interface FullBackupPanelProps {
  inputClass: string;
  /** Close the panel. */
  onClose: () => void;
  /** Told when a run starts and when it ends, so the page can hold its other buttons. */
  onRunningChange: (running: boolean) => void;
  /** A run ended: the vault download it began with wrote a history row. */
  onFinished: () => void;
}

/** The one sentence a saved backup is reported with. */
function savedSentence(result: SavedBackup): string {
  const where =
    result.kind === 'file'
      ? `saved as ${result.fileName}`
      : `handed to your browser's downloads as ${result.fileName}`;
  return `Full backup ${where} (${formatBytes(result.bytes)}): ${String(result.itemCount)} item(s), ${String(result.folderCount)} folder(s) and ${String(result.documentCount)} document(s).`;
}

/** The line under the bar while a run is going. */
function progressLine(progress: FullBackupProgress | null): string {
  if (progress === null || progress.phase === 'vault') return 'Downloading your vault…';
  if (progress.phase === 'finishing') return 'Finishing the file…';
  return `Reading document ${String(progress.index)} of ${String(progress.total)}: ${progress.name} (${formatBytes(progress.bytesRead)} read so far)`;
}

export function FullBackupPanel({
  inputClass,
  onClose,
  onRunningChange,
  onFinished,
}: FullBackupPanelProps) {
  const { toast } = useToast();
  const [state, setState] = useState<PanelState>({ kind: 'password' });
  const [password, setPassword] = useState('');
  const [checking, setChecking] = useState(false);
  const checkingRef = useRef(false);
  const [confirmingStop, setConfirmingStop] = useState(false);
  const jobRef = useRef<FullBackupJob | null>(null);
  const signingKeyRef = useRef<CryptoKey | null>(null);
  const controllerRef = useRef<AbortController | null>(null);
  // Set from the Save click until the run has settled, so a double press cannot
  // start a second run.
  const busyRef = useRef(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      // Leaving the page ends the run, and the run then saves nothing.
      controllerRef.current?.abort('left');
      signingKeyRef.current = null;
    };
  }, []);

  useBeforeUnloadWarning(state.kind === 'running');

  const handleContinue = useCallback(async () => {
    // A ref, so a second press inside one frame cannot start a second unwrap.
    if (!password || checkingRef.current) return;
    checkingRef.current = true;
    setChecking(true);
    let bwk: ArrayBuffer | null = null;
    try {
      const job = await loadFullBackupJob();
      const profile = (await getProfileApi()).data;
      if (!profile.success) throw new Error('Failed to load profile');
      const backup = profile.data.settings.backup;
      const wrapper = backup.isConfigured ? completeBwkWrapper(backup) : null;
      if (!wrapper) {
        toast({ title: 'Backup encryption is not configured', type: 'error' });
        return;
      }
      bwk = await unwrapBwk(wrapper, password);
      if (!bwk) {
        toast({ title: 'Incorrect backup password', type: 'error' });
        return;
      }
      signingKeyRef.current = await job.deriveFullBackupSigningKey(bwk);
      // Zeroed at once, before the estimate's request below can keep it waiting.
      cryptoService.clearKey(bwk);
      bwk = null;
      jobRef.current = job;
      // An estimate only: the server counts the trash too, which a full backup
      // leaves out, so the file is at most this plus the vault.
      let estimateBytes: number | null = null;
      try {
        const usage = (await getDocumentUsageApi()).data;
        if (usage.success) estimateBytes = usage.data.usedBytes;
      } catch {
        // No estimate is shown; the backup itself does not depend on it.
      }
      setState({
        kind: 'ready',
        estimateBytes,
        inMemory: !job.hasSaveDialog(),
        lockOnHidden: profile.data.settings.lockOnHidden,
      });
    } catch (err) {
      toast({
        title: 'Could not prepare the full backup',
        description: getApiErrorMessage(err, 'An unexpected error occurred. Please try again.'),
        type: 'error',
      });
    } finally {
      // The raw wrapping key and the typed password, on every exit.
      if (bwk) cryptoService.clearKey(bwk);
      setPassword('');
      checkingRef.current = false;
      setChecking(false);
    }
  }, [password, toast]);

  /** Start the run. Synchronous up to `openFullBackupTarget`, for the save dialog. */
  const handleSave = useCallback(() => {
    const job = jobRef.current;
    const signingKey = signingKeyRef.current;
    if (busyRef.current || job === null || signingKey === null) return;
    busyRef.current = true;
    const controller = new AbortController();
    controllerRef.current = controller;

    const settle = (result: FullBackupResult): void => {
      busyRef.current = false;
      // One run per password: a second run asks for it again.
      signingKeyRef.current = null;
      onRunningChange(false);
      onFinished();
      if (!mountedRef.current) return;
      // A Stop asked for while the run was ending has nothing left to stop.
      setConfirmingStop(false);
      setState(
        result.saved
          ? { kind: 'done', result }
          : { kind: 'failed', message: result.message, ran: true },
      );
    };

    void job.openFullBackupTarget(new Date()).then(
      async (target) => {
        if (target === null) {
          // The save dialog was dismissed: nothing started.
          busyRef.current = false;
          return;
        }
        if (controller.signal.aborted) {
          await target.discard();
          return;
        }
        onRunningChange(true);
        setState({ kind: 'running', progress: null });
        settle(
          await job.createFullBackup(target, {
            signal: controller.signal,
            signingKey,
            onProgress: (progress) => {
              setState((current) =>
                current.kind === 'running' ? { kind: 'running', progress } : current,
              );
            },
          }),
        );
      },
      (error: unknown) => {
        busyRef.current = false;
        setState({
          kind: 'failed',
          message: getApiErrorMessage(error, 'The save dialog could not be opened.'),
          ran: false,
        });
      },
    );
  }, [onFinished, onRunningChange]);

  const stop = useCallback(() => {
    setConfirmingStop(false);
    controllerRef.current?.abort('stopped');
  }, []);

  const status =
    state.kind === 'running'
      ? 'Making a full backup. Keep this page open until it finishes.'
      : state.kind === 'done'
        ? savedSentence(state.result)
        : state.kind === 'failed'
          ? `${state.message} Nothing was saved.`
          : '';

  const progress = state.kind === 'running' ? state.progress : null;

  return (
    <div
      data-testid="full-backup-panel"
      className="mt-4 space-y-3 rounded-md border border-[hsl(var(--input))] p-4"
    >
      <p className="text-sm font-medium text-[hsl(var(--foreground))]">Full Backup</p>

      {/* Mounted from the panel's first render; only the text inside it changes. */}
      <p
        role="status"
        data-testid="full-backup-status"
        className={status === '' ? 'sr-only' : 'text-sm font-medium text-[hsl(var(--foreground))]'}
      >
        {status}
      </p>

      {state.kind === 'password' && (
        <BackupPasswordPrompt
          description="Enter your backup password. It signs the full backup, so a restore can check that the file was not changed."
          value={password}
          onChange={setPassword}
          onSubmit={() => void handleContinue()}
          onCancel={onClose}
          submitLabel="Continue"
          busyLabel="Checking..."
          busy={checking}
          inputClass={inputClass}
          inputLabel="Backup password for the full backup"
        />
      )}

      {state.kind === 'ready' && (
        <div className="space-y-2 text-xs text-[hsl(var(--muted-foreground))]">
          {state.estimateBytes !== null && (
            <p>
              {`Your documents take up to ${formatBytes(state.estimateBytes)}, so the file is about that size plus your vault.`}
            </p>
          )}
          {state.inMemory && (
            <p>
              This browser has no save dialog, so the backup is built in memory first and is limited
              to 512 MB. Desktop Chrome or Edge save straight to disk, with no such limit.
            </p>
          )}
          {state.lockOnHidden && (
            <p>
              Your vault locks when this tab stays hidden, and a lock stops the backup. Keep this
              tab in front of you until it finishes.
            </p>
          )}
          <p>{FULL_BACKUP_PAUSE_STATEMENT}</p>
          <div className="flex gap-2 pt-1">
            <button
              type="button"
              onClick={handleSave}
              // The password field it replaces had the focus; it moves here.
              autoFocus
              className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90"
            >
              <Save className="h-4 w-4" /> Save full backup
            </button>
            <button
              type="button"
              onClick={onClose}
              className="rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {state.kind === 'running' && (
        <div className="space-y-2">
          {progress?.phase === 'documents' && (
            <div
              role="progressbar"
              aria-label="Full backup progress"
              aria-valuemin={0}
              aria-valuemax={progress.total}
              aria-valuenow={progress.index - 1}
              aria-valuetext={`${String(progress.index - 1)} of ${String(progress.total)} documents`}
              className="h-2 w-full overflow-hidden rounded-full bg-[hsl(var(--muted))]"
            >
              <div
                className="h-full bg-[hsl(var(--primary))]"
                style={{
                  width: `${String(Math.round(((progress.index - 1) / progress.total) * 100))}%`,
                }}
              />
            </div>
          )}
          <p
            data-testid="full-backup-current"
            className="flex items-center gap-2 text-xs text-[hsl(var(--muted-foreground))]"
          >
            <Loader2 className="h-3 w-3 shrink-0 animate-spin" />
            {progressLine(progress)}
          </p>
          {progress?.waitUntil !== undefined && (
            <WaitNotice key={progress.waitUntil} until={progress.waitUntil} />
          )}
          <button
            type="button"
            onClick={() => setConfirmingStop(true)}
            className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--border))] px-3 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
          >
            Stop
          </button>
        </div>
      )}

      {state.kind === 'done' && (
        <div className="space-y-2 text-xs text-[hsl(var(--muted-foreground))]">
          {state.result.kind === 'download' && (
            <p>
              Your browser saves the file wherever it normally saves downloads; its downloads list
              shows where it went.
            </p>
          )}
          {state.result.leftOut.length > 0 && (
            <>
              <p>{`${String(state.result.leftOut.length)} document(s) were left out:`}</p>
              <ul data-testid="full-backup-left-out" className="space-y-1">
                {state.result.leftOut.map((doc, index) => (
                  <li key={`${String(index)}-${doc.name}`}>
                    <span className="font-medium text-[hsl(var(--foreground))]">{doc.name}</span>
                    {`: ${doc.reason}`}
                  </li>
                ))}
              </ul>
            </>
          )}
          {state.result.unlisted > 0 && (
            <p>
              {`${String(state.result.unlisted)} document row(s) the server listed could not be read at all and are not in the file.`}
            </p>
          )}
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
          >
            Dismiss
          </button>
        </div>
      )}

      {state.kind === 'failed' && (
        <div className="space-y-2 text-xs text-[hsl(var(--muted-foreground))]">
          {state.ran && (
            <p>If it got as far as downloading your vault, Backup History lists that download.</p>
          )}
          <p>Download Latest still saves your vault on its own, without documents.</p>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => setState({ kind: 'password' })}
              className="rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90"
            >
              Try again
            </button>
            <button
              type="button"
              onClick={onClose}
              className="rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      <Dialog open={confirmingStop} onOpenChange={setConfirmingStop}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Stop the full backup?</DialogTitle>
            <DialogDescription>
              Nothing is saved: a full backup is kept only when it is complete.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <button
              type="button"
              onClick={() => setConfirmingStop(false)}
              className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
            >
              Keep going
            </button>
            <button
              type="button"
              onClick={stop}
              className="rounded-md bg-[hsl(var(--destructive))] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive-foreground))] hover:opacity-90"
            >
              Stop backup
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
