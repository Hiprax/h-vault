import { useCallback, useEffect, useRef, useState } from 'react';
import { isAxiosError } from 'axios';
import { Link, useLocation } from 'react-router';
import { FileWarning } from 'lucide-react';
import type { IUserProfile } from '@hvault/shared';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/Card';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Label } from '../ui/Label';
import { FormAlert } from '../ui/FormAlert';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/Dialog';
import { useToast } from '../ui/Toast';
import { getApiErrorMessage } from '../../lib/utils';
import { itemTypeLabel } from '../../lib/vaultDisplay';
import { refreshInBackground } from '../../lib/backgroundRefresh';
import { proveMasterPasswordForHeldKey } from '../../lib/masterPasswordProof';
import { useAuthStore } from '../../stores/authStore';
import { noteStaleVaultKey, useUIStore } from '../../stores/uiStore';
import { checkHeldVaultKey } from '../../stores/heldVaultKey';
import { useVaultStore } from '../../stores/vaultStore';
import { purgeUnreadableApi } from '../../services/api/vaultApi';
import { hasBackupKeyCopy } from '../../services/crypto/backupKeyCopy';
import {
  buildPurgePayload,
  isCleanScan,
  scanUnreadableEntries,
  type UnreadableScan,
} from '../../services/vault/unreadableEntries';

/** The fragment the vault banner's Review link (`AppLayout`) opens this card with. */
const UNREADABLE_ENTRIES_ANCHOR = 'unreadable-entries';

/** At most this many entries are listed; the count above the list is always whole. */
const MAX_LISTED_ENTRIES = 100;

type CheckState =
  | { kind: 'idle' }
  | { kind: 'checking' }
  | { kind: 'interrupted-rotation' }
  | { kind: 'key-not-current' }
  | { kind: 'failed'; message: string }
  | { kind: 'checked'; scan: UnreadableScan };

interface UnreadableEntriesCardProps {
  /** The account as the page holds it; decides whether a backup copy is offered. */
  profile: IUserProfile | null;
  /** Receives the account each check reads, so the page shows what was judged. */
  onProfile: (profile: IUserProfile) => void;
  /** Opens the vault-key dialog in recovery mode. */
  onRecover: () => void;
  /** True while a rotation, re-seal or recovery runs on the page. */
  busy: boolean;
  /** Changes whenever a recovery request was sent; the card checks again. */
  recoveryAttempts: number;
}

/** "1 entry" / "3 entries". */
function entries(count: number): string {
  return `${String(count)} ${count === 1 ? 'entry' : 'entries'}`;
}

/**
 * Finds the entries no key this account stores can open (what a master password
 * reset leaves behind), and offers to recover them with the backup's copy of the
 * earlier key or to delete them for good.
 *
 * The check runs in this browser, the only place that holds the key: it first
 * proves this session holds the account's CURRENT key and refuses to judge while
 * an interrupted rotation could still open the rows (`scanUnreadableEntries`). A
 * deletion names exactly the rows that check judged, each with the IVs it had then,
 * after the master password is checked here first; the server deletes a row only
 * while it is still the one judged. The result is kept only while the store holds
 * the key it was judged under.
 */
export function UnreadableEntriesCard({
  profile,
  onProfile,
  onRecover,
  busy,
  recoveryAttempts,
}: UnreadableEntriesCardProps) {
  const { toast } = useToast();
  const location = useLocation();
  const [check, setCheck] = useState<CheckState>({ kind: 'idle' });
  const [showDelete, setShowDelete] = useState(false);
  const [password, setPassword] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  // The key the shown result was judged under: a ref, never React state, so no
  // CryptoKey is copied into the component tree.
  const judgedUnder = useRef<CryptoKey | null>(null);
  const titleRef = useRef<HTMLHeadingElement | null>(null);
  const handledLocationKey = useRef<string | null>(null);
  const seenRecoveryAttempts = useRef(recoveryAttempts);

  const runCheck = useCallback(async () => {
    const { vaultKey: heldKey, mek } = useAuthStore.getState();
    if (!heldKey || !mek) {
      setCheck({ kind: 'failed', message: 'Unlock the vault first.' });
      return;
    }
    setCheck({ kind: 'checking' });
    try {
      const outcome = await scanUnreadableEntries(heldKey, mek, onProfile);
      // Locked, or moved to another key, while the check ran: its result describes
      // a key this session no longer holds.
      if (useAuthStore.getState().vaultKey !== heldKey) {
        setCheck({ kind: 'idle' });
        return;
      }
      if (outcome.kind === 'key-not-current') {
        // The held-key check locks the vault when the key was replaced elsewhere.
        checkHeldVaultKey(heldKey);
        setCheck({ kind: 'key-not-current' });
        return;
      }
      if (outcome.kind === 'interrupted-rotation') {
        setCheck({ kind: 'interrupted-rotation' });
        return;
      }
      judgedUnder.current = heldKey;
      const clean = isCleanScan(outcome.scan);
      useUIStore.getState().setUnreadableEntriesNotice(!clean);
      if (clean) {
        // Lowers the vault's "could not be decrypted" banner: nothing is left
        // for it to report.
        window.dispatchEvent(
          new CustomEvent('vault-decryption-failures', { detail: { count: 0 } }),
        );
      }
      setCheck({ kind: 'checked', scan: outcome.scan });
    } catch (err) {
      setCheck({
        kind: 'failed',
        message: getApiErrorMessage(err, 'The check could not finish. Nothing was changed.'),
      });
    }
  }, [onProfile]);

  // Opened from the vault banner's Review link: bring the card into view and
  // check. Keyed on the navigation, so a second Review click checks again, and
  // remembered, so a re-run of this effect for the same navigation does not.
  useEffect(() => {
    if (location.hash !== `#${UNREADABLE_ENTRIES_ANCHOR}`) return;
    if (handledLocationKey.current === location.key) return;
    handledLocationKey.current = location.key;
    titleRef.current?.scrollIntoView({ block: 'start' });
    titleRef.current?.focus();
    void runCheck();
  }, [location.hash, location.key, runCheck]);

  // A recovery request was sent from the page: what it changed is checked again,
  // whatever came back.
  useEffect(() => {
    if (seenRecoveryAttempts.current === recoveryAttempts) return;
    seenRecoveryAttempts.current = recoveryAttempts;
    void runCheck();
  }, [recoveryAttempts, runCheck]);

  // A result judged under a key the store no longer holds (a lock, or a rotation
  // adopted) is dropped. Watched only while a result is shown.
  useEffect(() => {
    if (check.kind !== 'checked') return;
    const dropIfMoved = (heldKey: CryptoKey | null): void => {
      if (heldKey === judgedUnder.current) return;
      judgedUnder.current = null;
      setCheck({ kind: 'idle' });
    };
    // Also now: the key may have moved between the check's end and this effect.
    dropIfMoved(useAuthStore.getState().vaultKey);
    return useAuthStore.subscribe((state) => {
      dropIfMoved(state.vaultKey);
    });
  }, [check.kind]);

  const scan = check.kind === 'checked' ? check.scan : null;
  const copyStored = hasBackupKeyCopy(profile?.settings.backup);
  const deletable = scan === null ? 0 : scan.items.length + scan.folders.length;
  const damaged = scan === null ? 0 : scan.damaged.items + scan.damaged.folders;
  const working = busy || check.kind === 'checking' || deleting;

  const closeDelete = () => {
    setShowDelete(false);
    setPassword('');
    setAcknowledged(false);
    setDeleteError(null);
  };

  // A finished check that leaves nothing to delete ends the deletion (a request
  // whose answer was lost may well have removed everything): the dialog would
  // otherwise offer to delete zero entries.
  const nothingLeftToDelete = check.kind === 'checked' && deletable === 0;
  useEffect(() => {
    if (showDelete && !deleting && nothingLeftToDelete) closeDelete();
  }, [showDelete, deleting, nothingLeftToDelete]);

  const handleDelete = async () => {
    const { vaultKey: heldKey, user } = useAuthStore.getState();
    if (scan === null || !heldKey || heldKey !== judgedUnder.current || !user?.email) {
      closeDelete();
      setCheck({ kind: 'idle' });
      toast({ title: 'Check the entries again before deleting them.', type: 'error' });
      return;
    }
    setDeleteError(null);
    setDeleting(true);
    let sent = false;
    try {
      // Checked here first: a typo sends nothing and spends nothing of the
      // account's master-password budget. The key is proved against the wrapper
      // the rows were judged under, which the server requires again.
      const authHash = await proveMasterPasswordForHeldKey(
        password,
        user.email,
        heldKey,
        scan.wrapper,
      );
      if (authHash === null) {
        setDeleteError('The master password is incorrect. Nothing was deleted.');
        return;
      }
      sent = true;
      const body = (await purgeUnreadableApi(buildPurgePayload(scan, authHash))).data;
      if (!body.success) throw new Error('The entries could not be deleted.');
      const result = body.data;
      const deleted = result.deletedItems + result.deletedFolders;
      const skipped = result.skippedItems + result.skippedFolders;
      toast({
        title: `Deleted ${String(deleted)} unreadable ${deleted === 1 ? 'entry' : 'entries'}`,
        ...(skipped > 0
          ? {
              description: `${entries(skipped)} changed since the check and ${skipped === 1 ? 'was' : 'were'} kept.`,
            }
          : {}),
        type: skipped > 0 ? 'warning' : 'success',
      });
      closeDelete();
    } catch (err) {
      const status = isAxiosError(err) ? err.response?.status : undefined;
      const fallback = 'The entries could not be deleted.';
      setDeleteError(
        status !== undefined && status >= 400 && status < 500
          ? getApiErrorMessage(err, fallback)
          : fallback,
      );
      noteStaleVaultKey(err);
    } finally {
      setPassword('');
      setDeleting(false);
      if (sent) {
        const vault = useVaultStore.getState();
        refreshInBackground(vault.fetchItems());
        refreshInBackground(vault.fetchTrashItems());
        refreshInBackground(vault.fetchFolders());
        void runCheck();
      }
    }
  };

  return (
    <Card id={UNREADABLE_ENTRIES_ANCHOR}>
      <CardHeader>
        <CardTitle ref={titleRef} tabIndex={-1} className="flex items-center gap-2">
          <FileWarning className="h-5 w-5" /> Unreadable Entries
        </CardTitle>
        <CardDescription>
          Entries your current vault key cannot open, such as those sealed before a master password
          reset. They stay hidden from your vault and still count against your storage.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Button
          type="button"
          variant="outline"
          loading={check.kind === 'checking'}
          disabled={working}
          onClick={() => void runCheck()}
        >
          Check entries
        </Button>

        <div aria-live="polite" className="space-y-3 text-sm text-[hsl(var(--foreground))]">
          {check.kind === 'checking' && <p>Checking every entry with your current key…</p>}
          {check.kind === 'failed' && <FormAlert message={check.message} />}
          {check.kind === 'interrupted-rotation' && (
            <p>
              An interrupted vault key rotation is outstanding, and its key may open these entries.
              Choose Finish Rotation above first, then check again.
            </p>
          )}
          {check.kind === 'key-not-current' && (
            <p>
              This page holds a vault key that is no longer your account&apos;s. Lock the vault and
              unlock it, then check again.
            </p>
          )}
          {scan !== null && isCleanScan(scan) && <p>Every entry opens with your current key.</p>}
          {scan !== null && deletable > 0 && (
            <div className="space-y-2">
              <p>{entries(deletable)} cannot be opened with your current vault key:</p>
              <ul
                // Scrollable, so reachable from the keyboard and named for it.
                tabIndex={0}
                aria-label="Entries that cannot be opened"
                className="max-h-60 list-disc space-y-1 overflow-y-auto pl-5 text-xs text-[hsl(var(--muted-foreground))]"
              >
                {scan.items.slice(0, MAX_LISTED_ENTRIES).map((item) => (
                  <li key={item.id}>
                    {itemTypeLabel(item.itemType)}, added{' '}
                    {new Date(item.createdAt).toLocaleDateString()}
                    {item.inTrash ? ', in the trash' : ''}
                  </li>
                ))}
                {scan.folders
                  .slice(0, Math.max(0, MAX_LISTED_ENTRIES - scan.items.length))
                  .map((folder) => (
                    <li key={folder.id}>
                      Folder, added {new Date(folder.createdAt).toLocaleDateString()}
                    </li>
                  ))}
              </ul>
              {deletable > MAX_LISTED_ENTRIES && (
                <p className="text-xs text-[hsl(var(--muted-foreground))]">
                  The first {MAX_LISTED_ENTRIES} are listed.
                </p>
              )}
            </div>
          )}
          {damaged > 0 && (
            <p>
              {damaged === 1
                ? '1 entry is damaged: part of it opens, or it is malformed.'
                : `${String(damaged)} entries are damaged: part of each opens, or it is malformed.`}{' '}
              Damaged entries are never offered for deletion here.
            </p>
          )}
          {scan !== null && scan.documents > 0 && (
            <p>
              {scan.documents} {scan.documents === 1 ? 'document' : 'documents'} cannot be opened
              either. Unopenable documents can be deleted on the{' '}
              <Link to="/documents" className="underline">
                Documents page
              </Link>
              .
            </p>
          )}
          {scan !== null && deletable + scan.documents > 0 && !copyStored && (
            <p className="text-[hsl(var(--muted-foreground))]">
              No backup copy of an earlier key is stored. A backup file made before the reset that
              holds them may still restore them: on the Backup page, restore it with Overwrite.
              Delete what is left here afterwards.
            </p>
          )}
        </div>

        {scan !== null && deletable + scan.documents > 0 && (
          <div className="flex flex-wrap gap-2">
            {copyStored && (
              <Button type="button" disabled={working} onClick={onRecover}>
                Recover with backup password
              </Button>
            )}
            {deletable > 0 && (
              <Button
                type="button"
                variant="destructive"
                disabled={working}
                onClick={() => setShowDelete(true)}
              >
                Delete permanently
              </Button>
            )}
          </div>
        )}

        <Dialog
          open={showDelete}
          onOpenChange={(open) => {
            if (!open && !deleting) closeDelete();
          }}
        >
          <DialogContent
            className="max-w-sm"
            onClose={() => {
              if (!deleting) closeDelete();
            }}
          >
            <DialogHeader>
              <DialogTitle>Delete Unreadable Entries</DialogTitle>
              <DialogDescription>
                {copyStored
                  ? `This permanently deletes ${entries(deletable)} that neither your current key nor, after a recovery, the backup copy opens.`
                  : `This permanently deletes ${entries(deletable)} that no key this account stores can open.`}{' '}
                This cannot be undone. Entries inside a deleted folder move to its parent.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              {deleteError && <FormAlert message={deleteError} />}
              <div className="space-y-2">
                <Label htmlFor="unreadable-delete-password">Your master password</Label>
                <Input
                  id="unreadable-delete-password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
              {copyStored && (
                <label className="flex items-start gap-2 text-sm text-[hsl(var(--foreground))]">
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={acknowledged}
                    onChange={(e) => setAcknowledged(e.target.checked)}
                  />
                  <span>
                    I tried Recover with backup password, or I do not want to recover these.
                  </span>
                </label>
              )}
            </div>
            <DialogFooter>
              <Button type="button" variant="ghost" disabled={deleting} onClick={closeDelete}>
                Cancel
              </Button>
              <Button
                type="button"
                variant="destructive"
                loading={deleting}
                disabled={deleting || password === '' || (copyStored && !acknowledged)}
                onClick={() => void handleDelete()}
              >
                Delete permanently
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}
