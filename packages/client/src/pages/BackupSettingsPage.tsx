import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useNavigate } from 'react-router';
import type zxcvbnType from 'zxcvbn';
import { getZxcvbn } from '../lib/lazyZxcvbn';
import {
  ArrowLeft,
  Download,
  Upload,
  Clock,
  Mail,
  Shield,
  Play,
  History,
  CheckCircle,
  XCircle,
  Loader2,
  Key,
  Plus,
  X,
} from 'lucide-react';
import { cn, getApiErrorMessage } from '../lib/utils';
import { downloadText } from '../lib/download';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/Card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../components/ui/Dialog';
import { useToast } from '../components/ui/Toast';
import { getProfileApi } from '../services/api/userApi';
import { api } from '../services/api/client';
import { getBackupHistoryApi } from '../services/api/backupApi';
import { Pagination } from '../components/ui/Pagination';
import { cryptoService } from '../services/crypto/cryptoService';
import { useAuthStore } from '../stores/authStore';
import { noteStaleVaultKey } from '../stores/uiStore';
import { resolveBackupSignature, type BackupSignatureVerdict } from '../lib/backupSignature';
import { MAX_BACKUP_EMAILS } from '@hvault/shared';
import type { IBackupLogEntry } from '@hvault/shared';

const MIN_BACKUP_PASSWORD_SCORE = 3;

/**
 * The four fields that make a backup-wrapping-key wrapper usable.
 *
 * The same shape arrives from two places — the account's `settings.backup` and
 * the `backupEncryption` block inside a backup file — and restore now unwraps
 * both, so the completeness test lives here once rather than twice at the call
 * site, where the two copies drifted apart.
 */
interface BwkWrapper {
  encryptedBWK: string;
  bwkIv: string;
  bwkTag: string;
  bwkSalt: string;
}

function completeBwkWrapper(block: Partial<BwkWrapper> | undefined): BwkWrapper | null {
  if (!block?.encryptedBWK || !block.bwkIv || !block.bwkTag || !block.bwkSalt) return null;
  return {
    encryptedBWK: block.encryptedBWK,
    bwkIv: block.bwkIv,
    bwkTag: block.bwkTag,
    bwkSalt: block.bwkSalt,
  };
}

/** Whether two wrappers name the same key, so it is derived once and not twice. */
function sameBwkWrapper(a: BwkWrapper, b: BwkWrapper): boolean {
  return (
    a.encryptedBWK === b.encryptedBWK &&
    a.bwkIv === b.bwkIv &&
    a.bwkTag === b.bwkTag &&
    a.bwkSalt === b.bwkSalt
  );
}

/**
 * Unwrap one backup wrapping key, or `null` when this password does not open
 * THIS wrapper.
 *
 * `null` rather than a throw, because restore now tries up to two wrappers and a
 * password that opens neither is the only thing that means "incorrect backup
 * password". A failure to DERIVE, by contrast, still propagates: that is Web
 * Crypto refusing, or a hostile file's unparseable salt, and reporting either as
 * a wrong password would be a lie.
 *
 * The salt and the derived BEK are zeroed here on every exit; the unwrapped key
 * belongs to the caller, which zeroes it in its own `finally`.
 */
async function unwrapBwk(wrapper: BwkWrapper, password: string): Promise<ArrayBuffer | null> {
  const salt = cryptoService.base64ToArrayBuffer(wrapper.bwkSalt);
  let bek: CryptoKey | undefined;
  try {
    bek = await cryptoService.deriveBEK(password, salt);
    try {
      return await cryptoService.decryptBWK(
        wrapper.encryptedBWK,
        wrapper.bwkIv,
        wrapper.bwkTag,
        bek,
      );
    } catch {
      return null;
    }
  } finally {
    cryptoService.clearKey(salt);
    if (bek) await cryptoService.clearCryptoKey(bek);
  }
}

/** Why a restore needs an answer before it runs. */
type UnverifiedRestoreReason = Extract<BackupSignatureVerdict, { kind: 'unconfirmed' }>['reason'];

const strengthLabels: Record<number, string> = {
  0: 'Very weak',
  1: 'Weak',
  2: 'Fair',
  3: 'Strong',
  4: 'Very strong',
};

const strengthColors: Record<number, string> = {
  0: 'bg-red-500',
  1: 'bg-orange-500',
  2: 'bg-yellow-500',
  3: 'bg-green-500',
  4: 'bg-emerald-500',
};

/**
 * Rows per page in the history card.
 *
 * Deliberately smaller than the server's own default of 20: this is a Card inside
 * a settings page that already scrolls a long way, and thirty rows made it about
 * two thousand pixels tall — which is the complaint that started this. Ten is a
 * screenful. The server's default is a decision about an API with no client; this
 * is a decision about a card.
 */
const HISTORY_PAGE_SIZE = 10;

export default function BackupSettingsPage() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [loading, setLoading] = useState(true);
  const [backupEnabled, setBackupEnabled] = useState(false);
  const [scheduleHour, setScheduleHour] = useState(3);
  const [backupEmails, setBackupEmails] = useState<string[]>([]);
  const [newEmailInput, setNewEmailInput] = useState('');
  const [isConfigured, setIsConfigured] = useState(false);
  const [backupPassword, setBackupPassword] = useState('');
  const [confirmBackupPassword, setConfirmBackupPassword] = useState('');
  const [setupMasterPassword, setSetupMasterPassword] = useState('');
  const [history, setHistory] = useState<IBackupLogEntry[]>([]);
  const [historyPage, setHistoryPage] = useState(1);
  const [historyTotalPages, setHistoryTotalPages] = useState(1);
  const [historyTotal, setHistoryTotal] = useState<number | null>(null);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState(false);
  const [historyReload, setHistoryReload] = useState(0);
  const [triggering, setTriggering] = useState(false);
  const [saving, setSaving] = useState(false);
  const [settingUpEncryption, setSettingUpEncryption] = useState(false);

  const [downloading, setDownloading] = useState(false);
  const [showDownloadPassword, setShowDownloadPassword] = useState(false);
  const [downloadBackupPassword, setDownloadBackupPassword] = useState('');
  const [changingBackupPassword, setChangingBackupPassword] = useState(false);

  // Change backup password state
  const [showChangePassword, setShowChangePassword] = useState(false);
  const [newBackupPassword, setNewBackupPassword] = useState('');
  const [changeBackupCurrentPassword, setChangeBackupCurrentPassword] = useState('');
  const [zxcvbnFn, setZxcvbnFn] = useState<typeof zxcvbnType | null>(null);

  useEffect(() => {
    void getZxcvbn().then((fn) => setZxcvbnFn(() => fn));
  }, []);

  const backupPasswordStrength = useMemo(
    () => (backupPassword && zxcvbnFn ? zxcvbnFn(backupPassword) : null),
    [backupPassword, zxcvbnFn],
  );
  const newBackupPasswordStrength = useMemo(
    () => (newBackupPassword && zxcvbnFn ? zxcvbnFn(newBackupPassword) : null),
    [newBackupPassword, zxcvbnFn],
  );

  // Restore state
  const [showRestore, setShowRestore] = useState(false);
  const [restorePassword, setRestorePassword] = useState('');
  const [restoreFile, setRestoreFile] = useState<File | null>(null);
  const [restoring, setRestoring] = useState(false);
  const [restoreConflictStrategy, setRestoreConflictStrategy] = useState<
    'skip' | 'overwrite' | 'keep_both'
  >('skip');

  // Restoring a file this client could not authenticate is gated on an explicit
  // answer, driven by a promise the restore flow awaits — the same shape the
  // import-overwrite confirmation uses on the Settings page, and for the same
  // reason: by the time the prompt appears the decision is already computed, and
  // the answer decides only whether it is carried out.
  const [unverifiedRestore, setUnverifiedRestore] = useState<UnverifiedRestoreReason | null>(null);
  const unverifiedRestoreResolverRef = useRef<((confirmed: boolean) => void) | null>(null);
  /**
   * Whether this page is still on screen.
   *
   * Load-bearing, and a resolver ref alone is NOT enough. The cleanup below can
   * only settle a resolver that has already been registered, and the restore
   * flow registers one late — after a profile read and up to two 600k-iteration
   * derivations, which is seconds. An auto-lock landing inside that window
   * unmounts the page while the ref is still null, and the flow then registers a
   * resolver nothing can ever reach: the promise never settles, `handleRestore`
   * never reaches its `finally`, and both unwrapped backup wrapping keys stay in
   * memory for the life of the tab with no outcome reported to anyone. Checking
   * the flag at registration time is what closes that window.
   */
  const mountedRef = useRef(true);

  const requestUnverifiedRestoreConfirmation = useCallback(
    (reason: UnverifiedRestoreReason): Promise<boolean> => {
      if (!mountedRef.current) return Promise.resolve(false);
      return new Promise<boolean>((resolve) => {
        unverifiedRestoreResolverRef.current = resolve;
        setUnverifiedRestore(reason);
      });
    },
    [],
  );

  const answerUnverifiedRestore = useCallback((confirmed: boolean) => {
    setUnverifiedRestore(null);
    const resolve = unverifiedRestoreResolverRef.current;
    unverifiedRestoreResolverRef.current = null;
    resolve?.(confirmed);
  }, []);

  // Settle a pending answer if this page goes away while the prompt is open — an
  // auto-lock unmounts it through ProtectedRoute. Left unanswered, the awaiting
  // restore would never reach its `finally`, holding the unwrapped backup
  // wrapping key live for the rest of the tab's life and reporting no outcome at
  // all. The state setter is skipped (there is nothing left to render); the toast
  // still reaches the user because the toast provider outlives the route.
  //
  // The flag is lowered in the SAME cleanup, so a prompt asked for after this
  // point is declined immediately rather than registering a resolver into the
  // void. Two halves of one guarantee: this settles the answer already pending,
  // the flag settles every answer asked for from now on.
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      const resolve = unverifiedRestoreResolverRef.current;
      unverifiedRestoreResolverRef.current = null;
      resolve?.(false);
    };
  }, []);

  useEffect(() => {
    const load = async () => {
      try {
        const profileRes = await getProfileApi();
        const profileResult = profileRes.data;
        if (!profileResult.success) throw new Error('Failed to load profile');
        const backup = profileResult.data.settings.backup;
        setBackupEnabled(backup.enabled);
        setScheduleHour(backup.scheduleHour);
        // Backward compat: prefer backupEmails, fall back to old backupEmail field
        const legacyEmail = (backup as unknown as Record<string, unknown>).backupEmail;
        setBackupEmails(
          backup.backupEmails ??
            (typeof legacyEmail === 'string' && legacyEmail ? [legacyEmail] : []),
        );
        setIsConfigured(backup.isConfigured);
      } catch {
        toast({ title: 'Failed to load backup settings', type: 'error' });
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, [toast]);

  // The history reads on its OWN schedule, not with the page's settings. It is
  // keyed on the page number and on a reload token, and the token is what makes
  // "read page one again" a single request: `setHistoryPage(1)` alone is a no-op
  // when the reader is already on page one, and calling the fetch directly as
  // well would fire two requests when they are on page three.
  useEffect(() => {
    let cancelled = false;
    setHistoryLoading(true);
    setHistoryError(false);
    void getBackupHistoryApi({ page: historyPage, limit: HISTORY_PAGE_SIZE })
      .then((res) => {
        if (cancelled) return;
        const result = res.data;
        if (!result.success) throw new Error('Failed to load backup history');
        setHistory(result.data);
        setHistoryTotalPages(result.pagination.totalPages);
        setHistoryTotal(result.pagination.total);
      })
      .catch(() => {
        // Reported IN the card rather than as a toast, and reported at all — the
        // silent `catch {}` this replaces made a broken endpoint look exactly
        // like an account that has never run a backup, which is the one reading a
        // reader must never be given. Everything else on this page still works.
        if (!cancelled) setHistoryError(true);
      })
      .finally(() => {
        if (!cancelled) setHistoryLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [historyPage, historyReload]);

  /** Re-read the history from its FIRST page, where a newly written row is. */
  const refreshHistory = useCallback(() => {
    setHistoryPage(1);
    setHistoryReload((n) => n + 1);
  }, []);

  const handleSetupEncryption = useCallback(async () => {
    if (!backupPassword || backupPassword !== confirmBackupPassword) {
      toast({ title: 'Passwords do not match', type: 'error' });
      return;
    }
    if (!backupPasswordStrength || backupPasswordStrength.score < MIN_BACKUP_PASSWORD_SCORE) {
      toast({
        title: 'Backup password is too weak. Please choose a stronger password.',
        type: 'error',
      });
      return;
    }
    const user = useAuthStore.getState().user;
    if (!user?.email || !setupMasterPassword) {
      toast({ title: 'Master password is required', type: 'error' });
      return;
    }
    setSettingUpEncryption(true);
    let salt: ArrayBuffer | undefined;
    let bek: CryptoKey | undefined;
    let bwk: ArrayBuffer | undefined;
    let authKey: ArrayBuffer | undefined;
    try {
      // Derive authHash from master password for server-side verification
      const derived = await cryptoService.deriveKeys(setupMasterPassword, user.email);
      authKey = derived.authKey;
      const authHash = cryptoService.getAuthHash(authKey);

      // Generate random salt
      salt = cryptoService.generateSalt();
      // Derive BEK from backup password + salt
      bek = await cryptoService.deriveBEK(backupPassword, salt);
      // Generate random BWK
      bwk = cryptoService.generateBWK();
      // Encrypt BWK with BEK
      const encryptedBWK = await cryptoService.encryptBWK(bwk, bek);

      // Encrypt vault key with BWK for cross-account restore support.
      //
      // ONE `getState()` for the key AND its generation: the number names the key
      // the wrapper below is built from, and a pair taken from two snapshots
      // could name a combination that never existed at the same instant. The
      // generation is sent even when this session holds no key and writes no
      // wrapper, because the body's `else` branch CLEARS the stored one, and a
      // check decided from which fields a request happens to carry is one the
      // sender can step around.
      const { vaultKey, vaultKeyVersion } = useAuthStore.getState();
      let bwkVaultKeyData: { encrypted: string; iv: string; tag: string } | undefined;
      if (vaultKey) {
        bwkVaultKeyData = await cryptoService.encryptVaultKeyWithBWK(vaultKey, bwk);
      }

      await api.post('/backup/setup', {
        authHash,
        encryptedBWK: encryptedBWK.encrypted,
        bwkIv: encryptedBWK.iv,
        bwkTag: encryptedBWK.tag,
        bwkSalt: cryptoService.arrayBufferToBase64(salt),
        vaultKeyVersion,
        ...(bwkVaultKeyData
          ? {
              bwkEncryptedVaultKey: bwkVaultKeyData.encrypted,
              bwkVaultKeyIv: bwkVaultKeyData.iv,
              bwkVaultKeyTag: bwkVaultKeyData.tag,
            }
          : {}),
      });
      setIsConfigured(true);
      setBackupPassword('');
      setConfirmBackupPassword('');
      setSetupMasterPassword('');
      toast({ title: 'Backup encryption configured', type: 'success' });
    } catch (err) {
      // The wrapper this request stores is the account's vault key sealed under
      // the backup key, so the server refuses it on a superseded generation like
      // any other write derived from that key. Raise the app-wide notice, exactly
      // as the restore driver above does: nothing on this page refreshes
      // `authStore.vaultKeyVersion`, so without it a retry would resend the same
      // stale number for ever, and the server's own remedy sentence — reload —
      // would never reach the user.
      noteStaleVaultKey(err);
      toast({
        title: 'Failed to setup backup encryption',
        description: getApiErrorMessage(err, 'An unexpected error occurred. Please try again.'),
        type: 'error',
      });
    } finally {
      setSettingUpEncryption(false);
      if (authKey) cryptoService.clearKey(authKey);
      if (salt) cryptoService.clearKey(salt);
      if (bwk) cryptoService.clearKey(bwk);
      if (bek) await cryptoService.clearCryptoKey(bek);
    }
  }, [backupPassword, confirmBackupPassword, backupPasswordStrength, setupMasterPassword, toast]);

  const handleSave = useCallback(async () => {
    setSaving(true);
    try {
      await api.put('/backup/settings', {
        enabled: backupEnabled,
        scheduleHour,
        backupEmails,
      });
      toast({ title: 'Backup settings saved', type: 'success' });
    } catch {
      toast({ title: 'Failed to save backup settings', type: 'error' });
    } finally {
      setSaving(false);
    }
  }, [backupEnabled, scheduleHour, backupEmails, toast]);

  const handleTriggerBackup = useCallback(async () => {
    setTriggering(true);
    try {
      const res = await api.post<{
        success: boolean;
        message: string;
        data: {
          emailSent?: boolean;
          emailsSent?: number;
          emailsFailed?: number;
          failedEmails?: string[];
        };
      }>('/backup/trigger');
      const { emailSent, emailsFailed, failedEmails } = res.data.data;
      if (emailSent === false) {
        toast({
          title: res.data.message || 'Backup created but email delivery failed',
          type: 'warning',
        });
      } else if (emailsFailed && emailsFailed > 0) {
        toast({
          title: `${res.data.message}. Failed: ${failedEmails?.join(', ') ?? 'unknown'}`,
          type: 'warning',
        });
      } else {
        toast({ title: 'Backup triggered successfully', type: 'success' });
      }
    } catch {
      toast({ title: 'Failed to trigger backup', type: 'error' });
    } finally {
      setTriggering(false);
      // In the `finally`: the server writes a `BackupLog` row on every path that
      // reaches it, including the ones that then report a partial email failure,
      // so a trigger that threw afterwards must still read the row back.
      refreshHistory();
    }
  }, [refreshHistory, toast]);

  const handleDownload = useCallback(async () => {
    if (!downloadBackupPassword) {
      setShowDownloadPassword(true);
      return;
    }
    setDownloading(true);
    let decryptedBwk: ArrayBuffer | undefined;
    try {
      // Fetch profile to get backup encryption metadata
      const profileRes = await getProfileApi();
      const profileResult = profileRes.data;
      if (!profileResult.success) throw new Error('Failed to load profile');
      const backup = profileResult.data.settings.backup;
      // Through the SAME two helpers the restore path uses. They were extracted
      // because this completeness test and this derive-and-unwrap sequence
      // existed twice and the two copies drifted; leaving one copy behind would
      // have made that justification false the day it was written.
      const wrapper = backup.isConfigured ? completeBwkWrapper(backup) : null;
      if (!wrapper) {
        toast({ title: 'Backup encryption is not configured', type: 'error' });
        return;
      }

      decryptedBwk = (await unwrapBwk(wrapper, downloadBackupPassword)) ?? undefined;
      if (!decryptedBwk) {
        toast({ title: 'Incorrect backup password', type: 'error' });
        return;
      }

      // Download backup JSON from server
      const res = await api.get<string>('/backup/download', { responseType: 'text' });
      const backupJson = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);

      // Canonicalize: parse and re-serialize to ensure the HMAC is computed
      // over the exact same form that restore will reproduce via JSON.parse +
      // delete integrity + JSON.stringify. This prevents mismatches caused by
      // server vs client JSON serialization differences.
      const backupObj = JSON.parse(backupJson) as Record<string, unknown>;
      const canonicalJson = JSON.stringify(backupObj);

      // Compute HMAC-SHA256 over the canonical form using BWK
      const hmac = await cryptoService.computeBackupHmac(canonicalJson, decryptedBwk);

      // Add integrity field and re-serialize for download
      backupObj.integrity = hmac;
      const signedJson = JSON.stringify(backupObj);

      // Download the signed backup file
      downloadText(
        signedJson,
        `hvault-backup-${new Date().toISOString().split('T')[0]}.enc`,
        'application/json',
      );

      toast({ title: 'Backup downloaded with integrity signature', type: 'success' });
      setShowDownloadPassword(false);
      setDownloadBackupPassword('');
      // `GET /backup/download` writes its own `{ status: 'success', sentTo:
      // ['download'] }` row — the server has always logged downloads, and this
      // page has never shown one without a full reload.
      refreshHistory();
    } catch {
      toast({ title: 'Failed to download backup', type: 'error' });
    } finally {
      if (decryptedBwk) cryptoService.clearKey(decryptedBwk);
      setDownloading(false);
    }
  }, [downloadBackupPassword, refreshHistory, toast]);

  const handleRestore = useCallback(async () => {
    if (!restoreFile || !restorePassword) return;

    // Client-side file size validation (25MB max, matching server BACKUP_MAX_SIZE_MB default)
    const MAX_RESTORE_FILE_SIZE = 25 * 1024 * 1024;
    if (restoreFile.size > MAX_RESTORE_FILE_SIZE) {
      toast({
        title: 'Backup file too large',
        description: `Maximum file size is 25 MB. Selected file is ${String(Math.ceil(restoreFile.size / (1024 * 1024)))} MB.`,
        type: 'error',
      });
      return;
    }

    setRestoring(true);
    try {
      // Parse the backup file first to check for embedded encryption metadata
      const text = await restoreFile.text();
      const backupData = JSON.parse(text) as {
        items?: Record<string, unknown>[];
        folders?: Record<string, unknown>[];
        encryptedVaultKey?: string;
        vaultKeyIv?: string;
        vaultKeyTag?: string;
        backupEncryption?: {
          encryptedBWK?: string;
          bwkIv?: string;
          bwkTag?: string;
          bwkSalt?: string;
          bwkEncryptedVaultKey?: string;
          bwkVaultKeyIv?: string;
          bwkVaultKeyTag?: string;
        };
        documentSummary?: { count?: number; totalBytes?: number };
        [key: string]: unknown;
      };

      // The two places a backup wrapping key can come from, and BOTH are unwrapped
      // wherever this password opens them, because the two jobs below want
      // DIFFERENT ones and a single "winner" gets one of them wrong:
      //
      //  - the integrity signature must be checked against the ACCOUNT's key, the
      //    only key material here that the file did not supply. Preferring the
      //    file's block — which is what this used to do — let anyone handing you a
      //    file plus "its" backup password supply the message AND the key that
      //    authenticates it, so a verified signature proved only self-consistency;
      //  - the file's own `bwkEncryptedVaultKey` is sealed under the FILE's key by
      //    construction, so nothing else can ever open it, and plumbing the
      //    account's key there would drop every row of a cross-account restore.
      //
      // For a same-account restore with an unchanged backup password the two
      // blocks are byte-identical — the server copies the account's block into
      // every download — so the second derivation is skipped and this path costs
      // the one 600k-iteration PBKDF2 it has always cost.
      const fileWrapper = completeBwkWrapper(backupData.backupEncryption);

      let accountWrapper: BwkWrapper | null = null;
      try {
        const profileRes = await getProfileApi();
        const profileResult = profileRes.data;
        if (!profileResult.success) throw new Error('Failed to load profile');
        const backup = profileResult.data.settings.backup;
        accountWrapper = backup.isConfigured ? completeBwkWrapper(backup) : null;
      } catch (err) {
        // The account's block is the TRUST ANCHOR, not the only key source, and
        // this read is unconditional now where it used to be a fallback. A profile
        // that will not load must therefore not take a self-describing file's
        // restore down with it: it costs the restore its anchor, which the verdict
        // below already answers by asking the user, and nothing more. When the
        // file carries no block of its own the profile IS the only key source and
        // the failure stays fatal, exactly as before.
        if (!fileWrapper) throw err;
      }

      if (!accountWrapper && !fileWrapper) {
        toast({
          title: 'Backup encryption is not configured and backup file has no encryption metadata',
          type: 'error',
        });
        return;
      }

      // Unwrapped backup wrapping keys, declared out here so `finally` zeroes them
      // on every exit. The raw password never leaves the client (zero-knowledge).
      let accountBwk: ArrayBuffer | null = null;
      let fileBwk: ArrayBuffer | null = null;
      // The vault key the backup's rows are encrypted under. Recovered from the
      // backup (via MEK for same-account, or the BWK-wrapped copy for
      // cross-account) and used ONLY to decrypt-then-re-encrypt the rows to this
      // account's current key. Declared out here so `finally` can zero it.
      let backupVaultKey: CryptoKey | undefined;
      try {
        accountBwk = accountWrapper ? await unwrapBwk(accountWrapper, restorePassword) : null;
        fileBwk = !fileWrapper
          ? null
          : accountWrapper && sameBwkWrapper(fileWrapper, accountWrapper)
            ? // Identical blocks are the same key. Deriving it a second time would
              // double the cost of the common case to learn nothing.
              accountBwk
            : await unwrapBwk(fileWrapper, restorePassword);

        // The key the REST of this handler uses, and it is the FILE's on purpose:
        // the only thing left to unwrap with it is the file's own wrapped vault
        // key. It falls back to the account's for a file that carried no block,
        // where the two are the same key anyway.
        const decryptedBwk = fileBwk ?? accountBwk;
        if (!decryptedBwk) {
          toast({ title: 'Incorrect backup password', type: 'error' });
          return;
        }

        // Strip the integrity field and re-serialize to recover the payload that
        // was signed. Built ONLY when there is a signature to check it against:
        // a restore may carry up to MAX_RESTORE_DATA_LENGTH (~25 MiB), and an
        // unsigned file would otherwise allocate that whole string for nothing.
        // `resolveBackupSignature` returns on a null signature before it reads
        // this argument, so the empty string is never looked at.
        const signature = typeof backupData.integrity === 'string' ? backupData.integrity : null;
        let signedPayload = '';
        if (signature !== null) {
          const dataForHmac = { ...backupData };
          delete dataForHmac.integrity;
          signedPayload = JSON.stringify(dataForHmac);
        }
        const verdict = await resolveBackupSignature(
          signature,
          signedPayload,
          [
            // ACCOUNT FIRST: the order is the control, not a preference. The
            // file's key is offered only when it is a different key, so a
            // signature that the account's key already verified is never
            // re-checked against material the file supplied.
            ...(accountBwk ? [{ source: 'account' as const, bwk: accountBwk }] : []),
            ...(fileBwk && fileBwk !== accountBwk
              ? [{ source: 'file' as const, bwk: fileBwk }]
              : []),
          ],
          (data, hmac, bwk) => cryptoService.verifyBackupHmac(data, hmac, bwk),
        );

        if (verdict.kind === 'refused') {
          // Deliberately NOT an accusation of tampering. A signature no available
          // key agrees with is equally a file signed under a backup password other
          // than the one entered, and nothing here can tell those two apart.
          toast({
            title: 'This backup’s integrity signature does not match its contents.',
            description:
              'It may have been modified after it was downloaded, or it may be signed under a different backup password than the one you entered. Nothing was restored.',
            type: 'error',
          });
          return;
        }

        if (verdict.kind === 'unconfirmed') {
          // LEGACY ALLOWANCE, dated 2026-09-22. Restoring a file this client could
          // not authenticate happens only behind this answer, and it is allowed at
          // all only because two legitimate cases land here: a backup downloaded
          // before the signature existed, and a backup from another account (or
          // from before the backup password was changed), whose signature can only
          // ever be checked against key material the file itself carries. When
          // every supported backup carries a signature verifiable against the
          // restoring account, delete this branch and let `refused` cover it.
          const vaultKeyAtPrompt = useAuthStore.getState().vaultKey;
          const confirmed = await requestUnverifiedRestoreConfirmation(verdict.reason);
          if (!confirmed) {
            toast({ title: 'Restore cancelled. Nothing was changed.', type: 'info' });
            return;
          }
          // The answer has no time limit, so re-check the key before acting on one
          // that may be minutes old. A lock unmounts this page (which answers the
          // prompt for the user), but a rotation in another tab does not, and every
          // row below is re-encrypted to the key captured after this point.
          if (useAuthStore.getState().vaultKey !== vaultKeyAtPrompt) {
            toast({
              title: 'Your vault key changed while the restore was waiting to be confirmed.',
              description: 'Nothing was restored. Reload the page and start the restore again.',
              type: 'error',
            });
            return;
          }
        }

        // Recover the vault key the backup's rows are encrypted under, then
        // RE-ENCRYPT those rows to THIS account's current vault key. We never
        // adopt (replace) the account's vault key — doing so would render the
        // account's own pre-existing items (encrypted under the current key, and
        // not present in the backup) permanently undecryptable. Re-encryption
        // touches only the backup rows, so existing data is never endangered and
        // no privileged key-replacement / master-password re-auth is required.
        // ONE read for all three: the generation names the key the rows below
        // are re-encrypted to, and a pair taken from two snapshots could name a
        // combination that never existed at the same instant.
        const {
          mek,
          vaultKey: currentVaultKey,
          vaultKeyVersion: currentVaultKeyVersion,
        } = useAuthStore.getState();
        // Whether the backup rows must be re-encrypted: true when the backup's
        // key differs from the current key (cross-account, or a same-account
        // backup taken before a vault-key rotation). When the keys match the
        // rows are already under the current key and are sent unchanged.
        let needsReEncryption = false;

        if (
          backupData.encryptedVaultKey &&
          backupData.vaultKeyIv &&
          backupData.vaultKeyTag &&
          mek
        ) {
          try {
            // Same account / same MEK: the current MEK decrypts the backup's VK.
            const rawBackupVK = await cryptoService.decryptVaultKey(
              backupData.encryptedVaultKey,
              backupData.vaultKeyIv,
              backupData.vaultKeyTag,
              mek,
            );
            try {
              backupVaultKey = await cryptoService.importVaultKey(rawBackupVK);
              // Compare BEFORE zeroing rawBackupVK. Different key ⇒ re-encrypt.
              needsReEncryption = currentVaultKey
                ? !(await cryptoService.vaultKeyEqualsRaw(currentVaultKey, rawBackupVK))
                : false;
            } finally {
              cryptoService.clearKey(rawBackupVK);
            }
          } catch {
            // MEK mismatch (cross-account). Recover the backup VK from its
            // BWK-wrapped copy, unwrapped with the BWK we already decrypted.
            const bwkVK = backupData.backupEncryption;
            if (bwkVK?.bwkEncryptedVaultKey && bwkVK.bwkVaultKeyIv && bwkVK.bwkVaultKeyTag) {
              try {
                const rawBackupVK = await cryptoService.decryptVaultKeyWithBWK(
                  bwkVK.bwkEncryptedVaultKey,
                  bwkVK.bwkVaultKeyIv,
                  bwkVK.bwkVaultKeyTag,
                  decryptedBwk,
                );
                try {
                  backupVaultKey = await cryptoService.importVaultKey(rawBackupVK);
                  needsReEncryption = currentVaultKey
                    ? !(await cryptoService.vaultKeyEqualsRaw(currentVaultKey, rawBackupVK))
                    : false;
                } finally {
                  cryptoService.clearKey(rawBackupVK);
                }
              } catch {
                toast({
                  title: 'Could not recover the backup’s vault key. Items may fail to decrypt.',
                  type: 'warning',
                });
              }
            } else {
              toast({
                title:
                  'Could not recover the backup’s vault key. If restoring another account’s backup, items may fail to decrypt.',
                type: 'warning',
              });
            }
          }

          // These server-only fields are never part of the restore request.
          delete backupData.encryptedVaultKey;
          delete backupData.vaultKeyIv;
          delete backupData.vaultKeyTag;
        }

        // Never needed by the server.
        delete backupData.backupEncryption;

        // Key used to DECRYPT the backup rows: the recovered backup key when we
        // have it, else the current key (same-account/no-rotation, where they are
        // identical). When re-encryption is needed the target is the current key.
        const decryptKey = backupVaultKey ?? currentVaultKey ?? undefined;

        // Re-encrypt (or, when keys already match, validate) items. Rows that
        // fail to decrypt are dropped, so a partial/foreign backup restores what
        // it can rather than failing wholesale.
        let filteredCount = 0;
        if (Array.isArray(backupData.items)) {
          const validItems: Record<string, unknown>[] = [];
          for (const item of backupData.items) {
            const enc = item.encryptedData as string | undefined;
            const iv = item.dataIv as string | undefined;
            const tag = item.dataTag as string | undefined;
            const encName = item.encryptedName as string | undefined;
            const nameIv = item.nameIv as string | undefined;
            const nameTag = item.nameTag as string | undefined;
            if (!enc || !iv || !tag || !encName || !nameIv || !nameTag || !decryptKey) {
              filteredCount++;
              continue;
            }
            try {
              const data = await cryptoService.decryptData(enc, iv, tag, decryptKey);
              const name = await cryptoService.decryptData(encName, nameIv, nameTag, decryptKey);
              if (needsReEncryption && currentVaultKey) {
                const reData = await cryptoService.encryptData(data, currentVaultKey);
                const reName = await cryptoService.encryptData(name, currentVaultKey);
                item.encryptedData = reData.encrypted;
                item.dataIv = reData.iv;
                item.dataTag = reData.tag;
                item.encryptedName = reName.encrypted;
                item.nameIv = reName.iv;
                item.nameTag = reName.tag;
                item.searchHash = await cryptoService.generateSearchHash(name, currentVaultKey);
                // Password history entries are encrypted under the backup key too.
                if (Array.isArray(item.passwordHistory)) {
                  const reHistory: Record<string, unknown>[] = [];
                  for (const rawEntry of item.passwordHistory) {
                    const entry = rawEntry as {
                      encryptedPassword?: unknown;
                      iv?: unknown;
                      tag?: unknown;
                      changedAt?: unknown;
                    };
                    if (
                      typeof entry.encryptedPassword !== 'string' ||
                      typeof entry.iv !== 'string' ||
                      typeof entry.tag !== 'string'
                    ) {
                      continue;
                    }
                    try {
                      const plain = await cryptoService.decryptData(
                        entry.encryptedPassword,
                        entry.iv,
                        entry.tag,
                        decryptKey,
                      );
                      const reEnc = await cryptoService.encryptData(plain, currentVaultKey);
                      reHistory.push({
                        encryptedPassword: reEnc.encrypted,
                        iv: reEnc.iv,
                        tag: reEnc.tag,
                        changedAt: entry.changedAt,
                      });
                    } catch {
                      // A single corrupt/undecryptable history entry must not drop
                      // the whole item (which still carries a valid current
                      // password) — skip just this entry, mirroring the type-guard
                      // `continue` above.
                      continue;
                    }
                  }
                  item.passwordHistory = reHistory;
                }
              }
              validItems.push(item);
            } catch {
              filteredCount++;
            }
          }
          backupData.items = validItems;
        }

        // Re-encrypt (or validate) folders.
        let filteredFolderCount = 0;
        if (Array.isArray(backupData.folders)) {
          const validFolders: Record<string, unknown>[] = [];
          for (const folder of backupData.folders) {
            const encName = folder.encryptedName as string | undefined;
            const nameIv = folder.nameIv as string | undefined;
            const nameTag = folder.nameTag as string | undefined;
            if (!encName || !nameIv || !nameTag || !decryptKey) {
              filteredFolderCount++;
              continue;
            }
            try {
              const name = await cryptoService.decryptData(encName, nameIv, nameTag, decryptKey);
              if (needsReEncryption && currentVaultKey) {
                const reName = await cryptoService.encryptData(name, currentVaultKey);
                folder.encryptedName = reName.encrypted;
                folder.nameIv = reName.iv;
                folder.nameTag = reName.tag;
                folder.searchHash = await cryptoService.generateSearchHash(name, currentVaultKey);
              }
              validFolders.push(folder);
            } catch {
              filteredFolderCount++;
            }
          }
          backupData.folders = validFolders;
        }

        // Abort if everything was filtered out
        const hasValidItems = Array.isArray(backupData.items) && backupData.items.length > 0;
        const hasValidFolders = Array.isArray(backupData.folders) && backupData.folders.length > 0;
        if (!hasValidItems && !hasValidFolders && filteredCount + filteredFolderCount > 0) {
          toast({
            title: `All items and folders failed decryption. The backup may use a different encryption key.`,
            type: 'error',
          });
          return;
        }

        // The account's vault key is never replaced (the backup rows were
        // re-encrypted to the current key above), so no vault-key adoption and no
        // master-password re-auth are sent — restore is a plain, unprivileged
        // add of rows already under this account's key.
        const restoreResponse = await api.post<{
          success: boolean;
          data: {
            itemsRestored: number;
            itemsSkipped: number;
            foldersRestored: number;
            foldersSkipped: number;
            itemSkipReasons?: { itemId: string; reason: string }[];
            folderSkipReasons?: { folderId: string; reason: string }[];
          };
        }>('/backup/restore', {
          conflictStrategy: restoreConflictStrategy,
          data: JSON.stringify(backupData),
          // Every row above was re-encrypted to `currentVaultKey`, captured at
          // the top of this handler. The server checks this immediately before
          // its first write, so a rotation that commits while a large backup is
          // being re-encrypted refuses the restore instead of storing rows
          // sealed under a key the account has already replaced.
          vaultKeyVersion: currentVaultKeyVersion,
        });

        const trashedAutoRestoredCount = (restoreResponse.data.data.itemSkipReasons ?? []).filter(
          (r) => r.reason === 'trashed_auto_restored',
        ).length;

        const totalFiltered = filteredCount + filteredFolderCount;
        if (totalFiltered > 0) {
          toast({
            title: `Backup restored. ${String(totalFiltered)} undecryptable item(s)/folder(s) were skipped.`,
            type: 'warning',
          });
        } else if (trashedAutoRestoredCount > 0 && restoreConflictStrategy !== 'overwrite') {
          // Trashed items are auto-restored regardless of conflict strategy —
          // surface this so the user knows their `skip`/`keep_both` selection
          // did not apply to those entries.
          toast({
            title: `Backup restored. ${String(trashedAutoRestoredCount)} trashed item(s) were auto-restored regardless of the conflict strategy.`,
            type: 'warning',
          });
        } else {
          toast({ title: 'Backup restored successfully', type: 'success' });
        }

        // Documents are not part of a backup, so a restored account can look
        // complete while every file the account held is missing. The breadcrumb
        // the server writes into the payload is the only way to say so, and it is
        // raised as its OWN notice rather than folded into the result toast above:
        // it is true regardless of which of those three branches was taken. It is
        // raised LAST so it is the notice sitting on top of the stack, because it
        // is the one that tells the user they are not finished. Absent on a backup
        // written by a server that predates the document store, and zero on one
        // from an account that held none — neither says anything worth
        // interrupting for.
        const documentsLeftBehind = backupData.documentSummary?.count ?? 0;
        if (documentsLeftBehind > 0) {
          toast({
            title: `This backup was taken from an account holding ${String(documentsLeftBehind)} document(s); documents are not part of a backup.`,
            description: 'Re-upload them from the Documents page to restore them.',
            type: 'warning',
          });
        }

        setShowRestore(false);
        setRestoreFile(null);
        setRestorePassword('');
        setRestoreConflictStrategy('skip');
      } finally {
        // Both wrapping keys, and each buffer only once: when the two blocks were
        // identical `fileBwk` IS `accountBwk`, and the identity check is what keeps
        // that legible rather than relying on a second zeroing being harmless.
        if (accountBwk) cryptoService.clearKey(accountBwk);
        if (fileBwk && fileBwk !== accountBwk) cryptoService.clearKey(fileBwk);
        if (backupVaultKey) await cryptoService.clearCryptoKey(backupVaultKey);
      }
    } catch (err) {
      // A vault-key rotation committed elsewhere while this restore was being
      // prepared. Raise the app-wide notice, then report the failure as usual:
      // nothing was restored, nothing is retried, and no key is re-derived —
      // reloading is the remedy, because adopting a generation the server named
      // is a decision about the whole session rather than about one restore.
      noteStaleVaultKey(err);
      // Surface the server's specific error (e.g. an incorrect backup password
      // caught client-side, or a persistence-layer rejection) instead of a
      // generic failure toast.
      toast({
        title: 'Failed to restore backup',
        description: getApiErrorMessage(err, 'An unexpected error occurred. Please try again.'),
        type: 'error',
      });
    } finally {
      setRestoring(false);
    }
  }, [
    restoreFile,
    restorePassword,
    restoreConflictStrategy,
    requestUnverifiedRestoreConfirmation,
    toast,
  ]);

  const handleChangeBackupPassword = useCallback(async () => {
    if (!newBackupPassword || !changeBackupCurrentPassword) return;
    if (!newBackupPasswordStrength || newBackupPasswordStrength.score < MIN_BACKUP_PASSWORD_SCORE) {
      toast({
        title: 'Backup password is too weak. Please choose a stronger password.',
        type: 'error',
      });
      return;
    }
    const user = useAuthStore.getState().user;
    if (!user?.email) {
      toast({ title: 'User not found', type: 'error' });
      return;
    }
    setChangingBackupPassword(true);
    let newSalt: ArrayBuffer | undefined;
    let newBek: CryptoKey | undefined;
    let newBwk: ArrayBuffer | undefined;
    let authKey: ArrayBuffer | undefined;
    try {
      // Derive authHash from master password (same as login/change-password flow)
      const derived = await cryptoService.deriveKeys(changeBackupCurrentPassword, user.email);
      authKey = derived.authKey;
      const authHash = cryptoService.getAuthHash(authKey);

      // Generate new salt
      newSalt = cryptoService.generateSalt();
      // Derive new BEK from new password + salt
      newBek = await cryptoService.deriveBEK(newBackupPassword, newSalt);
      // Generate new BWK
      newBwk = cryptoService.generateBWK();
      // Encrypt new BWK with new BEK
      const encryptedBWK = await cryptoService.encryptBWK(newBwk, newBek);

      // Re-encrypt vault key with new BWK for cross-account restore support. One
      // `getState()` for the key and its generation, for the reason the setup
      // driver above gives.
      const { vaultKey, vaultKeyVersion } = useAuthStore.getState();
      let bwkVaultKeyData: { encrypted: string; iv: string; tag: string } | undefined;
      if (vaultKey) {
        bwkVaultKeyData = await cryptoService.encryptVaultKeyWithBWK(vaultKey, newBwk);
      }

      await api.put('/backup/change-password', {
        password: authHash,
        newEncryptedBWK: encryptedBWK.encrypted,
        newBwkIv: encryptedBWK.iv,
        newBwkTag: encryptedBWK.tag,
        newBwkSalt: cryptoService.arrayBufferToBase64(newSalt),
        vaultKeyVersion,
        ...(bwkVaultKeyData
          ? {
              newBwkEncryptedVaultKey: bwkVaultKeyData.encrypted,
              newBwkVaultKeyIv: bwkVaultKeyData.iv,
              newBwkVaultKeyTag: bwkVaultKeyData.tag,
            }
          : {}),
      });
      toast({ title: 'Backup password changed', type: 'success' });
      setShowChangePassword(false);
      setNewBackupPassword('');
      setChangeBackupCurrentPassword('');
    } catch (err) {
      // Same wrapper, same refusal, same remedy as the setup driver above.
      noteStaleVaultKey(err);
      toast({
        title: 'Failed to change backup password',
        description: getApiErrorMessage(err, 'An unexpected error occurred. Please try again.'),
        type: 'error',
      });
    } finally {
      setChangingBackupPassword(false);
      if (authKey) cryptoService.clearKey(authKey);
      if (newSalt) cryptoService.clearKey(newSalt);
      if (newBwk) cryptoService.clearKey(newBwk);
      if (newBek) await cryptoService.clearCryptoKey(newBek);
    }
  }, [newBackupPassword, newBackupPasswordStrength, changeBackupCurrentPassword, toast]);

  const handleAddEmail = useCallback(() => {
    const trimmed = newEmailInput.trim().toLowerCase();
    if (!trimmed) return;
    if (backupEmails.includes(trimmed)) {
      toast({ title: 'Email already added', type: 'error' });
      return;
    }
    if (backupEmails.length >= MAX_BACKUP_EMAILS) {
      toast({ title: `Maximum ${String(MAX_BACKUP_EMAILS)} backup emails allowed`, type: 'error' });
      return;
    }
    setBackupEmails([...backupEmails, trimmed]);
    setNewEmailInput('');
  }, [newEmailInput, backupEmails, toast]);

  const handleRemoveEmail = useCallback(
    (index: number) => {
      setBackupEmails(backupEmails.filter((_, i) => i !== index));
    },
    [backupEmails],
  );

  const inputClass =
    'w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]';

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-8 w-8 animate-spin text-[hsl(var(--primary))]" />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
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
          <Shield className="h-6 w-6" /> Backup Settings
        </h1>
      </div>

      {/* Setup encryption */}
      {!isConfigured && (
        <Card className="border-yellow-300 dark:border-yellow-700">
          <CardHeader>
            <CardTitle>Setup Backup Encryption</CardTitle>
            <CardDescription>
              Set a backup encryption password to enable encrypted backups. This password is
              separate from your master password.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label htmlFor="backup-password" className="sr-only">
                Backup encryption password
              </label>
              <input
                id="backup-password"
                type="password"
                value={backupPassword}
                onChange={(e) => setBackupPassword(e.target.value)}
                placeholder="Backup encryption password"
                className={inputClass}
                autoComplete="new-password"
              />
            </div>
            {backupPasswordStrength && (
              <div className="space-y-1.5">
                <div className="flex h-1.5 w-full gap-1">
                  {[0, 1, 2, 3, 4].map((i) => (
                    <div
                      key={i}
                      className={cn(
                        'h-full flex-1 rounded-full transition-colors',
                        i <= backupPasswordStrength.score
                          ? strengthColors[backupPasswordStrength.score]
                          : 'bg-[hsl(var(--muted))]',
                      )}
                    />
                  ))}
                </div>
                <p className="text-xs text-[hsl(var(--muted-foreground))]">
                  {strengthLabels[backupPasswordStrength.score]}
                  {backupPasswordStrength.score < MIN_BACKUP_PASSWORD_SCORE &&
                    ' — Minimum "Strong" required'}
                </p>
              </div>
            )}
            <div>
              <label htmlFor="confirm-backup-password" className="sr-only">
                Confirm backup password
              </label>
              <input
                id="confirm-backup-password"
                type="password"
                value={confirmBackupPassword}
                onChange={(e) => setConfirmBackupPassword(e.target.value)}
                placeholder="Confirm backup password"
                className={inputClass}
                autoComplete="new-password"
              />
            </div>
            <div>
              <label htmlFor="setup-master-password" className="sr-only">
                Current master password
              </label>
              <input
                id="setup-master-password"
                type="password"
                value={setupMasterPassword}
                onChange={(e) => setSetupMasterPassword(e.target.value)}
                placeholder="Current master password"
                className={inputClass}
                autoComplete="current-password"
              />
            </div>
            <button
              type="button"
              onClick={() => void handleSetupEncryption()}
              disabled={
                settingUpEncryption ||
                !backupPassword ||
                !confirmBackupPassword ||
                !setupMasterPassword ||
                !backupPasswordStrength ||
                backupPasswordStrength.score < MIN_BACKUP_PASSWORD_SCORE
              }
              className="rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
            >
              {settingUpEncryption ? 'Setting Up...' : 'Setup Encryption'}
            </button>
          </CardContent>
        </Card>
      )}

      {/* Configuration */}
      <Card>
        <CardHeader>
          <CardTitle>Backup Configuration</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Auto-backup toggle */}
          <div className="flex items-center justify-between">
            <div>
              <p
                id="auto-backup-label"
                className="text-sm font-medium text-[hsl(var(--foreground))]"
              >
                Auto-backup
              </p>
              <p
                id="auto-backup-description"
                className="text-xs text-[hsl(var(--muted-foreground))]"
              >
                Send encrypted backup daily via email
              </p>
              {!isConfigured && (
                <p className="text-xs text-[hsl(var(--destructive))]">
                  Set up backup encryption first
                </p>
              )}
            </div>
            {/* `aria-labelledby`, not a duplicated `aria-label`: the switch's only
                content is the sliding knob, so it reached a screen reader as an
                unnamed control, and the words that name it are already on screen
                two elements away. Pointing at them means the spoken name and the
                visible one cannot drift (WCAG 2.5.3), which a hand-written label
                does not guarantee. `disabled` alone does not excuse the omission:
                the account that has not set up backup encryption yet is exactly
                the one being told what this control is for. */}
            <button
              type="button"
              onClick={() => setBackupEnabled(!backupEnabled)}
              disabled={!isConfigured}
              role="switch"
              aria-checked={backupEnabled}
              aria-labelledby="auto-backup-label"
              aria-describedby="auto-backup-description"
              className={cn(
                'relative h-6 w-11 rounded-full transition-colors disabled:opacity-50',
                backupEnabled ? 'bg-[hsl(var(--primary))]' : 'bg-[hsl(var(--muted))]',
              )}
            >
              <span
                className={cn(
                  'absolute left-0.5 top-0.5 h-5 w-5 rounded-full bg-white transition-transform',
                  backupEnabled && 'translate-x-5',
                )}
              />
            </button>
          </div>

          {/* Schedule hour. A real `<label htmlFor>` rather than the `<span>` that
              used to sit here: this is the one field on the page with neither a
              label nor a placeholder, so it was the one field with no accessible
              name at all — and a bare number spinner is precisely the control a
              reader cannot guess from context. */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />
              <label
                htmlFor="backup-schedule-hour"
                className="text-sm text-[hsl(var(--foreground))]"
              >
                Schedule (UTC hour)
              </label>
            </div>
            <input
              id="backup-schedule-hour"
              type="number"
              min={0}
              max={23}
              value={scheduleHour}
              onChange={(e) => setScheduleHour(Number(e.target.value))}
              className={cn(inputClass, 'w-20')}
            />
          </div>

          {/* Backup emails */}
          <div>
            <div className="mb-1 flex items-center gap-2">
              <Mail className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />
              <span className="text-sm text-[hsl(var(--foreground))]">Backup Emails</span>
              <span className="text-xs text-[hsl(var(--muted-foreground))]">
                ({String(backupEmails.length)}/{String(MAX_BACKUP_EMAILS)})
              </span>
            </div>
            {backupEmails.length > 0 && (
              <div className="mb-2 space-y-1">
                {backupEmails.map((email, index) => (
                  <div
                    key={email}
                    className="flex items-center justify-between rounded-md border border-[hsl(var(--border))] px-3 py-1.5"
                  >
                    <span className="text-sm text-[hsl(var(--foreground))]">{email}</span>
                    <button
                      type="button"
                      onClick={() => handleRemoveEmail(index)}
                      className="ml-2 rounded p-0.5 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--destructive))]"
                      aria-label={`Remove ${email}`}
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
            {backupEmails.length < MAX_BACKUP_EMAILS && (
              <div className="flex gap-2">
                <input
                  type="email"
                  value={newEmailInput}
                  onChange={(e) => setNewEmailInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      handleAddEmail();
                    }
                  }}
                  placeholder="Add backup email"
                  className={inputClass}
                />
                <button
                  type="button"
                  onClick={handleAddEmail}
                  disabled={!newEmailInput.trim()}
                  className="inline-flex items-center gap-1 rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
                >
                  <Plus className="h-4 w-4" /> Add
                </button>
              </div>
            )}
            <p className="mt-1 text-xs text-[hsl(var(--muted-foreground))]">
              Defaults to your account email if none specified
            </p>
          </div>

          {/* Action buttons */}
          <div className="flex flex-wrap gap-3 pt-2">
            <button
              type="button"
              onClick={() => void handleSave()}
              disabled={saving}
              className="rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
            >
              {saving ? 'Saving...' : 'Save Settings'}
            </button>
            <button
              type="button"
              onClick={() => void handleTriggerBackup()}
              disabled={triggering || !isConfigured}
              title={!isConfigured ? 'Set up backup encryption first' : undefined}
              className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-4 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] disabled:opacity-50"
            >
              <Play className="h-4 w-4" /> {triggering ? 'Triggering...' : 'Backup Now'}
            </button>
            <button
              type="button"
              onClick={() => void handleDownload()}
              disabled={downloading || !isConfigured}
              title={!isConfigured ? 'Set up backup encryption first' : undefined}
              className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-4 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] disabled:opacity-50"
            >
              {downloading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Download className="h-4 w-4" />
              )}
              {downloading ? 'Downloading...' : 'Download Latest'}
            </button>
          </div>

          {/* Download backup password prompt */}
          {showDownloadPassword && (
            <div className="mt-4 rounded-md border border-[hsl(var(--input))] p-4">
              <p className="mb-2 text-sm text-[hsl(var(--foreground))]">
                Enter your backup password to sign the download with an integrity signature.
              </p>
              <div className="flex gap-2">
                <input
                  type="password"
                  value={downloadBackupPassword}
                  onChange={(e) => setDownloadBackupPassword(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      void handleDownload();
                    }
                  }}
                  placeholder="Backup password"
                  className={inputClass}
                  autoFocus
                />
                <button
                  type="button"
                  onClick={() => void handleDownload()}
                  disabled={downloading || !downloadBackupPassword}
                  className="rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
                >
                  {downloading ? 'Downloading...' : 'Download'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowDownloadPassword(false);
                    setDownloadBackupPassword('');
                  }}
                  className="rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Restore from backup */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5" /> Restore from Backup
          </CardTitle>
        </CardHeader>
        <CardContent>
          {showRestore ? (
            <div className="space-y-4">
              <div>
                {/* `htmlFor`/`id`, because a `<label>` that is merely NEXT TO an
                    input labels nothing: the file picker had no accessible name,
                    and it is the control the whole panel exists for. */}
                <label
                  htmlFor="restore-backup-file"
                  className="mb-1 block text-sm font-medium text-[hsl(var(--foreground))]"
                >
                  Backup File
                </label>
                <input
                  id="restore-backup-file"
                  type="file"
                  onChange={(e) => setRestoreFile(e.target.files?.[0] ?? null)}
                  className="block w-full text-sm text-[hsl(var(--foreground))] file:mr-4 file:rounded-md file:border-0 file:bg-[hsl(var(--primary))] file:px-4 file:py-2 file:text-sm file:font-medium file:text-[hsl(var(--primary-foreground))]"
                  accept=".enc"
                />
              </div>
              <div>
                <label htmlFor="restore-password" className="sr-only">
                  Backup encryption password for restore
                </label>
                <input
                  id="restore-password"
                  type="password"
                  value={restorePassword}
                  onChange={(e) => setRestorePassword(e.target.value)}
                  placeholder="Backup encryption password"
                  className={inputClass}
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-[hsl(var(--foreground))]">
                  Conflict Strategy
                </label>
                <p className="mb-2 text-xs text-[hsl(var(--muted-foreground))]">
                  How to handle items that already exist in your vault
                </p>
                <div className="flex flex-col gap-2">
                  {(
                    [
                      ['skip', 'Skip', 'Keep existing items, skip duplicates'],
                      ['overwrite', 'Overwrite', 'Replace existing items with backup data'],
                      ['keep_both', 'Keep Both', 'Keep existing and create copies from backup'],
                    ] as const
                  ).map(([value, label, description]) => (
                    <label key={value} className="flex items-start gap-2 cursor-pointer">
                      <input
                        type="radio"
                        name="restore-conflict-strategy"
                        value={value}
                        checked={restoreConflictStrategy === value}
                        onChange={() => setRestoreConflictStrategy(value)}
                        className="mt-0.5"
                      />
                      <div>
                        <span className="text-sm font-medium text-[hsl(var(--foreground))]">
                          {label}
                        </span>
                        <p className="text-xs text-[hsl(var(--muted-foreground))]">{description}</p>
                      </div>
                    </label>
                  ))}
                </div>
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setShowRestore(false)}
                  className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => void handleRestore()}
                  disabled={restoring || !restoreFile || !restorePassword}
                  className="rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
                >
                  {restoring ? 'Restoring...' : 'Restore'}
                </button>
              </div>
            </div>
          ) : (
            <button
              type="button"
              onClick={() => setShowRestore(true)}
              className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-4 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
            >
              <Upload className="h-4 w-4" /> Restore from File
            </button>
          )}
        </CardContent>
      </Card>

      {/* Unverified-restore confirmation — nothing is sent until this is answered.
          Rendered OUTSIDE the restore panel on purpose: closing the panel would
          otherwise unmount the prompt with no answer, stranding the awaiting
          restore holding the unwrapped backup wrapping key and reporting nothing.
          The primary button is deliberately not called "Restore": two suites and
          two E2E specs already click a control by that exact name. */}
      <Dialog
        open={unverifiedRestore !== null}
        onOpenChange={(open) => {
          if (!open) answerUnverifiedRestore(false);
        }}
      >
        <DialogContent className="max-w-md" onClose={() => answerUnverifiedRestore(false)}>
          <DialogHeader>
            <DialogTitle>Restore a backup that could not be verified</DialogTitle>
            <DialogDescription>
              {unverifiedRestore === 'self_signed'
                ? 'This file’s integrity signature could only be checked against key material the file itself carries, so it shows that the file agrees with itself and nothing about where the file came from. A backup from another account, or one taken before you changed your backup password, looks exactly like this.'
                : 'This file carries no integrity signature at all, so there is no way to tell whether it is still the file that was written. A backup that arrived by email is never signed — the server assembles it and has no backup password to sign with — and backups written before signing existed look the same way.'}
            </DialogDescription>
          </DialogHeader>
          <ul className="list-disc space-y-1 pl-5 text-sm text-[hsl(var(--foreground))]">
            <li>
              Its entries are added to your vault and sealed under this account&apos;s vault key, so
              anything altered in the file since it was written is restored as the file says it.
            </li>
            <li>
              Your existing entries are replaced only if you chose <strong>Overwrite</strong>.
            </li>
            <li>Continue only if you know where this file came from.</li>
          </ul>
          <DialogFooter>
            <button
              type="button"
              onClick={() => answerUnverifiedRestore(false)}
              className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
            >
              Cancel Restore
            </button>
            <button
              type="button"
              onClick={() => answerUnverifiedRestore(true)}
              className="rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90"
            >
              Restore Unverified Backup
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Change backup password */}
      {isConfigured && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5" /> Change Backup Password
            </CardTitle>
          </CardHeader>
          <CardContent>
            {showChangePassword ? (
              <div className="space-y-4">
                <div>
                  <label htmlFor="change-backup-current-password" className="sr-only">
                    Current master password
                  </label>
                  <input
                    id="change-backup-current-password"
                    type="password"
                    value={changeBackupCurrentPassword}
                    onChange={(e) => setChangeBackupCurrentPassword(e.target.value)}
                    placeholder="Current master password"
                    className={inputClass}
                    autoComplete="current-password"
                  />
                </div>
                <div>
                  <label htmlFor="new-backup-password" className="sr-only">
                    New backup password
                  </label>
                  <input
                    id="new-backup-password"
                    type="password"
                    value={newBackupPassword}
                    onChange={(e) => setNewBackupPassword(e.target.value)}
                    placeholder="New backup password"
                    className={inputClass}
                    autoComplete="new-password"
                  />
                </div>
                {newBackupPasswordStrength && (
                  <div className="space-y-1.5">
                    <div className="flex h-1.5 w-full gap-1">
                      {[0, 1, 2, 3, 4].map((i) => (
                        <div
                          key={i}
                          className={cn(
                            'h-full flex-1 rounded-full transition-colors',
                            i <= newBackupPasswordStrength.score
                              ? strengthColors[newBackupPasswordStrength.score]
                              : 'bg-[hsl(var(--muted))]',
                          )}
                        />
                      ))}
                    </div>
                    <p className="text-xs text-[hsl(var(--muted-foreground))]">
                      {strengthLabels[newBackupPasswordStrength.score]}
                      {newBackupPasswordStrength.score < MIN_BACKUP_PASSWORD_SCORE &&
                        ' — Minimum "Strong" required'}
                    </p>
                  </div>
                )}
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setShowChangePassword(false)}
                    className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleChangeBackupPassword()}
                    disabled={
                      changingBackupPassword ||
                      !changeBackupCurrentPassword ||
                      !newBackupPassword ||
                      !newBackupPasswordStrength ||
                      newBackupPasswordStrength.score < MIN_BACKUP_PASSWORD_SCORE
                    }
                    className="rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
                  >
                    {changingBackupPassword ? 'Changing...' : 'Change Password'}
                  </button>
                </div>
              </div>
            ) : (
              <button
                type="button"
                onClick={() => setShowChangePassword(true)}
                className="text-sm text-[hsl(var(--primary))] hover:underline"
              >
                Change backup encryption password
              </button>
            )}
          </CardContent>
        </Card>
      )}

      {/* Backup history */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <History className="h-5 w-5" /> Backup History
          </CardTitle>
          <CardDescription>
            {historyTotal === null
              ? 'Every backup and download, newest first'
              : `${String(historyTotal)} ${historyTotal === 1 ? 'entry' : 'entries'}, newest first`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {historyLoading ? (
            <div
              role="status"
              className="flex items-center justify-center gap-2 py-6 text-sm text-[hsl(var(--muted-foreground))]"
            >
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading backup history…
            </div>
          ) : historyError ? (
            <div className="flex flex-col items-center gap-2 py-6 text-center">
              <p role="alert" className="text-sm text-[hsl(var(--destructive))]">
                Backup history could not be loaded.
              </p>
              <button
                type="button"
                onClick={refreshHistory}
                className="rounded-md border border-[hsl(var(--input))] px-3 py-1.5 text-sm text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent))]"
              >
                Retry
              </button>
            </div>
          ) : history.length === 0 ? (
            <p className="py-6 text-center text-sm text-[hsl(var(--muted-foreground))]">
              No backup history
            </p>
          ) : (
            <div className="space-y-2">
              {/* No `.slice()` here: the SERVER decides the page size, and slicing
                  on top of it was what made everything past the first page
                  unreachable. */}
              {history.map((entry) => (
                <div
                  key={entry._id}
                  className="flex items-center justify-between rounded-lg border border-[hsl(var(--border))] p-3"
                >
                  <div className="flex items-center gap-3">
                    {entry.status === 'success' ? (
                      <CheckCircle className="h-5 w-5 text-green-500" />
                    ) : (
                      <XCircle className="h-5 w-5 text-red-500" />
                    )}
                    <div>
                      <span
                        className={cn(
                          'inline-flex rounded-full px-2 py-0.5 text-xs font-medium',
                          entry.status === 'success'
                            ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                            : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
                        )}
                      >
                        {entry.status}
                      </span>
                      <p className="mt-1 text-xs text-[hsl(var(--muted-foreground))]">
                        {new Date(entry.timestamp).toLocaleString()}
                        {entry.itemCount != null && ` \u00B7 ${String(entry.itemCount)} items`}
                        {entry.fileSizeBytes != null &&
                          ` \u00B7 ${(entry.fileSizeBytes / 1024).toFixed(1)} KB`}
                      </p>
                      {entry.errorMessage && (
                        <p className="mt-0.5 text-xs text-[hsl(var(--destructive))]">
                          {entry.errorMessage}
                        </p>
                      )}
                    </div>
                  </div>
                  <span className="text-xs text-[hsl(var(--muted-foreground))]">
                    {entry.sentTo.join(', ')}
                  </span>
                </div>
              ))}
              {historyTotalPages > 1 && (
                <Pagination
                  page={historyPage}
                  totalPages={historyTotalPages}
                  label="backup history entries"
                  onPageChange={setHistoryPage}
                  {...(historyTotal === null ? {} : { total: historyTotal })}
                  className="pt-2"
                />
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
