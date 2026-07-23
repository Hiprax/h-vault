import { useState, useEffect, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
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
import { useToast } from '../components/ui/Toast';
import { getProfileApi } from '../services/api/userApi';
import { api } from '../services/api/client';
import { cryptoService } from '../services/crypto/cryptoService';
import { useAuthStore } from '../stores/authStore';
import { MAX_BACKUP_EMAILS } from '@hvault/shared';
import type { IBackupLogEntry } from '@hvault/shared';

const MIN_BACKUP_PASSWORD_SCORE = 3;

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
        try {
          const historyRes = await api.get<{ data: IBackupLogEntry[] }>('/backup/history');
          setHistory(historyRes.data.data);
        } catch {
          // history endpoint may not exist yet
        }
      } catch {
        toast({ title: 'Failed to load backup settings', type: 'error' });
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, [toast]);

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

      // Encrypt vault key with BWK for cross-account restore support
      const vaultKey = useAuthStore.getState().vaultKey;
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
    } catch {
      toast({ title: 'Failed to setup backup encryption', type: 'error' });
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
    }
  }, [toast]);

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
      if (
        !backup.isConfigured ||
        !backup.bwkSalt ||
        !backup.encryptedBWK ||
        !backup.bwkIv ||
        !backup.bwkTag
      ) {
        toast({ title: 'Backup encryption is not configured', type: 'error' });
        return;
      }

      // Derive BEK from backup password and decrypt BWK
      const salt = cryptoService.base64ToArrayBuffer(backup.bwkSalt);
      const bek = await cryptoService.deriveBEK(downloadBackupPassword, salt);
      try {
        decryptedBwk = await cryptoService.decryptBWK(
          backup.encryptedBWK,
          backup.bwkIv,
          backup.bwkTag,
          bek,
        );
      } catch {
        toast({ title: 'Incorrect backup password', type: 'error' });
        return;
      } finally {
        cryptoService.clearKey(salt);
        await cryptoService.clearCryptoKey(bek);
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
    } catch {
      toast({ title: 'Failed to download backup', type: 'error' });
    } finally {
      if (decryptedBwk) cryptoService.clearKey(decryptedBwk);
      setDownloading(false);
    }
  }, [downloadBackupPassword, toast]);

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
        [key: string]: unknown;
      };

      // Determine backup encryption source: prefer backup file metadata, fall back to account profile
      let encryptionSource: {
        encryptedBWK: string;
        bwkIv: string;
        bwkTag: string;
        bwkSalt: string;
      } | null = null;

      const fileEnc = backupData.backupEncryption;
      if (fileEnc?.encryptedBWK && fileEnc.bwkIv && fileEnc.bwkTag && fileEnc.bwkSalt) {
        encryptionSource = {
          encryptedBWK: fileEnc.encryptedBWK,
          bwkIv: fileEnc.bwkIv,
          bwkTag: fileEnc.bwkTag,
          bwkSalt: fileEnc.bwkSalt,
        };
      } else {
        // Fall back to current account's backup configuration
        const profileRes = await getProfileApi();
        const profileResult = profileRes.data;
        if (!profileResult.success) throw new Error('Failed to load profile');
        const backup = profileResult.data.settings.backup;
        if (
          backup.isConfigured &&
          backup.bwkSalt &&
          backup.encryptedBWK &&
          backup.bwkIv &&
          backup.bwkTag
        ) {
          encryptionSource = {
            encryptedBWK: backup.encryptedBWK,
            bwkIv: backup.bwkIv,
            bwkTag: backup.bwkTag,
            bwkSalt: backup.bwkSalt,
          };
        }
      }

      if (!encryptionSource) {
        toast({
          title: 'Backup encryption is not configured and backup file has no encryption metadata',
          type: 'error',
        });
        return;
      }

      // Verify the backup password client-side by deriving BEK and decrypting BWK.
      // The raw password never leaves the client (zero-knowledge).
      const salt = cryptoService.base64ToArrayBuffer(encryptionSource.bwkSalt);
      let bek: CryptoKey | undefined;
      let decryptedBwk: ArrayBuffer | undefined;
      // The vault key the backup's rows are encrypted under. Recovered from the
      // backup (via MEK for same-account, or the BWK-wrapped copy for
      // cross-account) and used ONLY to decrypt-then-re-encrypt the rows to this
      // account's current key. Declared out here so `finally` can zero it.
      let backupVaultKey: CryptoKey | undefined;
      try {
        bek = await cryptoService.deriveBEK(restorePassword, salt);

        // Decrypt BWK to verify the password is correct
        try {
          decryptedBwk = await cryptoService.decryptBWK(
            encryptionSource.encryptedBWK,
            encryptionSource.bwkIv,
            encryptionSource.bwkTag,
            bek,
          );
        } catch {
          toast({ title: 'Incorrect backup password', type: 'error' });
          return;
        }

        // Verify backup integrity (HMAC) if the file includes an integrity signature.
        // Old backups without integrity are allowed with a warning.
        const integrityHmac =
          typeof backupData.integrity === 'string' ? backupData.integrity : null;
        if (integrityHmac) {
          // Strip integrity field and re-serialize to get the original signed payload
          const dataForHmac = { ...backupData };
          delete dataForHmac.integrity;
          const canonicalJson = JSON.stringify(dataForHmac);
          const valid = await cryptoService.verifyBackupHmac(
            canonicalJson,
            integrityHmac,
            decryptedBwk,
          );
          if (!valid) {
            toast({
              title: 'Backup integrity check failed. The file may have been tampered with.',
              type: 'error',
            });
            return;
          }
        } else {
          toast({
            title: 'This backup has no integrity signature. It may be an older backup.',
            type: 'warning',
          });
        }

        // Recover the vault key the backup's rows are encrypted under, then
        // RE-ENCRYPT those rows to THIS account's current vault key. We never
        // adopt (replace) the account's vault key — doing so would render the
        // account's own pre-existing items (encrypted under the current key, and
        // not present in the backup) permanently undecryptable. Re-encryption
        // touches only the backup rows, so existing data is never endangered and
        // no privileged key-replacement / master-password re-auth is required.
        const mek = useAuthStore.getState().mek;
        const currentVaultKey = useAuthStore.getState().vaultKey;
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
        setShowRestore(false);
        setRestoreFile(null);
        setRestorePassword('');
        setRestoreConflictStrategy('skip');
      } finally {
        cryptoService.clearKey(salt);
        if (decryptedBwk) cryptoService.clearKey(decryptedBwk);
        if (bek) await cryptoService.clearCryptoKey(bek);
        if (backupVaultKey) await cryptoService.clearCryptoKey(backupVaultKey);
      }
    } catch (err) {
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
  }, [restoreFile, restorePassword, restoreConflictStrategy, toast]);

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

      // Re-encrypt vault key with new BWK for cross-account restore support
      const vaultKey = useAuthStore.getState().vaultKey;
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
    } catch {
      toast({ title: 'Failed to change backup password', type: 'error' });
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
              <p className="text-sm font-medium text-[hsl(var(--foreground))]">Auto-backup</p>
              <p className="text-xs text-[hsl(var(--muted-foreground))]">
                Send encrypted backup daily via email
              </p>
              {!isConfigured && (
                <p className="text-xs text-[hsl(var(--destructive))]">
                  Set up backup encryption first
                </p>
              )}
            </div>
            <button
              type="button"
              onClick={() => setBackupEnabled(!backupEnabled)}
              disabled={!isConfigured}
              role="switch"
              aria-checked={backupEnabled}
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

          {/* Schedule hour */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />
              <span className="text-sm text-[hsl(var(--foreground))]">Schedule (UTC hour)</span>
            </div>
            <input
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
                <label className="mb-1 block text-sm font-medium text-[hsl(var(--foreground))]">
                  Backup File
                </label>
                <input
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
          <CardDescription>Last 30 backup entries</CardDescription>
        </CardHeader>
        <CardContent>
          {history.length === 0 ? (
            <p className="py-6 text-center text-sm text-[hsl(var(--muted-foreground))]">
              No backup history
            </p>
          ) : (
            <div className="space-y-2">
              {history.slice(0, 30).map((entry) => (
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
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
