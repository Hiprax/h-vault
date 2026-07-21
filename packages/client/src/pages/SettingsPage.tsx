import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Settings,
  Shield,
  Palette,
  Download,
  Upload,
  Clock,
  Clipboard,
  Key,
  Monitor,
  Moon,
  Sun,
  ChevronRight,
  FileText,
  History,
  Loader2,
  Lock,
  CheckCircle,
  XCircle,
  AlertTriangle,
} from 'lucide-react';
import QRCode from 'qrcode';
import type zxcvbnType from 'zxcvbn';
import { getZxcvbn } from '../lib/lazyZxcvbn';
import { cn, getApiErrorMessage } from '../lib/utils';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/Card';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '../components/ui/Dialog';
import { useToast } from '../components/ui/Toast';
import { useAuthStore } from '../stores/authStore';
import { useUIStore } from '../stores/uiStore';
import { cryptoService } from '../services/crypto/cryptoService';
import { api } from '../services/api/client';
import {
  getProfileApi,
  updateSettingsApi,
  changePasswordApi,
  setup2faApi,
  verify2faApi,
  disable2faApi,
  regenerateBackupCodesApi,
  exportVaultApi,
  importVaultApi,
} from '../services/api/userApi';
import {
  MAX_IMPORT_DATA_LENGTH,
  MAX_IMPORT_FILE_SIZE_BYTES,
  MAX_ITEMS_PER_USER,
} from '@hvault/shared';
import type { IUserProfile } from '@hvault/shared';
import { clearSettingsCache } from '../hooks/useUserSettings';
import { useVaultStore } from '../stores/vaultStore';
import { parseCsv } from '../services/import/csv';
import {
  IMPORT_FORMATS,
  ImportParseError,
  buildEncryptedImportItems,
  chunkBySize,
  detectCsvFormat,
  parseImportData,
} from '../services/import';
import type { ImportSourceFormat } from '../services/import';

// ---------------------------------------------------------------------------
// CSV helpers
// ---------------------------------------------------------------------------

const HVAULT_FIELDS = [
  { value: '', label: '-- Skip --' },
  { value: 'name', label: 'Name' },
  { value: 'username', label: 'Username' },
  { value: 'password', label: 'Password' },
  { value: 'url', label: 'URL' },
  { value: 'notes', label: 'Notes' },
  { value: 'totp', label: 'TOTP Secret' },
  { value: 'folder', label: 'Folder' },
];

// The CSV mapping preview reuses the shared RFC-4180 tokenizer (services/import),
// which correctly handles quoted fields containing commas AND embedded newlines
// (a naive line-split parser corrupts those). The actual import parsing/encryption
// lives in services/import; this thin adapter only feeds the column-mapping UI.
function parseCSV(text: string): { headers: string[]; rows: string[][] } {
  const rows = parseCsv(text);
  if (rows.length === 0) return { headers: [], rows: [] };
  return { headers: rows[0] ?? [], rows: rows.slice(1) };
}

/**
 * Validate and unwrap a native H-Vault export for (batched) re-import. Items are
 * already encrypted; we confirm each decrypts with the current vault key and keep
 * the encrypted rows verbatim. Undecryptable rows (e.g. a different vault key) are
 * counted and dropped.
 */
async function extractNativeItems(
  raw: string,
  vaultKey: CryptoKey,
): Promise<{ items: Record<string, unknown>[]; filtered: number }> {
  let parsed: { items?: unknown };
  try {
    parsed = JSON.parse(raw) as { items?: unknown };
  } catch {
    throw new ImportParseError('Invalid H-Vault export: the file is not valid JSON.');
  }
  if (!Array.isArray(parsed.items)) {
    throw new ImportParseError('Invalid H-Vault export: expected an object with an "items" array.');
  }
  const items: Record<string, unknown>[] = [];
  let filtered = 0;
  for (const item of parsed.items as Record<string, unknown>[]) {
    const enc = item.encryptedData as string | undefined;
    const iv = item.dataIv as string | undefined;
    const tag = item.dataTag as string | undefined;
    const encName = item.encryptedName as string | undefined;
    const nameIv = item.nameIv as string | undefined;
    const nameTag = item.nameTag as string | undefined;
    if (!enc || !iv || !tag || !encName || !nameIv || !nameTag) {
      filtered++;
      continue;
    }
    try {
      await cryptoService.decryptData(enc, iv, tag, vaultKey);
      await cryptoService.decryptData(encName, nameIv, nameTag, vaultKey);
      items.push(item);
    } catch {
      filtered++;
    }
  }
  return { items, filtered };
}

// ---------------------------------------------------------------------------
// Password strength helpers
// ---------------------------------------------------------------------------

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
  4: 'bg-green-600',
};

// ---------------------------------------------------------------------------
// Theme options
// ---------------------------------------------------------------------------

const THEME_OPTIONS = [
  { value: 'light' as const, label: 'Light', icon: Sun },
  { value: 'dark' as const, label: 'Dark', icon: Moon },
  { value: 'system' as const, label: 'System', icon: Monitor },
];

export default function SettingsPage() {
  const { toast } = useToast();
  const navigate = useNavigate();
  const logout = useAuthStore((s) => s.logout);
  const user = useAuthStore((s) => s.user);
  const theme = useUIStore((s) => s.theme);
  const setTheme = useUIStore((s) => s.setTheme);

  const [profile, setProfile] = useState<IUserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [autoLockTimeout, setAutoLockTimeout] = useState(15);
  const [clipboardClearTimeout, setClipboardClearTimeout] = useState(30);
  const [savingSettings, setSavingSettings] = useState(false);
  const [zxcvbnFn, setZxcvbnFn] = useState<typeof zxcvbnType | null>(null);

  useEffect(() => {
    void getZxcvbn().then((fn) => setZxcvbnFn(() => fn));
  }, []);

  // Change password state
  const [showChangePassword, setShowChangePassword] = useState(false);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [changingPassword, setChangingPassword] = useState(false);

  // 2FA state
  const [show2faSetup, setShow2faSetup] = useState(false);
  const [show2faPasswordPrompt, setShow2faPasswordPrompt] = useState(false);
  const [twoFaPassword, setTwoFaPassword] = useState('');
  const [tfaSecret, setTfaSecret] = useState('');
  const [tfaQr, setTfaQr] = useState('');
  const [tfaCode, setTfaCode] = useState('');
  const [verifying2fa, setVerifying2fa] = useState(false);
  const [setting2fa, setSetting2fa] = useState(false);
  const [disabling2fa, setDisabling2fa] = useState(false);
  const [disable2faCode, setDisable2faCode] = useState('');
  const [disable2faPassword, setDisable2faPassword] = useState('');
  const [showDisable2fa, setShowDisable2fa] = useState(false);
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [showBackupCodes, setShowBackupCodes] = useState(false);
  const [showRegenerateBackupCodes, setShowRegenerateBackupCodes] = useState(false);
  const [regeneratePassword, setRegeneratePassword] = useState('');
  const [regenerateCode, setRegenerateCode] = useState('');
  const [regeneratingCodes, setRegeneratingCodes] = useState(false);

  // Export state
  const [showExportWarning, setShowExportWarning] = useState(false);
  const [exportPassword, setExportPassword] = useState('');
  const [exporting, setExporting] = useState(false);

  // Import state
  const [showImport, setShowImport] = useState(false);
  const [importData, setImportData] = useState('');
  const [importFormat, setImportFormat] = useState<ImportSourceFormat>('json');
  const [importing, setImporting] = useState(false);
  const [importProgress, setImportProgress] = useState<{ current: number; total: number } | null>(
    null,
  );
  const [conflictStrategy, setConflictStrategy] = useState<'skip' | 'overwrite' | 'keep_both'>(
    'skip',
  );

  const importFileRef = useRef<HTMLInputElement>(null);

  // CSV field mapping state
  const [csvHeaders, setCsvHeaders] = useState<string[]>([]);
  const [csvMapping, setCsvMapping] = useState<Record<string, string>>({});
  const [csvPreview, setCsvPreview] = useState<string[][]>([]);
  // Total data-row count for the preview header. Captured here from the single
  // parse below rather than re-derived in the JSX: an import file may be up to
  // MAX_IMPORT_FILE_SIZE_BYTES (8 MiB), and re-tokenizing it on every render —
  // every keystroke, every mapping dropdown change — blocks the main thread.
  const [csvRowCount, setCsvRowCount] = useState(0);

  // Vault key rotation state
  const [rotatingVaultKey, setRotatingVaultKey] = useState(false);
  const [rotationProgress, setRotationProgress] = useState(0);
  const [showRotateConfirm, setShowRotateConfirm] = useState(false);
  const [rotationPassword, setRotationPassword] = useState('');
  const [rotationBackupPassword, setRotationBackupPassword] = useState('');

  // Password strength
  const newPasswordStrength = useMemo(
    () => (newPassword && zxcvbnFn ? zxcvbnFn(newPassword) : null),
    [newPassword, zxcvbnFn],
  );

  // Parse CSV headers when import data or format changes
  useEffect(() => {
    if (importFormat === 'csv' && importData.trim()) {
      const { headers, rows } = parseCSV(importData);
      setCsvHeaders(headers);
      setCsvPreview(rows.slice(0, 3));
      setCsvRowCount(rows.length);
      // Auto-map common column names
      const mapping: Record<string, string> = {};
      for (const header of headers) {
        const lower = header.toLowerCase();
        if (lower.includes('name') || lower.includes('title')) mapping[header] = 'name';
        else if (lower.includes('user') || lower.includes('login')) mapping[header] = 'username';
        else if (lower.includes('pass')) mapping[header] = 'password';
        else if (lower.includes('url') || lower.includes('uri') || lower.includes('website'))
          mapping[header] = 'url';
        else if (lower.includes('note') || lower.includes('comment')) mapping[header] = 'notes';
        else if (lower.includes('totp') || lower.includes('otp') || lower.includes('2fa'))
          mapping[header] = 'totp';
        else if (lower.includes('folder') || lower.includes('group')) mapping[header] = 'folder';
        else mapping[header] = '';
      }
      setCsvMapping(mapping);
    } else {
      setCsvHeaders([]);
      setCsvMapping({});
      setCsvPreview([]);
      setCsvRowCount(0);
    }
  }, [importFormat, importData]);

  // Load profile on mount
  useEffect(() => {
    const loadProfile = async () => {
      try {
        const res = await getProfileApi();
        const profileResult = res.data;
        if (!profileResult.success) throw new Error('Failed to load profile');
        const p = profileResult.data;
        setProfile(p);
        setAutoLockTimeout(p.settings.autoLockTimeout);
        setClipboardClearTimeout(p.settings.clipboardClearTimeout);
      } catch {
        toast({ title: 'Failed to load profile', type: 'error' });
      } finally {
        setLoading(false);
      }
    };
    void loadProfile();
  }, [toast]);

  // Save settings
  const handleSaveSettings = useCallback(async () => {
    setSavingSettings(true);
    try {
      await updateSettingsApi({ autoLockTimeout, clipboardClearTimeout, theme });
      clearSettingsCache();
      toast({ title: 'Settings saved', type: 'success' });
    } catch {
      toast({ title: 'Failed to save settings', type: 'error' });
    } finally {
      setSavingSettings(false);
    }
  }, [autoLockTimeout, clipboardClearTimeout, theme, toast]);

  // Change master password
  const handleChangePassword = useCallback(async () => {
    if (newPassword !== confirmPassword) {
      toast({ title: 'Passwords do not match', type: 'error' });
      return;
    }
    const zxcvbnLoaded = await getZxcvbn();
    const strengthResult = zxcvbnLoaded(newPassword);
    if (strengthResult.score < 3) {
      toast({
        title: 'New password is too weak. Please choose a stronger password.',
        type: 'error',
      });
      return;
    }
    if (!user?.email) {
      toast({ title: 'User email not available', type: 'error' });
      return;
    }
    setChangingPassword(true);
    let newMek: CryptoKey | undefined;
    try {
      // Derive old keys
      const { authKey: currentAuthKey } = await cryptoService.deriveKeys(
        currentPassword,
        user.email,
      );
      const currentAuthHash = cryptoService.getAuthHash(currentAuthKey);
      cryptoService.clearKey(currentAuthKey);

      // Derive new keys
      const { masterEncryptionKey, authKey: newAuthKey } = await cryptoService.deriveKeys(
        newPassword,
        user.email,
      );
      newMek = masterEncryptionKey;
      const newAuthHash = cryptoService.getAuthHash(newAuthKey);
      cryptoService.clearKey(newAuthKey);

      // Re-encrypt vault key with new MEK
      const vaultKey = useAuthStore.getState().vaultKey;
      if (!vaultKey) {
        toast({ title: 'Vault is locked', type: 'error' });
        return;
      }
      const newEncrypted = await cryptoService.encryptVaultKey(vaultKey, newMek);

      await changePasswordApi({
        currentAuthHash,
        newAuthHash,
        newEncryptedVaultKey: newEncrypted.encrypted,
        newVaultKeyIv: newEncrypted.iv,
        newVaultKeyTag: newEncrypted.tag,
      });

      // Clean up the new MEK before logout clears everything
      await cryptoService.clearCryptoKey(newMek);
      newMek = undefined;

      // Force full logout — the server has already revoked all refresh tokens.
      // Without this, the current access token remains valid for up to 5 minutes,
      // and if the user locks then unlocks, the old MEK can't decrypt the new
      // encrypted vault key. The toast persists across the route change because
      // the toast provider lives above the router.
      toast({
        title: 'Password changed. Please log in again with your new password.',
        type: 'success',
      });
      await logout();
      void navigate('/login', { replace: true });
    } catch {
      toast({ title: 'Failed to change password', type: 'error' });
    } finally {
      if (newMek) await cryptoService.clearCryptoKey(newMek);
      setChangingPassword(false);
    }
  }, [currentPassword, newPassword, confirmPassword, user?.email, toast, logout, navigate]);

  // 2FA setup — prompt for password first, then call API
  const handleSetup2faPrompt = useCallback(() => {
    setTwoFaPassword('');
    setShow2faPasswordPrompt(true);
  }, []);

  const handleSetup2fa = useCallback(async () => {
    if (!twoFaPassword || !user?.email) return;
    setSetting2fa(true);
    try {
      const { authKey } = await cryptoService.deriveKeys(twoFaPassword, user.email);
      const authHash = cryptoService.getAuthHash(authKey);
      cryptoService.clearKey(authKey);
      const res = await setup2faApi({ password: authHash });
      const setupResult = res.data;
      if (!setupResult.success) throw new Error('Failed to start 2FA setup');
      const data = setupResult.data;
      setTfaSecret(data.secret);
      // The server returns an otpauth:// URI, not a data URL image.
      // Generate a real QR code data URL from the URI.
      const qrDataUrl = await QRCode.toDataURL(data.qrCodeDataUrl, { width: 200 });
      setTfaQr(qrDataUrl);
      setShow2faPasswordPrompt(false);
      setTwoFaPassword('');
      setShow2faSetup(true);
    } catch {
      toast({ title: 'Incorrect password or failed to start 2FA setup', type: 'error' });
    } finally {
      setSetting2fa(false);
    }
  }, [twoFaPassword, user?.email, toast]);

  const handleVerify2fa = useCallback(async () => {
    setVerifying2fa(true);
    try {
      const verifyRes = await verify2faApi({ code: tfaCode });
      const verifyResult = verifyRes.data;
      if (verifyResult.success && verifyResult.data.backupCodes.length > 0) {
        setBackupCodes(verifyResult.data.backupCodes);
        setShowBackupCodes(true);
      }
      toast({ title: '2FA enabled successfully', type: 'success' });
      setShow2faSetup(false);
      setTfaCode('');
      // Reload profile
      const res = await getProfileApi();
      const verifyProfileResult = res.data;
      if (verifyProfileResult.success) setProfile(verifyProfileResult.data);
    } catch {
      toast({ title: 'Invalid code', type: 'error' });
    } finally {
      setVerifying2fa(false);
    }
  }, [tfaCode, toast]);

  const handleDisable2fa = useCallback(async () => {
    const user = useAuthStore.getState().user;
    if (!user?.email) return;
    setDisabling2fa(true);
    try {
      const { authKey } = await cryptoService.deriveKeys(disable2faPassword, user.email);
      const authHash = cryptoService.getAuthHash(authKey);
      // Zero the derived auth material once the hash is computed (mirrors every
      // other key-deriving handler — getAuthHash does not consume the buffer).
      cryptoService.clearKey(authKey);
      await disable2faApi({ code: disable2faCode, password: authHash });
      toast({ title: '2FA disabled', type: 'success' });
      setShowDisable2fa(false);
      setDisable2faCode('');
      setDisable2faPassword('');
      const res = await getProfileApi();
      const disableProfileResult = res.data;
      if (disableProfileResult.success) setProfile(disableProfileResult.data);
    } catch {
      toast({ title: 'Invalid code or password', type: 'error' });
    } finally {
      setDisabling2fa(false);
    }
  }, [disable2faCode, disable2faPassword, toast]);

  const handleRegenerateBackupCodes = useCallback(async () => {
    const user = useAuthStore.getState().user;
    if (!user?.email || !regeneratePassword) return;
    setRegeneratingCodes(true);
    try {
      const { authKey } = await cryptoService.deriveKeys(regeneratePassword, user.email);
      const authHash = cryptoService.getAuthHash(authKey);
      cryptoService.clearKey(authKey);
      const res = await regenerateBackupCodesApi({
        password: authHash,
        ...(profile?.twoFactorEnabled && regenerateCode ? { code: regenerateCode } : {}),
      });
      const result = res.data;
      if (result.success && result.data.backupCodes.length > 0) {
        setBackupCodes(result.data.backupCodes);
        setShowRegenerateBackupCodes(false);
        setRegeneratePassword('');
        setRegenerateCode('');
        setShowBackupCodes(true);
        toast({ title: 'Backup codes regenerated', type: 'success' });
      }
    } catch {
      toast({ title: 'Failed to regenerate backup codes. Check your password.', type: 'error' });
    } finally {
      setRegeneratingCodes(false);
    }
  }, [regeneratePassword, regenerateCode, profile?.twoFactorEnabled, toast]);

  // Export
  const handleExport = useCallback(async () => {
    if (!exportPassword || !user?.email) {
      toast({ title: 'Password is required to export', type: 'error' });
      return;
    }
    setExporting(true);
    try {
      const { authKey } = await cryptoService.deriveKeys(exportPassword, user.email);
      const authHash = cryptoService.getAuthHash(authKey);
      cryptoService.clearKey(authKey);

      const res = await exportVaultApi({ format: 'json', authHash });
      const exportResult = res.data;
      if (!exportResult.success) throw new Error('Failed to export vault');
      const blob = new Blob([JSON.stringify(exportResult.data, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `hvault-export-${new Date().toISOString().split('T')[0]}.enc`;
      a.click();
      URL.revokeObjectURL(url);
      setExportPassword('');
      toast({ title: 'Vault exported', type: 'success' });
    } catch {
      toast({ title: 'Failed to export vault. Check your password.', type: 'error' });
    } finally {
      setExporting(false);
    }
  }, [toast, exportPassword, user?.email]);

  // Import file upload
  const handleImportFileUpload = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file) return;

      // Validate file type. A native H-Vault export/backup downloads as `.enc`
      // (JSON content); the OS reports an empty MIME type for `.enc`, so it must
      // be admitted by extension alongside the third-party JSON/CSV formats.
      if (
        !file.name.endsWith('.json') &&
        !file.name.endsWith('.csv') &&
        !file.name.endsWith('.enc') &&
        file.type !== 'application/json' &&
        file.type !== 'text/csv'
      ) {
        toast({ title: 'Only H-Vault (.enc), JSON, and CSV files are supported', type: 'error' });
        return;
      }

      // Validate file size. Parsing + encryption happen in the browser and the
      // encrypted payload is sent in size-bounded batches, so the raw file may be
      // larger than a single request body (the real ceiling is MAX_ITEMS_PER_USER).
      if (file.size > MAX_IMPORT_FILE_SIZE_BYTES) {
        toast({
          title: `File too large (max ${String(Math.round(MAX_IMPORT_FILE_SIZE_BYTES / 1_048_576))}MB)`,
          type: 'error',
        });
        return;
      }

      const reader = new FileReader();
      reader.onload = (event) => {
        const text = event.target?.result;
        if (typeof text === 'string') {
          setImportData(text);

          // Auto-detect format from file extension
          if (file.name.endsWith('.csv')) {
            // Sniff the header row to pre-select the matching source (Firefox,
            // LastPass, KeePass, Chrome, …); falls back to generic 'csv'.
            setImportFormat(detectCsvFormat(text));
          } else if (file.name.endsWith('.json') || file.name.endsWith('.enc')) {
            // `.enc` = a native H-Vault export (JSON content), detected as json below.
            // Try to detect specific format
            try {
              const parsed = JSON.parse(text) as Record<string, unknown>;
              // H-Vault exports have items with encryptedData fields
              const items = parsed.items as Record<string, unknown>[] | undefined;
              const isHVaultFormat =
                Array.isArray(items) &&
                items.length > 0 &&
                typeof items[0]?.encryptedData === 'string';
              if (
                isHVaultFormat ||
                (parsed.encrypted !== undefined && parsed.items !== undefined)
              ) {
                setImportFormat('json');
              } else if (
                parsed.folders !== undefined ||
                items?.some((i) => i.login != null || i.type != null)
              ) {
                setImportFormat('bitwarden');
              } else {
                setImportFormat('json');
              }
            } catch {
              setImportFormat('json');
            }
          }
        }
      };
      reader.readAsText(file);

      // Reset input so the same file can be re-selected
      e.target.value = '';
    },
    [toast],
  );

  // Import.
  //
  // Zero-knowledge pipeline: for any external source the browser parses the file,
  // converts each entry to a vault item, validates + encrypts it with the vault
  // key, and sends already-encrypted native items in size-bounded batches. The
  // native H-Vault (`json`) format is already encrypted, so it is only validated
  // for decryptability and re-sent. Plaintext never leaves the browser.
  const handleImport = useCallback(async () => {
    if (!importData.trim()) return;

    const vaultKey = useAuthStore.getState().vaultKey;
    if (!vaultKey) {
      toast({ title: 'Unlock your vault before importing', type: 'error' });
      return;
    }

    // Generic CSV needs at least one identifying column mapped; name is derived
    // from URL/username when unmapped, so any of the three suffices.
    if (
      importFormat === 'csv' &&
      !Object.values(csvMapping).some((v) => v === 'name' || v === 'url' || v === 'username')
    ) {
      toast({
        title: 'Map at least one of Name, URL, or Username before importing',
        type: 'error',
      });
      return;
    }

    setImporting(true);
    setImportProgress(null);
    try {
      let sendItems: unknown[];
      let clientSkipped = 0;
      // Why individual items were dropped during parse/encrypt. These are computed
      // by buildEncryptedImportItems and MUST be surfaced: a bare "7 skipped" gives
      // the user no way to tell which entries were lost or why (an over-long field
      // fails the whole item), and re-running the import cannot reveal it either.
      let skipReasons: string[] = [];

      if (importFormat === 'json') {
        const native = await extractNativeItems(importData, vaultKey);
        sendItems = native.items;
        clientSkipped = native.filtered;
        if (sendItems.length === 0) {
          toast({
            title:
              native.filtered > 0
                ? `All ${String(native.filtered)} items failed decryption and were rejected. They may be encrypted with a different vault key.`
                : 'No items found to import.',
            type: 'error',
          });
          return;
        }
      } else {
        const { items: parsed } = parseImportData(importFormat, importData, csvMapping);
        if (parsed.length === 0) {
          toast({ title: 'No items found in the file to import.', type: 'error' });
          return;
        }
        if (parsed.length > MAX_ITEMS_PER_USER) {
          toast({
            title: `Too many items (${String(parsed.length)}); the maximum is ${String(MAX_ITEMS_PER_USER)} per account.`,
            type: 'error',
          });
          return;
        }
        const built = await buildEncryptedImportItems(parsed, vaultKey);
        sendItems = built.items;
        clientSkipped = built.skipped;
        skipReasons = built.warnings;
        if (sendItems.length === 0) {
          toast({
            title: `No valid items to import; ${String(built.skipped)} could not be converted.`,
            ...(built.warnings.length > 0 ? { description: built.warnings.join('\n') } : {}),
            type: 'error',
          });
          return;
        }
      }

      // Split into requests each safely under the server's per-request data cap.
      const batches = chunkBySize(sendItems, Math.floor(MAX_IMPORT_DATA_LENGTH * 0.9));
      let imported = 0;
      let serverSkipped = 0;
      let duplicates = 0;
      let sentBatches = 0;

      try {
        for (let i = 0; i < batches.length; i++) {
          setImportProgress({ current: i + 1, total: batches.length });
          const res = await importVaultApi({
            format: importFormat,
            data: JSON.stringify({ items: batches[i] }),
            conflictStrategy,
          });
          const body = res.data;
          if (!body.success) throw new Error('Failed to import vault data');
          const r = body.data as {
            importedCount: number;
            skippedCount: number;
            duplicateCount?: number;
            overwrittenCount?: number;
          };
          imported += r.importedCount;
          serverSkipped += r.skippedCount;
          duplicates += r.duplicateCount ?? 0;
          sentBatches++;
        }
      } catch (batchErr) {
        // A later batch failed; earlier batches are already committed. Report the
        // partial result honestly and refresh so imported rows appear.
        const msg = getApiErrorMessage(batchErr, 'Failed to import some items');
        toast({
          title: sentBatches > 0 ? `Imported ${String(imported)} items, then stopped: ${msg}` : msg,
          type: 'error',
        });
        if (imported > 0) void useVaultStore.getState().fetchItems();
        return;
      }

      const parts = [`Imported ${String(imported)} items`];
      if (duplicates > 0) {
        parts.push(
          `${String(duplicates)} duplicates ${conflictStrategy === 'skip' ? 'skipped' : 'handled'}`,
        );
      }
      const totalSkipped = clientSkipped + serverSkipped;
      if (totalSkipped > 0) parts.push(`${String(totalSkipped)} skipped`);

      toast({
        title: parts.join(', '),
        // Name the entries that were dropped and why, rather than only counting them.
        ...(skipReasons.length > 0 ? { description: skipReasons.join('\n') } : {}),
        type: totalSkipped > 0 ? 'warning' : 'success',
      });
      void useVaultStore.getState().fetchItems();
      setShowImport(false);
      setImportData('');
    } catch (err) {
      const msg =
        err instanceof ImportParseError
          ? err.message
          : getApiErrorMessage(err, 'Failed to import vault data');
      toast({ title: msg, type: 'error' });
    } finally {
      setImporting(false);
      setImportProgress(null);
    }
  }, [importData, importFormat, csvMapping, conflictStrategy, toast]);

  // Vault key rotation — two-phase approach for atomicity
  const handleRotateVaultKey = useCallback(async () => {
    const { vaultKey: oldVaultKey, mek, user } = useAuthStore.getState();
    if (!oldVaultKey || !mek) {
      toast({ title: 'Vault is locked', type: 'error' });
      return;
    }

    if (!rotationPassword || !user?.email) {
      toast({ title: 'Password is required', type: 'error' });
      return;
    }

    setRotatingVaultKey(true);
    setRotationProgress(0);
    try {
      // Derive authHash from the master password for server-side verification
      const { authKey } = await cryptoService.deriveKeys(rotationPassword, user.email);
      const authHash = cryptoService.getAuthHash(authKey);
      cryptoService.clearKey(authKey);

      // Step 1: Generate new vault key
      const { newVaultKey, encrypted, iv, tag } = await cryptoService.rotateVaultKey(mek);

      // Step 2: Fetch all vault items (including trash)
      const { listItemsApi, listTrashApi } = await import('../services/api/vaultApi');
      const allItems: import('@hvault/shared').IVaultItemResponse[] = [];
      let page = 1;
      const perPage = 200;
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- pagination loop
      while (true) {
        const itemsRes = await listItemsApi({ page, limit: perPage });
        const itemsResult = itemsRes.data;
        if (!itemsResult.success) throw new Error('Failed to fetch vault items');
        allItems.push(...itemsResult.data);
        if (page >= itemsResult.pagination.totalPages) break;
        page++;
      }

      // Also fetch all trash items — they are encrypted with the same vault key
      let trashPage = 1;
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- pagination loop
      while (true) {
        const trashRes = await listTrashApi({ page: trashPage, limit: perPage });
        const trashResult = trashRes.data;
        if (!trashResult.success) throw new Error('Failed to fetch trash items');
        allItems.push(...trashResult.data);
        if (trashPage >= trashResult.pagination.totalPages) break;
        trashPage++;
      }
      const total = allItems.length;

      // Phase 1: Decrypt all items with old key and re-encrypt with new key
      // Collect ALL re-encrypted payloads before sending anything to the server.
      // If any single item fails, the entire rotation is aborted.
      const reEncryptedItems: {
        id: string;
        payload: {
          encryptedName: string;
          nameIv: string;
          nameTag: string;
          encryptedData: string;
          dataIv: string;
          dataTag: string;
          searchHash: string;
          passwordHistory?: {
            encryptedPassword: string;
            iv: string;
            tag: string;
            changedAt: string;
          }[];
        };
      }[] = [];

      for (const [i, item] of allItems.entries()) {
        try {
          // Decrypt name and data with old vault key
          const name = await cryptoService.decryptData(
            item.encryptedName,
            item.nameIv,
            item.nameTag,
            oldVaultKey,
          );
          const data = await cryptoService.decryptData(
            item.encryptedData,
            item.dataIv,
            item.dataTag,
            oldVaultKey,
          );

          // Re-encrypt with new vault key
          const encName = await cryptoService.encryptData(name, newVaultKey);
          const encData = await cryptoService.encryptData(data, newVaultKey);
          const searchHash = await cryptoService.generateSearchHash(name, newVaultKey);

          // Re-encrypt password history entries if present
          let reEncryptedHistory:
            { encryptedPassword: string; iv: string; tag: string; changedAt: string }[] | undefined;
          if (item.passwordHistory && item.passwordHistory.length > 0) {
            reEncryptedHistory = [];
            for (const entry of item.passwordHistory) {
              const plainPassword = await cryptoService.decryptData(
                entry.encryptedPassword,
                entry.iv,
                entry.tag,
                oldVaultKey,
              );
              const encPassword = await cryptoService.encryptData(plainPassword, newVaultKey);
              reEncryptedHistory.push({
                encryptedPassword: encPassword.encrypted,
                iv: encPassword.iv,
                tag: encPassword.tag,
                changedAt: entry.changedAt,
              });
            }
          }

          reEncryptedItems.push({
            id: item._id,
            payload: {
              encryptedName: encName.encrypted,
              nameIv: encName.iv,
              nameTag: encName.tag,
              encryptedData: encData.encrypted,
              dataIv: encData.iv,
              dataTag: encData.tag,
              searchHash,
              ...(reEncryptedHistory !== undefined ? { passwordHistory: reEncryptedHistory } : {}),
            },
          });
        } catch {
          // A single item failed — abort the entire rotation
          await cryptoService.clearCryptoKey(newVaultKey);
          toast({
            title: `Rotation aborted: failed to re-encrypt item ${i + 1} of ${total}`,
            type: 'error',
          });
          return;
        }

        // Show progress for phase 1 (re-encryption) as 0-50%
        setRotationProgress(Math.round(((i + 1) / total) * 50));
      }

      // Phase 1b: Re-encrypt folders
      const { listFoldersApi, bulkReEncryptApi } = await import('../services/api/vaultApi');
      setRotationProgress(55);
      const foldersRes = await listFoldersApi();
      const foldersResult = foldersRes.data;
      if (!foldersResult.success) throw new Error('Failed to fetch folders');
      const allFolders = foldersResult.data;

      const reEncryptedFolders: {
        id: string;
        encryptedName: string;
        nameIv: string;
        nameTag: string;
      }[] = [];

      for (const [i, folder] of allFolders.entries()) {
        try {
          const name = await cryptoService.decryptData(
            folder.encryptedName,
            folder.nameIv,
            folder.nameTag,
            oldVaultKey,
          );
          const encName = await cryptoService.encryptData(name, newVaultKey);
          reEncryptedFolders.push({
            id: folder._id,
            encryptedName: encName.encrypted,
            nameIv: encName.iv,
            nameTag: encName.tag,
          });
        } catch {
          await cryptoService.clearCryptoKey(newVaultKey);
          toast({
            title: `Rotation aborted: failed to re-encrypt folder ${i + 1} of ${allFolders.length}`,
            type: 'error',
          });
          return;
        }
      }

      // Phase 2: All re-encryptions succeeded — commit atomically to the server
      setRotationProgress(60);
      const idempotencyKey = crypto.randomUUID();
      await bulkReEncryptApi({
        authHash,
        idempotencyKey,
        items: reEncryptedItems.map((entry) => ({
          id: entry.id,
          ...entry.payload,
        })),
        folders: reEncryptedFolders,
        newEncryptedVaultKey: encrypted,
        newVaultKeyIv: iv,
        newVaultKeyTag: tag,
      });
      setRotationProgress(100);

      // Step 5: Update BWK-encrypted vault key if backup is configured
      try {
        const { getProfileApi } = await import('../services/api/userApi');
        const profileRes = await getProfileApi();
        const profileData = profileRes.data;
        if (profileData.success) {
          const backup = profileData.data.settings.backup;
          if (
            backup.isConfigured &&
            backup.encryptedBWK &&
            backup.bwkIv &&
            backup.bwkTag &&
            backup.bwkSalt
          ) {
            if (rotationBackupPassword) {
              // User provided backup password — decrypt BWK and re-encrypt new vault key
              const bwkSalt = cryptoService.base64ToArrayBuffer(backup.bwkSalt);
              const bek = await cryptoService.deriveBEK(rotationBackupPassword, bwkSalt);
              const rawBwk = await cryptoService.decryptBWK(
                backup.encryptedBWK,
                backup.bwkIv,
                backup.bwkTag,
                bek,
              );
              const bwkVaultKeyData = await cryptoService.encryptVaultKeyWithBWK(
                newVaultKey,
                rawBwk,
              );
              cryptoService.clearKey(rawBwk);
              await cryptoService.clearCryptoKey(bek);

              await api.post('/backup/setup', {
                authHash,
                encryptedBWK: backup.encryptedBWK,
                bwkIv: backup.bwkIv,
                bwkTag: backup.bwkTag,
                bwkSalt: backup.bwkSalt,
                bwkEncryptedVaultKey: bwkVaultKeyData.encrypted,
                bwkVaultKeyIv: bwkVaultKeyData.iv,
                bwkVaultKeyTag: bwkVaultKeyData.tag,
              });
            } else {
              // No backup password — clear stale bwkEncryptedVaultKey
              await api.post('/backup/setup', {
                authHash,
                encryptedBWK: backup.encryptedBWK,
                bwkIv: backup.bwkIv,
                bwkTag: backup.bwkTag,
                bwkSalt: backup.bwkSalt,
              });
              toast({
                title:
                  'Vault key rotated. To restore backups on a different account, please update your backup password.',
                type: 'warning',
              });
            }
          }
        }
      } catch {
        // Non-critical — backup will still work, just without BWK-encrypted vault key
      }

      // Step 6: Update client state
      void cryptoService.clearCryptoKey(oldVaultKey);
      useAuthStore.setState({
        vaultKey: newVaultKey,
        encryptedVaultKeyData: { encrypted, iv, tag },
      });

      toast({ title: 'Vault key rotated successfully', type: 'success' });
      setShowRotateConfirm(false);
      setRotationPassword('');
      setRotationBackupPassword('');
    } catch {
      toast({ title: 'Failed to rotate vault key', type: 'error' });
    } finally {
      setRotatingVaultKey(false);
      setRotationProgress(0);
    }
  }, [rotationPassword, rotationBackupPassword, toast]);

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
      <h1 className="flex items-center gap-2 text-2xl font-bold text-[hsl(var(--foreground))]">
        <Settings className="h-6 w-6" />
        Settings
      </h1>

      {/* Profile */}
      <Card>
        <CardHeader>
          <CardTitle>Profile</CardTitle>
          <CardDescription>Your account information</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm text-[hsl(var(--muted-foreground))]">Email</span>
            <span className="text-sm font-medium text-[hsl(var(--foreground))]">
              {profile?.email}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm text-[hsl(var(--muted-foreground))]">Email Verified</span>
            <span
              className={cn(
                'flex items-center gap-1 text-sm font-medium',
                profile?.emailVerified ? 'text-green-600' : 'text-yellow-600',
              )}
            >
              {profile?.emailVerified ? (
                <>
                  <CheckCircle className="h-4 w-4" /> Verified
                </>
              ) : (
                <>
                  <XCircle className="h-4 w-4" /> Not verified
                </>
              )}
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Security */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" /> Security
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Change password */}
          <div className="rounded-lg border border-[hsl(var(--border))] p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Key className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />
                <span className="text-sm font-medium text-[hsl(var(--foreground))]">
                  Master Password
                </span>
              </div>
              <button
                type="button"
                onClick={() => setShowChangePassword((p) => !p)}
                className="text-sm text-[hsl(var(--primary))] hover:underline"
              >
                Change
              </button>
            </div>
            {showChangePassword && (
              <div className="mt-4 space-y-3">
                <input
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  placeholder="Current master password"
                  className={inputClass}
                  autoComplete="current-password"
                />
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="New master password"
                  className={inputClass}
                  autoComplete="new-password"
                />
                {newPasswordStrength && (
                  <div className="space-y-1">
                    <div className="flex gap-1">
                      {[0, 1, 2, 3, 4].map((i) => (
                        <div
                          key={i}
                          className={cn(
                            'h-1.5 flex-1 rounded-full transition-colors',
                            i <= newPasswordStrength.score
                              ? strengthColors[newPasswordStrength.score]
                              : 'bg-[hsl(var(--muted))]',
                          )}
                        />
                      ))}
                    </div>
                    <p className="text-xs text-[hsl(var(--muted-foreground))]">
                      {strengthLabels[newPasswordStrength.score]}
                    </p>
                  </div>
                )}
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm new password"
                  className={inputClass}
                  autoComplete="new-password"
                />
                <div className="flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setShowChangePassword(false)}
                    className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleChangePassword()}
                    disabled={
                      changingPassword || !currentPassword || !newPassword || !confirmPassword
                    }
                    className="rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
                  >
                    {changingPassword ? 'Changing...' : 'Change Password'}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* 2FA */}
          <div className="rounded-lg border border-[hsl(var(--border))] p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Lock className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />
                <span className="text-sm font-medium text-[hsl(var(--foreground))]">
                  Two-Factor Authentication
                </span>
                <span
                  className={cn(
                    'rounded-full px-2 py-0.5 text-xs font-medium',
                    profile?.twoFactorEnabled
                      ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                      : 'bg-[hsl(var(--muted))] text-[hsl(var(--muted-foreground))]',
                  )}
                >
                  {profile?.twoFactorEnabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>
              {profile?.twoFactorEnabled ? (
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setShowRegenerateBackupCodes((p) => !p)}
                    className="text-sm text-[hsl(var(--primary))] hover:underline"
                  >
                    Regenerate Codes
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowDisable2fa((p) => !p)}
                    className="text-sm text-[hsl(var(--destructive))] hover:underline"
                  >
                    Disable
                  </button>
                </div>
              ) : (
                <button
                  type="button"
                  onClick={handleSetup2faPrompt}
                  disabled={setting2fa}
                  className="text-sm text-[hsl(var(--primary))] hover:underline"
                >
                  {setting2fa ? 'Setting up...' : 'Enable'}
                </button>
              )}
            </div>

            {/* 2FA password prompt */}
            {show2faPasswordPrompt && (
              <div className="mt-4 space-y-3">
                <p className="text-sm text-[hsl(var(--muted-foreground))]">
                  Enter your master password to enable two-factor authentication.
                </p>
                <input
                  type="password"
                  value={twoFaPassword}
                  onChange={(e) => setTwoFaPassword(e.target.value)}
                  placeholder="Master password"
                  className={cn(inputClass)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && twoFaPassword.length > 0) {
                      void handleSetup2fa();
                    }
                  }}
                />
                <div className="flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setShow2faPasswordPrompt(false);
                      setTwoFaPassword('');
                    }}
                    className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleSetup2fa()}
                    disabled={setting2fa || twoFaPassword.length === 0}
                    className="rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
                  >
                    {setting2fa ? 'Verifying...' : 'Continue'}
                  </button>
                </div>
              </div>
            )}

            {/* 2FA setup */}
            {show2faSetup && (
              <div className="mt-4 space-y-4">
                {tfaQr && (
                  <div className="flex justify-center">
                    <img src={tfaQr} alt="2FA QR Code" className="h-48 w-48" />
                  </div>
                )}
                <p className="text-center text-xs text-[hsl(var(--muted-foreground))]">
                  Scan the QR code with your authenticator app, then enter the 6-digit code below.
                </p>
                {tfaSecret && (
                  <div className="rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--muted))] p-3 text-center">
                    <p className="text-xs text-[hsl(var(--muted-foreground))] mb-1">
                      Can't scan? Enter this secret manually:
                    </p>
                    <code
                      className="cursor-pointer select-all font-mono text-sm font-medium tracking-widest text-[hsl(var(--foreground))]"
                      onClick={() => {
                        void navigator.clipboard
                          .writeText(tfaSecret)
                          .then(() => {
                            toast({ title: 'Secret copied', type: 'success', duration: 2000 });
                          })
                          .catch(() => {
                            /* ignore */
                          });
                      }}
                      title="Click to copy"
                    >
                      {tfaSecret}
                    </code>
                  </div>
                )}
                <input
                  type="text"
                  value={tfaCode}
                  onChange={(e) => setTfaCode(e.target.value)}
                  placeholder="6-digit code"
                  maxLength={6}
                  className={cn(inputClass, 'text-center tracking-widest')}
                />
                <div className="flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setShow2faSetup(false)}
                    className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleVerify2fa()}
                    disabled={verifying2fa || tfaCode.length !== 6}
                    className="rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
                  >
                    {verifying2fa ? 'Verifying...' : 'Verify'}
                  </button>
                </div>
              </div>
            )}

            {/* Regenerate Backup Codes */}
            {showRegenerateBackupCodes && (
              <div className="mt-4 space-y-3">
                <p className="text-sm text-[hsl(var(--muted-foreground))]">
                  Enter your master password{profile?.twoFactorEnabled ? ' and 2FA code' : ''} to
                  regenerate backup codes. All existing codes will be invalidated.
                </p>
                <input
                  type="password"
                  value={regeneratePassword}
                  onChange={(e) => setRegeneratePassword(e.target.value)}
                  placeholder="Master password"
                  className={inputClass}
                  onKeyDown={(e) => {
                    if (
                      e.key === 'Enter' &&
                      regeneratePassword.length > 0 &&
                      (!profile?.twoFactorEnabled || regenerateCode.length === 6)
                    ) {
                      void handleRegenerateBackupCodes();
                    }
                  }}
                />
                {profile?.twoFactorEnabled && (
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    value={regenerateCode}
                    onChange={(e) =>
                      setRegenerateCode(e.target.value.replace(/\D/g, '').slice(0, 6))
                    }
                    placeholder="6-digit 2FA code"
                    className={inputClass}
                    autoComplete="one-time-code"
                  />
                )}
                <div className="flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setShowRegenerateBackupCodes(false);
                      setRegeneratePassword('');
                      setRegenerateCode('');
                    }}
                    className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleRegenerateBackupCodes()}
                    disabled={
                      regeneratingCodes ||
                      regeneratePassword.length === 0 ||
                      (!!profile?.twoFactorEnabled && regenerateCode.length !== 6)
                    }
                    className="rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
                  >
                    {regeneratingCodes ? 'Regenerating...' : 'Regenerate'}
                  </button>
                </div>
              </div>
            )}

            {/* Disable 2FA */}
            {showDisable2fa && (
              <div className="mt-4 space-y-3">
                <p className="text-sm text-[hsl(var(--muted-foreground))]">
                  Enter your master password and a 2FA code to disable two-factor authentication.
                </p>
                <input
                  type="password"
                  value={disable2faPassword}
                  onChange={(e) => setDisable2faPassword(e.target.value)}
                  placeholder="Master password"
                  className={inputClass}
                />
                <input
                  type="text"
                  value={disable2faCode}
                  onChange={(e) => setDisable2faCode(e.target.value)}
                  placeholder="6-digit code"
                  maxLength={8}
                  className={cn(inputClass, 'text-center tracking-widest')}
                />
                <div className="flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setShowDisable2fa(false)}
                    className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleDisable2fa()}
                    disabled={
                      disabling2fa || disable2faCode.length < 6 || disable2faPassword.length === 0
                    }
                    className="rounded-md bg-[hsl(var(--destructive))] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive-foreground))] hover:opacity-90 disabled:opacity-50"
                  >
                    {disabling2fa ? 'Disabling...' : 'Disable 2FA'}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Backup Codes Dialog */}
          <Dialog open={showBackupCodes} onOpenChange={setShowBackupCodes}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Save Your Backup Codes</DialogTitle>
                <DialogDescription>
                  Store these codes in a safe place. Each code can only be used once to sign in if
                  you lose access to your authenticator app.
                </DialogDescription>
              </DialogHeader>
              <div className="grid grid-cols-2 gap-2 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--muted))] p-4">
                {backupCodes.map((code, i) => (
                  <code
                    key={i}
                    className="font-mono text-sm text-[hsl(var(--foreground))] tracking-wider"
                  >
                    {code}
                  </code>
                ))}
              </div>
              <div className="flex items-center gap-2 rounded-md border border-[hsl(var(--warning,40_96%_40%)/0.3)] bg-[hsl(var(--warning,40_96%_40%)/0.05)] p-3 text-sm text-[hsl(var(--warning,40_96%_40%))]">
                <Shield className="h-4 w-4 shrink-0" />
                <span>These codes will not be shown again.</span>
              </div>
              <DialogFooter>
                <button
                  type="button"
                  onClick={() => {
                    void navigator.clipboard
                      .writeText(backupCodes.join('\n'))
                      .then(() => {
                        toast({
                          title: 'Backup codes copied to clipboard',
                          type: 'success',
                          duration: 2000,
                        });
                      })
                      .catch(() => {
                        /* ignore */
                      });
                  }}
                  className="rounded-md border border-[hsl(var(--border))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
                >
                  Copy All
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowBackupCodes(false);
                    setBackupCodes([]);
                  }}
                  className="rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90"
                >
                  I've Saved These Codes
                </button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          {/* Links */}
          <Link
            to="/settings/sessions"
            className="flex items-center justify-between rounded-lg p-3 hover:bg-[hsl(var(--accent))] transition-colors"
          >
            <div className="flex items-center gap-3">
              <Monitor className="h-5 w-5 text-[hsl(var(--muted-foreground))]" />
              <div>
                <p className="text-sm font-medium text-[hsl(var(--foreground))]">Active Sessions</p>
                <p className="text-xs text-[hsl(var(--muted-foreground))]">
                  Manage your active sessions
                </p>
              </div>
            </div>
            <ChevronRight className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />
          </Link>
          <Link
            to="/settings/audit"
            className="flex items-center justify-between rounded-lg p-3 hover:bg-[hsl(var(--accent))] transition-colors"
          >
            <div className="flex items-center gap-3">
              <FileText className="h-5 w-5 text-[hsl(var(--muted-foreground))]" />
              <div>
                <p className="text-sm font-medium text-[hsl(var(--foreground))]">Audit Log</p>
                <p className="text-xs text-[hsl(var(--muted-foreground))]">View security events</p>
              </div>
            </div>
            <ChevronRight className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />
          </Link>
        </CardContent>
      </Card>

      {/* Vault Settings */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Key className="h-5 w-5" /> Vault
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />
              <span className="text-sm text-[hsl(var(--foreground))]">
                Auto-lock timeout (minutes)
              </span>
            </div>
            <input
              type="number"
              min={1}
              max={1440}
              value={autoLockTimeout}
              onChange={(e) => setAutoLockTimeout(Number(e.target.value))}
              className={cn(inputClass, 'w-20')}
            />
          </div>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Clipboard className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />
              <span className="text-sm text-[hsl(var(--foreground))]">
                Clipboard clear (seconds)
              </span>
            </div>
            <input
              type="number"
              min={5}
              max={300}
              value={clipboardClearTimeout}
              onChange={(e) => setClipboardClearTimeout(Number(e.target.value))}
              className={cn(inputClass, 'w-20')}
            />
          </div>

          {/* Vault Key Rotation */}
          <div className="border-t border-[hsl(var(--border))] pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-[hsl(var(--foreground))]">
                  Rotate Vault Key
                </p>
                <p className="text-xs text-[hsl(var(--muted-foreground))]">
                  Generate a new vault key and re-encrypt all items
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowRotateConfirm(true)}
                disabled={rotatingVaultKey}
                className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors disabled:opacity-50"
              >
                {rotatingVaultKey ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Key className="h-4 w-4" />
                )}
                {rotatingVaultKey ? `Rotating... ${rotationProgress}%` : 'Rotate Key'}
              </button>
            </div>
            {rotatingVaultKey && (
              <div className="mt-3">
                <div className="h-2 w-full rounded-full bg-[hsl(var(--muted))]">
                  <div
                    className="h-2 rounded-full bg-[hsl(var(--primary))] transition-all duration-300"
                    style={{ width: `${rotationProgress}%` }}
                  />
                </div>
                <p className="mt-1 text-xs text-[hsl(var(--muted-foreground))]">
                  Re-encrypting vault items... Do not close this page.
                </p>
              </div>
            )}
          </div>

          {/* Rotate confirmation dialog */}
          <Dialog
            open={showRotateConfirm}
            onOpenChange={(open) => {
              if (!open) {
                setShowRotateConfirm(false);
                setRotationPassword('');
                setRotationBackupPassword('');
              }
            }}
          >
            <DialogContent
              className="max-w-sm"
              onClose={() => {
                setShowRotateConfirm(false);
                setRotationPassword('');
                setRotationBackupPassword('');
              }}
            >
              <DialogHeader>
                <DialogTitle>Rotate Vault Key</DialogTitle>
                <DialogDescription>
                  This will generate a new vault key and re-encrypt all your vault items. This
                  operation cannot be undone. Make sure you have a recent backup.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <label
                    htmlFor="rotation-password"
                    className="block text-sm font-medium text-[hsl(var(--foreground))]"
                  >
                    Enter your master password to confirm
                  </label>
                  <input
                    id="rotation-password"
                    type="password"
                    value={rotationPassword}
                    onChange={(e) => setRotationPassword(e.target.value)}
                    placeholder="Master password"
                    className={inputClass + ' mt-1'}
                    autoComplete="current-password"
                  />
                </div>
                {profile?.settings.backup.isConfigured && (
                  <div>
                    <label
                      htmlFor="rotation-backup-password"
                      className="block text-sm font-medium text-[hsl(var(--foreground))]"
                    >
                      Backup password{' '}
                      <span className="font-normal text-[hsl(var(--muted-foreground))]">
                        (optional)
                      </span>
                    </label>
                    <input
                      id="rotation-backup-password"
                      type="password"
                      value={rotationBackupPassword}
                      onChange={(e) => setRotationBackupPassword(e.target.value)}
                      placeholder="Backup password"
                      className={inputClass + ' mt-1'}
                      autoComplete="off"
                    />
                    <p className="mt-1 text-xs text-[hsl(var(--muted-foreground))]">
                      Enter your backup password to maintain cross-account restore capability. If
                      left empty, you&apos;ll need to update your backup password later.
                    </p>
                  </div>
                )}
              </div>
              <DialogFooter>
                <button
                  type="button"
                  onClick={() => {
                    setShowRotateConfirm(false);
                    setRotationPassword('');
                    setRotationBackupPassword('');
                  }}
                  className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => void handleRotateVaultKey()}
                  disabled={rotatingVaultKey || !rotationPassword}
                  className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
                >
                  {rotatingVaultKey && <Loader2 className="h-4 w-4 animate-spin" />}
                  Confirm Rotation
                </button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </CardContent>
      </Card>

      {/* Appearance */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Palette className="h-5 w-5" /> Appearance
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-3">
            {THEME_OPTIONS.map(({ value, label, icon: Icon }) => (
              <button
                key={value}
                type="button"
                onClick={() => setTheme(value)}
                className={cn(
                  'flex flex-1 flex-col items-center gap-2 rounded-lg border p-4 transition-colors',
                  theme === value
                    ? 'border-[hsl(var(--primary))] bg-[hsl(var(--primary)/0.05)]'
                    : 'border-[hsl(var(--border))] hover:bg-[hsl(var(--accent))]',
                )}
              >
                <Icon className="h-5 w-5 text-[hsl(var(--foreground))]" />
                <span className="text-sm text-[hsl(var(--foreground))]">{label}</span>
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Data */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" /> Data
          </CardTitle>
          <CardDescription>Export or import your vault data</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap gap-3">
            <button
              type="button"
              onClick={() => setShowExportWarning(true)}
              className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-4 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
            >
              <Download className="h-4 w-4" /> Export Vault
            </button>
            <button
              type="button"
              onClick={() => setShowImport((p) => !p)}
              className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-4 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
            >
              <Upload className="h-4 w-4" /> Import Vault
            </button>
          </div>
          {showExportWarning && (
            <div className="space-y-3 rounded-lg border border-[hsl(var(--warning,45_93%_47%))/0.5] bg-[hsl(var(--warning,45_93%_47%))/0.05] p-4">
              <div className="flex items-start gap-2">
                <AlertTriangle className="h-5 w-5 shrink-0 text-amber-500 mt-0.5" />
                <div className="space-y-2 text-sm text-[hsl(var(--foreground))]">
                  <p className="font-medium">Important: Export Limitations</p>
                  <p>
                    Exported vault data is encrypted with your current vault key. This export will{' '}
                    <strong>not be usable</strong> if you:
                  </p>
                  <ul className="list-disc pl-5 space-y-1">
                    <li>Rotate your vault key (Settings &rarr; Vault &rarr; Rotate Key)</li>
                    <li>Create a new account (even with the same email and password)</li>
                  </ul>
                  <p>
                    For a portable backup that survives key rotations and account recreation, use
                    the <strong>Backup</strong> system instead (Settings &rarr; Backup).
                  </p>
                </div>
              </div>
              <div className="space-y-2 pt-1">
                <label className="block text-sm font-medium text-[hsl(var(--foreground))]">
                  Confirm Master Password
                </label>
                <input
                  type="password"
                  value={exportPassword}
                  onChange={(e) => setExportPassword(e.target.value)}
                  placeholder="Enter your master password"
                  className={inputClass}
                  autoComplete="current-password"
                />
              </div>
              <div className="flex justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => {
                    setShowExportWarning(false);
                    setExportPassword('');
                  }}
                  className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  disabled={exporting || !exportPassword}
                  onClick={() => {
                    setShowExportWarning(false);
                    void handleExport();
                  }}
                  className="rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
                >
                  {exporting ? 'Exporting...' : 'I Understand, Export'}
                </button>
              </div>
            </div>
          )}
          {showImport && (
            <div className="space-y-3 rounded-lg border border-[hsl(var(--border))] p-4">
              <select
                value={importFormat}
                onChange={(e) => setImportFormat(e.target.value as ImportSourceFormat)}
                className={inputClass}
              >
                {IMPORT_FORMATS.map((f) => (
                  <option key={f.value} value={f.value}>
                    {f.label}
                  </option>
                ))}
              </select>
              <div className="flex items-center gap-3">
                <input
                  ref={importFileRef}
                  type="file"
                  accept=".enc,.json,.csv"
                  onChange={handleImportFileUpload}
                  className="hidden"
                />
                <button
                  type="button"
                  onClick={() => importFileRef.current?.click()}
                  className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
                >
                  <Upload className="h-4 w-4" />
                  Upload File
                </button>
                <span className="text-xs text-[hsl(var(--muted-foreground))]">
                  H-Vault (.enc), JSON, or CSV (max{' '}
                  {String(Math.round(MAX_IMPORT_FILE_SIZE_BYTES / 1_048_576))}MB)
                </span>
              </div>
              <p className="text-xs text-[hsl(var(--muted-foreground))]">Or paste data below:</p>
              <textarea
                value={importData}
                onChange={(e) => setImportData(e.target.value)}
                placeholder="Paste exported data here..."
                rows={6}
                className={cn(inputClass, 'font-mono resize-y')}
              />

              {/* CSV Field Mapping UI */}
              {importFormat === 'csv' && csvHeaders.length > 0 && (
                <div className="space-y-3">
                  <h4 className="text-sm font-medium text-[hsl(var(--foreground))]">
                    Map CSV Columns
                  </h4>
                  <div className="space-y-2">
                    {csvHeaders.map((header) => (
                      <div key={header} className="flex items-center gap-3">
                        <span
                          className="w-32 truncate text-sm text-[hsl(var(--muted-foreground))]"
                          title={header}
                        >
                          {header}
                        </span>
                        <span className="text-sm text-[hsl(var(--muted-foreground))]">&rarr;</span>
                        <select
                          value={csvMapping[header] ?? ''}
                          onChange={(e) =>
                            setCsvMapping((prev) => ({ ...prev, [header]: e.target.value }))
                          }
                          className={cn(inputClass, 'flex-1')}
                        >
                          {HVAULT_FIELDS.map((f) => (
                            <option key={f.value} value={f.value}>
                              {f.label}
                            </option>
                          ))}
                        </select>
                      </div>
                    ))}
                  </div>

                  {/* Preview */}
                  {csvPreview.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-sm font-medium text-[hsl(var(--foreground))]">
                        Preview ({csvPreview.length} of {csvRowCount} rows)
                      </h4>
                      <div className="overflow-x-auto rounded-md border border-[hsl(var(--border))]">
                        <table className="w-full text-xs">
                          <thead>
                            <tr className="border-b border-[hsl(var(--border))] bg-[hsl(var(--muted))]">
                              {csvHeaders.map((h) => {
                                const mapped = csvMapping[h];
                                const field = HVAULT_FIELDS.find((f) => f.value === mapped);
                                return (
                                  <th
                                    key={h}
                                    className="px-2 py-1 text-left font-medium text-[hsl(var(--muted-foreground))]"
                                  >
                                    {field && mapped ? (
                                      field.label
                                    ) : (
                                      <span className="italic text-[hsl(var(--muted-foreground))]">
                                        Skip
                                      </span>
                                    )}
                                  </th>
                                );
                              })}
                            </tr>
                          </thead>
                          <tbody>
                            {csvPreview.map((row, i) => (
                              <tr
                                key={i}
                                className="border-b border-[hsl(var(--border))] last:border-0"
                              >
                                {row.map((cell, j) => {
                                  const mapped = csvMapping[csvHeaders[j] ?? ''];
                                  return (
                                    <td
                                      key={j}
                                      className={cn(
                                        'max-w-[150px] truncate px-2 py-1 text-[hsl(var(--foreground))]',
                                        !mapped && 'opacity-40',
                                      )}
                                    >
                                      {cell}
                                    </td>
                                  );
                                })}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              )}

              <div className="space-y-1">
                <label className="text-sm font-medium text-[hsl(var(--foreground))]">
                  If duplicates are found
                </label>
                <select
                  value={conflictStrategy}
                  onChange={(e) =>
                    setConflictStrategy(e.target.value as 'skip' | 'overwrite' | 'keep_both')
                  }
                  className="w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))]"
                >
                  <option value="skip">Skip duplicates</option>
                  <option value="overwrite">Overwrite existing</option>
                  <option value="keep_both">Keep both</option>
                </select>
              </div>

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowImport(false)}
                  className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => void handleImport()}
                  disabled={importing || !importData.trim()}
                  className="rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
                >
                  {importing
                    ? importProgress
                      ? `Importing (${String(importProgress.current)}/${String(importProgress.total)})...`
                      : 'Importing...'
                    : 'Import'}
                </button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Account */}
      <Card>
        <CardHeader>
          <CardTitle>Account</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <Link
            to="/settings/backup"
            className="flex items-center justify-between rounded-lg p-3 hover:bg-[hsl(var(--accent))] transition-colors"
          >
            <div className="flex items-center gap-3">
              <History className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />
              <span className="text-sm text-[hsl(var(--foreground))]">Backup Settings</span>
            </div>
            <ChevronRight className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />
          </Link>
        </CardContent>
      </Card>

      {/* Save button */}
      <div className="flex justify-end pb-6">
        <button
          type="button"
          onClick={() => void handleSaveSettings()}
          disabled={savingSettings}
          className="rounded-md bg-[hsl(var(--primary))] px-6 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity disabled:opacity-50"
        >
          {savingSettings ? 'Saving...' : 'Save Settings'}
        </button>
      </div>
    </div>
  );
}
