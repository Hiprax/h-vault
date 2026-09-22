import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { isAxiosError } from 'axios';
import { Link, useNavigate } from 'react-router';
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
  LogOut,
  EyeOff,
} from 'lucide-react';
import QRCode from 'qrcode';
import type zxcvbnType from 'zxcvbn';
import { getZxcvbn } from '../lib/lazyZxcvbn';
import { cn, getApiErrorMessage } from '../lib/utils';
import { downloadText } from '../lib/download';
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
  AUTO_LOCK_MAX_MINUTES,
  AUTO_LOCK_MIN_MINUTES,
  AUTO_LOCK_TIMEOUT_MINUTES,
  CLIPBOARD_CLEAR_MAX_SECONDS,
  CLIPBOARD_CLEAR_MIN_SECONDS,
  CLIPBOARD_CLEAR_SECONDS,
  LOCK_ON_HIDDEN_DEFAULT,
  LOCK_ON_HIDDEN_DELAY_MINUTES,
  ITEM_TYPES,
  MAX_IMPORT_FILE_SIZE_BYTES,
  MAX_ITEMS_PER_USER,
  MAX_TAG_LENGTH,
  MAX_TAGS_PER_ITEM,
  PASSWORD_HISTORY_MAX,
} from '@hvault/shared';
import type {
  BulkReEncryptInput,
  DocumentResponse,
  IFolderResponse,
  IPasswordHistoryEntry,
  ItemType,
  IUserProfile,
  IVaultItemResponse,
  PaginatedResponse,
} from '@hvault/shared';
import {
  DOCUMENT_PAGE_SIZE,
  MAX_DOCUMENT_PAGES,
  listDocumentTrashApi,
  listDocumentsApi,
  // The ONE reader of the refusal that carries a number, wherever that refusal
  // is answered. It lives beside the document routes because those were the
  // first to answer it; it is not document-specific, and a second copy here
  // would be a second place for "a 409 whose body has no non-negative integer
  // is an ordinary conflict" to drift.
  staleVaultKeyVersion,
} from '../services/api/documentsApi';
import { readDocumentsConfigFresh } from '../services/api/configApi';
import {
  deriveWrapKey,
  unwrapDek,
  wrapDek,
  zeroDek,
  type DocumentBytes,
} from '../services/crypto/documentCryptoService';
import { clearSettingsCache } from '../hooks/useUserSettings';
import { copySecretToClipboard } from '../services/clipboard/clipboardService';
import { getItemsFetchGeneration, useVaultStore } from '../stores/vaultStore';
import { passwordDidChange } from '../services/crypto/passwordHistory';
import { parseCsv } from '../services/import/csv';
import {
  IMPORT_FORMATS,
  ImportParseError,
  MAX_IMPORT_WARNINGS,
  buildImportOperations,
  chunkImportOperations,
  detectCsvFormat,
  parseImportData,
  resolveImport,
  validateImportItems,
} from '../services/import';
import type {
  ImportSourceFormat,
  NativeCiphertext,
  ResolvableImportItem,
} from '../services/import';

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
  // Named "2FA Recovery Codes", not "Backup Codes": this same page already uses
  // that phrase for the ACCOUNT's own 2FA recovery codes, which are a different
  // thing entirely (server-side, bcrypt-hashed, for signing in to H-Vault).
  { value: 'backupCodes', label: '2FA Recovery Codes' },
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

// ---------------------------------------------------------------------------
// Native (H-Vault export) import helpers
// ---------------------------------------------------------------------------

const OBJECT_ID_RE = /^[0-9a-fA-F]{24}$/;
/** Mirrors the `encryptedPassword` maxlength on the VaultItem model. */
const MAX_HISTORY_PASSWORD_LENGTH = 5_000;

interface NativeExtraction {
  /** Rows that decrypted cleanly, ready for conflict resolution. */
  items: ResolvableImportItem[];
  /** How many rows in the file could not be used. */
  filtered: number;
  /** Bounded, human-readable reasons for those rows. */
  reasons: string[];
  /** Every row the file contained, so the outcome counts can sum to it. */
  total: number;
}

/** True for a plain object — a hand-corrupted export may hold `null` or a scalar. */
function isRow(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The six ciphertext fields, or `undefined` when the row is missing any. */
function readNativeCiphertext(row: Record<string, unknown>): NativeCiphertext | undefined {
  const fields = ['encryptedData', 'dataIv', 'dataTag', 'encryptedName', 'nameIv', 'nameTag'];
  for (const field of fields) {
    const value = row[field];
    if (typeof value !== 'string' || value.length === 0) return undefined;
  }
  return {
    encryptedData: row.encryptedData as string,
    dataIv: row.dataIv as string,
    dataTag: row.dataTag as string,
    encryptedName: row.encryptedName as string,
    nameIv: row.nameIv as string,
    nameTag: row.nameTag as string,
  };
}

/**
 * Parse a decrypted native payload the way `vaultStore.decryptItem` does, so a
 * row hashes the same whether it arrives from an import or is read out of the
 * vault. A payload that parses to an object is returned as-is: unlike the store
 * this does not stamp `_validationError`, because identity re-validates the data
 * itself and an item whose stored data is already broken is excluded from the
 * match index on the store's side either way.
 */
function parseNativeData(dataJson: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(dataJson);
    if (isRow(parsed)) return parsed;
    return { _raw: parsed };
  } catch {
    return { _raw: dataJson };
  }
}

/** Tags as the wire schema requires them: trimmed, non-empty, bounded. */
function sanitizeNativeTags(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return (value as unknown[])
    .filter((tag): tag is string => typeof tag === 'string')
    .map((tag) => tag.trim())
    .filter((tag) => tag.length >= 1 && tag.length <= MAX_TAG_LENGTH)
    .slice(0, MAX_TAGS_PER_ITEM);
}

/**
 * Password history as the wire schema requires it: bounded entries with a
 * normalized timestamp.
 *
 * Carrying it is the point — re-importing a native export must not erase the
 * previous passwords of an item it restores. A malformed ENTRY is dropped rather
 * than failing the row (a rejected entry would 400 the whole batch), and
 * `changedAt` is re-serialized through `Date` so an export written with an
 * unusual-but-parseable timestamp still satisfies the schema.
 */
function sanitizeNativePasswordHistory(value: unknown): IPasswordHistoryEntry[] {
  if (!Array.isArray(value)) return [];
  const entries: IPasswordHistoryEntry[] = [];
  for (const raw of value as unknown[]) {
    if (!isRow(raw)) continue;
    const { encryptedPassword, iv, tag, changedAt } = raw;
    if (
      typeof encryptedPassword !== 'string' ||
      encryptedPassword.length === 0 ||
      encryptedPassword.length > MAX_HISTORY_PASSWORD_LENGTH ||
      typeof iv !== 'string' ||
      iv.length === 0 ||
      iv.length > 24 ||
      typeof tag !== 'string' ||
      tag.length === 0 ||
      tag.length > 32 ||
      typeof changedAt !== 'string'
    ) {
      continue;
    }
    const changedAtMs = Date.parse(changedAt);
    if (Number.isNaN(changedAtMs)) continue;
    entries.push({
      encryptedPassword,
      iv,
      tag,
      changedAt: new Date(changedAtMs).toISOString(),
    });
    if (entries.length === PASSWORD_HISTORY_MAX) break;
  }
  return entries;
}

/**
 * Unwrap a native H-Vault export into rows the resolver can work with.
 *
 * These rows are ALREADY encrypted under the current vault key, so they take the
 * same road as every other source but skip two of its steps: their content was
 * validated when it was first stored (no clamping, no re-validation), and the
 * ciphertext this decrypts is what gets re-sent — the decryption here exists
 * only to prove readability and to give the resolver an identity to match on.
 * A row that cannot be decrypted is counted and dropped, as before.
 */
async function extractNativeItems(raw: string, vaultKey: CryptoKey): Promise<NativeExtraction> {
  let parsed: { items?: unknown };
  try {
    parsed = JSON.parse(raw) as { items?: unknown };
  } catch {
    throw new ImportParseError('Invalid H-Vault export: the file is not valid JSON.');
  }
  if (!Array.isArray(parsed.items)) {
    throw new ImportParseError('Invalid H-Vault export: expected an object with an "items" array.');
  }

  const rows = parsed.items as Record<string, unknown>[];
  const items: ResolvableImportItem[] = [];
  const reasons: string[] = [];
  let filtered = 0;

  const drop = (index: number, why: string): void => {
    filtered++;
    if (reasons.length < MAX_IMPORT_WARNINGS) reasons.push(`Item ${String(index + 1)}: ${why}`);
  };

  for (const [index, row] of rows.entries()) {
    if (!isRow(row)) {
      drop(index, 'not an item object.');
      continue;
    }
    const cipher = readNativeCiphertext(row);
    if (!cipher) {
      drop(index, 'missing encryption fields.');
      continue;
    }
    const itemType = row.itemType;
    if (typeof itemType !== 'string' || !(ITEM_TYPES as readonly string[]).includes(itemType)) {
      drop(index, 'unrecognized item type.');
      continue;
    }

    let dataJson: string;
    let name: string;
    try {
      dataJson = await cryptoService.decryptData(
        cipher.encryptedData,
        cipher.dataIv,
        cipher.dataTag,
        vaultKey,
      );
      name = await cryptoService.decryptData(
        cipher.encryptedName,
        cipher.nameIv,
        cipher.nameTag,
        vaultKey,
      );
    } catch {
      drop(index, 'could not be decrypted with the current vault key.');
      continue;
    }

    const folderId = row.folderId;
    const passwordHistory = sanitizeNativePasswordHistory(row.passwordHistory);
    items.push({
      itemType: itemType as ItemType,
      name,
      data: parseNativeData(dataJson),
      tags: sanitizeNativeTags(row.tags),
      favorite: row.favorite === true,
      cipher,
      // A folder id from another account is stripped server-side; a malformed
      // one would fail the whole batch's schema, so it never leaves here.
      ...(typeof folderId === 'string' && OBJECT_ID_RE.test(folderId) ? { folderId } : {}),
      ...(passwordHistory.length > 0 ? { passwordHistory } : {}),
    });
  }

  return { items, filtered, reasons, total: rows.length };
}

/** What an `overwrite` import is about to change, shown before anything is sent. */
interface ImportConfirmSummary {
  updateCount: number;
  insertCount: number;
  passwordChanges: number;
}

// ---------------------------------------------------------------------------
// Vault-key rotation: the document leg
// ---------------------------------------------------------------------------

/**
 * Every row of one paginated document list, straight off the wire.
 *
 * Deliberately NOT `documentsStore`'s `fetchAllPages`, and the difference is the
 * whole point of this function rather than a duplication of it. That one exists to
 * DISPLAY documents: it opens each row's metadata blob, and it drops a row it
 * cannot validate so that one bad document does not cost the user every other one.
 * A rotation needs the exact opposite of both. It decrypts no metadata at all — the
 * blob is sealed under a key derived from the document's own DEK, which a rotation
 * only rewraps, so opening it would be reading user plaintext for no reason — and it
 * must never silently drop a row, because a document left out of the payload is a
 * document left sealed under a vault key that is about to stop existing.
 *
 * So every row this returns is carried into the rewrap loop, and anything wrong with
 * one surfaces there as an abort rather than here as a smaller list.
 */
async function enumerateDocumentRows(
  request: (page: number) => Promise<{ data: PaginatedResponse<DocumentResponse> }>,
): Promise<DocumentResponse[]> {
  const rows: DocumentResponse[] = [];
  let page = 1;
  let totalPages = 1;

  do {
    const body = (await request(page)).data;
    if (!body.success) throw new Error('Failed to fetch documents');
    // Clamped for the same reason the store clamps it: `MAX_DOCUMENT_PAGES` is
    // derived from how many rows an account can ACTUALLY hold, so a `totalPages`
    // past the ceiling is an inflated number rather than more rows to read. That
    // ceiling is NOT the advertised per-user limit — see the constant's own
    // comment — and it must not be re-derived from one here, because this walk is
    // the one that may never drop a row.
    totalPages = Math.min(body.pagination.totalPages, MAX_DOCUMENT_PAGES);
    rows.push(...body.data);
    page += 1;
  } while (page <= totalPages);

  return rows;
}

// ---------------------------------------------------------------------------
// Vault key rotation helpers
// ---------------------------------------------------------------------------

/** Which collection a row a rotation could not open belongs to. */
type RotationLeg = 'item' | 'folder' | 'document';

/**
 * The plaintext of one vault item, decrypted as a UNIT.
 *
 * All-or-nothing on purpose: a row's name, data and password history are written
 * in one request under one key, so a key that opens the name opens the rest. A
 * per-field fallback would let a half-decrypted row be re-encrypted under the new
 * key with the other half carried across unchanged, which is a row nothing can
 * ever open again.
 */
interface ItemPlaintext {
  name: string;
  data: string;
  /**
   * Each retained previous password beside the `changedAt` it was stored with.
   *
   * Paired rather than a parallel array indexed against the stored entries: with
   * two arrays the re-encrypt loop needs a lookup that TypeScript cannot prove is
   * in range under `noUncheckedIndexedAccess`, so it grows a fallback arm that
   * nothing can ever reach — a defect hiding behind an unreachable branch. Here
   * there is no index at all.
   */
  history: { password: string; changedAt: string }[];
}

/**
 * Decrypts one item under the FIRST candidate key that opens it, or `null`.
 *
 * There is more than one candidate for exactly one reason: a crashed sequential
 * rotation leaves rows on both sides of the swap, some under the key the account
 * still uses and some under the key the rotation was moving to, and finishing it
 * has to carry both across. An ordinary rotation passes one key and this is a
 * plain decrypt with a caught failure.
 *
 * `null` means no candidate opened it. That row was ALREADY unreadable before the
 * rotation started, so it is passed through verbatim and reported rather than
 * aborting every other row's rotation — see `passThroughItem`.
 */
async function decryptItemUnderAnyKey(
  item: IVaultItemResponse,
  keys: CryptoKey[],
): Promise<ItemPlaintext | null> {
  for (const key of keys) {
    try {
      const name = await cryptoService.decryptData(
        item.encryptedName,
        item.nameIv,
        item.nameTag,
        key,
      );
      const data = await cryptoService.decryptData(
        item.encryptedData,
        item.dataIv,
        item.dataTag,
        key,
      );
      const history: ItemPlaintext['history'] = [];
      for (const entry of item.passwordHistory ?? []) {
        history.push({
          password: await cryptoService.decryptData(
            entry.encryptedPassword,
            entry.iv,
            entry.tag,
            key,
          ),
          changedAt: entry.changedAt,
        });
      }
      return { name, data, history };
    } catch {
      // Not this key. A GCM tag mismatch is the only way this fails for a row
      // sealed under another candidate, and it is indistinguishable from
      // corruption — which is why exhausting the list is reported rather than
      // diagnosed.
    }
  }
  return null;
}

/** The same one-key-at-a-time attempt for a folder's encrypted name. */
async function decryptFolderNameUnderAnyKey(
  folder: IFolderResponse,
  keys: CryptoKey[],
): Promise<string | null> {
  for (const key of keys) {
    try {
      return await cryptoService.decryptData(
        folder.encryptedName,
        folder.nameIv,
        folder.nameTag,
        key,
      );
    } catch {
      // Not this key.
    }
  }
  return null;
}

/**
 * The item's OWN ciphertext, unchanged, as a rotation payload entry.
 *
 * A row that no candidate key opens is already lost to this account, so rewriting
 * it byte for byte costs nothing — and it is not OMITTED, which is the part that
 * matters: the server refuses a payload that does not name every row the account
 * holds, so dropping the row would refuse the whole rotation and the one poisoned
 * entry would wedge every future attempt as well.
 *
 * `searchHash` travels with it and stays under the superseded key. That is
 * correct rather than tolerated: the hash is an HMAC of a name nothing can read,
 * so there is no plaintext from which to recompute it and nothing that could
 * usefully match it.
 */
function passThroughItem(item: IVaultItemResponse): BulkReEncryptInput['items'][number] {
  return {
    id: item._id,
    encryptedName: item.encryptedName,
    nameIv: item.nameIv,
    nameTag: item.nameTag,
    encryptedData: item.encryptedData,
    dataIv: item.dataIv,
    dataTag: item.dataTag,
    ...(item.searchHash !== undefined ? { searchHash: item.searchHash } : {}),
    ...(item.passwordHistory !== undefined ? { passwordHistory: item.passwordHistory } : {}),
  };
}

/** "2 items, 1 folder" — the skipped rows, counted by leg, in a fixed order. */
function describeSkippedRows(rows: { leg: RotationLeg }[]): string {
  const labels: Record<RotationLeg, string> = {
    item: 'item',
    folder: 'folder',
    document: 'document',
  };
  const parts: string[] = [];
  for (const leg of ['item', 'folder', 'document'] as const) {
    const count = rows.filter((row) => row.leg === leg).length;
    if (count > 0) parts.push(`${String(count)} ${labels[leg]}${count === 1 ? '' : 's'}`);
  }
  return parts.join(', ');
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
  const [autoLockTimeout, setAutoLockTimeout] = useState(AUTO_LOCK_TIMEOUT_MINUTES);
  const [lockOnHidden, setLockOnHidden] = useState(LOCK_ON_HIDDEN_DEFAULT);
  const [lockOnHiddenDelay, setLockOnHiddenDelay] = useState(LOCK_ON_HIDDEN_DELAY_MINUTES);
  const [clipboardClearTimeout, setClipboardClearTimeout] = useState(CLIPBOARD_CLEAR_SECONDS);
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

  // Overwrite confirmation. An import may MODIFY existing items, so nothing is
  // sent until the user confirms a summary of what will change. The dialog is
  // driven by a promise the import flow awaits: the resolver has already decided
  // the outcome, and the answer decides only whether it is executed.
  const [importConfirm, setImportConfirm] = useState<ImportConfirmSummary | null>(null);
  const importConfirmResolverRef = useRef<((confirmed: boolean) => void) | null>(null);

  const requestImportConfirmation = useCallback(
    (summary: ImportConfirmSummary): Promise<boolean> =>
      new Promise<boolean>((resolve) => {
        importConfirmResolverRef.current = resolve;
        setImportConfirm(summary);
      }),
    [],
  );

  const answerImportConfirmation = useCallback((confirmed: boolean) => {
    setImportConfirm(null);
    const resolve = importConfirmResolverRef.current;
    importConfirmResolverRef.current = null;
    resolve?.(confirmed);
  }, []);

  // Settle a pending confirmation if this page goes away while it is open — an
  // auto-lock unmounts it through ProtectedRoute. Left unanswered, the awaiting
  // import would hang forever holding the resolution and report no outcome at
  // all, which is exactly the silent disappearance the accounting exists to
  // prevent. The state setter is skipped here (nothing left to render); the
  // toast still reaches the user because the toast provider outlives the route.
  useEffect(
    () => () => {
      const resolve = importConfirmResolverRef.current;
      importConfirmResolverRef.current = null;
      resolve?.(false);
    },
    [],
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
  /**
   * Which rotation the dialog is confirming: a fresh one, or finishing the one a
   * crash interrupted. The two differ only in WHICH key the vault is re-sealed
   * under, and getting that wrong in the `finish` direction is unrecoverable, so
   * it is chosen when the control is pressed rather than inferred at commit time.
   */
  const [rotationMode, setRotationMode] = useState<'new' | 'finish' | 'discard'>('new');
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
        // FIRST in the chain, and it has to be: the TOTP branch below matches "2fa",
        // so a column headed "2FA recovery codes" used to auto-map to the TOTP
        // secret, where the codes were truncated at 500 characters and rendered as
        // though they were an authenticator seed. Requiring BOTH a backup/recovery
        // word AND "code" keeps it from stealing "Backup email" or a bare "Code".
        if ((lower.includes('backup') || lower.includes('recovery')) && lower.includes('code'))
          mapping[header] = 'backupCodes';
        else if (lower.includes('name') || lower.includes('title')) mapping[header] = 'name';
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
        // No fallbacks needed: `getProfile` normalises settings server-side
        // (`withSettingsDefaults`), so an account created before these fields
        // existed still receives them.
        setLockOnHidden(p.settings.lockOnHidden);
        setLockOnHiddenDelay(p.settings.lockOnHiddenDelay);
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
      await updateSettingsApi({
        autoLockTimeout,
        lockOnHidden,
        lockOnHiddenDelay,
        clipboardClearTimeout,
        theme,
      });
      clearSettingsCache();
      toast({ title: 'Settings saved', type: 'success' });
    } catch {
      toast({ title: 'Failed to save settings', type: 'error' });
    } finally {
      setSavingSettings(false);
    }
  }, [autoLockTimeout, lockOnHidden, lockOnHiddenDelay, clipboardClearTimeout, theme, toast]);

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
    let recoveredVaultKey: CryptoKey | undefined;
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

      try {
        await changePasswordApi({
          currentAuthHash,
          newAuthHash,
          newEncryptedVaultKey: newEncrypted.encrypted,
          newVaultKeyIv: newEncrypted.iv,
          newVaultKeyTag: newEncrypted.tag,
          // WHICH vault key the wrapper above was built from. This request
          // REPLACES the stored wrapper, so a wrapper built from a key a
          // rotation elsewhere has already superseded would destroy the only
          // copy of the live one and cost the whole vault. Sending the
          // generation is what lets the server refuse instead.
          vaultKeyVersion: useAuthStore.getState().vaultKeyVersion,
        });
      } catch (err) {
        // ONE retry, and only for the refusal that carried a NUMBER.
        //
        // Keyed on the number rather than on `status === 409`, because this
        // endpoint answers 409 for two different things: a superseded
        // generation, which carries `data.vaultKeyVersion` and is recovered from
        // here, and a rotation still in progress, which carries nothing and
        // whose only remedy is to wait. Retrying the second would spend this
        // one retry on a request that cannot yet succeed.
        const refusedVersion = staleVaultKeyVersion(err);
        if (refusedVersion === null) throw err;

        // The live wrapper, from the server rather than from this session's own
        // record: `encryptedVaultKeyData` in the store moves WITH the key this
        // session holds, so on a session holding a superseded key it is exactly
        // as stale as the wrapper that was just refused.
        const profileRes = await getProfileApi();
        const profile = profileRes.data;
        if (!profile.success) throw err;

        // The SAME MEK opens it: a rotation re-wraps the new vault key under the
        // account's existing MEK, and the master password has not changed (this
        // request was refused). A missing MEK means the vault locked underneath
        // us, which is not something a retry fixes.
        const mek = useAuthStore.getState().mek;
        if (!mek) throw err;
        const rawLiveVaultKey = await cryptoService.decryptVaultKey(
          profile.data.encryptedVaultKey,
          profile.data.vaultKeyIv,
          profile.data.vaultKeyTag,
          mek,
        );
        // `finally`, not a following statement: these are the 32 plaintext bytes
        // of the account's LIVE vault key, and an `importVaultKey` that rejected
        // would otherwise leave them in the heap until the collector got to them.
        // Same shape as `documentsStore`'s own recovery of this exact value.
        try {
          recoveredVaultKey = await cryptoService.importVaultKey(rawLiveVaultKey);
        } finally {
          cryptoService.clearKey(rawLiveVaultKey);
        }
        const rewrapped = await cryptoService.encryptVaultKey(recoveredVaultKey, newMek);

        await changePasswordApi({
          currentAuthHash,
          newAuthHash,
          newEncryptedVaultKey: rewrapped.encrypted,
          newVaultKeyIv: rewrapped.iv,
          newVaultKeyTag: rewrapped.tag,
          // The generation the profile itself reports, which is the one that
          // names the wrapper just unwrapped — not the number the refusal
          // carried, which is older by however long the profile read took. An
          // account with no stored generation has never rotated, so `0`.
          vaultKeyVersion: profile.data.vaultKeyVersion ?? 0,
        });
      }

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
    } catch (err) {
      // A 4xx message is shown VERBATIM, and only a 4xx — the same rule the
      // rotation driver below states at length. `app.ts` redacts a 5xx to its
      // status text in production and leaves 4xx alone, so a 4xx sentence was
      // written for this user. The one that matters here is the vault-key
      // refusal that survived the retry: it names the generation to reload to,
      // and collapsing it into a flat "Failed to change password" would leave
      // someone retrying for ever with no way to learn that the answer is to
      // reload the application.
      const status = isAxiosError(err) ? err.response?.status : undefined;
      const title =
        status !== undefined && status >= 400 && status < 500
          ? getApiErrorMessage(err, 'Failed to change password')
          : 'Failed to change password';
      toast({ title, type: 'error' });
    } finally {
      if (newMek) await cryptoService.clearCryptoKey(newMek);
      // The live vault key recovered for the retry is plaintext-capable material
      // this handler minted, so it is zeroed on every path — including the
      // success path, where `logout()` clears the STORE's copy but has never
      // heard of this one.
      if (recoveredVaultKey) await cryptoService.clearCryptoKey(recoveredVaultKey);
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
      downloadText(
        JSON.stringify(exportResult.data, null, 2),
        `hvault-export-${new Date().toISOString().split('T')[0]}.enc`,
        'application/json',
      );
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
  // Zero-knowledge pipeline, resolved CLIENT-SIDE (PLAN §1.8): the browser parses
  // the file, validates each entry, loads the WHOLE vault, and resolves conflicts
  // once over the whole set — the match key for a login is its site and username,
  // both of which live inside the encrypted blob, so the server physically cannot
  // compute it. Only then is anything encrypted, batched (transport only) and
  // sent as explicit `inserts`/`updates`. Plaintext never leaves the browser.
  //
  // Every incoming row ends in exactly one reported outcome, and the reported
  // counts sum to the number of rows the file contained.
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
      // 1 ── Parse the source into resolvable rows. Why individual rows were
      // dropped MUST be surfaced: a bare "7 skipped" gives the user no way to
      // tell which entries were lost or why, and re-running cannot reveal it.
      let incoming: ResolvableImportItem[];
      let totalRows: number;
      let skippedInvalid = 0;
      const skipReasons: string[] = [];

      if (importFormat === 'json') {
        const native = await extractNativeItems(importData, vaultKey);
        incoming = native.items;
        totalRows = native.total;
        skippedInvalid = native.filtered;
        skipReasons.push(...native.reasons);
        if (incoming.length === 0) {
          // Name the per-row reasons rather than guessing at one cause: rows are
          // dropped for missing ciphertext fields and unrecognized item types as
          // well as for failing to decrypt under the current vault key.
          toast({
            title:
              native.filtered > 0
                ? `All ${String(native.filtered)} items were rejected and nothing was imported.`
                : 'No items found to import.',
            ...(native.reasons.length > 0 ? { description: native.reasons.join('\n') } : {}),
            type: 'error',
          });
          return;
        }
      } else {
        const { items: parsed, warnings: parseWarnings } = parseImportData(
          importFormat,
          importData,
          csvMapping,
        );
        // No parser emits these today, but the channel must not be a dead end:
        // anything a parser has to say about a row belongs in the report.
        skipReasons.push(...parseWarnings.slice(0, MAX_IMPORT_WARNINGS));
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
        totalRows = parsed.length;
        // Validate BEFORE resolving: an item whose data cannot be validated has
        // no meaningful identity, and reporting it as a "duplicate" would hide
        // the real reason it never reached the vault.
        const validated = validateImportItems(parsed);
        incoming = validated.items;
        skippedInvalid = validated.skipped;
        skipReasons.push(...validated.warnings);
        if (incoming.length === 0) {
          toast({
            title: `No valid items to import; ${String(validated.skipped)} could not be converted.`,
            ...(validated.warnings.length > 0
              ? { description: validated.warnings.join('\n') }
              : {}),
            type: 'error',
          });
          return;
        }
      }

      // 2 ── Resolution must run against a COMPLETE item set. `fetchItems`
      // streams pages and appends progressively, so reading `state.items` before
      // it settles would resolve against a partial vault and insert duplicates
      // of items it simply had not loaded yet. A failure here is fatal to the
      // import for the same reason: guessing is worse than not importing.
      const itemsFetch = useVaultStore.getState().fetchItems();
      const fetchGeneration = getItemsFetchGeneration();
      try {
        await itemsFetch;
      } catch {
        toast({
          title: 'Could not load your vault to check for duplicates. Nothing was imported.',
          type: 'error',
        });
        return;
      }

      // Awaiting is necessary but NOT sufficient: a fetch superseded mid-stream
      // — by an auto-lock (`clearStore()` empties `items` and bumps the
      // generation) or by a newer fetch — RESOLVES rather than rejecting. Going
      // ahead would resolve against an empty list, classify the whole file as
      // new, and duplicate a vault the user still has. Nothing downstream would
      // catch it: the server is a pure executor now.
      if (
        getItemsFetchGeneration() !== fetchGeneration ||
        useAuthStore.getState().vaultKey !== vaultKey
      ) {
        toast({
          title: 'Your vault was locked or reloaded while the import was preparing.',
          description: 'Nothing was imported. Unlock the vault and run the import again.',
          type: 'error',
        });
        return;
      }

      // The same hazard offline: `fetchItems` falls back to the IndexedDB cache,
      // which is cleared on lock/login/logout and may be empty or stale. It is
      // not a vault to resolve against.
      if (!navigator.onLine) {
        toast({
          title: 'You appear to be offline, so your vault list could not be verified.',
          description: 'Nothing was imported. Reconnect and run the import again.',
          type: 'error',
        });
        return;
      }

      // 3 ── Resolve ONCE over the whole set, against the whole vault.
      const resolution = await resolveImport({
        existing: useVaultStore.getState().items,
        incoming,
        strategy: conflictStrategy,
      });

      // 4 ── No update is sent without explicit confirmation.
      if (resolution.updates.length > 0) {
        const passwordChanges = resolution.updates.filter(
          ({ incoming: row, existing: match }) =>
            match.itemType === 'login' && passwordDidChange(match.data.password, row.data.password),
        ).length;
        const confirmed = await requestImportConfirmation({
          updateCount: resolution.updates.length,
          insertCount: resolution.inserts.length,
          passwordChanges,
        });
        if (!confirmed) {
          toast({ title: 'Import cancelled. Nothing was changed.', type: 'info' });
          return;
        }
        // The confirmation has no time limit, so re-check the vault before acting
        // on an answer that may be minutes old. A lock normally unmounts this page
        // (which answers the prompt for the user), but nothing downstream would
        // notice a key that changed under us — the captured one still encrypts.
        if (useAuthStore.getState().vaultKey !== vaultKey) {
          toast({
            title: 'Your vault was locked while the import was waiting to be confirmed.',
            description: 'Nothing was imported. Unlock the vault and run the import again.',
            type: 'error',
          });
          return;
        }
      }

      // 5 ── Encrypt only what will actually be sent.
      const operations = await buildImportOperations({
        inserts: resolution.inserts,
        updates: resolution.updates,
        vaultKey,
      });
      skippedInvalid += operations.failedCount;
      skipReasons.push(...operations.failureReasons);

      // 6 ── Batch (transport only) and send sequentially.
      const batches = chunkImportOperations(operations.inserts, operations.updates);
      let inserted = 0;
      let updated = 0;
      let sentBatches = 0;

      try {
        for (const [index, batch] of batches.entries()) {
          setImportProgress({ current: index + 1, total: batches.length });
          const res = await importVaultApi({
            format: importFormat,
            conflictStrategy,
            operations: batch,
          });
          const body = res.data;
          if (!body.success) throw new Error('Failed to import vault data');
          inserted += body.data.insertedCount;
          updated += body.data.updatedCount;
          sentBatches++;
        }
      } catch (batchErr) {
        // A later batch failed; earlier batches are already committed. Report the
        // partial result honestly and refresh so committed rows appear. Under
        // `skip`/`overwrite` re-running is safe: it re-resolves against the
        // now-updated vault and performs only the work that remains. Under
        // `keep_both` it is NOT — that strategy never matches anything (see
        // `services/import/resolve.ts`), so a re-run would insert the committed
        // rows a second time. Say so rather than advising a duplicate.
        const msg = getApiErrorMessage(batchErr, 'Failed to import some items');
        const retryAdvice =
          conflictStrategy === 'keep_both'
            ? 'Nothing else was changed. Re-running with "keep both" would add the rows that already landed a second time — re-run with "skip" to import only what is left.'
            : 'Nothing else was changed. Running the import again is safe.';
        toast({
          title:
            sentBatches > 0
              ? `Imported ${String(inserted)} and updated ${String(updated)} items, then stopped: ${msg}`
              : msg,
          ...(sentBatches > 0 ? { description: retryAdvice } : {}),
          type: 'error',
        });
        if (inserted > 0 || updated > 0) void useVaultStore.getState().fetchItems();
        return;
      }

      // 7 ── Full accounting: these counts sum to `totalRows`.
      const insertedPart = `Imported ${String(inserted)} items`;
      const parts = [insertedPart];
      if (updated > 0) parts.push(`${String(updated)} updated`);
      if (resolution.unchanged.length > 0) {
        parts.push(`${String(resolution.unchanged.length)} already up to date`);
      }
      if (resolution.duplicateSkipped.length > 0) {
        parts.push(`${String(resolution.duplicateSkipped.length)} duplicates skipped`);
      }
      if (resolution.duplicateInFile.length > 0) {
        parts.push(`${String(resolution.duplicateInFile.length)} duplicate rows in file`);
      }
      if (skippedInvalid > 0) parts.push(`${String(skippedInvalid)} skipped`);

      // When anything did NOT become a new item, name the row total too, so the
      // outcome counts are visibly complete rather than merely summing by luck.
      // A single-part message can only mean every row was inserted.
      const title =
        parts.length === 1 ? insertedPart : `${parts.join(', ')} (${String(totalRows)} rows)`;

      toast({
        title,
        // Name the entries that were dropped and why, rather than only counting them.
        ...(skipReasons.length > 0 ? { description: skipReasons.join('\n') } : {}),
        type: skippedInvalid > 0 ? 'warning' : 'success',
      });
      if (inserted > 0 || updated > 0) void useVaultStore.getState().fetchItems();
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
  }, [importData, importFormat, csvMapping, conflictStrategy, requestImportConfirmation, toast]);

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

    const finishing = rotationMode === 'finish';
    // Rotate to a fresh key and ABANDON the interrupted rotation's stored one. The
    // server refuses that by default while a wrapper is outstanding, because it
    // strands whatever the crash had already re-sealed; the flag below is how a
    // user says they mean it. The reachable case is a wrapper that can no longer
    // be opened at all — it is sealed under the MEK the rotation ran with, and a
    // master-password change since has replaced that MEK — where finishing is
    // impossible and, without this, the account could never rotate again.
    const discarding = rotationMode === 'discard';

    setRotatingVaultKey(true);
    setRotationProgress(0);
    try {
      // Derive authHash from the master password for server-side verification
      const { authKey } = await cryptoService.deriveKeys(rotationPassword, user.email);
      const authHash = cryptoService.getAuthHash(authKey);
      cryptoService.clearKey(authKey);

      // Step 1: the key this rotation moves TO.
      //
      // Finishing an interrupted rotation does NOT mint one. A crash in the
      // sequential path leaves rows already sealed under the key it was moving to,
      // and that key exists in exactly one place: the pending wrapper on the user
      // document, under this account's MEK. Generating a third key here would leave
      // those rows under a key nothing stores, and the commit clears the wrapper, so
      // there would be no second chance. The wrapper is re-read at the moment of
      // acting rather than taken from the profile this page loaded, because another
      // tab may have finished the rotation in between and committing a superseded
      // wrapper would undo it.
      let newVaultKey: CryptoKey;
      let encrypted: string;
      let iv: string;
      let tag: string;
      if (finishing) {
        const pendingRes = await getProfileApi();
        const pendingBody = pendingRes.data;
        if (!pendingBody.success) throw new Error('Failed to read the interrupted rotation');
        setProfile(pendingBody.data);
        const {
          interruptedRotation,
          pendingEncryptedVaultKey,
          pendingVaultKeyIv,
          pendingVaultKeyTag,
        } = pendingBody.data;
        if (
          interruptedRotation !== true ||
          pendingEncryptedVaultKey === undefined ||
          pendingVaultKeyIv === undefined ||
          pendingVaultKeyTag === undefined
        ) {
          toast({ title: 'There is no interrupted rotation left to finish.', type: 'success' });
          return;
        }

        let rawPendingKey: ArrayBuffer;
        try {
          rawPendingKey = await cryptoService.decryptVaultKey(
            pendingEncryptedVaultKey,
            pendingVaultKeyIv,
            pendingVaultKeyTag,
            mek,
          );
        } catch {
          // The wrapper is sealed under the MEK the rotation ran with. A master
          // password change since the crash replaces the MEK, and no retry and no
          // reload can open it again, so the message must not suggest either.
          toast({
            title:
              'Cannot finish the rotation: the stored in-flight vault key will not open with this account’s master password.',
            description:
              'Entries re-encrypted before the interruption cannot be recovered from this account; restore them from a backup.',
            type: 'error',
          });
          return;
        }
        try {
          newVaultKey = await cryptoService.importVaultKey(rawPendingKey);
        } finally {
          // The 32 plaintext bytes of a live vault key: zeroed on the rejecting
          // path as well as the accepting one.
          cryptoService.clearKey(rawPendingKey);
        }
        // The wrapper is committed VERBATIM, so the key the server stores is
        // exactly the key the crashed rotation had already sealed rows under.
        encrypted = pendingEncryptedVaultKey;
        iv = pendingVaultKeyIv;
        tag = pendingVaultKeyTag;
      } else {
        ({ newVaultKey, encrypted, iv, tag } = await cryptoService.rotateVaultKey(mek));
      }

      // The keys a stored row may be sealed under, tried in order. One for an
      // ordinary rotation; two while finishing an interrupted one, because the
      // crash left rows on both sides of the swap and neither set may be dropped.
      const candidateKeys = finishing ? [oldVaultKey, newVaultKey] : [oldVaultKey];

      // Rows no candidate key opened. They are carried into the payload UNCHANGED
      // (see `passThroughItem`) and reported at the end, never omitted and never
      // silently dropped.
      const undecryptable: { leg: RotationLeg; id: string }[] = [];
      let rowsSeen = 0;
      let rowsOpened = 0;

      // Step 2: Fetch all vault items (including trash)
      const { listItemsApi, listTrashApi } = await import('../services/api/vaultApi');
      const allItems: IVaultItemResponse[] = [];
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

      // Phase 1: read every item under whichever candidate key opens it and
      // re-encrypt it under the new one. The WHOLE payload is collected before
      // anything is sent, so the server sees one atomic request or none.
      //
      // A row that no candidate opens is SKIPPED AND REPORTED, not fatal: it was
      // already unreadable before this rotation started, and aborting would leave
      // every other row sealed under the key the user is trying to replace — for
      // ever, because the next attempt would hit the same row. It is carried into
      // the payload verbatim so the server's completeness check still passes.
      const reEncryptedItems: BulkReEncryptInput['items'] = [];

      for (const [i, item] of allItems.entries()) {
        rowsSeen++;
        const plaintext = await decryptItemUnderAnyKey(item, candidateKeys);

        if (plaintext === null) {
          reEncryptedItems.push(passThroughItem(item));
          undecryptable.push({ leg: 'item', id: item._id });
        } else {
          rowsOpened++;
          // Re-encrypt with new vault key
          const encName = await cryptoService.encryptData(plaintext.name, newVaultKey);
          const encData = await cryptoService.encryptData(plaintext.data, newVaultKey);
          const searchHash = await cryptoService.generateSearchHash(plaintext.name, newVaultKey);

          // Re-encrypt password history entries if present. Each rewritten
          // password carries the `changedAt` it was decrypted beside, so the
          // history cannot be re-dated by a rotation.
          let reEncryptedHistory: IPasswordHistoryEntry[] | undefined;
          if (plaintext.history.length > 0) {
            reEncryptedHistory = [];
            for (const entry of plaintext.history) {
              const encPassword = await cryptoService.encryptData(entry.password, newVaultKey);
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
            encryptedName: encName.encrypted,
            nameIv: encName.iv,
            nameTag: encName.tag,
            encryptedData: encData.encrypted,
            dataIv: encData.iv,
            dataTag: encData.tag,
            searchHash,
            ...(reEncryptedHistory !== undefined ? { passwordHistory: reEncryptedHistory } : {}),
          });
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

      const reEncryptedFolders: NonNullable<BulkReEncryptInput['folders']> = [];

      // Same skip-and-report rule as the item leg above, and for the same reason:
      // a folder nothing can open wedges every future rotation just as hard as an
      // item does, and its stored name is already lost either way.
      for (const folder of allFolders) {
        rowsSeen++;
        const name = await decryptFolderNameUnderAnyKey(folder, candidateKeys);
        if (name === null) {
          reEncryptedFolders.push({
            id: folder._id,
            encryptedName: folder.encryptedName,
            nameIv: folder.nameIv,
            nameTag: folder.nameTag,
          });
          undecryptable.push({ leg: 'folder', id: folder._id });
          continue;
        }
        rowsOpened++;
        const encName = await cryptoService.encryptData(name, newVaultKey);
        reEncryptedFolders.push({
          id: folder._id,
          encryptedName: encName.encrypted,
          nameIv: encName.iv,
          nameTag: encName.tag,
        });
      }

      // Phase 1c: Rewrap every document's key.
      //
      // This leg reads no file and touches no stored object: it unwraps the
      // 32-byte DEK each document is sealed under and wraps it again under the new
      // vault key. That is the whole reason the document store uses envelope
      // encryption — rotating an account holding gigabytes costs 32 bytes per
      // document rather than a re-upload of every one of them.
      //
      // TRASHED documents are enumerated alongside active ones, exactly as trashed
      // items are above: a trashed document is sealed under the same vault key, it
      // can still be restored, and one left out of the payload would come back
      // permanently unreadable. The server counts both, so omitting either is a
      // refusal rather than a silent loss.
      setRotationProgress(60);
      const reWrappedDocuments: BulkReEncryptInput['documents'] = [];

      // Whether this server has a document store at all is read from `GET /config`,
      // never inferred from an error: every document route sits behind
      // `requireStorage`, whose 503 is redacted to its status text in production
      // and so carries nothing to parse. A server without one holds no documents,
      // the payload's `documents` leg is empty, and the completeness check the
      // server runs against its own count agrees.
      //
      // Read FRESH, and refused on anything but an answer. `getDocumentsConfig`
      // memoises whatever it resolved first — INCLUDING the `{ enabled: false }` it
      // falls back to when the request fails — for the life of the tab, and nothing
      // invalidates it. Reading it here would let one transient `/config` failure,
      // minutes earlier, on a page this one never opened, silently turn every later
      // rotation into one that names no documents at all. The server refuses that
      // payload with a completeness 409 whose diagnosis blames a pending purge or
      // absent storage, so the account would be told two things that are not true
      // and given no way to act on either. `null` — the request failed, or its
      // answer did not satisfy the schema — is therefore NOT read as "there are
      // none": it aborts here, before a single row is enumerated and before
      // anything is sent, which changes nothing at all and can be retried.
      const documentsConfig = await readDocumentsConfigFresh();
      if (documentsConfig === null) {
        await cryptoService.clearCryptoKey(newVaultKey);
        toast({
          title:
            'Rotation aborted: could not confirm whether this server stores documents. Check your connection and try again.',
          type: 'error',
        });
        return;
      }

      if (documentsConfig.enabled) {
        const documentRows = [
          ...(await enumerateDocumentRows((page) =>
            listDocumentsApi({ page, limit: DOCUMENT_PAGE_SIZE }),
          )),
          ...(await enumerateDocumentRows((page) =>
            listDocumentTrashApi({ page, limit: DOCUMENT_PAGE_SIZE }),
          )),
        ];

        for (const [i, row] of documentRows.entries()) {
          rowsSeen++;
          let dek: DocumentBytes | null = null;
          try {
            for (const key of candidateKeys) {
              try {
                // Both wrapping keys are bound to THIS document's id, so a row
                // whose wrapped key was moved from another document fails here
                // rather than being carried forward under the new vault key.
                const wrapKey = await deriveWrapKey(key, row._id);
                dek = await unwrapDek(row, wrapKey);
                break;
              } catch {
                // Not this key; try the next candidate.
              }
            }

            if (dek === null) {
              // A document whose key no candidate opens keeps its EXISTING
              // wrapper, verbatim. The file is already unopenable by this
              // account, so nothing is lost by carrying it across — and it is
              // still NAMED, because the server refuses a payload that does not
              // cover every row it holds, so dropping it would refuse the whole
              // rotation and one such row would wedge every future attempt.
              reWrappedDocuments.push({
                id: row._id,
                encryptedDek: row.encryptedDek,
                dekIv: row.dekIv,
                dekTag: row.dekTag,
              });
              undecryptable.push({ leg: 'document', id: row._id });
            } else {
              rowsOpened++;
              const newWrapKey = await deriveWrapKey(newVaultKey, row._id);
              const rewrapped = await wrapDek(dek, newWrapKey);
              // Exactly four fields, built rather than spread off the row: the
              // framing, the sizes and the sealed metadata are not a rotation's to
              // send, and `PUT /documents/:id` cannot reach the wrapped key either.
              reWrappedDocuments.push({ id: row._id, ...rewrapped });
            }
          } finally {
            // The DEK is user-plaintext-capable material and this loop may hold
            // thousands of them in turn; each one is zeroed as soon as it has been
            // rewrapped, on the failure path as well as the success one.
            if (dek) zeroDek(dek);
          }

          setRotationProgress(60 + Math.round(((i + 1) / documentRows.length) * 30));
        }
      }

      // The safety valve that keeps skip-and-report from becoming a data-loss
      // path of its own. ONE row nobody can open is a poisoned row; EVERY row
      // failing means the key this session holds is not this account's — a
      // session left behind by a rotation somewhere else, say — and committing a
      // payload of pass-throughs there would swap the vault key for one that
      // opens nothing at all, with no way back. An empty vault is not that case
      // and rotates normally.
      if (rowsSeen > 0 && rowsOpened === 0) {
        await cryptoService.clearCryptoKey(newVaultKey);
        toast({
          title:
            `Rotation aborted: none of the ${String(rowsSeen)} entries in this vault could be ` +
            'decrypted, so the key this session holds is not this account\u2019s. Reload and try again.',
          type: 'error',
        });
        return;
      }

      // Phase 2: All re-encryptions succeeded — commit atomically to the server
      setRotationProgress(95);
      const idempotencyKey = crypto.randomUUID();
      await bulkReEncryptApi({
        authHash,
        idempotencyKey,
        items: reEncryptedItems,
        folders: reEncryptedFolders,
        // Every leg is sent explicitly. A rotation must name every row the
        // account holds, so an omitted leg is refused outright rather than
        // leaving those rows sealed under the key being replaced.
        documents: reWrappedDocuments,
        newEncryptedVaultKey: encrypted,
        newVaultKeyIv: iv,
        newVaultKeyTag: tag,
        ...(discarding ? { discardPendingVaultKey: true } : {}),
      });
      setRotationProgress(100);

      // Step 5: Update BWK-encrypted vault key if backup is configured
      try {
        const profileRes = await getProfileApi();
        const profileData = profileRes.data;
        if (profileData.success) {
          // The committed rotation clears the pending wrapper, so this re-read is
          // also what retires the "finish the interrupted rotation" offer. A
          // failure here leaves it showing, and the finish path re-reads the
          // profile before acting, so the stale offer answers "nothing left to
          // finish" rather than re-committing a superseded key.
          setProfile(profileData.data);
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
        // The generation moves with the key, or this session would keep claiming
        // the one it has just replaced — and an upload from it would then be
        // refused for ever rather than recovered from.
        //
        // `+ 1` rather than a re-read, and the DIRECTION of any error is what
        // makes that safe. The server increments once per committing rotation, so
        // a request that returns 200 here has moved the account by at least one
        // and this is a FLOOR. A floor that is short self-heals: the next upload
        // sends it, takes the recoverable 409 carrying the true number, rewraps
        // and finishes. A number ABOVE the account's own would have nothing to
        // recover from, so being short is the error to prefer.
        //
        // The one 200 that does NOT increment is the idempotent replay — a repeat
        // carrying a `lastRotationKey` already recorded — and it cannot make this
        // an over-estimate, because `idempotencyKey` is minted fresh per attempt
        // just above. A replay can therefore only be a retransmission of THIS
        // request, whose first delivery did the increment.
        vaultKeyVersion: useAuthStore.getState().vaultKeyVersion + 1,
      });

      // The outcome, in full: what moved and what did NOT. A rotation that left
      // rows behind must say so in the same breath as reporting success, because a
      // bare "rotated successfully" is how a skipped entry goes unnoticed until the
      // day someone needs it.
      const rotatedTitle = finishing
        ? 'Interrupted vault key rotation finished'
        : 'Vault key rotated successfully';
      if (undecryptable.length > 0) {
        const skipped = undecryptable.length;
        const one = skipped === 1;
        toast({
          title: `${rotatedTitle}. ${String(skipped)} ${one ? 'entry' : 'entries'} could not be decrypted and ${one ? 'was' : 'were'} left unchanged.`,
          description:
            `Left unchanged: ${describeSkippedRows(undecryptable)}. ` +
            (discarding
              ? // Said plainly, because here it may NOT have been lost already: a
                // discard abandons the interrupted rotation's key, and anything
                // sealed under it goes with it.
                `${one ? 'It is' : 'They are'} sealed under the abandoned rotation's key, which this ` +
                `account no longer stores. Only a backup can recover ${one ? 'it' : 'them'}.`
              : `${one ? 'It was' : 'They were'} already unreadable with the key this vault held, so nothing ` +
                `was lost here — restoring from a backup is the only way to recover ${one ? 'it' : 'them'}.`),
          type: 'warning',
        });
      } else {
        toast({ title: rotatedTitle, type: 'success' });
      }
      setShowRotateConfirm(false);
      setRotationPassword('');
      setRotationBackupPassword('');
    } catch (err) {
      // A 4xx refusal is shown VERBATIM, and only a 4xx.
      //
      // `app.ts` mounts `createErrorMiddleware({ exposeServerErrors: false })`,
      // which redacts a 5xx to its status text in production and leaves 4xx alone —
      // so a 4xx message was written for this user and a 5xx one says nothing but
      // "Internal Server Error". The refusal that matters here is the completeness
      // check's 409: it names which leg fell short and, for documents, says that a
      // permanent deletion still awaiting the hourly cleanup keeps its row counted.
      // Collapsing that into a flat "Failed to rotate vault key" leaves a user
      // retrying forever with no way to learn that the answer is to wait.
      const status = isAxiosError(err) ? err.response?.status : undefined;
      const title =
        status !== undefined && status >= 400 && status < 500
          ? getApiErrorMessage(err, 'Failed to rotate vault key')
          : 'Failed to rotate vault key';
      toast({ title, type: 'error' });
    } finally {
      setRotatingVaultKey(false);
      setRotationProgress(0);
    }
  }, [rotationMode, rotationPassword, rotationBackupPassword, toast]);

  /**
   * Is a crashed rotation still outstanding on this account?
   *
   * `=== true` rather than a truthiness test: the field is optional on the wire so
   * that a client talking to a server that predates it reads ABSENT as "no". That
   * is the safe direction — offering to finish a rotation nobody can confirm would
   * drive `bulkReEncrypt` from a wrapper that may not exist.
   */
  const interruptedRotation = profile?.interruptedRotation === true;

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
                // The 800 shades in the light theme: at 600 this 14px status
                // read 3.21:1 (verified) and 2.94:1 (unverified) on the card's
                // white surface. The 400 shades in the dark theme, and they are
                // not optional — the card there is near-black (#020817), where
                // green-800 falls to 2.80:1 and yellow-800 to 2.92:1, so
                // darkening this for the light theme alone would break the dark
                // one harder than the light one was ever broken. Same pairing as
                // the sidebar's connectivity indicator in AppLayout.
                profile?.emailVerified
                  ? 'text-green-800 dark:text-green-400'
                  : 'text-yellow-800 dark:text-yellow-400',
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
                      changingPassword ||
                      // Both halves of the same-tab race are closed at the
                      // control, not just one: a password change started during
                      // a rotation uploads a wrapper for the key the rotation is
                      // replacing, and a rotation started during a password
                      // change replaces the key whose wrapper is in flight.
                      // Either way the server now refuses, but a refusal the
                      // user can be stopped from earning is better than one they
                      // have to read.
                      rotatingVaultKey ||
                      !currentPassword ||
                      !newPassword ||
                      !confirmPassword
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
                        // A raw TOTP seed is secret material, so it goes through
                        // the clipboard guard like any vault field: auto-erased on
                        // the configured deadline and erased on lock/logout. A
                        // direct navigator.clipboard write would escape both.
                        void copySecretToClipboard(tfaSecret, clipboardClearTimeout * 1000).then(
                          () => {
                            toast({ title: 'Secret copied', type: 'success', duration: 2000 });
                          },
                          () => {
                            toast({ title: 'Failed to copy', type: 'error' });
                          },
                        );
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
                    // Backup codes are account-recovery secrets: same guard, so
                    // they are auto-erased and cleared on lock/logout. Going
                    // through the guard also gives this copy its own deadline, so
                    // an earlier vault copy's pending erase can no longer take
                    // the codes off the clipboard ahead of time.
                    void copySecretToClipboard(
                      backupCodes.join('\n'),
                      clipboardClearTimeout * 1000,
                    ).then(
                      () => {
                        toast({
                          title: 'Backup codes copied to clipboard',
                          type: 'success',
                          duration: 2000,
                        });
                      },
                      () => {
                        toast({ title: 'Failed to copy backup codes', type: 'error' });
                      },
                    );
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
              <label htmlFor="auto-lock-timeout" className="text-sm text-[hsl(var(--foreground))]">
                Auto-lock timeout (minutes)
              </label>
            </div>
            <input
              id="auto-lock-timeout"
              type="number"
              min={AUTO_LOCK_MIN_MINUTES}
              max={AUTO_LOCK_MAX_MINUTES}
              value={autoLockTimeout}
              onChange={(e) => setAutoLockTimeout(Number(e.target.value))}
              className={cn(inputClass, 'w-20')}
            />
          </div>

          {/* Opt-in: also lock once the tab has been hidden for a while. Off by
              default — the auto-lock timeout above governs on its own unless the
              user asks for this. */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <EyeOff className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />
              <label htmlFor="lock-on-hidden" className="text-sm text-[hsl(var(--foreground))]">
                Lock when the tab is hidden
              </label>
            </div>
            <input
              id="lock-on-hidden"
              type="checkbox"
              checked={lockOnHidden}
              onChange={(e) => setLockOnHidden(e.target.checked)}
              className="h-4 w-4 rounded border-[hsl(var(--input))] accent-[hsl(var(--primary))]"
            />
          </div>
          {lockOnHidden && (
            <div className="flex items-center justify-between pl-6">
              <label
                htmlFor="lock-on-hidden-delay"
                className="text-sm text-[hsl(var(--muted-foreground))]"
              >
                …after this many minutes hidden
              </label>
              <input
                id="lock-on-hidden-delay"
                type="number"
                min={AUTO_LOCK_MIN_MINUTES}
                max={AUTO_LOCK_MAX_MINUTES}
                value={lockOnHiddenDelay}
                onChange={(e) => setLockOnHiddenDelay(Number(e.target.value))}
                className={cn(inputClass, 'w-20')}
              />
            </div>
          )}

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Clipboard className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />
              {/* A `<label htmlFor>`, like both controls above it. It was a bare
                  `<span>`, which names nothing: the input was announced as an
                  unlabelled spin button (axe: `label`, CRITICAL) even though the
                  text sat right beside it. */}
              <label
                htmlFor="clipboard-clear-timeout"
                className="text-sm text-[hsl(var(--foreground))]"
              >
                Clipboard clear (seconds)
              </label>
            </div>
            <input
              id="clipboard-clear-timeout"
              type="number"
              min={CLIPBOARD_CLEAR_MIN_SECONDS}
              max={CLIPBOARD_CLEAR_MAX_SECONDS}
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
                  {interruptedRotation
                    ? 'Re-encrypt every entry under the key the interrupted rotation was moving to'
                    : 'Generate a new vault key and re-encrypt all items'}
                </p>
              </div>
              {/*
                While a rotation is outstanding the ordinary control is REPLACED,
                not merely supplemented. An ordinary rotation here would commit a
                third key and clear the pending wrapper on the way, and every entry
                the interrupted rotation had already re-sealed would become
                permanently unreadable — the exact loss keeping that wrapper exists
                to prevent.
              */}
              <button
                type="button"
                onClick={() => {
                  setRotationMode(interruptedRotation ? 'finish' : 'new');
                  setShowRotateConfirm(true);
                }}
                disabled={rotatingVaultKey || changingPassword}
                className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors disabled:opacity-50"
              >
                {rotatingVaultKey ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Key className="h-4 w-4" />
                )}
                {rotatingVaultKey
                  ? `${interruptedRotation ? 'Finishing' : 'Rotating'}... ${rotationProgress}%`
                  : interruptedRotation
                    ? 'Finish Rotation'
                    : 'Rotate Key'}
              </button>
            </div>
            {interruptedRotation && (
              <div className="mt-2 space-y-1">
                <p className="text-xs text-yellow-800 dark:text-yellow-400">
                  An interrupted vault key rotation is outstanding. Any entry re-encrypted before it
                  stopped is sealed under a key this account stores but does not yet use; finish the
                  rotation to bring every entry back under one key.
                </p>
                {/*
                  The escape hatch, and it is deliberately secondary. The stored key
                  is sealed under the master password that was in force when the
                  rotation ran, so a password change since makes finishing
                  impossible — and the server refuses any other rotation while the
                  wrapper is outstanding, which without this would leave the account
                  unable to rotate at all.
                */}
                <button
                  type="button"
                  onClick={() => {
                    setRotationMode('discard');
                    setShowRotateConfirm(true);
                  }}
                  disabled={rotatingVaultKey || changingPassword}
                  className="text-xs underline text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] disabled:opacity-50"
                >
                  Rotate with a new key instead, abandoning the interrupted one
                </button>
              </div>
            )}
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
                {/*
                  Keyed on the MODE the control was pressed in, not on the live
                  profile: this dialog describes what Confirm is about to do, and a
                  profile refresh while it is open must not relabel a button whose
                  behaviour was already fixed.
                */}
                <DialogTitle>
                  {rotationMode === 'finish'
                    ? 'Finish Interrupted Rotation'
                    : rotationMode === 'discard'
                      ? 'Abandon the Interrupted Rotation'
                      : 'Rotate Vault Key'}
                </DialogTitle>
                <DialogDescription>
                  {rotationMode === 'finish'
                    ? 'This will re-encrypt every entry under the key the interrupted rotation was already using, rather than generating another one. This operation cannot be undone. Make sure you have a recent backup.'
                    : rotationMode === 'discard'
                      ? 'This will generate a new vault key and abandon the one the interrupted rotation was using. Any entry already re-encrypted under that key becomes permanently unreadable — only a backup can recover it. Choose this only if finishing the rotation has failed. This operation cannot be undone.'
                      : 'This will generate a new vault key and re-encrypt all your vault items. This operation cannot be undone. Make sure you have a recent backup.'}
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
                  disabled={rotatingVaultKey || changingPassword || !rotationPassword}
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

      {/* Leave H-Vault — a DELIBERATELY separate entry point from the encrypted
          export/import above. It links to a standalone page that produces an
          UNENCRYPTED plaintext file for migrating to another password manager.
          It shares no control, dialog, or code path with the encrypted `.enc`
          export; the separation is itself a safety control, so a user can never
          confuse "back up my vault" with "hand out every password in the clear". */}
      <Card className="border-amber-500/40">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-amber-600 dark:text-amber-500">
            <LogOut className="h-5 w-5" /> Leave H-Vault
          </CardTitle>
          <CardDescription>
            Export your vault as an <strong>unencrypted</strong> plaintext file for another password
            manager (Bitwarden, Chrome). This is not a backup.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Link
            to="/settings/export-data"
            className="flex items-center justify-between rounded-lg border border-amber-500/40 bg-amber-500/5 p-3 transition-colors hover:bg-amber-500/10"
          >
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-5 w-5 shrink-0 text-amber-500" />
              <div>
                <p className="text-sm font-medium text-[hsl(var(--foreground))]">
                  Export to another manager
                </p>
                <p className="text-xs text-[hsl(var(--muted-foreground))]">
                  Produces a plaintext file with every password, TOTP secret, backup code and card
                  number.
                </p>
              </div>
            </div>
            <ChevronRight className="h-4 w-4 shrink-0 text-[hsl(var(--muted-foreground))]" />
          </Link>
        </CardContent>
      </Card>

      {/* Overwrite confirmation — nothing is sent until this is answered.
          Rendered OUTSIDE the import panel on purpose: closing the panel would
          otherwise unmount the prompt with no answer, stranding the awaiting
          import with no outcome reported. */}
      <Dialog
        open={importConfirm !== null}
        onOpenChange={(open) => {
          if (!open) answerImportConfirmation(false);
        }}
      >
        <DialogContent className="max-w-md" onClose={() => answerImportConfirmation(false)}>
          <DialogHeader>
            <DialogTitle>Confirm import changes</DialogTitle>
            <DialogDescription>
              This import will modify {importConfirm?.updateCount ?? 0} existing item
              {importConfirm?.updateCount === 1 ? '' : 's'} in place.
            </DialogDescription>
          </DialogHeader>
          <ul className="list-disc space-y-1 pl-5 text-sm text-[hsl(var(--foreground))]">
            <li>
              {importConfirm?.passwordChanges ?? 0} password
              {importConfirm?.passwordChanges === 1 ? '' : 's'} will change. The previous password
              is kept in each item&apos;s password history.
            </li>
            <li>
              Each matched item&apos;s <strong>name is replaced</strong> by the name in the imported
              file, so an item you renamed reverts to the source name.
            </li>
            <li>
              A matched item&apos;s content is replaced wholesale. Anything the imported file does
              not carry — a TOTP secret, backup codes, delivery notes, notes, custom fields — is{' '}
              <strong>lost</strong>, and only the password is recoverable from history.
            </li>
            <li>{importConfirm?.insertCount ?? 0} new items will be added.</li>
          </ul>
          <DialogFooter>
            <button
              type="button"
              onClick={() => answerImportConfirmation(false)}
              className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
            >
              Cancel Import
            </button>
            <button
              type="button"
              onClick={() => answerImportConfirmation(true)}
              className="rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90"
            >
              Apply Changes
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

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
