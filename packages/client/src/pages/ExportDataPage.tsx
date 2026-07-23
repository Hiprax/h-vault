/**
 * ExportDataPage — the standalone "Leave H-Vault" plaintext-export page.
 *
 * This is a DELIBERATELY separate UI surface from the app's normal encrypted
 * export/import (PLAN §1.2 principle 11). It has its own route
 * (`/settings/export-data`), its own entry-point card in Settings, and its own
 * warnings, and it shares NO control, dialog, or code path with the encrypted
 * `.enc` export. The reason is a safety one: this feature intentionally produces
 * UNENCRYPTED plaintext — every password, TOTP secret, card number and note — so
 * a user can migrate to another password manager. Mixing it into the everyday
 * backup/restore UI would invite someone to pick the wrong option and hand out
 * their entire vault in the clear. The whole page is the warning surface.
 *
 * Flow (PLAN §1.8 "Portable export"):
 *   1. Pick a format.
 *   2. Re-enter the master password.
 *   3. `POST /tools/export` with `portableFormat` — this is BOTH the re-auth gate
 *      (bcrypt on the server; a wrong password 401s and no plaintext is produced)
 *      AND the audit-log write (`export_plaintext`). Its ciphertext response is
 *      the authoritative COMPLETE set (all non-trashed items, streamed
 *      server-side), which is what guarantees a complete export (§1.2 #8).
 *   4. Decrypt that response with the in-memory vault key via the store bridge,
 *      normalize to `PortableItem`s.
 *   5. An explicit confirmation dialog restates the plaintext warning and the
 *      counts.
 *   6. Only on confirm: serialize and download. The serialized string lives only
 *      as a local const inside the confirm handler and is never stored in React
 *      state, a store, `localStorage`, `sessionStorage`, or the console. The
 *      decrypted intermediate is held in a ref and cleared as soon as the flow
 *      ends (download or cancel).
 */

import { useCallback, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, ChevronLeft, Download, Loader2, ShieldAlert } from 'lucide-react';
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
import { cryptoService } from '../services/crypto/cryptoService';
import { useAuthStore } from '../stores/authStore';
import { decryptExportResponse } from '../stores/vaultStore';
import {
  toPortableItems,
  type PortableItem,
  type SkippedItem,
} from '../services/export/portableItem';
import {
  serializePortableExport,
  PORTABLE_EXPORT_FORMATS,
  type PortableExportFormat,
} from '../services/export';
import { downloadText } from '../lib/download';
import { exportVaultApi } from '../services/api/userApi';
import { getApiErrorMessage } from '../lib/utils';

/** The decrypted intermediate, held only in a ref between prepare and confirm. */
interface PreparedExport {
  format: PortableExportFormat;
  portable: PortableItem[];
  skipped: SkippedItem[];
}

/** The summary shown in the confirmation dialog (counts only — no plaintext). */
interface ConfirmSummary {
  format: PortableExportFormat;
  label: string;
  lossNote: string;
  exportCount: number;
  skippedCount: number;
}

/** The post-download report (counts + skipped item names/reasons). */
interface ExportResult {
  exported: number;
  omitted: number;
  skipped: SkippedItem[];
}

const inputClass =
  'w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]';

export default function ExportDataPage() {
  const { toast } = useToast();
  const user = useAuthStore((s) => s.user);
  const vaultKey = useAuthStore((s) => s.vaultKey);

  const [format, setFormat] = useState<PortableExportFormat>('bitwarden-json');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<ConfirmSummary | null>(null);
  const [result, setResult] = useState<ExportResult | null>(null);

  // The decrypted plaintext intermediate lives here (never in React state, a
  // store, or any web-storage surface) and is cleared the moment the flow ends.
  const preparedRef = useRef<PreparedExport | null>(null);

  const selectedMeta = PORTABLE_EXPORT_FORMATS.find((f) => f.value === format);

  const discardPrepared = useCallback(() => {
    preparedRef.current = null;
  }, []);

  /**
   * Step 1-4: re-authenticate against the server, decrypt the authoritative
   * export response, normalize it, and open the confirmation dialog. Produces no
   * download and writes no file.
   */
  const handlePrepare = useCallback(async () => {
    if (!password) {
      toast({ title: 'Enter your master password to continue', type: 'error' });
      return;
    }
    if (!user?.email) {
      toast({ title: 'You must be signed in to export', type: 'error' });
      return;
    }
    if (!vaultKey) {
      toast({ title: 'Unlock your vault before exporting', type: 'error' });
      return;
    }

    setBusy(true);
    setResult(null);
    try {
      // The typed password only ever becomes an auth hash for the server re-auth;
      // the vault is decrypted with the in-memory vault key, not this password.
      const { authKey } = await cryptoService.deriveKeys(password, user.email);
      const authHash = cryptoService.getAuthHash(authKey);
      cryptoService.clearKey(authKey);

      // Re-auth gate + `export_plaintext` audit. A wrong password 401s here,
      // before any plaintext is produced. The response is the authoritative,
      // complete ciphertext set.
      const res = await exportVaultApi({ format: 'json', authHash, portableFormat: format });
      if (!res.data.success) {
        throw new Error('Export failed');
      }

      const { items, folders } = await decryptExportResponse(res.data.data, vaultKey);
      const { portable, skipped } = await toPortableItems({ items, folders, vaultKey });

      preparedRef.current = { format, portable, skipped };
      // Drop the typed password from state as soon as it has served its purpose.
      setPassword('');
      setConfirm({
        format,
        label: selectedMeta?.label ?? format,
        lossNote: selectedMeta?.lossNote ?? '',
        exportCount: portable.length,
        skippedCount: skipped.length,
      });
    } catch (error) {
      discardPrepared();
      toast({
        title: getApiErrorMessage(
          error,
          'Export failed. Check your master password and try again.',
        ),
        type: 'error',
      });
    } finally {
      setBusy(false);
    }
  }, [password, user?.email, vaultKey, format, selectedMeta, toast, discardPrepared]);

  /**
   * Step 6: on explicit confirmation only, serialize the prepared set and
   * trigger the download. The serialized string is a local const — it is never
   * assigned to React state, a store, or any storage.
   */
  const handleConfirm = useCallback(() => {
    const prepared = preparedRef.current;
    if (!prepared) {
      setConfirm(null);
      return;
    }
    try {
      const { content, filename, mimeType, omittedCount } = serializePortableExport(
        prepared.format,
        prepared.portable,
      );
      downloadText(content, filename, mimeType);
      setResult({
        exported: prepared.portable.length - omittedCount,
        omitted: omittedCount,
        skipped: prepared.skipped,
      });
      toast({ title: 'Plaintext export downloaded', type: 'success' });
    } catch (error) {
      toast({ title: getApiErrorMessage(error, 'Failed to build the export file'), type: 'error' });
    } finally {
      // Whether it succeeded or threw, the plaintext intermediate must not linger.
      discardPrepared();
      setConfirm(null);
    }
  }, [toast, discardPrepared]);

  const handleCancelConfirm = useCallback(() => {
    // Cancelling produces no download and drops the decrypted intermediate.
    discardPrepared();
    setConfirm(null);
  }, [discardPrepared]);

  return (
    <div className="mx-auto max-w-2xl space-y-6 pb-10">
      <div className="space-y-1">
        <Link
          to="/settings"
          className="inline-flex items-center gap-1 text-sm text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]"
        >
          <ChevronLeft className="h-4 w-4" /> Back to Settings
        </Link>
        <h1 className="flex items-center gap-2 text-2xl font-bold text-[hsl(var(--foreground))]">
          <ShieldAlert className="h-6 w-6 text-amber-500" />
          Leave H-Vault
        </h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">
          Export your entire vault to another password manager. This produces an{' '}
          <strong>unencrypted plaintext file</strong> — it is not a backup.
        </p>
      </div>

      {/* Persistent danger banner — the whole page is a warning surface. */}
      <div
        role="alert"
        className="space-y-2 rounded-lg border border-red-500/50 bg-red-500/5 p-4 text-sm text-[hsl(var(--foreground))]"
      >
        <p className="flex items-center gap-2 font-semibold text-red-600 dark:text-red-400">
          <AlertTriangle className="h-5 w-5 shrink-0" /> This file is UNENCRYPTED plaintext
        </p>
        <ul className="list-disc space-y-1 pl-5">
          <li>
            It contains <strong>every password, TOTP secret, card number, and note</strong> in your
            vault, readable by anyone who opens the file.
          </li>
          <li>
            <strong>Do not open it in a spreadsheet.</strong> Spreadsheet apps can execute formulas
            hidden in your data; values are written verbatim and are never altered.
          </li>
          <li>
            Import it into your new password manager immediately, then{' '}
            <strong>securely delete the file</strong>. Do not email it, sync it, or leave it in your
            Downloads folder.
          </li>
          <li>Nothing is uploaded — the plaintext is generated entirely in this browser.</li>
        </ul>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" /> Choose a format
          </CardTitle>
          <CardDescription>
            Pick the manager you are moving to. Each format carries a different subset of your data.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <fieldset className="space-y-2">
            <legend className="sr-only">Export format</legend>
            {PORTABLE_EXPORT_FORMATS.map((f) => (
              <label
                key={f.value}
                className="flex cursor-pointer items-start gap-3 rounded-lg border border-[hsl(var(--input))] p-3 hover:bg-[hsl(var(--accent))]"
              >
                <input
                  type="radio"
                  name="export-format"
                  value={f.value}
                  checked={format === f.value}
                  onChange={() => setFormat(f.value)}
                  className="mt-1"
                />
                <span className="space-y-0.5">
                  <span className="block text-sm font-medium text-[hsl(var(--foreground))]">
                    {f.label}
                  </span>
                  <span className="block text-xs text-[hsl(var(--muted-foreground))]">
                    {f.lossNote}
                  </span>
                </span>
              </label>
            ))}
          </fieldset>

          <div className="space-y-2">
            <label
              htmlFor="export-master-password"
              className="block text-sm font-medium text-[hsl(var(--foreground))]"
            >
              Confirm master password
            </label>
            <input
              id="export-master-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your master password"
              className={inputClass}
              autoComplete="current-password"
            />
            <p className="text-xs text-[hsl(var(--muted-foreground))]">
              Your password is verified by the server before any plaintext is produced.
            </p>
          </div>

          <div className="flex justify-end">
            <button
              type="button"
              disabled={busy}
              onClick={() => void handlePrepare()}
              className="inline-flex items-center gap-2 rounded-md bg-amber-600 px-4 py-2 text-sm font-medium text-white hover:bg-amber-700 disabled:opacity-50"
            >
              {busy ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" /> Preparing...
                </>
              ) : (
                <>Prepare plaintext export</>
              )}
            </button>
          </div>
        </CardContent>
      </Card>

      {result && (
        <Card>
          <CardHeader>
            <CardTitle>Export complete</CardTitle>
            <CardDescription>The file has been downloaded to this device.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm text-[hsl(var(--foreground))]">
            <ul className="space-y-1 font-medium">
              <li>
                {result.exported} item{result.exported === 1 ? '' : 's'} exported.
              </li>
              {result.omitted > 0 && (
                <li className="text-[hsl(var(--muted-foreground))]">
                  {result.omitted} item{result.omitted === 1 ? '' : 's'} omitted — this format
                  cannot represent them.
                </li>
              )}
              {result.skipped.length > 0 && (
                <li className="text-amber-600 dark:text-amber-500">
                  {result.skipped.length} item{result.skipped.length === 1 ? '' : 's'} skipped
                  because the data could not be decoded.
                </li>
              )}
            </ul>
            {result.skipped.length > 0 && (
              <div className="space-y-1 rounded-md border border-amber-500/40 bg-amber-500/5 p-3">
                <p className="text-xs font-medium text-[hsl(var(--foreground))]">Skipped items</p>
                <ul className="list-disc space-y-0.5 pl-5 text-xs text-[hsl(var(--muted-foreground))]">
                  {result.skipped.map((s) => (
                    <li key={s.id}>
                      {s.name || '(unnamed item)'} — {s.reason}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <p className="text-xs text-red-600 dark:text-red-400">
              Remember to securely delete this file once you have imported it elsewhere.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Explicit confirmation — no file is written until this is answered. */}
      <Dialog
        open={confirm !== null}
        onOpenChange={(open) => {
          if (!open) handleCancelConfirm();
        }}
      >
        <DialogContent className="max-w-md" onClose={handleCancelConfirm}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-600 dark:text-red-400">
              <AlertTriangle className="h-5 w-5 shrink-0" /> Download unencrypted plaintext?
            </DialogTitle>
            <DialogDescription>
              You are about to download <strong>{confirm?.exportCount ?? 0}</strong> item
              {confirm?.exportCount === 1 ? '' : 's'} as <strong>{confirm?.label ?? ''}</strong>.
              The file is <strong>unencrypted plaintext</strong> containing every password, TOTP
              secret and card number.
            </DialogDescription>
          </DialogHeader>
          <ul className="list-disc space-y-1 pl-5 text-sm text-[hsl(var(--foreground))]">
            <li>{confirm?.lossNote}</li>
            {confirm && confirm.skippedCount > 0 && (
              <li className="text-amber-600 dark:text-amber-500">
                {confirm.skippedCount} item{confirm.skippedCount === 1 ? '' : 's'} could not be
                decoded and will be listed as skipped, not exported.
              </li>
            )}
            <li>Do not open the file in a spreadsheet. Delete it after importing it elsewhere.</li>
          </ul>
          <DialogFooter>
            <button
              type="button"
              onClick={handleCancelConfirm}
              className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleConfirm}
              className="inline-flex items-center gap-2 rounded-md bg-red-600 px-3 py-2 text-sm font-medium text-white hover:bg-red-700"
            >
              <Download className="h-4 w-4" /> Download plaintext file
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
