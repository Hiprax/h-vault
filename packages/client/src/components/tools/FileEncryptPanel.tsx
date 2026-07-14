/**
 * FileEncryptPanel — the "Encrypt" half of the standalone File Encryption tool.
 *
 * Fully client-side and account-agnostic: the picked file and the password never
 * leave the browser and never touch account key material (`vaultKey`/`mek`/
 * master password). This component MUST NOT import `authStore` or any account
 * crypto service — it delegates all cryptography to `fileCryptoService`, which in
 * turn delegates to `@hiprax/crypto` container mode. (It does read a non-secret
 * size cap via `getFileEncryptionMaxBytes()`, whose only network dependency is a
 * plain `GET /config`; that is the sole permitted transitive network touch and
 * carries no file bytes and no password.)
 *
 * Password gate: `isValidPassword(pw)` (the package's own rule, so
 * `encryptContainer` never throws `WEAK_PASSWORD`) AND a lazily-loaded zxcvbn
 * score of at least 3 (the app's existing strength bar, matching backup setup).
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type zxcvbnType from 'zxcvbn';
import { AlertTriangle, FileUp, Loader2, Lock, X } from 'lucide-react';
import { cn } from '../../lib/utils';
import { getZxcvbn } from '../../lib/lazyZxcvbn';
import { logger } from '../../lib/logger';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/Card';
import { useToast } from '../ui/Toast';
import { getFileEncryptionMaxBytes } from '../../services/api/configApi';
import {
  encryptFile,
  describeFileCryptoError,
  isValidPassword,
} from '../../services/crypto/fileCryptoService';

/** Minimum zxcvbn score required, mirroring the backup encryption bar. */
const MIN_PASSWORD_SCORE = 3;

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

const inputClass =
  'w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]';

function formatMb(bytes: number): string {
  return `${String(Math.floor(bytes / (1024 * 1024)))} MB`;
}

/** Trigger a client-side download of `blob` under `filename` (Blob + anchor). */
function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function FileEncryptPanel() {
  const { toast } = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [working, setWorking] = useState(false);
  const [maxBytes, setMaxBytes] = useState<number | null>(null);
  const [zxcvbnFn, setZxcvbnFn] = useState<typeof zxcvbnType | null>(null);

  useEffect(() => {
    let cancelled = false;
    void getZxcvbn()
      .then((fn) => {
        if (!cancelled) setZxcvbnFn(() => fn);
      })
      .catch((err: unknown) => {
        // zxcvbn is a lazy chunk; if it fails to load the strength gate simply
        // stays closed. Log for diagnostics but nothing is actionable in the UI.
        logger.error('Failed to load zxcvbn for the file-encryption strength meter', err);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    void getFileEncryptionMaxBytes().then((bytes) => {
      if (!cancelled) setMaxBytes(bytes);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const strength = useMemo(
    () => (password && zxcvbnFn ? zxcvbnFn(password) : null),
    [password, zxcvbnFn],
  );

  const tooLarge = file !== null && maxBytes !== null && file.size > maxBytes;
  const passwordAccepted = isValidPassword(password);
  const strengthOk = (strength?.score ?? -1) >= MIN_PASSWORD_SCORE;
  const passwordsMatch = password.length > 0 && password === confirmPassword;
  const canSubmit =
    file !== null && !tooLarge && passwordAccepted && strengthOk && passwordsMatch && !working;

  const resetForm = useCallback(() => {
    setFile(null);
    setPassword('');
    setConfirmPassword('');
    if (fileInputRef.current) fileInputRef.current.value = '';
  }, []);

  const handleEncrypt = useCallback(async () => {
    if (!file) return;
    setWorking(true);
    try {
      // Authoritative guard: resolve the cap (cached) and let encryptFile enforce
      // it before any bytes are read, so an oversized file never reaches crypto.
      const limit = maxBytes ?? (await getFileEncryptionMaxBytes());
      const { blob, filename } = await encryptFile(file, password, { maxSizeBytes: limit });
      triggerDownload(blob, filename);
      toast({
        title: 'File encrypted',
        description: `Downloaded ${filename}. Keep your password safe — it cannot be recovered.`,
        type: 'success',
      });
      resetForm();
    } catch (err) {
      toast({ title: describeFileCryptoError(err).message, type: 'error' });
    } finally {
      setWorking(false);
    }
  }, [file, password, maxBytes, toast, resetForm]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <Lock className="h-5 w-5" /> Encrypt a file
        </CardTitle>
        <CardDescription>
          Choose any file and a strong password. The file is encrypted entirely in your browser and
          downloaded as a <code>.enc</code> file. Nothing is ever uploaded.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Irrecoverable-password warning — prominent and unmissable. */}
        <div
          role="note"
          className="flex items-start gap-3 rounded-md border border-yellow-400 bg-yellow-50 p-3 text-sm text-yellow-900 dark:border-yellow-700 dark:bg-yellow-950 dark:text-yellow-100"
        >
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
          <p>
            <strong>There is no password recovery.</strong> If you lose or forget this password, the
            encrypted file can never be opened again. There is no reset and no backdoor.
          </p>
        </div>

        {/* File picker */}
        <div>
          <label
            htmlFor="file-encrypt-input"
            className="mb-1 block text-sm font-medium text-[hsl(var(--foreground))]"
          >
            File to encrypt
          </label>
          <input
            id="file-encrypt-input"
            ref={fileInputRef}
            type="file"
            disabled={working}
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            className="block w-full text-sm text-[hsl(var(--foreground))] file:mr-4 file:rounded-md file:border-0 file:bg-[hsl(var(--primary))] file:px-4 file:py-2 file:text-sm file:font-medium file:text-[hsl(var(--primary-foreground))] disabled:opacity-50"
          />
          {maxBytes !== null && (
            <p className="mt-1 text-xs text-[hsl(var(--muted-foreground))]">
              Maximum file size: {formatMb(maxBytes)}
            </p>
          )}
          {file && (
            <div className="mt-2 flex items-center justify-between rounded-md border border-[hsl(var(--border))] px-3 py-1.5">
              <span className="truncate text-sm text-[hsl(var(--foreground))]">
                {file.name} ({formatMb(file.size)})
              </span>
              <button
                type="button"
                onClick={resetForm}
                disabled={working}
                className="ml-2 rounded p-0.5 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--destructive))] disabled:opacity-50"
                aria-label="Clear selected file"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          )}
          {tooLarge && (
            <p className="mt-1 text-xs text-[hsl(var(--destructive))]">
              This file is too large. The maximum size is {formatMb(maxBytes)}.
            </p>
          )}
        </div>

        {/* Password */}
        <div>
          <label htmlFor="file-encrypt-password" className="sr-only">
            Encryption password
          </label>
          <input
            id="file-encrypt-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Encryption password"
            className={inputClass}
            autoComplete="new-password"
            disabled={working}
          />
        </div>
        {strength && (
          <div className="space-y-1.5">
            <div className="flex h-1.5 w-full gap-1">
              {[0, 1, 2, 3, 4].map((i) => (
                <div
                  key={i}
                  className={cn(
                    'h-full flex-1 rounded-full transition-colors',
                    i <= strength.score ? strengthColors[strength.score] : 'bg-[hsl(var(--muted))]',
                  )}
                />
              ))}
            </div>
            <p className="text-xs text-[hsl(var(--muted-foreground))]">
              {strengthLabels[strength.score]}
              {strength.score < MIN_PASSWORD_SCORE && ' — Minimum "Strong" required'}
            </p>
          </div>
        )}
        {password.length > 0 && !passwordAccepted && (
          <p className="text-xs text-[hsl(var(--destructive))]">
            Use at least 20 characters, or 8+ with an uppercase letter, a lowercase letter, a digit,
            and a symbol.
          </p>
        )}

        {/* Confirm password */}
        <div>
          <label htmlFor="file-encrypt-confirm" className="sr-only">
            Confirm encryption password
          </label>
          <input
            id="file-encrypt-confirm"
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Confirm password"
            className={inputClass}
            autoComplete="new-password"
            disabled={working}
          />
        </div>
        {confirmPassword.length > 0 && !passwordsMatch && (
          <p className="text-xs text-[hsl(var(--destructive))]">Passwords do not match.</p>
        )}

        <button
          type="button"
          onClick={() => void handleEncrypt()}
          disabled={!canSubmit}
          className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
        >
          {working ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileUp className="h-4 w-4" />}
          {working ? 'Encrypting…' : 'Encrypt & Download'}
        </button>
      </CardContent>
    </Card>
  );
}

export default FileEncryptPanel;
