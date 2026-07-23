/**
 * FileDecryptPanel — the "Decrypt" half of the standalone File Encryption tool.
 *
 * Fully client-side and account-agnostic: the picked `.enc` file and the
 * password never leave the browser and never touch account key material. Like
 * {@link FileEncryptPanel}, this component MUST NOT import `authStore` or any
 * account crypto service; it delegates all cryptography to `fileCryptoService`.
 *
 * There is no password strength gate here — decryption simply tries the supplied
 * password. A wrong password or a tampered/corrupt file surfaces the honest,
 * oracle-free "Incorrect password, or the file is corrupted" message, while a
 * non-container file surfaces the distinct "not a valid file" message, both via
 * {@link describeFileCryptoError}.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { FileDown, Loader2, Unlock, X } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/Card';
import { useToast } from '../ui/Toast';
import { downloadBlob } from '../../lib/download';
import { FILE_ENCRYPTION_FILE_EXTENSION } from '@hvault/shared';
import { getFileEncryptionMaxBytes } from '../../services/api/configApi';
import {
  decryptFile,
  describeFileCryptoError,
  MAX_CONTAINER_OVERHEAD_BYTES,
} from '../../services/crypto/fileCryptoService';

const inputClass =
  'w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]';

function formatMb(bytes: number): string {
  return `${String(Math.floor(bytes / (1024 * 1024)))} MB`;
}

export function FileDecryptPanel() {
  const { toast } = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState('');
  const [working, setWorking] = useState(false);
  const [maxBytes, setMaxBytes] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    void getFileEncryptionMaxBytes().then((bytes) => {
      if (!cancelled) setMaxBytes(bytes);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  // A `.enc` container is always larger than the plaintext it wraps, so admit the
  // plaintext cap PLUS the max container overhead (mirroring decryptFile's guard) —
  // otherwise a file encrypted at exactly the cap would be falsely rejected here.
  const tooLarge =
    file !== null && maxBytes !== null && file.size > maxBytes + MAX_CONTAINER_OVERHEAD_BYTES;
  const canSubmit = file !== null && password.length > 0 && !tooLarge && !working;

  const resetForm = useCallback(() => {
    setFile(null);
    setPassword('');
    if (fileInputRef.current) fileInputRef.current.value = '';
  }, []);

  const handleDecrypt = useCallback(async () => {
    if (!file) return;
    setWorking(true);
    try {
      // Symmetric guard: a huge `.enc` is rejected before any bytes are read so
      // it can't OOM the tab any more than a huge plaintext can on encrypt.
      const limit = maxBytes ?? (await getFileEncryptionMaxBytes());
      const { blob, filename } = await decryptFile(file, password, { maxSizeBytes: limit });
      downloadBlob(blob, filename);
      toast({ title: 'File decrypted', description: `Downloaded ${filename}.`, type: 'success' });
      resetForm();
    } catch (err) {
      // describeFileCryptoError maps the distinct failure kinds (not-a-file,
      // wrong-password-or-corrupt, integrity, …) to distinct messages.
      toast({ title: describeFileCryptoError(err).message, type: 'error' });
    } finally {
      setWorking(false);
    }
  }, [file, password, maxBytes, toast, resetForm]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <Unlock className="h-5 w-5" /> Decrypt a file
        </CardTitle>
        <CardDescription>
          Choose a <code>.enc</code> file and enter its password. The file is decrypted entirely in
          your browser and the original file is downloaded.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* File picker */}
        <div>
          <label
            htmlFor="file-decrypt-input"
            className="mb-1 block text-sm font-medium text-[hsl(var(--foreground))]"
          >
            Encrypted file
          </label>
          <input
            id="file-decrypt-input"
            ref={fileInputRef}
            type="file"
            accept={FILE_ENCRYPTION_FILE_EXTENSION}
            disabled={working}
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            className="block w-full text-sm text-[hsl(var(--foreground))] file:mr-4 file:rounded-md file:border-0 file:bg-[hsl(var(--primary))] file:px-4 file:py-2 file:text-sm file:font-medium file:text-[hsl(var(--primary-foreground))] disabled:opacity-50"
          />
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
          <label htmlFor="file-decrypt-password" className="sr-only">
            Decryption password
          </label>
          <input
            id="file-decrypt-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password"
            className={inputClass}
            autoComplete="off"
            disabled={working}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && canSubmit) {
                e.preventDefault();
                void handleDecrypt();
              }
            }}
          />
        </div>

        <button
          type="button"
          onClick={() => void handleDecrypt()}
          disabled={!canSubmit}
          className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
        >
          {working ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <FileDown className="h-4 w-4" />
          )}
          {working ? 'Decrypting…' : 'Decrypt & Download'}
        </button>
      </CardContent>
    </Card>
  );
}

export default FileDecryptPanel;
