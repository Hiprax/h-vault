import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { MAX_DOCUMENT_NOTE_LENGTH } from '@hvault/shared';
import { Download, RotateCcw } from 'lucide-react';
import { useNavigate } from 'react-router';
import { TotpScanPanel } from './TotpScanPanel';
import { TotpImportResults } from './TotpImportResults';
import { TotpAttachDialog, type AttachChoice } from './TotpAttachDialog';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../ui/Dialog';
import { useToast } from '../ui/Toast';
import { useVaultStore } from '../../stores/vaultStore';
import { useDocumentsStore } from '../../stores/documentsStore';
import { readDocumentsConfigFresh } from '../../services/api/configApi';
import { getApiErrorMessage } from '../../lib/utils';
import { isMigrationUri, parseMigrationUri } from '../../services/totpImport/migrationUri';
import { MigrationParseError } from '../../services/totpImport/migrationReader';
import {
  acceptPart,
  capturedParts,
  collectedEntries,
  emptyBatch,
  isComplete,
  type BatchState,
} from '../../services/totpImport/batch';
import {
  endScanSession,
  holdEntries,
  otpauthUriFor,
  type ScannedEntry,
} from '../../services/totpImport/scanSession';
import { decodeBase32, parseTotpValue } from '../../lib/totp';

/**
 * The whole import flow: read codes, show them, decide where each one goes.
 *
 * ---------------------------------------------------------------------------
 * WHAT HOLDS THE KEYS, AND WHAT CLEARS THEM
 * ---------------------------------------------------------------------------
 *
 * Not this component. `scanSession` holds them in a module-level map and hands
 * out labels; this component holds only those labels. {@link endScanSession} is
 * called on unmount and on `pagehide`, and `authStore` calls it on lock and on
 * logout, so there is no path out of this page that leaves a key in memory.
 *
 * Auto-lock is deliberately NOT suppressed while scanning. Scanning is not
 * activity, a lock part way through is the correct outcome, and a feature that
 * quietly held the vault open would be trading a security control for
 * convenience. The warning in the results panel is the honest alternative.
 */

interface TotpImportFlowProps {
  readonly onStartOver: () => void;
}

export function TotpImportFlow({ onStartOver }: TotpImportFlowProps) {
  /**
   * The parts collected so far, in a REF rather than in state, and deliberately.
   *
   * The camera loop captures its `onDecoded` ONCE and runs for the life of the
   * session, so a handler that read this out of its closure would see the set as
   * it was when scanning started. Every part after the first would then be
   * judged against an empty set: part two would look like a fresh export and
   * replace part one, and a multi-code export could never complete. A ref makes
   * the handler's age irrelevant.
   *
   * Nothing renders from it either. Progress reaches the screen through
   * `status`, so there is no state to keep in step with it.
   */
  const batchRef = useRef<BatchState>(emptyBatch());
  const [entries, setEntries] = useState<readonly ScannedEntry[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  const [attaching, setAttaching] = useState<ScannedEntry | null>(null);
  const [attachedTo, setAttachedTo] = useState<ReadonlyMap<string, string>>(new Map());
  const [savingDocument, setSavingDocument] = useState(false);
  const { toast } = useToast();
  const navigate = useNavigate();
  const createItem = useVaultStore((state) => state.createItem);
  const updateItem = useVaultStore((state) => state.updateItem);
  const fetchItems = useVaultStore((state) => state.fetchItems);

  // The keys die with this component, however it goes away.
  useEffect(() => {
    const onHide = () => {
      endScanSession();
    };
    window.addEventListener('pagehide', onHide);
    return () => {
      window.removeEventListener('pagehide', onHide);
      endScanSession();
    };
  }, []);

  // The attach picker reads `items`, which is empty on a cold load of this page.
  useEffect(() => {
    void fetchItems();
  }, [fetchItems]);

  const handleDecoded = useCallback(
    (text: string) => {
      if (!isMigrationUri(text)) {
        // A single ordinary account code, which is worth accepting: the decoder
        // is already here and this is what a user will try next.
        const parsed = parseTotpValue(text);
        if (!parsed.ok) {
          setStatus('That code is not an authenticator code this app can read.');
          return;
        }
        const held = holdEntries([
          {
            type: parsed.value.type,
            // Back to BYTES, which is the form `scanSession` can zero.
            secret: decodeBase32(parsed.value.secret),
            name: parsed.value.account,
            issuer: parsed.value.issuer,
            algorithm: parsed.value.algorithm,
            digits: parsed.value.digits === 8 ? 8 : 6,
            counter: parsed.value.counter,
          },
        ]);
        setEntries((current) => [...current, ...held]);
        setStatus('Read one account.');
        return;
      }

      let payload;
      try {
        payload = parseMigrationUri(text);
      } catch (error) {
        setStatus(
          error instanceof MigrationParseError ? error.message : 'That code could not be read.',
        );
        return;
      }

      const outcome = acceptPart(batchRef.current, payload);
      switch (outcome.kind) {
        case 'wrong-export':
          setStatus('That code belongs to a different export. Finish this one, or start over.');
          return;
        case 'conflicting-part':
          setStatus('That part does not match the ones already read. Start over to be safe.');
          return;
        case 'duplicate':
          setStatus(
            `Already read that one. ${String(capturedParts(outcome.state))} of ${String(outcome.state.batchSize)} captured.`,
          );
          return;
        case 'added': {
          batchRef.current = outcome.state;
          if (!isComplete(outcome.state)) {
            setStatus(
              `Part ${String(capturedParts(outcome.state))} of ${String(outcome.state.batchSize)} captured. Show the next code on your phone.`,
            );
            return;
          }
          const held = holdEntries(collectedEntries(outcome.state));
          setEntries(held);
          setStatus(null);
          return;
        }
      }
    },
    // Deliberately no `batch` dependency: the handler reads the ref, so it stays
    // valid for the whole life of a camera session rather than being replaced
    // under a loop that has already captured it.
    [],
  );

  const handleCreateLogin = useCallback(
    async (entry: ScannedEntry) => {
      const uri = otpauthUriFor(entry);
      if (uri === null) {
        toast({ title: 'That key is no longer available', type: 'error' });
        return;
      }
      const name = entry.issuer.length > 0 ? entry.issuer : entry.account || 'Imported code';
      try {
        await createItem('login', name, {
          username: entry.account,
          password: '',
          uris: [],
          totp: uri,
          notes: '',
          customFields: [],
        });
        setAttachedTo((current) => new Map(current).set(entry.id, name));
        toast({ title: `Created "${name}"`, type: 'success' });
      } catch (error) {
        toast({ title: getApiErrorMessage(error, 'Could not create that login'), type: 'error' });
      }
    },
    [createItem, toast],
  );

  const handleAttach = useCallback(
    async (choice: AttachChoice) => {
      const entry = attaching;
      if (entry === null) return;
      const uri = otpauthUriFor(entry);
      if (uri === null) {
        toast({ title: 'That key is no longer available', type: 'error' });
        return;
      }
      setAttaching(null);

      const item = choice.item;
      const existing = typeof item.data.totp === 'string' ? item.data.totp : '';
      const data: Record<string, unknown> = { ...item.data, totp: uri };

      if (choice.keepExisting && existing.length > 0) {
        // The undo. A TOTP key is not recoverable from anywhere else, and the
        // person doing this is mid-import and moving fast.
        // Read as `unknown` and re-typed once, deliberately: `item.data` is a
        // bag of unknowns, and spreading it directly would launder an `any`
        // straight into a value about to be encrypted.
        const current: unknown = item.data.customFields;
        const fields: unknown[] = Array.isArray(current) ? [...(current as unknown[])] : [];
        fields.push({ name: 'Previous TOTP', value: existing, type: 'hidden' });
        data.customFields = fields;
      }

      try {
        await updateItem(item.id, 'login', item.name, data);
        setAttachedTo((current) => new Map(current).set(entry.id, item.name));
        toast({ title: `Added to "${item.name}"`, type: 'success' });
      } catch (error) {
        toast({ title: getApiErrorMessage(error, 'Could not add that code'), type: 'error' });
      }
    },
    [attaching, updateItem, toast],
  );

  /**
   * The file written to the document store.
   *
   * Plain text, one `otpauth://` URI per line, because that is the universal
   * interchange format: the file is then a genuine escape hatch rather than
   * something only this app can read. `text/plain` also renders in the existing
   * viewer, so it can be read back without downloading it.
   */
  const buildExportText = useCallback(
    () =>
      [
        `# Codes imported from Google Authenticator on ${new Date().toISOString().slice(0, 10)}.`,
        '# Each line below is a complete key. Anyone who reads this file can generate',
        '# your codes. Keep it inside H-Vault; do not download it or email it.',
        '',
        ...entries
          .map((entry) => otpauthUriFor(entry))
          .filter((uri): uri is string => uri !== null),
        '',
      ].join('\n'),
    [entries],
  );

  const handleSaveToDocuments = useCallback(async () => {
    setSavingDocument(true);
    try {
      // The UNCACHED read, and `null` fails closed: the memoised one collapses
      // every failure into "disabled" for the whole tab, which here would mean
      // silently telling a user their codes were not saved when the server was
      // merely slow.
      const config = await readDocumentsConfigFresh();
      if (!config?.enabled) {
        toast({ title: 'Document storage is not available on this server', type: 'error' });
        return;
      }
      const text = buildExportText();
      const name = `google-authenticator-import-${new Date().toISOString().slice(0, 10)}.txt`;
      await useDocumentsStore.getState().startUpload({
        source: new Blob([text], { type: 'text/plain' }),
        name,
        mime: 'text/plain',
        tags: ['totp', 'import'],
        note: 'Imported from Google Authenticator. Contains live TOTP secrets.'.slice(
          0,
          MAX_DOCUMENT_NOTE_LENGTH,
        ),
      });
      toast({ title: `Saved as "${name}"`, type: 'success' });
    } catch (error) {
      toast({ title: getApiErrorMessage(error, 'Could not save those codes'), type: 'error' });
    } finally {
      setSavingDocument(false);
    }
  }, [buildExportText, toast]);

  const hasResults = entries.length > 0;
  const savable = useMemo(() => entries.some((entry) => entry.generatable), [entries]);

  return (
    <div className="space-y-6">
      {!hasResults && (
        <TotpScanPanel onDecoded={handleDecoded} onError={setStatus} status={status} />
      )}

      {hasResults && (
        <>
          <TotpImportResults
            entries={entries}
            onCreateLogin={(entry) => void handleCreateLogin(entry)}
            onAttach={setAttaching}
            attachedTo={attachedTo}
          />

          <div className="flex flex-wrap gap-2">
            {savable && (
              <button
                type="button"
                onClick={() => void handleSaveToDocuments()}
                disabled={savingDocument}
                className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] disabled:opacity-50"
              >
                <Download className="h-4 w-4" />
                {savingDocument ? 'Saving…' : 'Save all to Documents'}
              </button>
            )}
            <button
              type="button"
              onClick={() => {
                endScanSession();
                onStartOver();
              }}
              className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
            >
              <RotateCcw className="h-4 w-4" />
              Start over
            </button>
            <button
              type="button"
              onClick={() => void navigate('/vault')}
              className="inline-flex items-center gap-2 rounded-md px-3 py-2 text-sm text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]"
            >
              Done
            </button>
          </div>
        </>
      )}

      <Dialog open={attaching !== null} onOpenChange={(open) => !open && setAttaching(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add this code to a login</DialogTitle>
          </DialogHeader>
          {attaching !== null && (
            <TotpAttachDialog
              entry={attaching}
              onCancel={() => setAttaching(null)}
              onConfirm={(choice) => void handleAttach(choice)}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
