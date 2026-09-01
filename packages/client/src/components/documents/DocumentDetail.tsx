import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router';
import {
  AlertTriangle,
  ArrowLeft,
  Download,
  FileText,
  FileWarning,
  FolderOpen,
  Loader2,
  Pencil,
  RotateCcw,
  Star,
  Trash2,
} from 'lucide-react';
import {
  MAX_DOCUMENT_META_JSON_BYTES,
  MAX_DOCUMENT_NAME_LENGTH,
  MAX_DOCUMENT_NOTE_LENGTH,
  MAX_DOCUMENT_TAGS,
  MAX_TAG_LENGTH,
  documentMetaJsonByteLength,
  formatBytes,
} from '@hvault/shared';
import type { DocumentMeta } from '@hvault/shared';
import { cn, getApiErrorMessage } from '../../lib/utils';
import { useToast } from '../ui/Toast';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/Dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../ui/DropdownMenu';
import { useVaultStore } from '../../stores/vaultStore';
import { useDocumentsStore, type DecryptedDocument } from '../../stores/documentsStore';
import {
  DocumentDownloadCancelledError,
  DocumentIntegrityError,
  saveDocument,
} from '../../services/documents/download';

// ---------------------------------------------------------------------------
// Copy that more than one element has to agree on
// ---------------------------------------------------------------------------

/**
 * The id of {@link UndecodableDocumentNotice}'s body, so the unavailable Edit
 * control can name it as its own description.
 *
 * Only ONE notice is ever in the document: the content area renders either the
 * notice or the download panel, never both.
 */
const UNDECODABLE_NOTICE_ID = 'undecodable-document-notice';

/**
 * Why editing is unavailable on a document whose metadata will not open.
 *
 * Used as the control's `title`, which is a BONUS channel — `title` is not
 * reliably announced by a screen reader and some engines decline to render a
 * tooltip at all. The reason reaches assistive technology through
 * `aria-describedby` pointing at the notice's `role="alert"` body.
 */
const UNDECODABLE_EDIT_HINT =
  'The name, tags and note of this document are sealed inside a blob that will not open, so there is nothing to edit and no key to re-seal it with.';

/**
 * Why this application does not show a document's contents.
 *
 * Written as a positive statement of the guarantee rather than as an apology for
 * a missing feature, because it IS the guarantee: a stored document is arbitrary
 * input, and the origin that would parse it is the one holding the unlocked
 * vault key.
 */
const DOWNLOAD_TO_VIEW_REASON =
  'H-Vault does not open a document inside the app. A stored file is arbitrary input, and the page that would render it is the page holding your unlocked vault key, so the file is decrypted here and handed straight to your computer instead. Download it and open it with the viewer you already trust.';

/** What both the folder trigger and the first menu item call "outside every folder". */
const NO_FOLDER_LABEL = 'No folder';

// ---------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------

/**
 * A comma-separated tag field, parsed the way the shared schema stores tags.
 *
 * `.trim()` and the empty drop mirror `documentMetaSchema`'s
 * `z.string().trim().min(1)`, and the de-duplication is this field's own: typing
 * the same tag twice is a slip rather than a request for two identical tags, and
 * it would otherwise spend one of the twenty slots.
 */
function parseTagField(value: string): string[] {
  const seen = new Set<string>();
  for (const raw of value.split(',')) {
    const tag = raw.trim();
    if (tag !== '') seen.add(tag);
  }
  return [...seen];
}

/**
 * Why these metadata values cannot be stored, or `null` when they can.
 *
 * Every bound is checked here, before anything is sealed, for the reason the
 * vault form records: a value the store refuses fails inside `encryptMeta` as a
 * schema error whose message is a serialized issue list, which is not a sentence
 * anyone can act on. The BYTE budget is checked with the shared helper rather
 * than by counting characters, because every field bound above it counts UTF-16
 * code units while the sealed blob is bytes — a 10,000-character note in a
 * non-Latin script is three times its own length once encoded.
 */
function refusalFor(meta: DocumentMeta): string | null {
  if (meta.name === '') return 'A document needs a name.';
  if (meta.tags.length > MAX_DOCUMENT_TAGS) {
    return `A document can carry at most ${String(MAX_DOCUMENT_TAGS)} tags.`;
  }
  const overlongTag = meta.tags.find((tag) => tag.length > MAX_TAG_LENGTH);
  if (overlongTag !== undefined) {
    return `Tags can be at most ${String(MAX_TAG_LENGTH)} characters; "${overlongTag}" is longer.`;
  }
  if (documentMetaJsonByteLength(meta) > MAX_DOCUMENT_META_JSON_BYTES) {
    return `The name, tags and note of a document have to fit in ${String(MAX_DOCUMENT_META_JSON_BYTES)} bytes once encoded. Shorten the note.`;
  }
  return null;
}

// ---------------------------------------------------------------------------
// The two content states
// ---------------------------------------------------------------------------

/**
 * The content area for a document this vault key cannot open.
 *
 * A document degrades in one of two ways — the wrapped key will not unwrap, or
 * the sealed blob will not open — and the store deliberately does not record
 * which, because nothing may act differently on them. Neither admits a rename:
 * the name, the type, the size, the tags, the note and the whole-file checksum
 * all live INSIDE that one blob, so unlike an undecodable vault item, whose name
 * is a separate ciphertext field, there is no name to rewrite and no key to
 * rewrite it with. Sealing a fresh blob would be worse than useless: its framing
 * would have to be copied off the very row a reader is required to check it
 * against, which would turn that check into a tautology for this document
 * forever, and its checksum would have to be invented.
 *
 * Nor can it be downloaded: the same key that opens the blob is the one the
 * segments are sealed under.
 */
function UndecodableDocumentNotice() {
  return (
    <div
      role="alert"
      data-testid="document-undecodable"
      className="rounded-lg border border-yellow-300 bg-yellow-50 p-4 text-sm text-yellow-800 dark:border-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-300"
    >
      <p className="font-medium">This document could not be opened with your vault key.</p>
      <p id={UNDECODABLE_NOTICE_ID} className="mt-1">
        Its name, type, tags and contents are all sealed under a key this vault could not unwrap, so
        it cannot be renamed, edited or downloaded. You can still move it to another folder,
        favorite it, send it to the trash, restore it from the trash, and delete it for good.
      </p>
    </div>
  );
}

interface DownloadToViewProps {
  meta: DocumentMeta;
  downloading: boolean;
  onDownload: () => void;
}

/**
 * The content area for a document that opens: what it is, and the one way to see
 * it.
 *
 * This is a permanent state rather than a placeholder. Every byte of a stored
 * document is decrypted and verified here, and then it leaves — nothing in this
 * application parses or renders it, because a parser that runs in this page runs
 * beside the vault key. When a document CAN be shown, it will be shown inside an
 * isolated document with an opaque origin, and this panel remains the answer for
 * everything that one cannot render.
 */
function DownloadToView({ meta, downloading, onDownload }: DownloadToViewProps) {
  return (
    <section
      aria-labelledby="document-open-heading"
      data-testid="document-download-to-view"
      className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-6 text-center"
    >
      <FileText className="mx-auto h-8 w-8 text-[hsl(var(--muted-foreground))]" />
      <h2
        id="document-open-heading"
        className="mt-3 text-base font-semibold text-[hsl(var(--card-foreground))]"
      >
        Download to view
      </h2>
      <p className="mx-auto mt-1 max-w-md text-sm text-[hsl(var(--muted-foreground))]">
        {DOWNLOAD_TO_VIEW_REASON}
      </p>
      <button
        type="button"
        onClick={onDownload}
        disabled={downloading}
        className="mt-4 inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] transition-opacity hover:opacity-90 disabled:opacity-50"
      >
        {downloading ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <Download className="h-4 w-4" />
        )}
        {downloading ? 'Decrypting and verifying…' : `Download ${formatBytes(meta.plaintextBytes)}`}
      </button>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Details
// ---------------------------------------------------------------------------

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs text-[hsl(var(--muted-foreground))]">{label}</p>
      <div className="text-sm text-[hsl(var(--foreground))]">{children}</div>
    </div>
  );
}

/** A timestamp in the reader's own locale, the way the vault detail renders one. */
function formatTimestamp(value: string): string {
  return new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

// ---------------------------------------------------------------------------
// The detail view
// ---------------------------------------------------------------------------

interface DocumentDetailProps {
  document: DecryptedDocument;
  isTrashed: boolean;
}

export function DocumentDetail({ document: doc, isTrashed }: DocumentDetailProps) {
  const navigate = useNavigate();
  const { toast } = useToast();
  const folders = useVaultStore((s) => s.folders);
  const updateDocumentMeta = useDocumentsStore((s) => s.updateDocumentMeta);
  const setFavorite = useDocumentsStore((s) => s.setFavorite);
  const moveToFolder = useDocumentsStore((s) => s.moveToFolder);
  const deleteDocument = useDocumentsStore((s) => s.deleteDocument);
  const restoreDocument = useDocumentsStore((s) => s.restoreDocument);
  const purgeDocument = useDocumentsStore((s) => s.purgeDocument);

  const [downloading, setDownloading] = useState(false);
  const [showEdit, setShowEdit] = useState(false);
  const [editName, setEditName] = useState('');
  const [editTags, setEditTags] = useState('');
  const [editNote, setEditNote] = useState('');
  const [editRefusal, setEditRefusal] = useState<string | null>(null);
  const [editLoading, setEditLoading] = useState(false);
  const [showDelete, setShowDelete] = useState(false);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [restoreLoading, setRestoreLoading] = useState(false);
  const [favoriteLoading, setFavoriteLoading] = useState(false);

  const meta = doc.meta;
  const degraded = meta === null;
  const currentFolder = folders.find((folder) => folder.id === doc.folderId);

  /**
   * Cancels a download in flight when this view goes away.
   *
   * A download is page-scoped, and deliberately unlike an upload: the documents
   * store is module-level precisely so a transfer survives navigation, but a
   * download exists to put a file in front of the person looking at it. So
   * navigating away ends it — and so does a lock, because `ProtectedRoute` swaps
   * this whole subtree out for the unlock screen, which unmounts this component
   * and fires the abort. Without it the decryption would run to completion and
   * save a file to disk after the vault had closed.
   */
  const downloadRef = useRef<AbortController | null>(null);
  useEffect(
    () => () => {
      downloadRef.current?.abort();
    },
    [],
  );

  const handleDownload = useCallback(() => {
    if (!meta) return;
    downloadRef.current?.abort();
    const controller = new AbortController();
    downloadRef.current = controller;
    setDownloading(true);
    void saveDocument({ id: doc.id, meta }, { signal: controller.signal })
      .then((filename) => {
        toast({ title: `Saved as ${filename}`, type: 'success' });
      })
      .catch((error: unknown) => {
        // A dismissed save dialog, a navigation and a lock all arrive here, and
        // none of them is a failure the user needs to be told about — the same
        // rule the upload panel applies to a cancelled transfer.
        if (error instanceof DocumentDownloadCancelledError) return;
        toast({
          title:
            error instanceof DocumentIntegrityError
              ? 'This document did not verify'
              : 'The download failed',
          description: getApiErrorMessage(error, 'Please try again.'),
          type: 'error',
        });
      })
      .finally(() => {
        setDownloading(false);
      });
  }, [doc.id, meta, toast]);

  const openEditor = useCallback(() => {
    if (!meta) return;
    setEditName(meta.name);
    setEditTags(meta.tags.join(', '));
    setEditNote(meta.note ?? '');
    setEditRefusal(null);
    setShowEdit(true);
  }, [meta]);

  const handleSaveDetails = useCallback(() => {
    if (!meta) return;
    const name = editName.trim();
    const tags = parseTagField(editTags);
    const note = editNote.trim();
    // The note is REMOVED from the spread before it is conditionally put back,
    // because `{ ...meta, ...(note === '' ? {} : { note }) }` carries the OLD
    // note forward when the field has been cleared. The pre-flight would then
    // charge the byte budget for text the store is about to delete, and could
    // refuse a save that fits with the words "Shorten the note" while the note
    // field is empty. It has to measure the object that will actually be sealed.
    const { note: _cleared, ...withoutNote } = meta;
    const candidate: DocumentMeta = {
      ...withoutNote,
      name,
      tags,
      ...(note === '' ? {} : { note }),
    };
    const refusal = refusalFor(candidate);
    if (refusal !== null) {
      setEditRefusal(refusal);
      return;
    }
    setEditRefusal(null);
    setEditLoading(true);
    // `note: null` REMOVES the note; `undefined` would leave the old one in
    // place, which is the one way an emptied field could silently keep its value.
    void updateDocumentMeta(doc.id, { name, tags, note: note === '' ? null : note })
      .then(() => {
        toast({ title: 'Document details updated', type: 'success' });
        setShowEdit(false);
      })
      .catch((error: unknown) => {
        setEditRefusal(getApiErrorMessage(error, 'The details could not be saved.'));
      })
      .finally(() => {
        setEditLoading(false);
      });
  }, [doc.id, editName, editNote, editTags, meta, toast, updateDocumentMeta]);

  const handleToggleFavorite = useCallback(() => {
    setFavoriteLoading(true);
    void setFavorite(doc.id, !doc.favorite)
      .then(() => {
        toast({
          title: doc.favorite ? 'Removed from favorites' : 'Added to favorites',
          type: 'success',
        });
      })
      .catch((error: unknown) => {
        toast({ title: getApiErrorMessage(error, 'Failed to update favorite'), type: 'error' });
      })
      .finally(() => {
        setFavoriteLoading(false);
      });
  }, [doc.favorite, doc.id, setFavorite, toast]);

  const handleMove = useCallback(
    (folderId: string | null) => {
      // The menu closes itself on an item click; this only has to do the write.
      void moveToFolder(doc.id, folderId)
        .then(() => {
          toast({ title: 'Document moved', type: 'success' });
        })
        .catch((error: unknown) => {
          toast({ title: getApiErrorMessage(error, 'Failed to move document'), type: 'error' });
        });
    },
    [doc.id, moveToFolder, toast],
  );

  const handleDelete = useCallback(() => {
    setDeleteLoading(true);
    const request = isTrashed ? purgeDocument(doc.id) : deleteDocument(doc.id);
    void request
      .then(() => {
        toast({
          title: isTrashed ? 'Document permanently deleted' : 'Document moved to trash',
          type: 'success',
        });
        void navigate('/documents');
      })
      .catch((error: unknown) => {
        toast({ title: getApiErrorMessage(error, 'Failed to delete document'), type: 'error' });
      })
      .finally(() => {
        setDeleteLoading(false);
        setShowDelete(false);
      });
  }, [deleteDocument, doc.id, isTrashed, navigate, purgeDocument, toast]);

  const handleRestore = useCallback(() => {
    setRestoreLoading(true);
    void restoreDocument(doc.id)
      .then(() => {
        toast({ title: 'Document restored', type: 'success' });
        void navigate('/documents');
      })
      .catch((error: unknown) => {
        toast({ title: getApiErrorMessage(error, 'Failed to restore document'), type: 'error' });
      })
      .finally(() => {
        setRestoreLoading(false);
      });
  }, [doc.id, navigate, restoreDocument, toast]);

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div className="flex items-center gap-3">
        <Link
          to="/documents"
          aria-label="Back to documents"
          className="rounded-md p-2 text-[hsl(var(--muted-foreground))] transition-colors hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--foreground))]"
        >
          <ArrowLeft className="h-5 w-5" />
        </Link>
        <span
          className={cn(
            'flex h-10 w-10 items-center justify-center rounded-lg',
            degraded
              ? 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300'
              : 'bg-[hsl(var(--primary)/0.1)] text-[hsl(var(--primary))]',
          )}
        >
          {degraded ? <FileWarning className="h-5 w-5" /> : <FileText className="h-5 w-5" />}
        </span>
        <div className="min-w-0 flex-1">
          <h1 className="truncate text-xl font-semibold text-[hsl(var(--foreground))]">
            {degraded ? 'Unopenable document' : meta.name}
          </h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))]">
            Last modified {formatTimestamp(doc.updatedAt)}
          </p>
        </div>
      </div>

      {isTrashed && (
        <p
          data-testid="document-trashed-note"
          className="flex items-start gap-2 rounded-md border border-[hsl(var(--border))] p-3 text-sm text-[hsl(var(--muted-foreground))]"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            This document is in the trash. It still occupies storage and still counts against your
            allowance until it is deleted for good.
          </span>
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2">
        {isTrashed ? (
          <>
            <button
              type="button"
              onClick={handleRestore}
              disabled={restoreLoading}
              className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {restoreLoading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <RotateCcw className="h-4 w-4" />
              )}
              Restore
            </button>
            <button
              type="button"
              onClick={() => setShowDelete(true)}
              className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--destructive)/0.3)] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive))] transition-colors hover:bg-[hsl(var(--destructive)/0.1)]"
            >
              <Trash2 className="h-4 w-4" />
              Delete Forever
            </button>
          </>
        ) : (
          <>
            {/* The one control an unopenable document must not offer. Saving it
                would seal a fresh blob whose framing came off the very row a
                reader has to check it against, and whose checksum would be
                invented — so the control keeps its place in the tab order,
                names the notice as its description, and does nothing.
                `aria-disabled` rather than `disabled` for the reason
                `VaultItemDetail` records: a `disabled` control leaves the tab
                order, so the people who most need the explanation cannot reach
                it. */}
            <button
              type="button"
              onClick={openEditor}
              aria-disabled={degraded ? true : undefined}
              aria-describedby={degraded ? UNDECODABLE_NOTICE_ID : undefined}
              title={degraded ? UNDECODABLE_EDIT_HINT : undefined}
              className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] transition-opacity hover:opacity-90 aria-disabled:cursor-not-allowed aria-disabled:opacity-50 aria-disabled:hover:opacity-50"
            >
              <Pencil className="h-4 w-4" />
              Edit details
            </button>
            <button
              type="button"
              onClick={handleToggleFavorite}
              disabled={favoriteLoading}
              className={cn(
                'inline-flex items-center gap-2 rounded-md border px-3 py-2 text-sm font-medium transition-colors disabled:opacity-50',
                doc.favorite
                  ? 'border-yellow-400 bg-yellow-50 text-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-300'
                  : 'border-[hsl(var(--input))] text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]',
              )}
            >
              {favoriteLoading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Star
                  className={cn('h-4 w-4', doc.favorite && 'fill-yellow-400 text-yellow-400')}
                />
              )}
              {doc.favorite ? 'Favorited' : 'Favorite'}
            </button>
            {/* The shared menu rather than a hand-rolled one, because this
                widget claims `role="menu"` and that role promises an interaction
                model: focus moves onto the first item when it opens, the arrows
                and Home/End rove between them, Escape closes it and returns
                focus to the trigger, and a click anywhere else dismisses it.
                `DropdownMenu` implements all of that (WCAG 2.1.1); a `div` with
                the role and nothing behind it announces a menu and then behaves
                like a list of buttons that never closes. */}
            <DropdownMenu>
              <DropdownMenuTrigger
                // Names the ACTION and the current state together. The visible
                // label is the folder, which on its own would announce as a
                // button called "No folder" that says nothing about what
                // pressing it does.
                aria-label={`Move to folder — currently ${currentFolder?.name ?? NO_FOLDER_LABEL}`}
                className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm font-medium text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent))]"
              >
                <FolderOpen className="h-4 w-4" />
                {currentFolder?.name ?? NO_FOLDER_LABEL}
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" aria-label="Move to folder" className="w-48">
                {[{ id: null, name: NO_FOLDER_LABEL }, ...folders].map((folder) => (
                  <DropdownMenuItem
                    key={folder.id ?? 'none'}
                    onClick={() => handleMove(folder.id)}
                    className={cn(
                      folder.id === (doc.folderId ?? null) && 'bg-[hsl(var(--accent))]',
                    )}
                  >
                    {folder.name}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
            <button
              type="button"
              onClick={() => setShowDelete(true)}
              className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--destructive)/0.3)] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive))] transition-colors hover:bg-[hsl(var(--destructive)/0.1)]"
            >
              <Trash2 className="h-4 w-4" />
              Delete
            </button>
          </>
        )}
      </div>

      {/* The content area, and the only place a document's own bytes are ever
          spoken about. Today it holds an explanation and a button; it never
          holds the file. */}
      {degraded ? (
        <UndecodableDocumentNotice />
      ) : (
        <DownloadToView meta={meta} downloading={downloading} onDownload={handleDownload} />
      )}

      {!degraded && meta.tags.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {meta.tags.map((tag) => (
            <span
              key={tag}
              className="rounded-full bg-[hsl(var(--secondary))] px-2.5 py-0.5 text-xs font-medium text-[hsl(var(--secondary-foreground))]"
            >
              {tag}
            </span>
          ))}
        </div>
      )}

      <div className="grid grid-cols-2 gap-4 border-t border-[hsl(var(--border))] pt-4">
        {!degraded && (
          <>
            <DetailRow label="Type">{meta.mime === '' ? 'Unknown' : meta.mime}</DetailRow>
            <DetailRow label="Size">{formatBytes(meta.plaintextBytes)}</DetailRow>
          </>
        )}
        <DetailRow label="Added">{formatTimestamp(doc.createdAt)}</DetailRow>
        <DetailRow label="Modified">{formatTimestamp(doc.updatedAt)}</DetailRow>
        {!degraded && meta.note !== undefined && (
          <div className="col-span-2">
            <p className="text-xs text-[hsl(var(--muted-foreground))]">Note</p>
            {/* Plain text, deliberately. A note is the user's own writing, but it
                travels with a file that is not, and this view has no business
                being the one place a document's metadata becomes markup. */}
            <p className="whitespace-pre-wrap text-sm text-[hsl(var(--foreground))]">{meta.note}</p>
          </div>
        )}
        {!degraded && (
          <div className="col-span-2">
            <p className="text-xs text-[hsl(var(--muted-foreground))]">
              SHA-256 of the original file
            </p>
            {/* Shown because it is the number a downloaded copy can be checked
                against outside this application, which is the only verification
                that does not depend on this application being correct. */}
            <code className="block break-all font-mono text-xs text-[hsl(var(--muted-foreground))]">
              {meta.sha256}
            </code>
          </div>
        )}
      </div>

      <Dialog open={showEdit} onOpenChange={setShowEdit}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Edit details</DialogTitle>
            <DialogDescription>
              The name, tags and note are re-sealed in your browser under this document&rsquo;s own
              key. The stored file is not touched and not re-uploaded.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3">
            <div>
              <label
                htmlFor="document-edit-name"
                className="mb-1.5 block text-sm font-medium text-[hsl(var(--foreground))]"
              >
                Name
              </label>
              <input
                id="document-edit-name"
                value={editName}
                onChange={(event) => setEditName(event.target.value)}
                maxLength={MAX_DOCUMENT_NAME_LENGTH}
                autoComplete="off"
                className="w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))]"
              />
            </div>
            <div>
              <label
                htmlFor="document-edit-tags"
                className="mb-1.5 block text-sm font-medium text-[hsl(var(--foreground))]"
              >
                Tags
              </label>
              <input
                id="document-edit-tags"
                value={editTags}
                onChange={(event) => setEditTags(event.target.value)}
                placeholder="Separate tags with commas"
                autoComplete="off"
                className="w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))]"
              />
            </div>
            <div>
              <label
                htmlFor="document-edit-note"
                className="mb-1.5 block text-sm font-medium text-[hsl(var(--foreground))]"
              >
                Note
              </label>
              <textarea
                id="document-edit-note"
                value={editNote}
                onChange={(event) => setEditNote(event.target.value)}
                maxLength={MAX_DOCUMENT_NOTE_LENGTH}
                rows={4}
                className="w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))]"
              />
            </div>
            {editRefusal !== null && (
              <p
                role="alert"
                data-testid="document-edit-refusal"
                className="text-xs text-red-700 dark:text-red-300"
              >
                {editRefusal}
              </p>
            )}
          </div>

          <DialogFooter>
            <button
              type="button"
              onClick={() => setShowEdit(false)}
              className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent))]"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleSaveDetails}
              disabled={editLoading}
              className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {editLoading && <Loader2 className="h-4 w-4 animate-spin" />}
              Save
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={showDelete} onOpenChange={setShowDelete}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>
              {isTrashed ? 'Delete this document for good' : 'Move to trash'}
            </DialogTitle>
            <DialogDescription>
              {isTrashed
                ? 'The stored file is deleted from object storage and the only copy of the key that decrypts it is destroyed with it. Nothing can bring it back.'
                : 'The document is kept for thirty days and can be restored. It still occupies storage while it is in the trash.'}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <button
              type="button"
              onClick={() => setShowDelete(false)}
              className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent))]"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleDelete}
              disabled={deleteLoading}
              className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--destructive))] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive-foreground))] transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {deleteLoading && <Loader2 className="h-4 w-4 animate-spin" />}
              {isTrashed ? 'Delete forever' : 'Move to trash'}
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
