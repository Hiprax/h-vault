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
  Maximize2,
  Minimize2,
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
  MAX_PREVIEW_BYTES,
  MAX_TAG_LENGTH,
  documentExtension,
  documentMetaJsonByteLength,
  formatBytes,
  previewModeForName,
} from '@hvault/shared';
import type { DocumentMeta, PreviewMode } from '@hvault/shared';
import { cn, getApiErrorMessage, isSafeUrl } from '../../lib/utils';
import { useToast } from '../ui/Toast';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  useInlineDialog,
} from '../ui/Dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../ui/DropdownMenu';
import { useVaultStore } from '../../stores/vaultStore';
import { resolveEffectiveTheme, useUIStore } from '../../stores/uiStore';
import { DocumentSandbox } from './DocumentSandbox';
import { useDocumentsStore, type DecryptedDocument } from '../../stores/documentsStore';
import {
  DocumentDownloadCancelledError,
  DocumentIntegrityError,
  readDocumentPlaintext,
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
 * Why a particular document is not shown, in the reader's own terms.
 *
 * Every branch of the decision below produces one of these, and the panel always
 * shows one when it declines. "Download to view" with no reason reads as a
 * missing feature; the same panel with the reason reads as a decision, which is
 * what each of these is.
 *
 * Note the shape of the PDF sentence in particular. It is the only type this
 * project has decided AGAINST rendering rather than merely not recognising, and
 * the interface should say which of those it is.
 */
const PREVIEW_DECLINED = {
  pdf: 'PDFs are download-only here, deliberately. A PDF viewer is a large third-party parser, and the best-known one has a documented history of running a document\u2019s own JavaScript in the page that hosts it \u2014 which here would be the page holding your unlocked vault key. Download it and open it in the viewer your computer already has.',
  unsupported: (extension: string) =>
    extension === ''
      ? 'This file has no extension, so there is nothing to work out how to display it from. Download it and open it with the application you would normally use.'
      : `There is no viewer here for a .${extension} file. Download it and open it with the application you would normally use.`,
  tooLarge: (bytes: number) =>
    `This document is ${formatBytes(bytes)}, which is larger than the ${formatBytes(MAX_PREVIEW_BYTES)} a preview holds in memory. Download it instead \u2014 the whole file is still decrypted and checked on the way out.`,
} as const;

/**
 * What the preview panel says about itself while it is doing the expensive part.
 *
 * The document is decrypted segment by segment, every segment's authentication
 * tag is checked, and the whole file's SHA-256 is compared with the one sealed
 * in its metadata. On a large file that is seconds of work, and a panel that
 * said nothing would read as a preview that had failed.
 */
const PREVIEW_LOADING_LABEL = 'Decrypting and verifying\u2026';

/** What both the folder trigger and the first menu item call "outside every folder". */
const NO_FOLDER_LABEL = 'No folder';

/** The id of {@link PurgePendingNotice}'s body, so the inert Restore can describe itself. */
const PURGE_PENDING_NOTICE_ID = 'document-purge-pending-notice';

/**
 * Why a document already being destroyed cannot be restored.
 *
 * `restoreDocument` filters on `purgePending: null` server-side, so a Restore
 * here would answer 404 and read as a bug. The state became reachable the moment
 * the trash gained an Empty-trash control: a run that could not delete every
 * object leaves the rows it failed on marked and still listed.
 */
const PURGE_PENDING_HINT =
  'This document is already being deleted for good. What remains of it is removed automatically, and it cannot be restored.';

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

/**
 * Why a preview is not being offered, or `null` when one is.
 *
 * Decided from the row's AUTHENTICATED METADATA ALONE, and decided BEFORE a
 * single segment is requested. That ordering is the whole point: reversed, a
 * multi-gigabyte document would be fetched, decrypted and verified in full and
 * only then turned away at the size check.
 */
function previewRefusalFor(meta: DocumentMeta, mode: PreviewMode): string | null {
  if (mode === 'none') {
    const extension = documentExtension(meta.name);
    return extension === 'pdf' ? PREVIEW_DECLINED.pdf : PREVIEW_DECLINED.unsupported(extension);
  }
  if (meta.plaintextBytes > MAX_PREVIEW_BYTES) {
    return PREVIEW_DECLINED.tooLarge(meta.plaintextBytes);
  }
  return null;
}

interface DocumentContentProps {
  meta: DocumentMeta;
  downloading: boolean;
  onDownload: () => void;
  /** The verified plaintext, or `null` while it is being read or not wanted. */
  bytes: ArrayBuffer | null;
  mode: PreviewMode;
  loading: boolean;
  /** Why no frame is being drawn, or `null` when one is. */
  refusal: string | null;
  onLink: (href: string) => void;
  onUnavailable: (reason: string) => void;
  /** Whether the reader has ASKED for full screen. Honoured only when a frame exists. */
  expanded: boolean;
  onExpandedChange: (next: boolean) => void;
  /**
   * Whether one of this view's dialogs is open ON TOP of the panel.
   *
   * `Dialog` renders through `createPortal(…, document.body)`, i.e. OUTSIDE this
   * section — and `aria-modal="true"` is precisely the assertion that everything
   * outside its own container is inert. Left on, it would tell a screen reader to
   * ignore the link-confirmation dialog, which is the control the whole
   * link-safety design rests on. No axe rule catches this.
   */
  dialogOpen: boolean;
}

/**
 * The content area: the document's own chrome, and either a preview frame or the
 * reason there is not one.
 *
 * THE TITLE AND THE DOWNLOAD BUTTON ARE DRAWN HERE, OUTSIDE THE FRAME, and that
 * is a security property rather than a layout choice. Everything inside the
 * rectangle is rendered by whatever the document turned out to be; a renderer
 * that could draw the document's name, or a button labelled "Download", could
 * draw a different name and a different destination. So the two things a reader
 * would act on live in the application's own DOM, where no renderer can reach
 * them.
 *
 * A view toggle for a CSV or a JSON document IS inside the frame, and that is
 * not an exception to the rule: it switches between two renderings of the same
 * bytes and has nothing to forge.
 */
function DocumentContent({
  meta,
  downloading,
  onDownload,
  bytes,
  mode,
  loading,
  refusal,
  onLink,
  onUnavailable,
  expanded,
  onExpandedChange,
  dialogOpen,
}: DocumentContentProps) {
  const theme = resolveEffectiveTheme(useUIStore((state) => state.theme));
  const panelRef = useRef<HTMLElement | null>(null);

  // The request is HONOURED only when there is actually a frame to enlarge, and
  // that is DERIVED rather than stored: a frame that dies — a handshake that
  // timed out, a renderer that reported failure — drops the panel out of full
  // screen in the SAME commit, instead of stranding one paragraph of "download to
  // view" on a full-viewport canvas.
  const canExpand = refusal === null && !loading && bytes !== null;
  const isExpanded = expanded && canExpand;
  const collapse = useCallback(() => onExpandedChange(false), [onExpandedChange]);
  useInlineDialog(panelRef, isExpanded, collapse);

  return (
    <section
      ref={panelRef}
      aria-labelledby="document-open-heading"
      data-testid="document-content"
      // Claimed only while the panel fills the viewport. A full-screen overlay
      // that left the page behind it tabbable would send a keyboard user's focus
      // to things they cannot see — the ARIA modal-dialog pattern, and WCAG 2.4.3
      // (Focus Order); at rest this is a named `region` landmark and must stay
      // one. The name is the document's own, drawn by the application — never by
      // anything inside the frame.
      role={isExpanded ? 'dialog' : undefined}
      // The ROLE stays while expanded; only the modality is dropped, and only
      // while a portalled dialog is open above it. See `dialogOpen`.
      aria-modal={isExpanded && !dialogOpen ? true : undefined}
      className={cn(
        'bg-[hsl(var(--card))]',
        isExpanded
          ? // A CLASS CHANGE ON THE ELEMENT THAT WAS ALREADY THERE. Never a
            // portal, never a second <section>, never a wrapper that exists in
            // one branch only: all three move the iframe in the React tree, which
            // detaches it, discards its browsing context, restarts the ten-second
            // handshake and re-posts up to 25 MiB of verified plaintext.
            //
            // `fixed` resolves against the viewport here because no ancestor of
            // AppLayout's <main> establishes a containing block — no `transform`,
            // `filter`, `backdrop-filter`, `contain` or `will-change`. Adding one
            // upstream would confine this panel to the content column, silently.
            'animate-in fixed inset-0 z-50 flex flex-col'
          : // `overflow-hidden` exists to clip the frame's square corners to the
            // rounded border, so it goes with the border rather than separately.
            'overflow-hidden rounded-lg border border-[hsl(var(--border))]',
      )}
    >
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-[hsl(var(--border))] p-3">
        <h2
          id="document-open-heading"
          className="min-w-0 flex-1 truncate text-sm font-semibold text-[hsl(var(--card-foreground))]"
        >
          {meta.name}
        </h2>
        {/* FIRST in the action group, and that placement is load-bearing:
            `useInlineDialog` focuses the first focusable element inside this
            panel, so opening full screen puts focus on the control that gets the
            reader back out. ONE button in both states — the same DOM node — so
            collapsing leaves focus exactly where expanding put it and no focus
            restoration is needed.

            Neither `aria-pressed` nor `aria-expanded`: nothing is shown or
            hidden, the same element changes size, and the visible text and the
            accessible name change together. "Exit full screen, pressed" would
            read backwards. */}
        {canExpand && (
          <button
            type="button"
            onClick={() => onExpandedChange(!isExpanded)}
            className="inline-flex shrink-0 items-center gap-2 rounded-md border border-[hsl(var(--input))] px-3 py-1.5 text-sm font-medium text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent))]"
          >
            {isExpanded ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
            {isExpanded ? 'Exit full screen' : 'Full screen'}
          </button>
        )}
        <button
          type="button"
          onClick={onDownload}
          disabled={downloading}
          className="inline-flex shrink-0 items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-3 py-1.5 text-sm font-medium text-[hsl(var(--primary-foreground))] transition-opacity hover:opacity-90 disabled:opacity-50"
        >
          {downloading ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Download className="h-4 w-4" />
          )}
          {downloading ? PREVIEW_LOADING_LABEL : `Download ${formatBytes(meta.plaintextBytes)}`}
        </button>
      </div>

      {refusal !== null ? (
        <div data-testid="document-download-to-view" className="p-6 text-center">
          <FileText className="mx-auto h-8 w-8 text-[hsl(var(--muted-foreground))]" />
          <p className="mx-auto mt-3 max-w-md text-sm text-[hsl(var(--muted-foreground))]">
            {refusal}
          </p>
        </div>
      ) : loading || bytes === null ? (
        <div
          className="flex items-center justify-center gap-2 p-10 text-sm text-[hsl(var(--muted-foreground))]"
          role="status"
        >
          <Loader2 className="h-4 w-4 animate-spin" />
          {PREVIEW_LOADING_LABEL}
        </div>
      ) : (
        <DocumentSandbox
          bytes={bytes}
          mode={mode}
          ext={documentExtension(meta.name)}
          theme={theme}
          onLink={onLink}
          onUnavailable={onUnavailable}
          title={`Preview of ${meta.name}`}
          className={cn(
            'w-full border-0 bg-[hsl(var(--background))]',
            // `min-h-0` defeats a flex item's default `min-height: auto`, which an
            // iframe's intrinsic 150px would otherwise use to push the box open.
            isExpanded ? 'min-h-0 flex-1' : 'h-[70vh]',
          )}
        />
      )}
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

/**
 * The origin of a destination, for the confirmation dialog's prominent line.
 *
 * `mailto:` has no origin — `new URL('mailto:a@b').origin` is the string
 * `"null"` — so it is answered with the address itself, which is the part a
 * reader would check. Anything that will not parse falls back to the raw value
 * rather than to an empty line: `isSafeUrl` has already admitted it, and showing
 * nothing where the destination should be is the one outcome a confirmation
 * dialog must never have.
 */
function linkOrigin(href: string | null): string {
  if (href === null) return '';
  try {
    const url = new URL(href);
    return url.protocol === 'mailto:' ? href : url.origin;
  } catch {
    return href;
  }
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
  const clearFilters = useDocumentsStore((s) => s.clearFilters);

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
  const [previewBytes, setPreviewBytes] = useState<ArrayBuffer | null>(null);
  const [previewUnavailable, setPreviewUnavailable] = useState<string | null>(null);
  const [pendingLink, setPendingLink] = useState<string | null>(null);
  const [previewExpanded, setPreviewExpanded] = useState(false);

  const meta = doc.meta;
  const degraded = meta === null;
  const currentFolder = folders.find((folder) => folder.id === doc.folderId);

  // Decided from the row's authenticated metadata alone, and decided BEFORE any
  // segment is fetched. `previewUnavailable` is the fourth reason and the only
  // one that is not knowable up front: the frame failed to start, or a renderer
  // reported that it could not display the file.
  const mode = meta === null ? 'none' : previewModeForName(meta.name);
  const previewRefusal =
    meta === null ? null : (previewUnavailable ?? previewRefusalFor(meta, mode));

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

  /**
   * Read the document once, for the preview, and only when one is being offered.
   *
   * Through `readDocumentPlaintext`, which is the SAME verified read the save
   * paths use: it checks every segment's authentication tag, compares the
   * framing on the row with the authenticated copy inside the metadata, and
   * checks the whole file's SHA-256 at the end. A preview must never be fed
   * bytes that read would have rejected, and a second read path here would be a
   * second place for one of those checks to go missing.
   *
   * Keyed on the document ID, so opening another document reads that one; the
   * abort in the cleanup is what stops the previous read finishing into a
   * component that is now showing something else. It also ends the read on a
   * lock, because `ProtectedRoute` swaps this whole subtree out.
   */
  // Per-document preview state, reset when the document changes.
  //
  // `DocumentPage` renders this component without a `key`, so React REUSES the
  // instance across a detail-to-detail navigation and every piece of state below
  // would otherwise follow the reader to the next document: a failure banner
  // from the previous file, or a link dialog still offering the previous file's
  // destination. `previewBytes` was already reset by the read effect; these two
  // were not. Derived during render rather than in an effect (React's documented
  // adjust-state-when-a-prop-changes pattern) so the stale banner is never
  // painted even for one frame.
  const [seenId, setSeenId] = useState(doc.id);
  if (seenId !== doc.id) {
    setSeenId(doc.id);
    setPreviewBytes(null);
    setPreviewUnavailable(null);
    setPendingLink(null);
    // Full screen is a viewing mode for THIS document. Carried forward, the next
    // file opens filling the viewport without anyone having asked it to — and
    // does so over a spinner, because `previewBytes` above has just been cleared.
    setPreviewExpanded(false);
  }

  useEffect(() => {
    // `degraded` rather than `meta === null`: a document whose blob will not
    // open has NO refusal text — there is no name to read a mode from and no
    // size to compare — so `previewRefusal` is null for it too, and this is the
    // guard that tells the two apart.
    if (previewRefusal !== null || degraded) return undefined;
    const controller = new AbortController();
    setPreviewBytes(null);
    void readDocumentPlaintext(doc.id, { signal: controller.signal })
      .then((plaintext) => {
        if (controller.signal.aborted) return;
        // A fresh buffer rather than the view's own, because the sandbox host
        // treats buffer IDENTITY as "this is a different document" and remounts
        // the frame on a change.
        const copy = new ArrayBuffer(plaintext.bytes.byteLength);
        new Uint8Array(copy).set(plaintext.bytes);
        setPreviewBytes(copy);
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted || error instanceof DocumentDownloadCancelledError) return;
        // Reported IN the panel rather than as a toast: a preview that failed is
        // a state of this page, and the download button beside it still works.
        setPreviewUnavailable(
          getApiErrorMessage(error, 'This document could not be opened for preview.'),
        );
      });
    return () => {
      controller.abort();
    };
    // Depends on the document's IDENTITY and on the decision, never on the
    // `meta` OBJECT. `updateDocumentMeta` builds a fresh `meta` for a rename, so
    // a `meta` dependency made renaming a document re-download and re-decrypt up
    // to 25 MiB of it — for a change to a field the preview does not read.
    // `previewRefusal` already folds in everything about `meta` that decides
    // whether a preview happens at all — the mode and the size — so together
    // with `degraded` these three primitives are the complete and honest
    // dependency set, and nothing in the body reads `meta` itself.
  }, [doc.id, degraded, previewRefusal]);

  /**
   * A link the reader clicked INSIDE the frame.
   *
   * The scheme has already been checked, at the message boundary, by
   * `DocumentSandbox` — which is where it has to happen, because an arrangement
   * where the host forwarded a raw href and this layer decided would be the
   * whole compromise in one message. It is checked AGAIN here, and that is not
   * belt-and-braces for its own sake: this callback is a public prop, so the
   * check that protects it belongs where the window is actually opened.
   */
  /**
   * Collapse only when no dialog is open on top of the panel.
   *
   * `useInlineDialog` and `Dialog` both listen for Escape on `document` and
   * neither stops propagation, so one keypress would close the link dialog AND
   * collapse the panel underneath it. A dialog opened on top owns Escape. The
   * BUTTON is unaffected: while a modal is open it sits behind the overlay and
   * outside that modal's focus trap, so it cannot be reached.
   */
  // ONE expression for two rules that must never disagree: which surface owns
  // Escape, and which surface assistive technology is allowed to read.
  const dialogOpen = pendingLink !== null || showEdit || showDelete;

  const setPreviewExpandedSafely = useCallback(
    (next: boolean) => {
      if (!next && dialogOpen) return;
      setPreviewExpanded(next);
    },
    [dialogOpen],
  );

  const handleLink = useCallback((href: string) => {
    if (!isSafeUrl(href)) return;
    setPendingLink(href);
  }, []);

  const handleOpenLink = useCallback(() => {
    if (pendingLink === null || !isSafeUrl(pendingLink)) return;
    window.open(pendingLink, '_blank', 'noopener,noreferrer');
    setPendingLink(null);
  }, [pendingLink]);

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
        // Land where the document now IS. A reader who reached this page from the
        // trash would otherwise be returned to the trash — the one view the row
        // they just restored is, correctly, no longer in.
        clearFilters();
        void navigate('/documents');
      })
      .catch((error: unknown) => {
        toast({ title: getApiErrorMessage(error, 'Failed to restore document'), type: 'error' });
      })
      .finally(() => {
        setRestoreLoading(false);
      });
  }, [clearFilters, doc.id, navigate, restoreDocument, toast]);

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

      {isTrashed && doc.purgePending === true && (
        <p
          role="alert"
          id={PURGE_PENDING_NOTICE_ID}
          data-testid="document-purge-pending"
          className="flex items-start gap-2 rounded-md border border-amber-400 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-100"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{PURGE_PENDING_HINT}</span>
        </p>
      )}

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
            {/* `aria-disabled` rather than `disabled`, for the reason the Edit
                control records below: a `disabled` control leaves the tab order,
                so the people who most need the explanation cannot reach it. */}
            <button
              type="button"
              onClick={doc.purgePending === true ? undefined : handleRestore}
              disabled={restoreLoading}
              aria-disabled={doc.purgePending === true ? true : undefined}
              aria-describedby={doc.purgePending === true ? PURGE_PENDING_NOTICE_ID : undefined}
              title={doc.purgePending === true ? PURGE_PENDING_HINT : undefined}
              className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] transition-opacity hover:opacity-90 disabled:opacity-50 aria-disabled:cursor-not-allowed aria-disabled:opacity-50 aria-disabled:hover:opacity-100"
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

      {/* The content area. A document that opens is rendered inside an isolated
          frame with an opaque origin; one that cannot be, or must not be, keeps
          the download affordance with the reason beside it. Either way the name
          and the download button are drawn HERE, outside anything a renderer
          controls. */}
      {degraded ? (
        <UndecodableDocumentNotice />
      ) : (
        <DocumentContent
          meta={meta}
          downloading={downloading}
          onDownload={handleDownload}
          bytes={previewBytes}
          mode={mode}
          loading={previewBytes === null}
          refusal={previewRefusal}
          onLink={handleLink}
          onUnavailable={setPreviewUnavailable}
          expanded={previewExpanded}
          onExpandedChange={setPreviewExpandedSafely}
          dialogOpen={dialogOpen}
        />
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
        {/* Rendered unconditionally, and that is not redundancy with the move
            menu above: the menu exists only in the ACTIVE toolbar, so a trashed
            document showed its folder nowhere at all. The menu is a control; this
            is a fact. */}
        <DetailRow label="Folder">{currentFolder?.name ?? NO_FOLDER_LABEL}</DetailRow>
        {isTrashed && doc.deletedAt !== undefined && (
          <DetailRow label="Deleted">{formatTimestamp(doc.deletedAt)}</DetailRow>
        )}
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

      {/* The link-confirmation dialog, on the APPLICATION side.
          The href reaching here has already passed `isSafeUrl` at the message
          boundary in `DocumentSandbox`, and passes it again in `handleOpenLink`
          before anything is opened. What this dialog adds is the part a scheme
          check cannot: the reader gets to see WHERE they are about to go, with
          the ORIGIN shown on its own line, because a link in a document someone
          else wrote is a link someone else chose. */}
      <Dialog
        open={pendingLink !== null}
        onOpenChange={(open) => {
          if (!open) setPendingLink(null);
        }}
      >
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Leave H-Vault?</DialogTitle>
            <DialogDescription>
              This link is inside the document you are viewing, and it was written by whoever made
              the file. It opens in a new tab.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-1">
            <p className="text-xs text-[hsl(var(--muted-foreground))]">Destination</p>
            {/* The ORIGIN first and prominently, then the rest in a quieter
                weight. A long path with a lookalike host buried in it is the
                oldest trick there is, and reading the whole URL as one string is
                exactly how someone misses it. */}
            <p
              data-testid="document-link-origin"
              className="break-all font-mono text-sm font-semibold text-[hsl(var(--foreground))]"
            >
              {linkOrigin(pendingLink)}
            </p>
            <p className="break-all font-mono text-xs text-[hsl(var(--muted-foreground))]">
              {pendingLink}
            </p>
          </div>
          <DialogFooter>
            <button
              type="button"
              onClick={() => setPendingLink(null)}
              className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent))]"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleOpenLink}
              className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] transition-opacity hover:opacity-90"
            >
              Open link
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
