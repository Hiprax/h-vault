import { useEffect, useRef, useState } from 'react';
import { Link, Navigate, useParams } from 'react-router';
import { AlertTriangle, Loader2 } from 'lucide-react';
import { getApiErrorMessage } from '../lib/utils';
import { useDocumentsConfig } from '../hooks/useDocumentsConfig';
import { useDocumentsStore } from '../stores/documentsStore';
import { useVaultStore } from '../stores/vaultStore';
import { DocumentDetail } from '../components/documents/DocumentDetail';
import { StorageUnavailable } from '../components/documents/StorageUnavailable';

function Spinner() {
  return (
    <div className="flex items-center justify-center py-20" role="status" aria-label="Loading">
      <Loader2 className="h-8 w-8 animate-spin text-[hsl(var(--primary))]" />
    </div>
  );
}

function BackToDocuments() {
  return (
    <Link
      to="/documents"
      className="mt-4 inline-block rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] transition-opacity hover:opacity-90"
    >
      Back to documents
    </Link>
  );
}

/**
 * One document.
 *
 * The feature flag is answered before anything is requested, exactly as the list
 * route does, so a server with no document store is never asked for a document
 * it cannot produce and the 503 its endpoints would answer with — redacted to
 * its status text in production — never has to be interpreted.
 */
export default function DocumentPage() {
  const { id } = useParams<{ id: string }>();
  const config = useDocumentsConfig();
  const documents = useDocumentsStore((s) => s.documents);
  const trashDocuments = useDocumentsStore((s) => s.trashDocuments);
  const documentsLoading = useDocumentsStore((s) => s.documentsLoading);
  const trashLoading = useDocumentsStore((s) => s.trashLoading);
  const folderCount = useVaultStore((s) => s.folders.length);
  const fetchFolders = useVaultStore((s) => s.fetchFolders);
  const [loadError, setLoadError] = useState<string | null>(null);

  const enabled = config?.enabled === true;
  const requested = useRef(false);

  // The decision to fetch is made ONCE, at mount, from what the store already
  // holds — read imperatively so this effect does not depend on the two arrays
  // and re-run every time one of them is replaced.
  //
  // Arriving from the list means the row is already open and no request is made
  // at all, which matters: opening the list is a decrypt of every row a user
  // owns, and repeating it on each document they look at would be the same work
  // over again. Arriving by URL, or at a document that is in the trash, means
  // neither list can be assumed, so both are read.
  useEffect(() => {
    // `id === undefined` is checked HERE as well as at the render below, because
    // an effect runs whatever the render returned: without it, a mount with no id
    // would decrypt both whole lists on its way to a redirect.
    if (!enabled || id === undefined || requested.current) return;
    requested.current = true;
    const store = useDocumentsStore.getState();
    const known =
      store.documents.some((doc) => doc.id === id) ||
      store.trashDocuments.some((doc) => doc.id === id);
    if (known) return;
    void Promise.all([store.fetchDocuments(), store.fetchTrash()]).catch((error: unknown) => {
      setLoadError(getApiErrorMessage(error, 'This document could not be loaded.'));
    });
  }, [enabled, id]);

  // The folder names the move menu offers. They belong to the vault store, which
  // this route does not otherwise use, so a user who came straight here by URL
  // has never loaded them.
  useEffect(() => {
    if (!enabled || folderCount > 0) return;
    void fetchFolders().catch(() => {
      // A missing folder list costs the move menu its names and nothing else.
      // Reporting it here would put an error in front of someone whose document
      // loaded perfectly well.
    });
  }, [enabled, folderCount, fetchFolders]);

  if (config === null) return <Spinner />;
  if (!config.enabled) return <StorageUnavailable />;
  if (id === undefined) return <Navigate to="/documents" replace />;

  const active = documents.find((doc) => doc.id === id);
  const trashed = trashDocuments.find((doc) => doc.id === id);
  const document = active ?? trashed;

  if (document) return <DocumentDetail document={document} isTrashed={active === undefined} />;

  if (loadError !== null) {
    return (
      <div
        role="alert"
        data-testid="document-load-error"
        className="mx-auto max-w-md py-20 text-center"
      >
        <AlertTriangle className="mx-auto h-8 w-8 text-red-700 dark:text-red-300" />
        <h1 className="mt-3 text-xl font-semibold text-[hsl(var(--foreground))]">
          This document could not be loaded
        </h1>
        <p className="mt-2 text-sm text-[hsl(var(--muted-foreground))]">{loadError}</p>
        <BackToDocuments />
      </div>
    );
  }

  if (documentsLoading || trashLoading) return <Spinner />;

  return (
    <div data-testid="document-not-found" className="mx-auto max-w-md py-20 text-center">
      <h1 className="text-2xl font-bold text-[hsl(var(--foreground))]">Document not found</h1>
      <p className="mt-2 text-sm text-[hsl(var(--muted-foreground))]">
        It does not exist, or it has been permanently deleted.
      </p>
      <BackToDocuments />
    </div>
  );
}
