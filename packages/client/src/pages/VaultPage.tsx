import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useVaultStore } from '../stores/vaultStore';
import { useAuthStore } from '../stores/authStore';
import { ExpiringCardsReminder } from '../components/vault/ExpiringCardsReminder';
import { SearchBar, VAULT_SEARCH_RESULTS_ID } from '../components/vault/SearchBar';
import { FolderRail } from '../components/folders/FolderRail';
import { RailLayout } from '../components/layout/RailLayout';
import { useVaultFolderScope } from '../hooks/useVaultFolderScope';
import { VaultList } from '../components/vault/VaultList';
import { VaultItemForm, useCustomFieldsLimit } from '../components/vault/VaultItemForm';
import { useKeyboardShortcuts } from '../hooks/useKeyboardShortcuts';
import { useToast } from '../components/ui/Toast';
import { useInlineDialog } from '../components/ui/Dialog';
import { ErrorBoundary } from '../components/layout/ErrorBoundary';
import { describeTransientFailure } from '../services/auth/sessionFailure';
import { refreshInBackground } from '../lib/backgroundRefresh';

export default function VaultPage() {
  const fetchItems = useVaultStore((s) => s.fetchItems);
  const fetchTrashItems = useVaultStore((s) => s.fetchTrashItems);
  const fetchFolders = useVaultStore((s) => s.fetchFolders);
  const showTrash = useVaultStore((s) => s.showTrash);
  const items = useVaultStore((s) => s.items);
  const userId = useAuthStore((s) => s.user?.userId ?? '');
  // Hiding the card-expiry reminder unmounts the button that was pressed, so focus
  // is handed to the page's heading rather than falling to <body>.
  const headingRef = useRef<HTMLHeadingElement>(null);
  const focusHeading = useCallback(() => headingRef.current?.focus(), []);
  const selectedType = useVaultStore((s) => s.selectedType);
  const selectedFolder = useVaultStore((s) => s.selectedFolder);
  // One reader of the filter state, shared with the rail. Two independent readers
  // is the split that made a document's folder and favorite do nothing visible.
  const scope = useVaultFolderScope();
  const searchQuery = useVaultStore((s) => s.searchQuery);
  const setSearchQuery = useVaultStore((s) => s.setSearchQuery);
  // Set by `VaultList` after it filters, so the field reports the same number the
  // list is showing without either of them re-deriving the other's work.
  const filteredItemCount = useVaultStore((s) => s.filteredItemCount);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  // Read here and handed to the editor, so the form itself issues no request.
  const customFieldsLimit = useCustomFieldsLimit();
  const { toast } = useToast();
  const createDialogRef = useRef<HTMLDivElement>(null);
  const closeCreateDialog = useCallback(() => setShowCreateDialog(false), []);
  useInlineDialog(createDialogRef, showCreateDialog, closeCreateDialog);

  // Fetch data on mount
  useEffect(() => {
    // A refused or failed reload leaves the list on screen as it was (the store
    // puts it back); the toast says why when the reason is a passing one.
    void fetchItems().catch((error: unknown) => {
      const why = describeTransientFailure(error);
      toast({
        title: 'Failed to load vault items',
        type: 'error',
        ...(why === null ? {} : { description: why }),
      });
    });
    void fetchFolders().catch(() => toast({ title: 'Failed to load folders', type: 'error' }));
    void fetchTrashItems().catch(() => {
      /* Trash is non-critical */
    });
  }, [fetchItems, fetchFolders, fetchTrashItems, toast]);

  // Listen for decryption failures and show a toast warning
  useEffect(() => {
    const handler = (e: Event) => {
      const count = (e as CustomEvent<{ count: number }>).detail.count;
      // A zero is Settings' clean check lowering the banner, not a failure to report.
      if (count < 1) return;
      toast({
        title: `${String(count)} item(s) could not be decrypted`,
        description: 'These items may be corrupted or encrypted with a different key.',
        type: 'warning',
      });
    };
    window.addEventListener('vault-decryption-failures', handler);
    return () => window.removeEventListener('vault-decryption-failures', handler);
  }, [toast]);

  // Fetch trash items when switching to trash view
  useEffect(() => {
    if (showTrash) {
      refreshInBackground(fetchTrashItems());
    }
  }, [showTrash, fetchTrashItems]);

  const handleCreateNew = useCallback(() => {
    setShowCreateDialog(true);
  }, []);

  // Keyboard shortcut: Ctrl+N to create new item
  const vaultShortcuts = useMemo(
    () => ({
      n: () => setShowCreateDialog(true),
    }),
    [],
  );
  useKeyboardShortcuts(vaultShortcuts);

  // The re-read after a save is what refreshes the offline copy of the vault (it
  // is written by a whole walk and nothing else). A refused or failed one leaves
  // the list as it was, with the saved row in it.
  const handleFormSaved = useCallback(() => {
    setShowCreateDialog(false);
    void fetchItems().catch(() => {
      /* the store keeps the list; the next walk refreshes the offline copy */
    });
  }, [fetchItems]);

  const handleFormCancel = useCallback(() => {
    setShowCreateDialog(false);
  }, []);

  return (
    <>
      <RailLayout
        rail={(close) => <FolderRail scope={scope} className="flex-1" onClose={close} />}
        toolbar={
          <SearchBar
            query={searchQuery}
            onQueryChange={setSearchQuery}
            resultCount={filteredItemCount}
            placeholder="Search vault... (Ctrl+K)"
            label="Search vault items"
            controlsId={VAULT_SEARCH_RESULTS_ID}
            className="max-w-lg flex-1"
          />
        }
      >
        {/* The page's one h1, as `/documents` has. Outside the list's error
            boundary so a list that fails to render still leaves a named page,
            and outside the rail so it names the page rather than one pane. */}
        <h1
          ref={headingRef}
          tabIndex={-1}
          className="mb-4 text-2xl font-bold text-[hsl(var(--foreground))] focus:outline-none"
        >
          Vault
        </h1>
        {/* Expired and soon-expiring cards, worked out in the browser; nothing at
            all when there are none, when hidden, or in the trash view. */}
        {!showTrash && (
          <ExpiringCardsReminder
            items={items}
            userId={userId}
            onHidden={focusHeading}
            className="mb-4"
          />
        )}
        <ErrorBoundary>
          <VaultList onCreateNew={handleCreateNew} />
        </ErrorBoundary>
      </RailLayout>

      {/* Create item dialog */}
      {showCreateDialog && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/50 p-4 pt-[10vh]"
          onClick={(e) => {
            if (e.target === e.currentTarget) closeCreateDialog();
          }}
        >
          <div
            ref={createDialogRef}
            className="w-full max-w-2xl rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-6 shadow-xl"
            role="dialog"
            aria-modal="true"
            aria-label="Create new vault item"
          >
            <ErrorBoundary>
              <VaultItemForm
                defaultType={selectedType ?? undefined}
                defaultFolderId={selectedFolder ?? undefined}
                onSaved={handleFormSaved}
                onCancel={handleFormCancel}
                customFieldsLimit={customFieldsLimit}
              />
            </ErrorBoundary>
          </div>
        </div>
      )}
    </>
  );
}
