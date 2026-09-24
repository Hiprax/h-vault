import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useVaultStore } from '../stores/vaultStore';
import { SearchBar, VAULT_SEARCH_RESULTS_ID } from '../components/vault/SearchBar';
import { FolderRail } from '../components/folders/FolderRail';
import { RailLayout } from '../components/layout/RailLayout';
import { useVaultFolderScope } from '../hooks/useVaultFolderScope';
import { VaultList } from '../components/vault/VaultList';
import { VaultItemForm } from '../components/vault/VaultItemForm';
import { useKeyboardShortcuts } from '../hooks/useKeyboardShortcuts';
import { useToast } from '../components/ui/Toast';
import { useInlineDialog } from '../components/ui/Dialog';
import { ErrorBoundary } from '../components/layout/ErrorBoundary';

export default function VaultPage() {
  const fetchItems = useVaultStore((s) => s.fetchItems);
  const fetchTrashItems = useVaultStore((s) => s.fetchTrashItems);
  const fetchFolders = useVaultStore((s) => s.fetchFolders);
  const showTrash = useVaultStore((s) => s.showTrash);
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
  const { toast } = useToast();
  const createDialogRef = useRef<HTMLDivElement>(null);
  const closeCreateDialog = useCallback(() => setShowCreateDialog(false), []);
  useInlineDialog(createDialogRef, showCreateDialog, closeCreateDialog);

  // Fetch data on mount
  useEffect(() => {
    void fetchItems().catch(() => toast({ title: 'Failed to load vault items', type: 'error' }));
    void fetchFolders().catch(() => toast({ title: 'Failed to load folders', type: 'error' }));
    void fetchTrashItems().catch(() => {
      /* Trash is non-critical */
    });
  }, [fetchItems, fetchFolders, fetchTrashItems, toast]);

  // Listen for decryption failures and show a toast warning
  useEffect(() => {
    const handler = (e: Event) => {
      const count = (e as CustomEvent<{ count: number }>).detail.count;
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
      void fetchTrashItems();
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

  const handleFormSaved = useCallback(() => {
    setShowCreateDialog(false);
    void fetchItems();
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
        <h1 className="mb-4 text-2xl font-bold text-[hsl(var(--foreground))]">Vault</h1>
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
              />
            </ErrorBoundary>
          </div>
        </div>
      )}
    </>
  );
}
