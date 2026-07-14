import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { X, PanelLeftClose, PanelLeft } from 'lucide-react';
import { cn } from '../lib/utils';
import { useVaultStore } from '../stores/vaultStore';
import { SearchBar } from '../components/vault/SearchBar';
import { FolderSidebar } from '../components/vault/FolderSidebar';
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
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
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
    <div className="flex h-full -m-4 lg:-m-6">
      {/* Desktop sidebar toggle */}
      <button
        type="button"
        onClick={() => setSidebarOpen((p) => !p)}
        className="absolute left-2 top-2 z-10 hidden rounded-md p-1.5 text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--foreground))] lg:block"
        aria-label={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}
      >
        {sidebarOpen ? <PanelLeftClose className="h-4 w-4" /> : <PanelLeft className="h-4 w-4" />}
      </button>

      {/* Mobile sidebar overlay */}
      {mobileSidebarOpen && (
        <button
          type="button"
          className="fixed inset-0 z-30 bg-black/50 lg:hidden cursor-default"
          onClick={() => setMobileSidebarOpen(false)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') setMobileSidebarOpen(false);
          }}
          aria-label="Close sidebar"
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          'shrink-0 border-r border-[hsl(var(--border))] bg-[hsl(var(--card))] transition-all duration-200',
          sidebarOpen ? 'hidden w-64 lg:block' : 'hidden',
          mobileSidebarOpen && 'fixed inset-y-0 left-0 z-40 block w-64 lg:static lg:z-auto',
        )}
      >
        <div className="flex h-full flex-col">
          {/* Mobile close button */}
          <div className="flex items-center justify-between border-b border-[hsl(var(--border))] p-3 lg:hidden">
            <span className="text-sm font-semibold text-[hsl(var(--foreground))]">Navigation</span>
            <button
              type="button"
              onClick={() => setMobileSidebarOpen(false)}
              className="rounded p-1 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]"
              aria-label="Close sidebar"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          <FolderSidebar className="flex-1" onClose={() => setMobileSidebarOpen(false)} />
        </div>
      </aside>

      {/* Main content */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Top bar */}
        <div className="flex items-center gap-3 border-b border-[hsl(var(--border))] p-4">
          {/* Mobile sidebar trigger */}
          <button
            type="button"
            onClick={() => setMobileSidebarOpen(true)}
            className="rounded-md p-2 text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--accent))] lg:hidden"
            aria-label="Open sidebar"
          >
            <PanelLeft className="h-4 w-4" />
          </button>
          <SearchBar className="max-w-lg flex-1" />
        </div>

        {/* Items list */}
        <div className="flex-1 overflow-y-auto p-4 lg:p-6">
          <ErrorBoundary>
            <VaultList onCreateNew={handleCreateNew} />
          </ErrorBoundary>
        </div>
      </div>

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
    </div>
  );
}
