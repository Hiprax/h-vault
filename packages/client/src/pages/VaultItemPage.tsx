import { useEffect, useRef, useState } from 'react';
import { useParams, Navigate, useNavigate } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
import { VaultItemDetail } from '../components/vault/VaultItemDetail';
import { VaultItemForm } from '../components/vault/VaultItemForm';
import { useVaultStore } from '../stores/vaultStore';

export default function VaultItemPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const items = useVaultStore((s) => s.items);
  const trashItems = useVaultStore((s) => s.trashItems);
  const loading = useVaultStore((s) => s.loading);
  const fetchItems = useVaultStore((s) => s.fetchItems);
  const fetchTrashItems = useVaultStore((s) => s.fetchTrashItems);
  const [editing, setEditing] = useState(false);
  const initialFetchDone = useRef(false);

  // If items haven't loaded yet, try to fetch (only once to avoid infinite loop on empty vaults)
  useEffect(() => {
    if (items.length === 0 && !loading && !initialFetchDone.current) {
      initialFetchDone.current = true;
      void fetchItems();
      void fetchTrashItems();
    }
  }, [items.length, loading, fetchItems, fetchTrashItems]);

  if (!id) return <Navigate to="/vault" replace />;

  // Search both regular and trash items
  const item = items.find((i) => i.id === id) ?? trashItems.find((i) => i.id === id);
  const isTrashed = trashItems.some((i) => i.id === id);

  // Still loading
  if (loading && !item) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-8 w-8 animate-spin text-[hsl(var(--primary))]" />
      </div>
    );
  }

  // Not found
  if (!item && !loading) {
    return (
      <div className="mx-auto max-w-md py-20 text-center">
        <h2 className="text-2xl font-bold text-[hsl(var(--foreground))]">Item Not Found</h2>
        <p className="mt-2 text-[hsl(var(--muted-foreground))]">
          The vault item you are looking for does not exist or has been deleted.
        </p>
        <button
          type="button"
          onClick={() => void navigate('/vault')}
          className="mt-4 rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity"
        >
          Back to Vault
        </button>
      </div>
    );
  }

  if (!item) return null;

  const handleFormSaved = () => {
    setEditing(false);
    void fetchItems();
  };

  // Don't allow editing trashed items
  if (editing && !isTrashed) {
    return (
      <div className="mx-auto max-w-2xl">
        <VaultItemForm item={item} onSaved={handleFormSaved} onCancel={() => setEditing(false)} />
      </div>
    );
  }

  return <VaultItemDetail item={item} onEdit={() => setEditing(true)} isTrashed={isTrashed} />;
}
