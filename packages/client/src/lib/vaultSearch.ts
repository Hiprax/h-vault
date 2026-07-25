import type { ItemType } from '@hvault/shared';

const TYPE_LABELS: Record<ItemType, string> = {
  login: 'Login',
  note: 'Note',
  card: 'Card',
  identity: 'Identity',
  secret: 'Secret',
};

/**
 * Tests whether a vault item matches a search query.
 * Searches across the item name, tags, type label, and all decrypted data fields.
 */
export function itemMatchesSearch(
  item: {
    name: string;
    tags: string[];
    itemType: ItemType;
    data: Record<string, unknown>;
  },
  lowerQuery: string,
): boolean {
  // Search item name
  if (item.name.toLowerCase().includes(lowerQuery)) return true;

  // Search tags
  if (item.tags.some((tag) => tag.toLowerCase().includes(lowerQuery))) return true;

  // Search item type label
  if (TYPE_LABELS[item.itemType].toLowerCase().includes(lowerQuery)) return true;

  // Search through decrypted data fields. Every string is matched, including the
  // secret ones: a password has always been searchable here, and a login's backup
  // codes are too. That is deliberate and not an oversight — a match never RENDERS
  // the matched value (a row's label comes from `getItemSubtitle`, which allowlists
  // non-secret fields), so this only lets you find an item by a value you already
  // hold. Excluding one secret field and not the others would be an inconsistent
  // half-measure and the first exception in this function.
  for (const value of Object.values(item.data)) {
    if (typeof value === 'string' && value.toLowerCase().includes(lowerQuery)) return true;
    // Search arrays (e.g., URIs, custom fields)
    if (Array.isArray(value)) {
      for (const entry of value) {
        if (typeof entry === 'string' && entry.toLowerCase().includes(lowerQuery)) return true;
        if (typeof entry === 'object' && entry !== null) {
          for (const v of Object.values(entry as Record<string, unknown>)) {
            if (typeof v === 'string' && v.toLowerCase().includes(lowerQuery)) return true;
          }
        }
      }
    }
  }
  return false;
}
