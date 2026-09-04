import type { DecryptedDocument } from '../stores/documentsStore';

/**
 * Whether a document matches what the reader typed.
 *
 * Deliberately NOT `lib/vaultSearch.ts`'s `valueMatches`. That walks an
 * arbitrary object to a bounded depth, which is right for a vault item — whose
 * `data` is a different shape per type and whose every field is the user's own
 * text — and wrong for a document, whose metadata carries its SHA-256 and its
 * byte counts, and whose row carries the stream salt and nonce prefix beside it.
 * A search that matched any of those would answer a query nobody typed on
 * purpose while burying the ones they did. The fields below are the ones a
 * person would search a filing cabinet by.
 *
 * `mime` is deliberately absent even though the detail view renders it as
 * "Type": it is machine vocabulary, and matching it makes a search for "text"
 * return every `text/plain`, `text/csv` and `text/markdown` document at once —
 * which buries the file actually called "text". The EXTENSION is searched
 * instead, because that is the part a person recognises and types.
 *
 * A degraded row matches nothing, and that is honest rather than convenient: its
 * name, tags and note are sealed under a key this vault could not unwrap, so
 * there is no text to match. The list says how many such rows exist, so they are
 * accounted for rather than silently missing.
 *
 * The query is expected pre-lowercased and pre-trimmed by the caller, once per
 * keystroke, rather than once per row.
 */
export function documentMatchesQuery(doc: DecryptedDocument, query: string): boolean {
  if (query === '') return true;
  const { meta } = doc;
  if (meta === null) return false;
  if (meta.name.toLowerCase().includes(query)) return true;
  if (meta.ext.toLowerCase().includes(query)) return true;
  if (meta.note?.toLowerCase().includes(query) === true) return true;
  return meta.tags.some((tag) => tag.toLowerCase().includes(query));
}
