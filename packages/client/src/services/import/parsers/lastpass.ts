import { rowsToRecords, toLowerKeyed, pick } from '../csv';
import { buildLogin, buildNote } from '../itemBuilders';
import type { ParsedImportItem } from '../types';

/**
 * LastPass CSV export.
 *
 * Columns: `url,username,password,totp,extra,name,grouping,fav`. LastPass encodes
 * secure notes as rows whose `url` is the sentinel `http://sn`; those become vault
 * notes (their body lives in `extra`). `grouping` (the folder path) is preserved
 * as a tag, and `fav === '1'` marks a favorite.
 *
 * Column audit: every LastPass export column is consumed (url, username, password,
 * totp, extra→notes, name, grouping→tag, fav→favorite). No column is discarded;
 * the `http://sn` sentinel is intentionally not stored as a URL — it is a
 * note-type marker, not a real address.
 */
export function parseLastpass(text: string): ParsedImportItem[] {
  const { records } = rowsToRecords(text);
  const items: ParsedImportItem[] = [];
  for (const rec of records) {
    const lc = toLowerKeyed(rec);
    const url = pick(lc, 'url');
    const username = pick(lc, 'username');
    const password = pick(lc, 'password');
    const totp = pick(lc, 'totp');
    const extra = pick(lc, 'extra');
    const name = pick(lc, 'name');
    const grouping = pick(lc, 'grouping');
    const favorite = pick(lc, 'fav') === '1';

    if (!url && !username && !password && !name && !extra) continue;

    const tags = grouping ? [lastSegment(grouping)] : [];

    if (url.toLowerCase() === 'http://sn') {
      items.push(buildNote({ name, content: extra, tags, favorite }));
      continue;
    }

    items.push(
      buildLogin({ name, urls: [url], username, password, totp, notes: extra, tags, favorite }),
    );
  }
  return items;
}

function lastSegment(group: string): string {
  const parts = group.split('\\').flatMap((p) => p.split('/'));
  return parts[parts.length - 1] ?? group;
}
