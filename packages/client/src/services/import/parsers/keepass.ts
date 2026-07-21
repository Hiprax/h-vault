import { rowsToRecords, toLowerKeyed, pick } from '../csv';
import { buildLogin } from '../itemBuilders';
import type { ParsedImportItem } from '../types';

/**
 * KeePass 2.x CSV export.
 *
 * Columns: `"Group","Title","Username","Password","URL","Notes"` (some exports
 * add a `TOTP` column). `Group` is a path like `Root/Internet`; its last segment
 * is preserved as a tag.
 */
export function parseKeepass(text: string): ParsedImportItem[] {
  const { records } = rowsToRecords(text);
  const items: ParsedImportItem[] = [];
  for (const rec of records) {
    const lc = toLowerKeyed(rec);
    const group = pick(lc, 'group');
    const name = pick(lc, 'title', 'name');
    const username = pick(lc, 'username', 'user name');
    const password = pick(lc, 'password');
    const url = pick(lc, 'url');
    const notes = pick(lc, 'notes');
    const totp = pick(lc, 'totp', 'otp');

    if (!name && !username && !password && !url && !notes) continue;

    const tags = group ? [lastSegment(group)] : [];
    items.push({ ...buildLogin({ name, urls: [url], username, password, totp, notes, tags }) });
  }
  return items;
}

function lastSegment(group: string): string {
  const parts = group.split('\\').flatMap((p) => p.split('/'));
  return parts[parts.length - 1]?.trim() ?? group;
}
