import { rowsToRecords, toLowerKeyed, pick } from '../csv';
import { buildLogin } from '../itemBuilders';
import type { ParsedImportItem } from '../types';

/**
 * Chrome / Edge password export (`Passwords.csv`).
 *
 * Columns: `name,url,username,password,note`. `name` is usually the site host.
 */
export function parseChrome(text: string): ParsedImportItem[] {
  const { records } = rowsToRecords(text);
  const items: ParsedImportItem[] = [];
  for (const rec of records) {
    const lc = toLowerKeyed(rec);
    const name = pick(lc, 'name');
    const url = pick(lc, 'url');
    const username = pick(lc, 'username');
    const password = pick(lc, 'password');
    const notes = pick(lc, 'note', 'notes');
    if (!name && !url && !username && !password) continue;
    items.push(buildLogin({ name, urls: [url], username, password, notes }));
  }
  return items;
}
