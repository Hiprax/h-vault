import { rowsToRecords, toLowerKeyed, pick } from '../csv';
import { buildLogin } from '../itemBuilders';
import type { ParsedImportItem } from '../types';

/**
 * Firefox password export (`Passwords.csv` from about:logins).
 *
 * Columns: `url,username,password,httpRealm,formActionOrigin,guid,timeCreated,
 * timeLastUsed,timePasswordChanged`. There is NO title column, so the display
 * name is derived from the URL host (see {@link buildLogin}).
 */
export function parseFirefox(text: string): ParsedImportItem[] {
  const { records } = rowsToRecords(text);
  const items: ParsedImportItem[] = [];
  for (const rec of records) {
    const lc = toLowerKeyed(rec);
    const url = pick(lc, 'url');
    const username = pick(lc, 'username');
    const password = pick(lc, 'password');
    if (!url && !username && !password) continue;
    items.push(buildLogin({ urls: [url], username, password }));
  }
  return items;
}
