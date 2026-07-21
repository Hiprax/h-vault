import { rowsToRecords, toLowerKeyed, pick } from '../csv';
import { buildLogin } from '../itemBuilders';
import type { ParsedImportItem } from '../types';

/**
 * Firefox password export (`Passwords.csv` from about:logins).
 *
 * Columns: `url,username,password,httpRealm,formActionOrigin,guid,timeCreated,
 * timeLastUsed,timePasswordChanged`. There is NO title column, so the display
 * name is derived from the URL host (see {@link buildLogin}).
 *
 * `httpRealm` is preserved into notes when present — it identifies an HTTP
 * Basic/Digest auth credential and its realm, which is user-meaningful and has no
 * dedicated vault field. The remaining columns are deliberately NOT imported:
 * `formActionOrigin` (a technical form-submission origin, redundant with the
 * preserved `url`), `guid` (a Firefox-internal identifier, meaningless outside
 * Firefox), and `timeCreated` / `timeLastUsed` / `timePasswordChanged` (internal
 * epoch timestamps with no vault field, which would clutter every imported row).
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
    const httpRealm = pick(lc, 'httprealm');
    const notes = httpRealm ? `HTTP realm: ${httpRealm}` : '';
    items.push(buildLogin({ urls: [url], username, password, notes }));
  }
  return items;
}
