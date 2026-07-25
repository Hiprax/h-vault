import { parseBackupCodes } from '@hvault/shared';
import { rowsToRecords, toLowerKeyed } from '../csv';
import { buildLogin } from '../itemBuilders';
import type { CsvFieldMapping, ParsedImportItem } from '../types';

/**
 * Generic CSV import driven by a user-supplied column mapping.
 *
 * `mapping` maps a source column header to one of the friendly targets
 * `name | username | password | url | notes | totp | backupCodes | folder` (a `''`
 * target skips the column). Multiple columns may map to `url` (collected into the
 * URI list); every other target takes the first non-empty column. `folder` becomes
 * a tag. Rows with no mapped content are skipped. Every row is imported as a
 * login.
 *
 * A `backupCodes` cell holds however many codes the source packed into it, so it
 * runs through the shared `parseBackupCodes` in auto-detect mode — the same
 * definition of a valid code the item form uses. A cell the parser rejects
 * contributes nothing rather than storing junk in a security-critical list.
 */
/**
 * The only mapping targets the parser honours. A target outside this set (e.g. a
 * tampered `__proto__`) is ignored — defense-in-depth behind the UI dropdown,
 * which already offers only these values.
 */
const ALLOWED_TARGETS = new Set([
  'name',
  'username',
  'password',
  'url',
  'notes',
  'totp',
  'backupCodes',
  'folder',
]);

export function parseGenericCsv(text: string, mapping: CsvFieldMapping): ParsedImportItem[] {
  const { records } = rowsToRecords(text);
  const items: ParsedImportItem[] = [];

  for (const rec of records) {
    const lc = toLowerKeyed(rec);
    const urls: string[] = [];
    const single: Record<string, string> = {};

    for (const [header, target] of Object.entries(mapping)) {
      if (!target || !ALLOWED_TARGETS.has(target)) continue;
      // A column literally named `__proto__` resolves to Object.prototype rather
      // than a cell value (the `??` guard does not fire — it is an object, not
      // nullish). Nothing is polluted, but calling a string method on it would
      // throw and abort the whole file with a misleading "unparseable" error, so
      // require an actual string.
      const value = lc[header.trim().toLowerCase()];
      if (typeof value !== 'string' || !value.trim()) continue;
      if (target === 'url') urls.push(value);
      else single[target] ??= value;
    }

    if (urls.length === 0 && Object.keys(single).length === 0) continue;

    const folder = single.folder ?? '';
    const rawCodes = single.backupCodes ?? '';
    const parsedCodes = rawCodes === '' ? null : parseBackupCodes(rawCodes);
    // A cell that is not a list of codes contributes none, but it is REPORTED
    // rather than dropped in silence: an import that says it succeeded while
    // quietly discarding every recovery code is the worst outcome here. The note
    // is a fixed sentence with no cell content in it, so it is safe everywhere
    // notes travel — including the Chrome CSV `note` column.
    const unreadableCodes =
      parsedCodes !== null && !parsedCodes.ok
        ? 'A backup-codes column was present but could not be read as a list of codes, so no codes were imported for this item.'
        : '';
    const baseNotes = single.notes ?? '';
    items.push(
      buildLogin({
        name: single.name ?? '',
        username: single.username ?? '',
        password: single.password ?? '',
        urls,
        totp: single.totp ?? '',
        backupCodes: parsedCodes?.ok === true ? parsedCodes.codes : [],
        notes: [baseNotes, unreadableCodes].filter(Boolean).join('\n\n'),
        tags: folder ? [folder] : [],
      }),
    );
  }

  return items;
}
