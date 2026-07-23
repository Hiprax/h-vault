/**
 * Portable-export format registry and dispatcher.
 *
 * This is the single place that knows the set of plaintext export formats the
 * app offers (Bitwarden JSON, Bitwarden CSV, Chrome/Edge CSV), the user-facing
 * metadata for each (label, file extension, MIME type, and a one-line "what this
 * loses" note), and how to route a chosen format to its Phase 6/7 serializer.
 *
 * The three serializers all share ONE signature —
 * `(portable: readonly PortableItem[]) => { content: string; omittedCount: number }`
 * — so {@link serializePortableExport} composes them uniformly and only has to
 * attach the `filename`/`mimeType` drawn from the registry.
 *
 * Two compile-time guarantees hold here (PLAN Phase 8 acceptance):
 *
 * - **Every format has metadata.** {@link FORMAT_META} is a
 *   `Record<PortableExportFormat, …>`, so adding a member to the
 *   {@link PortableExportFormat} union without a metadata entry fails to compile.
 * - **Every format is serialized.** The dispatcher `switch` ends in a `never`
 *   default, so adding a member without a matching `case` fails to compile (the
 *   new value is no longer assignable to `never`).
 *
 * The registry array {@link PORTABLE_EXPORT_FORMATS} is derived from
 * {@link FORMAT_META}, so the two can never drift.
 */

import { toBitwardenJson } from './formats/bitwardenJson.js';
import { toBitwardenCsv } from './formats/bitwardenCsv.js';
import { toChromeCsv } from './formats/chromeCsv.js';
import type { PortableItem } from './portableItem.js';

/** The set of portable plaintext export formats the app offers. */
export type PortableExportFormat = 'bitwarden-json' | 'bitwarden-csv' | 'chrome-csv';

/** The file extensions a portable export can carry. */
export type PortableExportExtension = 'json' | 'csv';

/**
 * User-facing metadata for one export format: a display label, the file
 * extension and MIME type the download uses, and a single-line note stating
 * what that format cannot represent (surfaced verbatim on the export page).
 */
export interface PortableExportFormatMeta {
  value: PortableExportFormat;
  label: string;
  extension: PortableExportExtension;
  mimeType: string;
  /** One-line summary of what this format drops, shown next to the choice. */
  lossNote: string;
}

/**
 * The metadata source of truth, keyed by format. Being a
 * `Record<PortableExportFormat, …>`, it forces a metadata entry for every union
 * member at compile time. `value` is intentionally NOT stored here — it is the
 * key, and is re-attached when {@link PORTABLE_EXPORT_FORMATS} is built, so a
 * key and its own `value` can never disagree.
 */
const FORMAT_META: Record<PortableExportFormat, Omit<PortableExportFormatMeta, 'value'>> = {
  'bitwarden-json': {
    label: 'Bitwarden (.json)',
    extension: 'json',
    mimeType: 'application/json',
    lossNote:
      'Carries every item type. Folder paths re-import as tags, and some Bitwarden imports drop password history.',
  },
  'bitwarden-csv': {
    label: 'Bitwarden (.csv)',
    extension: 'csv',
    mimeType: 'text/csv',
    lossNote:
      'Logins and secure notes only — cards, identities and secrets are omitted. Folder paths re-import as tags.',
  },
  'chrome-csv': {
    label: 'Chrome / Edge (.csv)',
    extension: 'csv',
    mimeType: 'text/csv',
    lossNote:
      'Logins only — every other item type is omitted, and each login loses its TOTP secret, custom fields and folder.',
  },
};

/**
 * The ordered registry the export UI iterates: one entry per format, each with
 * its `value`, `label`, `extension`, `mimeType` and `lossNote`. Derived from
 * {@link FORMAT_META} so it can never fall out of step with the dispatcher.
 */
export const PORTABLE_EXPORT_FORMATS: readonly PortableExportFormatMeta[] = (
  Object.keys(FORMAT_META) as PortableExportFormat[]
).map((value) => ({ value, ...FORMAT_META[value] }));

/** The result of serializing the portable set for one chosen format. */
export interface SerializedPortableExport {
  /** The serialized file body (JSON or CSV text). */
  content: string;
  /** `hvault-export-YYYY-MM-DD.<ext>`, matching the app's export convention. */
  filename: string;
  mimeType: string;
  /** How many input items the chosen format could not represent (0 for JSON). */
  omittedCount: number;
}

/**
 * Serialize the normalized portable set for a chosen format, returning the file
 * body plus the download metadata (`filename`, `mimeType`) drawn from the
 * registry.
 *
 * @param format   One of {@link PortableExportFormat}.
 * @param portable The normalized items produced by `toPortableItems`.
 * @returns `{ content, filename, mimeType, omittedCount }`.
 * @throws If called (from untyped JS) with a format outside the union — the
 *   `never` default guards the runtime; the TypeScript `switch` is exhaustive.
 */
export function serializePortableExport(
  format: PortableExportFormat,
  portable: readonly PortableItem[],
): SerializedPortableExport {
  let result: { content: string; omittedCount: number };

  switch (format) {
    case 'bitwarden-json':
      result = toBitwardenJson(portable);
      break;
    case 'bitwarden-csv':
      result = toBitwardenCsv(portable);
      break;
    case 'chrome-csv':
      result = toChromeCsv(portable);
      break;
    default: {
      // Exhaustiveness guard: if a PortableExportFormat is ever added without a
      // matching `case` above, `format` is no longer assignable to `never` and
      // this line fails to compile. At runtime it also rejects a bad value
      // handed in from untyped JavaScript.
      const unreachable: never = format;
      throw new Error(`Unknown portable export format: ${String(unreachable)}`);
    }
  }

  const meta = FORMAT_META[format];
  // toISOString() is always `YYYY-MM-DDT…`; slice(0, 10) is the date, and yields
  // a plain `string` (no noUncheckedIndexedAccess narrowing to worry about).
  const datestamp = new Date().toISOString().slice(0, 10);

  return {
    content: result.content,
    filename: `hvault-export-${datestamp}.${meta.extension}`,
    mimeType: meta.mimeType,
    omittedCount: result.omittedCount,
  };
}
