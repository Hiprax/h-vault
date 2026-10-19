/**
 * The operator's custom-field limit, applied to an import.
 *
 * `CUSTOM_FIELDS_LIMIT` (advertised by `GET /config` as `vault.customFieldsLimit`)
 * is how many custom fields an entry may have. The item editor enforces it on
 * input; this module enforces it on every import, H-Vault's own export included,
 * BEFORE conflict resolution, so a row is matched as what will actually be written.
 *
 * A row over the limit keeps its first `limit` fields. Each text or boolean field
 * past them becomes a `name: value` line in the row's free text (`notes`, a note's
 * `content`, a secret's `description`), as far as that field's own bound allows. A
 * HIDDEN field past them is dropped and only its name is written: notes are shown
 * in the clear, and a hidden field is the custom-field equivalent of a password. A
 * field of a type this release does not know is treated as hidden.
 *
 * Nothing here ever reports a VALUE. Every report names fields, so the import can
 * say exactly what happened, before it writes and after.
 *
 * A row the limit leaves alone is returned as the SAME object, so a native row
 * keeps its stored data string and is sealed byte for byte. A row it cuts is a new
 * object with no `native` content: it is validated and serialised from its data
 * like any other source, which also drops a key this release does not know (only
 * possible in an export from a newer one).
 *
 * Pure: no store, no network, no key material.
 */

import { MAX_NOTE_CONTENT_LENGTH, MAX_SECRET_DESCRIPTION_LENGTH } from '@hvault/shared';
import type { ItemType } from '@hvault/shared';
import { hiddenFieldsNotImportedLine } from './itemBuilders';
import type { LimitMerge, ResolvableExistingItem, ResolvedUpdate } from './resolve';
import type { ResolvableImportItem } from './types';

/** Where each item type keeps its free text, and the stored bound of that text. */
const NOTES_FIELD: Record<ItemType, { key: string; max: number }> = {
  login: { key: 'notes', max: MAX_NOTE_CONTENT_LENGTH },
  card: { key: 'notes', max: MAX_NOTE_CONTENT_LENGTH },
  identity: { key: 'notes', max: MAX_NOTE_CONTENT_LENGTH },
  note: { key: 'content', max: MAX_NOTE_CONTENT_LENGTH },
  secret: { key: 'description', max: MAX_SECRET_DESCRIPTION_LENGTH },
};

/** The blank line the importer's notes join puts before each appended section. */
const SECTION_GAP = '\n\n';

/** What the limit, and the parser's own clamp before it, cut from one row. Names only. */
export interface LimitReport {
  /** The row's display name, as the file names it. */
  itemName: string;
  itemType: ItemType;
  /** Text and boolean fields whose value, or the part that did not fit, went into the notes. */
  movedToNotes: string[];
  /** Hidden fields dropped: their values are written nowhere. */
  hiddenDropped: string[];
  /** Text and boolean fields whose line did not fit in the notes, so not imported. */
  notWritten: string[];
}

/** One row after the limit, with the row it was cut from when it was cut. */
interface LimitedImportItem {
  item: ResolvableImportItem;
  untrimmed?: ResolvableImportItem;
  /** `null` when neither the limit nor the parser cut anything. */
  report: LimitReport | null;
}

interface Fold {
  /** The new free text, or `undefined` when nothing could be appended to it. */
  text: string | undefined;
  movedToNotes: string[];
  hiddenDropped: string[];
  notWritten: string[];
}

const NOTHING_CUT: Omit<Fold, 'text'> = { movedToNotes: [], hiddenDropped: [], notWritten: [] };

/**
 * Cut one row to `cap` custom fields.
 *
 * A row with `cap` fields or fewer is returned unchanged, as the same object; its
 * report carries only what the parser's clamp noticed, if anything. A cut row keeps
 * its name, type, tags, favourite, folder and previous passwords, and its original
 * comes back as `untrimmed` so resolution can still match the entry it came from.
 */
export function limitImportItem(item: ResolvableImportItem, cap: number): LimitedImportItem {
  const fields = fieldList(item.data);
  if (fields === undefined || fields.length <= cap) {
    return { item, report: item.importNotices ? reportFor(item, NOTHING_CUT) : null };
  }

  const { key, max } = NOTES_FIELD[item.itemType];
  const base = item.data[key];
  const fold = foldOverflow(typeof base === 'string' ? base : '', fields.slice(cap), cap, max);
  const data: Record<string, unknown> = { ...item.data, customFields: fields.slice(0, cap) };
  if (fold.text !== undefined) data[key] = fold.text;

  const cut: ResolvableImportItem = {
    itemType: item.itemType,
    name: item.name,
    data,
    tags: item.tags,
    favorite: item.favorite,
    ...(item.folderId !== undefined ? { folderId: item.folderId } : {}),
    ...(item.previousPasswords !== undefined ? { previousPasswords: item.previousPasswords } : {}),
  };
  return { item: cut, untrimmed: item, report: reportFor(item, fold) };
}

/** A whole import after the limit, with the lookups resolution and reporting need. */
interface LimitedImport {
  /** Every row, cut where the limit required it, in file order. */
  items: ResolvableImportItem[];
  /** The row a cut row was cut from: `resolveImport`'s `alternateOf`. */
  untrimmedOf: (item: ResolvableImportItem) => ResolvableImportItem | undefined;
  /** What was cut from a row of `items`, or `null` when nothing was. */
  reportOf: (item: ResolvableImportItem) => LimitReport | null;
}

/** {@link limitImportItem} over every row of an import. */
export function limitImportItems(
  items: readonly ResolvableImportItem[],
  cap: number,
): LimitedImport {
  const untrimmed = new Map<ResolvableImportItem, ResolvableImportItem>();
  const reports = new Map<ResolvableImportItem, LimitReport>();
  const limited = items.map((row) => {
    const result = limitImportItem(row, cap);
    if (result.untrimmed) untrimmed.set(result.item, result.untrimmed);
    if (result.report) reports.set(result.item, result.report);
    return result.item;
  });
  return {
    items: limited,
    untrimmedOf: (item) => untrimmed.get(item),
    reportOf: (item) => reports.get(item) ?? null,
  };
}

/**
 * Re-cut every `overwrite` update so the limit never SHRINKS a stored entry.
 *
 * Resolution matched each update as cut to `limit`. Before anything is written,
 * each one is cut again from the row it was cut from, at the larger of the limit
 * and the number of custom fields the stored entry already has: an entry saved
 * with 40 fields keeps 40 when the limit is 30. An overwrite still replaces the
 * entry's content wholesale, as it always has. Returns the updates to write and
 * the report of every one still cut, or carrying a cut the parser made.
 */
export function prepareLimitedUpdates<E extends ResolvableExistingItem>(
  updates: readonly ResolvedUpdate<ResolvableImportItem, E>[],
  limit: number,
  untrimmedOf: (item: ResolvableImportItem) => ResolvableImportItem | undefined,
): { updates: ResolvedUpdate<ResolvableImportItem, E>[]; reports: LimitReport[] } {
  const reports: LimitReport[] = [];
  const prepared = updates.map(({ incoming, existing }) => {
    const floor = Math.max(limit, fieldList(existing.data)?.length ?? 0);
    const result = limitImportItem(untrimmedOf(incoming) ?? incoming, floor);
    if (result.report) reports.push(result.report);
    return { incoming: result.item, existing };
  });
  return { updates: prepared, reports };
}

/** A list of field names, cut to a bound, with how many were left out. */
interface BoundedNames {
  names: string[];
  more: number;
}

/** One cut row, as the import report lists it. */
interface LimitSummaryEntry {
  itemName: string;
  itemType: ItemType;
  movedToNotes: BoundedNames;
  hiddenDropped: BoundedNames;
  notWritten: BoundedNames;
}

/** One row folded into another only because the cut made the two identical. */
interface LimitSummaryMerge {
  itemName: string;
  itemType: ItemType;
  /** The name of the row it was folded into. */
  keptName: string;
  /** What only this row held, past the cut. */
  hiddenDropped: BoundedNames;
  notWritten: BoundedNames;
}

/**
 * Everything the limit did to an import, for the confirmation and the report.
 * The counts cover every row; the lists stop at the bounds given.
 */
export interface LimitSummary {
  /** Rows written with fewer custom fields than the file held. */
  rowCount: number;
  movedToNotesCount: number;
  hiddenDroppedCount: number;
  notWrittenCount: number;
  /** Rows not written at all, because the cut made them identical to another. */
  mergedCount: number;
  entries: LimitSummaryEntry[];
  merged: LimitSummaryMerge[];
}

/**
 * Summarise the reports of the rows an import will write (each insert and each
 * update; a `null` is skipped), and the rows resolution merged because of the cut.
 */
export function summariseLimitReports(
  reports: readonly (LimitReport | null)[],
  options: {
    merges: readonly LimitMerge<ResolvableImportItem>[];
    reportOf: (item: ResolvableImportItem) => LimitReport | null;
    maxEntries: number;
    maxNames: number;
  },
): LimitSummary {
  const { merges, reportOf, maxEntries, maxNames } = options;
  const cut = reports.filter((report): report is LimitReport => report !== null);
  const total = (pick: (report: LimitReport) => string[]): number =>
    cut.reduce((sum, report) => sum + pick(report).length, 0);
  const bound = (names: readonly string[]): BoundedNames => ({
    names: names.slice(0, maxNames),
    more: Math.max(0, names.length - maxNames),
  });

  return {
    rowCount: cut.length,
    movedToNotesCount: total((report) => report.movedToNotes),
    hiddenDroppedCount: total((report) => report.hiddenDropped),
    notWrittenCount: total((report) => report.notWritten),
    mergedCount: merges.length,
    entries: cut.slice(0, maxEntries).map((report) => ({
      itemName: report.itemName,
      itemType: report.itemType,
      movedToNotes: bound(report.movedToNotes),
      hiddenDropped: bound(report.hiddenDropped),
      notWritten: bound(report.notWritten),
    })),
    merged: merges.slice(0, maxEntries).map(({ kept, absorbed }) => {
      const report = reportOf(absorbed);
      return {
        itemName: absorbed.name,
        itemType: absorbed.itemType,
        keptName: kept.name,
        hiddenDropped: bound(report?.hiddenDropped ?? []),
        notWritten: bound(report?.notWritten ?? []),
      };
    }),
  };
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/** A row's custom-field list, or `undefined` when its data carries none. */
function fieldList(data: Record<string, unknown>): readonly unknown[] | undefined {
  const fields: unknown = data.customFields;
  return Array.isArray(fields) ? (fields as unknown[]) : undefined;
}

/**
 * Write the fields past the cut into the free text, as one section of
 * `name: value` lines under a heading and a names-only line for the hidden ones,
 * joined to the trimmed text by a blank line exactly as the parsers' notes are.
 *
 * Each line is written only if it still fits `max`; one that does not is named in
 * `notWritten`, and the lines after it are still tried. The hidden-name line is a
 * marker rather than data, so it is written only when it fits too. When nothing is
 * appended the text is left exactly as it was, untrimmed.
 */
function foldOverflow(base: string, overflow: readonly unknown[], cap: number, max: number): Fold {
  const trimmed = base.trim();
  const heading = `Custom fields beyond the import limit of ${String(cap)}:`;
  const lines: string[] = [];
  const movedToNotes: string[] = [];
  const hiddenDropped: string[] = [];
  const notWritten: string[] = [];

  // The length the text would have with the heading and every line so far.
  let length = (trimmed ? trimmed.length + SECTION_GAP.length : 0) + heading.length;
  for (const entry of overflow) {
    const field = readField(entry);
    if (!field.plain) {
      hiddenDropped.push(field.name);
      continue;
    }
    const line = `${field.name}: ${field.value}`;
    if (length + 1 + line.length > max) {
      notWritten.push(field.name);
      continue;
    }
    lines.push(line);
    length += 1 + line.length;
    movedToNotes.push(field.name);
  }

  const compose = (sections: readonly string[]): string =>
    [trimmed, ...sections].filter(Boolean).join(SECTION_GAP);
  const sections = lines.length > 0 ? [[heading, ...lines].join('\n')] : [];
  if (hiddenDropped.length > 0) {
    const marker = hiddenFieldsNotImportedLine(hiddenDropped);
    if (compose([...sections, marker]).length <= max) sections.push(marker);
  }

  return {
    text: sections.length > 0 ? compose(sections) : undefined,
    movedToNotes,
    hiddenDropped,
    notWritten,
  };
}

/**
 * One field past the cut, read defensively: a native row's data is not validated
 * again before this runs. Only a field KNOWN to be text or boolean is `plain`; a
 * hidden one, a malformed one or a type this release does not know is treated as
 * a secret and never written out.
 */
function readField(entry: unknown): { name: string; value: string; plain: boolean } {
  const rec = typeof entry === 'object' && entry !== null ? (entry as Record<string, unknown>) : {};
  return {
    name: typeof rec.name === 'string' ? rec.name : '',
    value: typeof rec.value === 'string' ? rec.value : '',
    plain: rec.type === 'text' || rec.type === 'boolean',
  };
}

/** The report for a row: the parser's notice first, then what the limit cut. */
function reportFor(item: ResolvableImportItem, cut: Omit<Fold, 'text'>): LimitReport {
  const notice = item.importNotices;
  return {
    itemName: item.name,
    itemType: item.itemType,
    movedToNotes: [...(notice?.movedToNotes ?? []), ...cut.movedToNotes],
    hiddenDropped: [...(notice?.hiddenDropped ?? []), ...cut.hiddenDropped],
    notWritten: [...cut.notWritten],
  };
}
