import {
  MAX_PREVIEW_TABLE_CELLS,
  MAX_PREVIEW_TABLE_COLUMNS,
  MAX_PREVIEW_TEXT_LINES,
} from '@hvault/shared';
import { el } from '../dom';

/**
 * Delimiter-separated data, parsed here and rendered as a table of TEXT NODES.
 *
 * ---------------------------------------------------------------------------
 * WHY OUR OWN PARSER
 * ---------------------------------------------------------------------------
 *
 * Not to avoid a dependency for its own sake. A CSV parser is thirty lines of
 * state machine, and the alternative is a third-party parser running over
 * attacker-supplied bytes — which is precisely the class of code this whole
 * isolated document exists to contain, and the cheapest place to simply not have
 * one. The grammar below is RFC 4180's: fields separated by the delimiter, a
 * quoted field may contain the delimiter, a newline and a doubled quote, and a
 * row ends at LF or CRLF.
 *
 * ---------------------------------------------------------------------------
 * THE ONE THING A SPREADSHEET DOES THAT THIS MUST NOT
 * ---------------------------------------------------------------------------
 *
 * A cell whose text begins `=`, `+`, `-` or `@` is a FORMULA to Excel, Numbers
 * and Sheets, and `=cmd|' /C calc'!A0` is the classic CSV-injection payload. It
 * is not a formula here and must never become one: every cell is a text node
 * inside a `<td>`, nothing evaluates it, and nothing re-serialises it. The cell
 * is shown EXACTLY as stored — not escaped, not prefixed with an apostrophe,
 * not stripped — because the reader is looking at this to find out what the file
 * contains, and silently altering a cell would be a worse answer than showing
 * it. The danger lives in the spreadsheet the file is opened in AFTER it is
 * downloaded, and that is a property of the file rather than of this preview.
 */

/** What a parse produced, and whether the reader is seeing all of it. */
export interface DelimitedTable {
  readonly rows: readonly (readonly string[])[];
  /** True when rows were cut, by the row cap or by the cell budget. */
  readonly truncated: boolean;
  /** How many rows the file actually has, counted even past the cap. */
  readonly totalRows: number;
  /**
   * The width the table RENDERS at: the widest kept row, and the number every
   * row is padded to. Bounded by {@link MAX_PREVIEW_TABLE_COLUMNS} and by the
   * cell budget, so `rows.length * columns` is a number a tab survives.
   */
  readonly columns: number;
  /**
   * True when the file is wider than the table: either a kept row lost fields
   * from its right-hand side, or a row wider than every kept one was counted and
   * dropped. Both mean the same thing to a reader — there are columns in this
   * file you are not being shown — which is what the notice says.
   */
  readonly columnsTruncated: boolean;
  /** How many columns the file's widest row actually has, counted past the cap. */
  readonly totalColumns: number;
}

/** The delimiter a given extension means. Anything else is not tabular. */
export function delimiterFor(ext: string): string | null {
  if (ext === 'csv') return ',';
  if (ext === 'tsv') return '\t';
  return null;
}

/**
 * Parse delimited text into rows of cells.
 *
 * ---------------------------------------------------------------------------
 * THE BUDGET IS CELLS, AND CELLS ARE ROWS TIMES COLUMNS
 * ---------------------------------------------------------------------------
 *
 * Three caps, and the reason there are three is that any one of them alone
 * leaves the tab killable by a file that is comfortably under
 * `MAX_PREVIEW_BYTES`:
 *
 *   * {@link MAX_PREVIEW_TEXT_LINES} bounds the rows. On its own it bounds
 *     nothing that matters, because the render pads every row out to the WIDEST
 *     one and a 25 MiB line of commas is twenty-six million columns.
 *   * {@link MAX_PREVIEW_TABLE_COLUMNS} bounds the width. Fields past it are
 *     counted and dropped as they are read, so the cap is on the array being
 *     built and not only on the tree built from it — a row of twenty-six million
 *     empty strings is a quarter of a gigabyte before a single element exists.
 *   * {@link MAX_PREVIEW_TABLE_CELLS} bounds the PRODUCT, which is the node
 *     count and therefore the thing that actually stops a tab. 50,000 rows at
 *     1,000 columns satisfies both of the other two and is fifty million cells.
 *
 * The invariant the render depends on is maintained here, on every row kept:
 * `rows.length * columns <= MAX_PREVIEW_TABLE_CELLS`. Because `columns` only
 * ever grows, the number of rows that fits only ever shrinks, and a row arriving
 * once the budget is spent is counted and dropped rather than causing earlier
 * rows to be thrown away — a reader who has the top of a file has the part of it
 * that reads in order.
 *
 * Everything cut is COUNTED, which is the point of counting: the notice names
 * the file's real height and real width instead of saying "some".
 *
 * A trailing newline does not create a final empty row, which is the difference
 * between "this file has 3 rows" and "this file has 4, one of them blank".
 */
export function parseDelimited(text: string, delimiter: string): DelimitedTable {
  const rows: string[][] = [];
  let totalRows = 0;
  let totalColumns = 0;
  // The widest KEPT row: the width the table renders at.
  let columns = 0;
  let row: string[] = [];
  // Fields seen in the current row, counted past the column cap so the notice
  // can name a width no row in `rows` carries.
  let rowFields = 0;
  let field = '';
  let quoted = false;
  let sawContent = false;

  const endField = (): void => {
    rowFields += 1;
    // Counted, then kept only while the row has room. The string was built
    // either way; what is bounded is the array, which is what the render walks.
    if (row.length < MAX_PREVIEW_TABLE_COLUMNS) row.push(field);
    field = '';
  };
  /**
   * Keep a finished row if, and only if, the cell budget still fits it at the
   * width it would force the table to.
   *
   * `width` is at least 1 — `endField` runs before every call and pushes
   * whenever the row is under the column cap, which an empty row always is — so
   * the division below is never by zero.
   */
  const keepRow = (candidate: string[]): void => {
    if (rows.length >= MAX_PREVIEW_TEXT_LINES) return;
    const width = Math.max(columns, candidate.length);
    if (rows.length >= Math.floor(MAX_PREVIEW_TABLE_CELLS / width)) return;
    columns = width;
    rows.push(candidate);
  };
  const endRow = (): void => {
    endField();
    totalRows += 1;
    totalColumns = Math.max(totalColumns, rowFields);
    keepRow(row);
    row = [];
    rowFields = 0;
    sawContent = false;
  };

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (character === undefined) break;
    sawContent = true;

    if (quoted) {
      if (character !== '"') {
        field += character;
        continue;
      }
      // A doubled quote inside a quoted field is one literal quote; a single one
      // closes the field.
      if (text[index + 1] === '"') {
        field += '"';
        index += 1;
        continue;
      }
      quoted = false;
      continue;
    }

    if (character === '"' && field === '') {
      quoted = true;
      continue;
    }
    if (character === delimiter) {
      endField();
      continue;
    }
    if (character === '\r') {
      // CRLF and a bare CR both end a row; the LF of a CRLF is consumed with it.
      if (text[index + 1] === '\n') index += 1;
      endRow();
      continue;
    }
    if (character === '\n') {
      endRow();
      continue;
    }
    field += character;
  }

  // A file that does not end in a newline still has a last row; one that does
  // must not gain an empty one.
  if (sawContent || field !== '' || row.length > 0) endRow();

  return {
    rows,
    truncated: totalRows > rows.length,
    totalRows,
    columns,
    columnsTruncated: totalColumns > columns,
    totalColumns,
  };
}

/**
 * Build the table.
 *
 * The first row becomes `<th>` in a `<thead>`, because a delimited file
 * essentially always has a header and a table without one is unreadable to a
 * screen reader. If the guess is wrong the reader loses nothing but a bold row —
 * whereas rendering every row as data loses the column names for everybody.
 *
 * Ragged rows are padded rather than dropped: a row with fewer cells than the
 * header is real data in a real file, and a table whose rows have different
 * lengths is what breaks column alignment. That padding is exactly why the width
 * is a budget rather than a formatting detail: every row costs `columns` cells
 * whatever it actually contains.
 *
 * The two clamps below re-apply {@link parseDelimited}'s invariant rather than
 * trusting it, and they are a no-op on everything that parser produces. The
 * point is where this function sits: it is the LAST place before the elements
 * exist, and it is called EAGERLY — `renderers/text.ts` builds the table on
 * FIRST render, not behind the view toggle — so a budget applied only during
 * parsing would be a budget a second caller could opt out of.
 *
 * The row budget is spent at the width the caller DECLARED, before that width is
 * clamped. For a parsed table the two are the same number. For one assembled by
 * hand they are not, and taking the declared width is the conservative reading:
 * a table that claims to be a hundred thousand columns wide buys one row, rather
 * than buying `MAX_PREVIEW_TABLE_CELLS / MAX_PREVIEW_TABLE_COLUMNS` of them at a
 * width it never had.
 */
export function renderTable(doc: Document, table: DelimitedTable): HTMLTableElement {
  const node = el(doc, 'table', 'hv-table');
  const columns = Math.min(table.columns, MAX_PREVIEW_TABLE_COLUMNS);
  // A width of zero prices a row at nothing, so the budget below would buy every
  // row in the array and each would render as an empty `<tr>` — a boundary that
  // answers a degenerate input with 250,000 elements is not defending anything.
  // `parseDelimited` never produces this shape, because a kept row always has at
  // least one field; a caller assembling the table itself can.
  if (columns === 0) return node;
  const rowBudget = Math.floor(MAX_PREVIEW_TABLE_CELLS / table.columns);

  const [header, ...body] = table.rows.slice(0, rowBudget);
  if (header) {
    const head = el(doc, 'thead');
    const headRow = el(doc, 'tr');
    for (let index = 0; index < columns; index += 1) {
      const cell = el(doc, 'th');
      cell.scope = 'col';
      cell.textContent = header[index] ?? '';
      headRow.append(cell);
    }
    head.append(headRow);
    node.append(head);
  }

  const tbody = el(doc, 'tbody');
  for (const row of body) {
    const tr = el(doc, 'tr');
    for (let index = 0; index < columns; index += 1) {
      const cell = el(doc, 'td');
      // `textContent`, and nothing else, ever. This is the line that makes a
      // formula-shaped cell a string.
      cell.textContent = row[index] ?? '';
      tr.append(cell);
    }
    tbody.append(tr);
  }
  node.append(tbody);
  return node;
}

/**
 * What a preview cut, as a phrase, or `null` when it cut nothing.
 *
 * Both dimensions, because either one alone is a lie in the case where both
 * happened: a reader told "the first 250 of 60,000 rows" about a file that was
 * ALSO cut from 26,000 columns to 1,000 has been told the truth about the wrong
 * half, and has no way to know the columns they can see are not all of them.
 *
 * The row count comes from `rows.length` rather than from
 * {@link MAX_PREVIEW_TEXT_LINES}: the cell budget cuts rows too, and past it the
 * number kept is smaller than the row cap. Naming the constant instead was
 * correct only while the row cap was the only thing that could cut a row.
 *
 * The sentence is finished by the caller, which owns the byte count and the
 * "download the file" half every truncation notice in the text renderer ends
 * with.
 */
export function describeTableTruncation(table: DelimitedTable): string | null {
  const cut: string[] = [];
  if (table.truncated) {
    cut.push(`the first ${String(table.rows.length)} of ${String(table.totalRows)} rows`);
  }
  if (table.columnsTruncated) {
    cut.push(`the first ${String(table.columns)} of ${String(table.totalColumns)} columns`);
  }
  if (cut.length === 0) return null;
  return `Showing ${cut.join(' and ')}`;
}
