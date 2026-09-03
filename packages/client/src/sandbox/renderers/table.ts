import { MAX_PREVIEW_TEXT_LINES } from '@hvault/shared';
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
  /** True when the file had more rows than {@link MAX_PREVIEW_TEXT_LINES}. */
  readonly truncated: boolean;
  /** How many rows the file actually has, counted even past the cap. */
  readonly totalRows: number;
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
 * Rows past {@link MAX_PREVIEW_TEXT_LINES} are COUNTED but not kept: the cap is
 * a DOM-node budget (one `<td>` per cell), and a ten-million-row export would
 * otherwise stop the tab rather than show a table. The count is kept so the
 * notice can say how much is missing instead of "some".
 *
 * A trailing newline does not create a final empty row, which is the difference
 * between "this file has 3 rows" and "this file has 4, one of them blank".
 */
export function parseDelimited(text: string, delimiter: string): DelimitedTable {
  const rows: string[][] = [];
  let totalRows = 0;
  let row: string[] = [];
  let field = '';
  let quoted = false;
  let sawContent = false;

  const endField = (): void => {
    row.push(field);
    field = '';
  };
  const endRow = (): void => {
    endField();
    totalRows += 1;
    // Kept only while there is room. `totalRows` still advances, so the notice
    // can name the real size.
    if (rows.length < MAX_PREVIEW_TEXT_LINES) rows.push(row);
    row = [];
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

  return { rows, truncated: totalRows > rows.length, totalRows };
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
 * lengths is what breaks column alignment.
 */
export function renderTable(doc: Document, table: DelimitedTable): HTMLTableElement {
  const node = el(doc, 'table', 'hv-table');
  const columns = table.rows.reduce((widest, row) => Math.max(widest, row.length), 0);

  const [header, ...body] = table.rows;
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
