/**
 * A correct RFC-4180 CSV tokenizer.
 *
 * Unlike a naive `text.split('\n').map(line => line.split(','))`, this handles
 * fields that are quoted and themselves contain commas, embedded newlines, and
 * escaped quotes (`""`). It also strips a leading UTF-8 BOM, tolerates both LF
 * and CRLF line endings, and drops blank lines.
 *
 * Field values are returned VERBATIM (no trimming) so passwords that legitimately
 * contain leading/trailing whitespace survive the round-trip. Header matching
 * trims separately (see {@link rowsToRecords}).
 */
export function parseCsv(text: string): string[][] {
  // Strip a leading UTF-8 BOM if present.
  const input = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;

  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;
  let sawAnyChar = false;

  const endField = (): void => {
    row.push(field);
    field = '';
  };
  const endRow = (): void => {
    endField();
    // Drop blank lines: a row that is a single empty field with no other content.
    if (!(row.length === 1 && row[0] === '')) {
      rows.push(row);
    }
    row = [];
  };

  for (let i = 0; i < input.length; i++) {
    const ch = input[i] ?? '';
    sawAnyChar = true;

    if (inQuotes) {
      if (ch === '"') {
        if (input[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
      continue;
    }

    if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      endField();
    } else if (ch === '\r') {
      // Swallow the paired \n of a CRLF sequence.
      if (input[i + 1] === '\n') i++;
      endRow();
    } else if (ch === '\n') {
      endRow();
    } else {
      field += ch;
    }
  }

  // Flush the final field/row if the input did not end with a newline.
  if (sawAnyChar && (field !== '' || row.length > 0)) {
    endRow();
  }

  return rows;
}

/**
 * Parse CSV into header-keyed records.
 *
 * Headers are trimmed for stable matching. Ragged rows are tolerated: missing
 * trailing cells become `''`; cells beyond the header count are ignored.
 * Returns the (trimmed) header list alongside the records.
 */
export function rowsToRecords(text: string): {
  headers: string[];
  records: Record<string, string>[];
} {
  const rows = parseCsv(text);
  if (rows.length === 0) return { headers: [], records: [] };

  const headers = (rows[0] ?? []).map((h) => h.trim());
  const records: Record<string, string>[] = [];

  for (let r = 1; r < rows.length; r++) {
    const cells = rows[r] ?? [];
    const record: Record<string, string> = {};
    for (let c = 0; c < headers.length; c++) {
      const key = headers[c] ?? '';
      if (key === '') continue;
      record[key] = cells[c] ?? '';
    }
    records.push(record);
  }

  return { headers, records };
}

/** Return a copy of a record with all keys lower-cased, for case-insensitive lookup. */
export function toLowerKeyed(record: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(record)) out[k.toLowerCase()] = v;
  return out;
}

/**
 * First non-empty value among the given (case-insensitive) column names.
 * `lc` must be a lower-keyed record (see {@link toLowerKeyed}); `names` are
 * matched lower-cased.
 */
export function pick(lc: Record<string, string>, ...names: string[]): string {
  for (const n of names) {
    const v = lc[n.toLowerCase()];
    if (typeof v === 'string' && v.trim()) return v;
  }
  return '';
}
