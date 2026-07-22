import axios from 'axios';

/**
 * HIBP Pwned Passwords range-API helpers.
 *
 * Single source of the outbound fetch + padding-strip logic, shared by the
 * runtime cache layer (`toolsController.getRange`) and the bulk seed
 * (`utils/breachSeed`), so there is exactly ONE implementation of each.
 */

const HIBP_RANGE_URL = 'https://api.pwnedpasswords.com/range/';

/**
 * Remove `Add-Padding` dummy rows and blank/malformed lines from a range body,
 * re-joining the real rows with CRLF (HIBP's native line ending, so the client
 * parser sees exactly what an unpadded HIBP response would have contained).
 *
 * HIBP padding rows always carry `COUNT === 0` and must be discarded; a real
 * breached suffix always has a positive count. Counts are decimal with no
 * leading zeros, so "the portion after the last colon equals '0'" precisely
 * identifies a padding row (e.g. `...:10` and `...:100` are kept).
 */
export function stripPaddingRows(body: string): string {
  return body
    .split('\n')
    .map((line) => line.replace(/\r$/, ''))
    .filter((line) => {
      if (line.length === 0) return false;
      const colon = line.lastIndexOf(':');
      if (colon === -1) return false; // malformed line — drop defensively
      return line.slice(colon + 1) !== '0';
    })
    .join('\r\n');
}

/**
 * Fetch a single range from HIBP WITH padding (so an on-path observer cannot
 * infer the queried prefix from the response size) and return it stripped of
 * the count-0 padding rows.
 *
 * SSRF-hardened identically to the inline handler it replaces: `maxRedirects: 0`
 * and a bounded timeout. The caller is responsible for validating `prefix`
 * against the 5-hex-char format before calling.
 */
export async function fetchRangeFromHibp(prefix: string): Promise<string> {
  const response = await axios.get<string>(`${HIBP_RANGE_URL}${prefix}`, {
    headers: {
      'User-Agent': 'H-Vault-Password-Manager',
      'Add-Padding': 'true',
    },
    timeout: 10_000,
    responseType: 'text',
    maxRedirects: 0,
  });
  return stripPaddingRows(response.data);
}
