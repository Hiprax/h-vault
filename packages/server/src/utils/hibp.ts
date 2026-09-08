import axios from 'axios';
import { HIBP_MAX_RANGE_RESPONSE_BYTES } from '../constants/index.js';

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
 *
 * The response is also SIZE-bounded. This is the server's only outbound HTTP
 * call, its whole body is buffered into a string before anything inspects it,
 * and the batch endpoint runs `HIBP_FANOUT_CONCURRENCY` of them at once — so an
 * anomalous or hostile upstream body is a memory-exhaustion vector against a
 * container with a 1g limit. `axios` defaults both length limits to `-1` and
 * only enforces a limit that is `> -1`, so the bound has to be given
 * explicitly; once given, the Node adapter checks it incrementally on the
 * response stream and destroys the socket on the chunk that crosses it, which
 * is what makes it a real bound rather than an after-the-fact complaint.
 *
 * Exceeding it REJECTS (`ERR_BAD_RESPONSE`). That is deliberate and is the
 * whole point: `getRange`'s caller turns the rejection into a 5xx (measured:
 * 502, because a real `AxiosError` carrying no `.response` maps to "Error
 * communicating with an external service") or an `errors[]` entry on the batch
 * endpoint, so an unreadable upstream can never be mistaken for "this password
 * appears in no breach".
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
    maxContentLength: HIBP_MAX_RANGE_RESPONSE_BYTES,
    // Bounds the REQUEST body, which this GET does not send — so it does no
    // work today. Do not delete it on that basis: axios enforces it itself (a
    // buffered body is checked before dispatch, a streamed one through its own
    // byte-counting pipeline on native transports), so the bound is already in
    // place for any future caller that gives this helper a body.
    maxBodyLength: HIBP_MAX_RANGE_RESPONSE_BYTES,
  });
  return stripPaddingRows(response.data);
}
