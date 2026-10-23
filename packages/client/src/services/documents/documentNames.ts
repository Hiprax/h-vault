/**
 * What the list calls a row whose sealed metadata would not open.
 *
 * THE definition, read by `components/documents/DocumentList.tsx`, by
 * `DocumentDetail.tsx` (a degraded row's heading) and by the bulk archive's
 * failure summary (`downloadAll.ts`) rather than each repeating the words. A
 * failure summary has to name a document exactly as the list beside it does, or
 * the reader cannot tell which of the rows in front of them the reason belongs
 * to — and a degraded row has no other name to be identified by, because the
 * only copy of its name is inside the blob that would not open.
 *
 * A module of its own so the single-document chunk that imports it never pulls
 * in the archive writer beside it.
 */
export const UNOPENABLE_DOCUMENT_NAME = 'Unopenable document';
