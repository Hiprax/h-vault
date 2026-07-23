/**
 * Client-side file-download helpers.
 *
 * The browser has no direct "save this data to a file" API; the portable idiom
 * is to wrap the bytes in a Blob, point a synthetic `<a download>` at an object
 * URL for it, click the anchor, and then revoke the URL. This one place owns
 * that dance so the four call sites (the File Encryption tool's encrypt/decrypt
 * panels, the Settings encrypted export, and the encrypted backup download) do
 * not each re-inline it — and so the revoke can never be forgotten.
 *
 * The object URL is revoked in a `finally`: `HTMLAnchorElement.click()` runs
 * synchronous listeners and can throw, and a leaked object URL pins its Blob in
 * memory until the document is discarded. Revoking in `finally` frees it on both
 * the success and the throw path.
 */

/**
 * Trigger a client-side download of `blob`, saved as `filename`.
 *
 * Nothing is uploaded; the bytes never leave the browser. The object URL is
 * always revoked, even if the anchor click throws.
 */
export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
  } finally {
    URL.revokeObjectURL(url);
  }
}

/**
 * Trigger a client-side download of `text` as `filename`, tagging the Blob with
 * `mimeType` (e.g. `'application/json'`, `'text/csv'`). Built on
 * {@link downloadBlob}, so it inherits the always-revoke guarantee.
 */
export function downloadText(text: string, filename: string, mimeType: string): void {
  downloadBlob(new Blob([text], { type: mimeType }), filename);
}
