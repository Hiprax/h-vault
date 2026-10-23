/**
 * Fetches the code that builds the encrypted export file. Only an export needs
 * it, so it is a separate chunk loaded on the first export rather than part of
 * the Settings chunk, whose size budget can only ever come down.
 *
 * Fetching it is the FIRST wait of an export, ahead of the key derivation and
 * the request: the server records an export as completed once it has sent the
 * file, so a chunk that failed to load after that would leave an audit entry for
 * a file the owner never received. It lives in a module of its own so a test can
 * refuse the fetch.
 */
export function loadNativeExport() {
  return import('./nativeExport');
}
