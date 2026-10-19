/**
 * Fetches the code that applies the custom-field limit to an import. Only an
 * import needs it, so it is a separate chunk loaded on the first import rather
 * than part of the Settings chunk, whose size budget can only ever come down.
 *
 * Fetching it is a WAIT, and the import must finish every wait before it takes
 * its snapshot of the vault (a lock during a later one empties that snapshot), so
 * it lives in a module of its own, where a test can hold the fetch open.
 */
export function loadCustomFieldsLimit() {
  return import('./customFieldsLimit');
}
