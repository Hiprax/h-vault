import { useEffect, useRef, useState } from 'react';
import { DEFAULT_CUSTOM_FIELDS_LIMIT } from '@hvault/shared';
import { cachedCustomFieldsLimitValue, getCustomFieldsLimit } from '../services/api/configApi';

/**
 * The operator's custom-field limit, for the item editor.
 *
 * Starts from the value an earlier read cached, else the documented default, so the
 * editor never waits on a round trip to render. When the server's answer differs it
 * replaces the starting value; when it is the same, NOTHING is set. That second half
 * is load-bearing rather than tidy: React may still re-render for a `setState` with
 * an equal value, and a render that lands after a test has finished is the "update
 * outside act" failure this suite treats as an error.
 *
 * Mounted by the two pages that host the editor (`VaultPage`, `VaultItemPage`),
 * which hand the number to `VaultItemForm` as a prop, so the form itself issues no
 * request and stays a pure component.
 */
export function useCustomFieldsLimit(): number {
  const [limit, setLimit] = useState<number>(
    () => cachedCustomFieldsLimitValue() ?? DEFAULT_CUSTOM_FIELDS_LIMIT,
  );
  // The value this mount started from, compared before any `setState` (a ref, so the
  // read-once effect below needs no dependency on the state it may replace).
  const startedFrom = useRef(limit);

  useEffect(() => {
    let cancelled = false;
    void getCustomFieldsLimit().then((resolved) => {
      if (!cancelled && resolved !== startedFrom.current) setLimit(resolved);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return limit;
}
