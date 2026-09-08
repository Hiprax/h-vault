import { useEffect, useState } from 'react';
import { getDocumentsConfig, type DocumentsConfig } from '../services/api/configApi';

/**
 * What this server says about the document store, or `null` until it has said it.
 *
 * Three consumers ask the same question and each acts on a different part of the
 * answer: the sidebar needs only `enabled`, the Documents page needs the quota
 * numbers, and the upload panel needs the size cap and the extension allowlist.
 * They share one hook rather than three copies of the same effect, because three
 * copies is three places for the loading state to be handled differently — and
 * because {@link getDocumentsConfig} is memoised for the tab's lifetime, so the
 * question costs one round trip however many components ask it.
 *
 * `null` means "not answered yet", never "disabled". The distinction matters at
 * the only place it is visible: a navigation entry that appeared and then
 * vanished would be worse than one that appeared a beat late, so a consumer
 * renders the feature only for an explicit `enabled: true`.
 *
 * It cannot reject. `getDocumentsConfig` resolves to `{ enabled: false }` for an
 * older server, for an unconfigured one and for a failed request alike, and
 * caches that answer too, so a transient outage cannot re-hit the endpoint on
 * every render.
 *
 * That collapse is safe HERE and nowhere else: these three consumers decide only
 * what to show, and every number in the answer is advisory — the server enforces
 * its own size cap and extension list on ciphertext it cannot inspect. Anything
 * that ACTS on the answer reads `readDocumentsConfigFresh` instead, which is
 * uncached and reports "the server did not say" as its own third answer. A
 * successful call to it replaces the memo, so a mount after one gets the corrected
 * value; an already-mounted consumer keeps what it was given.
 */
export function useDocumentsConfig(): DocumentsConfig | null {
  const [config, setConfig] = useState<DocumentsConfig | null>(null);

  useEffect(() => {
    let cancelled = false;
    void getDocumentsConfig().then((resolved) => {
      if (!cancelled) setConfig(resolved);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return config;
}
