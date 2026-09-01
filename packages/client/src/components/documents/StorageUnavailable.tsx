import { FileWarning } from 'lucide-react';

/**
 * What a user sees on a documents route when this server has no object storage
 * configured, or is older than the feature.
 *
 * Nothing is fetched in this state, deliberately. The endpoints answer 503 and,
 * because the error middleware redacts every 5xx body in production, that answer
 * carries no explanation at all — so the honest source for "this is unavailable"
 * is the public configuration the client already read, and probing for a
 * redacted refusal would produce a worse message and a wasted request.
 *
 * One component rather than one per route: the list and the detail view reach
 * this state through the same `GET /config` answer, and two copies of the
 * explanation is two places for it to stop being true.
 */
export function StorageUnavailable() {
  return (
    <div
      data-testid="documents-unavailable"
      className="mx-auto max-w-xl rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-6 text-center"
    >
      <FileWarning className="mx-auto h-8 w-8 text-[hsl(var(--muted-foreground))]" />
      <h1 className="mt-3 text-lg font-semibold text-[hsl(var(--foreground))]">
        Documents are not available on this server
      </h1>
      <p className="mt-1 text-sm text-[hsl(var(--muted-foreground))]">
        The document store needs object storage, which the operator of this server has not
        configured. Nothing else about your vault is affected.
      </p>
    </div>
  );
}
