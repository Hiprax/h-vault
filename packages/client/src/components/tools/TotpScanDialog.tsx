import { useCallback, useState } from 'react';
import { TotpScanPanel } from './TotpScanPanel';
import { isMigrationUri } from '../../services/totpImport/migrationUri';
import { parseTotpValue } from '../../lib/totp';

/**
 * Scanning ONE code, for the TOTP field of an item being edited.
 *
 * The same panel the import tool uses, with a different destination: here the
 * decoded value goes straight into the field the user is filling in, and nothing
 * is held anywhere. `scanSession` is not involved at all, because there is no
 * list to keep and no key to hold beyond the moment it lands in the form.
 *
 * A full Google Authenticator EXPORT is refused here rather than silently taking
 * its first account. An export holds many codes and this field holds one, so
 * picking one for the user would be a guess with a wrong answer available; the
 * refusal names the tool that does handle it.
 */
export function TotpScanDialog({
  onScanned,
  onCancel,
}: {
  readonly onScanned: (value: string) => void;
  readonly onCancel: () => void;
}) {
  const [status, setStatus] = useState<string | null>(null);

  const handleDecoded = useCallback(
    (text: string) => {
      if (isMigrationUri(text)) {
        setStatus(
          'That is a full Google Authenticator export, which holds several codes. Use Import from Authenticator for it.',
        );
        return;
      }
      const parsed = parseTotpValue(text);
      if (!parsed.ok) {
        setStatus('That code is not an authenticator code this app can read.');
        return;
      }
      onScanned(text);
    },
    [onScanned],
  );

  return (
    <div className="space-y-4">
      <TotpScanPanel onDecoded={handleDecoded} onError={setStatus} status={status} />
      <div className="flex justify-end">
        <button
          type="button"
          onClick={onCancel}
          className="rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
