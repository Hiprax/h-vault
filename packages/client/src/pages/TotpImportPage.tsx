import { Suspense, lazy, useState } from 'react';
import { ScanLine, Loader2 } from 'lucide-react';

const TotpImportFlow = lazy(() =>
  import('../components/tools/TotpImportFlow').then((m) => ({ default: m.TotpImportFlow })),
);

/**
 * The "Import from Authenticator" tool page.
 *
 * A shell, like `GeneratorPage` and `FileEncryptionPage`: the flow underneath it
 * is lazy so that the QR scanner's driver, the camera module and the migration
 * reader stay out of the initial payload for the many people who never open it.
 */
function FlowFallback() {
  return (
    <div className="flex items-center justify-center py-12" role="status" aria-label="Loading">
      <Loader2 className="h-6 w-6 animate-spin text-[hsl(var(--muted-foreground))]" />
    </div>
  );
}

export default function TotpImportPage() {
  // Remounting the flow is how "Start over" throws away every decoded key: the
  // unmount is what tears the scan session down.
  const [generation, setGeneration] = useState(0);

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div className="space-y-1">
        <h1 className="flex items-center gap-2 text-2xl font-bold text-[hsl(var(--foreground))]">
          <ScanLine className="h-6 w-6" />
          Import from Authenticator
        </h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">
          Read the codes out of Google Authenticator with your camera, then decide yourself where
          each one belongs. Nothing is attached to a login automatically.
        </p>
      </div>

      <Suspense fallback={<FlowFallback />}>
        <TotpImportFlow key={generation} onStartOver={() => setGeneration((value) => value + 1)} />
      </Suspense>
    </div>
  );
}
