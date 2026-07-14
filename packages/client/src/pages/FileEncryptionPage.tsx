/**
 * FileEncryptionPage — the standalone "File Encryption" tool page.
 *
 * A page shell (like {@link GeneratorPage}) hosting a two-tab view: an Encrypt
 * panel and a Decrypt panel. Both panels — and, transitively, the
 * `fileCryptoService` plus its `@hiprax/crypto` + `hash-wasm` dependencies — are
 * lazy-imported here so the (heavy) WASM Argon2id bundle stays out of the initial
 * app bundle and out of this page's own chunk until a panel first renders. Only
 * the active tab's panel is mounted at a time ({@link TabsContent} unmounts the
 * inactive one), so the Decrypt bundle isn't even fetched until that tab opens.
 *
 * The page itself touches no crypto and no account key material — it is a thin,
 * account-agnostic container. The zero-knowledge / no-upload guarantees live in
 * `fileCryptoService` and the panels.
 */

import { Suspense, lazy, useState } from 'react';
import { FileLock2, Loader2 } from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/Tabs';

// Lazy-load the panels so `@hiprax/crypto` + `hash-wasm` land in a dynamic chunk
// kept out of the initial bundle.
const FileEncryptPanel = lazy(() =>
  import('../components/tools/FileEncryptPanel').then((m) => ({ default: m.FileEncryptPanel })),
);
const FileDecryptPanel = lazy(() =>
  import('../components/tools/FileDecryptPanel').then((m) => ({ default: m.FileDecryptPanel })),
);

function PanelFallback() {
  return (
    <div className="flex items-center justify-center py-12" role="status" aria-label="Loading">
      <Loader2 className="h-6 w-6 animate-spin text-[hsl(var(--muted-foreground))]" />
    </div>
  );
}

export default function FileEncryptionPage() {
  const [tab, setTab] = useState('encrypt');

  return (
    <div className="mx-auto max-w-xl space-y-6">
      <div className="space-y-1">
        <h1 className="flex items-center gap-2 text-2xl font-bold text-[hsl(var(--foreground))]">
          <FileLock2 className="h-6 w-6" />
          File Encryption
        </h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">
          Encrypt any file with a password, entirely in your browser. Nothing is ever uploaded, and
          the file is never linked to your account — anyone with the password can decrypt it on any
          device.
        </p>
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="w-full">
          <TabsTrigger value="encrypt" className="flex-1">
            Encrypt
          </TabsTrigger>
          <TabsTrigger value="decrypt" className="flex-1">
            Decrypt
          </TabsTrigger>
        </TabsList>

        <TabsContent value="encrypt">
          <Suspense fallback={<PanelFallback />}>
            <FileEncryptPanel />
          </Suspense>
        </TabsContent>

        <TabsContent value="decrypt">
          <Suspense fallback={<PanelFallback />}>
            <FileDecryptPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </div>
  );
}
