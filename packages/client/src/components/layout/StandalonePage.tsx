import type { ReactNode } from 'react';
import { cn } from '../../lib/utils';

interface StandalonePageProps {
  children: ReactNode;
  /** Merged over the centred full-screen defaults (tailwind-merge resolves clashes). */
  className?: string;
}

/**
 * The `<main>` landmark of a screen that owns the whole viewport: the sign-in,
 * registration, password-reset, email-verification and account-unlock pages, the
 * vault's unlock screen, the 404 page, and the screens `ProtectedRoute` draws
 * while a session is being resumed.
 *
 * None of those render inside `AppLayout`, so none of them inherits its `<main>`,
 * and each used to be a bare centred `<div>`: a page with no main landmark and
 * every word of it outside any landmark at all (`landmark-one-main`, `region`).
 * One element fixes both, because on a screen like this the centred card IS the
 * main content — there is no chrome around it to put anywhere else.
 *
 * It must never be used inside `AppLayout`, which already has the page's one
 * `<main>`; a second would be a nested main landmark.
 */
export function StandalonePage({ children, className }: StandalonePageProps) {
  return (
    <main
      className={cn(
        'flex min-h-screen items-center justify-center bg-[hsl(var(--background))] px-4',
        className,
      )}
    >
      {children}
    </main>
  );
}
