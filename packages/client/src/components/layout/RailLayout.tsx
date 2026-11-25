import { useState, type ReactNode } from 'react';
import { X, PanelLeftClose, PanelLeft } from 'lucide-react';
import { cn } from '../../lib/utils';

interface RailLayoutProps {
  /**
   * The rail itself, as a render prop so this layout owns the drawer state and
   * can hand the rail a way to close it after a selection.
   */
  rail: (close: () => void) => ReactNode;
  /**
   * What the bar above the pane holds after the rail's own control — the search
   * field, and on the documents route the trash controls beside it. The bar is
   * drawn at every width with or without it, because it always carries the
   * rail's control: the collapse toggle on a large screen, the drawer trigger on
   * a small one.
   */
  toolbar?: ReactNode;
  children: ReactNode;
}

/**
 * The two-pane shell shared by `/vault` and `/documents`.
 *
 * Extracted rather than copied, and that is not a style preference: this is
 * roughly forty-five contiguous lines of collapse toggle, mobile overlay, drawer
 * and pane, and a second copy would be a copy-paste clone the duplication gate
 * rejects — before it became two navigation shells drifting apart.
 */
export function RailLayout({ rail, toolbar, children }: RailLayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const closeMobileSidebar = (): void => setMobileSidebarOpen(false);
  // One string for the toggle's accessible name and its tooltip, so the two
  // cannot drift apart.
  const railToggleLabel = sidebarOpen ? 'Close sidebar' : 'Open sidebar';

  return (
    <div className="flex h-full -m-4 lg:-m-6">
      {/* Mobile sidebar overlay */}
      {mobileSidebarOpen && (
        <button
          type="button"
          className="fixed inset-0 z-30 bg-black/50 lg:hidden cursor-default"
          onClick={closeMobileSidebar}
          onKeyDown={(e) => {
            if (e.key === 'Escape') closeMobileSidebar();
          }}
          aria-label="Close sidebar"
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          'shrink-0 border-r border-[hsl(var(--border))] bg-[hsl(var(--card))] transition-all duration-200',
          sidebarOpen ? 'hidden w-64 lg:block' : 'hidden',
          mobileSidebarOpen && 'fixed inset-y-0 left-0 z-40 block w-64 lg:static lg:z-auto',
        )}
      >
        <div className="flex h-full flex-col">
          {/* Mobile close button */}
          <div className="flex items-center justify-between border-b border-[hsl(var(--border))] p-3 lg:hidden">
            <span className="text-sm font-semibold text-[hsl(var(--foreground))]">Navigation</span>
            <button
              type="button"
              onClick={closeMobileSidebar}
              className="rounded p-1 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]"
              aria-label="Close sidebar"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          {rail(closeMobileSidebar)}
        </div>
      </aside>

      {/* Main content */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Top bar — drawn at every width, because its first slot always holds
            the rail's control. */}
        <div className="flex items-center gap-3 border-b border-[hsl(var(--border))] p-4">
          {/* Desktop rail toggle, IN the bar's flow. It used to be `absolute`
              with no positioned ancestor, so it resolved against the viewport
              and sat hidden under the application sidebar: never visible and
              never clickable on a large screen, yet still a tab stop. */}
          <button
            type="button"
            onClick={() => setSidebarOpen((p) => !p)}
            className="hidden cursor-pointer rounded-md p-2 text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--foreground))] lg:inline-flex"
            aria-label={railToggleLabel}
            title={railToggleLabel}
          >
            {sidebarOpen ? (
              <PanelLeftClose className="h-4 w-4" />
            ) : (
              <PanelLeft className="h-4 w-4" />
            )}
          </button>

          {/* Mobile sidebar trigger */}
          <button
            type="button"
            onClick={() => setMobileSidebarOpen(true)}
            className="rounded-md p-2 text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--accent))] lg:hidden"
            aria-label="Open sidebar"
          >
            <PanelLeft className="h-4 w-4" />
          </button>
          {toolbar}
        </div>

        {/* The pane is the scroller on `/vault` and `/documents`, and
            `relative` so that it is also the containing block of the absolutely
            positioned elements inside it (the lists' `sr-only` live regions):
            otherwise they escape it and lengthen `<main>` or the document. */}
        <div className="relative flex-1 overflow-y-auto p-4 lg:p-6">{children}</div>
      </div>
    </div>
  );
}
