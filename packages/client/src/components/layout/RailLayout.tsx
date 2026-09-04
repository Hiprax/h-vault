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
   * The bar above the pane — the search field, and on the documents route the
   * trash controls beside it. When absent the bar still renders on small screens
   * because it carries the drawer trigger, but it is hidden on desktop rather
   * than left as an empty bordered strip.
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

  return (
    <div className="flex h-full -m-4 lg:-m-6">
      {/* Desktop sidebar toggle */}
      <button
        type="button"
        onClick={() => setSidebarOpen((p) => !p)}
        className="absolute left-2 top-2 z-10 hidden rounded-md p-1.5 text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--foreground))] lg:block"
        aria-label={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}
      >
        {sidebarOpen ? <PanelLeftClose className="h-4 w-4" /> : <PanelLeft className="h-4 w-4" />}
      </button>

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
        {/* Top bar */}
        <div
          className={cn(
            'flex items-center gap-3 border-b border-[hsl(var(--border))] p-4',
            toolbar === undefined && 'lg:hidden',
          )}
        >
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

        <div className="flex-1 overflow-y-auto p-4 lg:p-6">{children}</div>
      </div>
    </div>
  );
}
