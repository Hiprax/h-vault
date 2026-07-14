import {
  createContext,
  forwardRef,
  useCallback,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type HTMLAttributes,
  type KeyboardEvent,
  type ReactNode,
} from 'react';
import { cn } from '../../lib/utils';

/* -------------------------------------------------------------------------- */
/*  Context                                                                   */
/* -------------------------------------------------------------------------- */

interface DropdownMenuContextValue {
  open: boolean;
  setOpen: (open: boolean) => void;
  triggerRef: React.RefObject<HTMLButtonElement | null>;
  activeDescendantId: string;
  setActiveDescendantId: (id: string) => void;
}

const DropdownMenuContext = createContext<DropdownMenuContextValue | null>(null);

function useDropdownContext(): DropdownMenuContextValue {
  const ctx = useContext(DropdownMenuContext);
  if (!ctx) {
    throw new Error('DropdownMenu compound components must be used within a <DropdownMenu> parent');
  }
  return ctx;
}

/* -------------------------------------------------------------------------- */
/*  DropdownMenu (root)                                                       */
/* -------------------------------------------------------------------------- */

interface DropdownMenuProps {
  children: ReactNode;
}

function DropdownMenu({ children }: DropdownMenuProps) {
  const [open, setOpen] = useState(false);
  const [activeDescendantId, setActiveDescendantId] = useState('');
  const triggerRef = useRef<HTMLButtonElement | null>(null);

  // Clear active descendant when menu closes
  const handleSetOpen = useCallback((value: boolean) => {
    setOpen(value);
    if (!value) {
      setActiveDescendantId('');
    }
  }, []);

  return (
    <DropdownMenuContext.Provider
      value={{
        open,
        setOpen: handleSetOpen,
        triggerRef,
        activeDescendantId,
        setActiveDescendantId,
      }}
    >
      <div className="relative inline-block text-left">{children}</div>
    </DropdownMenuContext.Provider>
  );
}

/* -------------------------------------------------------------------------- */
/*  DropdownMenuTrigger                                                       */
/* -------------------------------------------------------------------------- */

const DropdownMenuTrigger = forwardRef<HTMLButtonElement, ButtonHTMLAttributes<HTMLButtonElement>>(
  ({ className, onClick, ...props }, ref) => {
    const { open, setOpen, triggerRef } = useDropdownContext();

    const handleRef = useCallback(
      (node: HTMLButtonElement | null) => {
        triggerRef.current = node;
        if (typeof ref === 'function') {
          ref(node);
        } else if (ref) {
          ref.current = node;
        }
      },
      [ref, triggerRef],
    );

    return (
      <button
        ref={handleRef}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={(e) => {
          setOpen(!open);
          onClick?.(e);
        }}
        className={cn('inline-flex items-center', className)}
        {...props}
      />
    );
  },
);
DropdownMenuTrigger.displayName = 'DropdownMenuTrigger';

/* -------------------------------------------------------------------------- */
/*  DropdownMenuContent                                                       */
/* -------------------------------------------------------------------------- */

interface DropdownMenuContentProps extends HTMLAttributes<HTMLDivElement> {
  align?: 'start' | 'end';
}

const DropdownMenuContent = forwardRef<HTMLDivElement, DropdownMenuContentProps>(
  ({ className, align = 'end', children, ...props }, ref) => {
    const { open, setOpen, triggerRef, activeDescendantId, setActiveDescendantId } =
      useDropdownContext();
    const contentRef = useRef<HTMLDivElement | null>(null);

    const handleRef = useCallback(
      (node: HTMLDivElement | null) => {
        contentRef.current = node;
        if (typeof ref === 'function') {
          ref(node);
        } else if (ref) {
          ref.current = node;
        }
      },
      [ref],
    );

    // Close on click outside
    useEffect(() => {
      if (!open) return;

      const handleClickOutside = (e: MouseEvent) => {
        const target = e.target as Node;
        if (
          contentRef.current &&
          !contentRef.current.contains(target) &&
          triggerRef.current &&
          !triggerRef.current.contains(target)
        ) {
          setOpen(false);
        }
      };

      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }, [open, setOpen, triggerRef]);

    // Close on Escape
    useEffect(() => {
      if (!open) return;

      const handleEscape = (e: globalThis.KeyboardEvent) => {
        if (e.key === 'Escape') {
          setOpen(false);
          triggerRef.current?.focus();
        }
      };

      document.addEventListener('keydown', handleEscape);
      return () => document.removeEventListener('keydown', handleEscape);
    }, [open, setOpen, triggerRef]);

    // Move focus into the menu on open (WCAG 2.1.1). The trigger and content are
    // siblings, so the browser leaves focus on the trigger after activation —
    // and `handleKeyDown` drives navigation from whichever menuitem currently
    // holds focus. Focusing the first enabled item makes the menu keyboard
    // operable and also seeds `aria-activedescendant` via the item's onFocus.
    useEffect(() => {
      if (!open) return;
      const firstItem = contentRef.current?.querySelector<HTMLElement>(
        '[role="menuitem"]:not([disabled]):not([aria-disabled="true"])',
      );
      firstItem?.focus();
    }, [open]);

    // Keyboard navigation inside the menu
    const handleKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
      const items = contentRef.current?.querySelectorAll<HTMLElement>(
        '[role="menuitem"]:not([disabled]):not([aria-disabled="true"])',
      );
      if (!items || items.length === 0) return;

      const activeElement = document.activeElement as HTMLElement;
      const currentIndex = Array.from(items).indexOf(activeElement);

      let nextItem: HTMLElement | undefined;

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        const next = currentIndex < items.length - 1 ? currentIndex + 1 : 0;
        nextItem = items[next];
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        const prev = currentIndex > 0 ? currentIndex - 1 : items.length - 1;
        nextItem = items[prev];
      } else if (e.key === 'Home') {
        e.preventDefault();
        nextItem = items[0];
      } else if (e.key === 'End') {
        e.preventDefault();
        nextItem = items[items.length - 1];
      }

      if (nextItem) {
        nextItem.focus();
        setActiveDescendantId(nextItem.id);
      }
    };

    if (!open) return null;

    return (
      <div
        ref={handleRef}
        role="menu"
        aria-orientation="vertical"
        aria-activedescendant={activeDescendantId || undefined}
        onKeyDown={handleKeyDown}
        className={cn(
          'absolute z-50 mt-2 min-w-[8rem] overflow-hidden rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--popover))] p-1 text-[hsl(var(--popover-foreground))] shadow-md',
          align === 'end' ? 'right-0' : 'left-0',
          className,
        )}
        {...props}
      >
        {children}
      </div>
    );
  },
);
DropdownMenuContent.displayName = 'DropdownMenuContent';

/* -------------------------------------------------------------------------- */
/*  DropdownMenuItem                                                          */
/* -------------------------------------------------------------------------- */

interface DropdownMenuItemProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  inset?: boolean;
}

const DropdownMenuItem = forwardRef<HTMLButtonElement, DropdownMenuItemProps>(
  ({ className, inset, onClick, onFocus, ...props }, ref) => {
    const { setOpen, setActiveDescendantId } = useDropdownContext();
    const itemId = useId();

    const handleFocus = useCallback(
      (e: React.FocusEvent<HTMLButtonElement>) => {
        setActiveDescendantId(itemId);
        onFocus?.(e);
      },
      [itemId, setActiveDescendantId, onFocus],
    );

    return (
      <button
        ref={ref}
        id={itemId}
        role="menuitem"
        type="button"
        tabIndex={-1}
        onFocus={handleFocus}
        onClick={(e) => {
          onClick?.(e);
          setOpen(false);
        }}
        className={cn(
          'relative flex w-full cursor-default select-none items-center rounded-sm px-2 py-1.5 text-sm outline-none transition-colors hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--accent-foreground))] focus:bg-[hsl(var(--accent))] focus:text-[hsl(var(--accent-foreground))] disabled:pointer-events-none disabled:opacity-50',
          inset && 'pl-8',
          className,
        )}
        {...props}
      />
    );
  },
);
DropdownMenuItem.displayName = 'DropdownMenuItem';

/* -------------------------------------------------------------------------- */
/*  DropdownMenuSeparator                                                     */
/* -------------------------------------------------------------------------- */

const DropdownMenuSeparator = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      role="separator"
      className={cn('-mx-1 my-1 h-px bg-[hsl(var(--border))]', className)}
      {...props}
    />
  ),
);
DropdownMenuSeparator.displayName = 'DropdownMenuSeparator';

export {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
};
