import {
  createContext,
  forwardRef,
  useCallback,
  useContext,
  useRef,
  type HTMLAttributes,
  type ButtonHTMLAttributes,
  type KeyboardEvent,
} from 'react';
import { cn } from '../../lib/utils';

/* -------------------------------------------------------------------------- */
/*  Context                                                                   */
/* -------------------------------------------------------------------------- */

interface TabsContextValue {
  value: string;
  onValueChange: (value: string) => void;
}

const TabsContext = createContext<TabsContextValue | null>(null);

function useTabsContext(): TabsContextValue {
  const ctx = useContext(TabsContext);
  if (!ctx) {
    throw new Error('Tabs compound components must be used within a <Tabs> parent');
  }
  return ctx;
}

/* -------------------------------------------------------------------------- */
/*  Tabs (root)                                                               */
/* -------------------------------------------------------------------------- */

interface TabsProps extends HTMLAttributes<HTMLDivElement> {
  value: string;
  onValueChange: (value: string) => void;
}

const Tabs = forwardRef<HTMLDivElement, TabsProps>(
  ({ value, onValueChange, className, ...props }, ref) => (
    <TabsContext.Provider value={{ value, onValueChange }}>
      <div ref={ref} className={cn('w-full', className)} {...props} />
    </TabsContext.Provider>
  ),
);
Tabs.displayName = 'Tabs';

/* -------------------------------------------------------------------------- */
/*  TabsList                                                                  */
/* -------------------------------------------------------------------------- */

const TabsList = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  ({ className, onKeyDown, ...props }, ref) => {
    const listRef = useRef<HTMLDivElement | null>(null);

    const handleRef = useCallback(
      (node: HTMLDivElement | null) => {
        listRef.current = node;
        if (typeof ref === 'function') {
          ref(node);
        } else if (ref) {
          ref.current = node;
        }
      },
      [ref],
    );

    const handleKeyDown = useCallback(
      (e: KeyboardEvent<HTMLDivElement>) => {
        onKeyDown?.(e);
        if (e.defaultPrevented) return;

        const tabs = listRef.current?.querySelectorAll<HTMLElement>('[role="tab"]:not([disabled])');
        if (!tabs || tabs.length === 0) return;

        const currentIndex = Array.from(tabs).indexOf(document.activeElement as HTMLElement);
        if (currentIndex === -1) return;

        let nextTab: HTMLElement | undefined;

        if (e.key === 'ArrowRight') {
          e.preventDefault();
          const next = currentIndex < tabs.length - 1 ? currentIndex + 1 : 0;
          nextTab = tabs[next];
        } else if (e.key === 'ArrowLeft') {
          e.preventDefault();
          const prev = currentIndex > 0 ? currentIndex - 1 : tabs.length - 1;
          nextTab = tabs[prev];
        } else if (e.key === 'Home') {
          e.preventDefault();
          nextTab = tabs[0];
        } else if (e.key === 'End') {
          e.preventDefault();
          nextTab = tabs[tabs.length - 1];
        }

        if (nextTab) {
          nextTab.focus();
          // Activate the tab on arrow key navigation
          nextTab.click();
        }
      },
      [onKeyDown],
    );

    return (
      <div
        ref={handleRef}
        role="tablist"
        aria-orientation="horizontal"
        onKeyDown={handleKeyDown}
        className={cn(
          'inline-flex h-10 items-center justify-center rounded-md bg-[hsl(var(--muted))] p-1 text-[hsl(var(--muted-foreground))]',
          className,
        )}
        {...props}
      />
    );
  },
);
TabsList.displayName = 'TabsList';

/* -------------------------------------------------------------------------- */
/*  TabsTrigger                                                               */
/* -------------------------------------------------------------------------- */

interface TabsTriggerProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  value: string;
}

const TabsTrigger = forwardRef<HTMLButtonElement, TabsTriggerProps>(
  ({ className, value, ...props }, ref) => {
    const { value: selectedValue, onValueChange } = useTabsContext();
    const isSelected = selectedValue === value;

    return (
      <button
        ref={ref}
        type="button"
        role="tab"
        aria-selected={isSelected}
        tabIndex={isSelected ? 0 : -1}
        data-state={isSelected ? 'active' : 'inactive'}
        onClick={() => onValueChange(value)}
        className={cn(
          'inline-flex items-center justify-center whitespace-nowrap rounded-sm px-3 py-1.5 text-sm font-medium ring-offset-[hsl(var(--background))] transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[hsl(var(--ring))] focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50',
          isSelected
            ? 'bg-[hsl(var(--background))] text-[hsl(var(--foreground))] shadow-sm'
            : 'hover:bg-[hsl(var(--background)/0.5)] hover:text-[hsl(var(--foreground))]',
          className,
        )}
        {...props}
      />
    );
  },
);
TabsTrigger.displayName = 'TabsTrigger';

/* -------------------------------------------------------------------------- */
/*  TabsContent                                                               */
/* -------------------------------------------------------------------------- */

interface TabsContentProps extends HTMLAttributes<HTMLDivElement> {
  value: string;
}

const TabsContent = forwardRef<HTMLDivElement, TabsContentProps>(
  ({ className, value, ...props }, ref) => {
    const { value: selectedValue } = useTabsContext();

    if (selectedValue !== value) return null;

    return (
      <div
        ref={ref}
        role="tabpanel"
        tabIndex={0}
        className={cn(
          'mt-2 ring-offset-[hsl(var(--background))] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[hsl(var(--ring))] focus-visible:ring-offset-2',
          className,
        )}
        {...props}
      />
    );
  },
);
TabsContent.displayName = 'TabsContent';

export { Tabs, TabsList, TabsTrigger, TabsContent };
