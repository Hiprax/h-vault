import {
  type ReactNode,
  type HTMLAttributes,
  forwardRef,
  useEffect,
  useCallback,
  useRef,
  useId,
  createContext,
  useContext,
} from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';
import { cn } from '../../lib/utils';

/* -------------------------------------------------------------------------- */
/*  Body scroll lock reference counter                                        */
/* -------------------------------------------------------------------------- */

let scrollLockCount = 0;

function lockBodyScroll(): void {
  scrollLockCount++;
  if (scrollLockCount === 1) {
    document.body.style.overflow = 'hidden';
  }
}

function unlockBodyScroll(): void {
  scrollLockCount = Math.max(0, scrollLockCount - 1);
  if (scrollLockCount === 0) {
    document.body.style.overflow = '';
  }
}

/** Reset the scroll lock counter (for testing only). */
export function _resetScrollLockCount(): void {
  scrollLockCount = 0;
  document.body.style.overflow = '';
}

/* -------------------------------------------------------------------------- */
/*  Dialog context (shares generated title ID for aria-labelledby)            */
/* -------------------------------------------------------------------------- */

interface DialogContextValue {
  titleId: string;
  descriptionId: string;
}

const DialogContext = createContext<DialogContextValue | null>(null);

/* -------------------------------------------------------------------------- */
/*  Focus trap helper                                                         */
/* -------------------------------------------------------------------------- */

const FOCUSABLE_SELECTOR = [
  'a[href]:not([disabled]):not([aria-disabled="true"])',
  'button:not([disabled]):not([aria-disabled="true"])',
  'input:not([disabled]):not([aria-disabled="true"])',
  'textarea:not([disabled]):not([aria-disabled="true"])',
  'select:not([disabled]):not([aria-disabled="true"])',
  '[tabindex]:not([tabindex="-1"]):not([disabled]):not([aria-disabled="true"])',
].join(', ');

function useFocusTrap(containerRef: React.RefObject<HTMLDivElement | null>, active: boolean) {
  useEffect(() => {
    if (!active || !containerRef.current) return;

    const container = containerRef.current;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return;

      const focusableElements = container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR);
      if (focusableElements.length === 0) {
        e.preventDefault();
        return;
      }

      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- length > 0 checked above
      const first = focusableElements[0]!;
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- length > 0 checked above
      const last = focusableElements[focusableElements.length - 1]!;

      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault();
          last.focus();
        }
      } else {
        if (document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };

    container.addEventListener('keydown', handleKeyDown);
    return () => container.removeEventListener('keydown', handleKeyDown);
  }, [containerRef, active]);
}

/* -------------------------------------------------------------------------- */
/*  Dialog (root)                                                             */
/* -------------------------------------------------------------------------- */

interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: ReactNode;
}

function Dialog({ open, onOpenChange, children }: DialogProps) {
  const titleId = useId();
  const descriptionId = useId();
  const previouslyFocusedRef = useRef<HTMLElement | null>(null);
  const wasOpenRef = useRef(false);

  // Capture the element that had focus BEFORE the dialog content mounts.
  // This has to happen during render: child effects run before parent effects,
  // so by the time this component's own effect runs, DialogContent's auto-focus
  // has already moved focus INSIDE the dialog. Recording that element would make
  // focus restoration a no-op (it is disconnected once the dialog unmounts),
  // stranding focus on <body>.
  if (open && !wasOpenRef.current) {
    previouslyFocusedRef.current = document.activeElement as HTMLElement | null;
  }
  wasOpenRef.current = open;

  const handleEscape = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onOpenChange(false);
      }
    },
    [onOpenChange],
  );

  useEffect(() => {
    if (!open) return;

    document.addEventListener('keydown', handleEscape);
    lockBodyScroll();
    return () => {
      document.removeEventListener('keydown', handleEscape);
      unlockBodyScroll();
    };
  }, [open, handleEscape]);

  // Restore focus when dialog closes
  useEffect(() => {
    if (!open && previouslyFocusedRef.current) {
      const el = previouslyFocusedRef.current;
      previouslyFocusedRef.current = null;
      // Use requestAnimationFrame to ensure the DOM has settled
      requestAnimationFrame(() => {
        if (el.isConnected) {
          el.focus();
        }
      });
    }
  }, [open]);

  if (!open) return null;

  return createPortal(
    <DialogContext.Provider value={{ titleId, descriptionId }}>
      <div className="fixed inset-0 z-50 flex items-center justify-center">
        {/* Overlay */}
        <div
          className="fixed inset-0 bg-black/80 backdrop-blur-sm"
          onClick={() => onOpenChange(false)}
          aria-hidden="true"
        />
        {children}
      </div>
    </DialogContext.Provider>,
    document.body,
  );
}

/* -------------------------------------------------------------------------- */
/*  DialogContent                                                             */
/* -------------------------------------------------------------------------- */

interface DialogContentProps extends HTMLAttributes<HTMLDivElement> {
  onClose?: () => void;
}

const DialogContent = forwardRef<HTMLDivElement, DialogContentProps>(
  ({ className, children, onClose, ...props }, ref) => {
    const ctx = useContext(DialogContext);
    const internalRef = useRef<HTMLDivElement | null>(null);

    // Merge forwarded ref with internal ref
    const setRef = useCallback(
      (node: HTMLDivElement | null) => {
        internalRef.current = node;
        if (typeof ref === 'function') {
          ref(node);
        } else if (ref) {
          ref.current = node;
        }
      },
      [ref],
    );

    // Focus trap
    useFocusTrap(internalRef, true);

    // Auto-focus the first focusable element in the dialog
    useEffect(() => {
      if (!internalRef.current) return;
      const focusable = internalRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR);
      if (focusable.length > 0) {
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- length > 0 checked above
        focusable[0]!.focus();
      } else {
        // If no focusable element, focus the dialog itself
        internalRef.current.focus();
      }
    }, []);

    return (
      <div
        ref={setRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={ctx?.titleId}
        aria-describedby={ctx?.descriptionId}
        tabIndex={-1}
        className={cn(
          'relative z-50 grid w-full max-w-lg gap-4 rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-6 shadow-lg animate-in',
          'mx-4 sm:mx-0',
          className,
        )}
        {...props}
      >
        {children}
        {onClose && (
          <button
            type="button"
            onClick={onClose}
            className="absolute right-4 top-4 rounded-sm opacity-70 ring-offset-[hsl(var(--background))] transition-opacity hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))] focus:ring-offset-2"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>
    );
  },
);
DialogContent.displayName = 'DialogContent';

/* -------------------------------------------------------------------------- */
/*  DialogHeader                                                              */
/* -------------------------------------------------------------------------- */

const DialogHeader = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn('flex flex-col space-y-1.5 text-center sm:text-left', className)}
      {...props}
    />
  ),
);
DialogHeader.displayName = 'DialogHeader';

/* -------------------------------------------------------------------------- */
/*  DialogTitle                                                               */
/* -------------------------------------------------------------------------- */

const DialogTitle = forwardRef<HTMLHeadingElement, HTMLAttributes<HTMLHeadingElement>>(
  ({ className, ...props }, ref) => {
    const ctx = useContext(DialogContext);
    return (
      <h2
        ref={ref}
        id={ctx?.titleId}
        className={cn('text-lg font-semibold leading-none tracking-tight', className)}
        {...props}
      />
    );
  },
);
DialogTitle.displayName = 'DialogTitle';

/* -------------------------------------------------------------------------- */
/*  DialogDescription                                                         */
/* -------------------------------------------------------------------------- */

const DialogDescription = forwardRef<HTMLParagraphElement, HTMLAttributes<HTMLParagraphElement>>(
  ({ className, ...props }, ref) => {
    const ctx = useContext(DialogContext);
    return (
      <p
        ref={ref}
        id={ctx?.descriptionId}
        className={cn('text-sm text-[hsl(var(--muted-foreground))]', className)}
        {...props}
      />
    );
  },
);
DialogDescription.displayName = 'DialogDescription';

/* -------------------------------------------------------------------------- */
/*  DialogFooter                                                              */
/* -------------------------------------------------------------------------- */

const DialogFooter = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn('flex flex-col-reverse sm:flex-row sm:justify-end sm:space-x-2', className)}
      {...props}
    />
  ),
);
DialogFooter.displayName = 'DialogFooter';

/* -------------------------------------------------------------------------- */
/*  Inline dialog helper hook                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Hook for inline dialogs that aren't using the full Dialog component.
 * Provides focus trap, escape key handling, auto-focus, and body scroll lock.
 */
function useInlineDialog(
  ref: React.RefObject<HTMLDivElement | null>,
  isOpen: boolean,
  onClose: () => void,
) {
  // Focus trap
  useFocusTrap(ref, isOpen);

  // Escape key handler
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Auto-focus first focusable element
  useEffect(() => {
    if (!isOpen || !ref.current) return;
    const focusable = ref.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR);
    if (focusable.length > 0) {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- length > 0 checked above
      focusable[0]!.focus();
    }
  }, [isOpen, ref]);

  // Body scroll lock (reference counted)
  useEffect(() => {
    if (!isOpen) return;
    lockBodyScroll();
    return () => {
      unlockBodyScroll();
    };
  }, [isOpen]);
}

export {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  useInlineDialog,
};
