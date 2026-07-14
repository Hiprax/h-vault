import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  useEffect,
  type ReactNode,
} from 'react';
import { X, CheckCircle, AlertCircle, AlertTriangle, Info } from 'lucide-react';
import { cn } from '../../lib/utils';

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

type ToastType = 'success' | 'error' | 'warning' | 'info';

interface ToastItem {
  id: string;
  type: ToastType;
  title: string;
  description?: string | undefined;
  duration: number;
}

interface ToastOptions {
  title: string;
  description?: string;
  type?: ToastType;
  duration?: number;
}

interface ToastContextValue {
  toast: (options: ToastOptions) => string;
  dismiss: (id: string) => void;
  update: (id: string, options: Partial<ToastOptions>) => void;
}

/* -------------------------------------------------------------------------- */
/*  Context                                                                   */
/* -------------------------------------------------------------------------- */

const ToastContext = createContext<ToastContextValue | null>(null);

/* -------------------------------------------------------------------------- */
/*  Toast styles                                                              */
/* -------------------------------------------------------------------------- */

const typeStyles: Record<ToastType, string> = {
  success: 'border-green-500/30 bg-green-50 text-green-900 dark:bg-green-950 dark:text-green-100',
  error: 'border-red-500/30 bg-red-50 text-red-900 dark:bg-red-950 dark:text-red-100',
  warning:
    'border-yellow-500/30 bg-yellow-50 text-yellow-900 dark:bg-yellow-950 dark:text-yellow-100',
  info: 'border-blue-500/30 bg-blue-50 text-blue-900 dark:bg-blue-950 dark:text-blue-100',
};

const iconMap: Record<ToastType, typeof CheckCircle> = {
  success: CheckCircle,
  error: AlertCircle,
  warning: AlertTriangle,
  info: Info,
};

const iconColorMap: Record<ToastType, string> = {
  success: 'text-green-600 dark:text-green-400',
  error: 'text-red-600 dark:text-red-400',
  warning: 'text-yellow-600 dark:text-yellow-400',
  info: 'text-blue-600 dark:text-blue-400',
};

/* -------------------------------------------------------------------------- */
/*  Single toast element                                                      */
/* -------------------------------------------------------------------------- */

interface ToastElementProps {
  item: ToastItem;
  onDismiss: (id: string) => void;
}

function ToastElement({ item, onDismiss }: ToastElementProps) {
  const [exiting, setExiting] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      setExiting(true);
    }, item.duration - 300);

    const removeTimer = setTimeout(() => {
      onDismiss(item.id);
    }, item.duration);

    return () => {
      clearTimeout(timer);
      clearTimeout(removeTimer);
    };
  }, [item.id, item.duration, onDismiss]);

  const Icon = iconMap[item.type];

  return (
    <div
      role={item.type === 'error' ? 'alert' : 'status'}
      aria-live={item.type === 'error' ? 'assertive' : 'polite'}
      className={cn(
        'pointer-events-auto flex w-full max-w-sm items-start gap-3 rounded-lg border p-4 shadow-lg transition-all duration-300',
        typeStyles[item.type],
        exiting ? 'translate-x-full opacity-0' : 'translate-x-0 opacity-100 animate-slide-in-right',
      )}
    >
      <Icon className={cn('mt-0.5 h-5 w-5 shrink-0', iconColorMap[item.type])} />
      <div className="flex-1 space-y-1">
        <p className="text-sm font-semibold">{item.title}</p>
        {item.description && <p className="text-sm opacity-80">{item.description}</p>}
      </div>
      <button
        type="button"
        onClick={() => {
          setExiting(true);
          setTimeout(() => onDismiss(item.id), 300);
        }}
        className="shrink-0 rounded-md p-1 opacity-60 hover:opacity-100 transition-opacity"
        aria-label="Dismiss notification"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Provider                                                                  */
/* -------------------------------------------------------------------------- */

const DEFAULT_DURATION = 5000;

let toastCounter = 0;

function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const toast = useCallback((options: ToastOptions): string => {
    const id = `toast-${++toastCounter}`;
    const newToast: ToastItem = {
      id,
      type: options.type ?? 'info',
      title: options.title,
      description: options.description,
      duration: options.duration ?? DEFAULT_DURATION,
    };
    setToasts((prev) => [...prev, newToast]);
    return id;
  }, []);

  const update = useCallback((id: string, options: Partial<ToastOptions>) => {
    setToasts((prev) =>
      prev.map((t) =>
        t.id === id
          ? {
              ...t,
              ...(options.title !== undefined ? { title: options.title } : {}),
              ...(options.description !== undefined ? { description: options.description } : {}),
              ...(options.type !== undefined ? { type: options.type } : {}),
            }
          : t,
      ),
    );
  }, []);

  const value = useMemo(() => ({ toast, dismiss, update }), [toast, dismiss, update]);

  return (
    <ToastContext.Provider value={value}>
      {children}

      {/* Toast container - top right */}
      <div
        aria-label="Notifications"
        className="pointer-events-none fixed top-4 right-4 z-[100] flex max-h-screen flex-col gap-2"
      >
        {toasts.map((item) => (
          <ToastElement key={item.id} item={item} onDismiss={dismiss} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

/* -------------------------------------------------------------------------- */
/*  Hook                                                                      */
/* -------------------------------------------------------------------------- */

function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error('useToast must be used within a <ToastProvider>');
  }
  return ctx;
}

export { ToastProvider, useToast };
export type { ToastType, ToastOptions };
