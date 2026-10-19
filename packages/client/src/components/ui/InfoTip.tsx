import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type PointerEvent as ReactPointerEvent,
  type ReactNode,
} from 'react';
import { CircleHelp } from 'lucide-react';
import { cn } from '../../lib/utils';

/** How long a mouse rests on the trigger before the panel opens, so a pass-over does not flash it. */
const HOVER_OPEN_DELAY_MS = 150;

/** How long the panel waits after the mouse leaves, which is the time it has to reach the panel. */
const HOVER_CLOSE_DELAY_MS = 200;

/** The panel's chunk: started by the first approach to the trigger, so it is there by the time it opens. */
const loadPanel = () => import('./InfoTipPanel');
const InfoTipPanel = lazy(loadPanel);

/** `hover` follows the mouse; `pinned` (a click, a tap, Enter or Space) stays until dismissed. */
type Mode = 'closed' | 'hover' | 'pinned';

interface InfoTipProps {
  /** The trigger's accessible name, e.g. "Help: what rotating the vault key does". */
  label: string;
  /** The panel's heading, which also names the panel. */
  title: string;
  /**
   * The panel body. Text only: Tab leaves the panel, so nothing inside it can be
   * reached by keyboard. It may be lazy; a spinner stands in until it arrives.
   */
  children: ReactNode;
  /**
   * Called once, the first time the trigger is hovered, focused or pressed: the
   * moment to start fetching a lazy body. A rejection it returns is ignored,
   * because the body reports its own failure when it renders.
   */
  onPreload?: () => unknown;
}

/**
 * A help toggletip: a small question-mark button that opens a panel of
 * explanation beside it.
 *
 * It meets WCAG 1.4.13 (content on hover or focus). A resting MOUSE opens it
 * after a short delay and leaving closes it after a grace period, during which
 * the mouse can move onto the panel and keep it open (hoverable). A click, a
 * tap, Enter or Space PINS it open and moves focus into it (persistent); Escape
 * anywhere, a press outside, or Tab dismisses it (dismissible). Touch and pen
 * never open it by hovering, since the tap that "enters" also clicks.
 *
 * Only the trigger and the open/close state live here. The panel itself
 * (`InfoTipPanel`: the portal, placement and the listeners that dismiss it) is a
 * chunk of its own, fetched on the first hover, focus or press, so a page with
 * several of these carries one small button each.
 */
export function InfoTip({ label, title, children, onPreload }: InfoTipProps) {
  const panelId = useId();
  const [mode, setMode] = useState<Mode>('closed');
  const triggerRef = useRef<HTMLButtonElement>(null);
  // One timer serves both delays: an open and a close are never pending together.
  const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const preloadedRef = useRef(false);
  const focusPanelRef = useRef(false);

  const cancelTimer = () => {
    clearTimeout(timerRef.current);
  };

  const schedule = (next: Mode, delay: number) => {
    clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => {
      setMode(next);
    }, delay);
  };

  const close = useCallback((refocusTrigger: boolean) => {
    clearTimeout(timerRef.current);
    // A pin whose panel never arrived must not pull focus into a later hover.
    focusPanelRef.current = false;
    setMode('closed');
    if (refocusTrigger) triggerRef.current?.focus();
  }, []);

  const takeFocusRequest = useCallback(() => {
    const wanted = focusPanelRef.current;
    focusPanelRef.current = false;
    return wanted;
  }, []);

  useEffect(() => cancelTimer, []);

  const preload = () => {
    if (preloadedRef.current) return;
    preloadedRef.current = true;
    void Promise.all([loadPanel(), onPreload?.()]).catch(() => undefined);
  };

  const pin = () => {
    clearTimeout(timerRef.current);
    setMode('pinned');
  };

  const handleTriggerClick = () => {
    preload();
    if (mode === 'pinned') {
      // Read through the DOM: the panel is another module's, and may not have arrived.
      close(document.getElementById(panelId)?.contains(document.activeElement) === true);
      return;
    }
    focusPanelRef.current = true;
    pin();
  };

  const handleTriggerEnter = (event: ReactPointerEvent) => {
    preload();
    if (event.pointerType !== 'mouse') return;
    if (mode === 'closed') schedule('hover', HOVER_OPEN_DELAY_MS);
    else cancelTimer();
  };

  // From the trigger or the panel. Only a hover-opened panel closes on its own;
  // otherwise this abandons a pending open.
  const handleLeave = () => {
    if (mode === 'hover') schedule('closed', HOVER_CLOSE_DELAY_MS);
    else cancelTimer();
  };

  const open = mode !== 'closed';

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        aria-label={label}
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        onClick={handleTriggerClick}
        onFocus={preload}
        onPointerEnter={handleTriggerEnter}
        onPointerLeave={handleLeave}
        className={cn(
          'inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full transition-colors hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--primary))] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[hsl(var(--ring))]',
          open ? 'text-[hsl(var(--primary))]' : 'text-[hsl(var(--muted-foreground))]',
        )}
      >
        <CircleHelp className="h-4 w-4" aria-hidden="true" />
      </button>
      {open && (
        <Suspense fallback={null}>
          <InfoTipPanel
            id={panelId}
            title={title}
            triggerRef={triggerRef}
            pinned={mode === 'pinned'}
            takeFocusRequest={takeFocusRequest}
            onClose={close}
            onPin={pin}
            onHoverEnter={cancelTimer}
            onHoverLeave={handleLeave}
          >
            {children}
          </InfoTipPanel>
        </Suspense>
      )}
    </>
  );
}
