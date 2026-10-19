import {
  Suspense,
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
  type RefObject,
} from 'react';
import { createPortal } from 'react-dom';
import { CircleHelp } from 'lucide-react';
import { placePopover } from '../../lib/popoverPlacement';
import { Spinner } from './Spinner';

const PANEL_WIDTH = 'min(24rem, calc(100vw - 32px))';

interface InfoTipPanelProps {
  /** The id the trigger's `aria-controls` names. */
  id: string;
  title: string;
  children: ReactNode;
  triggerRef: RefObject<HTMLButtonElement | null>;
  /** Whether the panel is pinned; a hover-opened panel pinned later takes focus then. */
  pinned: boolean;
  /** Whether focus should move into the panel now, which also consumes the request. */
  takeFocusRequest: () => boolean;
  /** Closes the panel, handing focus back to the trigger when asked. */
  onClose: (refocusTrigger: boolean) => void;
  onPin: () => void;
  onHoverEnter: () => void;
  onHoverLeave: () => void;
}

/** Places the panel again whenever what it wraps commits, e.g. a lazy body replacing the spinner. */
function PlaceOnCommit({ place }: { place: () => void }) {
  useLayoutEffect(place, [place]);
  return null;
}

/**
 * The open half of `InfoTip`, in a chunk of its own: everything the trigger does
 * not need until the panel is open, so the page that shows the trigger carries
 * only the button. `InfoTip` owns when it is open and how it closes; this owns
 * the panel, where it goes, and what dismisses it from inside or from the page.
 *
 * A non-modal `role="dialog"` named by its title, portalled to `body` with
 * `position: fixed` so a scrolling ancestor cannot clip it. Where it goes is
 * `placePopover`'s decision, re-made on resize, on any scroll, and when its
 * content commits.
 */
export default function InfoTipPanel({
  id,
  title,
  children,
  triggerRef,
  pinned,
  takeFocusRequest,
  onClose,
  onPin,
  onHoverEnter,
  onHoverLeave,
}: InfoTipPanelProps) {
  const titleId = useId();
  // State rather than a ref, so placing and listening follow the panel's mount.
  const [panel, setPanel] = useState<HTMLDivElement | null>(null);
  const [placement, setPlacement] = useState<ReturnType<typeof placePopover> | null>(null);

  const place = useCallback(() => {
    const trigger = triggerRef.current;
    if (panel === null || trigger === null) {
      setPlacement(null);
      return;
    }
    setPlacement(
      placePopover({
        trigger: trigger.getBoundingClientRect(),
        // The NATURAL height, not the capped one: `scrollHeight` ignores
        // `max-height`, and offset minus client adds the borders back.
        panel: {
          width: panel.offsetWidth,
          height: panel.scrollHeight + panel.offsetHeight - panel.clientHeight,
        },
        viewport: { width: window.innerWidth, height: window.innerHeight },
      }),
    );
  }, [panel, triggerRef]);

  useLayoutEffect(place, [place]);

  // Focus moves in once the panel is placed: it is `visibility: hidden` until
  // then, and a hidden element cannot take focus. `pinned` is a dependency for
  // the hover-to-pinned case, where the panel is already placed.
  useEffect(() => {
    if (panel !== null && placement !== null && takeFocusRequest()) {
      panel.focus({ preventScroll: true });
    }
  }, [pinned, panel, placement, takeFocusRequest]);

  useEffect(() => {
    if (panel === null) return;
    let frame = 0;
    const reposition = (event: Event) => {
      // One placement per frame is plenty, and the panel scrolling its own text moves nothing.
      if (frame !== 0 || (event.target instanceof Node && panel.contains(event.target))) return;
      frame = requestAnimationFrame(() => {
        frame = 0;
        place();
      });
    };
    const dismissOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose(panel.contains(document.activeElement));
    };
    const dismissOnOutsidePress = (event: PointerEvent) => {
      const target = event.target;
      const inside =
        target instanceof Node &&
        (panel.contains(target) || triggerRef.current?.contains(target) === true);
      if (!inside) onClose(false);
    };
    window.addEventListener('resize', reposition);
    // Capture: scroll does not bubble, and the page scrolls inside `<main>`.
    document.addEventListener('scroll', reposition, { capture: true, passive: true });
    document.addEventListener('keydown', dismissOnEscape);
    document.addEventListener('pointerdown', dismissOnOutsidePress);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener('resize', reposition);
      document.removeEventListener('scroll', reposition, { capture: true });
      document.removeEventListener('keydown', dismissOnEscape);
      document.removeEventListener('pointerdown', dismissOnOutsidePress);
    };
  }, [panel, place, onClose, triggerRef]);

  const handleKeyDown = (event: ReactKeyboardEvent) => {
    if (event.key !== 'Tab') return;
    // Back to the trigger, and out. Tab keeps its default, so the browser goes on
    // to the control after the trigger; Shift+Tab stops on the trigger itself.
    if (event.shiftKey) event.preventDefault();
    onClose(true);
  };

  return createPortal(
    <div
      ref={setPanel}
      id={id}
      role="dialog"
      aria-labelledby={titleId}
      tabIndex={-1}
      onPointerEnter={onHoverEnter}
      onPointerLeave={onHoverLeave}
      // Pressing inside (to select text, say) makes a hover-opened panel stay.
      onPointerDown={onPin}
      onKeyDown={handleKeyDown}
      className="animate-in fixed z-50 overflow-y-auto rounded-xl border border-[hsl(var(--border))] bg-[hsl(var(--popover))] p-4 text-[hsl(var(--popover-foreground))] shadow-lg outline-none focus-visible:ring-2 focus-visible:ring-[hsl(var(--ring))]"
      style={
        placement === null
          ? { width: PANEL_WIDTH, visibility: 'hidden' }
          : {
              width: PANEL_WIDTH,
              top: placement.top,
              left: placement.left,
              maxHeight: placement.maxHeight,
              transformOrigin: placement.side === 'top' ? 'bottom left' : 'top left',
            }
      }
    >
      <h2 id={titleId} className="mb-3 flex items-center gap-2 text-sm font-semibold">
        <CircleHelp className="h-4 w-4 shrink-0 text-[hsl(var(--primary))]" aria-hidden="true" />
        {title}
      </h2>
      <Suspense fallback={<Spinner size="sm" className="mx-auto" />}>
        {children}
        <PlaceOnCommit place={place} />
      </Suspense>
    </div>,
    document.body,
  );
}
