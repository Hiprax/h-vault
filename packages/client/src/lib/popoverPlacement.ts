/**
 * Where a popover panel goes beside the control that opened it.
 *
 * Pure geometry in viewport coordinates, so it is decided once here and tested
 * without a layout engine (jsdom has none). The caller measures the trigger with
 * `getBoundingClientRect()`, the panel's natural size and the viewport, and
 * positions the panel `fixed` at the answer.
 *
 * The rules, in order:
 *
 *   - Below the trigger by default, where reading continues. It flips above only
 *     when the panel does not fit below AND there is more room above; with no
 *     clear winner it stays below.
 *   - The panel's height is capped to the room on its side (it scrolls inside),
 *     but never below {@link MIN_PANEL_HEIGHT}, or what the viewport can hold
 *     when that is less: a 40 px window onto a long explanation is not readable.
 *     Only that floor can make the panel cover its trigger, and then it is slid
 *     back inside the viewport rather than off its edge.
 *   - Left-aligned with the trigger, kept inside the side margins. A panel wider
 *     than the viewport keeps the left margin, so its start stays readable.
 */

/** The shortest the panel is capped to, room permitting. */
const MIN_PANEL_HEIGHT = 120;

interface PopoverGeometry {
  /** The trigger's box; a `DOMRect` fits. */
  trigger: Pick<DOMRectReadOnly, 'top' | 'bottom' | 'left'>;
  /** The panel's natural size, before any height cap. */
  panel: { width: number; height: number };
  viewport: { width: number; height: number };
  /** Space kept clear at every viewport edge. */
  margin?: number;
  /** Space between the trigger and the panel. */
  gap?: number;
}

export function placePopover({ trigger, panel, viewport, margin = 16, gap = 8 }: PopoverGeometry): {
  top: number;
  left: number;
  maxHeight: number;
  side: 'bottom' | 'top';
} {
  const spaceBelow = viewport.height - margin - (trigger.bottom + gap);
  const spaceAbove = trigger.top - gap - margin;
  const side = spaceBelow < panel.height && spaceAbove > spaceBelow ? 'top' : 'bottom';
  const floor = Math.max(0, Math.min(MIN_PANEL_HEIGHT, viewport.height - 2 * margin));
  const maxHeight = Math.max(side === 'top' ? spaceAbove : spaceBelow, floor);
  const height = Math.min(panel.height, maxHeight);
  const top =
    side === 'top'
      ? Math.max(margin, trigger.top - gap - height)
      : Math.min(trigger.bottom + gap, viewport.height - margin - height);
  const left = Math.max(margin, Math.min(trigger.left, viewport.width - margin - panel.width));
  return { top, left, maxHeight, side };
}
