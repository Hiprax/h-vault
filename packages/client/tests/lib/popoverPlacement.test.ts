/**
 * Where a help panel opens beside its trigger (`placePopover`).
 *
 * Every number below is worked by hand from the rules in the module header, so a
 * changed comparison, a dropped clamp or a swapped `min`/`max` lands on a
 * different number rather than on the same one by luck. The boundary pairs
 * (equal, then one pixel past) are the cases a `<` turned into `<=` would flip.
 *
 * Defaults throughout: a 16 px margin, an 8 px gap, a 24 px trigger (the
 * InfoTip's hit area) and a 384 px panel (its 24rem width).
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { placePopover } from '../../src/lib/popoverPlacement';
import { PROPERTY_RUNS, propertyRun } from '../../../../tests/harness/property.js';

const LAPTOP = { width: 1024, height: 768 };

/** A 24 px trigger whose top edge is at `top`. */
function triggerAt(top: number, left = 40) {
  return { top, bottom: top + 24, left };
}

function panelOf(height: number, width = 384) {
  return { width, height };
}

describe('placePopover: which side', () => {
  it('opens below the trigger, at its left edge, when the panel fits there', () => {
    expect(
      placePopover({ trigger: triggerAt(100, 200), panel: panelOf(300), viewport: LAPTOP }),
    ).toEqual({ top: 132, left: 200, maxHeight: 620, side: 'bottom' });
  });

  it('stays below when the room below exactly equals the panel height', () => {
    // 768 - 16 - (444 + 8) = 300 below; 396 above would have been more.
    expect(
      placePopover({ trigger: triggerAt(420), panel: panelOf(300), viewport: LAPTOP }),
    ).toEqual({ top: 452, left: 40, maxHeight: 300, side: 'bottom' });
  });

  it('flips above when the room below is one pixel short and there is more room above', () => {
    // 299 below, 397 above: the panel's bottom edge sits one gap above the trigger.
    expect(
      placePopover({ trigger: triggerAt(421), panel: panelOf(300), viewport: LAPTOP }),
    ).toEqual({ top: 113, left: 40, maxHeight: 397, side: 'top' });
  });

  it('stays below when the panel fits neither side and the room above is only equal', () => {
    // A 400 px viewport: 164 below and 164 above, so there is no clear winner.
    expect(
      placePopover({
        trigger: triggerAt(188),
        panel: panelOf(300),
        viewport: { width: 1024, height: 400 },
      }),
    ).toEqual({ top: 220, left: 40, maxHeight: 164, side: 'bottom' });
  });

  it('flips above, capped to the room there, when that room is larger by one pixel', () => {
    // 163 below, 165 above.
    expect(
      placePopover({
        trigger: triggerAt(189),
        panel: panelOf(300),
        viewport: { width: 1024, height: 400 },
      }),
    ).toEqual({ top: 16, left: 40, maxHeight: 165, side: 'top' });
  });
});

describe('placePopover: how tall', () => {
  it('never caps the height below 120 px, sliding up over the trigger when the room below is shorter', () => {
    // 97 below, 81 above, on a 250 px viewport that could hold 218.
    expect(
      placePopover({
        trigger: triggerAt(105),
        panel: panelOf(200),
        viewport: { width: 1024, height: 250 },
      }),
    ).toEqual({ top: 114, left: 40, maxHeight: 120, side: 'bottom' });
  });

  it('never caps the height below 120 px above either, and keeps the top margin', () => {
    // 82 below, 96 above.
    expect(
      placePopover({
        trigger: triggerAt(120),
        panel: panelOf(200),
        viewport: { width: 1024, height: 250 },
      }),
    ).toEqual({ top: 16, left: 40, maxHeight: 120, side: 'top' });
  });

  it('lowers that floor to what a short viewport can hold between its margins', () => {
    // 100 - 2 * 16 = 68 is all there is.
    expect(
      placePopover({
        trigger: triggerAt(30),
        panel: panelOf(200),
        viewport: { width: 1024, height: 100 },
      }),
    ).toEqual({ top: 16, left: 40, maxHeight: 68, side: 'bottom' });
  });

  it('never answers a negative height when the viewport is shorter than its two margins', () => {
    expect(
      placePopover({
        trigger: triggerAt(0),
        panel: panelOf(50),
        viewport: { width: 1024, height: 20 },
      }),
    ).toEqual({ top: 16, left: 40, maxHeight: 0, side: 'top' });
  });
});

describe('placePopover: how far left', () => {
  it('holds the panel off the right edge when the trigger sits near it', () => {
    // 1024 - 16 - 384 = 624.
    expect(
      placePopover({ trigger: triggerAt(100, 900), panel: panelOf(300), viewport: LAPTOP }),
    ).toEqual({ top: 132, left: 624, maxHeight: 620, side: 'bottom' });
  });

  it('keeps the left margin when the trigger starts inside it', () => {
    expect(
      placePopover({ trigger: triggerAt(100, 4), panel: panelOf(300), viewport: LAPTOP }).left,
    ).toBe(16);
  });

  it('keeps the left margin when the panel is wider than the viewport', () => {
    expect(
      placePopover({
        trigger: triggerAt(100, 50),
        panel: panelOf(300),
        viewport: { width: 300, height: 768 },
      }).left,
    ).toBe(16);
  });
});

describe('placePopover: margin and gap', () => {
  it('measures below with the margin and gap it is given', () => {
    expect(
      placePopover({
        trigger: triggerAt(100, 200),
        panel: panelOf(300),
        viewport: LAPTOP,
        margin: 8,
        gap: 4,
      }),
    ).toEqual({ top: 128, left: 200, maxHeight: 632, side: 'bottom' });
  });

  it('measures above and clamps left with the margin and gap it is given', () => {
    // 132 below, 588 above; the left margin is 8, not 16.
    expect(
      placePopover({
        trigger: triggerAt(600, 4),
        panel: panelOf(300),
        viewport: LAPTOP,
        margin: 8,
        gap: 4,
      }),
    ).toEqual({ top: 296, left: 8, maxHeight: 588, side: 'top' });
  });
});

describe('placePopover: properties', () => {
  /**
   * A viewport, a trigger fully inside it and a panel, with room on at least one
   * side for the 120 px floor: the only arrangement in which the panel can be
   * kept clear of its trigger at all.
   */
  const roomyLayout = fc
    .record({
      viewportWidth: fc.integer({ min: 420, max: 2560 }),
      viewportHeight: fc.integer({ min: 300, max: 1600 }),
      topFraction: fc.double({ min: 0, max: 1, noNaN: true }),
      leftFraction: fc.double({ min: 0, max: 1, noNaN: true }),
      panelHeight: fc.integer({ min: 1, max: 3000 }),
    })
    .map(({ viewportWidth, viewportHeight, topFraction, leftFraction, panelHeight }) => {
      const top = Math.round(topFraction * (viewportHeight - 24));
      const left = Math.round(leftFraction * (viewportWidth - 24));
      return {
        trigger: { top, bottom: top + 24, left },
        panel: { width: 384, height: panelHeight },
        viewport: { width: viewportWidth, height: viewportHeight },
      };
    })
    .filter(({ trigger, viewport }) => {
      const below = viewport.height - 16 - (trigger.bottom + 8);
      const above = trigger.top - 8 - 16;
      return Math.max(below, above) >= 120;
    });

  it('never covers its trigger and never leaves the viewport when there is room', () => {
    fc.assert(
      fc.property(roomyLayout, (layout) => {
        const { top, maxHeight, side } = placePopover(layout);
        const shown = Math.min(layout.panel.height, maxHeight);
        expect(top).toBeGreaterThanOrEqual(16);
        expect(top + shown).toBeLessThanOrEqual(layout.viewport.height - 16);
        if (side === 'bottom') expect(top).toBeGreaterThanOrEqual(layout.trigger.bottom + 8);
        else expect(top + shown).toBeLessThanOrEqual(layout.trigger.top - 8);
      }),
      propertyRun({ numRuns: PROPERTY_RUNS }),
    );
  });

  it('shows the whole panel below, uncapped, whenever it fits there', () => {
    fc.assert(
      fc.property(roomyLayout, (layout) => {
        const below = layout.viewport.height - 16 - (layout.trigger.bottom + 8);
        fc.pre(layout.panel.height <= below);
        const { top, maxHeight, side } = placePopover(layout);
        expect(side).toBe('bottom');
        expect(top).toBe(layout.trigger.bottom + 8);
        expect(maxHeight).toBeGreaterThanOrEqual(layout.panel.height);
      }),
      propertyRun({ numRuns: PROPERTY_RUNS }),
    );
  });

  it('keeps the panel between the side margins whenever the viewport is wide enough', () => {
    fc.assert(
      fc.property(roomyLayout, (layout) => {
        const { left } = placePopover(layout);
        expect(left).toBeGreaterThanOrEqual(16);
        expect(left + layout.panel.width).toBeLessThanOrEqual(layout.viewport.width - 16);
      }),
      propertyRun({ numRuns: PROPERTY_RUNS }),
    );
  });
});
