/**
 * The help toggletip (`InfoTip`): a question-mark button whose panel explains a
 * setting.
 *
 * What is pinned here is WCAG 1.4.13 as the component promises it: a resting
 * mouse opens the panel without taking focus (and touch never does, since the
 * same tap also clicks), the panel can be hovered, Escape dismisses it from
 * anywhere, and a click, tap, Enter or Space pins it until dismissed, with focus
 * moved in and handed back to the trigger on the way out. Plus the wiring a
 * screen reader depends on, the placement it is given, and the lazy body.
 *
 * jsdom has no layout, so every box measures zero unless a test says otherwise;
 * the placement RULES are pinned in `tests/lib/popoverPlacement.test.ts`, and
 * here only that the panel is placed from the trigger, the panel and the window.
 *
 * The panel is a lazy chunk (`InfoTipPanel`). The `beforeAll` below opens one
 * panel and waits for it, which resolves that lazy component for the whole file,
 * so every test here sees the panel render in the same act as the event that
 * opened it, in any order the runner picks. The first open, while the chunk is
 * still on its way, is pinned on its own in `InfoTip.coldStart.test.tsx`.
 */
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { lazy, type ComponentType } from 'react';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { InfoTip } from '../../src/components/ui/InfoTip';

const LABEL = 'Help: what this setting does';
const TITLE = 'This setting, explained';

beforeAll(async () => {
  render(
    <InfoTip label="Warm-up" title="Warm-up">
      <p>Warm-up</p>
    </InfoTip>,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Warm-up' }));
  await screen.findByRole('dialog', { name: 'Warm-up' });
  cleanup();
});

function renderTip(props: { onPreload?: () => unknown } = {}) {
  return render(
    <>
      <button type="button">Before</button>
      <InfoTip label={LABEL} title={TITLE} {...props}>
        <p>Plain words about the setting.</p>
      </InfoTip>
      <button type="button">After</button>
    </>,
  );
}

const trigger = () => screen.getByRole('button', { name: LABEL });
const panel = () => screen.getByRole('dialog', { name: TITLE });
const panelShown = () => screen.queryByRole('dialog') !== null;

const MOUSE = { pointerType: 'mouse' } as const;

/** Advances the faked `setTimeout` clock inside `act`, so the state it sets is flushed. */
function wait(ms: number) {
  act(() => {
    vi.advanceTimersByTime(ms);
  });
}

function hoverOpen() {
  fireEvent.pointerEnter(trigger(), MOUSE);
  wait(150);
}

describe('InfoTip: a resting mouse', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('opens the panel after 150 ms, not before, and leaves focus where it was', () => {
    renderTip();
    const before = screen.getByRole('button', { name: 'Before' });
    before.focus();

    fireEvent.pointerEnter(trigger(), MOUSE);
    wait(149);
    expect(panelShown()).toBe(false);
    expect(trigger().getAttribute('aria-expanded')).toBe('false');

    wait(1);
    expect(panel()).toBeInTheDocument();
    expect(trigger().getAttribute('aria-expanded')).toBe('true');
    expect(document.activeElement).toBe(before);
  });

  it('closes the panel 200 ms after the mouse leaves the trigger, not before', () => {
    renderTip();
    hoverOpen();

    fireEvent.pointerLeave(trigger(), MOUSE);
    wait(199);
    expect(panelShown()).toBe(true);

    wait(1);
    expect(panelShown()).toBe(false);
    expect(trigger().getAttribute('aria-expanded')).toBe('false');
    expect(vi.getTimerCount()).toBe(0);
  });

  it('abandons the open when the mouse leaves before the delay is up', () => {
    renderTip();
    fireEvent.pointerEnter(trigger(), MOUSE);
    wait(100);
    fireEvent.pointerLeave(trigger(), MOUSE);
    expect(vi.getTimerCount()).toBe(0);

    wait(1_000);
    expect(panelShown()).toBe(false);
  });

  it('never opens for a touch or a pen resting on the trigger', () => {
    renderTip();
    fireEvent.pointerEnter(trigger(), { pointerType: 'touch' });
    fireEvent.pointerEnter(trigger(), { pointerType: 'pen' });
    expect(vi.getTimerCount()).toBe(0);

    wait(1_000);
    expect(panelShown()).toBe(false);
  });

  it('stays open while the mouse travels from the trigger onto the panel, and closes once it leaves the panel', () => {
    renderTip();
    hoverOpen();

    fireEvent.pointerLeave(trigger(), MOUSE);
    wait(100);
    fireEvent.pointerEnter(panel(), MOUSE);
    wait(1_000);
    expect(panelShown()).toBe(true);

    fireEvent.pointerLeave(panel(), MOUSE);
    wait(199);
    expect(panelShown()).toBe(true);
    wait(1);
    expect(panelShown()).toBe(false);
  });

  it('stays open when the mouse comes back to the trigger within the grace period', () => {
    renderTip();
    hoverOpen();

    fireEvent.pointerLeave(trigger(), MOUSE);
    wait(150);
    fireEvent.pointerEnter(trigger(), MOUSE);
    wait(1_000);
    expect(panelShown()).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('closes on Escape pressed anywhere, without moving focus', () => {
    renderTip();
    const before = screen.getByRole('button', { name: 'Before' });
    before.focus();
    hoverOpen();

    fireEvent.keyDown(before, { key: 'Escape' });
    expect(panelShown()).toBe(false);
    expect(document.activeElement).toBe(before);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('ignores any other key pressed on the page', () => {
    renderTip();
    hoverOpen();

    fireEvent.keyDown(document, { key: 'a' });
    expect(panelShown()).toBe(true);
  });

  it('stays once the panel is pressed, so the mouse can then leave it', () => {
    renderTip();
    hoverOpen();

    fireEvent.pointerDown(panel(), MOUSE);
    fireEvent.pointerLeave(panel(), MOUSE);
    wait(1_000);
    expect(panelShown()).toBe(true);
    expect(trigger().getAttribute('aria-expanded')).toBe('true');
  });

  it('pins a hover-opened panel when the trigger is clicked, and moves focus into it', () => {
    renderTip();
    hoverOpen();

    fireEvent.click(trigger());
    expect(document.activeElement).toBe(panel());

    fireEvent.pointerLeave(trigger(), MOUSE);
    wait(1_000);
    expect(panelShown()).toBe(true);
  });

  it('leaves no timer behind when it unmounts with an open or a close pending', () => {
    const opening = renderTip();
    fireEvent.pointerEnter(trigger(), MOUSE);
    expect(vi.getTimerCount()).toBe(1);
    opening.unmount();
    expect(vi.getTimerCount()).toBe(0);

    const closing = renderTip();
    hoverOpen();
    fireEvent.pointerLeave(trigger(), MOUSE);
    expect(vi.getTimerCount()).toBe(1);
    closing.unmount();
    expect(vi.getTimerCount()).toBe(0);
    expect(panelShown()).toBe(false);
  });
});

describe('InfoTip: a click, a tap, Enter or Space', () => {
  it('pins the panel open and moves focus into it', () => {
    renderTip();
    fireEvent.click(trigger());

    expect(document.activeElement).toBe(panel());
    expect(trigger().getAttribute('aria-expanded')).toBe('true');
  });

  it('closes on a second click and hands focus back to the trigger', () => {
    renderTip();
    fireEvent.click(trigger());
    fireEvent.click(trigger());

    expect(panelShown()).toBe(false);
    expect(document.activeElement).toBe(trigger());
    expect(trigger().getAttribute('aria-expanded')).toBe('false');
  });

  it('does not pull focus back from another control when the second click closes it', () => {
    renderTip();
    fireEvent.click(trigger());
    const after = screen.getByRole('button', { name: 'After' });
    after.focus();
    fireEvent.click(trigger());

    expect(panelShown()).toBe(false);
    expect(document.activeElement).toBe(after);
  });

  it('closes on Escape and returns focus to the trigger', () => {
    renderTip();
    fireEvent.click(trigger());
    fireEvent.keyDown(panel(), { key: 'Escape' });

    expect(panelShown()).toBe(false);
    expect(document.activeElement).toBe(trigger());
  });

  it('closes on Tab and puts focus on the trigger, leaving the browser to move on from there', () => {
    renderTip();
    fireEvent.click(trigger());
    const notCancelled = fireEvent.keyDown(panel(), { key: 'Tab' });

    expect(notCancelled).toBe(true);
    expect(panelShown()).toBe(false);
    expect(document.activeElement).toBe(trigger());
  });

  it('closes on Shift+Tab and stops focus on the trigger', () => {
    renderTip();
    fireEvent.click(trigger());
    const notCancelled = fireEvent.keyDown(panel(), { key: 'Tab', shiftKey: true });

    expect(notCancelled).toBe(false);
    expect(panelShown()).toBe(false);
    expect(document.activeElement).toBe(trigger());
  });

  it('keeps the panel and its focus for any other key pressed inside it', () => {
    renderTip();
    fireEvent.click(trigger());
    const notCancelled = fireEvent.keyDown(panel(), { key: 'ArrowDown' });

    expect(notCancelled).toBe(true);
    expect(document.activeElement).toBe(panel());
  });

  it('closes on a press outside, without moving focus to the trigger', () => {
    renderTip();
    fireEvent.click(trigger());
    fireEvent.pointerDown(trigger(), MOUSE);
    fireEvent.pointerDown(panel(), MOUSE);
    expect(panelShown()).toBe(true);

    fireEvent.pointerDown(screen.getByRole('button', { name: 'After' }), MOUSE);
    expect(panelShown()).toBe(false);
    expect(document.activeElement).not.toBe(trigger());
  });
});

describe('InfoTip: what assistive technology is told', () => {
  it('names the trigger, says it opens a dialog, and keeps its icon silent', () => {
    renderTip();
    const button = trigger();

    expect(button.getAttribute('type')).toBe('button');
    expect(button.getAttribute('aria-haspopup')).toBe('dialog');
    expect(button.getAttribute('aria-expanded')).toBe('false');
    // Nothing to point at while closed.
    expect(button.hasAttribute('aria-controls')).toBe(false);
    expect(button.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');
  });

  it('points the trigger at a dialog named by its level-2 title, portalled to the body', () => {
    renderTip();
    fireEvent.click(trigger());
    const dialog = panel();
    const heading = screen.getByRole('heading', { level: 2, name: TITLE });

    expect(trigger().getAttribute('aria-controls')).toBe(dialog.id);
    expect(dialog.getAttribute('aria-labelledby')).toBe(heading.id);
    expect(dialog.getAttribute('tabindex')).toBe('-1');
    expect(dialog.parentElement).toBe(document.body);
    expect(dialog).toHaveTextContent('Plain words about the setting.');
  });
});

describe('InfoTip: placement', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('places the panel at fixed coordinates worked out from the trigger and the window', () => {
    renderTip();
    fireEvent.click(trigger());
    const { style } = panel();

    // A zero-sized trigger at the origin of jsdom's 1024 x 768 window: one gap
    // below it, held off the left edge by the margin, capped to the room below.
    expect(style.top).toBe('8px');
    expect(style.left).toBe('16px');
    expect(style.maxHeight).toBe('744px');
    expect(style.visibility).toBe('');
    // 24rem, or the window less its two margins on a phone.
    expect(style.width).toMatch(/^min\(24rem, /);
  });

  it('places it afresh after a resize or any scroll, once per frame, but not when the panel scrolls itself', () => {
    const frames: FrameRequestCallback[] = [];
    vi.spyOn(window, 'requestAnimationFrame').mockImplementation((callback) =>
      frames.push(callback),
    );
    const cancel = vi.spyOn(window, 'cancelAnimationFrame');
    renderTip();
    fireEvent.click(trigger());
    const rect = vi.spyOn(trigger(), 'getBoundingClientRect');

    rect.mockReturnValue(DOMRect.fromRect({ x: 100, y: 300, width: 24, height: 24 }));
    fireEvent(window, new Event('resize'));
    fireEvent(window, new Event('resize'));
    expect(frames).toHaveLength(1);
    act(() => {
      frames[0]!(0);
    });
    expect(panel().style.top).toBe('332px');
    expect(panel().style.left).toBe('100px');

    rect.mockReturnValue(DOMRect.fromRect({ x: 60, y: 200, width: 24, height: 24 }));
    // Scroll does not bubble: only a capturing listener hears a scrolling region.
    const region = screen.getByRole('button', { name: 'After' });
    fireEvent.scroll(region);
    expect(frames).toHaveLength(2);
    act(() => {
      frames[1]!(0);
    });
    expect(panel().style.top).toBe('232px');

    fireEvent.scroll(panel());
    expect(frames).toHaveLength(2);

    // Closing with a placement still pending cancels it.
    fireEvent(window, new Event('resize'));
    expect(frames).toHaveLength(3);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(cancel).toHaveBeenCalledWith(3);
  });
});

describe('InfoTip: a lazy body', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('shows a spinner until the body arrives, then the body, and places the panel again for its new size', async () => {
    // The trigger sits low in the window: 120 px of room below, 576 above.
    let deliver: (module: { default: ComponentType }) => void = () => undefined;
    const Body = lazy(
      () =>
        new Promise<{ default: ComponentType }>((resolve) => {
          deliver = resolve;
        }),
    );
    vi.spyOn(Element.prototype, 'scrollHeight', 'get').mockImplementation(function (this: Element) {
      return this.textContent.includes('Loaded body') ? 300 : 40;
    });
    render(
      <InfoTip label={LABEL} title={TITLE}>
        <Body />
      </InfoTip>,
    );
    vi.spyOn(trigger(), 'getBoundingClientRect').mockReturnValue(
      DOMRect.fromRect({ x: 40, y: 600, width: 24, height: 24 }),
    );

    fireEvent.click(trigger());
    expect(screen.getByRole('status', { name: 'Loading' })).toBeInTheDocument();
    // The spinner fits below the trigger.
    expect(panel().style.top).toBe('632px');
    expect(panel().style.maxHeight).toBe('120px');
    expect(panel().style.transformOrigin).toBe('top left');

    await act(async () => {
      deliver({ default: () => <p>Loaded body</p> });
      await Promise.resolve();
    });
    expect(await screen.findByText('Loaded body')).toBeInTheDocument();
    expect(screen.queryByRole('status')).toBeNull();
    // The body does not: the panel flips above, its bottom one gap over the trigger.
    expect(panel().style.top).toBe('292px');
    expect(panel().style.maxHeight).toBe('576px');
    expect(panel().style.transformOrigin).toBe('bottom left');
  });
});

describe('InfoTip: preloading', () => {
  it('asks for the body once, however many ways the trigger is approached', () => {
    const onPreload = vi.fn();
    renderTip({ onPreload });

    fireEvent.pointerEnter(trigger(), { pointerType: 'touch' });
    expect(onPreload).toHaveBeenCalledTimes(1);
    fireEvent.focus(trigger());
    fireEvent.click(trigger());
    fireEvent.click(trigger());
    expect(onPreload).toHaveBeenCalledTimes(1);
  });

  it('asks on keyboard focus alone, before anything opens', () => {
    const onPreload = vi.fn();
    renderTip({ onPreload });

    fireEvent.focus(trigger());
    expect(onPreload).toHaveBeenCalledTimes(1);
    expect(panelShown()).toBe(false);
  });

  it('asks on a press alone', () => {
    const onPreload = vi.fn();
    renderTip({ onPreload });

    fireEvent.click(trigger());
    expect(onPreload).toHaveBeenCalledTimes(1);
  });

  it('lets a failed preload go without an unhandled rejection', async () => {
    const unhandled = vi.fn();
    process.on('unhandledRejection', unhandled);
    try {
      // A plain function rather than a mock: a mock's returned promise always
      // counts as handled, which would hide the very rejection this looks for.
      renderTip({ onPreload: () => Promise.reject(new Error('chunk failed to load')) });
      fireEvent.focus(trigger());
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(unhandled).not.toHaveBeenCalled();
    } finally {
      process.off('unhandledRejection', unhandled);
    }
  });
});
