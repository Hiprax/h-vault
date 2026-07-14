/**
 * Behavioral coverage for the primitive UI components.
 *
 * Focus: the branches the existing suites leave untested — the DropdownMenu
 * roving-focus keyboard contract (wrap-around, disabled-item skipping, Escape
 * focus restoration, click-outside), the Dialog focus trap / scroll-lock
 * reference count / focus restoration and the `useInlineDialog` hook, plus the
 * Tabs, OtpInput, Input and Label edge branches.
 *
 * Deliberately does NOT duplicate tests/ui-components.test.tsx,
 * tests/accessibility-phase8.test.tsx or tests/components/OtpInput.test.tsx.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { createRef, useRef, useState } from 'react';

import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from '../src/components/ui/DropdownMenu';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  useInlineDialog,
  _resetScrollLockCount,
} from '../src/components/ui/Dialog';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../src/components/ui/Tabs';
import { OtpInput } from '../src/components/ui/OtpInput';
import { Input } from '../src/components/ui/Input';
import { Label } from '../src/components/ui/Label';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from '../src/components/ui/Card';
import { ToastProvider, useToast } from '../src/components/ui/Toast';

/* ========================================================================== */
/*  DropdownMenu — keyboard contract (WCAG 2.1.1)                             */
/* ========================================================================== */

describe('DropdownMenu', () => {
  function openMenu(): HTMLElement {
    const trigger = screen.getByRole('button', { name: 'Open' });
    trigger.focus();
    fireEvent.click(trigger);
    return trigger;
  }

  describe('roving focus', () => {
    function renderThreeItems() {
      render(
        <DropdownMenu>
          <DropdownMenuTrigger>Open</DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>Alpha</DropdownMenuItem>
            <DropdownMenuItem>Beta</DropdownMenuItem>
            <DropdownMenuItem>Gamma</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>,
      );
      const trigger = openMenu();
      return { trigger, items: screen.getAllByRole('menuitem') };
    }

    it('wraps focus from the last item back to the first on ArrowDown', () => {
      const { items } = renderThreeItems();
      const last = items[2]!;
      last.focus();

      fireEvent.keyDown(last, { key: 'ArrowDown' });

      expect(document.activeElement).toBe(items[0]);
      expect(screen.getByRole('menu')).toHaveAttribute('aria-activedescendant', items[0]!.id);
    });

    it('wraps focus from the first item to the last on ArrowUp', () => {
      const { items } = renderThreeItems();
      // Focus lands on the first item automatically on open.
      expect(document.activeElement).toBe(items[0]);

      fireEvent.keyDown(items[0]!, { key: 'ArrowUp' });

      expect(document.activeElement).toBe(items[2]);
      expect(screen.getByRole('menu')).toHaveAttribute('aria-activedescendant', items[2]!.id);
    });

    it('Home focuses the first item and End focuses the last', () => {
      const { items } = renderThreeItems();
      items[1]!.focus();

      fireEvent.keyDown(items[1]!, { key: 'End' });
      expect(document.activeElement).toBe(items[2]);
      expect(screen.getByRole('menu')).toHaveAttribute('aria-activedescendant', items[2]!.id);

      fireEvent.keyDown(items[2]!, { key: 'Home' });
      expect(document.activeElement).toBe(items[0]);
      expect(screen.getByRole('menu')).toHaveAttribute('aria-activedescendant', items[0]!.id);
    });

    it('leaves focus untouched for a key it does not handle', () => {
      const { items } = renderThreeItems();
      items[1]!.focus();

      fireEvent.keyDown(items[1]!, { key: 'a' });

      expect(document.activeElement).toBe(items[1]);
    });
  });

  describe('disabled items', () => {
    it('focuses the first ENABLED item on open, skipping a leading disabled item', () => {
      render(
        <DropdownMenu>
          <DropdownMenuTrigger>Open</DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem disabled>Disabled first</DropdownMenuItem>
            <DropdownMenuItem>Enabled second</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>,
      );
      openMenu();

      expect(document.activeElement).toBe(screen.getByRole('menuitem', { name: 'Enabled second' }));
    });

    it('skips a disabled item when navigating with ArrowDown/ArrowUp', () => {
      render(
        <DropdownMenu>
          <DropdownMenuTrigger>Open</DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>Alpha</DropdownMenuItem>
            <DropdownMenuItem disabled>Beta</DropdownMenuItem>
            <DropdownMenuItem>Gamma</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>,
      );
      openMenu();

      const alpha = screen.getByRole('menuitem', { name: 'Alpha' });
      const gamma = screen.getByRole('menuitem', { name: 'Gamma' });
      expect(document.activeElement).toBe(alpha);

      // ArrowDown must jump straight over the disabled Beta.
      fireEvent.keyDown(alpha, { key: 'ArrowDown' });
      expect(document.activeElement).toBe(gamma);

      // ArrowUp back over it again.
      fireEvent.keyDown(gamma, { key: 'ArrowUp' });
      expect(document.activeElement).toBe(alpha);
    });

    it('also skips an aria-disabled item', () => {
      render(
        <DropdownMenu>
          <DropdownMenuTrigger>Open</DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem aria-disabled="true">Soft disabled</DropdownMenuItem>
            <DropdownMenuItem>Real</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>,
      );
      openMenu();

      expect(document.activeElement).toBe(screen.getByRole('menuitem', { name: 'Real' }));
    });

    it('leaves focus on the trigger and sets no aria-activedescendant when no item is enabled', () => {
      render(
        <DropdownMenu>
          <DropdownMenuTrigger>Open</DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem disabled>Only disabled</DropdownMenuItem>
            <DropdownMenuSeparator />
          </DropdownMenuContent>
        </DropdownMenu>,
      );
      const trigger = openMenu();

      expect(document.activeElement).toBe(trigger);
      const menu = screen.getByRole('menu');
      expect(menu).not.toHaveAttribute('aria-activedescendant');

      // A key press with no navigable items must not throw or move focus.
      fireEvent.keyDown(menu, { key: 'ArrowDown' });
      expect(document.activeElement).toBe(trigger);
    });
  });

  describe('open / close', () => {
    it('toggles open state and aria-expanded on the trigger, and calls the caller onClick', () => {
      const onClick = vi.fn();
      render(
        <DropdownMenu>
          <DropdownMenuTrigger onClick={onClick}>Open</DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>Alpha</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>,
      );

      const trigger = screen.getByRole('button', { name: 'Open' });
      expect(trigger).toHaveAttribute('aria-expanded', 'false');
      expect(screen.queryByRole('menu')).not.toBeInTheDocument();

      fireEvent.click(trigger);
      expect(trigger).toHaveAttribute('aria-expanded', 'true');
      expect(screen.getByRole('menu')).toBeInTheDocument();

      fireEvent.click(trigger);
      expect(trigger).toHaveAttribute('aria-expanded', 'false');
      expect(screen.queryByRole('menu')).not.toBeInTheDocument();
      expect(onClick).toHaveBeenCalledTimes(2);
    });

    it('Escape closes the menu and restores focus to the trigger', () => {
      render(
        <DropdownMenu>
          <DropdownMenuTrigger>Open</DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>Alpha</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>,
      );
      const trigger = openMenu();
      expect(document.activeElement).not.toBe(trigger);

      fireEvent.keyDown(document, { key: 'Escape' });

      expect(screen.queryByRole('menu')).not.toBeInTheDocument();
      expect(document.activeElement).toBe(trigger);
    });

    it('closes on a mousedown outside the menu and trigger', () => {
      render(
        <div>
          <DropdownMenu>
            <DropdownMenuTrigger>Open</DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuItem>Alpha</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <button type="button">Outside</button>
        </div>,
      );
      openMenu();
      expect(screen.getByRole('menu')).toBeInTheDocument();

      fireEvent.mouseDown(screen.getByRole('button', { name: 'Outside' }));

      expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    });

    it('stays open on a mousedown inside the menu content or on the trigger', () => {
      render(
        <DropdownMenu>
          <DropdownMenuTrigger>Open</DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuSeparator data-testid="sep" />
            <DropdownMenuItem>Alpha</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>,
      );
      const trigger = openMenu();

      fireEvent.mouseDown(screen.getByTestId('sep'));
      expect(screen.getByRole('menu')).toBeInTheDocument();

      fireEvent.mouseDown(trigger);
      expect(screen.getByRole('menu')).toBeInTheDocument();
    });

    it('closes after an item is activated and invokes the item handler', () => {
      const onSelect = vi.fn();
      render(
        <DropdownMenu>
          <DropdownMenuTrigger>Open</DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem onClick={onSelect}>Alpha</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>,
      );
      openMenu();

      fireEvent.click(screen.getByRole('menuitem', { name: 'Alpha' }));

      expect(onSelect).toHaveBeenCalledTimes(1);
      expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    });

    it('stops listening for outside clicks once closed', () => {
      render(
        <DropdownMenu>
          <DropdownMenuTrigger>Open</DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>Alpha</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>,
      );
      const trigger = openMenu();
      fireEvent.keyDown(document, { key: 'Escape' });
      expect(screen.queryByRole('menu')).not.toBeInTheDocument();

      // A stray Escape while closed must not re-steal focus or throw.
      trigger.blur();
      fireEvent.keyDown(document, { key: 'Escape' });
      expect(document.activeElement).not.toBe(trigger);
    });
  });

  describe('rendering options', () => {
    it('aligns to the right by default and to the left with align="start"', () => {
      const { unmount } = render(
        <DropdownMenu>
          <DropdownMenuTrigger>Open</DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>Alpha</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>,
      );
      openMenu();
      expect(screen.getByRole('menu').className).toContain('right-0');
      unmount();

      render(
        <DropdownMenu>
          <DropdownMenuTrigger>Open</DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            <DropdownMenuItem>Alpha</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>,
      );
      openMenu();
      const menu = screen.getByRole('menu');
      expect(menu.className).toContain('left-0');
      expect(menu.className).not.toContain('right-0');
    });

    it('forwards refs on the trigger (object ref) and the content (callback ref)', () => {
      const triggerRef = createRef<HTMLButtonElement>();
      const contentRef = vi.fn();
      render(
        <DropdownMenu>
          <DropdownMenuTrigger ref={triggerRef}>Open</DropdownMenuTrigger>
          <DropdownMenuContent ref={contentRef}>
            <DropdownMenuItem>Alpha</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>,
      );

      expect(triggerRef.current).toBe(screen.getByRole('button', { name: 'Open' }));

      openMenu();
      expect(contentRef).toHaveBeenCalledWith(screen.getByRole('menu'));
    });

    it('applies inset padding only when inset is set', () => {
      render(
        <DropdownMenu>
          <DropdownMenuTrigger>Open</DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem inset>Inset</DropdownMenuItem>
            <DropdownMenuItem>Flush</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>,
      );
      openMenu();

      expect(screen.getByRole('menuitem', { name: 'Inset' }).className).toContain('pl-8');
      expect(screen.getByRole('menuitem', { name: 'Flush' }).className).not.toContain('pl-8');
    });

    it('calls a caller-supplied onFocus in addition to tracking the active descendant', () => {
      const onFocus = vi.fn();
      render(
        <DropdownMenu>
          <DropdownMenuTrigger>Open</DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem onFocus={onFocus}>Alpha</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>,
      );
      openMenu();

      const item = screen.getByRole('menuitem', { name: 'Alpha' });
      expect(onFocus).toHaveBeenCalledTimes(1);
      expect(screen.getByRole('menu')).toHaveAttribute('aria-activedescendant', item.id);
    });

    it('throws a helpful error when a compound part is used outside <DropdownMenu>', () => {
      const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => render(<DropdownMenuItem>Orphan</DropdownMenuItem>)).toThrow(
        /must be used within a <DropdownMenu> parent/,
      );
      spy.mockRestore();
    });
  });
});

/* ========================================================================== */
/*  Dialog                                                                    */
/* ========================================================================== */

describe('Dialog', () => {
  beforeEach(() => {
    _resetScrollLockCount();
  });

  afterEach(() => {
    _resetScrollLockCount();
  });

  it('closes when the backdrop is clicked', () => {
    const onOpenChange = vi.fn();
    render(
      <Dialog open onOpenChange={onOpenChange}>
        <DialogContent>
          <DialogTitle>Title</DialogTitle>
        </DialogContent>
      </Dialog>,
    );

    const backdrop = screen.getByRole('dialog').parentElement!.firstElementChild!;
    expect(backdrop).toHaveAttribute('aria-hidden', 'true');

    fireEvent.click(backdrop);

    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('locks body scroll while open and releases it on close', () => {
    const { rerender } = render(
      <Dialog open onOpenChange={vi.fn()}>
        <DialogContent>
          <DialogTitle>Title</DialogTitle>
        </DialogContent>
      </Dialog>,
    );
    expect(document.body.style.overflow).toBe('hidden');

    rerender(
      <Dialog open={false} onOpenChange={vi.fn()}>
        <DialogContent>
          <DialogTitle>Title</DialogTitle>
        </DialogContent>
      </Dialog>,
    );
    expect(document.body.style.overflow).toBe('');
  });

  it('reference-counts the scroll lock so closing one of two dialogs keeps it locked', () => {
    const { rerender } = render(
      <>
        <Dialog open onOpenChange={vi.fn()}>
          <DialogContent>
            <DialogTitle>One</DialogTitle>
          </DialogContent>
        </Dialog>
        <Dialog open onOpenChange={vi.fn()}>
          <DialogContent>
            <DialogTitle>Two</DialogTitle>
          </DialogContent>
        </Dialog>
      </>,
    );
    expect(document.body.style.overflow).toBe('hidden');

    rerender(
      <>
        <Dialog open onOpenChange={vi.fn()}>
          <DialogContent>
            <DialogTitle>One</DialogTitle>
          </DialogContent>
        </Dialog>
        <Dialog open={false} onOpenChange={vi.fn()}>
          <DialogContent>
            <DialogTitle>Two</DialogTitle>
          </DialogContent>
        </Dialog>
      </>,
    );
    // The still-open dialog must keep the body locked.
    expect(document.body.style.overflow).toBe('hidden');

    rerender(
      <>
        <Dialog open={false} onOpenChange={vi.fn()}>
          <DialogContent>
            <DialogTitle>One</DialogTitle>
          </DialogContent>
        </Dialog>
        <Dialog open={false} onOpenChange={vi.fn()}>
          <DialogContent>
            <DialogTitle>Two</DialogTitle>
          </DialogContent>
        </Dialog>
      </>,
    );
    expect(document.body.style.overflow).toBe('');
  });

  it('auto-focuses the first focusable element inside the content', () => {
    render(
      <Dialog open onOpenChange={vi.fn()}>
        <DialogContent>
          <DialogTitle>Title</DialogTitle>
          <input aria-label="Name" />
          <button type="button">Save</button>
        </DialogContent>
      </Dialog>,
    );

    expect(document.activeElement).toBe(screen.getByLabelText('Name'));
  });

  it('focuses the dialog itself when it holds no focusable element', () => {
    render(
      <Dialog open onOpenChange={vi.fn()}>
        <DialogContent>
          <DialogTitle>Title</DialogTitle>
          <DialogDescription>Nothing to focus</DialogDescription>
        </DialogContent>
      </Dialog>,
    );

    const dialog = screen.getByRole('dialog');
    expect(document.activeElement).toBe(dialog);
    expect(dialog).toHaveAttribute('aria-describedby', screen.getByText('Nothing to focus').id);
  });

  it('swallows Tab when there is nothing focusable to trap', () => {
    render(
      <Dialog open onOpenChange={vi.fn()}>
        <DialogContent>
          <DialogTitle>Title</DialogTitle>
        </DialogContent>
      </Dialog>,
    );

    const dialog = screen.getByRole('dialog');
    // fireEvent returns false when the handler called preventDefault().
    const notPrevented = fireEvent.keyDown(dialog, { key: 'Tab' });
    expect(notPrevented).toBe(false);
  });

  it('wraps Shift+Tab from the first focusable element to the last', () => {
    render(
      <Dialog open onOpenChange={vi.fn()}>
        <DialogContent>
          <button type="button">First</button>
          <button type="button">Middle</button>
          <button type="button">Last</button>
        </DialogContent>
      </Dialog>,
    );

    const first = screen.getByRole('button', { name: 'First' });
    const last = screen.getByRole('button', { name: 'Last' });
    first.focus();

    fireEvent.keyDown(first, { key: 'Tab', shiftKey: true });

    expect(document.activeElement).toBe(last);
  });

  it('does not intercept Tab from a middle element (native order is preserved)', () => {
    render(
      <Dialog open onOpenChange={vi.fn()}>
        <DialogContent>
          <button type="button">First</button>
          <button type="button">Middle</button>
          <button type="button">Last</button>
        </DialogContent>
      </Dialog>,
    );

    const middle = screen.getByRole('button', { name: 'Middle' });
    middle.focus();

    const notPrevented = fireEvent.keyDown(middle, { key: 'Tab' });

    expect(notPrevented).toBe(true);
    expect(document.activeElement).toBe(middle);
  });

  it('ignores non-Tab keys in the focus trap', () => {
    render(
      <Dialog open onOpenChange={vi.fn()}>
        <DialogContent>
          <button type="button">First</button>
          <button type="button">Last</button>
        </DialogContent>
      </Dialog>,
    );

    const last = screen.getByRole('button', { name: 'Last' });
    last.focus();

    fireEvent.keyDown(last, { key: 'ArrowDown' });

    expect(document.activeElement).toBe(last);
  });

  it('restores focus to the element that opened it when it closes', async () => {
    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>
            Launch
          </button>
          <Dialog open={open} onOpenChange={setOpen}>
            <DialogContent>
              <DialogTitle>Title</DialogTitle>
              <button type="button" onClick={() => setOpen(false)}>
                Done
              </button>
            </DialogContent>
          </Dialog>
        </>
      );
    }
    render(<Harness />);

    const launch = screen.getByRole('button', { name: 'Launch' });
    launch.focus();
    fireEvent.click(launch);

    const done = screen.getByRole('button', { name: 'Done' });
    expect(document.activeElement).toBe(done);

    fireEvent.click(done);

    await waitFor(() => {
      expect(document.activeElement).toBe(launch);
    });
  });

  it('renders the close button only when onClose is supplied and invokes it', () => {
    const onClose = vi.fn();
    const { unmount } = render(
      <Dialog open onOpenChange={vi.fn()}>
        <DialogContent onClose={onClose}>
          <DialogTitle>Title</DialogTitle>
        </DialogContent>
      </Dialog>,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(onClose).toHaveBeenCalledTimes(1);
    unmount();

    render(
      <Dialog open onOpenChange={vi.fn()}>
        <DialogContent>
          <DialogTitle>Title</DialogTitle>
          <DialogFooter>
            <button type="button">Ok</button>
          </DialogFooter>
        </DialogContent>
      </Dialog>,
    );
    expect(screen.queryByRole('button', { name: 'Close' })).not.toBeInTheDocument();
  });

  it('forwards a ref to the dialog element', () => {
    const ref = createRef<HTMLDivElement>();
    render(
      <Dialog open onOpenChange={vi.fn()}>
        <DialogContent ref={ref}>
          <DialogTitle>Title</DialogTitle>
        </DialogContent>
      </Dialog>,
    );

    expect(ref.current).toBe(screen.getByRole('dialog'));
  });

  it('renders nothing at all while closed', () => {
    render(
      <Dialog open={false} onOpenChange={vi.fn()}>
        <DialogContent>
          <DialogTitle>Hidden</DialogTitle>
        </DialogContent>
      </Dialog>,
    );

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.queryByText('Hidden')).not.toBeInTheDocument();
    expect(document.body.style.overflow).toBe('');
  });
});

/* ========================================================================== */
/*  useInlineDialog                                                           */
/* ========================================================================== */

describe('useInlineDialog', () => {
  beforeEach(() => {
    _resetScrollLockCount();
  });

  afterEach(() => {
    _resetScrollLockCount();
  });

  function InlineHarness({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
    const ref = useRef<HTMLDivElement | null>(null);
    useInlineDialog(ref, isOpen, onClose);
    if (!isOpen) return <button type="button">Opener</button>;
    return (
      <div ref={ref} role="dialog" aria-label="Inline">
        <button type="button">First</button>
        <button type="button">Last</button>
      </div>
    );
  }

  it('auto-focuses the first focusable element and locks body scroll when opened', () => {
    const { rerender } = render(<InlineHarness isOpen={false} onClose={vi.fn()} />);
    expect(document.body.style.overflow).toBe('');

    rerender(<InlineHarness isOpen onClose={vi.fn()} />);

    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'First' }));
    expect(document.body.style.overflow).toBe('hidden');
  });

  it('releases the body scroll lock when closed', () => {
    const { rerender } = render(<InlineHarness isOpen onClose={vi.fn()} />);
    expect(document.body.style.overflow).toBe('hidden');

    rerender(<InlineHarness isOpen={false} onClose={vi.fn()} />);

    expect(document.body.style.overflow).toBe('');
  });

  it('calls onClose on Escape while open, and not after it closes', () => {
    const onClose = vi.fn();
    const { rerender } = render(<InlineHarness isOpen onClose={onClose} />);

    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);

    // Other keys must not close it.
    fireEvent.keyDown(document, { key: 'Enter' });
    expect(onClose).toHaveBeenCalledTimes(1);

    rerender(<InlineHarness isOpen={false} onClose={onClose} />);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('traps Tab focus inside the inline container', () => {
    render(<InlineHarness isOpen onClose={vi.fn()} />);

    const first = screen.getByRole('button', { name: 'First' });
    const last = screen.getByRole('button', { name: 'Last' });

    last.focus();
    fireEvent.keyDown(last, { key: 'Tab' });
    expect(document.activeElement).toBe(first);

    fireEvent.keyDown(first, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(last);
  });
});

/* ========================================================================== */
/*  Tabs                                                                      */
/* ========================================================================== */

describe('Tabs', () => {
  it('skips a disabled trigger during arrow navigation and activates the next enabled tab', () => {
    const onValueChange = vi.fn();
    render(
      <Tabs value="tab1" onValueChange={onValueChange}>
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2" disabled>
            Tab 2
          </TabsTrigger>
          <TabsTrigger value="tab3">Tab 3</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>,
    );

    const tab1 = screen.getByRole('tab', { name: 'Tab 1' });
    const tab3 = screen.getByRole('tab', { name: 'Tab 3' });
    tab1.focus();

    fireEvent.keyDown(screen.getByRole('tablist'), { key: 'ArrowRight' });

    expect(document.activeElement).toBe(tab3);
    expect(onValueChange).toHaveBeenCalledWith('tab3');
    expect(onValueChange).not.toHaveBeenCalledWith('tab2');
  });

  it('honours a consumer onKeyDown that calls preventDefault (navigation is suppressed)', () => {
    const onValueChange = vi.fn();
    render(
      <Tabs value="tab1" onValueChange={onValueChange}>
        <TabsList
          onKeyDown={(e) => {
            e.preventDefault();
          }}
        >
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>,
    );

    const tab1 = screen.getByRole('tab', { name: 'Tab 1' });
    tab1.focus();

    fireEvent.keyDown(screen.getByRole('tablist'), { key: 'ArrowRight' });

    expect(document.activeElement).toBe(tab1);
    expect(onValueChange).not.toHaveBeenCalled();
  });

  it('ignores arrow keys when focus is not on one of the tabs', () => {
    const onValueChange = vi.fn();
    render(
      <>
        <button type="button">Elsewhere</button>
        <Tabs value="tab1" onValueChange={onValueChange}>
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
        </Tabs>
      </>,
    );

    const outside = screen.getByRole('button', { name: 'Elsewhere' });
    outside.focus();

    fireEvent.keyDown(screen.getByRole('tablist'), { key: 'ArrowRight' });

    expect(document.activeElement).toBe(outside);
    expect(onValueChange).not.toHaveBeenCalled();
  });

  it('ignores keys it does not handle', () => {
    const onValueChange = vi.fn();
    render(
      <Tabs value="tab1" onValueChange={onValueChange}>
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>,
    );

    const tab1 = screen.getByRole('tab', { name: 'Tab 1' });
    tab1.focus();

    fireEvent.keyDown(screen.getByRole('tablist'), { key: 'Enter' });

    expect(document.activeElement).toBe(tab1);
    expect(onValueChange).not.toHaveBeenCalled();
  });

  it('renders only the selected panel and marks the selected trigger', () => {
    const onValueChange = vi.fn();
    const { rerender } = render(
      <Tabs value="tab1" onValueChange={onValueChange}>
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
        <TabsContent value="tab2">Content 2</TabsContent>
      </Tabs>,
    );

    expect(screen.getByText('Content 1')).toBeInTheDocument();
    expect(screen.queryByText('Content 2')).not.toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Tab 1' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('tab', { name: 'Tab 2' })).toHaveAttribute('aria-selected', 'false');

    rerender(
      <Tabs value="tab2" onValueChange={onValueChange}>
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
        <TabsContent value="tab2">Content 2</TabsContent>
      </Tabs>,
    );

    expect(screen.queryByText('Content 1')).not.toBeInTheDocument();
    expect(screen.getByText('Content 2')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Tab 2' })).toHaveAttribute('tabindex', '0');
  });

  it('clicking a trigger reports the tab value to the caller', () => {
    const onValueChange = vi.fn();
    render(
      <Tabs value="tab1" onValueChange={onValueChange}>
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>,
    );

    fireEvent.click(screen.getByRole('tab', { name: 'Tab 2' }));

    expect(onValueChange).toHaveBeenCalledWith('tab2');
  });

  it('forwards an object ref on TabsList to the tablist element', () => {
    const ref = createRef<HTMLDivElement>();
    render(
      <Tabs value="tab1" onValueChange={vi.fn()}>
        <TabsList ref={ref}>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>,
    );

    expect(ref.current).toBe(screen.getByRole('tablist'));
  });
});

/* ========================================================================== */
/*  OtpInput                                                                  */
/* ========================================================================== */

describe('OtpInput', () => {
  it('advances focus to the next box after a digit is typed', () => {
    render(<OtpInput value="" onChange={vi.fn()} />);
    const inputs = screen.getAllByRole('textbox');

    fireEvent.change(inputs[0]!, { target: { value: '7' } });

    expect(document.activeElement).toBe(inputs[1]);
  });

  it('keeps only the last character when a box receives multiple characters', () => {
    const onChange = vi.fn();
    render(<OtpInput value="" onChange={onChange} />);
    const inputs = screen.getAllByRole('textbox');

    fireEvent.change(inputs[0]!, { target: { value: '49' } });

    expect(onChange).toHaveBeenCalledWith('9');
  });

  it('moves focus back to the previous box when backspacing an empty box', () => {
    render(<OtpInput value="12" onChange={vi.fn()} />);
    const inputs = screen.getAllByRole('textbox');

    fireEvent.keyDown(inputs[2]!, { key: 'Backspace' });

    expect(document.activeElement).toBe(inputs[1]);
  });

  it('clamps arrow navigation at both ends', () => {
    render(<OtpInput value="123456" onChange={vi.fn()} />);
    const inputs = screen.getAllByRole('textbox');

    inputs[0]!.focus();
    fireEvent.keyDown(inputs[0]!, { key: 'ArrowLeft' });
    expect(document.activeElement).toBe(inputs[0]);

    inputs[5]!.focus();
    fireEvent.keyDown(inputs[5]!, { key: 'ArrowRight' });
    expect(document.activeElement).toBe(inputs[5]);
  });

  it('ArrowRight/ArrowLeft move focus one box at a time', () => {
    render(<OtpInput value="123456" onChange={vi.fn()} />);
    const inputs = screen.getAllByRole('textbox');

    inputs[2]!.focus();
    fireEvent.keyDown(inputs[2]!, { key: 'ArrowRight' });
    expect(document.activeElement).toBe(inputs[3]);

    fireEvent.keyDown(inputs[3]!, { key: 'ArrowLeft' });
    expect(document.activeElement).toBe(inputs[2]);
  });

  it('truncates an over-long paste to the field length and parks focus on the last box', () => {
    const onChange = vi.fn();
    render(<OtpInput value="" onChange={onChange} />);
    const inputs = screen.getAllByRole('textbox');

    fireEvent.paste(inputs[0]!, { clipboardData: { getData: () => '123456789' } });

    expect(onChange).toHaveBeenCalledWith('123456');
    expect(document.activeElement).toBe(inputs[5]);
  });

  it('a short paste parks focus on the box after the last pasted digit', () => {
    render(<OtpInput value="" onChange={vi.fn()} />);
    const inputs = screen.getAllByRole('textbox');

    fireEvent.paste(inputs[0]!, { clipboardData: { getData: () => '123' } });

    expect(document.activeElement).toBe(inputs[3]);
  });

  it('renders a value longer than the field length truncated to the boxes available', () => {
    render(<OtpInput value="1234" onChange={vi.fn()} length={3} />);
    const inputs = screen.getAllByRole('textbox') as HTMLInputElement[];

    expect(inputs).toHaveLength(3);
    expect(inputs.map((i) => i.value)).toEqual(['1', '2', '3']);
  });

  it('autoFocus focuses only the first box', () => {
    render(<OtpInput value="" onChange={vi.fn()} autoFocus />);
    const inputs = screen.getAllByRole('textbox');

    expect(document.activeElement).toBe(inputs[0]);
  });
});

/* ========================================================================== */
/*  Input / Label / Card                                                      */
/* ========================================================================== */

describe('Input', () => {
  it('marks the field aria-invalid and applies the destructive border in the error state', () => {
    render(<Input error aria-label="Email" />);
    const input = screen.getByLabelText('Email');

    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input.className).toContain('border-[hsl(var(--destructive))]');
  });

  it('omits aria-invalid entirely when there is no error', () => {
    render(<Input aria-label="Email" />);
    const input = screen.getByLabelText('Email');

    expect(input).not.toHaveAttribute('aria-invalid');
    expect(input.className).not.toContain('border-[hsl(var(--destructive))]');
  });

  it('forwards the ref, the type and the user value', () => {
    const ref = createRef<HTMLInputElement>();
    render(<Input ref={ref} type="password" aria-label="Master password" />);

    const input = screen.getByLabelText('Master password');
    expect(ref.current).toBe(input);
    expect(input).toHaveAttribute('type', 'password');

    fireEvent.change(input, { target: { value: 'hunter2' } });
    expect((input as HTMLInputElement).value).toBe('hunter2');
  });
});

describe('Label', () => {
  it('associates with its control via htmlFor and colours destructively on error', () => {
    render(
      <>
        <Label htmlFor="pw" error>
          Master password
        </Label>
        <input id="pw" />
      </>,
    );

    const label = screen.getByText('Master password');
    expect(label.className).toContain('text-[hsl(var(--destructive))]');
    // The association is what makes the input reachable by its label text.
    expect(screen.getByLabelText('Master password')).toHaveAttribute('id', 'pw');
  });

  it('does not apply destructive colouring without the error flag', () => {
    render(<Label>Plain</Label>);
    expect(screen.getByText('Plain').className).not.toContain('text-[hsl(var(--destructive))]');
  });
});

describe('Card', () => {
  it('renders the title as a heading and keeps the description and content addressable', () => {
    render(
      <Card data-testid="card" className="custom">
        <CardHeader>
          <CardTitle>Vault health</CardTitle>
          <CardDescription>3 weak passwords</CardDescription>
        </CardHeader>
        <CardContent>
          <button type="button">Fix now</button>
        </CardContent>
      </Card>,
    );

    expect(screen.getByRole('heading', { name: 'Vault health' }).tagName).toBe('H3');
    expect(screen.getByText('3 weak passwords')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Fix now' })).toBeInTheDocument();
    expect(screen.getByTestId('card').className).toContain('custom');
  });
});

/* ========================================================================== */
/*  Toast — partial update semantics                                          */
/* ========================================================================== */

describe('Toast partial update', () => {
  it('update() leaves fields that were not supplied untouched', () => {
    let api: ReturnType<typeof useToast> | null = null;
    function Consumer() {
      api = useToast();
      return null;
    }
    render(
      <ToastProvider>
        <Consumer />
      </ToastProvider>,
    );
    const toastApi = api as unknown as ReturnType<typeof useToast>;

    let id = '';
    act(() => {
      id = toastApi.toast({ title: 'Uploading', description: 'Step 1', type: 'info' });
    });

    act(() => {
      toastApi.update(id, { description: 'Step 2' });
    });

    // Only the description changed; title and type (role=status/info) are preserved.
    expect(screen.getByText('Uploading')).toBeInTheDocument();
    expect(screen.getByText('Step 2')).toBeInTheDocument();
    expect(screen.getByRole('status').className).toContain('border-blue');
  });

  it('update() with an unknown id changes nothing', () => {
    let api: ReturnType<typeof useToast> | null = null;
    function Consumer() {
      api = useToast();
      return null;
    }
    render(
      <ToastProvider>
        <Consumer />
      </ToastProvider>,
    );
    const toastApi = api as unknown as ReturnType<typeof useToast>;

    act(() => {
      toastApi.toast({ title: 'Original' });
    });
    act(() => {
      toastApi.update('toast-does-not-exist', { title: 'Hijacked' });
    });

    expect(screen.getByText('Original')).toBeInTheDocument();
    expect(screen.queryByText('Hijacked')).not.toBeInTheDocument();
  });
});
