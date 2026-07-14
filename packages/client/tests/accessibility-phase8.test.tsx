/**
 * Phase 8 Accessibility tests (fix.md tasks 8.1–8.4):
 *
 * 8.1 — Dialog: ARIA attributes, focus trap, focus restoration
 * 8.2 — DropdownMenu: menuitem roles, aria-activedescendant
 * 8.3 — Tabs: aria-orientation, arrow key navigation, tabIndex management
 * 8.4 — FolderSidebar: keyboard alternative for folder reordering
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';

// ---------------------------------------------------------------------------
// Polyfill matchMedia
// ---------------------------------------------------------------------------

vi.hoisted(() => {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    configurable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
});

// ==========================================================================
// 8.1 — Dialog ARIA attributes and focus trap
// ==========================================================================

describe('8.1 — Dialog ARIA attributes and focus trap', () => {
  // Dynamic import to avoid mock conflicts
  let Dialog: typeof import('../src/components/ui/Dialog').Dialog;
  let DialogContent: typeof import('../src/components/ui/Dialog').DialogContent;
  let DialogHeader: typeof import('../src/components/ui/Dialog').DialogHeader;
  let DialogTitle: typeof import('../src/components/ui/Dialog').DialogTitle;

  beforeEach(async () => {
    const mod = await import('../src/components/ui/Dialog');
    Dialog = mod.Dialog;
    DialogContent = mod.DialogContent;
    DialogHeader = mod.DialogHeader;
    DialogTitle = mod.DialogTitle;
  });

  it('should render role="dialog" and aria-modal="true" on DialogContent', () => {
    const onOpenChange = vi.fn();
    render(
      <Dialog open={true} onOpenChange={onOpenChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Test Dialog</DialogTitle>
          </DialogHeader>
          <p>Content</p>
        </DialogContent>
      </Dialog>,
    );

    const dialog = screen.getByRole('dialog');
    expect(dialog).toBeInTheDocument();
    expect(dialog).toHaveAttribute('aria-modal', 'true');
  });

  it('should link DialogContent aria-labelledby to DialogTitle id', () => {
    const onOpenChange = vi.fn();
    render(
      <Dialog open={true} onOpenChange={onOpenChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Test Title</DialogTitle>
          </DialogHeader>
        </DialogContent>
      </Dialog>,
    );

    const dialog = screen.getByRole('dialog');
    const labelledBy = dialog.getAttribute('aria-labelledby');
    expect(labelledBy).toBeTruthy();

    const title = screen.getByText('Test Title');
    expect(title.id).toBe(labelledBy);
  });

  it('should trap focus within the dialog (Tab from last wraps to first, Shift+Tab from first wraps to last)', () => {
    const onOpenChange = vi.fn();
    render(
      <Dialog open={true} onOpenChange={onOpenChange}>
        <DialogContent>
          <button type="button">First</button>
          <button type="button">Second</button>
          <button type="button">Last</button>
        </DialogContent>
      </Dialog>,
    );

    const buttons = screen.getAllByRole('button');
    const firstButton = buttons[0]!;
    const lastButton = buttons[buttons.length - 1]!;

    // Tab on the LAST focusable must wrap focus to the FIRST. Asserting the exact
    // element (not merely `dialog.contains(activeElement)`, which is true even if
    // the trap is deleted and focus simply stays on lastButton) is what makes this
    // fail if `useFocusTrap`'s wrap (`first.focus()`) is removed.
    lastButton.focus();
    fireEvent.keyDown(lastButton, { key: 'Tab', bubbles: true });
    expect(document.activeElement).toBe(firstButton);

    // Shift+Tab on the FIRST focusable must wrap focus to the LAST.
    firstButton.focus();
    fireEvent.keyDown(firstButton, { key: 'Tab', shiftKey: true, bubbles: true });
    expect(document.activeElement).toBe(lastButton);
  });

  it('should have focus restoration logic in source (previouslyFocusedRef + requestAnimationFrame)', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const source = fs.readFileSync(
      path.resolve(__dirname, '../src/components/ui/Dialog.tsx'),
      'utf-8',
    );

    // Verify previouslyFocusedRef stores the active element on open
    expect(source).toContain('previouslyFocusedRef');
    expect(source).toContain('document.activeElement');
    // Verify focus is restored via requestAnimationFrame when dialog closes
    expect(source).toContain('requestAnimationFrame');
    expect(source).toContain('el.focus()');
    expect(source).toContain('el.isConnected');
  });

  it('should close on Escape key', () => {
    const onOpenChange = vi.fn();
    render(
      <Dialog open={true} onOpenChange={onOpenChange}>
        <DialogContent>
          <p>Content</p>
        </DialogContent>
      </Dialog>,
    );

    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });
});

// ==========================================================================
// 8.2 — DropdownMenu item roles and aria-activedescendant
// ==========================================================================

describe('8.2 — DropdownMenu item roles and aria-activedescendant', () => {
  let DropdownMenu: typeof import('../src/components/ui/DropdownMenu').DropdownMenu;
  let DropdownMenuTrigger: typeof import('../src/components/ui/DropdownMenu').DropdownMenuTrigger;
  let DropdownMenuContent: typeof import('../src/components/ui/DropdownMenu').DropdownMenuContent;
  let DropdownMenuItem: typeof import('../src/components/ui/DropdownMenu').DropdownMenuItem;

  beforeEach(async () => {
    const mod = await import('../src/components/ui/DropdownMenu');
    DropdownMenu = mod.DropdownMenu;
    DropdownMenuTrigger = mod.DropdownMenuTrigger;
    DropdownMenuContent = mod.DropdownMenuContent;
    DropdownMenuItem = mod.DropdownMenuItem;
  });

  it('should render role="menuitem" on each DropdownMenuItem', () => {
    render(
      <DropdownMenu>
        <DropdownMenuTrigger>Open</DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem>Item 1</DropdownMenuItem>
          <DropdownMenuItem>Item 2</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>,
    );

    // Open the menu
    fireEvent.click(screen.getByText('Open'));

    const items = screen.getAllByRole('menuitem');
    expect(items).toHaveLength(2);
  });

  it('should have role="menu" on the content container', () => {
    render(
      <DropdownMenu>
        <DropdownMenuTrigger>Open</DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem>Item 1</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>,
    );

    fireEvent.click(screen.getByText('Open'));
    const menu = screen.getByRole('menu');
    expect(menu).toBeInTheDocument();
  });

  it('should assign unique ids to each DropdownMenuItem', () => {
    render(
      <DropdownMenu>
        <DropdownMenuTrigger>Open</DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem>Item A</DropdownMenuItem>
          <DropdownMenuItem>Item B</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>,
    );

    fireEvent.click(screen.getByText('Open'));
    const items = screen.getAllByRole('menuitem');
    expect(items[0]!.id).toBeTruthy();
    expect(items[1]!.id).toBeTruthy();
    expect(items[0]!.id).not.toBe(items[1]!.id);
  });

  it('should update aria-activedescendant on focus', () => {
    render(
      <DropdownMenu>
        <DropdownMenuTrigger>Open</DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem>Item A</DropdownMenuItem>
          <DropdownMenuItem>Item B</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>,
    );

    fireEvent.click(screen.getByText('Open'));
    const items = screen.getAllByRole('menuitem');
    const menu = screen.getByRole('menu');

    // Focus on Item A
    fireEvent.focus(items[0]!);
    expect(menu.getAttribute('aria-activedescendant')).toBe(items[0]!.id);

    // Focus on Item B
    fireEvent.focus(items[1]!);
    expect(menu.getAttribute('aria-activedescendant')).toBe(items[1]!.id);
  });

  it('should navigate items with ArrowDown/ArrowUp keys', () => {
    render(
      <DropdownMenu>
        <DropdownMenuTrigger>Open</DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem>Item A</DropdownMenuItem>
          <DropdownMenuItem>Item B</DropdownMenuItem>
          <DropdownMenuItem>Item C</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>,
    );

    fireEvent.click(screen.getByText('Open'));
    const menu = screen.getByRole('menu');
    const items = screen.getAllByRole('menuitem');

    // Focus first item
    items[0]!.focus();

    // ArrowDown should move to next item
    fireEvent.keyDown(menu, { key: 'ArrowDown' });
    expect(document.activeElement).toBe(items[1]);

    // ArrowUp should move back
    fireEvent.keyDown(menu, { key: 'ArrowUp' });
    expect(document.activeElement).toBe(items[0]);
  });

  it('moves focus to the first item on open and navigates without manual focus (WCAG 2.1.1)', () => {
    render(
      <DropdownMenu>
        <DropdownMenuTrigger>Open</DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem>Item A</DropdownMenuItem>
          <DropdownMenuItem>Item B</DropdownMenuItem>
          <DropdownMenuItem>Item C</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>,
    );

    // Open via the trigger only — no manual item.focus() (the real keyboard path).
    fireEvent.click(screen.getByText('Open'));

    const items = screen.getAllByRole('menuitem');

    // Focus should land on the first menu item automatically on open.
    expect(document.activeElement).toBe(items[0]);

    // ArrowDown from the focused item advances focus (bubbles to the menu).
    fireEvent.keyDown(items[0]!, { key: 'ArrowDown' });
    expect(document.activeElement).toBe(items[1]);

    // ArrowDown again advances to the third item.
    fireEvent.keyDown(items[1]!, { key: 'ArrowDown' });
    expect(document.activeElement).toBe(items[2]);
  });
});

// ==========================================================================
// 8.3 — Tabs arrow key navigation
// ==========================================================================

describe('8.3 — Tabs arrow key navigation', () => {
  let Tabs: typeof import('../src/components/ui/Tabs').Tabs;
  let TabsList: typeof import('../src/components/ui/Tabs').TabsList;
  let TabsTrigger: typeof import('../src/components/ui/Tabs').TabsTrigger;
  let TabsContent: typeof import('../src/components/ui/Tabs').TabsContent;

  beforeEach(async () => {
    const mod = await import('../src/components/ui/Tabs');
    Tabs = mod.Tabs;
    TabsList = mod.TabsList;
    TabsTrigger = mod.TabsTrigger;
    TabsContent = mod.TabsContent;
  });

  it('should have aria-orientation="horizontal" on TabsList', () => {
    const onValueChange = vi.fn();
    render(
      <Tabs value="tab1" onValueChange={onValueChange}>
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
        <TabsContent value="tab2">Content 2</TabsContent>
      </Tabs>,
    );

    const tablist = screen.getByRole('tablist');
    expect(tablist).toHaveAttribute('aria-orientation', 'horizontal');
  });

  it('should set tabIndex=0 on selected tab and tabIndex=-1 on others', () => {
    const onValueChange = vi.fn();
    render(
      <Tabs value="tab1" onValueChange={onValueChange}>
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          <TabsTrigger value="tab3">Tab 3</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>,
    );

    const tabs = screen.getAllByRole('tab');
    expect(tabs[0]).toHaveAttribute('tabindex', '0');
    expect(tabs[1]).toHaveAttribute('tabindex', '-1');
    expect(tabs[2]).toHaveAttribute('tabindex', '-1');
  });

  it('should navigate tabs with ArrowRight and ArrowLeft keys', () => {
    const onValueChange = vi.fn();
    render(
      <Tabs value="tab1" onValueChange={onValueChange}>
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          <TabsTrigger value="tab3">Tab 3</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>,
    );

    const tabs = screen.getAllByRole('tab');
    const tablist = screen.getByRole('tablist');

    // Focus the first tab
    tabs[0]!.focus();
    expect(document.activeElement).toBe(tabs[0]);

    // ArrowRight should move to next tab
    fireEvent.keyDown(tablist, { key: 'ArrowRight' });
    expect(document.activeElement).toBe(tabs[1]);

    // ArrowRight again
    fireEvent.keyDown(tablist, { key: 'ArrowRight' });
    expect(document.activeElement).toBe(tabs[2]);

    // ArrowRight on last tab should wrap to first
    fireEvent.keyDown(tablist, { key: 'ArrowRight' });
    expect(document.activeElement).toBe(tabs[0]);
  });

  it('should navigate tabs with ArrowLeft key', () => {
    const onValueChange = vi.fn();
    render(
      <Tabs value="tab1" onValueChange={onValueChange}>
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          <TabsTrigger value="tab3">Tab 3</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>,
    );

    const tabs = screen.getAllByRole('tab');
    const tablist = screen.getByRole('tablist');

    // Focus the last tab first (navigate right to end, then wrap)
    tabs[2]!.focus();
    expect(document.activeElement).toBe(tabs[2]);

    // ArrowLeft should move to previous tab
    fireEvent.keyDown(tablist, { key: 'ArrowLeft' });
    expect(document.activeElement).toBe(tabs[1]);

    // ArrowLeft again
    fireEvent.keyDown(tablist, { key: 'ArrowLeft' });
    expect(document.activeElement).toBe(tabs[0]);

    // ArrowLeft on first tab should wrap to last
    fireEvent.keyDown(tablist, { key: 'ArrowLeft' });
    expect(document.activeElement).toBe(tabs[2]);
  });

  it('should navigate tabs with Home and End keys', () => {
    const onValueChange = vi.fn();
    render(
      <Tabs value="tab1" onValueChange={onValueChange}>
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          <TabsTrigger value="tab3">Tab 3</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>,
    );

    const tabs = screen.getAllByRole('tab');
    const tablist = screen.getByRole('tablist');

    tabs[0]!.focus();

    // End should move to last tab
    fireEvent.keyDown(tablist, { key: 'End' });
    expect(document.activeElement).toBe(tabs[2]);

    // Home should move to first tab
    fireEvent.keyDown(tablist, { key: 'Home' });
    expect(document.activeElement).toBe(tabs[0]);
  });

  it('should activate tab on arrow key navigation (calls onValueChange)', () => {
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

    const tabs = screen.getAllByRole('tab');
    const tablist = screen.getByRole('tablist');

    tabs[0]!.focus();
    fireEvent.keyDown(tablist, { key: 'ArrowRight' });

    // The click() on the next tab should trigger onValueChange
    expect(onValueChange).toHaveBeenCalledWith('tab2');
  });

  it('should throw when TabsTrigger is used outside of Tabs parent', () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => render(<TabsTrigger value="orphan">Orphan</TabsTrigger>)).toThrow(
      /must be used within/,
    );
    consoleSpy.mockRestore();
  });

  it('should forward callback ref on TabsList', () => {
    const onValueChange = vi.fn();
    const refCallback = vi.fn();
    render(
      <Tabs value="tab1" onValueChange={onValueChange}>
        <TabsList ref={refCallback}>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>,
    );
    expect(refCallback).toHaveBeenCalledWith(expect.any(HTMLElement));
  });
});

// ==========================================================================
// 8.4 — FolderSidebar keyboard alternative for folder reordering
// ==========================================================================
//
// The former "8.4 — FolderSidebar keyboard reorder (source verification)" block
// (4 tests) was removed here. Every one of them read FolderSidebar.tsx as text
// and asserted substrings — including a raw `onKeyboardReorder` occurrence count
// (`>= 5`). None executed the component, so a handler that computed the wrong
// swap index, dropped the boundary check, or never awaited `reorderFolderApi`
// would leave them all green, while a harmless rename/extract would fail them for
// no behavioural reason.
//
// The keyboard-reorder behaviour is executed and asserted behaviourally in
// sidebar-client-coverage.test.tsx ("FolderSidebar - keyboard reorder
// (Ctrl+Up/Down)"): rendering the real component with sibling folders in the
// store, firing Ctrl+ArrowUp / Ctrl+ArrowDown and asserting `reorderFolderApi`
// runs, plus boundary presses at the first/last sibling being no-ops.
