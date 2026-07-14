/**
 * P2 Accessibility tests (FIX.md Tasks 13–18):
 *
 * 13 — Dialog: aria-describedby, focus trap excludes disabled/aria-disabled elements
 * 14 — Toast: aria-live polite for success/info, assertive for errors
 * 15 — VaultList: tabIndex on role="button", responsive list height, FAB mobile position
 * 16 — VaultItemForm: tighter email regex, phone length constraint, Luhn validation
 * 17 — DropdownMenu: disabled selector includes aria-disabled, unique IDs
 * 18 — VaultPage: ErrorBoundary wrappers
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React from 'react';

// ---------------------------------------------------------------------------
// Polyfill matchMedia
// ---------------------------------------------------------------------------

vi.hoisted(() => {
  if (typeof window !== 'undefined') {
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
  }
});

// ==========================================================================
// 13 — Dialog: aria-describedby and focus trap excluding disabled elements
// ==========================================================================

describe('13 — Dialog aria-describedby and focus trap', () => {
  let Dialog: typeof import('../src/components/ui/Dialog').Dialog;
  let DialogContent: typeof import('../src/components/ui/Dialog').DialogContent;
  let DialogHeader: typeof import('../src/components/ui/Dialog').DialogHeader;
  let DialogTitle: typeof import('../src/components/ui/Dialog').DialogTitle;
  let DialogDescription: typeof import('../src/components/ui/Dialog').DialogDescription;

  beforeEach(async () => {
    const mod = await import('../src/components/ui/Dialog');
    Dialog = mod.Dialog;
    DialogContent = mod.DialogContent;
    DialogHeader = mod.DialogHeader;
    DialogTitle = mod.DialogTitle;
    DialogDescription = mod.DialogDescription;
  });

  it('should link DialogDescription to DialogContent via aria-describedby', () => {
    render(
      <Dialog open onOpenChange={() => {}}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Test Title</DialogTitle>
            <DialogDescription>Test Description</DialogDescription>
          </DialogHeader>
        </DialogContent>
      </Dialog>,
    );

    const dialog = screen.getByRole('dialog');
    const description = screen.getByText('Test Description');

    expect(dialog).toHaveAttribute('aria-describedby');
    const describedById = dialog.getAttribute('aria-describedby');
    expect(description.id).toBe(describedById);
  });

  it('should link DialogTitle via aria-labelledby', () => {
    render(
      <Dialog open onOpenChange={() => {}}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Title</DialogTitle>
            <DialogDescription>Desc</DialogDescription>
          </DialogHeader>
        </DialogContent>
      </Dialog>,
    );

    const dialog = screen.getByRole('dialog');
    const title = screen.getByText('Title');

    expect(dialog).toHaveAttribute('aria-labelledby');
    expect(title.id).toBe(dialog.getAttribute('aria-labelledby'));
  });

  it('should skip disabled elements in focus trap', () => {
    render(
      <Dialog open onOpenChange={() => {}}>
        <DialogContent>
          <button type="button" disabled>
            Disabled
          </button>
          <button type="button">Enabled</button>
        </DialogContent>
      </Dialog>,
    );

    // The enabled button should receive focus (auto-focus first focusable)
    const enabledButton = screen.getByText('Enabled');
    expect(document.activeElement).toBe(enabledButton);
  });

  it('should skip aria-disabled elements in focus trap', () => {
    render(
      <Dialog open onOpenChange={() => {}}>
        <DialogContent>
          <button type="button" aria-disabled="true">
            AriaDisabled
          </button>
          <button type="button">Active</button>
        </DialogContent>
      </Dialog>,
    );

    const activeButton = screen.getByText('Active');
    expect(document.activeElement).toBe(activeButton);
  });
});

// ==========================================================================
// 14 — Toast: aria-live polite for success/info, assertive for errors
// ==========================================================================

describe('14 — Toast aria-live attribute', () => {
  let ToastProvider: typeof import('../src/components/ui/Toast').ToastProvider;
  let useToast: typeof import('../src/components/ui/Toast').useToast;

  beforeEach(async () => {
    const mod = await import('../src/components/ui/Toast');
    ToastProvider = mod.ToastProvider;
    useToast = mod.useToast;
  });

  function ToastTrigger({ type }: { type: 'success' | 'error' | 'info' | 'warning' }) {
    const { toast } = useToast();
    return (
      <button type="button" onClick={() => toast({ title: `${type} toast`, type })}>
        Show
      </button>
    );
  }

  it('should use aria-live="polite" for success toasts', () => {
    render(
      <ToastProvider>
        <ToastTrigger type="success" />
      </ToastProvider>,
    );

    fireEvent.click(screen.getByText('Show'));
    const toast = screen.getByText('success toast').closest('[aria-live]');
    expect(toast).toHaveAttribute('aria-live', 'polite');
  });

  it('should use aria-live="assertive" for error toasts', () => {
    render(
      <ToastProvider>
        <ToastTrigger type="error" />
      </ToastProvider>,
    );

    fireEvent.click(screen.getByText('Show'));
    const toast = screen.getByText('error toast').closest('[aria-live]');
    expect(toast).toHaveAttribute('aria-live', 'assertive');
  });

  it('should use aria-live="polite" for info toasts', () => {
    render(
      <ToastProvider>
        <ToastTrigger type="info" />
      </ToastProvider>,
    );

    fireEvent.click(screen.getByText('Show'));
    const toast = screen.getByText('info toast').closest('[aria-live]');
    expect(toast).toHaveAttribute('aria-live', 'polite');
  });

  it('should use role="alert" for error toasts and role="status" for others', () => {
    render(
      <ToastProvider>
        <ToastTrigger type="error" />
      </ToastProvider>,
    );

    fireEvent.click(screen.getByText('Show'));
    const errorToast = screen.getByText('error toast').closest('[role]');
    expect(errorToast).toHaveAttribute('role', 'alert');
  });

  it('should use role="status" for success toasts', () => {
    render(
      <ToastProvider>
        <ToastTrigger type="success" />
      </ToastProvider>,
    );

    fireEvent.click(screen.getByText('Show'));
    const successToast = screen.getByText('success toast').closest('[role]');
    expect(successToast).toHaveAttribute('role', 'status');
  });
});

// ==========================================================================
// 15 — VaultList accessibility (tabIndex on role="button", responsive height)
// ==========================================================================

describe('15 — VaultList accessibility', () => {
  it('should verify VaultListItem has tabIndex={0} on role="button" div', async () => {
    // Mock vaultStore
    vi.doMock('../src/stores/vaultStore', () => ({
      useVaultStore: Object.assign(
        (selector: (state: Record<string, unknown>) => unknown) =>
          selector({
            items: [
              {
                id: '1',
                name: 'Test Item',
                itemType: 'login',
                favorite: false,
                tags: [],
                folderId: null,
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString(),
                data: {},
              },
            ],
            trashItems: [],
            loading: false,
            searchQuery: '',
            selectedFolder: null,
            selectedType: null,
            showFavorites: false,
            showTrash: false,
            fetchItems: vi.fn().mockResolvedValue(undefined),
            fetchTrashItems: vi.fn().mockResolvedValue(undefined),
            emptyTrash: vi.fn().mockResolvedValue(undefined),
            folders: [],
            sortBy: 'name',
            sortOrder: 'asc',
            setSortBy: vi.fn(),
            setSortOrder: vi.fn(),
            setFilteredItemCount: vi.fn(),
            filteredItemCount: null,
          }),
        { getState: () => ({}) },
      ),
    }));

    vi.doMock('../src/components/ui/Toast', () => ({
      useToast: () => ({ toast: vi.fn(), dismiss: vi.fn(), update: vi.fn() }),
    }));

    vi.doMock('react-router-dom', () => ({
      useNavigate: () => vi.fn(),
    }));

    const { VaultList } = await import('../src/components/vault/VaultList');
    const { render: r } = await import('@testing-library/react');

    const { container } = r(<VaultList onCreateNew={() => {}} />);
    const roleButtons = container.querySelectorAll('[role="button"]');

    for (const btn of roleButtons) {
      expect(btn).toHaveAttribute('tabindex', '0');
    }

    vi.doUnmock('../src/stores/vaultStore');
    vi.doUnmock('../src/components/ui/Toast');
    vi.doUnmock('react-router-dom');
  });
});

// ==========================================================================
// 16 — VaultItemForm validation patterns
//
// The former tests here re-declared the email/phone Zod schemas and copied
// `isValidLuhn` INTO the test body, so they exercised hand-rolled clones and
// gave zero signal about VaultItemForm.tsx (whose helpers are module-private
// and not exported). The identity email/phone rejection and the card Luhn
// warning are covered against the REAL, rendered form in
// coverage-vault-item-form.test.tsx ('rejects a malformed email address',
// 'rejects a phone number with illegal characters', 'warns inline and blocks
// submit when the card number fails the Luhn check') and in
// phase3-fixes.test.tsx ('VaultItemForm - Card Luhn warning'), so the clone
// tests were removed rather than left masquerading as coverage.
// ==========================================================================

// ==========================================================================
// 17 — DropdownMenu accessibility
// ==========================================================================

describe('17 — DropdownMenu accessibility', () => {
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

  it('should skip aria-disabled items during keyboard navigation', () => {
    render(
      <DropdownMenu>
        <DropdownMenuTrigger>Open</DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem>Item 1</DropdownMenuItem>
          <DropdownMenuItem aria-disabled="true">Disabled Item</DropdownMenuItem>
          <DropdownMenuItem>Item 3</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>,
    );

    fireEvent.click(screen.getByText('Open'));
    expect(screen.getByRole('menu')).toBeInTheDocument();

    // On open, focus moves to the first enabled item.
    const item1 = screen.getByText('Item 1');
    const disabled = screen.getByText('Disabled Item');
    const item3 = screen.getByText('Item 3');
    expect(document.activeElement).toBe(item1);

    // ArrowDown from Item 1 must SKIP the aria-disabled item and land on Item 3.
    // If the roving-focus selector stopped excluding [aria-disabled="true"],
    // focus would land on the disabled item instead — this assertion catches it.
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: 'ArrowDown' });
    expect(document.activeElement).toBe(item3);
    expect(document.activeElement).not.toBe(disabled);
  });

  it('should generate unique IDs for all menu items', () => {
    render(
      <DropdownMenu>
        <DropdownMenuTrigger>Open</DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem>A</DropdownMenuItem>
          <DropdownMenuItem>B</DropdownMenuItem>
          <DropdownMenuItem>C</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>,
    );

    fireEvent.click(screen.getByText('Open'));
    const items = screen.getAllByRole('menuitem');
    const ids = items.map((item) => item.id);

    // All IDs should be non-empty
    ids.forEach((id) => expect(id).not.toBe(''));
    // All IDs should be unique
    expect(new Set(ids).size).toBe(ids.length);
  });
});

// ==========================================================================
// 18 — ErrorBoundary wrappers in VaultPage
// ==========================================================================

describe('18 — VaultPage ErrorBoundary wrappers', () => {
  it('should import ErrorBoundary in VaultPage source', async () => {
    // Read the VaultPage source to verify ErrorBoundary is imported and used
    // This is a structural test that verifies the error boundary wrapping
    const fs = await import('fs');
    const path = await import('path');
    const vaultPagePath = path.resolve(__dirname, '../src/pages/VaultPage.tsx');
    const source = fs.readFileSync(vaultPagePath, 'utf-8');

    expect(source).toContain('import { ErrorBoundary }');
    expect(source).toContain('<ErrorBoundary>');
    // Should wrap VaultList
    expect(source).toMatch(/<ErrorBoundary>\s*<VaultList/);
    // Should wrap VaultItemForm
    expect(source).toMatch(/<ErrorBoundary>\s*<VaultItemForm/);
  });
});
