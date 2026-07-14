/**
 * Comprehensive tests for core UI components.
 *
 * Covers:
 * 1 - Toast.tsx   (ToastProvider, useToast hook, display, dismiss, auto-dismiss, multiple toasts, variants)
 * 2 - Badge.tsx   (all variants, className merging, children rendering, ref forwarding)
 * 3 - Spinner.tsx (SVG rendering, size variants, custom className, a11y attributes)
 * 4 - Button.tsx  (all variants, all sizes, loading state, asChild/Slot, disabled, onClick)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import React, { createRef } from 'react';

// Components under test
import { ToastProvider, useToast } from '../src/components/ui/Toast';
import { Badge } from '../src/components/ui/Badge';
import { Spinner } from '../src/components/ui/Spinner';
import { Button } from '../src/components/ui/Button';

/* ========================================================================== */
/*  1. Toast                                                                  */
/* ========================================================================== */

describe('Toast', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  /** Helper that renders a consumer inside a ToastProvider and returns the toast API */
  function renderWithToast() {
    let toastApi: ReturnType<typeof useToast> | null = null;

    function Consumer() {
      toastApi = useToast();
      return null;
    }

    const utils = render(
      <ToastProvider>
        <Consumer />
      </ToastProvider>,
    );

    if (!toastApi) throw new Error('useToast did not provide a value');
    return { ...utils, toastApi: toastApi as ReturnType<typeof useToast> };
  }

  describe('ToastProvider', () => {
    it('renders its children', () => {
      render(
        <ToastProvider>
          <div data-testid="child">Hello</div>
        </ToastProvider>,
      );
      expect(screen.getByTestId('child')).toHaveTextContent('Hello');
    });

    it('renders the notification container with aria-label', () => {
      render(
        <ToastProvider>
          <div />
        </ToastProvider>,
      );
      expect(screen.getByLabelText('Notifications')).toBeInTheDocument();
    });
  });

  describe('useToast hook', () => {
    it('throws when used outside of ToastProvider', () => {
      function Orphan() {
        useToast();
        return null;
      }

      // Suppress console.error for the expected error boundary trigger
      const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => render(<Orphan />)).toThrow('useToast must be used within a <ToastProvider>');
      spy.mockRestore();
    });

    it('provides toast, dismiss, and update functions', () => {
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
      expect(api).not.toBeNull();
      expect(typeof api!.toast).toBe('function');
      expect(typeof api!.dismiss).toBe('function');
      expect(typeof api!.update).toBe('function');
    });
  });

  describe('Toast display', () => {
    it('shows a toast with title when toast() is called', () => {
      const { toastApi } = renderWithToast();

      act(() => {
        toastApi.toast({ title: 'Item saved' });
      });

      expect(screen.getByText('Item saved')).toBeInTheDocument();
    });

    it('shows a toast with title and description', () => {
      const { toastApi } = renderWithToast();

      act(() => {
        toastApi.toast({ title: 'Success', description: 'Your changes were saved.' });
      });

      expect(screen.getByText('Success')).toBeInTheDocument();
      expect(screen.getByText('Your changes were saved.')).toBeInTheDocument();
    });

    it('renders the toast with appropriate role for accessibility', () => {
      const { toastApi } = renderWithToast();

      act(() => {
        toastApi.toast({ title: 'Alert' });
      });

      // Default type is info, which uses role="status"
      expect(screen.getByRole('status')).toBeInTheDocument();
    });

    it('returns a unique id for each toast', () => {
      const { toastApi } = renderWithToast();

      let id1 = '';
      let id2 = '';
      act(() => {
        id1 = toastApi.toast({ title: 'First' });
        id2 = toastApi.toast({ title: 'Second' });
      });

      expect(id1).toBeTruthy();
      expect(id2).toBeTruthy();
      expect(id1).not.toBe(id2);
    });
  });

  describe('Toast types', () => {
    it('defaults to info type', () => {
      const { toastApi } = renderWithToast();

      act(() => {
        toastApi.toast({ title: 'Info toast' });
      });

      const toast = screen.getByRole('status');
      // Info type should have blue border styling class
      expect(toast.className).toContain('border-blue');
    });

    it('renders success toast with green styling', () => {
      const { toastApi } = renderWithToast();

      act(() => {
        toastApi.toast({ title: 'Done', type: 'success' });
      });

      const toast = screen.getByRole('status');
      expect(toast.className).toContain('border-green');
    });

    it('renders error toast with red styling', () => {
      const { toastApi } = renderWithToast();

      act(() => {
        toastApi.toast({ title: 'Failed', type: 'error' });
      });

      const alert = screen.getByRole('alert');
      expect(alert.className).toContain('border-red');
    });

    it('renders warning toast with yellow styling', () => {
      const { toastApi } = renderWithToast();

      act(() => {
        toastApi.toast({ title: 'Watch out', type: 'warning' });
      });

      const toast = screen.getByRole('status');
      expect(toast.className).toContain('border-yellow');
    });
  });

  describe('Toast dismiss', () => {
    it('dismisses a toast when the dismiss button is clicked', () => {
      const { toastApi } = renderWithToast();

      act(() => {
        toastApi.toast({ title: 'Dismissable' });
      });

      expect(screen.getByText('Dismissable')).toBeInTheDocument();

      const dismissBtn = screen.getByLabelText('Dismiss notification');
      fireEvent.click(dismissBtn);

      // The dismiss button sets exiting=true, then removes after 300ms
      act(() => {
        vi.advanceTimersByTime(350);
      });

      expect(screen.queryByText('Dismissable')).not.toBeInTheDocument();
    });

    it('dismisses a toast programmatically via dismiss()', () => {
      const { toastApi } = renderWithToast();

      let toastId = '';
      act(() => {
        toastId = toastApi.toast({ title: 'Will dismiss' });
      });

      expect(screen.getByText('Will dismiss')).toBeInTheDocument();

      act(() => {
        toastApi.dismiss(toastId);
      });

      expect(screen.queryByText('Will dismiss')).not.toBeInTheDocument();
    });

    it('auto-dismisses after the default duration (5000ms)', () => {
      const { toastApi } = renderWithToast();

      act(() => {
        toastApi.toast({ title: 'Auto dismiss' });
      });

      expect(screen.getByText('Auto dismiss')).toBeInTheDocument();

      // Advance past the default 5000ms duration
      act(() => {
        vi.advanceTimersByTime(5100);
      });

      expect(screen.queryByText('Auto dismiss')).not.toBeInTheDocument();
    });

    it('auto-dismisses after a custom duration', () => {
      const { toastApi } = renderWithToast();

      act(() => {
        toastApi.toast({ title: 'Quick', duration: 1000 });
      });

      expect(screen.getByText('Quick')).toBeInTheDocument();

      act(() => {
        vi.advanceTimersByTime(1100);
      });

      expect(screen.queryByText('Quick')).not.toBeInTheDocument();
    });

    it('starts exit animation 300ms before removal', () => {
      const { toastApi } = renderWithToast();

      act(() => {
        toastApi.toast({ title: 'Animating', duration: 2000 });
      });

      // At 1700ms (duration - 300), the exiting class should be set
      act(() => {
        vi.advanceTimersByTime(1700);
      });

      const toast = screen.getByRole('status');
      expect(toast.className).toContain('translate-x-full');
      expect(toast.className).toContain('opacity-0');
    });
  });

  describe('Multiple toasts', () => {
    it('renders multiple toasts simultaneously', () => {
      const { toastApi } = renderWithToast();

      act(() => {
        toastApi.toast({ title: 'Toast A' });
        toastApi.toast({ title: 'Toast B' });
        toastApi.toast({ title: 'Toast C' });
      });

      expect(screen.getByText('Toast A')).toBeInTheDocument();
      expect(screen.getByText('Toast B')).toBeInTheDocument();
      expect(screen.getByText('Toast C')).toBeInTheDocument();
    });

    it('dismisses only the targeted toast, others remain', () => {
      const { toastApi } = renderWithToast();

      let idB = '';
      act(() => {
        toastApi.toast({ title: 'Stay A' });
        idB = toastApi.toast({ title: 'Bye B' });
        toastApi.toast({ title: 'Stay C' });
      });

      act(() => {
        toastApi.dismiss(idB);
      });

      expect(screen.getByText('Stay A')).toBeInTheDocument();
      expect(screen.queryByText('Bye B')).not.toBeInTheDocument();
      expect(screen.getByText('Stay C')).toBeInTheDocument();
    });
  });

  describe('Toast update', () => {
    it('updates a toast title', () => {
      const { toastApi } = renderWithToast();

      let id = '';
      act(() => {
        id = toastApi.toast({ title: 'Uploading...' });
      });

      expect(screen.getByText('Uploading...')).toBeInTheDocument();

      act(() => {
        toastApi.update(id, { title: 'Upload complete!' });
      });

      expect(screen.queryByText('Uploading...')).not.toBeInTheDocument();
      expect(screen.getByText('Upload complete!')).toBeInTheDocument();
    });

    it('updates a toast description', () => {
      const { toastApi } = renderWithToast();

      let id = '';
      act(() => {
        id = toastApi.toast({ title: 'Processing', description: 'Step 1 of 3' });
      });

      act(() => {
        toastApi.update(id, { description: 'Step 2 of 3' });
      });

      expect(screen.getByText('Step 2 of 3')).toBeInTheDocument();
    });

    it('updates a toast type', () => {
      const { toastApi } = renderWithToast();

      let id = '';
      act(() => {
        id = toastApi.toast({ title: 'Working', type: 'info' });
      });

      const toastBefore = screen.getByRole('status');
      expect(toastBefore.className).toContain('border-blue');

      act(() => {
        toastApi.update(id, { type: 'success' });
      });

      const toastAfter = screen.getByRole('status');
      expect(toastAfter.className).toContain('border-green');
    });
  });
});

/* ========================================================================== */
/*  2. Badge                                                                  */
/* ========================================================================== */

describe('Badge', () => {
  it('renders children', () => {
    render(<Badge>New</Badge>);
    expect(screen.getByText('New')).toBeInTheDocument();
  });

  it('renders with the default variant', () => {
    const { container } = render(<Badge>Default</Badge>);
    const badge = container.firstChild as HTMLElement;
    // Default variant uses primary background
    expect(badge.className).toContain('bg-[hsl(var(--primary))]');
  });

  it('renders with the secondary variant', () => {
    const { container } = render(<Badge variant="secondary">Secondary</Badge>);
    const badge = container.firstChild as HTMLElement;
    expect(badge.className).toContain('bg-[hsl(var(--secondary))]');
  });

  it('renders with the destructive variant', () => {
    const { container } = render(<Badge variant="destructive">Danger</Badge>);
    const badge = container.firstChild as HTMLElement;
    expect(badge.className).toContain('bg-[hsl(var(--destructive))]');
  });

  it('renders with the outline variant', () => {
    const { container } = render(<Badge variant="outline">Outline</Badge>);
    const badge = container.firstChild as HTMLElement;
    expect(badge.className).toContain('text-[hsl(var(--foreground))]');
    // Outline should NOT have primary/secondary/destructive background
    expect(badge.className).not.toContain('bg-[hsl(var(--primary))]');
    expect(badge.className).not.toContain('bg-[hsl(var(--destructive))]');
  });

  it('merges custom className with variant classes', () => {
    const { container } = render(<Badge className="my-custom-class">Custom</Badge>);
    const badge = container.firstChild as HTMLElement;
    expect(badge.className).toContain('my-custom-class');
    // Should still have the base badge styles
    expect(badge.className).toContain('inline-flex');
  });

  it('passes through additional HTML attributes', () => {
    render(
      <Badge data-testid="my-badge" title="Status">
        Active
      </Badge>,
    );
    const badge = screen.getByTestId('my-badge');
    expect(badge).toHaveAttribute('title', 'Status');
    expect(badge).toHaveTextContent('Active');
  });

  it('forwards ref', () => {
    const ref = createRef<HTMLDivElement>();
    render(<Badge ref={ref}>Ref</Badge>);
    expect(ref.current).toBeInstanceOf(HTMLDivElement);
    expect(ref.current?.textContent).toBe('Ref');
  });

  it('renders complex children', () => {
    render(
      <Badge>
        <span data-testid="icon">*</span> Count: 5
      </Badge>,
    );
    expect(screen.getByTestId('icon')).toBeInTheDocument();
    expect(screen.getByText(/Count: 5/)).toBeInTheDocument();
  });
});

/* ========================================================================== */
/*  3. Spinner                                                                */
/* ========================================================================== */

describe('Spinner', () => {
  it('renders an SVG element', () => {
    render(<Spinner />);
    const svg = screen.getByRole('status');
    expect(svg.tagName.toLowerCase()).toBe('svg');
  });

  it('has role="status" and aria-label="Loading" for accessibility', () => {
    render(<Spinner />);
    const svg = screen.getByRole('status');
    expect(svg).toHaveAttribute('aria-label', 'Loading');
  });

  it('applies animate-spin class', () => {
    render(<Spinner />);
    const svg = screen.getByRole('status');
    expect(svg.className.baseVal || svg.getAttribute('class')).toContain('animate-spin');
  });

  describe('Size variants', () => {
    it('defaults to md size (h-6 w-6)', () => {
      render(<Spinner />);
      const svg = screen.getByRole('status');
      const classes = svg.className.baseVal || svg.getAttribute('class') || '';
      expect(classes).toContain('h-6');
      expect(classes).toContain('w-6');
    });

    it('renders sm size (h-4 w-4)', () => {
      render(<Spinner size="sm" />);
      const svg = screen.getByRole('status');
      const classes = svg.className.baseVal || svg.getAttribute('class') || '';
      expect(classes).toContain('h-4');
      expect(classes).toContain('w-4');
    });

    it('renders lg size (h-8 w-8)', () => {
      render(<Spinner size="lg" />);
      const svg = screen.getByRole('status');
      const classes = svg.className.baseVal || svg.getAttribute('class') || '';
      expect(classes).toContain('h-8');
      expect(classes).toContain('w-8');
    });
  });

  it('merges custom className', () => {
    render(<Spinner className="text-red-500" />);
    const svg = screen.getByRole('status');
    const classes = svg.className.baseVal || svg.getAttribute('class') || '';
    expect(classes).toContain('text-red-500');
    expect(classes).toContain('animate-spin');
  });

  it('passes through additional SVG attributes', () => {
    render(<Spinner data-testid="my-spinner" />);
    expect(screen.getByTestId('my-spinner')).toBeInTheDocument();
  });

  it('contains circle and path elements for the spinner visual', () => {
    const { container } = render(<Spinner />);
    const circles = container.querySelectorAll('circle');
    const paths = container.querySelectorAll('path');
    expect(circles.length).toBeGreaterThanOrEqual(1);
    expect(paths.length).toBeGreaterThanOrEqual(1);
  });
});

/* ========================================================================== */
/*  4. Button                                                                 */
/* ========================================================================== */

describe('Button', () => {
  describe('Rendering', () => {
    it('renders a button element with children', () => {
      render(<Button>Click me</Button>);
      expect(screen.getByRole('button', { name: 'Click me' })).toBeInTheDocument();
    });

    it('renders as a native HTML button', () => {
      render(<Button>Native</Button>);
      const btn = screen.getByRole('button');
      expect(btn.tagName.toLowerCase()).toBe('button');
    });

    it('forwards ref', () => {
      const ref = createRef<HTMLButtonElement>();
      render(<Button ref={ref}>Ref</Button>);
      expect(ref.current).toBeInstanceOf(HTMLButtonElement);
    });

    it('passes through HTML button attributes', () => {
      render(
        <Button type="submit" name="submitBtn">
          Submit
        </Button>,
      );
      const btn = screen.getByRole('button');
      expect(btn).toHaveAttribute('type', 'submit');
      expect(btn).toHaveAttribute('name', 'submitBtn');
    });
  });

  describe('Variants', () => {
    it('applies default variant styles', () => {
      render(<Button>Default</Button>);
      const btn = screen.getByRole('button');
      expect(btn.className).toContain('bg-[hsl(var(--primary))]');
    });

    it('applies destructive variant styles', () => {
      render(<Button variant="destructive">Delete</Button>);
      const btn = screen.getByRole('button');
      expect(btn.className).toContain('bg-[hsl(var(--destructive))]');
    });

    it('applies outline variant styles', () => {
      render(<Button variant="outline">Outline</Button>);
      const btn = screen.getByRole('button');
      expect(btn.className).toContain('border');
      expect(btn.className).toContain('bg-[hsl(var(--background))]');
    });

    it('applies secondary variant styles', () => {
      render(<Button variant="secondary">Secondary</Button>);
      const btn = screen.getByRole('button');
      expect(btn.className).toContain('bg-[hsl(var(--secondary))]');
    });

    it('applies ghost variant styles', () => {
      render(<Button variant="ghost">Ghost</Button>);
      const btn = screen.getByRole('button');
      expect(btn.className).toContain('hover:bg-[hsl(var(--accent))]');
    });

    it('applies link variant styles', () => {
      render(<Button variant="link">Link</Button>);
      const btn = screen.getByRole('button');
      expect(btn.className).toContain('underline-offset-4');
    });
  });

  describe('Sizes', () => {
    it('applies default size (h-10 px-4)', () => {
      render(<Button>Default size</Button>);
      const btn = screen.getByRole('button');
      expect(btn.className).toContain('h-10');
      expect(btn.className).toContain('px-4');
    });

    it('applies sm size (h-9 px-3)', () => {
      render(<Button size="sm">Small</Button>);
      const btn = screen.getByRole('button');
      expect(btn.className).toContain('h-9');
      expect(btn.className).toContain('px-3');
    });

    it('applies lg size (h-11 px-8)', () => {
      render(<Button size="lg">Large</Button>);
      const btn = screen.getByRole('button');
      expect(btn.className).toContain('h-11');
      expect(btn.className).toContain('px-8');
    });

    it('applies icon size (h-10 w-10)', () => {
      render(<Button size="icon">X</Button>);
      const btn = screen.getByRole('button');
      expect(btn.className).toContain('h-10');
      expect(btn.className).toContain('w-10');
    });
  });

  describe('Custom className', () => {
    it('merges custom className with variant classes', () => {
      render(<Button className="mt-4 extra-class">Custom</Button>);
      const btn = screen.getByRole('button');
      expect(btn.className).toContain('mt-4');
      expect(btn.className).toContain('extra-class');
      // Should still include base styles
      expect(btn.className).toContain('inline-flex');
    });
  });

  describe('Disabled state', () => {
    it('sets the disabled attribute when disabled=true', () => {
      render(<Button disabled>Disabled</Button>);
      const btn = screen.getByRole('button');
      expect(btn).toBeDisabled();
    });

    it('applies disabled styling classes', () => {
      render(<Button disabled>Disabled</Button>);
      const btn = screen.getByRole('button');
      expect(btn.className).toContain('disabled:pointer-events-none');
      expect(btn.className).toContain('disabled:opacity-50');
    });

    it('does not trigger onClick when disabled', () => {
      const handleClick = vi.fn();
      render(
        <Button disabled onClick={handleClick}>
          No click
        </Button>,
      );
      fireEvent.click(screen.getByRole('button'));
      expect(handleClick).not.toHaveBeenCalled();
    });
  });

  describe('onClick handler', () => {
    it('calls onClick when clicked', () => {
      const handleClick = vi.fn();
      render(<Button onClick={handleClick}>Clickable</Button>);
      fireEvent.click(screen.getByRole('button'));
      expect(handleClick).toHaveBeenCalledTimes(1);
    });

    it('receives the mouse event', () => {
      const handleClick = vi.fn();
      render(<Button onClick={handleClick}>Event</Button>);
      fireEvent.click(screen.getByRole('button'));
      expect(handleClick).toHaveBeenCalledWith(expect.objectContaining({ type: 'click' }));
    });
  });

  describe('Loading state', () => {
    it('renders a Spinner when loading=true', () => {
      render(<Button loading>Saving</Button>);
      const btn = screen.getByRole('button');
      // The Spinner renders with role="status"
      const spinner = within(btn).getByRole('status');
      expect(spinner).toBeInTheDocument();
    });

    it('disables the button when loading=true', () => {
      render(<Button loading>Saving</Button>);
      expect(screen.getByRole('button')).toBeDisabled();
    });

    it('still renders children alongside the spinner', () => {
      render(<Button loading>Saving...</Button>);
      expect(screen.getByText('Saving...')).toBeInTheDocument();
    });

    it('does not render a Spinner when loading=false (default)', () => {
      render(<Button>Normal</Button>);
      const btn = screen.getByRole('button');
      expect(within(btn).queryByRole('status')).not.toBeInTheDocument();
    });

    it('does not trigger onClick when loading', () => {
      const handleClick = vi.fn();
      render(
        <Button loading onClick={handleClick}>
          Loading
        </Button>,
      );
      fireEvent.click(screen.getByRole('button'));
      expect(handleClick).not.toHaveBeenCalled();
    });

    it('the spinner uses sm size', () => {
      render(<Button loading>Load</Button>);
      const btn = screen.getByRole('button');
      const spinner = within(btn).getByRole('status');
      const classes = spinner.className.baseVal || spinner.getAttribute('class') || '';
      expect(classes).toContain('h-4');
      expect(classes).toContain('w-4');
    });
  });

  describe('asChild / Slot pattern', () => {
    it('renders children as the root element when asChild=true', () => {
      const { container } = render(
        <Button asChild>
          <a href="/home">Go home</a>
        </Button>,
      );
      const link = container.querySelector('a');
      expect(link).toBeInTheDocument();
      expect(link).toHaveAttribute('href', '/home');
      expect(link?.textContent).toBe('Go home');
    });

    it('merges button variant classes onto the child element', () => {
      const { container } = render(
        <Button asChild variant="destructive">
          <a href="/delete" className="custom-link">
            Delete
          </a>
        </Button>,
      );
      const link = container.querySelector('a');
      expect(link).not.toBeNull();
      // Should have both button variant styles and the custom class
      expect(link!.className).toContain('custom-link');
      expect(link!.className).toContain('bg-[hsl(var(--destructive))]');
    });

    it('does not render a button element when asChild=true', () => {
      render(
        <Button asChild>
          <span>Span child</span>
        </Button>,
      );
      expect(screen.queryByRole('button')).not.toBeInTheDocument();
    });

    it('renders non-element children as a fragment fallback', () => {
      const { container } = render(<Button asChild>Just text</Button>);
      expect(container.textContent).toContain('Just text');
    });
  });

  describe('Combined props', () => {
    it('combines variant and size props correctly', () => {
      render(
        <Button variant="outline" size="lg">
          Large Outline
        </Button>,
      );
      const btn = screen.getByRole('button');
      expect(btn.className).toContain('border');
      expect(btn.className).toContain('h-11');
      expect(btn.className).toContain('px-8');
    });

    it('explicit disabled takes priority over loading=false for enabled state', () => {
      render(
        <Button disabled loading={false}>
          Explicitly disabled
        </Button>,
      );
      expect(screen.getByRole('button')).toBeDisabled();
    });

    it('loading=true disables even when disabled is not set', () => {
      render(<Button loading>Loading no explicit disable</Button>);
      expect(screen.getByRole('button')).toBeDisabled();
    });
  });
});
