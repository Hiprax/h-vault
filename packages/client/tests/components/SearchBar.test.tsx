import { render, screen, fireEvent, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SearchBar, VAULT_SEARCH_RESULTS_ID } from '../../src/components/vault/SearchBar';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockSetSearchQuery = vi.fn();

vi.mock('../../src/stores/vaultStore', () => ({
  useVaultStore: vi.fn((selector) => {
    const state = {
      setSearchQuery: mockSetSearchQuery,
      items: [],
      searchQuery: '',
    };
    return selector(state);
  }),
}));

// Re-import so we can mutate the mock per-test
import { useVaultStore } from '../../src/stores/vaultStore';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function setMockStoreState(overrides: Record<string, unknown> = {}) {
  const state = {
    setSearchQuery: mockSetSearchQuery,
    items: [],
    searchQuery: '',
    ...overrides,
  };
  vi.mocked(useVaultStore).mockImplementation(
    (selector: (state: Record<string, unknown>) => unknown) => selector(state),
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SearchBar', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockSetSearchQuery.mockClear();
    setMockStoreState();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // -------------------------------------------------------------------------
  // 1. Renders search input with correct placeholder
  // -------------------------------------------------------------------------
  it('renders search input with correct placeholder', () => {
    render(<SearchBar />);

    const input = screen.getByPlaceholderText('Search vault... (Ctrl+K)');
    expect(input).toBeInTheDocument();
    expect(input).toHaveAttribute('aria-label', 'Search vault items');
  });

  // -------------------------------------------------------------------------
  // 1b. Search input has aria-autocomplete and aria-controls attributes
  // -------------------------------------------------------------------------
  it('has aria-autocomplete="list" and aria-controls attributes', () => {
    render(<SearchBar />);

    const input = screen.getByLabelText('Search vault items');
    expect(input).toHaveAttribute('aria-autocomplete', 'list');
    expect(input).toHaveAttribute('aria-controls', VAULT_SEARCH_RESULTS_ID);
  });

  // -------------------------------------------------------------------------
  // 2. Typing updates local input value immediately
  // -------------------------------------------------------------------------
  it('typing updates local input value immediately', () => {
    render(<SearchBar />);

    const input = screen.getByLabelText('Search vault items');
    fireEvent.change(input, { target: { value: 'github' } });

    expect(input).toHaveValue('github');
  });

  // -------------------------------------------------------------------------
  // 3. Debounced store update after 300ms
  // -------------------------------------------------------------------------
  it('calls setSearchQuery in the store after 300ms debounce', () => {
    render(<SearchBar />);

    const input = screen.getByLabelText('Search vault items');
    fireEvent.change(input, { target: { value: 'test query' } });

    // Should NOT have been called yet (debounce pending)
    expect(mockSetSearchQuery).not.toHaveBeenCalled();

    // Advance timers by 300ms
    act(() => {
      vi.advanceTimersByTime(300);
    });

    expect(mockSetSearchQuery).toHaveBeenCalledWith('test query');
    expect(mockSetSearchQuery).toHaveBeenCalledTimes(1);
  });

  // -------------------------------------------------------------------------
  // 4. Clear button appears and works
  // -------------------------------------------------------------------------
  it('shows clear button when input has text and clears on click', () => {
    render(<SearchBar />);

    const input = screen.getByLabelText('Search vault items');

    // Clear button should not be visible initially
    expect(screen.queryByLabelText('Clear search')).not.toBeInTheDocument();

    // Type something so clear button appears
    fireEvent.change(input, { target: { value: 'hello' } });

    const clearButton = screen.getByLabelText('Clear search');
    expect(clearButton).toBeInTheDocument();

    // Click clear
    fireEvent.click(clearButton);

    expect(input).toHaveValue('');
    expect(mockSetSearchQuery).toHaveBeenCalledWith('');
  });

  // -------------------------------------------------------------------------
  // 5. Result count display
  // -------------------------------------------------------------------------
  it('shows result count when filteredItemCount is set', () => {
    setMockStoreState({
      searchQuery: 'git',
      filteredItemCount: 2,
    });

    render(<SearchBar />);

    // filteredItemCount = 2 => "2 results"
    expect(screen.getByText('2 results')).toBeInTheDocument();
  });

  it('shows "1 result" (singular) when filteredItemCount is 1', () => {
    setMockStoreState({
      searchQuery: 'amazon',
      filteredItemCount: 1,
    });

    render(<SearchBar />);

    expect(screen.getByText('1 result')).toBeInTheDocument();
  });

  it('does not show result count when filteredItemCount is null', () => {
    setMockStoreState({
      searchQuery: '',
      filteredItemCount: null,
    });

    render(<SearchBar />);

    expect(screen.queryByText(/result/)).not.toBeInTheDocument();
  });

  // -------------------------------------------------------------------------
  // 6. Keyboard shortcut: Ctrl+K focuses the input
  // -------------------------------------------------------------------------
  it('focuses input on Ctrl+K keyboard shortcut', () => {
    render(<SearchBar />);

    const input = screen.getByLabelText('Search vault items');
    expect(document.activeElement).not.toBe(input);

    fireEvent.keyDown(document, { key: 'k', ctrlKey: true });

    expect(document.activeElement).toBe(input);
  });

  it('focuses input on Cmd+K (metaKey) keyboard shortcut', () => {
    render(<SearchBar />);

    const input = screen.getByLabelText('Search vault items');
    expect(document.activeElement).not.toBe(input);

    fireEvent.keyDown(document, { key: 'k', metaKey: true });

    expect(document.activeElement).toBe(input);
  });

  // L30: maxLength on search input
  it('has maxLength attribute on the search input', () => {
    render(<SearchBar />);
    const input = screen.getByLabelText('Search vault items');
    expect(input).toHaveAttribute('maxLength', '200');
  });
});
