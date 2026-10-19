/**
 * The custom-field limit readers (`services/api/configApi.ts`) and the hook the
 * editor's host pages use (`hooks/useCustomFieldsLimit.ts`).
 *
 * The two readers have different contracts on purpose. The DISPLAY reader
 * (`getCustomFieldsLimit`) never fails and remembers only a real answer, so one
 * dropped request cannot pin the default for the rest of the tab. The IMPORT reader
 * (`readCustomFieldsLimitFresh`) answers `null` for "the server did not say",
 * because an import acts on the number and must stop rather than guess.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import { DEFAULT_CUSTOM_FIELDS_LIMIT } from '@hvault/shared';

const { mockGet } = vi.hoisted(() => ({ mockGet: vi.fn() }));

vi.mock('../src/services/api/client', () => ({
  api: {
    get: (...args: unknown[]) => mockGet(...args),
  },
  clearCsrfToken: vi.fn(),
}));

/** A `/config` wire response carrying the given vault block (or none). */
function wire(vault?: unknown): { data: unknown } {
  return {
    data: {
      success: true,
      data: {
        fileEncryption: { maxSizeMB: 100 },
        ...(vault === undefined ? {} : { vault }),
      },
    },
  };
}

async function importConfigApi() {
  return import('../src/services/api/configApi');
}

beforeEach(() => {
  mockGet.mockReset();
  vi.resetModules();
});

describe('readCustomFieldsLimitFresh', () => {
  it('returns the advertised limit', async () => {
    mockGet.mockResolvedValue(wire({ customFieldsLimit: 12 }));
    const { readCustomFieldsLimitFresh } = await importConfigApi();

    expect(await readCustomFieldsLimitFresh()).toBe(12);
    expect(mockGet).toHaveBeenCalledWith('/config');
  });

  it('reads an absent vault block (an older server) as the documented default', async () => {
    mockGet.mockResolvedValue(wire());
    const { readCustomFieldsLimitFresh } = await importConfigApi();

    expect(await readCustomFieldsLimitFresh()).toBe(DEFAULT_CUSTOM_FIELDS_LIMIT);
  });

  it('answers null for a malformed block, never a guess', async () => {
    mockGet.mockResolvedValue(wire({ customFieldsLimit: 0 }));
    const { readCustomFieldsLimitFresh } = await importConfigApi();

    expect(await readCustomFieldsLimitFresh()).toBeNull();
  });

  it('answers null for a failed request', async () => {
    mockGet.mockRejectedValue(new Error('network down'));
    const { readCustomFieldsLimitFresh } = await importConfigApi();

    expect(await readCustomFieldsLimitFresh()).toBeNull();
  });

  it('is never cached: every call asks the server', async () => {
    mockGet.mockResolvedValueOnce(wire({ customFieldsLimit: 12 }));
    mockGet.mockResolvedValueOnce(wire({ customFieldsLimit: 40 }));
    const { readCustomFieldsLimitFresh } = await importConfigApi();

    expect(await readCustomFieldsLimitFresh()).toBe(12);
    expect(await readCustomFieldsLimitFresh()).toBe(40);
    expect(mockGet).toHaveBeenCalledTimes(2);
  });

  it('refreshes the display memo on success but not on failure', async () => {
    mockGet.mockResolvedValueOnce(wire({ customFieldsLimit: 12 }));
    mockGet.mockRejectedValueOnce(new Error('network down'));
    const { readCustomFieldsLimitFresh, cachedCustomFieldsLimitValue } = await importConfigApi();

    expect(cachedCustomFieldsLimitValue()).toBeNull();
    await readCustomFieldsLimitFresh();
    expect(cachedCustomFieldsLimitValue()).toBe(12);
    // A failure leaves the last good answer where it was.
    await readCustomFieldsLimitFresh();
    expect(cachedCustomFieldsLimitValue()).toBe(12);
  });
});

describe('getCustomFieldsLimit', () => {
  it('returns the advertised limit and remembers it', async () => {
    mockGet.mockResolvedValue(wire({ customFieldsLimit: 50 }));
    const { getCustomFieldsLimit, cachedCustomFieldsLimitValue } = await importConfigApi();

    expect(await getCustomFieldsLimit()).toBe(50);
    expect(await getCustomFieldsLimit()).toBe(50);
    expect(mockGet).toHaveBeenCalledTimes(1);
    expect(cachedCustomFieldsLimitValue()).toBe(50);
  });

  it('falls back to the default on failure WITHOUT caching it, so the next call retries', async () => {
    mockGet.mockRejectedValueOnce(new Error('429'));
    mockGet.mockResolvedValueOnce(wire({ customFieldsLimit: 50 }));
    const { getCustomFieldsLimit, cachedCustomFieldsLimitValue } = await importConfigApi();

    expect(await getCustomFieldsLimit()).toBe(DEFAULT_CUSTOM_FIELDS_LIMIT);
    expect(cachedCustomFieldsLimitValue()).toBeNull();
    expect(await getCustomFieldsLimit()).toBe(50);
    expect(mockGet).toHaveBeenCalledTimes(2);
  });

  it('falls back to the default for a malformed block, also uncached', async () => {
    mockGet.mockResolvedValue(wire({ customFieldsLimit: 'thirty' }));
    const { getCustomFieldsLimit, cachedCustomFieldsLimitValue } = await importConfigApi();

    expect(await getCustomFieldsLimit()).toBe(DEFAULT_CUSTOM_FIELDS_LIMIT);
    expect(cachedCustomFieldsLimitValue()).toBeNull();
  });
});

describe('useCustomFieldsLimit', () => {
  async function renderProbe() {
    const { useCustomFieldsLimit } = await import('../src/hooks/useCustomFieldsLimit');
    let renders = 0;
    function Probe() {
      renders++;
      return <span data-testid="limit">{useCustomFieldsLimit()}</span>;
    }
    const view = render(<Probe />);
    return { view, renderCount: () => renders };
  }

  it('starts at the default and adopts a different advertised limit', async () => {
    mockGet.mockResolvedValue(wire({ customFieldsLimit: 12 }));
    await renderProbe();

    expect(screen.getByTestId('limit').textContent).toBe(String(DEFAULT_CUSTOM_FIELDS_LIMIT));
    await act(async () => {
      await Promise.resolve();
    });
    expect(await screen.findByText('12')).toBeTruthy();
  });

  it('sets no state when the server agrees with the starting value', async () => {
    mockGet.mockResolvedValue(wire({ customFieldsLimit: DEFAULT_CUSTOM_FIELDS_LIMIT }));
    const { renderCount } = await renderProbe();
    const before = renderCount();

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(mockGet).toHaveBeenCalledTimes(1);
    // No extra commit: an equal value must not schedule a render at all.
    expect(renderCount()).toBe(before);
    expect(screen.getByTestId('limit').textContent).toBe(String(DEFAULT_CUSTOM_FIELDS_LIMIT));
  });

  it('starts from a previously cached limit without waiting', async () => {
    mockGet.mockResolvedValue(wire({ customFieldsLimit: 7 }));
    const { getCustomFieldsLimit } = await importConfigApi();
    await getCustomFieldsLimit();

    await renderProbe();
    expect(screen.getByTestId('limit').textContent).toBe('7');
  });

  it('unmounts cleanly while the read is still pending, and renders nothing after it', async () => {
    let resolve: (value: unknown) => void = () => undefined;
    mockGet.mockReturnValue(
      new Promise((r) => {
        resolve = r;
      }),
    );
    const { view } = await renderProbe();
    view.unmount();

    await act(async () => {
      resolve(wire({ customFieldsLimit: 12 }));
      await Promise.resolve();
    });
    expect(screen.queryByTestId('limit')).toBeNull();
  });
});
