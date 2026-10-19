/**
 * The views of what the custom-field limit cut from an import: the list inside the
 * confirmation (`ImportLimitCuts`) and the report kept on the Settings page
 * (`ImportLimitReport`). Names only, never values, and every count stated.
 */

import { describe, it, expect, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import {
  ImportLimitCuts,
  ImportLimitReport,
} from '../../src/components/settings/ImportLimitSummary';
import type { LimitSummary } from '../../src/services/import/customFieldsLimit';

const names = (list: string[], more = 0) => ({ names: list, more });

function summary(overrides: Partial<LimitSummary> = {}): LimitSummary {
  return {
    rowCount: 1,
    movedToNotesCount: 1,
    hiddenDroppedCount: 2,
    notWrittenCount: 0,
    mergedCount: 0,
    entries: [
      {
        itemName: 'Bank',
        itemType: 'login',
        movedToNotes: names(['Branch']),
        hiddenDropped: names(['PIN', 'Recovery'], 3),
        notWritten: names([]),
      },
    ],
    merged: [],
    ...overrides,
  };
}

describe('ImportLimitCuts', () => {
  it('states the limit, the rule and each entry, in a labelled focusable region', () => {
    render(<ImportLimitCuts summary={summary()} limit={30} />);

    const region = screen.getByRole('region', {
      name: 'Custom fields this import will move or leave out',
    });
    expect(region).toHaveAttribute('tabindex', '0');
    expect(region).toHaveTextContent(
      'In 1 entry, some custom fields are moved or left out. The limit is 30 custom fields per entry.',
    );
    expect(region).toHaveTextContent('so their values are never written anywhere');
    expect(region).toHaveTextContent(
      'Bank: moved to its notes: Branch; hidden, not imported: PIN, Recovery and 3 more',
    );
    // Nothing was too long for the notes, so that clause is absent.
    expect(region).not.toHaveTextContent('did not fit');
    expect(region).toHaveTextContent('An administrator can raise the limit (CUSTOM_FIELDS_LIMIT)');
  });

  it('uses the plural, names an unnamed field and entry, and lists what did not fit', () => {
    render(
      <ImportLimitCuts
        summary={summary({
          rowCount: 2,
          entries: [
            {
              itemName: '',
              itemType: 'note',
              movedToNotes: names([]),
              hiddenDropped: names([]),
              notWritten: names(['', 'Long']),
            },
          ],
        })}
        limit={5}
      />,
    );

    const region = screen.getByRole('region');
    expect(region).toHaveTextContent('In 2 entries, some custom fields are moved or left out.');
    expect(region).toHaveTextContent('The limit is 5 custom fields per entry.');
    expect(region).toHaveTextContent(
      'Unnamed item; did not fit in its notes, not imported: (unnamed), Long',
    );
    // Two cut rows but one listed: the rest are counted.
    expect(region).toHaveTextContent('And 1 entry more.');
  });

  it('explains a row folded into another by the cut, and nothing else when nothing else was cut', () => {
    render(
      <ImportLimitCuts
        summary={summary({
          rowCount: 0,
          mergedCount: 1,
          entries: [],
          merged: [
            {
              itemName: 'Copy',
              itemType: 'login',
              keptName: '',
              hiddenDropped: names(['Secret']),
              notWritten: names(['Extra']),
            },
          ],
        })}
        limit={30}
      />,
    );

    const region = screen.getByRole('region');
    expect(region).not.toHaveTextContent('some custom fields are moved or left out');
    // The limit is named even when no entry was cut on its own.
    expect(region).toHaveTextContent('The limit is 30 custom fields per entry.');
    expect(region).toHaveTextContent(
      'Copy became identical to Unnamed item once its extra fields were cut, so it is imported once; hidden, not imported: Secret; not imported: Extra',
    );
    expect(region).not.toHaveTextContent(/And \d+ (entry|entries) more/);
  });
});

describe('ImportLimitReport', () => {
  it('is a labelled section with the summary, and closes on request', () => {
    const onClose = vi.fn();
    render(<ImportLimitReport summary={summary()} limit={30} onClose={onClose} />);

    const report = screen.getByRole('region', { name: 'Import report' });
    expect(report.tagName).toBe('SECTION');
    expect(report).toHaveTextContent('hidden, not imported: PIN, Recovery and 3 more');
    // A report, not an announcement.
    expect(report).not.toHaveAttribute('aria-live');

    fireEvent.click(screen.getByRole('button', { name: 'Close import report' }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
