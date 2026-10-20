/**
 * The one tag editor (`components/ui/TagEditor.tsx` + `hooks/useTagField.ts`),
 * shared by the vault item editor and the two document details panels.
 *
 * The vault editor's own suites pin its item wording through the real form; this
 * one pins the editor itself, both subjects, and `commitPending`, the save-time
 * step that keeps a typed-but-not-added tag instead of dropping it.
 */
import { describe, it, expect } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { MAX_DOCUMENT_TAGS, MAX_TAG_LENGTH } from '@hvault/shared';
import { TagEditor, type TagSubject } from '../../src/components/ui/TagEditor';
import { useTagField, type TagField } from '../../src/hooks/useTagField';

/** Renders the editor and hands the test the live field, refreshed every render. */
function renderEditor(
  options: { initial?: string[]; max?: number; subject?: TagSubject; disabled?: boolean } = {},
) {
  const latest: { field: TagField | null } = { field: null };
  function Harness() {
    const field = useTagField(options.initial ?? [], options.max ?? MAX_DOCUMENT_TAGS);
    latest.field = field;
    return (
      <TagEditor
        id="t-tags"
        field={field}
        subject={options.subject ?? 'document'}
        disabled={options.disabled}
      />
    );
  }
  render(<Harness />);
  return {
    field: (): TagField => latest.field!,
    input: (): HTMLInputElement => screen.getByLabelText('Tags'),
    chips: (): string[] =>
      screen
        .queryAllByLabelText(/^Remove tag /)
        .map((button) => (button.getAttribute('aria-label') ?? '').replace('Remove tag ', '')),
  };
}

const tagsOf = (count: number): string[] =>
  Array.from({ length: count }, (_, i) => `t${String(i)}`);

describe('adding and removing', () => {
  it('adds the trimmed tag on Enter and on Add, and empties the input each time', () => {
    const editor = renderEditor();
    fireEvent.change(editor.input(), { target: { value: '  tax  ' } });
    fireEvent.keyDown(editor.input(), { key: 'Enter' });
    expect(editor.chips()).toEqual(['tax']);
    expect(editor.input()).toHaveValue('');

    fireEvent.change(editor.input(), { target: { value: '2025' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add' }));
    expect(editor.chips()).toEqual(['tax', '2025']);
    expect(editor.input()).toHaveValue('');
  });

  it('keeps a comma as part of ONE tag, as the vault editor always has', () => {
    const editor = renderEditor();
    fireEvent.change(editor.input(), { target: { value: 'a, b' } });
    fireEvent.keyDown(editor.input(), { key: 'Enter' });
    expect(editor.chips()).toEqual(['a, b']);
  });

  it('keeps case: Work and work are two tags', () => {
    const editor = renderEditor();
    for (const tag of ['Work', 'work']) {
      fireEvent.change(editor.input(), { target: { value: tag } });
      fireEvent.keyDown(editor.input(), { key: 'Enter' });
    }
    expect(editor.chips()).toEqual(['Work', 'work']);
  });

  it('adds nothing for blank text, and Add stays disabled for it', () => {
    const editor = renderEditor();
    fireEvent.change(editor.input(), { target: { value: '   ' } });
    expect(screen.getByRole('button', { name: 'Add' })).toBeDisabled();
    fireEvent.keyDown(editor.input(), { key: 'Enter' });
    expect(editor.chips()).toEqual([]);
  });

  it('removes a chip, and hands keyboard focus from its vanishing button to the input', () => {
    const editor = renderEditor({ initial: ['a', 'b'] });
    const remove = screen.getByRole('button', { name: 'Remove tag a' });
    remove.focus();
    fireEvent.click(remove);
    expect(editor.chips()).toEqual(['b']);
    expect(editor.input()).toHaveFocus();
  });

  it('does not move focus for a pointer press that never focused the button', () => {
    const editor = renderEditor({ initial: ['a'] });
    const elsewhere = document.createElement('button');
    document.body.appendChild(elsewhere);
    elsewhere.focus();
    fireEvent.click(screen.getByRole('button', { name: 'Remove tag a' }));
    expect(editor.chips()).toEqual([]);
    expect(elsewhere).toHaveFocus();
    elsewhere.remove();
  });

  it('does not move focus for a tap that focused the button (a pointer click carries a detail)', () => {
    const editor = renderEditor({ initial: ['a', 'b'] });
    const remove = screen.getByRole('button', { name: 'Remove tag a' });
    remove.focus();
    fireEvent.click(remove, { detail: 1 });
    expect(editor.chips()).toEqual(['b']);
    expect(editor.input()).not.toHaveFocus();
  });

  it('does not add a tag on the Enter that ends an input-method composition', () => {
    const editor = renderEditor();
    fireEvent.change(editor.input(), { target: { value: '東京' } });
    fireEvent.keyDown(editor.input(), { key: 'Enter', isComposing: true });
    expect(editor.chips()).toEqual([]);
    expect(editor.input()).toHaveValue('東京');
    fireEvent.keyDown(editor.input(), { key: 'Enter' });
    expect(editor.chips()).toEqual(['東京']);
  });

  it('bounds the input at the one tag-length definition', () => {
    const editor = renderEditor();
    expect(editor.input()).toHaveAttribute('maxLength', String(MAX_TAG_LENGTH));
  });

  it('disables the input, Add and every Remove while disabled', () => {
    renderEditor({ initial: ['a'], disabled: true });
    expect(screen.getByLabelText('Tags')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Add' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Remove tag a' })).toBeDisabled();
  });
});

describe('saying why a tag was not added', () => {
  it('names a duplicate, links the sentence to the input, and drops it on the next keystroke', () => {
    const editor = renderEditor({ initial: ['tax'] });
    fireEvent.change(editor.input(), { target: { value: 'tax' } });
    fireEvent.keyDown(editor.input(), { key: 'Enter' });

    expect(screen.getByRole('status')).toHaveTextContent('That tag is already on this document.');
    expect(editor.input()).toHaveAttribute('aria-describedby', 't-tags-notice');
    expect(editor.chips()).toEqual(['tax']);

    fireEvent.change(editor.input(), { target: { value: 'taxes' } });
    expect(screen.getByRole('status')).toHaveTextContent('');
    expect(editor.input()).not.toHaveAttribute('aria-describedby');
  });

  it('names the limit and keeps the typed text, for each subject', () => {
    for (const [subject, sentence] of [
      ['document', `A document can have up to ${String(MAX_DOCUMENT_TAGS)} tags.`],
      ['item', `An item can have up to ${String(MAX_DOCUMENT_TAGS)} tags.`],
    ] as const) {
      const editor = renderEditor({ initial: tagsOf(MAX_DOCUMENT_TAGS), subject });
      fireEvent.change(editor.input(), { target: { value: 'one-more' } });
      fireEvent.click(screen.getByRole('button', { name: 'Add' }));
      expect(screen.getByRole('status')).toHaveTextContent(sentence);
      expect(editor.chips()).toHaveLength(MAX_DOCUMENT_TAGS);
      expect(editor.input()).toHaveValue('one-more');
      document.body.innerHTML = '';
    }
  });

  it('keeps the status line mounted and visually hidden while it has nothing to say', () => {
    renderEditor();
    const status = screen.getByRole('status');
    expect(status).toHaveTextContent('');
    expect(status).toHaveClass('sr-only');
  });
});

describe('commitPending: the tags a save stores', () => {
  function commit(editor: ReturnType<typeof renderEditor>): string[] | null {
    let result: string[] | null = null;
    act(() => {
      result = editor.field().commitPending();
    });
    return result;
  }

  it('returns the tags unchanged when nothing, or only spaces, is typed', () => {
    const editor = renderEditor({ initial: ['a'] });
    expect(commit(editor)).toEqual(['a']);
    fireEvent.change(editor.input(), { target: { value: '   ' } });
    expect(commit(editor)).toEqual(['a']);
    expect(editor.chips()).toEqual(['a']);
  });

  it('appends a typed tag, trimmed, and shows it as a chip', () => {
    const editor = renderEditor({ initial: ['a'] });
    fireEvent.change(editor.input(), { target: { value: ' b ' } });
    expect(commit(editor)).toEqual(['a', 'b']);
    expect(editor.chips()).toEqual(['a', 'b']);
    expect(editor.input()).toHaveValue('');
  });

  it('adds the last one that fits (n-1 → n)', () => {
    const editor = renderEditor({ initial: tagsOf(MAX_DOCUMENT_TAGS - 1) });
    fireEvent.change(editor.input(), { target: { value: 'last' } });
    expect(commit(editor)).toEqual([...tagsOf(MAX_DOCUMENT_TAGS - 1), 'last']);
  });

  it('refuses past the limit: null, the sentence, the typed text kept, the focus on the input', () => {
    const editor = renderEditor({ initial: tagsOf(MAX_DOCUMENT_TAGS) });
    fireEvent.change(editor.input(), { target: { value: 'overflow' } });
    expect(commit(editor)).toBeNull();
    expect(screen.getByRole('status')).toHaveTextContent(
      `That tag was not added because a document can have ${String(MAX_DOCUMENT_TAGS)} tags. Clear the box or remove a tag to save.`,
    );
    expect(editor.chips()).toHaveLength(MAX_DOCUMENT_TAGS);
    expect(editor.input()).toHaveValue('overflow');
    expect(editor.input()).toHaveFocus();
  });

  it('saves a full list when the typed tag is already in it', () => {
    const editor = renderEditor({ initial: tagsOf(MAX_DOCUMENT_TAGS) });
    fireEvent.change(editor.input(), { target: { value: 't3' } });
    expect(commit(editor)).toEqual(tagsOf(MAX_DOCUMENT_TAGS));
    expect(screen.getByRole('status')).toHaveTextContent('');
  });
});

describe('reset', () => {
  it('replaces the tags and clears the draft and the notice', () => {
    const editor = renderEditor({ initial: ['a'] });
    fireEvent.change(editor.input(), { target: { value: 'a' } });
    fireEvent.keyDown(editor.input(), { key: 'Enter' });
    expect(screen.getByRole('status')).not.toHaveTextContent('');

    act(() => editor.field().reset(['x', 'y']));

    expect(editor.chips()).toEqual(['x', 'y']);
    expect(editor.input()).toHaveValue('');
    expect(screen.getByRole('status')).toHaveTextContent('');
  });
});
