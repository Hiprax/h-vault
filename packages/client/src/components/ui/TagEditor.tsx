import { X } from 'lucide-react';
import { MAX_TAG_LENGTH } from '@hvault/shared';
import { cn } from '../../lib/utils';
import type { TagField, TagNotice } from '../../hooks/useTagField';
import { inputClass } from '../vault/formStyles';

/** What the tags belong to, which is all the sentences below need to know. */
export type TagSubject = 'item' | 'document';

const ARTICLE: Record<TagSubject, string> = { item: 'an', document: 'a' };

function noticeText(notice: TagNotice, subject: TagSubject, max: number): string {
  const owner = `${ARTICLE[subject]} ${subject}`;
  switch (notice) {
    case 'duplicate':
      return `That tag is already on this ${subject}.`;
    case 'limit':
      return `${owner.charAt(0).toUpperCase()}${owner.slice(1)} can have up to ${String(max)} tags.`;
    case 'pending-limit':
      return `That tag was not added because ${owner} can have ${String(max)} tags. Clear the box or remove a tag to save.`;
  }
}

interface TagEditorProps {
  /** The input's id; the notice is `<id>-notice`. */
  readonly id: string;
  readonly field: TagField;
  readonly subject: TagSubject;
  readonly disabled?: boolean | undefined;
}

/**
 * The one tag editor: the tags as chips, each with its own remove button, and an
 * input that adds one tag on Enter or Add.
 *
 * A tag that is not added says why (already there, or the list is full) in a
 * status line under the input, instead of the input simply emptying. That line is
 * always mounted, so a screen reader is already listening when it gains text; it
 * is visually hidden while empty, and the input names it only while it speaks.
 *
 * Enter is consumed here, so inside a `<form>` it adds the tag rather than
 * submitting, and in the document panels (which have no form) it cannot start an
 * upload.
 */
export function TagEditor({ id, field, subject, disabled = false }: TagEditorProps) {
  const noticeId = `${id}-notice`;

  return (
    <div>
      <label
        htmlFor={id}
        className="mb-1.5 block text-sm font-medium text-[hsl(var(--foreground))]"
      >
        Tags
      </label>
      <div className="mb-2 flex flex-wrap gap-1.5">
        {field.tags.map((tag) => (
          <span
            key={tag}
            className="inline-flex items-center gap-1 rounded-full bg-[hsl(var(--secondary))] px-2.5 py-0.5 text-xs font-medium text-[hsl(var(--secondary-foreground))]"
          >
            {tag}
            <button
              type="button"
              onClick={(event) => {
                // The button is about to be destroyed: keyboard focus on it would
                // fall to the page, so it is handed to the input. Only for a
                // keyboard press (a click event with no pointer `detail`): a tap
                // that focused the button must not raise an on-screen keyboard.
                const keyboard =
                  event.detail === 0 && event.currentTarget === document.activeElement;
                field.remove(tag);
                if (keyboard) field.inputRef.current?.focus();
              }}
              disabled={disabled}
              className="rounded-full p-0.5 hover:bg-[hsl(var(--muted))]"
              aria-label={`Remove tag ${tag}`}
            >
              <X className="h-3 w-3" />
            </button>
          </span>
        ))}
      </div>
      <div className="flex gap-2">
        <input
          ref={field.inputRef}
          id={id}
          type="text"
          value={field.draft}
          onChange={(event) => field.setDraft(event.target.value)}
          aria-describedby={field.notice !== null ? noticeId : undefined}
          onKeyDown={(event) => {
            // Not while an input method is composing: that Enter confirms the
            // composition, and the tag is not finished yet.
            if (event.key === 'Enter' && !event.nativeEvent.isComposing) {
              event.preventDefault();
              field.add();
            }
          }}
          placeholder="Add a tag..."
          maxLength={MAX_TAG_LENGTH}
          autoComplete="off"
          disabled={disabled}
          className={cn(inputClass, 'flex-1 disabled:opacity-50')}
        />
        <button
          type="button"
          onClick={field.add}
          disabled={disabled || !field.draft.trim()}
          className="rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] disabled:opacity-50 transition-colors"
        >
          Add
        </button>
      </div>
      <p
        id={noticeId}
        role="status"
        className={
          field.notice === null ? 'sr-only' : 'mt-1 text-xs text-[hsl(var(--muted-foreground))]'
        }
      >
        {field.notice === null ? '' : noticeText(field.notice, subject, field.max)}
      </p>
    </div>
  );
}
