import { MAX_DOCUMENT_NAME_LENGTH, MAX_DOCUMENT_NOTE_LENGTH } from '@hvault/shared';
import { ORIGINAL_NAME_NOT_RECORDED } from '../../lib/documentDetails';
import { cn } from '../../lib/utils';
import type { TagField } from '../../hooks/useTagField';
import { TagEditor } from '../ui/TagEditor';
import { inputClass } from '../vault/formStyles';

/**
 * What a person types about a document as text: the name without its extension,
 * and the note. The tags live in a {@link TagField} the form owns, because a save
 * has to add a tag that was typed but not added yet.
 */
export interface DocumentDetailsValues {
  readonly stem: string;
  readonly note: string;
}

interface DocumentDetailsFieldsProps {
  /**
   * Prefixes every control's id. The Edit details dialog passes
   * `document-edit`, which keeps the ids it has always had.
   */
  readonly idPrefix: string;
  readonly values: DocumentDetailsValues;
  /** The tags, edited with the same editor as a vault item's. */
  readonly tagField: TagField;
  /** The fixed part of the name: `''`, or the last dot and what follows it. */
  readonly suffix: string;
  readonly onChange: (next: DocumentDetailsValues) => void;
  /**
   * The name the file had when it was added. `undefined` leaves the row out (the
   * upload panel, where it is the file being chosen); `null` says it was not
   * recorded, which is true of every document added before it was.
   */
  readonly originalName?: string | null | undefined;
  readonly disabled?: boolean | undefined;
}

/**
 * The name, tags and note of a document, as ONE set of controls for the two
 * places they are typed: the upload panel and the Edit details dialog.
 *
 * Only the stem of the name is editable. The extension is shown beside it and
 * described to assistive technology, and `nameFromStem` (`lib/documentDetails.ts`) puts it back, so a
 * rename can never change how a document opens. No `<form>`: Enter in the tags
 * field adds a tag (the editor consumes it) and must never start an upload.
 */
export function DocumentDetailsFields({
  idPrefix,
  values,
  tagField,
  suffix,
  onChange,
  originalName,
  disabled = false,
}: DocumentDetailsFieldsProps) {
  const nameHintId = `${idPrefix}-name-hint`;
  const fieldClass = cn(inputClass, 'disabled:opacity-50');

  return (
    <div className="space-y-3">
      <div>
        <label
          htmlFor={`${idPrefix}-name`}
          className="mb-1.5 block text-sm font-medium text-[hsl(var(--foreground))]"
        >
          Name
        </label>
        <div className="flex items-center gap-2">
          <input
            id={`${idPrefix}-name`}
            value={values.stem}
            onChange={(event) => onChange({ ...values, stem: event.target.value })}
            maxLength={MAX_DOCUMENT_NAME_LENGTH - suffix.length}
            autoComplete="off"
            disabled={disabled}
            aria-describedby={suffix === '' ? undefined : nameHintId}
            className={cn(fieldClass, 'min-w-0 flex-1')}
          />
          {suffix !== '' && (
            <span
              data-testid={`${idPrefix}-suffix`}
              className="shrink-0 font-mono text-sm text-[hsl(var(--muted-foreground))]"
            >
              {suffix}
            </span>
          )}
        </div>
        {suffix !== '' && (
          <p id={nameHintId} className="mt-1 text-xs text-[hsl(var(--muted-foreground))]">
            The file type stays {suffix}: it is fixed when a document is added.
          </p>
        )}
      </div>
      <TagEditor id={`${idPrefix}-tags`} field={tagField} subject="document" disabled={disabled} />
      <div>
        <label
          htmlFor={`${idPrefix}-note`}
          className="mb-1.5 block text-sm font-medium text-[hsl(var(--foreground))]"
        >
          Note
        </label>
        <textarea
          id={`${idPrefix}-note`}
          value={values.note}
          onChange={(event) => onChange({ ...values, note: event.target.value })}
          maxLength={MAX_DOCUMENT_NOTE_LENGTH}
          rows={4}
          disabled={disabled}
          className={fieldClass}
        />
      </div>
      {originalName !== undefined && (
        <div>
          <p className="mb-1.5 text-sm font-medium text-[hsl(var(--foreground))]">Original name</p>
          <p
            data-testid={`${idPrefix}-original-name`}
            className="break-all text-sm text-[hsl(var(--muted-foreground))]"
          >
            {originalName ?? ORIGINAL_NAME_NOT_RECORDED}
          </p>
        </div>
      )}
    </div>
  );
}
