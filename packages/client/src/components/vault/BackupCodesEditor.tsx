/**
 * The backup-codes editor inside the vault item form.
 *
 * Fully controlled and react-hook-form-agnostic: the host owns the `codes` array
 * and hands down a setter, which keeps every quirk of that untyped form in
 * `VaultItemForm` and makes this component testable on its own.
 */
import { useCallback, useMemo, useRef, useState } from 'react';
import { AlertCircle, Check } from 'lucide-react';
import {
  BACKUP_CODES_INPUT_FORMATS,
  MAX_LOGIN_BACKUP_CODES,
  mergeBackupCodes,
  parseBackupCodes,
  type BackupCodesFormat,
  type BackupCodesInputFormat,
  type BackupCodesIssue,
  type MergeBackupCodesResult,
} from '@hvault/shared';
import { cn } from '../../lib/utils';
import { inputClass } from './formStyles';
import { BackupCodeList } from './BackupCodeList';
import { BackupCodeExcerpt, buildExcerptWindow } from './BackupCodeExcerpt';

/**
 * The format picker's options. `auto` leads because making the user classify their
 * own paste before pasting it is a tax, and the parser reports which format it
 * settled on. The explicit entries exist so a paste that was read the wrong way
 * can be pinned to one format and validated strictly against it.
 */
const FORMAT_OPTIONS: readonly {
  readonly value: BackupCodesInputFormat;
  readonly label: string;
}[] = [
  { value: 'auto', label: 'Detect automatically' },
  { value: 'newline', label: 'One per line' },
  { value: 'comma', label: 'Comma-separated' },
  { value: 'space', label: 'Space-separated' },
  { value: 'array', label: 'JSON array' },
  { value: 'single', label: 'A single code' },
];

const FORMAT_NAMES: Record<BackupCodesFormat, string> = {
  array: 'a JSON array',
  comma: 'comma-separated',
  space: 'space-separated',
  newline: 'one per line',
  single: 'a single code',
};

function isInputFormat(value: string): value is BackupCodesInputFormat {
  return (BACKUP_CODES_INPUT_FORMATS as readonly string[]).includes(value);
}

/**
 * Report what actually happened to the codes the user pasted, in full sentences.
 *
 * Every count is named: a silently dropped duplicate or an overflowing code would
 * otherwise look like the paste simply did not work.
 */
function describeMerge(result: MergeBackupCodesResult): string {
  if (result.addedCount === 0 && result.overflowCount === 0 && result.duplicateCount > 0) {
    return result.duplicateCount === 1
      ? 'That code is already in the list.'
      : `All ${result.duplicateCount} codes are already in the list.`;
  }
  const parts = [result.addedCount === 1 ? 'Added 1 code.' : `Added ${result.addedCount} codes.`];
  if (result.duplicateCount > 0) {
    parts.push(
      result.duplicateCount === 1
        ? '1 duplicate skipped.'
        : `${result.duplicateCount} duplicates skipped.`,
    );
  }
  if (result.overflowCount > 0) {
    parts.push(`${result.overflowCount} not added (limit ${MAX_LOGIN_BACKUP_CODES} reached).`);
  }
  return parts.join(' ');
}

/**
 * The rejected-paste strip: what is wrong, what to do about it, where it is, and a
 * marked-up excerpt of the line it is on.
 *
 * Module-private and built here rather than memoised in the parent so the window
 * is never nullable: every issue carries a position, and a `null` branch the parser
 * cannot produce would be permanently unreachable.
 */
function ParseErrorStrip({ raw, issue }: { raw: string; issue: BackupCodesIssue }) {
  const excerpt = buildExcerptWindow(raw, issue.index, issue.length);
  return (
    <div className="rounded-md border border-[hsl(var(--destructive)/0.3)] bg-[hsl(var(--destructive)/0.05)] px-3 py-2">
      <p className="flex items-start gap-2 text-xs text-[hsl(var(--destructive))]">
        <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        <span>
          {issue.message}
          {issue.hint !== undefined && <span className="opacity-80"> {issue.hint}</span>}
          {` Line ${excerpt.lineNumber}, character ${excerpt.column}.`}
        </span>
      </p>
      <BackupCodeExcerpt excerpt={excerpt} />
    </div>
  );
}

export interface BackupCodesEditorProps {
  /** The current codes. */
  readonly codes: readonly string[];
  /** Replace the whole array; the host writes it back into the form. */
  readonly onChangeCodes: (next: string[]) => void;
  /** Collapse and discard the section. Offered only while the list is empty. */
  readonly onRemoveSection: () => void;
}

export function BackupCodesEditor({
  codes,
  onChangeCodes,
  onRemoveSection,
}: BackupCodesEditorProps) {
  const [raw, setRaw] = useState('');
  const [format, setFormat] = useState<BackupCodesInputFormat>('auto');
  const [confirmClear, setConfirmClear] = useState(false);
  const [status, setStatus] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const parsed = useMemo(
    () => (raw.trim() === '' ? null : parseBackupCodes(raw, { format })),
    [raw, format],
  );

  /**
   * A dry run of the merge, so the strip can promise exactly what Add will do —
   * including duplicates against codes ALREADY in the list, and anything that will
   * not fit under the cap.
   */
  const preview = useMemo(() => {
    if (parsed?.ok !== true) return null;
    return mergeBackupCodes(codes, parsed.codes);
  }, [parsed, codes]);

  const handleAdd = useCallback(() => {
    if (preview === null) return;
    onChangeCodes(preview.codes);
    setStatus(describeMerge(preview));
    setRaw('');
    // Add becomes inert the instant the box empties, and a focused element that
    // becomes disabled blurs to document.body in Chromium.
    textareaRef.current?.focus();
  }, [onChangeCodes, preview]);

  const handleDelete = useCallback(
    (index: number) => {
      onChangeCodes(codes.filter((_, position) => position !== index));
      setStatus(`Backup code ${index + 1} removed. ${codes.length - 1} remaining.`);
    },
    [codes, onChangeCodes],
  );

  const handleClearAll = useCallback(() => {
    onChangeCodes([]);
    setConfirmClear(false);
    setStatus('All backup codes removed.');
    textareaRef.current?.focus();
  }, [onChangeCodes]);

  const headerActions =
    codes.length === 0 ? (
      <button
        type="button"
        onClick={onRemoveSection}
        className="text-xs text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] hover:underline"
      >
        Remove
      </button>
    ) : confirmClear ? (
      // An inline two-step confirm, not a dialog: this form is itself commonly
      // rendered inside a modal, and nesting a focus trap and a scroll lock inside
      // one is a hazard for no benefit. It also keeps the user's eye on the control
      // they just pressed.
      <span className="flex items-center gap-2 text-xs">
        <span className="text-[hsl(var(--muted-foreground))]">
          Remove all {codes.length} codes?
        </span>
        <button
          type="button"
          onClick={() => setConfirmClear(false)}
          className="rounded px-1.5 py-0.5 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={handleClearAll}
          className="rounded px-1.5 py-0.5 font-medium text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)]"
        >
          Clear
        </button>
      </span>
    ) : (
      <button
        type="button"
        onClick={() => setConfirmClear(true)}
        className="text-xs text-[hsl(var(--destructive))] hover:underline"
      >
        Clear all
      </button>
    );

  return (
    <div className="space-y-3 rounded-lg border border-[hsl(var(--border))] p-4">
      <BackupCodeList
        codes={codes}
        onDelete={handleDelete}
        headerActions={headerActions}
        emptyFocusRef={textareaRef}
      />

      <div className="space-y-2">
        <textarea
          id="field-backupCodes"
          ref={textareaRef}
          value={raw}
          onChange={(event) => setRaw(event.target.value)}
          rows={4}
          placeholder="Paste your backup codes"
          // Every other control here is named by `FormField`; this one is not inside
          // one, so without this its accessible name would fall back to the
          // placeholder.
          aria-label="Paste your backup codes"
          // Mobile autocorrect will happily turn AAAA-1111 into "AAA A-1111".
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          autoComplete="off"
          aria-invalid={parsed !== null && !parsed.ok ? true : undefined}
          aria-describedby="field-backupCodes-feedback"
          className={cn(inputClass, 'resize-y font-mono')}
        />

        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="flex items-center gap-2">
            <label
              htmlFor="field-backupCodesFormat"
              className="text-xs text-[hsl(var(--muted-foreground))]"
            >
              Format
            </label>
            <select
              id="field-backupCodesFormat"
              value={format}
              onChange={(event) => {
                if (isInputFormat(event.target.value)) setFormat(event.target.value);
              }}
              className={cn(inputClass, 'w-52')}
            >
              {FORMAT_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </span>
          <button
            type="button"
            onClick={handleAdd}
            disabled={preview === null}
            className="shrink-0 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent))] disabled:opacity-50"
          >
            Add codes
          </button>
        </div>

        {/*
          One always-mounted region, polite rather than role="alert": it updates on
          every keystroke, and an assertive region would machine-gun a screen
          reader. Always mounted so assistive tech has it registered before the
          first update.
        */}
        <div id="field-backupCodes-feedback" aria-live="polite" aria-atomic="true">
          {parsed !== null && parsed.ok && preview !== null && (
            <p className="flex items-start gap-2 rounded-md border border-green-500/30 bg-green-50 px-3 py-2 text-xs text-green-800 dark:bg-green-950 dark:text-green-200">
              <Check className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>
                {parsed.detected ? `Detected: ${FORMAT_NAMES[parsed.format]} · ` : ''}
                {parsed.codes.length === 1 ? '1 code found' : `${parsed.codes.length} codes found`}
                {preview.duplicateCount > 0 &&
                  ` · ${preview.duplicateCount === 1 ? '1 duplicate' : `${preview.duplicateCount} duplicates`} will be skipped`}
                {preview.overflowCount > 0 &&
                  ` · ${preview.overflowCount} will not fit (limit ${MAX_LOGIN_BACKUP_CODES})`}
              </span>
            </p>
          )}
          {parsed !== null && !parsed.ok && <ParseErrorStrip raw={raw} issue={parsed.issue} />}
        </div>

        <p
          id="field-backupCodes-status"
          aria-live="polite"
          aria-atomic="true"
          className="text-xs text-[hsl(var(--muted-foreground))]"
        >
          {status}
        </p>
      </div>
    </div>
  );
}
