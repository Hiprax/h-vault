import { AlertTriangle, FileText, Loader2 } from 'lucide-react';
import {
  MAX_FORMATTABLE_SIZE_BYTES,
  canRepairSyntax,
  formatBytes,
  transformSyntaxForName,
  type TransformSyntax,
} from '@hvault/shared';
import { cn } from '../../lib/utils';
import type { TextDiff } from '../../lib/textDiff';
import type { TransformFailure, TransformReview } from '../../services/documents/transform';

/**
 * The two optional in-browser transforms, and everything the user is shown
 * before one of them rewrites a file.
 *
 * Three rules shape this component, and each of them is a promise the panel
 * makes rather than a styling choice:
 *
 *  1. NOTHING IS REWRITTEN SILENTLY. A completed transform is REVIEWED — the
 *     byte delta, the lines added and removed, and a collapsible diff — and the
 *     upload does not start until the user says so. The comparison shown here is
 *     computed by the application from its own copy of the original; the frame
 *     that did the work has no say in it.
 *  2. A TRANSFORM THAT CANNOT RUN SAYS WHY, WHERE THE CHECKBOX IS. A disabled
 *     control with no explanation is indistinguishable from a broken one, and
 *     the two reasons a control is disabled here are both things the user can
 *     act on: the file is too large, or its type has no repairer.
 *  3. A FAILURE STOPS THE UPLOAD AND OFFERS THE ORIGINAL. A file that could not
 *     be repaired is not half-repaired and it is not quietly uploaded as though
 *     the checkbox had never been ticked; the panel names the line, the column
 *     and the offending text, and offers the original bytes unchanged.
 */

/** Which transforms a file may have, and why not when it may not. */
export interface TransformAvailability {
  readonly syntax: TransformSyntax | null;
  readonly formatEnabled: boolean;
  readonly repairEnabled: boolean;
  /** Why formatting is unavailable, or `null` when it is available. */
  readonly formatReason: string | null;
  readonly repairReason: string | null;
}

/**
 * Decide what this file may have done to it, from its NAME and SIZE alone.
 *
 * Metadata only, deliberately, and it is the same property the panel's other two
 * guardrails have: a checkbox is enabled or disabled without reading a byte of
 * the file. Everything that needs the CONTENT — whether it is UTF-8, whether it
 * parses — is a transform-time failure with an "upload the original unchanged"
 * affordance, never a silently disabled control.
 */
export function transformAvailability(fileName: string, fileSize: number): TransformAvailability {
  const syntax = transformSyntaxForName(fileName);
  const tooLarge = fileSize > MAX_FORMATTABLE_SIZE_BYTES;
  const sizeReason = `Formatting and repair run in your browser and are available for files up to ${formatBytes(MAX_FORMATTABLE_SIZE_BYTES)}.`;
  const typeReason = 'Formatting is available for JSON, JSON Lines, Markdown and YAML files.';
  const repairTypeReason =
    'Repair covers the JSON family only. YAML indentation cannot be guessed at without changing what a file means, and Markdown has no syntax error to repair.';

  if (tooLarge) {
    return {
      syntax,
      formatEnabled: false,
      repairEnabled: false,
      formatReason: sizeReason,
      repairReason: sizeReason,
    };
  }
  if (syntax === null) {
    return {
      syntax,
      formatEnabled: false,
      repairEnabled: false,
      formatReason: typeReason,
      repairReason: repairTypeReason,
    };
  }
  const repairable = canRepairSyntax(syntax);
  return {
    syntax,
    formatEnabled: true,
    repairEnabled: repairable,
    formatReason: null,
    repairReason: repairable ? null : repairTypeReason,
  };
}

interface TransformCheckboxProps {
  id: string;
  label: string;
  description: string;
  checked: boolean;
  enabled: boolean;
  reason: string | null;
  locked: boolean;
  onChange: (value: boolean) => void;
}

function TransformCheckbox({
  id,
  label,
  description,
  checked,
  enabled,
  reason,
  locked,
  onChange,
}: TransformCheckboxProps) {
  const reasonId = `${id}-reason`;
  return (
    <div className="space-y-1">
      <label
        htmlFor={id}
        className={cn(
          'flex items-start gap-2',
          enabled && !locked ? 'cursor-pointer' : 'cursor-not-allowed opacity-70',
        )}
      >
        <input
          id={id}
          type="checkbox"
          checked={checked}
          disabled={!enabled || locked}
          // The reason is wired to the control itself, so a screen reader reaches
          // it from the checkbox rather than only by reading on past it.
          aria-describedby={reason === null ? undefined : reasonId}
          onChange={(event) => {
            onChange(event.target.checked);
          }}
          className="mt-0.5 h-4 w-4 rounded border-[hsl(var(--input))] accent-[hsl(var(--primary))] focus:ring-[hsl(var(--ring))]"
        />
        <span className="text-sm text-[hsl(var(--foreground))]">
          {label}
          <span className="block text-xs text-[hsl(var(--muted-foreground))]">{description}</span>
        </span>
      </label>
      {reason !== null && (
        <p id={reasonId} className="pl-6 text-xs text-[hsl(var(--muted-foreground))]">
          {reason}
        </p>
      )}
    </div>
  );
}

export interface DocumentTransformControlsProps {
  readonly availability: TransformAvailability;
  readonly format: boolean;
  readonly repair: boolean;
  readonly onChange: (next: { format: boolean; repair: boolean }) => void;
  /** True while a transform is running or its result is awaiting confirmation. */
  readonly locked: boolean;
}

export function DocumentTransformControls({
  availability,
  format,
  repair,
  onChange,
  locked,
}: DocumentTransformControlsProps) {
  return (
    <fieldset
      data-testid="transform-controls"
      className="space-y-2 rounded-md border border-[hsl(var(--border))] px-3 py-2"
    >
      <legend className="px-1 text-xs font-medium text-[hsl(var(--muted-foreground))]">
        Before uploading (optional)
      </legend>
      <TransformCheckbox
        id="document-transform-format"
        label="Format this document"
        description="Re-indents and normalises spacing. Runs in your browser; nothing is sent anywhere to do it."
        checked={format}
        enabled={availability.formatEnabled}
        reason={availability.formatReason}
        locked={locked}
        onChange={(value) => {
          onChange({ format: value, repair });
        }}
      />
      <TransformCheckbox
        id="document-transform-repair"
        label="Repair syntax errors"
        description="Rewrites comments, single quotes, unquoted keys and trailing commas into strict JSON."
        checked={repair}
        enabled={availability.repairEnabled}
        reason={availability.repairReason}
        locked={locked}
        onChange={(value) => {
          onChange({ format, repair: value });
        }}
      />
      <p className="text-xs text-[hsl(var(--muted-foreground))]">
        Formatting alone already accepts a trailing comma, so a file may be fixed by formatting
        without repair being needed. You will see exactly what changed before anything is uploaded.
      </p>
    </fieldset>
  );
}

/** The unified diff, rendered as text nodes and never as markup. */
function DiffView({ diff }: { diff: TextDiff }) {
  if (diff.hunks === null) {
    return (
      <p className="text-xs text-[hsl(var(--muted-foreground))]">
        This document is too large to compare line by line. The byte and line totals above are
        exact.
      </p>
    );
  }
  return (
    <pre
      data-testid="transform-diff"
      className="max-h-64 overflow-auto rounded bg-[hsl(var(--muted))] p-2 text-xs leading-5"
    >
      {diff.hunks.map((hunk, hunkIndex) => (
        <div key={`${String(hunk.beforeStart)}-${String(hunk.afterStart)}-${String(hunkIndex)}`}>
          <div className="text-[hsl(var(--muted-foreground))]">
            {`@@ -${String(hunk.beforeStart)},${String(hunk.beforeCount)} +${String(hunk.afterStart)},${String(hunk.afterCount)} @@`}
          </div>
          {hunk.lines.map((line, lineIndex) => (
            <div
              key={`${String(hunkIndex)}-${String(lineIndex)}`}
              className={cn(
                line.kind === 'added' && 'text-green-700 dark:text-green-300',
                line.kind === 'removed' && 'text-red-700 dark:text-red-300',
              )}
            >
              {`${line.kind === 'added' ? '+' : line.kind === 'removed' ? '-' : ' '}${line.text}`}
            </div>
          ))}
        </div>
      ))}
    </pre>
  );
}

export interface TransformReviewPanelProps {
  readonly review: TransformReview;
  /**
   * Why the result cannot be uploaded, or `null` when it can.
   *
   * REQUIRED rather than optional, because the one thing it guards is the one
   * thing this panel exists to offer: a caller that forgot it would offer a
   * confirmation for bytes the server is going to refuse, which is the defect
   * it was added for rather than a lesser version of it.
   */
  readonly refusal: string | null;
  readonly onConfirm: () => void;
  readonly onUploadOriginal: () => void;
  readonly onCancel: () => void;
}

/** The confirmation: what changed, in numbers the application computed itself. */
export function TransformReviewPanel({
  review,
  refusal,
  onConfirm,
  onUploadOriginal,
  onCancel,
}: TransformReviewPanelProps) {
  const delta = review.bytesAfter - review.bytesBefore;
  const deltaText =
    delta === 0
      ? 'the same size'
      : `${delta > 0 ? '+' : '−'}${formatBytes(Math.abs(delta))} (${formatBytes(review.bytesBefore)} → ${formatBytes(review.bytesAfter)})`;

  return (
    <div
      data-testid="transform-review"
      className="space-y-2 rounded-md border border-[hsl(var(--border))] p-3"
    >
      <p className="flex items-center gap-2 text-sm font-medium text-[hsl(var(--foreground))]">
        <FileText className="h-4 w-4" />
        {review.diff.identical
          ? 'Nothing changed — this file is already formatted.'
          : 'Review the changes before uploading'}
      </p>
      <p data-testid="transform-summary" className="text-xs text-[hsl(var(--muted-foreground))]">
        {deltaText}
        {' · '}
        {`${String(review.diff.linesAdded)} line${review.diff.linesAdded === 1 ? '' : 's'} added, ${String(review.diff.linesRemoved)} removed`}
        {' · '}
        {`${review.transform.tool} ${review.transform.toolVersion}`}
      </p>
      {!review.diff.identical && (
        <details>
          <summary className="cursor-pointer text-xs text-[hsl(var(--primary))]">
            Show what changed
          </summary>
          <div className="mt-2">
            <DiffView diff={review.diff} />
          </div>
        </details>
      )}
      {/*
        A refused result keeps its comparison and loses its confirmation. The
        diff is what tells the reader whether the transform was worth pursuing
        by another route, so hiding it would leave them with a refusal and
        nothing to act on; the confirm is simply not OFFERED, rather than
        offered and then rejected, because a button that cannot work is a worse
        answer than the sentence saying why.
      */}
      {refusal !== null && (
        <p
          role="alert"
          data-testid="transform-refusal"
          className="text-xs text-red-700 dark:text-red-300"
        >
          {refusal}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2">
        {refusal === null && (
          <button
            type="button"
            onClick={onConfirm}
            className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90"
          >
            Upload the formatted file
          </button>
        )}
        <button
          type="button"
          onClick={onUploadOriginal}
          className="rounded-md border border-[hsl(var(--border))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
        >
          Upload the original unchanged
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="rounded px-2 py-1 text-sm text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

export interface TransformFailurePanelProps {
  readonly failure: TransformFailure;
  readonly onUploadOriginal: () => void;
  readonly onCancel: () => void;
}

/**
 * The stop. Where the document broke, and the one thing that can still be done.
 *
 * The sentence is the APPLICATION's own — the frame reports a refusal as a code
 * and `services/documents/transform.ts` words it — and the position is two
 * integers. The excerpt is the one string here nothing in the application wrote:
 * a line of the reader's own document, usually quoted from the application's own
 * copy, bounded, and rendered in a `<pre>` as a quotation. All of it is rendered
 * as text and none of it is interpreted.
 */
export function TransformFailurePanel({
  failure,
  onUploadOriginal,
  onCancel,
}: TransformFailurePanelProps) {
  const position =
    failure.line === null
      ? null
      : failure.column === null
        ? `Line ${String(failure.line)}`
        : `Line ${String(failure.line)}, column ${String(failure.column)}`;

  return (
    <div
      role="alert"
      data-testid="transform-failure"
      className="space-y-2 rounded-md border border-red-400 bg-red-50 p-3 text-red-900 dark:border-red-700 dark:bg-red-950 dark:text-red-100"
    >
      <p className="flex items-start gap-2 text-sm font-medium">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
        <span>This file was not uploaded: it could not be repaired or formatted.</span>
      </p>
      <p data-testid="transform-failure-message" className="text-xs">
        {failure.message}
      </p>
      {position !== null && (
        <p data-testid="transform-failure-position" className="text-xs font-medium">
          {position}
        </p>
      )}
      {failure.excerpt !== '' && (
        <pre
          data-testid="transform-failure-excerpt"
          className="overflow-auto rounded bg-[hsl(var(--muted))] p-2 text-xs text-[hsl(var(--foreground))]"
        >
          {failure.excerpt}
        </pre>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={onUploadOriginal}
          className="rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
        >
          Upload the original unchanged
        </button>
        <button type="button" onClick={onCancel} className="rounded px-2 py-1 text-sm underline">
          Cancel
        </button>
      </div>
    </div>
  );
}

/** The spinner shown while the isolated document is working. */
export function TransformRunning() {
  return (
    <p
      data-testid="transform-running"
      className="flex items-center gap-2 text-xs text-[hsl(var(--muted-foreground))]"
    >
      <Loader2 className="h-3 w-3 animate-spin" />
      Formatting in your browser…
    </p>
  );
}
