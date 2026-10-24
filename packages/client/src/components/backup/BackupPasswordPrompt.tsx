import type { ReactNode } from 'react';

interface BackupPasswordPromptProps {
  /** The one sentence that says what the password is for. */
  description: string;
  value: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  onCancel: () => void;
  submitLabel: string;
  busyLabel: string;
  busy: boolean;
  inputClass: string;
  /** An accessible name of its own, when the placeholder alone would be ambiguous. */
  inputLabel?: string;
  /** More to say before the password, rendered under the description. */
  children?: ReactNode;
}

/**
 * The backup password, asked for one job: signing the vault download, or a full
 * backup. One component so the two prompts cannot drift: same field, same Enter
 * key, same Cancel. The vault download's prompt renders exactly the markup it
 * always had, because its suites find the field by placeholder and the buttons by
 * name.
 */
export function BackupPasswordPrompt({
  description,
  value,
  onChange,
  onSubmit,
  onCancel,
  submitLabel,
  busyLabel,
  busy,
  inputClass,
  inputLabel,
  children,
}: BackupPasswordPromptProps) {
  return (
    <div className="mt-4 rounded-md border border-[hsl(var(--input))] p-4">
      <p className="mb-2 text-sm text-[hsl(var(--foreground))]">{description}</p>
      {children}
      <div className="flex gap-2">
        <input
          type="password"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              onSubmit();
            }
          }}
          placeholder="Backup password"
          {...(inputLabel === undefined ? {} : { 'aria-label': inputLabel })}
          className={inputClass}
          autoFocus
        />
        <button
          type="button"
          onClick={onSubmit}
          disabled={busy || !value}
          className="rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
        >
          {busy ? busyLabel : submitLabel}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
