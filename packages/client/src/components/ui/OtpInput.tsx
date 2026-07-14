import {
  useRef,
  useCallback,
  type KeyboardEvent,
  type ClipboardEvent,
  type ChangeEvent,
} from 'react';
import { cn } from '../../lib/utils';

interface OtpInputProps {
  length?: number;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  autoFocus?: boolean;
  'aria-label'?: string;
}

export function OtpInput({
  length = 6,
  value,
  onChange,
  disabled = false,
  autoFocus = false,
  'aria-label': ariaLabel = 'One-time password',
}: OtpInputProps) {
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  const digits = value.split('').concat(Array(length).fill('')).slice(0, length);

  const focusInput = useCallback(
    (idx: number) => {
      const clamped = Math.max(0, Math.min(idx, length - 1));
      inputRefs.current[clamped]?.focus();
    },
    [length],
  );

  const handleChange = useCallback(
    (idx: number) => (e: ChangeEvent<HTMLInputElement>) => {
      const char = e.target.value.replace(/\D/g, '').slice(-1);
      if (!char) return;

      const arr = digits.slice();
      arr[idx] = char;
      const newVal = arr.join('').slice(0, length);
      onChange(newVal);

      if (idx < length - 1) {
        focusInput(idx + 1);
      }
    },
    [digits, length, onChange, focusInput],
  );

  const handleKeyDown = useCallback(
    (idx: number) => (e: KeyboardEvent<HTMLInputElement>) => {
      if (e.key === 'Backspace') {
        e.preventDefault();
        const arr = digits.slice();
        if (arr[idx]) {
          arr[idx] = '';
          onChange(arr.join(''));
        } else if (idx > 0) {
          arr[idx - 1] = '';
          onChange(arr.join(''));
          focusInput(idx - 1);
        }
      } else if (e.key === 'ArrowLeft') {
        e.preventDefault();
        focusInput(idx - 1);
      } else if (e.key === 'ArrowRight') {
        e.preventDefault();
        focusInput(idx + 1);
      }
    },
    [digits, onChange, focusInput],
  );

  const handlePaste = useCallback(
    (e: ClipboardEvent<HTMLInputElement>) => {
      e.preventDefault();
      const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, length);
      if (pasted) {
        onChange(pasted);
        focusInput(Math.min(pasted.length, length - 1));
      }
    },
    [length, onChange, focusInput],
  );

  return (
    <div className="flex gap-2 justify-center" role="group" aria-label={ariaLabel}>
      {digits.map((digit, idx) => (
        <input
          key={idx}
          ref={(el) => {
            inputRefs.current[idx] = el;
          }}
          type="text"
          inputMode="numeric"
          pattern="[0-9]*"
          maxLength={1}
          value={digit}
          onChange={handleChange(idx)}
          onKeyDown={handleKeyDown(idx)}
          onPaste={handlePaste}
          onFocus={(e) => e.target.select()}
          disabled={disabled}
          autoFocus={autoFocus && idx === 0}
          aria-label={`Digit ${String(idx + 1)} of ${String(length)}`}
          className={cn(
            'h-12 w-10 rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))]',
            'text-center text-lg font-mono text-[hsl(var(--foreground))]',
            'placeholder:text-[hsl(var(--muted-foreground))]',
            'focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]',
            'disabled:cursor-not-allowed disabled:opacity-50',
          )}
        />
      ))}
    </div>
  );
}
