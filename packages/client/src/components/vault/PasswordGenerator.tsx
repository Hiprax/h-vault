import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Copy, RefreshCw, Check, Eye, EyeOff, History, Loader2 } from 'lucide-react';
import { cn } from '../../lib/utils';
import { PASSPHRASE_WORDS } from '../../constants/passphraseWords';
import {
  buildCharset,
  classifyStrength,
  formatCrackTime,
  getEffectiveCharsetSize,
  passphraseEntropyBits,
  passwordEntropyBits,
  OFFLINE_GPU_GUESSES_PER_SEC,
  OFFLINE_GPU_RATE_LABEL,
} from '../../utils/passwordEntropy';
import { useToast } from '../ui/Toast';
import { useUserSettings } from '../../hooks/useUserSettings';
import { copySecretToClipboard } from '../../services/clipboard/clipboardService';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
// Character sets and the shared `buildCharset` pool builder live in
// ../../utils/passwordEntropy so the generator and the entropy metrics always agree.

function getSecureRandom(max: number): number {
  if (max <= 0) return 0;
  // Rejection sampling to eliminate modular bias.
  // Values >= limit would introduce bias when mapped via modulo.
  const limit = Math.floor(0x100000000 / max) * max;
  const arr = new Uint32Array(1);
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  while (true) {
    crypto.getRandomValues(arr);
    const value = arr[0] ?? 0;
    if (value < limit) return value % max;
  }
}

function generatePassword(options: {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}): string {
  // buildCharset is the single source of truth shared with the entropy metrics, so the
  // strength readout is always computed from the exact pool drawn from here.
  const charset = buildCharset(options);

  const result = Array.from(
    { length: options.length },
    () => charset[getSecureRandom(charset.length)] ?? '',
  ).join('');
  return result;
}

function generatePassphrase(wordCount: number, separator: string): string {
  const words: string[] = [];
  for (let i = 0; i < wordCount; i++) {
    words.push(PASSPHRASE_WORDS[getSecureRandom(PASSPHRASE_WORDS.length)] ?? 'word');
  }
  return words.join(separator);
}

// ---------------------------------------------------------------------------
// Strength indicator
// ---------------------------------------------------------------------------

// One Tailwind fill colour per strength level (0..4), aligned with the classifier.
const STRENGTH_COLORS = [
  'bg-red-500',
  'bg-orange-500',
  'bg-yellow-500',
  'bg-green-500',
  'bg-emerald-500',
];

/**
 * Renders the exact strength of a GENERATED secret. `bits` is the true Shannon entropy
 * of the generation process (computed from the options, not by inspecting the output
 * string), so the meter differentiates across the whole range instead of saturating the
 * way a zxcvbn score does past ~33 bits.
 */
function StrengthIndicator({ bits }: { bits: number }) {
  const { level, label } = classifyStrength(bits);

  return (
    <div className="space-y-1.5">
      <div className="flex gap-1">
        {[0, 1, 2, 3, 4].map((i) => (
          <div
            key={i}
            className={cn(
              'h-1.5 flex-1 rounded-full transition-colors',
              i <= level ? STRENGTH_COLORS[level] : 'bg-[hsl(var(--muted))]',
            )}
          />
        ))}
      </div>
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-medium text-[hsl(var(--muted-foreground))]">{label}</span>
        <span className="text-xs font-mono text-[hsl(var(--muted-foreground))]">
          {/* Floor (never round up) so the shown bits never over-state the true entropy
              and always fall in the same band as the label (band edges are integers). */}
          {Math.floor(bits)} bits
        </span>
      </div>
      <p className="text-xs text-[hsl(var(--muted-foreground))]">
        Time to crack (offline GPU, {OFFLINE_GPU_RATE_LABEL}):{' '}
        {formatCrackTime(bits, OFFLINE_GPU_GUESSES_PER_SEC)}
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

interface PasswordGeneratorProps {
  /** Called when user confirms password selection (for embedding in forms) */
  onSelect?: (password: string) => void;
  /** Additional className */
  className?: string;
}

export function PasswordGenerator({ onSelect, className }: PasswordGeneratorProps) {
  const { toast } = useToast();
  const { clipboardClearTimeout } = useUserSettings();
  const [mode, setMode] = useState<'password' | 'passphrase'>('password');
  const [length, setLength] = useState(20);
  const [uppercase, setUppercase] = useState(true);
  const [lowercase, setLowercase] = useState(true);
  const [numbers, setNumbers] = useState(true);
  const [symbols, setSymbols] = useState(true);
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(false);
  const [wordCount, setWordCount] = useState(5);
  const [separator, setSeparator] = useState('-');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(true);
  const [copied, setCopied] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [regenerating, setRegenerating] = useState(false);
  // Exact Shannon entropy of the CURRENT generation settings, computed from the inputs
  // (mode/options) — which is exact — rather than by inspecting the generated output.
  const entropyBits = useMemo(() => {
    if (mode === 'passphrase') {
      return passphraseEntropyBits(wordCount, PASSPHRASE_WORDS.length);
    }
    const poolSize = getEffectiveCharsetSize({
      uppercase,
      lowercase,
      numbers,
      symbols,
      excludeAmbiguous,
    });
    return passwordEntropyBits(length, poolSize);
  }, [mode, wordCount, length, uppercase, lowercase, numbers, symbols, excludeAmbiguous]);

  const copyTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const regenerateTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const regenerate = useCallback(() => {
    if (regenerateTimerRef.current) {
      clearTimeout(regenerateTimerRef.current);
    }
    setRegenerating(true);
    // Small delay so the browser can paint the spinner before the synchronous
    // password generation runs (entropy is now O(1), but a long charset x length
    // still does real work, and the paint keeps the control responsive).
    regenerateTimerRef.current = setTimeout(() => {
      let newPassword: string;
      if (mode === 'passphrase') {
        newPassword = generatePassphrase(wordCount, separator);
      } else {
        newPassword = generatePassword({
          length,
          uppercase,
          lowercase,
          numbers,
          symbols,
          excludeAmbiguous,
        });
      }
      setPassword(newPassword);
      setHistory((prev) => {
        const updated = [newPassword, ...prev.filter((p) => p !== newPassword)];
        return updated.slice(0, 5);
      });
      setRegenerating(false);
      regenerateTimerRef.current = null;
    }, 50);
  }, [
    mode,
    length,
    uppercase,
    lowercase,
    numbers,
    symbols,
    excludeAmbiguous,
    wordCount,
    separator,
  ]);

  // Generate on mount and when options change
  useEffect(() => {
    regenerate();
  }, [regenerate]);

  const handleCopy = useCallback(async () => {
    // `password` is empty until the debounced first generation lands, so a click
    // in that window used to put an EMPTY string on the clipboard and report
    // "copied" anyway. The button is disabled in that state; this is the guard
    // behind it.
    if (!password) return;
    try {
      // The guard owns the write, the single app-wide erase deadline and the
      // countdown notice: a later copy anywhere in the app re-arms that one
      // deadline rather than letting this timer erase the newer value early.
      await copySecretToClipboard(password, clipboardClearTimeout * 1000);
      setCopied(true);
      toast({ title: 'Password copied to clipboard', type: 'success', duration: 2000 });
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
      copyTimeoutRef.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      toast({ title: 'Failed to copy', type: 'error' });
    }
  }, [password, toast, clipboardClearTimeout]);

  // Copying a password out of the history list puts a secret on the OS clipboard
  // exactly like the main copy button does, so it must go through the same guard:
  // a direct navigator.clipboard write would be erased by neither the deadline
  // nor lock/logout.
  const handleCopyHistory = useCallback(
    (pw: string) => {
      void copySecretToClipboard(pw, clipboardClearTimeout * 1000).then(
        () => {
          toast({ title: 'Copied', type: 'success', duration: 1500 });
        },
        () => {
          toast({ title: 'Failed to copy', type: 'error' });
        },
      );
    },
    [toast, clipboardClearTimeout],
  );

  // Cleanup on unmount. The clipboard erase deadline is deliberately NOT
  // cancelled here — it belongs to the shared guard so the copied password is
  // still erased after navigating away. Lock/logout erase it immediately instead.
  useEffect(() => {
    return () => {
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
      if (regenerateTimerRef.current) clearTimeout(regenerateTimerRef.current);
      // Clear generated password history to prevent sensitive data from lingering
      // in memory after the component is unmounted.
      setHistory([]);
    };
  }, []);

  return (
    <div className={cn('space-y-4', className)}>
      {/* Mode toggle */}
      <div className="flex rounded-lg border border-[hsl(var(--border))] p-1">
        <button
          type="button"
          onClick={() => setMode('password')}
          className={cn(
            'flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition-colors',
            mode === 'password'
              ? 'bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))]'
              : 'text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]',
          )}
        >
          Password
        </button>
        <button
          type="button"
          onClick={() => setMode('passphrase')}
          className={cn(
            'flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition-colors',
            mode === 'passphrase'
              ? 'bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))]'
              : 'text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]',
          )}
        >
          Passphrase
        </button>
      </div>

      {/* Generated password display */}
      <div className="flex items-center gap-2 rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--muted))] p-3">
        <code className="flex-1 break-all font-mono text-sm text-[hsl(var(--foreground))]">
          {showPassword ? password : '\u2022'.repeat(Math.min(password.length, 40))}
        </code>
        <button
          type="button"
          onClick={() => setShowPassword((p) => !p)}
          className="shrink-0 rounded p-1 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors"
          aria-label={showPassword ? 'Hide password' : 'Show password'}
        >
          {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
        <button
          type="button"
          onClick={() => void handleCopy()}
          disabled={!password}
          className="shrink-0 rounded p-1 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors disabled:cursor-not-allowed disabled:opacity-50"
          aria-label="Copy password"
        >
          {copied ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
        </button>
        <button
          type="button"
          onClick={regenerate}
          className="shrink-0 rounded p-1 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors"
          aria-label="Regenerate password"
        >
          {regenerating ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <RefreshCw className="h-4 w-4" />
          )}
        </button>
      </div>

      {/* Strength indicator */}
      {password && <StrengthIndicator bits={entropyBits} />}

      {/* Password mode options */}
      {mode === 'password' && (
        <div className="space-y-4">
          {/* Length slider */}
          <div>
            <div className="flex items-center justify-between">
              <label
                htmlFor="pw-length"
                className="text-sm font-medium text-[hsl(var(--foreground))]"
              >
                Length
              </label>
              <span className="text-sm font-mono text-[hsl(var(--muted-foreground))]">
                {length}
              </span>
            </div>
            <input
              id="pw-length"
              type="range"
              min={8}
              max={128}
              value={length}
              onChange={(e) => setLength(Number(e.target.value))}
              className="mt-1 w-full accent-[hsl(var(--primary))]"
            />
          </div>

          {/* Toggles */}
          <div className="grid grid-cols-2 gap-3">
            <Toggle label="Uppercase (A-Z)" checked={uppercase} onChange={setUppercase} />
            <Toggle label="Lowercase (a-z)" checked={lowercase} onChange={setLowercase} />
            <Toggle label="Numbers (0-9)" checked={numbers} onChange={setNumbers} />
            <Toggle label="Symbols (!@#$)" checked={symbols} onChange={setSymbols} />
            <Toggle
              label="Exclude ambiguous"
              checked={excludeAmbiguous}
              onChange={setExcludeAmbiguous}
              tooltip="Removes easily confused characters: l, I, 1, O, 0"
            />
          </div>
        </div>
      )}

      {/* Passphrase mode options */}
      {mode === 'passphrase' && (
        <div className="space-y-4">
          {/* Word count slider */}
          <div>
            <div className="flex items-center justify-between">
              <label
                htmlFor="word-count"
                className="text-sm font-medium text-[hsl(var(--foreground))]"
              >
                Word Count
              </label>
              <span className="text-sm font-mono text-[hsl(var(--muted-foreground))]">
                {wordCount}
              </span>
            </div>
            <input
              id="word-count"
              type="range"
              min={3}
              max={24}
              value={wordCount}
              onChange={(e) => setWordCount(Number(e.target.value))}
              className="mt-1 w-full accent-[hsl(var(--primary))]"
            />
          </div>

          {/* Separator */}
          <div>
            <label
              htmlFor="separator"
              className="text-sm font-medium text-[hsl(var(--foreground))]"
            >
              Separator
            </label>
            <input
              id="separator"
              type="text"
              maxLength={5}
              value={separator}
              onChange={(e) => setSeparator(e.target.value)}
              className="mt-1 w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
            />
          </div>
        </div>
      )}

      {/* Action buttons */}
      <div className="flex gap-2">
        {onSelect && (
          <button
            type="button"
            onClick={() => onSelect(password)}
            className="flex-1 rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity"
          >
            Use Password
          </button>
        )}
        <button
          type="button"
          onClick={() => setShowHistory((p) => !p)}
          className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
        >
          <History className="h-4 w-4" />
          History ({history.length})
        </button>
      </div>

      {/* History */}
      {showHistory && history.length > 0 && (
        <div className="space-y-1 rounded-lg border border-[hsl(var(--border))] p-3">
          <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
            Recent passwords
          </p>
          {history.map((pw, idx) => (
            <div
              key={`${pw}-${idx}`}
              className="flex items-center gap-2 rounded px-2 py-1 text-xs hover:bg-[hsl(var(--accent))]"
            >
              <code className="flex-1 truncate font-mono text-[hsl(var(--foreground))]">{pw}</code>
              <button
                type="button"
                onClick={() => handleCopyHistory(pw)}
                className="shrink-0 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]"
                aria-label="Copy password"
              >
                <Copy className="h-3 w-3" />
              </button>
              {onSelect && (
                <button
                  type="button"
                  onClick={() => onSelect(pw)}
                  className="shrink-0 text-xs text-[hsl(var(--primary))] hover:underline"
                >
                  Use
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Toggle helper component
// ---------------------------------------------------------------------------

function Toggle({
  label,
  checked,
  onChange,
  tooltip,
}: {
  label: string;
  checked: boolean;
  onChange: (value: boolean) => void;
  tooltip?: string;
}) {
  return (
    <label className="flex items-center gap-2 cursor-pointer" title={tooltip}>
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="h-4 w-4 rounded border-[hsl(var(--input))] text-[hsl(var(--primary))] accent-[hsl(var(--primary))] focus:ring-[hsl(var(--ring))]"
      />
      <span className="text-sm text-[hsl(var(--foreground))]">
        {label}
        {tooltip && (
          <span
            className="ml-1 inline-flex h-4 w-4 items-center justify-center rounded-full bg-[hsl(var(--muted))] text-[10px] text-[hsl(var(--muted-foreground))] align-middle"
            title={tooltip}
          >
            ?
          </span>
        )}
      </span>
    </label>
  );
}
