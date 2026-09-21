import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Copy, RefreshCw, Check, Eye, EyeOff, History, Loader2 } from 'lucide-react';
import {
  MAX_PASSWORD_CLASS_MINIMUM,
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
} from '@hvault/shared';
import { cn, getApiErrorMessage } from '../../lib/utils';
import { PASSPHRASE_WORDS } from '../../constants/passphraseWords';
import {
  classifyStrength,
  formatCrackTime,
  passphraseEntropyBits,
  OFFLINE_GPU_GUESSES_PER_SEC,
  OFFLINE_GPU_RATE_LABEL,
} from '../../utils/passwordEntropy';
import {
  PasswordGeneratorError,
  generatePassphrase,
  generatePassword,
  passwordEntropyBitsForOptions,
  type PasswordGenOptionsLike,
} from '../../lib/passwordGenerator';
import { useToast } from '../ui/Toast';
import { clearSettingsCache, useUserSettings } from '../../hooks/useUserSettings';
import { updateSettingsApi } from '../../services/api/userApi';
import { copySecretToClipboard } from '../../services/clipboard/clipboardService';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
// Generation, counting and the exact entropy live in ../../lib/passwordGenerator.
// This component owns the controls and nothing else: it never draws a random
// number itself, so there is one place where bias could be introduced and one
// place where it has to be proved absent.

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
function StrengthIndicator({
  bits,
  constraintCostBits,
}: {
  bits: number;
  constraintCostBits: number;
}) {
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
      {/* Required minimums shrink the keyspace. Saying so is the honest thing:
          the near-universal belief is that complexity rules add strength. */}
      {constraintCostBits > 0 && (
        <p className="text-xs text-[hsl(var(--muted-foreground))]">
          Required minimums cost {constraintCostBits.toFixed(2)} bits
        </p>
      )}
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
  const { clipboardClearTimeout, defaultPasswordOptions } = useUserSettings();
  const [mode, setMode] = useState<'password' | 'passphrase'>('password');
  // Seeded from the account's saved policy. `useState`'s initialiser runs once,
  // so a later profile fetch does not yank the controls out from under someone
  // mid-adjustment; the "Save as my default" action is what writes back.
  const [length, setLength] = useState(defaultPasswordOptions.length);
  const [uppercase, setUppercase] = useState(defaultPasswordOptions.uppercase);
  const [lowercase, setLowercase] = useState(defaultPasswordOptions.lowercase);
  const [numbers, setNumbers] = useState(defaultPasswordOptions.numbers);
  const [symbols, setSymbols] = useState(defaultPasswordOptions.symbols);
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(defaultPasswordOptions.excludeAmbiguous);
  const [minUppercase, setMinUppercase] = useState(defaultPasswordOptions.minUppercase);
  const [minLowercase, setMinLowercase] = useState(defaultPasswordOptions.minLowercase);
  const [minNumbers, setMinNumbers] = useState(defaultPasswordOptions.minNumbers);
  const [minSymbols, setMinSymbols] = useState(defaultPasswordOptions.minSymbols);
  const [wordCount, setWordCount] = useState(5);
  const [separator, setSeparator] = useState('-');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(true);
  const [copied, setCopied] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [regenerating, setRegenerating] = useState(false);
  const [savingDefaults, setSavingDefaults] = useState(false);

  const options: PasswordGenOptionsLike = {
    length,
    uppercase,
    lowercase,
    numbers,
    symbols,
    excludeAmbiguous,
    minUppercase,
    minLowercase,
    minNumbers,
    minSymbols,
  };

  // A policy with no character class cannot generate anything. The controls make
  // this reachable (all four boxes unticked), so it is a state the UI has to
  // name rather than a case to fall back from: the generator used to answer it
  // by silently substituting lowercase, which is a weaker password than the one
  // the user thought they had asked for.
  const noClassSelected = !uppercase && !lowercase && !numbers && !symbols;
  const requiredTotal =
    (uppercase ? minUppercase : 0) +
    (lowercase ? minLowercase : 0) +
    (numbers ? minNumbers : 0) +
    (symbols ? minSymbols : 0);
  const tooManyRequired = !noClassSelected && requiredTotal > length;
  const canGenerate = mode === 'passphrase' || (!noClassSelected && !tooManyRequired);
  // Exact Shannon entropy of the CURRENT generation settings, computed from the inputs
  // (mode/options) — which is exact — rather than by inspecting the generated output.
  const entropyBits = useMemo(() => {
    if (mode === 'passphrase') {
      return passphraseEntropyBits(wordCount, PASSPHRASE_WORDS.length);
    }
    if (noClassSelected || tooManyRequired) return 0;
    // The EXACT entropy of the constrained keyspace, not `length * log2(pool)`.
    // Once a minimum is required the two differ, and they differ in the
    // attacker-favourable direction, which is the one this readout promises
    // never to take.
    return passwordEntropyBitsForOptions(options);
  }, [
    mode,
    wordCount,
    length,
    uppercase,
    lowercase,
    numbers,
    symbols,
    excludeAmbiguous,
    minUppercase,
    minLowercase,
    minNumbers,
    minSymbols,
    noClassSelected,
    tooManyRequired,
  ]);

  // The honest cost of the required minimums, shown only when there are any.
  const constraintCostBits = useMemo(() => {
    if (mode === 'passphrase' || noClassSelected || tooManyRequired || requiredTotal === 0) {
      return 0;
    }
    const unconstrained = passwordEntropyBitsForOptions({
      ...options,
      minUppercase: 0,
      minLowercase: 0,
      minNumbers: 0,
      minSymbols: 0,
    });
    return unconstrained - entropyBits;
  }, [
    mode,
    noClassSelected,
    tooManyRequired,
    requiredTotal,
    entropyBits,
    length,
    uppercase,
    lowercase,
    numbers,
    symbols,
    excludeAmbiguous,
  ]);

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
      try {
        newPassword =
          mode === 'passphrase'
            ? generatePassphrase(wordCount, separator, PASSPHRASE_WORDS)
            : generatePassword(options);
      } catch (error) {
        // A policy the generator refuses: no character class at all, or more
        // required characters than there are positions. Clear the field rather
        // than leaving a stale password beside contradictory settings, which
        // would read as though it satisfied them.
        setPassword('');
        setRegenerating(false);
        regenerateTimerRef.current = null;
        if (!(error instanceof PasswordGeneratorError)) throw error;
        return;
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
    minUppercase,
    minLowercase,
    minNumbers,
    minSymbols,
    wordCount,
    separator,
  ]);

  // Generate on mount and when options change
  useEffect(() => {
    // No `canGenerate` gate here, deliberately. The generator's own spec builder
    // already refuses a policy it cannot satisfy, and duplicating that decision
    // in the effect meant two places had to agree about what is generable; the
    // catch inside `regenerate` is the single place that decides, and clearing
    // the field is what it does about it. `canGenerate` remains, but only to
    // drive what the UI SAYS.
    regenerate();
  }, [regenerate]);

  /**
   * Persist the current policy as this account's default.
   *
   * The settings endpoint has accepted `defaultPasswordOptions` since it was
   * written; nothing ever sent it, so the stored value has always been whatever
   * the model defaulted to. This is the action that makes the field mean
   * something, and `clearSettingsCache()` is what makes every other mounted
   * consumer re-read it rather than keep rendering the pre-save value.
   */
  const handleSaveDefaults = useCallback(async () => {
    setSavingDefaults(true);
    try {
      await updateSettingsApi({
        defaultPasswordLength: length,
        defaultPasswordOptions: options,
      });
      clearSettingsCache();
      toast({ title: 'Saved as your default', type: 'success', duration: 2000 });
    } catch (error) {
      toast({ title: getApiErrorMessage(error, 'Could not save your default'), type: 'error' });
    } finally {
      setSavingDefaults(false);
    }
  }, [
    length,
    uppercase,
    lowercase,
    numbers,
    symbols,
    excludeAmbiguous,
    minUppercase,
    minLowercase,
    minNumbers,
    minSymbols,
    toast,
  ]);

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
      // The history is NOT cleared here, and the `setHistory([])` that used to
      // sit on this line was removed rather than kept for reassurance: setting
      // state on an unmounting component is a no-op that React discards, so it
      // delivered none of the safety its comment claimed.
      //
      // What is actually true is narrower and worth stating instead. The history
      // is five generated passwords held as ordinary strings in this component's
      // state; they become unreachable when it unmounts and are collected
      // whenever the engine decides to, and being strings they cannot be
      // overwritten in the meantime. Anything COPIED from the list is a separate
      // matter and is covered: it goes through `copySecretToClipboard`, so the
      // shared erase deadline owns it.
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
      {password && <StrengthIndicator bits={entropyBits} constraintCostBits={constraintCostBits} />}

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
              min={MIN_PASSWORD_LENGTH}
              max={MAX_PASSWORD_LENGTH}
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

          {/* Minimum counts, one per ENABLED class. A stepper for a class that
              is switched off would be a control with no effect: the generator
              drops the class entirely, which is what makes its minimum inert. */}
          <div className="space-y-2">
            <p className="text-sm font-medium text-[hsl(var(--foreground))]">
              Minimum characters of each type
            </p>
            <div className="grid grid-cols-2 gap-3">
              {uppercase && (
                <MinimumStepper label="Uppercase" value={minUppercase} onChange={setMinUppercase} />
              )}
              {lowercase && (
                <MinimumStepper label="Lowercase" value={minLowercase} onChange={setMinLowercase} />
              )}
              {numbers && (
                <MinimumStepper label="Numbers" value={minNumbers} onChange={setMinNumbers} />
              )}
              {symbols && (
                <MinimumStepper label="Symbols" value={minSymbols} onChange={setMinSymbols} />
              )}
            </div>
            {tooManyRequired && (
              <p role="alert" className="text-xs text-[hsl(var(--destructive))]">
                Those minimums need {requiredTotal} characters, but the password is only {length}{' '}
                long.
              </p>
            )}
          </div>

          {noClassSelected && (
            <p role="alert" className="text-xs text-[hsl(var(--destructive))]">
              Select at least one character type to generate a password.
            </p>
          )}

          <button
            type="button"
            onClick={() => void handleSaveDefaults()}
            disabled={savingDefaults || !canGenerate}
            className="text-xs text-[hsl(var(--muted-foreground))] underline underline-offset-2 hover:text-[hsl(var(--foreground))] disabled:opacity-50"
          >
            {savingDefaults ? 'Saving…' : 'Save as my default'}
          </button>
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

/**
 * A bounded numeric stepper for a per-class minimum.
 *
 * Buttons rather than `<input type="number">`, because the range is tiny and a
 * free-text number field invites a value the generator would have to clamp
 * silently. The bound comes from the shared constant, so the control cannot
 * offer a policy the generator refuses to honour.
 */
function MinimumStepper({
  label,
  value,
  onChange,
}: {
  label: string;
  value: number;
  onChange: (value: number) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-sm text-[hsl(var(--foreground))]">{label}</span>
      <span className="flex items-center gap-1">
        <button
          type="button"
          onClick={() => onChange(Math.max(0, value - 1))}
          disabled={value <= 0}
          aria-label={`Decrease minimum ${label.toLowerCase()}`}
          className="h-6 w-6 rounded border border-[hsl(var(--input))] text-sm leading-none text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] disabled:opacity-40"
        >
          -
        </button>
        <output
          aria-label={`Minimum ${label.toLowerCase()}`}
          className="w-5 text-center text-sm font-mono text-[hsl(var(--foreground))]"
        >
          {value}
        </output>
        <button
          type="button"
          onClick={() => onChange(Math.min(MAX_PASSWORD_CLASS_MINIMUM, value + 1))}
          disabled={value >= MAX_PASSWORD_CLASS_MINIMUM}
          aria-label={`Increase minimum ${label.toLowerCase()}`}
          className="h-6 w-6 rounded border border-[hsl(var(--input))] text-sm leading-none text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] disabled:opacity-40"
        >
          +
        </button>
      </span>
    </div>
  );
}

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
