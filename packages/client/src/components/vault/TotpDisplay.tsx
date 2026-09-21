import { useCallback, useEffect, useRef, useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { useToast } from '../ui/Toast';
import { useUserSettings } from '../../hooks/useUserSettings';
import { copySecretToClipboard } from '../../services/clipboard/clipboardService';
import {
  describeTotpFailure,
  parseTotpValue,
  TOTP_DEFAULTS,
  type ParsedTotp,
} from '../../lib/totp';

/**
 * The live one-time code for a stored TOTP value. ONE definition, shared by the
 * vault's item detail view and the authenticator-import tool, so the two cannot
 * disagree about what a stored value means or how a code is presented.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS FIXES, AND THE TRAP IN FIXING IT
 * ---------------------------------------------------------------------------
 *
 * The version this replaces accepted a bare base32 secret whose length was a
 * multiple of 8, and nothing else. Two shapes the application itself produces
 * therefore rendered "Invalid TOTP secret": a 26-character (16-byte) secret,
 * which is what most services issue, and a full `otpauth://` URI, which every
 * third-party import parser stores verbatim and which `toOtpauthUri` emits on
 * every export. An export followed by a re-import broke the tile.
 *
 * The trap is that the obvious fix is worse than the bug. Accepting a URI while
 * ignoring its parameters, or dropping the length rule entirely, makes this
 * component generate codes that look right and are wrong, with nothing to show
 * for it. So the parameters are honoured (`lib/totp.ts` reports an algorithm or
 * digit count it cannot generate as a FAILURE rather than defaulting), and an
 * `otpauth://hotp/...` value gets its OWN sentence instead of being generated as
 * though it were time-based. Before this change the base32 gate rejected HOTP by
 * accident; a naive fix would have started producing a confidently wrong code
 * for it forever.
 *
 * `otpauth` stays a lazy import, used only to generate. Understanding the stored
 * value is `lib/totp.ts`'s job and needs no dependency at all.
 */

/** Group a code for reading: `123 456`, `1234 5678`, anything else verbatim. */
function groupCode(code: string): string {
  if (code.length !== 6 && code.length !== 8) return code;
  const half = code.length / 2;
  return `${code.slice(0, half)} ${code.slice(half)}`;
}

function placeholderFor(digits: number): string {
  return '-'.repeat(digits);
}

function Panel({ tone, children }: { tone: 'normal' | 'error'; children: React.ReactNode }) {
  const border =
    tone === 'error' ? 'border-[hsl(var(--destructive))]' : 'border-[hsl(var(--border))]';
  return (
    <div className={`rounded-lg border ${border} bg-[hsl(var(--card))] p-3`}>
      <p className="text-xs font-medium uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
        TOTP Code
      </p>
      {children}
    </div>
  );
}

export function TotpDisplay({ secret }: { secret: string }) {
  const parsed = parseTotpValue(secret);
  const generatable: ParsedTotp | null =
    parsed.ok && parsed.value.type === 'totp' ? parsed.value : null;
  const period = generatable?.period ?? TOTP_DEFAULTS.period;
  const digits = generatable?.digits ?? TOTP_DEFAULTS.digits;

  const [code, setCode] = useState(() => placeholderFor(digits));
  const [secondsLeft, setSecondsLeft] = useState(period);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();
  const { clipboardClearTimeout } = useUserSettings();
  const copyTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const clearTimeoutMs = clipboardClearTimeout * 1000;

  // Read off `parsed` rather than passing the object itself, so the effect does
  // not re-run on every render just because the parse produced a fresh object.
  const secretKey = generatable?.secret ?? '';
  const algorithm = generatable?.algorithm ?? TOTP_DEFAULTS.algorithm;

  useEffect(() => {
    if (secretKey === '') return undefined;

    let intervalId: ReturnType<typeof setInterval> | null = null;
    let cancelled = false;

    const initTotp = async () => {
      try {
        const { TOTP } = await import('otpauth');
        if (cancelled) return;

        const totp = new TOTP({ secret: secretKey, digits, period, algorithm });

        const generate = () => {
          setCode(totp.generate());
          const epoch = Math.floor(Date.now() / 1000);
          setSecondsLeft(period - (epoch % period));
        };

        setError(null);
        generate();
        intervalId = setInterval(generate, 1000);
      } catch {
        if (!cancelled) {
          setCode(placeholderFor(digits));
          setError('Failed to generate TOTP code');
        }
      }
    };

    void initTotp();
    return () => {
      cancelled = true;
      if (intervalId) clearInterval(intervalId);
    };
  }, [secretKey, digits, period, algorithm]);

  const handleCopy = useCallback(async () => {
    if (code === placeholderFor(digits) || error) return;
    try {
      // One shared deadline, owned by the most recent copy (see CopyField).
      await copySecretToClipboard(code, clearTimeoutMs);
      setCopied(true);
      toast({ title: 'TOTP code copied', type: 'success', duration: 2000 });
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
      copyTimeoutRef.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      toast({ title: 'Failed to copy', type: 'error' });
    }
  }, [code, digits, error, toast, clearTimeoutMs]);

  useEffect(() => {
    return () => {
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
    };
  }, []);

  if (!parsed.ok) {
    return (
      <Panel tone="error">
        <p className="mt-1 text-sm text-[hsl(var(--destructive))]">
          {describeTotpFailure(parsed.reason)}
        </p>
      </Panel>
    );
  }

  if (parsed.value.type === 'hotp') {
    return (
      <Panel tone="error">
        <p className="mt-1 text-sm text-[hsl(var(--destructive))]">
          Counter-based (HOTP) codes are not generated here
        </p>
      </Panel>
    );
  }

  if (error) {
    return (
      <Panel tone="error">
        <p className="mt-1 text-sm text-[hsl(var(--destructive))]">{error}</p>
      </Panel>
    );
  }

  const progress = (secondsLeft / period) * 100;

  return (
    <Panel tone="normal">
      <div className="mt-1 flex items-center gap-3">
        <button
          type="button"
          onClick={() => void handleCopy()}
          className="group flex items-center gap-2 rounded px-1 py-0.5 hover:bg-[hsl(var(--accent))] transition-colors"
          aria-label="Copy TOTP code"
        >
          <span className="font-mono text-2xl font-bold tracking-widest text-[hsl(var(--foreground))]">
            {groupCode(code)}
          </span>
          {copied ? (
            <Check className="h-4 w-4 text-green-500" />
          ) : (
            <Copy className="h-4 w-4 text-[hsl(var(--muted-foreground))] opacity-0 group-hover:opacity-100 transition-opacity" />
          )}
        </button>
        <div className="relative h-8 w-8">
          <svg className="h-8 w-8 -rotate-90" viewBox="0 0 36 36">
            <circle cx="18" cy="18" r="16" fill="none" stroke="hsl(var(--muted))" strokeWidth="3" />
            <circle
              cx="18"
              cy="18"
              r="16"
              fill="none"
              stroke="hsl(var(--primary))"
              strokeWidth="3"
              strokeDasharray={`${progress} 100`}
              strokeLinecap="round"
            />
          </svg>
          <span className="absolute inset-0 flex items-center justify-center text-xs font-medium text-[hsl(var(--foreground))]">
            {secondsLeft}
          </span>
        </div>
      </div>
    </Panel>
  );
}
