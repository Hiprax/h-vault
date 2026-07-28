import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router';
import {
  ArrowLeft,
  Copy,
  Check,
  Eye,
  EyeOff,
  Pencil,
  Trash2,
  Star,
  FolderOpen,
  Key,
  FileText,
  CreditCard,
  User,
  Lock,
  Clock,
  History,
  ExternalLink,
  Loader2,
  RotateCcw,
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { cn, getApiErrorMessage, isSafeUrl } from '../../lib/utils';
import { hasAnyValue, isUndecodableData } from '../../lib/vaultData';
import { ErrorBoundary } from '../layout/ErrorBoundary';
import { useVaultStore, type DecryptedVaultItem } from '../../stores/vaultStore';
import { useAuthStore } from '../../stores/authStore';
import { cryptoService } from '../../services/crypto/cryptoService';
import { useToast } from '../ui/Toast';
import { useInlineDialog } from '../ui/Dialog';
import { BackupCodesSection } from './BackupCodesSection';
import { useUserSettings } from '../../hooks/useUserSettings';
import { copySecretToClipboard } from '../../services/clipboard/clipboardService';
import type { ItemType } from '@hvault/shared';
import type {
  ILoginData,
  ISecretData,
  INoteData,
  ICardData,
  IIdentityData,
  IPasswordHistoryEntry,
} from '@hvault/shared';

const ICON_MAP: Record<ItemType, typeof Key> = {
  login: Key,
  note: FileText,
  card: CreditCard,
  identity: User,
  secret: Lock,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  });
}

// ---------------------------------------------------------------------------
// Copy field component
// ---------------------------------------------------------------------------

interface CopyFieldProps {
  label: string;
  value: string;
  masked?: boolean;
  mono?: boolean;
  isLink?: boolean;
  /**
   * Preserve line breaks in the rendered value.
   *
   * Opt-in rather than the default, and every FREE-TEXT field now opts in: `notes`
   * on a login, card and identity, a secret's `description` and multi-line `value`
   * (a PEM key or a certificate is exactly that), and custom-field values, which an
   * import can populate with several lines. Each of those is edited through a
   * `<textarea>` or arrives from a source file that permits newlines, so collapsing
   * them on screen misrepresented what was stored.
   *
   * It stays opt-in because the SINGLE-line fields must keep collapsing: a username,
   * a URI, a card number, a ZIP code and a TOTP seed cannot legitimately span lines,
   * and `whitespace-pre-wrap` on those would let a crafted value push a row's layout
   * around. The stored and COPIED string is byte-identical either way; this controls
   * display only.
   *
   * A secure note's `content` needs nothing here — `NoteDetail` renders it through
   * react-markdown or its own `whitespace-pre-wrap` block, not through this
   * component.
   */
  multiline?: boolean;
}

function CopyField({
  label,
  value,
  masked = false,
  mono = false,
  isLink = false,
  multiline = false,
}: CopyFieldProps) {
  const { toast } = useToast();
  const { clipboardClearTimeout } = useUserSettings();
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const clearTimeoutMs = clipboardClearTimeout * 1000;

  const handleCopy = useCallback(async () => {
    try {
      // The guard owns the write, the one app-wide erase deadline and the
      // countdown notice. Copying another field re-arms that single deadline
      // instead of leaving an older field's timer to erase this value early, and
      // the erase still happens if this component unmounts first.
      await copySecretToClipboard(value, clearTimeoutMs);
      setCopied(true);
      toast({ title: `${label} copied`, type: 'success', duration: 2000 });
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
      timeoutRef.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      toast({ title: 'Failed to copy', type: 'error' });
    }
  }, [value, label, toast, clearTimeoutMs]);

  useEffect(() => {
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, []);

  const displayValue = masked && !revealed ? '\u2022'.repeat(Math.min(value.length, 32)) : value;

  return (
    <div className="group flex items-start gap-3 rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-3">
      <div className="min-w-0 flex-1">
        <p className="text-xs font-medium uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
          {label}
        </p>
        {isLink && isSafeUrl(value) ? (
          <a
            href={value}
            target="_blank"
            rel="noopener noreferrer"
            className={cn(
              'mt-1 flex items-center gap-1 text-sm text-[hsl(var(--primary))] hover:underline',
              mono && 'font-mono',
            )}
          >
            {displayValue}
            <ExternalLink className="h-3 w-3 shrink-0" />
          </a>
        ) : (
          <p
            className={cn(
              'mt-1 break-all text-sm text-[hsl(var(--foreground))]',
              mono && 'font-mono',
              multiline && 'whitespace-pre-wrap',
            )}
          >
            {displayValue || '\u2014'}
          </p>
        )}
      </div>
      <div className="flex shrink-0 items-center gap-1">
        {masked && (
          <button
            type="button"
            onClick={() => setRevealed((p) => !p)}
            className="rounded p-1 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors"
            aria-label={revealed ? 'Hide value' : 'Reveal value'}
          >
            {revealed ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </button>
        )}
        <button
          type="button"
          onClick={() => void handleCopy()}
          className="rounded p-1 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors"
          aria-label={`Copy ${label}`}
        >
          {copied ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// TOTP component
// ---------------------------------------------------------------------------

const BASE32_REGEX = /^[A-Z2-7]+={0,6}$/;

function isValidBase32(value: string): boolean {
  const normalized = value.replace(/\s+/g, '').toUpperCase();
  if (normalized.length === 0 || !BASE32_REGEX.test(normalized)) return false;
  // Base32 strings (including padding) must have a total length that is a multiple of 8
  return normalized.length % 8 === 0;
}

function TotpDisplay({ secret }: { secret: string }) {
  const [code, setCode] = useState('------');
  const [secondsLeft, setSecondsLeft] = useState(30);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();
  const { clipboardClearTimeout } = useUserSettings();
  const copyTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const clearTimeoutMs = clipboardClearTimeout * 1000;

  useEffect(() => {
    let intervalId: ReturnType<typeof setInterval> | null = null;
    let cancelled = false;

    const initTotp = async () => {
      try {
        const normalized = secret.replace(/\s+/g, '').toUpperCase();
        if (!isValidBase32(normalized)) {
          if (!cancelled) {
            setCode('------');
            setError('Invalid TOTP secret (not valid base32)');
          }
          return;
        }

        const { TOTP } = await import('otpauth');
        if (cancelled) return;

        const totp = new TOTP({
          secret: normalized,
          digits: 6,
          period: 30,
          algorithm: 'SHA1',
        });

        const generate = () => {
          setCode(totp.generate());
          const epoch = Math.floor(Date.now() / 1000);
          setSecondsLeft(30 - (epoch % 30));
        };

        setError(null);
        generate();
        intervalId = setInterval(generate, 1000);
      } catch {
        if (!cancelled) {
          setCode('------');
          setError('Failed to generate TOTP code');
        }
      }
    };

    void initTotp();
    return () => {
      cancelled = true;
      if (intervalId) clearInterval(intervalId);
    };
  }, [secret]);

  const handleCopy = useCallback(async () => {
    if (code === '------' || error) return;
    try {
      // One shared deadline, owned by the most recent copy (see CopyField above).
      await copySecretToClipboard(code, clearTimeoutMs);
      setCopied(true);
      toast({ title: 'TOTP code copied', type: 'success', duration: 2000 });
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
      copyTimeoutRef.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      toast({ title: 'Failed to copy', type: 'error' });
    }
  }, [code, error, toast, clearTimeoutMs]);

  useEffect(() => {
    return () => {
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
    };
  }, []);

  const progress = (secondsLeft / 30) * 100;

  if (error) {
    return (
      <div className="rounded-lg border border-[hsl(var(--destructive))] bg-[hsl(var(--card))] p-3">
        <p className="text-xs font-medium uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
          TOTP Code
        </p>
        <p className="mt-1 text-sm text-[hsl(var(--destructive))]">{error}</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-3">
      <p className="text-xs font-medium uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
        TOTP Code
      </p>
      <div className="mt-1 flex items-center gap-3">
        <button
          type="button"
          onClick={() => void handleCopy()}
          className="group flex items-center gap-2 rounded px-1 py-0.5 hover:bg-[hsl(var(--accent))] transition-colors"
          aria-label="Copy TOTP code"
        >
          <span className="font-mono text-2xl font-bold tracking-widest text-[hsl(var(--foreground))]">
            {code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code}
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
    </div>
  );
}

// ---------------------------------------------------------------------------
// Password history section
// ---------------------------------------------------------------------------

interface PasswordHistoryProps {
  entries: IPasswordHistoryEntry[];
}

function PasswordHistorySection({ entries }: PasswordHistoryProps) {
  const vaultKey = useAuthStore((s) => s.vaultKey);
  const [decrypted, setDecrypted] = useState<{ password: string; changedAt: string }[]>([]);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const handleExpand = useCallback(async () => {
    if (expanded) {
      setExpanded(false);
      return;
    }
    if (!vaultKey || entries.length === 0) return;
    setLoading(true);
    try {
      const results = await Promise.allSettled(
        entries.map(async (entry) => {
          const password = await cryptoService.decryptData(
            entry.encryptedPassword,
            entry.iv,
            entry.tag,
            vaultKey,
          );
          return { password, changedAt: entry.changedAt };
        }),
      );
      const fulfilled = results
        .filter(
          (r): r is PromiseFulfilledResult<{ password: string; changedAt: string }> =>
            r.status === 'fulfilled',
        )
        .map((r) => r.value);
      setDecrypted(fulfilled);
      setExpanded(true);
    } catch {
      // Decryption failed
    } finally {
      setLoading(false);
    }
  }, [expanded, entries, vaultKey]);

  if (entries.length === 0) return null;

  return (
    <div className="space-y-2">
      <button
        type="button"
        onClick={() => void handleExpand()}
        className="flex items-center gap-2 text-sm font-medium text-[hsl(var(--foreground))] hover:text-[hsl(var(--primary))] transition-colors"
      >
        <History className="h-4 w-4" />
        Password History ({entries.length})
      </button>
      {expanded && (
        <div className="space-y-1">
          {decrypted.map((entry, idx) => (
            <div key={idx} className="space-y-1">
              <CopyField
                label={`Previous password (${formatDate(entry.changedAt)})`}
                value={entry.password}
                masked
                mono
              />
            </div>
          ))}
        </div>
      )}
      {loading && <p className="text-xs text-[hsl(var(--muted-foreground))]">Decrypting...</p>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Type-specific detail views
// ---------------------------------------------------------------------------

/**
 * The custom-field rows of an item whose form offers the Boolean type — a login and
 * (since it gained custom-field controls) an identity.
 *
 * `SecretDetail` deliberately keeps its own simpler renderer: the secret form has
 * only ever offered text/hidden, so the same split holds on both sides.
 */
function CustomFieldRows({
  fields,
}: {
  fields: readonly { name: string; value: string; type: 'text' | 'hidden' | 'boolean' }[];
}) {
  return (
    <>
      {fields.map((field, idx) =>
        field.type === 'boolean' ? (
          <div
            key={idx}
            className="flex items-center gap-3 rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-3"
          >
            <div className="min-w-0 flex-1">
              <p className="text-xs font-medium uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                {field.name}
              </p>
              <p className="mt-1 flex items-center gap-2 text-sm text-[hsl(var(--foreground))]">
                <span
                  className={cn(
                    'inline-block h-4 w-4 rounded-sm border',
                    field.value === 'true'
                      ? 'border-[hsl(var(--primary))] bg-[hsl(var(--primary))]'
                      : 'border-[hsl(var(--input))] bg-[hsl(var(--background))]',
                  )}
                >
                  {field.value === 'true' && (
                    <Check className="h-4 w-4 text-[hsl(var(--primary-foreground))]" />
                  )}
                </span>
                {field.value === 'true' ? 'Yes' : 'No'}
              </p>
            </div>
          </div>
        ) : (
          <CopyField
            key={idx}
            label={field.name}
            value={field.value}
            masked={field.type === 'hidden'}
            mono={field.type === 'hidden'}
            multiline
          />
        ),
      )}
    </>
  );
}

function LoginDetail({
  data,
  itemId,
  itemName,
  canEdit,
}: {
  data: ILoginData;
  itemId: string;
  itemName: string;
  canEdit: boolean;
}) {
  return (
    <div className="space-y-3">
      <CopyField label="Username" value={data.username} mono />
      <CopyField label="Password" value={data.password} masked mono />
      {data.uris.map((uri, idx) => (
        <CopyField key={idx} label={`URI ${idx + 1}`} value={uri.uri} isLink />
      ))}
      {data.totp && <TotpDisplay secret={data.totp} />}
      <BackupCodesSection itemId={itemId} itemName={itemName} data={data} canEdit={canEdit} />
      {data.notes && <CopyField label="Notes" value={data.notes} multiline />}
      <CustomFieldRows fields={data.customFields} />
    </div>
  );
}

function formatRemainingTime(expiresAt: string): { text: string; isExpired: boolean } {
  const now = Date.now();
  const expiry = new Date(expiresAt).getTime();
  const diff = expiry - now;

  if (diff <= 0) {
    const elapsed = Math.abs(diff);
    const days = Math.floor(elapsed / (1000 * 60 * 60 * 24));
    const hours = Math.floor((elapsed % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    if (days > 0) {
      return { text: `Expired ${String(days)}d ${String(hours)}h ago`, isExpired: true };
    }
    const minutes = Math.floor((elapsed % (1000 * 60 * 60)) / (1000 * 60));
    if (hours > 0) {
      return { text: `Expired ${String(hours)}h ${String(minutes)}m ago`, isExpired: true };
    }
    if (minutes > 0) {
      return { text: `Expired ${String(minutes)}m ago`, isExpired: true };
    }
    return { text: 'Expired just now', isExpired: true };
  }

  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));

  if (days > 0) {
    return { text: `${String(days)}d ${String(hours)}h remaining`, isExpired: false };
  }
  if (hours > 0) {
    return { text: `${String(hours)}h ${String(minutes)}m remaining`, isExpired: false };
  }
  if (minutes > 0) {
    return { text: `${String(minutes)}m remaining`, isExpired: false };
  }
  return { text: 'Less than a minute remaining', isExpired: false };
}

function SecretDetail({ data }: { data: ISecretData }) {
  const [remaining, setRemaining] = useState(
    data.expiresAt ? formatRemainingTime(data.expiresAt) : null,
  );

  useEffect(() => {
    const expiresAt = data.expiresAt;
    if (!expiresAt) return;
    setRemaining(formatRemainingTime(expiresAt));
    const interval = setInterval(() => {
      setRemaining(formatRemainingTime(expiresAt));
    }, 60_000);
    return () => clearInterval(interval);
  }, [data.expiresAt]);

  return (
    <div className="space-y-3">
      <CopyField label="Value" value={data.value} masked mono multiline />
      {data.description && <CopyField label="Description" value={data.description} multiline />}
      {data.expiresAt && remaining && (
        <div
          className={cn(
            'flex items-center gap-2 rounded-lg border p-3',
            remaining.isExpired
              ? 'border-red-500/30 bg-red-50 dark:bg-red-950/30'
              : 'border-[hsl(var(--border))] bg-[hsl(var(--card))]',
          )}
        >
          <Clock
            className={cn(
              'h-4 w-4',
              remaining.isExpired
                ? 'text-red-500 dark:text-red-400'
                : 'text-[hsl(var(--muted-foreground))]',
            )}
          />
          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
              Expires
            </p>
            <p className="text-sm text-[hsl(var(--foreground))]">{formatDate(data.expiresAt)}</p>
            <p
              className={cn(
                'text-xs mt-0.5',
                remaining.isExpired
                  ? 'text-red-600 dark:text-red-400 font-medium'
                  : 'text-[hsl(var(--muted-foreground))]',
              )}
            >
              {remaining.text}
            </p>
          </div>
        </div>
      )}
      {data.customFields.map((field, idx) => (
        <CopyField
          key={idx}
          label={field.name}
          value={field.value}
          masked={field.type === 'hidden'}
          mono={field.type === 'hidden'}
          multiline
        />
      ))}
    </div>
  );
}

function NoteDetail({ data }: { data: INoteData }) {
  return (
    <div className="space-y-3">
      {data.format === 'markdown' ? (
        <div className="prose prose-sm dark:prose-invert max-w-none rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4">
          <ReactMarkdown
            skipHtml={true}
            allowedElements={[
              'p',
              'a',
              'strong',
              'em',
              'code',
              'pre',
              'ul',
              'ol',
              'li',
              'h1',
              'h2',
              'h3',
              'h4',
              'h5',
              'h6',
              'blockquote',
              'br',
              'hr',
            ]}
            components={{
              a: ({ href, children }) => (
                <a
                  href={href && isSafeUrl(href) ? href : '#'}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {children}
                </a>
              ),
            }}
          >
            {data.content}
          </ReactMarkdown>
        </div>
      ) : (
        <div className="whitespace-pre-wrap rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4 text-sm text-[hsl(var(--foreground))]">
          {data.content}
        </div>
      )}
    </div>
  );
}

function CardDetail({ data }: { data: ICardData }) {
  const billing = data.billingAddress;
  return (
    <div className="space-y-3">
      <CopyField label="Cardholder Name" value={data.cardholderName} />
      <CopyField label="Card Number" value={data.number} masked mono />
      <div className="grid grid-cols-2 gap-3">
        <CopyField label="Expiry" value={`${data.expMonth}/${data.expYear}`} />
        <CopyField label="CVV" value={data.cvv} masked mono />
      </div>
      {data.brand && <CopyField label="Brand" value={data.brand} />}
      {data.notes && <CopyField label="Notes" value={data.notes} multiline />}
      {billing &&
        hasAnyValue([
          billing.street,
          billing.street2,
          billing.city,
          billing.state,
          billing.zip,
          billing.country,
        ]) && (
          <div className="space-y-2 rounded-lg border border-[hsl(var(--border))] p-3">
            <p className="text-xs font-medium text-[hsl(var(--muted-foreground))]">
              Billing Address
            </p>
            {billing.street && <CopyField label="Street" value={billing.street} />}
            {billing.street2 && <CopyField label="Street 2" value={billing.street2} />}
            {hasAnyValue([billing.city, billing.state]) && (
              <CopyField
                label="City / State"
                value={[billing.city, billing.state].filter(Boolean).join(', ')}
              />
            )}
            {billing.zip && <CopyField label="ZIP" value={billing.zip} />}
            {billing.country && <CopyField label="Country" value={billing.country} />}
          </div>
        )}
    </div>
  );
}

function IdentityDetail({ data }: { data: IIdentityData }) {
  const address = data.address;
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <CopyField label="First Name" value={data.firstName} />
        <CopyField label="Last Name" value={data.lastName} />
      </div>
      {data.email && <CopyField label="Email" value={data.email} />}
      {data.phone && <CopyField label="Phone" value={data.phone} />}
      {/* Every row is guarded and the whole block is omitted for an all-empty
          address, matching `CardDetail`. Street/City/State/ZIP/Country used to render
          UNCONDITIONALLY inside `{data.address && …}`, and `CopyField` shows an em
          dash for an empty value — so, since the form always writes a FULL address
          object, every identity created through the UI displayed an Address panel of
          up to five blank rows. The two newest rows were already guarded; the other
          five have now caught up. */}
      {address &&
        hasAnyValue([
          address.street,
          address.street2,
          address.city,
          address.state,
          address.zip,
          address.country,
          address.deliveryNotes,
        ]) && (
          <>
            {address.street && <CopyField label="Street" value={address.street} />}
            {address.street2 && <CopyField label="Street 2" value={address.street2} />}
            {hasAnyValue([address.city, address.state]) && (
              <div className="grid grid-cols-2 gap-3">
                {address.city && <CopyField label="City" value={address.city} />}
                {address.state && <CopyField label="State" value={address.state} />}
              </div>
            )}
            {hasAnyValue([address.zip, address.country]) && (
              <div className="grid grid-cols-2 gap-3">
                {address.zip && <CopyField label="ZIP" value={address.zip} />}
                {address.country && <CopyField label="Country" value={address.country} />}
              </div>
            )}
            {address.deliveryNotes && (
              <CopyField label="Delivery Notes" value={address.deliveryNotes} multiline />
            )}
          </>
        )}
      {/* Stored by `identityDataSchema` and written by the Bitwarden importer, but
          until now only `notes` was rendered: a retained company, SSN or passport
          number was invisible in the app, so it could not be checked, corrected or
          removed without deleting the whole identity.
          `ssn` and `passport` are SECRETS and use the same masked reveal the card
          number and CVV do — and `getItemSubtitle` must never put either on a
          vault-list row, which `vault-list-subtitle.test.tsx` asserts. */}
      {data.company && <CopyField label="Company" value={data.company} />}
      {data.ssn && <CopyField label="Social Security Number" value={data.ssn} masked mono />}
      {data.passport && <CopyField label="Passport Number" value={data.passport} masked mono />}
      {data.notes && <CopyField label="Notes" value={data.notes} multiline />}
      <CustomFieldRows fields={data.customFields} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Degraded view for items whose decrypted payload failed schema validation
// ---------------------------------------------------------------------------

/**
 * Why the Edit button is unavailable on an undecodable item.
 *
 * Used as the button's `title`, which is a BONUS channel: `title` is not reliably
 * announced by a screen reader and some engines decline to render a tooltip at all.
 * The reason is reachable to assistive technology through
 * {@link UNDECODABLE_NOTICE_ID}, which the button points at with
 * `aria-describedby` — and reachable to anyone reading the page, because that id
 * belongs to {@link UndecodableNotice}'s `role="alert"` body.
 */
const UNDECODABLE_EDIT_HINT =
  'Editing is unavailable because this item could not be decoded. Saving the form would overwrite its stored contents. You can still rename it.';

/**
 * The id of {@link UndecodableNotice}'s body, so the unavailable Edit control can
 * name it as its own description.
 *
 * Only ONE notice is ever in the document: it renders either as the degraded
 * content panel or as the local `ErrorBoundary`'s fallback, never both.
 */
const UNDECODABLE_NOTICE_ID = 'undecodable-item-notice';

/**
 * Rendered in place of the type-specific detail when an item's decrypted data
 * could not be schema-validated (vaultStore flags these with `_validationError`
 * or stores a non-object payload under `_raw`). In that state Zod's array
 * defaults were never applied, so fields like `uris`/`customFields` may be
 * absent and the type views would throw. This panel keeps the page usable —
 * the name, tags, and the action bar live outside it — so the user can still
 * move, favorite, delete or restore the bad item.
 *
 * The copy names exactly the operations that are actually safe, and Edit is not
 * among them. Every action it does promise encrypts nothing the item depends on:
 * move, favorite, delete and restore route through `updateItemMeta`, which encrypts
 * NOTHING at all, and RENAME routes through `vaultStore.renameItem`, which sends the
 * name trio plus its `searchHash` and leaves `encryptedData` out of the payload
 * entirely. The edit FORM is the one that cannot be offered: it re-encrypts
 * `JSON.stringify(item.data)` wholesale, and for one of these items `data` is only
 * the placeholder wrapper, so one Save would replace the real ciphertext with it,
 * permanently.
 *
 * "Rename" was removed from this copy when no path could deliver it safely. It is
 * back only because one now can.
 */
function UndecodableNotice() {
  return (
    <div
      role="alert"
      className="rounded-lg border border-yellow-300 bg-yellow-50 p-4 text-sm text-yellow-800 dark:border-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-300"
    >
      <p className="font-medium">This item could not be fully decoded.</p>
      <p id={UNDECODABLE_NOTICE_ID} className="mt-1">
        Its contents may be corrupted or were saved in an unsupported format. You can still rename,
        move, favorite, delete, or restore it using the actions above. Editing is disabled because
        saving the form would overwrite the stored contents with this placeholder — the original
        data would be unrecoverable.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main detail component
// ---------------------------------------------------------------------------

// `isUndecodableData` lives in `lib/vaultData` so this view and the import
// resolver share one definition (see that module for why they must agree).

interface VaultItemDetailProps {
  item: DecryptedVaultItem;
  onEdit: () => void;
  isTrashed?: boolean | undefined;
}

export function VaultItemDetail({ item, onEdit, isTrashed = false }: VaultItemDetailProps) {
  const navigate = useNavigate();
  const { toast } = useToast();
  const folders = useVaultStore((s) => s.folders);
  const deleteItem = useVaultStore((s) => s.deleteItem);
  const permanentDeleteItem = useVaultStore((s) => s.permanentDeleteItem);
  const restoreItem = useVaultStore((s) => s.restoreItem);
  const updateItemMeta = useVaultStore((s) => s.updateItemMeta);
  const renameItem = useVaultStore((s) => s.renameItem);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [moveFolderOpen, setMoveFolderOpen] = useState(false);
  const [favoriteLoading, setFavoriteLoading] = useState(false);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [restoreLoading, setRestoreLoading] = useState(false);
  const [showRename, setShowRename] = useState(false);
  const [renameValue, setRenameValue] = useState('');
  const [renameLoading, setRenameLoading] = useState(false);
  const deleteDialogRef = useRef<HTMLDivElement>(null);
  const closeDeleteDialog = useCallback(() => setShowDeleteConfirm(false), []);
  useInlineDialog(deleteDialogRef, showDeleteConfirm, closeDeleteDialog);
  const renameDialogRef = useRef<HTMLDivElement>(null);
  const closeRenameDialog = useCallback(() => setShowRename(false), []);
  useInlineDialog(renameDialogRef, showRename, closeRenameDialog);

  const Icon = ICON_MAP[item.itemType];
  const data = item.data;
  const currentFolder = folders.find((f) => f.id === item.folderId);
  // One predicate drives BOTH the degraded content panel below and the Edit
  // affordance in the action bar. They were previously independent: the notice
  // rendered while Edit stayed live, so the form opened on a placeholder and one
  // Save destroyed the item's real ciphertext (a `{_raw}` payload defaults every
  // control to `''` and writes an EMPTY item; a `_validationError` one re-stores
  // the exact value that fails validation, wedging the item in a loop).
  const undecodable = isUndecodableData(data);

  const handleDelete = useCallback(async () => {
    setDeleteLoading(true);
    try {
      if (isTrashed) {
        await permanentDeleteItem(item.id);
        toast({ title: 'Item permanently deleted', type: 'success' });
      } else {
        await deleteItem(item.id);
        toast({ title: 'Item moved to trash', type: 'success' });
      }
      void navigate('/vault');
    } catch {
      toast({ title: 'Failed to delete item', type: 'error' });
    } finally {
      setDeleteLoading(false);
      setShowDeleteConfirm(false);
    }
  }, [isTrashed, permanentDeleteItem, deleteItem, item.id, navigate, toast]);

  const handleRestore = useCallback(async () => {
    setRestoreLoading(true);
    try {
      await restoreItem(item.id);
      toast({ title: 'Item restored', type: 'success' });
      void navigate('/vault');
    } catch {
      toast({ title: 'Failed to restore item', type: 'error' });
    } finally {
      setRestoreLoading(false);
    }
  }, [restoreItem, item.id, navigate, toast]);

  // Favorite and move are METADATA-ONLY changes, so they go through
  // updateItemMeta, which sends just the changed field and re-encrypts nothing.
  // updateItem() would encrypt JSON.stringify(item.data) over the item's real
  // ciphertext — and for an item that failed to decode, `item.data` is only a
  // placeholder wrapper (see isUndecodableData), so that would destroy it.
  const handleToggleFavorite = useCallback(async () => {
    setFavoriteLoading(true);
    try {
      await updateItemMeta(item.id, { favorite: !item.favorite });
      toast({
        title: item.favorite ? 'Removed from favorites' : 'Added to favorites',
        type: 'success',
      });
    } catch {
      toast({ title: 'Failed to update favorite', type: 'error' });
    } finally {
      setFavoriteLoading(false);
    }
  }, [updateItemMeta, item.id, item.favorite, toast]);

  // A NAME-ONLY write: the one thing an undecodable item can safely be changed to.
  // `renameItem` omits `encryptedData`/`dataIv`/`dataTag` from the request, so unlike
  // the edit form it cannot overwrite the placeholder onto the item's real ciphertext.
  const handleRename = useCallback(async () => {
    const nextName = renameValue.trim();
    if (!nextName) return;
    setRenameLoading(true);
    try {
      await renameItem(item.id, nextName);
      toast({ title: 'Item renamed', type: 'success' });
      setShowRename(false);
    } catch (error) {
      toast({
        title: 'Failed to rename item',
        description: getApiErrorMessage(error, 'Please try again.'),
        type: 'error',
      });
    } finally {
      setRenameLoading(false);
    }
  }, [renameItem, item.id, renameValue, toast]);

  const handleMoveToFolder = useCallback(
    async (folderId: string | null) => {
      try {
        await updateItemMeta(item.id, { folderId });
        toast({ title: 'Item moved', type: 'success' });
        setMoveFolderOpen(false);
      } catch {
        toast({ title: 'Failed to move item', type: 'error' });
      }
    },
    [updateItemMeta, item.id, toast],
  );

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={() => void navigate('/vault')}
          className="rounded-md p-2 text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--foreground))] transition-colors"
          aria-label="Back to vault"
        >
          <ArrowLeft className="h-5 w-5" />
        </button>
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-[hsl(var(--primary)/0.1)]">
          <Icon className="h-5 w-5 text-[hsl(var(--primary))]" />
        </div>
        <div className="min-w-0 flex-1">
          <h1 className="truncate text-xl font-semibold text-[hsl(var(--foreground))]">
            {item.name || 'Unnamed item'}
          </h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))]">
            Last modified {formatDate(item.updatedAt)}
          </p>
        </div>
      </div>

      {/* Action bar */}
      <div className="flex flex-wrap items-center gap-2">
        {isTrashed ? (
          <>
            {/* Trashed items: only Restore and Permanent Delete */}
            <button
              type="button"
              onClick={() => void handleRestore()}
              disabled={restoreLoading}
              className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity disabled:opacity-50"
            >
              {restoreLoading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <RotateCcw className="h-4 w-4" />
              )}
              Restore
            </button>
            <button
              type="button"
              onClick={() => setShowDeleteConfirm(true)}
              className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--destructive)/0.3)] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)] transition-colors"
            >
              <Trash2 className="h-4 w-4" />
              Delete Forever
            </button>
          </>
        ) : (
          <>
            {/* Normal items: Edit, Favorite, Move, Delete. Edit is the ONE action
                here that re-encrypts `data`, so it is the one action an
                undecodable item must not offer.
                `aria-disabled` rather than `disabled`, following `BackupCodeList`: a
                `disabled` control leaves the tab order, so a keyboard or screen-reader
                user could not reach it to be told WHY it is unavailable, and `title`
                is neither reliably rendered on a disabled element nor reliably
                announced. The control stays focusable and names the notice as its
                description; the click handler is what makes it inert. */}
            <button
              type="button"
              onClick={() => {
                if (undecodable) return;
                onEdit();
              }}
              aria-disabled={undecodable ? true : undefined}
              aria-describedby={undecodable ? UNDECODABLE_NOTICE_ID : undefined}
              title={undecodable ? UNDECODABLE_EDIT_HINT : undefined}
              className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity aria-disabled:cursor-not-allowed aria-disabled:opacity-50 aria-disabled:hover:opacity-50"
            >
              <Pencil className="h-4 w-4" />
              Edit
            </button>
            {/* Offered ONLY for an undecodable item: every other item renames through
                the edit form. `renameItem` sends the name trio and its `searchHash`
                and omits `encryptedData` entirely, so the item's real ciphertext is
                left byte-identical. */}
            {undecodable && (
              <button
                type="button"
                onClick={() => {
                  setRenameValue(item.name);
                  setShowRename(true);
                }}
                className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
              >
                <Pencil className="h-4 w-4" />
                Rename
              </button>
            )}
            <button
              type="button"
              onClick={() => void handleToggleFavorite()}
              disabled={favoriteLoading}
              className={cn(
                'inline-flex items-center gap-2 rounded-md border px-3 py-2 text-sm font-medium transition-colors disabled:opacity-50',
                item.favorite
                  ? 'border-yellow-400 bg-yellow-50 text-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-300'
                  : 'border-[hsl(var(--input))] text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]',
              )}
            >
              {favoriteLoading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Star
                  className={cn('h-4 w-4', item.favorite && 'fill-yellow-400 text-yellow-400')}
                />
              )}
              {item.favorite ? 'Favorited' : 'Favorite'}
            </button>
            <div className="relative">
              <button
                type="button"
                onClick={() => setMoveFolderOpen((p) => !p)}
                className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
              >
                <FolderOpen className="h-4 w-4" />
                {currentFolder?.name ?? 'No folder'}
              </button>
              {moveFolderOpen && (
                <div
                  className="absolute left-0 top-full z-20 mt-1 w-48 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--popover))] p-1 shadow-lg"
                  role="menu"
                  aria-label="Move to folder"
                >
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => void handleMoveToFolder(null)}
                    className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-sm text-[hsl(var(--popover-foreground))] hover:bg-[hsl(var(--accent))]"
                  >
                    No folder
                  </button>
                  {folders.map((folder) => (
                    <button
                      key={folder.id}
                      type="button"
                      role="menuitem"
                      onClick={() => void handleMoveToFolder(folder.id)}
                      className={cn(
                        'flex w-full items-center gap-2 rounded px-2 py-1.5 text-sm text-[hsl(var(--popover-foreground))] hover:bg-[hsl(var(--accent))]',
                        folder.id === item.folderId && 'bg-[hsl(var(--accent))]',
                      )}
                    >
                      {folder.name}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <button
              type="button"
              onClick={() => setShowDeleteConfirm(true)}
              className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--destructive)/0.3)] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)] transition-colors"
            >
              <Trash2 className="h-4 w-4" />
              Delete
            </button>
          </>
        )}
      </div>

      {/* Tags */}
      {item.tags.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {item.tags.map((tag) => (
            <span
              key={tag}
              className="rounded-full bg-[hsl(var(--secondary))] px-2.5 py-0.5 text-xs font-medium text-[hsl(var(--secondary-foreground))]"
            >
              {tag}
            </span>
          ))}
        </div>
      )}

      {/* Type-specific content. A malformed (schema-invalid) payload is shown
          as a degraded notice instead of the type view, which would otherwise
          throw on missing fields. The local ErrorBoundary — keyed on the item
          so it resets across navigation — is a final safety net for any
          unforeseen render error, degrading just this section rather than
          crashing the whole app and stranding the action bar above. */}
      <ErrorBoundary key={item.id} fallback={<UndecodableNotice />}>
        {undecodable ? (
          <UndecodableNotice />
        ) : (
          <>
            {item.itemType === 'login' && (
              <LoginDetail
                data={data as unknown as ILoginData}
                itemId={item.id}
                itemName={item.name}
                canEdit={!isTrashed}
              />
            )}
            {item.itemType === 'secret' && <SecretDetail data={data as unknown as ISecretData} />}
            {item.itemType === 'note' && <NoteDetail data={data as unknown as INoteData} />}
            {item.itemType === 'card' && <CardDetail data={data as unknown as ICardData} />}
            {item.itemType === 'identity' && (
              <IdentityDetail data={data as unknown as IIdentityData} />
            )}
          </>
        )}
      </ErrorBoundary>

      {/* Password history for login items */}
      {item.itemType === 'login' && item._raw.passwordHistory && (
        <PasswordHistorySection entries={item._raw.passwordHistory} />
      )}

      {/* Metadata */}
      <div className="border-t border-[hsl(var(--border))] pt-4">
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-xs text-[hsl(var(--muted-foreground))]">Created</p>
            <p className="text-[hsl(var(--foreground))]">{formatDate(item.createdAt)}</p>
          </div>
          <div>
            <p className="text-xs text-[hsl(var(--muted-foreground))]">Modified</p>
            <p className="text-[hsl(var(--foreground))]">{formatDate(item.updatedAt)}</p>
          </div>
        </div>
      </div>

      {/* Rename dialog (undecodable items only) */}
      {showRename && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
          onClick={(e) => {
            if (e.target === e.currentTarget) closeRenameDialog();
          }}
        >
          <div
            ref={renameDialogRef}
            className="w-full max-w-sm rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-6 shadow-lg"
            role="dialog"
            aria-modal="true"
            aria-label="Rename item"
          >
            <h3 className="text-lg font-semibold text-[hsl(var(--card-foreground))]">
              Rename Item
            </h3>
            <p className="mt-2 text-sm text-[hsl(var(--muted-foreground))]">
              Only the name is changed. The item&rsquo;s stored contents are left exactly as they
              are.
            </p>
            <label
              htmlFor="undecodable-rename-input"
              className="mt-4 mb-1.5 block text-sm font-medium text-[hsl(var(--foreground))]"
            >
              Name
            </label>
            <input
              id="undecodable-rename-input"
              value={renameValue}
              onChange={(e) => setRenameValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  void handleRename();
                }
              }}
              placeholder="Item name"
              autoComplete="off"
              className="w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))]"
            />
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={closeRenameDialog}
                className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void handleRename()}
                disabled={renameLoading || !renameValue.trim()}
                className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity disabled:opacity-50"
              >
                {renameLoading && <Loader2 className="h-4 w-4 animate-spin" />}
                Save
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirmation dialog */}
      {showDeleteConfirm && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
          onClick={(e) => {
            if (e.target === e.currentTarget) closeDeleteDialog();
          }}
        >
          <div
            ref={deleteDialogRef}
            className="w-full max-w-sm rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-6 shadow-lg"
            role="alertdialog"
            aria-modal="true"
            aria-label="Confirm delete"
          >
            <h3 className="text-lg font-semibold text-[hsl(var(--card-foreground))]">
              {isTrashed ? 'Permanently Delete Item' : 'Delete Item'}
            </h3>
            <p className="mt-2 text-sm text-[hsl(var(--muted-foreground))]">
              {isTrashed ? (
                <>
                  Are you sure you want to permanently delete &ldquo;{item.name}&rdquo;? This action
                  cannot be undone.
                </>
              ) : (
                <>
                  Are you sure you want to move &ldquo;{item.name}&rdquo; to the trash? You can
                  restore it within 30 days.
                </>
              )}
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowDeleteConfirm(false)}
                className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void handleDelete()}
                disabled={deleteLoading}
                className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--destructive))] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive-foreground))] hover:opacity-90 transition-opacity disabled:opacity-50"
              >
                {deleteLoading && <Loader2 className="h-4 w-4 animate-spin" />}
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
