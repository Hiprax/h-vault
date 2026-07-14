import { useCallback, useMemo, useState } from 'react';
import { useForm, useFieldArray, type SubmitHandler } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Key, FileText, CreditCard, User, Lock, Trash2, Star, Eye, EyeOff, X } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { cn, getApiErrorMessage, isSafeUrl } from '../../lib/utils';
import {
  useVaultStore,
  EncryptedFieldTooLargeError,
  type DecryptedVaultItem,
} from '../../stores/vaultStore';
import { useToast } from '../ui/Toast';
import { PasswordGenerator } from './PasswordGenerator';
import { MAX_TAGS_PER_ITEM, normalizeUri } from '@hvault/shared';
import type { ItemType } from '@hvault/shared';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

const TYPE_TABS: { type: ItemType; label: string; icon: typeof Key }[] = [
  { type: 'login', label: 'Login', icon: Key },
  { type: 'secret', label: 'Secret', icon: Lock },
  { type: 'note', label: 'Note', icon: FileText },
  { type: 'card', label: 'Card', icon: CreditCard },
  { type: 'identity', label: 'Identity', icon: User },
];

// ---------------------------------------------------------------------------
// Zod schemas (one per item type)
// ---------------------------------------------------------------------------

const uriEntrySchema = z
  .object({
    uri: z.string().max(2048, 'URI too long').optional().default(''),
    match: z.enum(['domain', 'exact', 'startsWith', 'regex']).default('domain'),
  })
  .transform((entry) => ({
    ...entry,
    uri: entry.match === 'regex' ? entry.uri : normalizeUri(entry.uri),
  }))
  .refine(
    (entry) => {
      if (entry.match === 'regex') return true;
      return !entry.uri || /^(https?:|mailto:)/i.test(entry.uri);
    },
    { message: 'URI must start with http://, https://, or mailto:', path: ['uri'] },
  );

const customFieldSchema = z.object({
  name: z.string().optional().default(''),
  value: z.string().optional().default(''),
  type: z.enum(['text', 'hidden', 'boolean']).default('text'),
});

const loginSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  username: z.string().optional().default(''),
  password: z.string().optional().default(''),
  uris: z.array(uriEntrySchema).optional().default([]),
  totp: z.string().optional().default(''),
  notes: z.string().optional().default(''),
  customFields: z.array(customFieldSchema).optional().default([]),
});

const secretSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  value: z.string().min(1, 'Value is required'),
  description: z.string().optional().default(''),
  expiryDate: z.string().optional().default(''),
  expiryTime: z.string().optional().default(''),
  customFields: z
    .array(
      z.object({
        name: z.string().optional().default(''),
        value: z.string().optional().default(''),
        type: z.enum(['text', 'hidden']).default('text'),
      }),
    )
    .optional()
    .default([]),
});

const noteSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  content: z.string().min(1, 'Content is required'),
  format: z.enum(['markdown', 'plaintext']).default('markdown'),
});

/** Convert empty string to undefined while preserving non-empty string values. */
function emptyToUndefined(value: unknown): string | undefined {
  if (typeof value !== 'string' || value === '') return undefined;
  return value;
}

/** Luhn checksum validation for card numbers. Returns true if the number passes. */
function isValidLuhn(value: string): boolean {
  const digits = value.replace(/[\s-]/g, '');
  if (!/^\d+$/.test(digits) || digits.length < 8) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = Number(digits[i]);
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}

/** Format a card number string with spaces every 4 digits */
function formatCardNumber(value: string): string {
  const digits = value.replace(/\D/g, '').slice(0, 19);
  const groups: string[] = [];
  for (let i = 0; i < digits.length; i += 4) {
    groups.push(digits.slice(i, i + 4));
  }
  return groups.join(' ');
}

const cardSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  cardholderName: z.string().min(1, 'Cardholder name is required'),
  number: z
    .string()
    .min(1, 'Card number is required')
    .refine(
      (val) => /^\d[\d ]*\d$/.test(val) && val.replace(/\s/g, '').length >= 13,
      'Must be at least 13 digits',
    )
    .refine((val) => val.replace(/\s/g, '').length <= 19, 'Must be at most 19 digits')
    .refine((val) => /^\d+$/.test(val.replace(/\s/g, '')), 'Must contain only digits')
    .refine((val) => isValidLuhn(val), 'Card number fails Luhn check — verify the number')
    // Strip spaces before the value reaches buildDataPayload / encryption
    .transform((val) => val.replace(/\s/g, '')),
  expMonth: z
    .string()
    .regex(/^$|^(0[1-9]|1[0-2])$/, 'Invalid month (01-12)')
    .optional()
    .default(''),
  expYear: z
    .string()
    .regex(/^$|^\d{4}$/, 'Invalid year')
    .optional()
    .default(''),
  cvv: z
    .string()
    .regex(/^$|^\d{3,4}$/, 'Must be 3-4 digits')
    .optional()
    .default(''),
  brand: z.string().optional().default(''),
  billingStreet: z.string().optional().default(''),
  billingCity: z.string().optional().default(''),
  billingState: z.string().optional().default(''),
  billingZip: z.string().optional().default(''),
  billingCountry: z.string().optional().default(''),
});

const identitySchema = z.object({
  name: z.string().min(1, 'Name is required'),
  firstName: z.string().min(1, 'Required'),
  lastName: z.string().min(1, 'Required'),
  email: z
    .string()
    .max(254, 'Email too long')
    .regex(/^$|^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/, 'Invalid email address')
    .optional()
    .default(''),
  phone: z
    .string()
    .min(0)
    .max(30, 'Phone number too long')
    .regex(/^$|^[+\d\s().-]{3,30}$/, 'Invalid phone number (3-30 characters)')
    .optional()
    .default(''),
  street: z.string().optional().default(''),
  city: z.string().optional().default(''),
  state: z.string().optional().default(''),
  zip: z.string().optional().default(''),
  country: z.string().optional().default(''),
});

/** Return the Zod schema that corresponds to a given item type. */
function getSchemaForType(itemType: ItemType) {
  switch (itemType) {
    case 'login':
      return loginSchema;
    case 'secret':
      return secretSchema;
    case 'note':
      return noteSchema;
    case 'card':
      return cardSchema;
    case 'identity':
      return identitySchema;
    default:
      return z.object({ name: z.string().min(1, 'Name is required') });
  }
}

// ---------------------------------------------------------------------------
// Default values helper
// ---------------------------------------------------------------------------

function getDefaultValues(itemType: ItemType, item?: DecryptedVaultItem): Record<string, unknown> {
  const data: Record<string, unknown> = item?.data ?? {};

  switch (itemType) {
    case 'login':
      return {
        name: item?.name ?? '',
        username: data.username ?? '',
        password: data.password ?? '',
        uris: data.uris ?? [{ uri: '', match: 'domain' as const }],
        totp: data.totp ?? '',
        notes: data.notes ?? '',
        customFields: data.customFields ?? [],
      };
    case 'secret': {
      const expiresAt = (data.expiresAt as string | undefined) ?? '';
      let expiryDate = '';
      let expiryTime = '';
      if (expiresAt) {
        // Handle both ISO format (2025-12-31T23:59:00.000Z) and datetime-local (2025-12-31T23:59)
        // eslint-disable-next-line security/detect-unsafe-regex -- anchored date regex, no ReDoS risk
        const dtMatch = /^(\d{4}-\d{2}-\d{2})(?:T(\d{2}:\d{2}))?/.exec(expiresAt);
        if (dtMatch) {
          expiryDate = dtMatch[1] ?? '';
          expiryTime = dtMatch[2] ?? '';
        }
      }
      return {
        name: item?.name ?? '',
        value: data.value ?? '',
        description: data.description ?? '',
        expiryDate,
        expiryTime,
        customFields: data.customFields ?? [],
      };
    }
    case 'note':
      return {
        name: item?.name ?? '',
        content: data.content ?? '',
        format: data.format ?? 'markdown',
      };
    case 'card': {
      const billing = (data.billingAddress as Record<string, string> | undefined) ?? {};
      return {
        name: item?.name ?? '',
        cardholderName: data.cardholderName ?? '',
        number: formatCardNumber((data.number as string | undefined) ?? ''),
        expMonth: data.expMonth ?? '',
        expYear: data.expYear ?? '',
        cvv: data.cvv ?? '',
        brand: data.brand ?? '',
        billingStreet: billing.street ?? '',
        billingCity: billing.city ?? '',
        billingState: billing.state ?? '',
        billingZip: billing.zip ?? '',
        billingCountry: billing.country ?? '',
      };
    }
    case 'identity': {
      const address = (data.address as Record<string, string> | undefined) ?? {};
      return {
        name: item?.name ?? '',
        firstName: data.firstName ?? '',
        lastName: data.lastName ?? '',
        email: data.email ?? '',
        phone: data.phone ?? '',
        street: address.street ?? '',
        city: address.city ?? '',
        state: address.state ?? '',
        zip: address.zip ?? '',
        country: address.country ?? '',
      };
    }
    default:
      return { name: item?.name ?? '' };
  }
}

// ---------------------------------------------------------------------------
// Build data payload helper
// ---------------------------------------------------------------------------

/**
 * Drop custom-field entries whose name is blank after trimming.
 *
 * The shared `customFieldSchema` requires `name` to be a non-empty string
 * (`min(1)`). A blank-named entry (e.g. an "+ Add Field" row the user never
 * filled in) would pass the lenient form schema, get encrypted, and then fail
 * the shared schema on read-back — degrading the whole item to the "could not
 * be fully decoded" notice even though its ciphertext is intact. Stripping the
 * entry before encryption keeps the item readable; a field with a real name
 * but an empty value is intentionally retained.
 */
function stripEmptyCustomFields(fields: unknown): unknown {
  if (!Array.isArray(fields)) return fields;
  return (fields as Record<string, unknown>[]).filter((field) => {
    const name = field.name;
    return typeof name === 'string' && name.trim().length > 0;
  });
}

function buildDataPayload(
  itemType: ItemType,
  values: Record<string, unknown>,
): Record<string, unknown> {
  switch (itemType) {
    case 'login':
      return {
        name: values.name,
        username: values.username,
        password: values.password,
        uris: values.uris,
        totp: emptyToUndefined(values.totp),
        notes: emptyToUndefined(values.notes),
        customFields: stripEmptyCustomFields(values.customFields),
      };
    case 'secret': {
      const date = (values.expiryDate as string) || '';
      const time = (values.expiryTime as string) || '';
      let expiresAt: string | undefined;
      if (date) {
        expiresAt = time ? `${date}T${time}` : `${date}T00:00`;
      }
      return {
        name: values.name,
        value: values.value,
        description: emptyToUndefined(values.description),
        expiresAt,
        customFields: stripEmptyCustomFields(values.customFields),
      };
    }
    case 'note':
      return {
        name: values.name,
        content: values.content,
        format: values.format,
      };
    case 'card': {
      const billingStreet = (values.billingStreet as string) || '';
      const billingCity = (values.billingCity as string) || '';
      const billingState = (values.billingState as string) || '';
      const billingZip = (values.billingZip as string) || '';
      const billingCountry = (values.billingCountry as string) || '';
      const hasBilling =
        billingStreet || billingCity || billingState || billingZip || billingCountry;
      return {
        name: values.name,
        cardholderName: values.cardholderName,
        number: (values.number as string).replace(/\s/g, ''),
        expMonth: values.expMonth,
        expYear: values.expYear,
        cvv: values.cvv,
        brand: emptyToUndefined(values.brand),
        ...(hasBilling
          ? {
              billingAddress: {
                street: billingStreet,
                city: billingCity,
                state: billingState,
                zip: billingZip,
                country: billingCountry,
              },
            }
          : {}),
      };
    }
    case 'identity':
      return {
        name: values.name,
        firstName: values.firstName,
        lastName: values.lastName,
        email: emptyToUndefined(values.email),
        phone: emptyToUndefined(values.phone),
        address: {
          street: values.street,
          city: values.city,
          state: values.state,
          zip: values.zip,
          country: values.country,
        },
      };
    default:
      return values;
  }
}

// ---------------------------------------------------------------------------
// Reusable form field wrapper
// ---------------------------------------------------------------------------

function FormField({
  label,
  name,
  children,
  error,
}: {
  label: string;
  name?: string | undefined;
  children: React.ReactNode;
  error?: string | undefined;
}) {
  const fieldId = name ? `field-${name}` : undefined;
  const errorId = name && error ? `field-${name}-error` : undefined;
  return (
    <div>
      <label
        htmlFor={fieldId}
        className="mb-1.5 block text-sm font-medium text-[hsl(var(--foreground))]"
      >
        {label}
      </label>
      {children}
      {error && (
        <p id={errorId} role="alert" className="mt-1 text-xs text-[hsl(var(--destructive))]">
          {error}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main form component
// ---------------------------------------------------------------------------

interface VaultItemFormProps {
  /** Existing item for editing; undefined means creating new */
  item?: DecryptedVaultItem;
  /** Default item type for new items (e.g. pre-select based on active type filter) */
  defaultType?: ItemType | undefined;
  /** Default folder ID for new items (e.g. pre-select based on active folder) */
  defaultFolderId?: string | undefined;
  /** Called on successful save */
  onSaved: () => void;
  /** Called on cancel */
  onCancel: () => void;
}

export function VaultItemForm({
  item,
  defaultType,
  defaultFolderId,
  onSaved,
  onCancel,
}: VaultItemFormProps) {
  const { toast } = useToast();
  const createItem = useVaultStore((s) => s.createItem);
  const updateItem = useVaultStore((s) => s.updateItem);
  const folders = useVaultStore((s) => s.folders);

  const [itemType, setItemType] = useState<ItemType>(item?.itemType ?? defaultType ?? 'login');
  const [folderId, setFolderId] = useState(item?.folderId ?? defaultFolderId ?? '');
  const [tags, setTags] = useState(item?.tags ?? []);
  const [tagInput, setTagInput] = useState('');
  const [favorite, setFavorite] = useState(item?.favorite ?? false);
  const [saving, setSaving] = useState(false);
  const [showPasswordGen, setShowPasswordGen] = useState(false);
  const [showPasswordField, setShowPasswordField] = useState(false);
  const [showPreview, setShowPreview] = useState(false);
  const [showBillingAddress, setShowBillingAddress] = useState(() => {
    if (item?.itemType !== 'card') return false;
    const billing = item.data.billingAddress as Record<string, string> | undefined;
    return !!(
      billing?.street ??
      billing?.city ??
      billing?.state ??
      billing?.zip ??
      billing?.country
    );
  });

  const isEditing = item != null;

  const defaultValues = useMemo(
    () => getDefaultValues(itemType, item),
    // Only compute defaults once on mount (empty deps is intentional)
    [],
  );

  const schema = useMemo(() => getSchemaForType(itemType), [itemType]);

  const {
    register,
    handleSubmit,
    control,
    setValue,
    watch,
    reset,
    formState: { errors },
  } = useForm({
    defaultValues,
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-explicit-any -- dynamic form schema requires broad resolver type
    resolver: zodResolver(schema) as any,
  });

  // Field arrays for login URIs and custom fields
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-explicit-any -- dynamic form shape requires broad control type
  const typedControl = control as any;
  /* eslint-disable @typescript-eslint/no-unsafe-assignment -- dynamic form control type from zodResolver */
  const {
    fields: uriFields,
    append: appendUri,
    remove: removeUri,
  } = useFieldArray({ control: typedControl, name: 'uris' });

  const {
    fields: customFields,
    append: appendCustomField,
    remove: removeCustomField,
  } = useFieldArray({ control: typedControl, name: 'customFields' });
  /* eslint-enable @typescript-eslint/no-unsafe-assignment */

  const noteContent = watch('content') as string | undefined;
  const watchedCardNumber = watch('number') as string | undefined;
  const cardLuhnWarning = useMemo(() => {
    if (itemType !== 'card' || !watchedCardNumber) return null;
    const digits = watchedCardNumber.replace(/\s/g, '');
    if (digits.length < 13 || !/^\d+$/.test(digits)) return null;
    return isValidLuhn(digits) ? null : 'Card number does not pass Luhn check';
  }, [itemType, watchedCardNumber]);

  // Type tab change (new items only)
  const handleTypeChange = useCallback(
    (type: ItemType) => {
      if (isEditing) return;
      setItemType(type);
      reset(getDefaultValues(type));
    },
    [isEditing, reset],
  );

  // Tag management
  const handleAddTag = useCallback(() => {
    if (tags.length >= MAX_TAGS_PER_ITEM) return;
    const tag = tagInput.trim();
    if (tag && !tags.includes(tag)) {
      setTags((prev) => [...prev, tag]);
    }
    setTagInput('');
  }, [tagInput, tags]);

  const handleRemoveTag = useCallback((tag: string) => {
    setTags((prev) => prev.filter((t) => t !== tag));
  }, []);

  // Submit handler
  const onSubmit: SubmitHandler<Record<string, unknown>> = useCallback(
    async (values) => {
      setSaving(true);
      try {
        const name = values.name as string;
        const data = buildDataPayload(itemType, values);

        if (item != null) {
          await updateItem(item.id, name, data, {
            folderId: folderId || null,
            tags,
            favorite,
          });
          toast({ title: 'Item updated', type: 'success' });
        } else {
          await createItem(itemType, name, data, {
            ...(folderId ? { folderId } : {}),
            tags,
            favorite,
          });
          toast({ title: 'Item created', type: 'success' });
        }
        onSaved();
      } catch (err) {
        // Surface the actual error message (especially for the pre-flight
        // oversize check) instead of a generic "failed" toast.
        const isSizeError = err instanceof EncryptedFieldTooLargeError;
        toast({
          title: isSizeError ? 'Item too large to save' : 'Failed to save item',
          description: getApiErrorMessage(err, 'An unexpected error occurred. Please try again.'),
          type: 'error',
        });
      } finally {
        setSaving(false);
      }
    },
    [itemType, isEditing, item, folderId, tags, favorite, createItem, updateItem, onSaved, toast],
  );

  const inputClass =
    'w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]';

  return (
    <form onSubmit={(e) => void handleSubmit(onSubmit)(e)} className="space-y-6">
      <h2 className="text-lg font-semibold text-[hsl(var(--foreground))]">
        {isEditing ? 'Edit Item' : 'New Item'}
      </h2>

      {/* Type tabs (only for new items) */}
      {!isEditing && (
        <div
          className="flex gap-1 overflow-x-auto rounded-lg border border-[hsl(var(--border))] p-1"
          role="tablist"
          aria-label="Item type"
        >
          {TYPE_TABS.map(({ type, label, icon: Icon }) => (
            <button
              key={type}
              type="button"
              role="tab"
              aria-selected={itemType === type}
              onClick={() => handleTypeChange(type)}
              className={cn(
                'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium whitespace-nowrap transition-colors',
                itemType === type
                  ? 'bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))]'
                  : 'text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]',
              )}
            >
              <Icon className="h-4 w-4" />
              {label}
            </button>
          ))}
        </div>
      )}

      {/* Name field (common to all types) */}
      <FormField label="Name" name="name" error={errors.name?.message}>
        <input
          id="field-name"
          {...register('name')}
          placeholder="Item name"
          className={inputClass}
          autoFocus
          autoComplete="off"
          aria-describedby={errors.name ? 'field-name-error' : undefined}
          aria-invalid={errors.name ? true : undefined}
        />
      </FormField>

      {/* --- Login fields --- */}
      {itemType === 'login' && (
        <div className="space-y-4">
          <FormField label="Username" name="username">
            <input
              id="field-username"
              {...register('username')}
              placeholder="Username or email"
              className={inputClass}
              autoComplete="off"
            />
          </FormField>

          <FormField label="Password" name="password">
            <div className="flex gap-2">
              <div className="relative flex-1">
                <input
                  id="field-password"
                  {...register('password')}
                  type={showPasswordField ? 'text' : 'password'}
                  placeholder="Password"
                  className={cn(inputClass, 'pr-10')}
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPasswordField((p) => !p)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]"
                  aria-label={showPasswordField ? 'Hide password' : 'Show password'}
                >
                  {showPasswordField ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              <button
                type="button"
                onClick={() => setShowPasswordGen((p) => !p)}
                className="shrink-0 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
              >
                Generate
              </button>
            </div>
            {showPasswordGen && (
              <div className="mt-2 rounded-lg border border-[hsl(var(--border))] p-4">
                <PasswordGenerator
                  onSelect={(pw) => {
                    setValue('password', pw);
                    setShowPasswordGen(false);
                  }}
                />
              </div>
            )}
          </FormField>

          {/* URIs */}
          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <span className="text-sm font-medium text-[hsl(var(--foreground))]">URIs</span>
              <button
                type="button"
                onClick={() => appendUri({ uri: '', match: 'domain' })}
                className="text-xs text-[hsl(var(--primary))] hover:underline"
              >
                + Add URI
              </button>
            </div>
            <div className="space-y-2">
              {uriFields.map((field, idx) => {
                // react-hook-form's error object is sparse, so the indexed entry
                // may be absent. Type the intermediate as explicitly nullable so
                // each optional-chain link guards a genuinely nullable value.
                const uriFieldError: { uri?: { message?: string } } | undefined = (
                  errors.uris as Record<string, { uri?: { message?: string } }> | undefined
                )?.[idx];
                const uriError = uriFieldError?.uri?.message;
                return (
                  <div key={field.id}>
                    <div className="flex gap-2">
                      <input
                        {...register(`uris.${idx}.uri` as const)}
                        placeholder="example.com"
                        className={cn(inputClass, 'flex-1')}
                        aria-invalid={uriError ? true : undefined}
                      />
                      <select
                        {...register(`uris.${idx}.match` as const)}
                        className={cn(inputClass, 'w-28')}
                      >
                        <option value="domain">Domain</option>
                        <option value="exact">Exact</option>
                        <option value="startsWith">Starts with</option>
                        <option value="regex">Regex</option>
                      </select>
                      <button
                        type="button"
                        onClick={() => removeUri(idx)}
                        className="shrink-0 rounded p-2 text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)]"
                        aria-label="Remove URI"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                    {uriError && (
                      <p role="alert" className="mt-1 text-xs text-[hsl(var(--destructive))]">
                        {uriError}
                      </p>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          <FormField label="TOTP Secret" name="totp">
            <input
              id="field-totp"
              {...register('totp')}
              placeholder="TOTP secret key (optional)"
              className={inputClass}
              autoComplete="off"
            />
          </FormField>

          <FormField label="Notes" name="notes">
            <textarea
              id="field-notes"
              {...register('notes')}
              placeholder="Additional notes"
              rows={3}
              className={cn(inputClass, 'resize-y')}
            />
          </FormField>

          {/* Custom fields */}
          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <span className="text-sm font-medium text-[hsl(var(--foreground))]">
                Custom Fields
              </span>
              <button
                type="button"
                onClick={() => appendCustomField({ name: '', value: '', type: 'text' })}
                className="text-xs text-[hsl(var(--primary))] hover:underline"
              >
                + Add Field
              </button>
            </div>
            <div className="space-y-2">
              {customFields.map((field, idx) => {
                // eslint-disable-next-line @typescript-eslint/no-confusing-void-expression, @typescript-eslint/no-unnecessary-condition -- react-hook-form watch() returns void for dynamic paths in Record<string, unknown> forms
                const fieldType = (watch(`customFields.${idx}.type`) ?? 'text') as string;
                // eslint-disable-next-line @typescript-eslint/no-confusing-void-expression, @typescript-eslint/no-unnecessary-condition -- same as above
                const fieldValue = (watch(`customFields.${idx}.value`) ?? '') as string;
                const isBooleanTrue = fieldType === 'boolean' && fieldValue === 'true';
                return (
                  <div key={field.id} className="flex gap-2">
                    <input
                      {...register(`customFields.${idx}.name` as const)}
                      placeholder="Field name"
                      className={cn(inputClass, 'w-1/3')}
                    />
                    {fieldType === 'boolean' ? (
                      <label className="flex flex-1 items-center gap-2 rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2">
                        <input
                          type="checkbox"
                          checked={isBooleanTrue}
                          onChange={(e) => {
                            // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-explicit-any -- dynamic form path requires broad setValue type
                            (setValue as any)(
                              `customFields.${idx}.value`,
                              String(e.target.checked),
                            );
                          }}
                          className="h-4 w-4 rounded border-[hsl(var(--input))] text-[hsl(var(--primary))] focus:ring-[hsl(var(--ring))]"
                        />
                        <span className="text-sm text-[hsl(var(--foreground))]">
                          {isBooleanTrue ? 'True' : 'False'}
                        </span>
                      </label>
                    ) : (
                      <input
                        {...register(`customFields.${idx}.value` as const)}
                        placeholder="Value"
                        className={cn(inputClass, 'flex-1')}
                      />
                    )}
                    <select
                      {...register(`customFields.${idx}.type` as const)}
                      className={cn(inputClass, 'w-24')}
                    >
                      <option value="text">Text</option>
                      <option value="hidden">Hidden</option>
                      <option value="boolean">Boolean</option>
                    </select>
                    <button
                      type="button"
                      onClick={() => removeCustomField(idx)}
                      className="shrink-0 rounded p-2 text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)]"
                      aria-label="Remove custom field"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* --- Secret fields --- */}
      {itemType === 'secret' && (
        <div className="space-y-4">
          <FormField label="Value" name="value" error={errors.value?.message}>
            <textarea
              id="field-value"
              {...register('value')}
              placeholder="Secret value (API key, token, etc.)"
              rows={3}
              className={cn(inputClass, 'font-mono resize-y')}
              aria-describedby={errors.value ? 'field-value-error' : undefined}
              aria-invalid={errors.value ? true : undefined}
            />
          </FormField>
          <FormField label="Description" name="description">
            <textarea
              id="field-description"
              {...register('description')}
              placeholder="Description (optional)"
              rows={2}
              className={cn(inputClass, 'resize-y')}
            />
          </FormField>
          <div className="grid grid-cols-2 gap-3">
            <FormField label="Expiry Date" name="expiryDate">
              <input
                id="field-expiryDate"
                {...register('expiryDate')}
                type="date"
                className={inputClass}
              />
            </FormField>
            <FormField label="Time (optional)" name="expiryTime">
              <input
                id="field-expiryTime"
                {...register('expiryTime')}
                type="time"
                className={inputClass}
              />
            </FormField>
          </div>
          {/* Custom fields for secret */}
          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <span className="text-sm font-medium text-[hsl(var(--foreground))]">
                Custom Fields
              </span>
              <button
                type="button"
                onClick={() => appendCustomField({ name: '', value: '', type: 'text' })}
                className="text-xs text-[hsl(var(--primary))] hover:underline"
              >
                + Add Field
              </button>
            </div>
            <div className="space-y-2">
              {customFields.map((field, idx) => (
                <div key={field.id} className="flex gap-2">
                  <input
                    {...register(`customFields.${idx}.name` as const)}
                    placeholder="Field name"
                    className={cn(inputClass, 'w-1/3')}
                  />
                  <input
                    {...register(`customFields.${idx}.value` as const)}
                    placeholder="Value"
                    className={cn(inputClass, 'flex-1')}
                  />
                  <select
                    {...register(`customFields.${idx}.type` as const)}
                    className={cn(inputClass, 'w-24')}
                  >
                    <option value="text">Text</option>
                    <option value="hidden">Hidden</option>
                  </select>
                  <button
                    type="button"
                    onClick={() => removeCustomField(idx)}
                    className="shrink-0 rounded p-2 text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)]"
                    aria-label="Remove custom field"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* --- Note fields --- */}
      {itemType === 'note' && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <select {...register('format')} className={cn(inputClass, 'w-36')}>
              <option value="markdown">Markdown</option>
              <option value="plaintext">Plain Text</option>
            </select>
            <button
              type="button"
              onClick={() => setShowPreview((p) => !p)}
              className="text-sm text-[hsl(var(--primary))] hover:underline"
            >
              {showPreview ? 'Edit' : 'Preview'}
            </button>
          </div>
          {showPreview && noteContent ? (
            <div className="prose prose-sm dark:prose-invert max-w-none rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4">
              <ReactMarkdown
                skipHtml
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
                {noteContent}
              </ReactMarkdown>
            </div>
          ) : (
            <FormField label="Content" name="content" error={errors.content?.message}>
              <textarea
                id="field-content"
                {...register('content')}
                placeholder="Write your note..."
                rows={10}
                className={cn(inputClass, 'font-mono resize-y')}
                aria-describedby={errors.content ? 'field-content-error' : undefined}
                aria-invalid={errors.content ? true : undefined}
              />
            </FormField>
          )}
        </div>
      )}

      {/* --- Card fields --- */}
      {itemType === 'card' && (
        <div className="space-y-4">
          <FormField
            label="Cardholder Name"
            name="cardholderName"
            error={errors.cardholderName?.message}
          >
            <input
              id="field-cardholderName"
              {...register('cardholderName')}
              placeholder="Name on card"
              className={inputClass}
              autoComplete="off"
              aria-describedby={errors.cardholderName ? 'field-cardholderName-error' : undefined}
              aria-invalid={errors.cardholderName ? true : undefined}
            />
          </FormField>
          <FormField label="Card Number" name="number" error={errors.number?.message}>
            <input
              id="field-number"
              value={(watch('number') as string | undefined) ?? ''}
              onChange={(e) => {
                const formatted = formatCardNumber(e.target.value);
                setValue('number', formatted, { shouldValidate: true });
              }}
              placeholder="1234 5678 9012 3456"
              inputMode="numeric"
              maxLength={23}
              className={cn(inputClass, 'font-mono tracking-wider')}
              autoComplete="off"
              aria-describedby={errors.number ? 'field-number-error' : undefined}
              aria-invalid={errors.number ? true : undefined}
            />
            {cardLuhnWarning && (
              <p className="mt-1 text-xs text-yellow-600 dark:text-yellow-400">{cardLuhnWarning}</p>
            )}
          </FormField>
          <div className="grid grid-cols-3 gap-3">
            <FormField label="Exp Month" name="expMonth" error={errors.expMonth?.message}>
              <input
                id="field-expMonth"
                {...register('expMonth')}
                placeholder="MM"
                maxLength={2}
                className={inputClass}
                autoComplete="off"
                aria-describedby={errors.expMonth ? 'field-expMonth-error' : undefined}
                aria-invalid={errors.expMonth ? true : undefined}
              />
            </FormField>
            <FormField label="Exp Year" name="expYear" error={errors.expYear?.message}>
              <input
                id="field-expYear"
                {...register('expYear')}
                placeholder="YYYY"
                maxLength={4}
                className={inputClass}
                autoComplete="off"
                aria-describedby={errors.expYear ? 'field-expYear-error' : undefined}
                aria-invalid={errors.expYear ? true : undefined}
              />
            </FormField>
            <FormField label="CVV" name="cvv" error={errors.cvv?.message}>
              <input
                id="field-cvv"
                {...register('cvv')}
                type="password"
                placeholder="CVV"
                maxLength={4}
                className={cn(inputClass, 'font-mono')}
                autoComplete="off"
                aria-describedby={errors.cvv ? 'field-cvv-error' : undefined}
                aria-invalid={errors.cvv ? true : undefined}
              />
            </FormField>
          </div>
          <FormField label="Brand" name="brand">
            <input
              id="field-brand"
              {...register('brand')}
              placeholder="Visa, Mastercard, etc."
              className={inputClass}
            />
          </FormField>

          {/* Billing Address (optional, collapsible) */}
          {!showBillingAddress ? (
            <button
              type="button"
              onClick={() => setShowBillingAddress(true)}
              className="text-sm text-[hsl(var(--primary))] hover:underline"
            >
              + Add billing address
            </button>
          ) : (
            <div className="space-y-3 rounded-lg border border-[hsl(var(--border))] p-4">
              <div className="flex items-center justify-between">
                <p className="text-sm font-medium text-[hsl(var(--foreground))]">Billing Address</p>
                <button
                  type="button"
                  onClick={() => {
                    setShowBillingAddress(false);
                    setValue('billingStreet', '');
                    setValue('billingCity', '');
                    setValue('billingState', '');
                    setValue('billingZip', '');
                    setValue('billingCountry', '');
                  }}
                  className="text-xs text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]"
                >
                  Remove
                </button>
              </div>
              <FormField label="Street" name="billingStreet">
                <input
                  id="field-billingStreet"
                  {...register('billingStreet')}
                  placeholder="Street address"
                  className={inputClass}
                  autoComplete="off"
                />
              </FormField>
              <div className="grid grid-cols-2 gap-3">
                <FormField label="City" name="billingCity">
                  <input
                    id="field-billingCity"
                    {...register('billingCity')}
                    placeholder="City"
                    className={inputClass}
                    autoComplete="off"
                  />
                </FormField>
                <FormField label="State" name="billingState">
                  <input
                    id="field-billingState"
                    {...register('billingState')}
                    placeholder="State"
                    className={inputClass}
                    autoComplete="off"
                  />
                </FormField>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <FormField label="ZIP" name="billingZip">
                  <input
                    id="field-billingZip"
                    {...register('billingZip')}
                    placeholder="ZIP code"
                    className={inputClass}
                    autoComplete="off"
                  />
                </FormField>
                <FormField label="Country" name="billingCountry">
                  <input
                    id="field-billingCountry"
                    {...register('billingCountry')}
                    placeholder="Country"
                    className={inputClass}
                    autoComplete="off"
                  />
                </FormField>
              </div>
            </div>
          )}
        </div>
      )}

      {/* --- Identity fields --- */}
      {itemType === 'identity' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <FormField label="First Name" name="firstName" error={errors.firstName?.message}>
              <input
                id="field-firstName"
                {...register('firstName')}
                placeholder="First name"
                className={inputClass}
                autoComplete="off"
                aria-describedby={errors.firstName ? 'field-firstName-error' : undefined}
                aria-invalid={errors.firstName ? true : undefined}
              />
            </FormField>
            <FormField label="Last Name" name="lastName" error={errors.lastName?.message}>
              <input
                id="field-lastName"
                {...register('lastName')}
                placeholder="Last name"
                className={inputClass}
                autoComplete="off"
                aria-describedby={errors.lastName ? 'field-lastName-error' : undefined}
                aria-invalid={errors.lastName ? true : undefined}
              />
            </FormField>
          </div>
          <FormField label="Email" name="email" error={errors.email?.message}>
            <input
              id="field-email"
              {...register('email')}
              type="email"
              placeholder="Email address"
              className={inputClass}
              autoComplete="off"
              aria-describedby={errors.email ? 'field-email-error' : undefined}
              aria-invalid={errors.email ? true : undefined}
            />
          </FormField>
          <FormField label="Phone" name="phone" error={errors.phone?.message}>
            <input
              id="field-phone"
              {...register('phone')}
              type="tel"
              placeholder="Phone number"
              className={inputClass}
              autoComplete="off"
              aria-describedby={errors.phone ? 'field-phone-error' : undefined}
              aria-invalid={errors.phone ? true : undefined}
            />
          </FormField>
          <div className="space-y-3 rounded-lg border border-[hsl(var(--border))] p-4">
            <p className="text-sm font-medium text-[hsl(var(--foreground))]">Address</p>
            <FormField label="Street" name="street">
              <input
                id="field-street"
                {...register('street')}
                placeholder="Street address"
                className={inputClass}
                autoComplete="off"
              />
            </FormField>
            <div className="grid grid-cols-2 gap-3">
              <FormField label="City" name="city">
                <input
                  id="field-city"
                  {...register('city')}
                  placeholder="City"
                  className={inputClass}
                  autoComplete="off"
                />
              </FormField>
              <FormField label="State" name="state">
                <input
                  id="field-state"
                  {...register('state')}
                  placeholder="State"
                  className={inputClass}
                  autoComplete="off"
                />
              </FormField>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <FormField label="ZIP" name="zip">
                <input
                  id="field-zip"
                  {...register('zip')}
                  placeholder="ZIP code"
                  className={inputClass}
                  autoComplete="off"
                />
              </FormField>
              <FormField label="Country" name="country">
                <input
                  id="field-country"
                  {...register('country')}
                  placeholder="Country"
                  className={inputClass}
                  autoComplete="off"
                />
              </FormField>
            </div>
          </div>
        </div>
      )}

      {/* Common: Folder, Tags, Favorite */}
      <div className="space-y-4 border-t border-[hsl(var(--border))] pt-4">
        {/* Folder selector */}
        <FormField label="Folder" name="folder">
          <select
            id="field-folder"
            value={folderId}
            onChange={(e) => setFolderId(e.target.value)}
            className={inputClass}
          >
            <option value="">No folder</option>
            {folders.map((folder) => (
              <option key={folder.id} value={folder.id}>
                {folder.name}
              </option>
            ))}
          </select>
        </FormField>

        {/* Tags */}
        <div>
          <label className="mb-1.5 block text-sm font-medium text-[hsl(var(--foreground))]">
            Tags
          </label>
          <div className="mb-2 flex flex-wrap gap-1.5">
            {tags.map((tag) => (
              <span
                key={tag}
                className="inline-flex items-center gap-1 rounded-full bg-[hsl(var(--secondary))] px-2.5 py-0.5 text-xs font-medium text-[hsl(var(--secondary-foreground))]"
              >
                {tag}
                <button
                  type="button"
                  onClick={() => handleRemoveTag(tag)}
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
              type="text"
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  handleAddTag();
                }
              }}
              placeholder="Add a tag..."
              maxLength={50}
              className={cn(inputClass, 'flex-1')}
            />
            <button
              type="button"
              onClick={handleAddTag}
              disabled={!tagInput.trim()}
              className="rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] disabled:opacity-50 transition-colors"
            >
              Add
            </button>
          </div>
        </div>

        {/* Favorite toggle */}
        <label className="flex cursor-pointer items-center gap-2">
          <button
            type="button"
            onClick={() => setFavorite((p) => !p)}
            className="rounded p-0.5"
            aria-pressed={favorite}
          >
            <Star
              className={cn(
                'h-5 w-5 transition-colors',
                favorite
                  ? 'fill-yellow-400 text-yellow-400'
                  : 'text-[hsl(var(--muted-foreground))]',
              )}
            />
          </button>
          <span className="text-sm text-[hsl(var(--foreground))]">Mark as favorite</span>
        </label>
      </div>

      {/* Actions */}
      <div className="flex justify-end gap-2 border-t border-[hsl(var(--border))] pt-4">
        <button
          type="button"
          onClick={onCancel}
          className="rounded-md px-4 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={saving}
          className="rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity disabled:opacity-50"
        >
          {saving ? 'Saving...' : isEditing ? 'Update' : 'Create'}
        </button>
      </div>
    </form>
  );
}
