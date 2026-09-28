import { z } from '../zod.js';
import {
  MAX_RELEASE_CHANGES,
  MAX_RELEASE_HIGHLIGHTS,
  MAX_RELEASE_HIGHLIGHT_TITLE_LENGTH,
  MAX_RELEASE_NOTES_LISTED,
  MAX_RELEASE_SUMMARY_LENGTH,
  MAX_RELEASE_TEXT_LENGTH,
  MAX_RELEASE_TITLE_LENGTH,
  MAX_RELEASE_URL_LENGTH,
  MAX_RELEASE_VERSION_LENGTH,
  MAX_RELEASE_WIRE_CODE_LENGTH,
  MIN_RELEASE_CHANGES,
  MIN_RELEASE_HIGHLIGHTS,
  MIN_RELEASE_HIGHLIGHT_TITLE_LENGTH,
  MIN_RELEASE_SUMMARY_LENGTH,
  MIN_RELEASE_TEXT_LENGTH,
  MIN_RELEASE_TITLE_LENGTH,
  RELEASE_AUDIENCES,
} from '../constants/index.js';
import { isReleaseVersion } from '../utils/releaseVersion.js';

// The release-notes and update-status API: what `GET /releases/status`,
// `GET /releases/notes`, `POST /releases/seen` and `POST /releases/update-check`
// carry. The client parses every response with these before using it, and the
// server's content test parses every authored entry with the same entry schema,
// so an entry the client would refuse can never be shipped.
//
// Kinds, icons and update states travel as bounded STRINGS, not enums. A tab still
// running the previous release keeps working against a newer server: an unknown
// code gets a neutral fallback on screen instead of failing the whole response.
// Membership in the closed lists is enforced where the values are WRITTEN, by the
// server's content test.

/** A release version (see `RELEASE_VERSION_PATTERN`). */
export const releaseVersionSchema = z
  .string()
  .max(MAX_RELEASE_VERSION_LENGTH)
  .refine(isReleaseVersion, { message: 'Must be a release version such as 1.4.0' });

/**
 * A calendar date written `YYYY-MM-DD`, as the CHANGELOG headings write them. The
 * round trip through `Date` refuses a well-shaped impossible date (2026-02-30),
 * and the `NaN` check comes first because `toISOString()` THROWS on an invalid
 * date rather than returning something a comparison could refuse.
 */
const releaseDateSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, { message: 'Must be a date written YYYY-MM-DD' })
  .refine(
    (value) => {
      const time = Date.parse(`${value}T00:00:00Z`);
      return !Number.isNaN(time) && new Date(time).toISOString().startsWith(value);
    },
    { message: 'Must be a real calendar date' },
  );

/** Plain text between two lengths, measured after trimming the ends. */
function releaseText(min: number, max: number) {
  return z
    .string()
    .max(max)
    .refine((value) => value.trim().length >= min, {
      message: `Must hold at least ${String(min)} characters`,
    });
}

const wireCodeSchema = z.string().min(1).max(MAX_RELEASE_WIRE_CODE_LENGTH);
const audienceSchema = z.enum(RELEASE_AUDIENCES);

export const releaseHighlightSchema = z.object({
  icon: wireCodeSchema,
  title: releaseText(MIN_RELEASE_HIGHLIGHT_TITLE_LENGTH, MAX_RELEASE_HIGHLIGHT_TITLE_LENGTH),
  body: releaseText(MIN_RELEASE_TEXT_LENGTH, MAX_RELEASE_TEXT_LENGTH),
  audience: audienceSchema.optional(),
});

export const releaseChangeSchema = z.object({
  kind: wireCodeSchema,
  text: releaseText(MIN_RELEASE_TEXT_LENGTH, MAX_RELEASE_TEXT_LENGTH),
  audience: audienceSchema.optional(),
});

/** One release's notes, as authored. */
export const releaseNoteSchema = z.object({
  version: releaseVersionSchema,
  date: releaseDateSchema,
  title: releaseText(MIN_RELEASE_TITLE_LENGTH, MAX_RELEASE_TITLE_LENGTH),
  summary: releaseText(MIN_RELEASE_SUMMARY_LENGTH, MAX_RELEASE_SUMMARY_LENGTH),
  highlights: z
    .array(releaseHighlightSchema)
    .min(MIN_RELEASE_HIGHLIGHTS)
    .max(MAX_RELEASE_HIGHLIGHTS),
  changes: z.array(releaseChangeSchema).min(MIN_RELEASE_CHANGES).max(MAX_RELEASE_CHANGES),
});

/** One release's notes as a given viewer receives them. */
export const releaseNoteViewSchema = releaseNoteSchema.extend({
  /** Newer than the release notes this account last acknowledged. */
  isNew: z.boolean(),
});

const releaseUrlSchema = z.string().max(MAX_RELEASE_URL_LENGTH);
const timestampSchema = z.iso.datetime();

/** What the server knows about newer releases. Sent only to the update audience. */
export const updateStatusSchema = z.object({
  state: wireCodeSchema,
  /** The newest release the last successful check found, or `null` before one. */
  latestVersion: releaseVersionSchema.nullable(),
  publishedAt: timestampSchema.nullable(),
  /** The release page for `latestVersion`, built by the server, never taken from the network. */
  releaseUrl: releaseUrlSchema.nullable(),
  lastCheckedAt: timestampSchema.nullable(),
  lastSuccessAt: timestampSchema.nullable(),
  /** Whether a "Check now" is allowed at all (false while checks are turned off). */
  canCheckNow: z.boolean(),
});

export const releaseStatusDataSchema = z.object({
  /** The version this server runs. */
  version: releaseVersionSchema,
  releaseUrl: releaseUrlSchema,
  releaseNotes: z.object({
    seenVersion: releaseVersionSchema,
    unseenCount: z.number().int().min(0),
    showOnUpdate: z.boolean(),
  }),
  update: updateStatusSchema.nullable(),
});

export const releaseNotesDataSchema = z.object({
  version: releaseVersionSchema,
  seenVersion: releaseVersionSchema,
  releases: z.array(releaseNoteViewSchema).max(MAX_RELEASE_NOTES_LISTED),
});

/** Body of `POST /releases/seen`: the newest release the viewer was shown. */
export const markReleaseNotesSeenSchema = z.object({
  version: releaseVersionSchema,
});

export const releaseNotesSeenDataSchema = z.object({
  seenVersion: releaseVersionSchema,
  unseenCount: z.number().int().min(0),
});

export const updateCheckDataSchema = z.object({
  update: updateStatusSchema,
  /** False when the answer came from the stored state rather than a fresh request. */
  fetched: z.boolean(),
});

/** The `{ success, data }` envelope around one of the data schemas above. */
function envelope<T extends z.ZodType>(data: T) {
  return z.object({
    success: z.literal(true),
    data,
    message: z.string().optional(),
  });
}

export const releaseStatusResponseSchema = envelope(releaseStatusDataSchema);
export const releaseNotesResponseSchema = envelope(releaseNotesDataSchema);
export const releaseNotesSeenResponseSchema = envelope(releaseNotesSeenDataSchema);
export const updateCheckResponseSchema = envelope(updateCheckDataSchema);
