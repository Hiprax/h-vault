/**
 * The rules a document's editable details are checked against, shared by the two
 * places a person types them: the upload panel, before a file is sent, and the
 * Edit details dialog, before a committed document is re-sealed.
 *
 * One module, because the two forms ask the same questions of the same blob and
 * two copies of a bound would drift. It is imported only by lazy page chunks (the
 * two forms, and the bulk tag in `documentBulk.ts`), never by the store: the store is in the initial payload, so the
 * dependency runs one way, and the sentence the store itself refuses with
 * ({@link DOCUMENT_TYPE_LOCKED_MESSAGE}) is defined there and imported here.
 */
import {
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  MAX_DOCUMENT_META_JSON_BYTES,
  MAX_DOCUMENT_NAME_LENGTH,
  MAX_DOCUMENT_NOTE_LENGTH,
  MAX_DOCUMENT_TAGS,
  MAX_TAG_LENGTH,
  documentChunkCountFor,
  documentExtension,
  documentMetaJsonByteLength,
  documentMetaSchema,
} from '@hvault/shared';
import type { DocumentMeta } from '@hvault/shared';
import {
  DOCUMENT_TYPE_LOCKED_MESSAGE,
  PLACEHOLDER_DIGEST,
  metaShapeFor,
  type StartUploadInput,
} from '../stores/documentsStore';

/**
 * What a document added before original names were recorded shows instead of
 * one. Nothing is inferred from its current name: a guess would assert where a
 * file came from when nobody observed it.
 */
export const ORIGINAL_NAME_NOT_RECORDED = 'Not recorded for this document.';

/**
 * Why this metadata cannot be stored, or `null` when it can.
 *
 * Every bound a person can reach by typing is checked here, before anything is
 * sealed, for the reason the vault form records: a value the store refuses fails
 * as a schema issue, which is not a sentence anyone can act on. The BYTE budget is
 * checked with the shared helper rather than by counting characters, because
 * every field bound above it counts UTF-16 code units while the sealed blob is
 * bytes: a 10,000-character note in a non-Latin script is three times its own
 * length once encoded.
 *
 * The schema itself has the last word, so a bound nobody types (a file type the
 * operating system reported at an absurd length) is still refused here rather
 * than after the whole file has been read.
 */
export function documentMetaRefusal(meta: DocumentMeta): string | null {
  if (meta.tags.length > MAX_DOCUMENT_TAGS) {
    return `A document can carry at most ${String(MAX_DOCUMENT_TAGS)} tags.`;
  }
  const overlongTag = meta.tags.find((tag) => tag.length > MAX_TAG_LENGTH);
  if (overlongTag !== undefined) {
    return `Tags can be at most ${String(MAX_TAG_LENGTH)} characters; "${overlongTag}" is longer.`;
  }
  if (meta.note !== undefined && meta.note.length > MAX_DOCUMENT_NOTE_LENGTH) {
    return `A note can be at most ${String(MAX_DOCUMENT_NOTE_LENGTH)} characters.`;
  }
  if (documentMetaJsonByteLength(meta) > MAX_DOCUMENT_META_JSON_BYTES) {
    return `The name, tags and note of a document have to fit in ${String(MAX_DOCUMENT_META_JSON_BYTES)} bytes once encoded. Shorten the note.`;
  }
  if (!documentMetaSchema.safeParse(meta).success) {
    return 'The details of this file cannot be stored with it.';
  }
  return null;
}

/**
 * The name a document gets from the part of it a person typed.
 *
 * The file type is fixed when a document is added: the preview, the renderer and
 * the download all key on the extension, so the forms edit only the STEM and the
 * suffix is put back here, exactly as it was written. The extension is compared
 * with the CURRENT name's rather than assumed, which is what refuses a dot typed
 * into a name that has no extension (`Dockerfile` becoming `Docker.file`), and
 * what lets a document renamed to another type before this rule existed keep the
 * type it shows today.
 */
export function nameFromStem(
  stem: string,
  suffix: string,
  currentName: string,
): { name: string } | { refusal: string } {
  const trimmed = stem.trim();
  if (trimmed === '') return { refusal: 'A document needs a name.' };
  const name = `${trimmed}${suffix}`;
  if (documentExtension(name) !== documentExtension(currentName)) {
    return { refusal: DOCUMENT_TYPE_LOCKED_MESSAGE };
  }
  if (name.length > MAX_DOCUMENT_NAME_LENGTH) {
    return {
      refusal: `A name can be at most ${String(MAX_DOCUMENT_NAME_LENGTH)} characters, including its extension.`,
    };
  }
  return { name };
}

/**
 * Why this upload's details cannot be stored, or `null` when they can.
 *
 * Built on the store's own {@link metaShapeFor} with the same placeholder digest
 * the store's pre-flight uses, so the panel measures exactly the blob the store
 * will seal, original name included, and a refusal keeps the file and the typed
 * details on screen instead of arriving as a failed transfer.
 */
export function uploadRefusal(
  input: Pick<StartUploadInput, 'name' | 'originalName' | 'mime' | 'tags' | 'note' | 'transform'>,
  plaintextBytes: number,
): string | null {
  const chunkCount = documentChunkCountFor(plaintextBytes, DOCUMENT_PLAINTEXT_CHUNK_BYTES);
  return documentMetaRefusal({
    ...metaShapeFor(input, plaintextBytes, chunkCount, new Date().toISOString()),
    sha256: PLACEHOLDER_DIGEST,
  });
}
