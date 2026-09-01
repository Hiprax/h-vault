import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { requireStorage } from '../middleware/requireStorage.js';
import { validate } from '../middleware/validate.js';
import { validateObjectId } from '../middleware/validateObjectId.js';
import {
  documentPartLimiter,
  documentReadLimiter,
  documentUploadLimiter,
  generalAuthLimiter,
} from '../middleware/rateLimiter.js';
import {
  holdPartUploadSlot,
  parsePartUploadBody,
  requirePartContentLength,
} from '../middleware/documentPartBody.js';
import {
  completeDocumentUploadSchema,
  documentPartParamsSchema,
  documentSegmentParamsSchema,
  initDocumentUploadSchema,
  listDocumentTrashSchema,
  listDocumentsSchema,
} from '@hvault/shared';
import {
  abortUpload,
  completeUpload,
  getDocument,
  getSegment,
  getUpload,
  getUsage,
  initUpload,
  listDocumentTrash,
  listDocuments,
  listUploads,
  uploadPart,
} from '../controllers/documentController.js';

const router = Router();

// Every document route is authenticated, and every one of them then requires
// object storage to be configured. Both are ROUTER-level: `authenticate` first, so
// an unauthenticated caller learns nothing about this operator's configuration,
// and `requireStorage` ahead of every route-level limiter, so a deployment with no
// bucket spends no rate-limit budget answering requests it will always refuse.
router.use(authenticate);
router.use(requireStorage);

// ── Collections ──────────────────────────────────────────────────────
//
// The three literal paths (`/trash`, `/usage`, and `/uploads` below) are all
// declared ABOVE the `/:id` routes at the foot of this file — exactly as
// `routes/vault.ts` declares `/items/trash` before `/items/:id`. Express matches
// in declaration order, so a `/:id` above any of them would swallow the literal
// word as an id and answer 400 for a malformed ObjectId.

router.get('/', generalAuthLimiter, validate(listDocumentsSchema, 'query'), listDocuments);
router.get(
  '/trash',
  generalAuthLimiter,
  validate(listDocumentTrashSchema, 'query'),
  listDocumentTrash,
);
router.get('/usage', generalAuthLimiter, getUsage);

// ── Uploads ──────────────────────────────────────────────────────────
//
// The literal `/uploads` prefix is declared here, and every later route that
// takes a bare `/:id` must be declared BELOW it — exactly as `routes/vault.ts`
// declares `/items/trash` before `/items/:id`. Express matches in declaration
// order, so a `/:id` above these would swallow the word `uploads` as an id.

router.get('/uploads', generalAuthLimiter, listUploads);
router.post(
  '/uploads',
  documentUploadLimiter,
  validate(initDocumentUploadSchema, 'body'),
  initUpload,
);
router.get('/uploads/:id', generalAuthLimiter, validateObjectId(), getUpload);
router.delete('/uploads/:id', documentUploadLimiter, validateObjectId(), abortUpload);

// One sealed segment.
//
// THE ORDER OF THIS CHAIN IS LOAD-BEARING, and every step of it is placed rather
// than accumulated:
//
//   * `validateObjectId()` runs BEFORE the param schema, so a malformed id is
//     answered with this codebase's one "Invalid id format" message rather than
//     with a Zod issue — the cross-user matrix asserts that message on every
//     id-taking route.
//   * `documentPartParamsSchema` declares `id` as well as `partNumber`, because
//     `validate()` REPLACES `req.params` wholesale and `z.object()` strips by
//     default: a schema naming only `partNumber` would delete `id` from the
//     request and the handler would read `undefined`.
//   * `requirePartContentLength` answers 411 before a byte is read, and before a
//     concurrency slot is spent on a request that can never be accepted.
//   * `holdPartUploadSlot` sits AHEAD of the parser, never inside the handler:
//     Express runs a route's parser before its handler, so a slot taken in the
//     handler is taken after 8 MiB has already been buffered and bounds nothing.
//     It is held across the storage call and released when the response closes.
//   * `parsePartUploadBody` is mounted HERE, at route level, and must never move to
//     `app.ts`: the Mongo-injection sanitizer there rewrites any object body key by
//     key, and a Buffer is an object — mounted app-level, the parser would run
//     first and the part would arrive as `{0: 137, 1: 80, …}`.
router.put(
  '/uploads/:id/parts/:partNumber',
  documentPartLimiter,
  validateObjectId(),
  validate(documentPartParamsSchema, 'params'),
  requirePartContentLength,
  holdPartUploadSlot,
  parsePartUploadBody,
  uploadPart,
);

// Turn a finished transfer into a document.
//
// `documentUploadLimiter` rather than a budget of its own, because init, complete
// and abort are the three requests of ONE transfer and belong to one budget; the
// part route is the volume one and has its own, derived from the operator's size
// cap. The body is JSON again here — the sealed metadata blob and the wrapped
// document key — so the global parser handles it and no route-level parser is
// mounted, unlike the octet-stream route above.
router.post(
  '/uploads/:id/complete',
  documentUploadLimiter,
  validateObjectId(),
  validate(completeDocumentUploadSchema, 'body'),
  completeUpload,
);

// ── One document ─────────────────────────────────────────────────────
//
// LAST in the file, because these are the routes that take a bare `/:id`.

router.get('/:id', generalAuthLimiter, validateObjectId(), getDocument);

// One sealed segment.
//
// `documentReadLimiter` rather than `generalAuthLimiter`, because this is the
// only read whose request count scales with a file's size: one download is one
// request per segment, so a single 100 MB document is thirteen of them. Its
// ceiling is derived from the operator's own `MAX_DOCUMENT_SIZE_MB` for exactly
// that reason, and it is user-keyed like every other document limiter, so
// downloading can never spend a budget a sign-in needs.
//
// The chain mirrors the part route above, and for the same two reasons:
// `validateObjectId()` runs FIRST so a malformed id gets this codebase's one
// "Invalid id format" message rather than a Zod issue, and
// `documentSegmentParamsSchema` declares `id` as well as `index` because
// `validate()` REPLACES `req.params` wholesale and `z.object()` strips by
// default — a schema naming only `index` would delete `id` from the request and
// the handler would read `undefined`.
//
// There is no body parser and no `Range` header: the byte window is computed
// server-side from the row.
router.get(
  '/:id/segments/:index',
  documentReadLimiter,
  validateObjectId(),
  validate(documentSegmentParamsSchema, 'params'),
  getSegment,
);

export default router;
