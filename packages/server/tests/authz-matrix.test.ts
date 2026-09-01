/**
 * The cross-user authorization matrix, driven by `tests/support/routeTable.ts`.
 *
 * Risk R4 was that cross-user isolation was tested ad hoc: every case was
 * written by hand against a particular endpoint, so a route added tomorrow got
 * no IDOR check and nothing anywhere said so. This suite replaces "someone
 * remembered" with "the table said so":
 *
 *   * every row that takes an owned `:id` gets the same four cases, and
 *   * every row whatsoever gets its `auth` and `csrf` classification OBSERVED
 *     over the wire, so the table cannot claim a protection the app does not
 *     apply.
 *
 * The invariant, per id-taking route: **user B presenting user A's id receives
 * 404 or 403, and A's document is byte-identical afterwards** — including its
 * `updatedAt`, because a write that "fails" after touching the row is not
 * isolation, it is a data-loss bug wearing a 404.
 *
 * Seam: the real Express app through supertest against the real mongod
 * `tests/setup.ts` starts, with two real accounts from `tests/helpers.ts`.
 * Ownership here is enforced by the `{ _id, userId }` filter in each
 * controller's query, which is a database behaviour, so a faked datastore
 * would test nothing at all — the datastore, the middleware and the clock are
 * all real. Exactly two things are replaced, both EXTERNAL to the application:
 * the storage feature flag (see the two mocks below) and object storage itself.
 *
 * ---------------------------------------------------------------------------
 * THE CHAIN THAT MAKES A NEW ROUTE FAIL UNTIL IT IS CLASSIFIED
 * ---------------------------------------------------------------------------
 *
 *   new route in src/routes/*.ts   → route-table.test.ts fails: unclassified
 *   classified with `owned: {...}` → this suite fails: no scenario
 *   scenario added                 → the four cases run against it
 *
 * A row is only allowed out of the matrix by declaring `owned: null`, and
 * `route-table.test.ts` refuses that for any path carrying a parameter.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS SUITE DELIBERATELY DOES NOT COVER
 * ---------------------------------------------------------------------------
 *
 * A foreign id passed in the BODY rather than the path — `bulk-delete`'s `ids`,
 * `bulk-move`'s `folderId`, a folder's `parentId`, an import's `updates[].id`,
 * a rotation's `items[].id` — is not expressible as a table row, because the
 * table classifies the URL. Those live in `cross-user-isolation.test.ts` and
 * `phase7-cross-user-edge-cases.test.ts`, together with the collection-scoping
 * cases (a LIST endpoint returning only the caller's rows), which are an
 * invariant about a response body rather than about an id.
 */
import { createHash } from 'node:crypto';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES, DOCUMENT_TAG_BYTES } from '@hvault/shared';

/**
 * Turn the document store ON for this file's module graph.
 *
 * Every document route sits behind `requireStorage`, which answers 503 unless the
 * four `S3_*` connection variables are set — and `vitest.config.ts` pins them
 * EMPTY on purpose, so that a developer's root `.env` cannot change the shape of
 * the application under test. Without this the matrix would observe 503 on every
 * document row and prove nothing about ownership.
 *
 * A HOISTED `vi.mock`, never `vi.resetModules()` + `vi.doMock`: resetting the
 * registry re-evaluates `models/User.ts` against the externalised mongoose
 * singleton, which throws `OverwriteModelError`. `coverage-rate-limiter.test.ts`
 * forces `isProduction` the same way.
 */
vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return { ...actual, storageConfigured: true };
});

/**
 * …and give it somewhere to put bytes.
 *
 * This file used to override `storageConfigured` ALONE, on the argument that no
 * document route the table declared could reach object storage. That stopped being
 * true with `PUT /uploads/:id/parts/:partNumber`: a legitimate call from the owner
 * stores a part, and the matrix's owner case asserts that the call really acts. So
 * the in-memory double is installed here, exactly as `document-uploads.test.ts`
 * installs it, and a fresh one per test keeps one row's bytes out of the next.
 *
 * It is a DOUBLE and not a stub of the controller: object storage is an external
 * service in the same class as SMTP, the datastore this suite is really asking
 * about is Mongo, and Mongo stays real — ownership is decided by a `{_id, userId}`
 * filter, which is a database behaviour.
 */
const { storageRef } = vi.hoisted(() => ({
  storageRef: { current: undefined as ReturnType<typeof createInMemoryStorage> | undefined },
}));

vi.mock('../src/services/storage/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/services/storage/index.js')>();
  return {
    ...actual,
    getStorage: () => {
      if (storageRef.current === undefined) {
        throw new Error('the in-memory storage double was not installed for this test');
      }
      return storageRef.current;
    },
  };
});

import app from '../src/app.js';
import { DocumentUpload } from '../src/models/DocumentUpload.js';
import { Document } from '../src/models/Document.js';
import { Folder } from '../src/models/Folder.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { TrustedDevice } from '../src/models/TrustedDevice.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { hashToken } from '../src/utils/token.js';
import { PART_DIGEST_HEADER } from '../src/controllers/documentController.js';
import { buildObjectKey } from '../src/utils/documentObjects.js';
import { createInMemoryStorage } from './helpers/inMemoryStorage.js';
import {
  ROUTE_TABLE,
  isMountedUnderTest,
  rowKey,
  type HttpMethod,
  type OwnedResource,
  type RouteRow,
} from './support/routeTable.js';
import {
  authHeader,
  createTestUser,
  getCsrf,
  sampleFolder,
  sampleVaultItem,
  type TestUser,
} from './helpers.js';

/** A syntactically valid ObjectId that belongs to nobody. */
const ORPHAN_ID = '0123456789abcdef01234567';
/** Not an ObjectId at all — `validateObjectId` must answer 400, never a CastError 500. */
const MALFORMED_ID = 'not-a-valid-object-id';

/**
 * Passport's message when the Authorization header is absent.
 *
 * Asserted rather than just the 401, because several routes 401 for reasons of
 * their own — `POST /auth/refresh` answers "Refresh token not provided" — and a
 * bare status check could not tell "this route is behind `authenticate`" from
 * "this route rejected me for something else".
 */
const NO_BEARER_MESSAGE = /no auth token/i;

type Agent = ReturnType<typeof request.agent>;

interface SendOptions {
  method: HttpMethod;
  path: string;
  bearer?: string | undefined;
  /** Omit to send the request with no `x-csrf-token` at all. */
  csrf?: boolean;
  body?: Record<string, unknown> | undefined;
  /**
   * A NON-JSON body, with the content type it is sent as.
   *
   * One route in the table takes one: `PUT /uploads/:id/parts/:partNumber` carries
   * a sealed segment as `application/octet-stream`. Sending it as JSON instead
   * would be refused with 415 before ownership was ever consulted, and every case
   * in the matrix would then pass while proving nothing.
   */
  raw?: { body: Buffer; contentType: string } | undefined;
  /** Extra headers a legitimate call carries, such as a part's digest. */
  headers?: Record<string, string> | undefined;
}

/**
 * One request through the real stack.
 *
 * A fresh agent per call, because the CSRF token is bound to the session that
 * minted it: reusing one agent across users would test the token's binding
 * rather than the route's authorization.
 */
async function send({
  method,
  path,
  bearer,
  csrf = true,
  body,
  raw,
  headers,
}: SendOptions): Promise<request.Response> {
  const agent: Agent = request.agent(app);
  const pending = agent[method](path);
  if (bearer !== undefined) pending.set('Authorization', authHeader(bearer));
  if (csrf) {
    const pair = await getCsrf(agent);
    pending.set('Cookie', pair.cookie).set('x-csrf-token', pair.token);
  }
  for (const [name, value] of Object.entries(headers ?? {})) pending.set(name, value);
  // A raw body wins over the JSON one. The `auth`/`csrf` block below calls every
  // row with `body: {}` and no scenario, and both of those refusals happen before
  // any parser runs, so a JSON body on the octet-stream route is harmless there.
  if (raw !== undefined) {
    pending.type(raw.contentType).send(raw.body);
  } else if (body !== undefined) {
    pending.send(body);
  }
  return pending;
}

// ---------------------------------------------------------------------------
// Scenarios: how to give user A a resource, and what a legitimate call to each
// route looks like. Keyed by the table's own row key, so a row and its scenario
// cannot drift apart silently.
// ---------------------------------------------------------------------------

interface Scenario {
  /** Creates the target document for `ownerId` and returns its id. */
  seed: (ownerId: string) => Promise<string>;
  /** Reads the target back as a plain object, or `null` once it is gone. */
  read: (id: string) => Promise<Record<string, unknown> | null>;
  /** How many documents of this kind `userId` owns — the "B gained nothing" check. */
  count: (userId: string) => Promise<number>;
  /**
   * Extra setup ONE route needs on top of its shared resource, run right after
   * `seed` and before the snapshot every case compares against.
   *
   * `POST /uploads/:id/complete` is the reason it exists. The `documentUpload`
   * resource is a live staging row with an EMPTY part ledger, which is what three
   * of its four routes want; completion additionally needs the transfer's one part
   * to have been delivered. Moving that into the shared `seed` would quietly
   * disarm the part route's own control: a re-sent identical part leaves the row
   * byte-identical, so `ownerMutates` there would stop meaning anything. A
   * per-route addition to a shared resource is exactly what `CALLS` is for.
   */
  prepare?: (id: string) => Promise<void>;
  /** Appended to the path (a query string), when the route needs one. */
  query?: string;
  /**
   * Path parameters OTHER than `:id`.
   *
   * `:id` is the one the matrix owns — it is the value ownership is decided by, so
   * it is supplied per case (the owner's, an orphan's, a malformed one). Any other
   * parameter is part of addressing the resource rather than owning it, so it comes
   * from here.
   */
  params?: Record<string, string>;
  /** The body a legitimate call carries. */
  body?: Record<string, unknown>;
  /** A non-JSON body, for the one route that takes one. */
  raw?: { body: Buffer; contentType: string };
  /** Extra headers a legitimate call carries. */
  headers?: Record<string, string>;
  /** What the OWNER receives. */
  ownerStatus: number;
  /**
   * The owner's response body is the document's raw bytes rather than this
   * application's JSON envelope.
   *
   * True for exactly one route, `GET /documents/:id/segments/:index`, and the
   * flag exists because the two things every other read asserts are simply not
   * there: an octet-stream response has no `success` field and no `_id` to echo
   * back. What replaces them is the pair of headers only this route sets and a
   * body equal, byte for byte, to what was stored — a handler that answered with
   * another document's segment could not produce that by accident.
   */
  ownerRespondsWithBytes?: boolean;
  /**
   * Whether a legitimate call CHANGES the target document.
   *
   * This is the control for the refusal case, not bookkeeping. "A non-owner
   * changed nothing" is worth nothing unless an owner would have changed
   * something: a route that 200s and quietly no-ops would otherwise pass the
   * whole matrix while doing neither job.
   */
  ownerMutates: boolean;
}

/**
 * A lean read, as an untyped record.
 *
 * Untyped on purpose: the byte-identical assertion compares the WHOLE document,
 * so it must see whatever fields the model has — including any added later,
 * which a typed projection would quietly drop from the comparison.
 */
const readDoc = async (query: { lean: () => unknown }): Promise<Record<string, unknown> | null> =>
  (await query.lean()) as Record<string, unknown> | null;

/**
 * The ciphertext columns every document row and staging row carries.
 *
 * Opaque strings rather than real ciphertext: this suite asks who may address a
 * row, never what the bytes decrypt to, and a real seal here would tie an
 * ownership test to the crypto service.
 */
const MATRIX_DOCUMENT_CRYPTO = {
  encryptedDek: 'matrix-dek-ciphertext',
  dekIv: 'matrix-dek-iv',
  dekTag: 'matrix-dek-tag',
  streamSalt: 'matrix-stream-salt',
  noncePrefix: 'matrix-prefix',
};

/**
 * The one sealed segment this suite uploads, and the digest that goes with it.
 *
 * Deterministic bytes and a digest computed FROM them rather than written out, so
 * the pair cannot drift: a hard-coded digest beside a changed body would fail every
 * case in this row for the wrong reason, and a test that then "fixed" the body to
 * match would be pinning nothing.
 */
const MATRIX_PART_BODY = Buffer.alloc(1024 + DOCUMENT_TAG_BYTES, 0x5a);
const MATRIX_PART_DIGEST = createHash('sha256').update(MATRIX_PART_BODY).digest('hex');

/** A committed document row for `ownerId`, active or trashed. */
async function seedDocument(ownerId: string, overrides: Record<string, unknown>): Promise<string> {
  const documentId = new mongoose.Types.ObjectId();
  const document = await Document.create({
    _id: documentId,
    userId: ownerId,
    objectKey: buildObjectKey(ownerId, documentId.toHexString()),
    ...MATRIX_DOCUMENT_CRYPTO,
    encryptedMeta: 'matrix-meta-ciphertext',
    metaIv: 'matrix-meta-iv',
    metaTag: 'matrix-meta-tag',
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount: 1,
    ciphertextBytes: 1024 + DOCUMENT_TAG_BYTES,
    plaintextBytes: 1024,
    ...overrides,
  });
  return String(document._id);
}

const RESOURCES: Record<OwnedResource, Pick<Scenario, 'seed' | 'read' | 'count'>> = {
  vaultItem: {
    seed: async (ownerId) => {
      const item = await VaultItem.create({
        userId: ownerId,
        ...sampleVaultItem({ encryptedName: 'owner-item-ciphertext' }),
      });
      return String(item._id);
    },
    read: (id) => readDoc(VaultItem.findById(id)),
    count: (userId) => VaultItem.countDocuments({ userId }),
  },
  trashedVaultItem: {
    seed: async (ownerId) => {
      const item = await VaultItem.create({
        userId: ownerId,
        ...sampleVaultItem({ encryptedName: 'owner-trashed-ciphertext' }),
        deletedAt: new Date(),
      });
      return String(item._id);
    },
    read: (id) => readDoc(VaultItem.findById(id)),
    count: (userId) => VaultItem.countDocuments({ userId }),
  },
  folder: {
    seed: async (ownerId) => {
      const folder = await Folder.create({
        userId: ownerId,
        ...sampleFolder({ encryptedName: 'owner-folder-ciphertext', sortOrder: 3 }),
      });
      return String(folder._id);
    },
    read: (id) => readDoc(Folder.findById(id)),
    count: (userId) => Folder.countDocuments({ userId }),
  },
  session: {
    seed: async (ownerId) => {
      // `createTestUser` already gives each account one refresh token; this is
      // a second, distinct row so the owner-success case can delete one without
      // destroying the session the rest of the matrix authenticates with.
      const token = await RefreshToken.create({
        userId: ownerId,
        tokenHash: hashToken(`matrix-session-${ownerId}`),
        familyId: `matrix-family-${ownerId}`,
        deviceInfo: { userAgent: 'matrix-agent', ip: '127.0.0.1', fingerprint: 'matrix-fp' },
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      });
      return String(token._id);
    },
    read: (id) => readDoc(RefreshToken.findById(id)),
    count: (userId) => RefreshToken.countDocuments({ userId }),
  },
  trustedDevice: {
    seed: async (ownerId) => {
      const device = await TrustedDevice.create({
        userId: ownerId,
        tokenHash: hashToken(`matrix-device-${ownerId}`),
        deviceInfo: { userAgent: 'matrix-agent', ip: '127.0.0.1', fingerprint: 'matrix-fp' },
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      });
      return String(device._id);
    },
    read: (id) => readDoc(TrustedDevice.findById(id)),
    count: (userId) => TrustedDevice.countDocuments({ userId }),
  },
  document: {
    seed: (ownerId) => seedDocument(ownerId, {}),
    read: (id) => readDoc(Document.findById(id)),
    count: (userId) => Document.countDocuments({ userId }),
  },
  trashedDocument: {
    seed: (ownerId) => seedDocument(ownerId, { deletedAt: new Date() }),
    read: (id) => readDoc(Document.findById(id)),
    count: (userId) => Document.countDocuments({ userId }),
  },
  documentUpload: {
    // Deliberately WITHOUT an `s3UploadId`, which makes it a SINGLE-SEGMENT
    // transfer. Two routes depend on that: `DELETE /uploads/:id` has no
    // engine-side multipart upload to abort, and `PUT .../parts/1` addresses the
    // one and only part, so it is the FINAL part and may be short — which is what
    // lets the owner case send a plausible sealed segment of 1024 bytes plus a tag
    // rather than a full 8 MiB chunk.
    //
    // (This file used to add "and no handler here reaches storage"; that stopped
    // being true when the part route arrived, and the in-memory double at the top
    // of the file is what replaced it.)
    seed: async (ownerId) => {
      const uploadId = new mongoose.Types.ObjectId();
      const upload = await DocumentUpload.create({
        _id: uploadId,
        userId: ownerId,
        objectKey: buildObjectKey(ownerId, uploadId.toHexString()),
        ...MATRIX_DOCUMENT_CRYPTO,
        declaredPlaintextBytes: 1024,
        declaredChunkCount: 1,
        chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
        vaultKeyVersion: 0,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      });
      return String(upload._id);
    },
    read: (id) => readDoc(DocumentUpload.findById(id)),
    count: (userId) => DocumentUpload.countDocuments({ userId }),
  },
};

/**
 * Per-route additions to its resource: the body a legitimate call carries and
 * the status its owner gets back.
 */
const CALLS: Record<
  string,
  Pick<
    Scenario,
    | 'prepare'
    | 'query'
    | 'params'
    | 'body'
    | 'raw'
    | 'headers'
    | 'ownerStatus'
    | 'ownerMutates'
    | 'ownerRespondsWithBytes'
  >
> = {
  'GET /api/v1/vault/items/:id': { ownerStatus: 200, ownerMutates: false },
  'PUT /api/v1/vault/items/:id': {
    ownerStatus: 200,
    ownerMutates: true,
    body: { encryptedName: 'renamed-ciphertext', nameIv: 'new-iv', nameTag: 'new-tag' },
  },
  'DELETE /api/v1/vault/items/:id': { ownerStatus: 200, ownerMutates: true },
  'DELETE /api/v1/vault/items/:id/permanent': { ownerStatus: 200, ownerMutates: true },
  'POST /api/v1/vault/items/restore/:id': { ownerStatus: 200, ownerMutates: true },
  'PUT /api/v1/folders/:id': {
    ownerStatus: 200,
    ownerMutates: true,
    body: { encryptedName: 'renamed-folder', nameIv: 'new-iv', nameTag: 'new-tag' },
  },
  'DELETE /api/v1/folders/:id': { ownerStatus: 200, ownerMutates: true, query: '?action=delete' },
  'PUT /api/v1/folders/:id/sort': {
    ownerStatus: 200,
    ownerMutates: true,
    body: { sortOrder: 42 },
  },
  'DELETE /api/v1/user/sessions/:id': { ownerStatus: 200, ownerMutates: true },
  'DELETE /api/v1/user/trusted-devices/:id': { ownerStatus: 200, ownerMutates: true },
  // Only the owned document routes THIS release mounts. `CALLS` is keyed by
  // route, so an entry written ahead of the route it names is an orphan and the
  // "names no scenario for a route the table does not declare" case above fails
  // by design.
  'GET /api/v1/documents/:id': { ownerStatus: 200, ownerMutates: false },
  'GET /api/v1/documents/:id/segments/:index': {
    ownerStatus: 200,
    ownerMutates: false,
    ownerRespondsWithBytes: true,
    // Segment 0 of the one-segment document the shared `document` scenario
    // seeds. `PLACEHOLDER_PARAM` would supply `1`, which is a real index on some
    // documents and outside this one, so the 400 it earns would hide whatever
    // this case is really trying to observe.
    params: { index: '0' },
    // The shared `document` seed writes a ROW and no object, because three of
    // the four routes that use it never reach storage. This is the one that
    // does, so it stores the sealed segment the row's `ciphertextBytes` already
    // describes — `MATRIX_PART_BODY` is exactly 1024 plaintext bytes plus one
    // authentication tag, which is what `seedDocument` records.
    prepare: async (id) => {
      const document = await Document.findById(id).lean();
      await storageRef.current!.putObject(document!.objectKey, MATRIX_PART_BODY);
    },
  },
  'PUT /api/v1/documents/:id': {
    ownerStatus: 200,
    ownerMutates: true,
    // A re-seal of the metadata blob, which is the whole of what this route may
    // write beside the favorite flag and the folder. The values differ from the
    // ones `seedDocument` stored, so the owner case really changes the row and
    // the refusal cases below have something to be evidence of.
    body: { encryptedMeta: 're-sealed-ciphertext', metaIv: 'new-meta-iv', metaTag: 'new-meta-tag' },
  },
  'DELETE /api/v1/documents/:id': { ownerStatus: 200, ownerMutates: true },
  'POST /api/v1/documents/:id/restore': { ownerStatus: 200, ownerMutates: true },
  'DELETE /api/v1/documents/:id/permanent': {
    ownerStatus: 200,
    // The row is destroyed outright, so `read` finds nothing afterwards — the
    // strongest form of "the call really acts".
    ownerMutates: true,
    // The shared `trashedDocument` seed writes a ROW and no object; the purge
    // deletes the object before the row, and S3 deletion is idempotent, so no
    // `prepare` is needed. Storing one anyway would test nothing further and
    // would hide a handler that skipped the object delete entirely.
  },
  'GET /api/v1/documents/uploads/:id': { ownerStatus: 200, ownerMutates: false },
  'DELETE /api/v1/documents/uploads/:id': { ownerStatus: 200, ownerMutates: true },
  'POST /api/v1/documents/uploads/:id/complete': {
    ownerStatus: 201,
    // The staging row is consumed: a successful completion deletes it and inserts
    // the `documents` row in its place, so `read` finds nothing afterwards. That is
    // the strongest possible form of "the call really acts", and it is what makes
    // the refusal cases below mean something.
    ownerMutates: true,
    // The shared `documentUpload` seed is a live transfer with an EMPTY ledger, and
    // completion is the one route that needs its part actually delivered. Stored
    // through the double and recorded in the ledger exactly as `uploadPart` would
    // have: one part of `MATRIX_PART_BODY`, which is 1024 plaintext bytes plus one
    // authentication tag, matching the row's `declaredPlaintextBytes` of 1024.
    prepare: async (id) => {
      const upload = await DocumentUpload.findById(id).lean();
      await storageRef.current!.putObject(upload!.objectKey, MATRIX_PART_BODY);
      await DocumentUpload.updateOne(
        { _id: id },
        {
          $set: {
            parts: [{ partNumber: 1, bytes: MATRIX_PART_BODY.byteLength }],
            receivedBytes: MATRIX_PART_BODY.byteLength,
          },
        },
      );
    },
    body: {
      encryptedMeta: 'matrix-meta-ciphertext',
      metaIv: 'matrix-meta-iv',
      metaTag: 'matrix-meta-tag',
      encryptedDek: 'matrix-dek-ciphertext',
      dekIv: 'matrix-dek-iv',
      dekTag: 'matrix-dek-tag',
      vaultKeyVersion: 0,
    },
  },
  'PUT /api/v1/documents/uploads/:id/parts/:partNumber': {
    ownerStatus: 200,
    // The ledger grows and `receivedBytes` moves, which is what makes the refusal
    // cases below mean something: they assert the row is byte-identical afterwards,
    // and that is only evidence if a legitimate call would have changed it.
    ownerMutates: true,
    // Part 1 of a one-part transfer, so it is the FINAL part and may be short. The
    // `documentUpload` scenario declares one segment of 1024 plaintext bytes; one
    // sealed segment of that is the plaintext plus a single authentication tag.
    params: { partNumber: '1' },
    raw: { body: MATRIX_PART_BODY, contentType: 'application/octet-stream' },
    headers: { [PART_DIGEST_HEADER]: MATRIX_PART_DIGEST },
  },
};

type OwnedRow = RouteRow & { owned: NonNullable<RouteRow['owned']> };

const OWNED_ROWS: OwnedRow[] = ROUTE_TABLE.filter(
  (row): row is OwnedRow => row.owned !== null && isMountedUnderTest(row),
);
const EXERCISABLE_ROWS = ROUTE_TABLE.filter(isMountedUnderTest);

const scenarioFor = (row: OwnedRow): Scenario => ({
  ...RESOURCES[row.owned.resource],
  ...CALLS[rowKey(row)]!,
});

/**
 * A stand-in for a path parameter no scenario named.
 *
 * The `auth`/`csrf` block below walks EVERY row with no scenario at all, and a URL
 * still carrying a literal `:partNumber` would be a URL whose 401 or 403 might
 * really be a routing miss. `1` is a legal value for every non-`:id` parameter the
 * table declares, so those two observations stay about the middleware they name.
 */
const PLACEHOLDER_PARAM = '1';

/** The concrete URL a call to `row` uses: `:id`, then every other parameter. */
const urlFor = (
  row: RouteRow,
  id: string,
  query = '',
  params: Record<string, string> = {},
): string =>
  `${row.path.replace(/:([A-Za-z][A-Za-z0-9_]*)/g, (_match, name: string) =>
    name === 'id' ? id : (params[name] ?? PLACEHOLDER_PARAM),
  )}${query}`;

describe('the matrix covers the table', () => {
  it('has a scenario for every id-taking route', () => {
    // The link that makes a newly-classified owned route fail here until it is
    // actually exercised. Without it, adding `owned: {...}` to the table would
    // satisfy route-table.test.ts and quietly test nothing.
    const missing = OWNED_ROWS.filter((row) => CALLS[rowKey(row)] === undefined).map(rowKey);
    expect(missing, 'id-taking route(s) with no scenario in CALLS').toEqual([]);
  });

  it('names no scenario for a route the table does not declare', () => {
    const declared = new Set(OWNED_ROWS.map(rowKey));
    const orphaned = Object.keys(CALLS).filter((key) => !declared.has(key));
    expect(orphaned, 'scenario(s) whose route is no longer in the table').toEqual([]);
  });

  it('runs the matrix over all twenty id-taking routes', () => {
    // A pinned count, because the cheapest way to silence a failing IDOR case
    // is to change its row's `owned` to null: route-table.test.ts would still
    // pass (it only forces `owned` non-null for paths carrying a parameter, and
    // the parameter would have to go too), and this suite would simply run one
    // fewer describe block with nothing to say so. The number moves only when a
    // route that takes an owned id is genuinely added or removed.
    //
    // Note what is deliberately NOT asserted here: that the row count and the
    // exercised-row count agree. Both are filters of the same array, so that
    // comparison is n === n and cannot fail.
    expect(OWNED_ROWS.map(rowKey).sort()).toEqual(Object.keys(CALLS).sort());
    expect(OWNED_ROWS).toHaveLength(20);
  });
});

describe('cross-user isolation, per id-taking route', () => {
  let userA: TestUser;
  let userB: TestUser;

  beforeEach(async () => {
    storageRef.current = createInMemoryStorage();
    userA = await createTestUser({ email: 'matrix-owner@example.com' });
    userB = await createTestUser({ email: 'matrix-intruder@example.com' });
  });

  describe.each(OWNED_ROWS.map((row) => [rowKey(row), row] as const))('%s', (_key, row) => {
    const scenario = scenarioFor(row);

    it('lets the owner through, and the call really acts', async () => {
      const id = await scenario.seed(userA.id);
      await scenario.prepare?.(id);
      const before = await scenario.read(id);

      const res = await send({
        method: row.method,
        path: urlFor(row, id, scenario.query, scenario.params),
        bearer: userA.accessToken,
        body: scenario.body,
        raw: scenario.raw,
        headers: scenario.headers,
      });

      expect(res.status, JSON.stringify(res.body)).toBe(scenario.ownerStatus);

      const after = await scenario.read(id);
      if (scenario.ownerRespondsWithBytes === true) {
        // Raw ciphertext, so there is no envelope to check. The substitutes are
        // the two headers only this route sets and the bytes themselves, which
        // must be the ones `prepare` stored: a handler reading the wrong offset,
        // the wrong object or a truncated range fails on the body, and one that
        // let the response be cached fails on the header.
        expect(res.headers['content-type']).toBe('application/octet-stream');
        expect(res.headers['cache-control']).toBe('no-store');
        expect(res.body).toEqual(MATRIX_PART_BODY);
        expect(after).toEqual(before);
        return;
      }

      expect(res.body.success).toBe(true);
      if (scenario.ownerMutates) {
        expect(
          after,
          'the owner was told it succeeded but the document did not change',
        ).not.toEqual(before);
      } else {
        // A read: it must hand back THIS document, and leave it alone.
        expect(String((res.body.data as { _id: string })._id)).toBe(id);
        expect(after).toEqual(before);
      }
    });

    it("refuses user B and leaves user A's document byte-identical", async () => {
      const id = await scenario.seed(userA.id);
      await scenario.prepare?.(id);
      const before = await scenario.read(id);
      expect(before, 'the fixture must exist before the attempt').not.toBeNull();
      // B's own holdings, so the check below is "B's side is unchanged" rather
      // than "B owns nothing" — B legitimately owns a refresh-token session
      // from the moment its account exists.
      const intruderBefore = await scenario.count(userB.id);

      const res = await send({
        method: row.method,
        path: urlFor(row, id, scenario.query, scenario.params),
        bearer: userB.accessToken,
        body: scenario.body,
        raw: scenario.raw,
        headers: scenario.headers,
      });

      // 404 (the row does not exist FOR B) or 403. Never a 2xx, and never a 5xx
      // — a stack trace from a CastError would be its own information leak.
      expect([403, 404], `status was ${String(res.status)}: ${JSON.stringify(res.body)}`).toContain(
        res.status,
      );
      expect(res.body.success).toBe(false);

      const after = await scenario.read(id);
      expect(after, "user A's document was deleted by a request that was refused").not.toBeNull();
      // The whole document, not a field of it: `updatedAt` alone would miss a
      // write that Mongoose did not stamp, and a field-by-field check would
      // miss whatever field the next release adds.
      expect(after).toEqual(before);
      expect(after!.updatedAt).toEqual(before!.updatedAt);

      // …and the attempt neither created nor destroyed anything on B's side.
      expect(await scenario.count(userB.id)).toBe(intruderBefore);
    });

    it('answers an unauthenticated caller with 401 and touches nothing', async () => {
      const id = await scenario.seed(userA.id);
      await scenario.prepare?.(id);
      const before = await scenario.read(id);

      const res = await send({
        method: row.method,
        path: urlFor(row, id, scenario.query, scenario.params),
        body: scenario.body,
        raw: scenario.raw,
        headers: scenario.headers,
      });

      expect(res.status).toBe(401);
      expect(String(res.body.message)).toMatch(NO_BEARER_MESSAGE);
      expect(await scenario.read(id)).toEqual(before);
    });

    it('rejects a malformed ObjectId with 400', async () => {
      const res = await send({
        method: row.method,
        path: urlFor(row, MALFORMED_ID, scenario.query, scenario.params),
        bearer: userB.accessToken,
        body: scenario.body,
        raw: scenario.raw,
        headers: scenario.headers,
      });

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(String(res.body.message)).toMatch(/invalid id format/i);
    });

    it('answers a well-formed id that belongs to nobody the same way as a foreign one', async () => {
      // The two must be indistinguishable, or the response is an oracle: a
      // different status for "exists but is not yours" than for "does not
      // exist" enumerates other users' ids one request at a time.
      const foreignId = await scenario.seed(userA.id);
      await scenario.prepare?.(foreignId);

      const foreign = await send({
        method: row.method,
        path: urlFor(row, foreignId, scenario.query, scenario.params),
        bearer: userB.accessToken,
        body: scenario.body,
        raw: scenario.raw,
        headers: scenario.headers,
      });
      const absent = await send({
        method: row.method,
        path: urlFor(row, ORPHAN_ID, scenario.query, scenario.params),
        bearer: userB.accessToken,
        body: scenario.body,
        raw: scenario.raw,
        headers: scenario.headers,
      });

      expect(foreign.status).toBe(absent.status);
      expect(foreign.body.message).toEqual(absent.body.message);
    });
  });
});

describe('every route enforces the auth and CSRF classification the table declares', () => {
  // No fixtures: `authenticate` and `doubleCsrfProtection` both run before any
  // handler, so these cases need no account and reach no controller. The two
  // public state-changing routes that DO reach their handler here
  // (`/auth/register`, `/auth/login`, …) get an empty body and answer 400.
  describe.each(EXERCISABLE_ROWS.map((row) => [rowKey(row), row] as const))('%s', (_key, row) => {
    const path = urlFor(row, ORPHAN_ID);

    it(`is ${row.auth === 'required' ? 'behind' : 'not behind'} authenticate`, async () => {
      // A CSRF token is attached only where the table says one is REQUIRED. For
      // an `exempt` row that omission is the observation: the request arrives
      // with no `x-csrf-token` at all and must still reach its handler, which is
      // the only place this suite watches the exempt half of that column.
      const res = await send({
        method: row.method,
        path,
        csrf: row.csrf === 'required',
        body: {},
      });

      if (row.auth === 'required') {
        expect(res.status, JSON.stringify(res.body)).toBe(401);
        expect(String(res.body.message)).toMatch(NO_BEARER_MESSAGE);
      } else {
        // A public route may still answer 401 for a reason of its own
        // (`/auth/refresh` has no cookie here); what it must never do is
        // reject the caller for having presented no bearer token.
        expect(String(res.body?.message ?? '')).not.toMatch(NO_BEARER_MESSAGE);
      }
    });

    if (row.csrf === 'required') {
      it('rejects a request carrying no CSRF token', async () => {
        const res = await send({ method: row.method, path, csrf: false, body: {} });

        expect(res.status, JSON.stringify(res.body)).toBe(403);
        expect(String(res.body.message)).toMatch(/csrf/i);
      });
    }
  });
});
