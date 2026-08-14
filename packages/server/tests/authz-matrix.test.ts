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
 * Nothing is mocked — not the datastore, not the middleware, not the clock.
 * Ownership here is enforced by the `{ _id, userId }` filter in each
 * controller's query, which is a database behaviour, so a faked datastore
 * would test nothing at all.
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
import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../src/app.js';
import { Folder } from '../src/models/Folder.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { TrustedDevice } from '../src/models/TrustedDevice.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { hashToken } from '../src/utils/token.js';
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
}: SendOptions): Promise<request.Response> {
  const agent: Agent = request.agent(app);
  const pending = agent[method](path);
  if (bearer !== undefined) pending.set('Authorization', authHeader(bearer));
  if (csrf) {
    const pair = await getCsrf(agent);
    pending.set('Cookie', pair.cookie).set('x-csrf-token', pair.token);
  }
  if (body !== undefined) pending.send(body);
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
  /** Appended to the path (a query string), when the route needs one. */
  query?: string;
  /** The body a legitimate call carries. */
  body?: Record<string, unknown>;
  /** What the OWNER receives. */
  ownerStatus: number;
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
};

/**
 * Per-route additions to its resource: the body a legitimate call carries and
 * the status its owner gets back.
 */
const CALLS: Record<string, Pick<Scenario, 'query' | 'body' | 'ownerStatus' | 'ownerMutates'>> = {
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

/** The concrete URL a call to `row` uses for `id`. */
const urlFor = (row: RouteRow, id: string, query = ''): string =>
  `${row.path.replace(':id', id)}${query}`;

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

  it('runs the matrix over all ten id-taking routes', () => {
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
    expect(OWNED_ROWS).toHaveLength(10);
  });
});

describe('cross-user isolation, per id-taking route', () => {
  let userA: TestUser;
  let userB: TestUser;

  beforeEach(async () => {
    userA = await createTestUser({ email: 'matrix-owner@example.com' });
    userB = await createTestUser({ email: 'matrix-intruder@example.com' });
  });

  describe.each(OWNED_ROWS.map((row) => [rowKey(row), row] as const))('%s', (_key, row) => {
    const scenario = scenarioFor(row);

    it('lets the owner through, and the call really acts', async () => {
      const id = await scenario.seed(userA.id);
      const before = await scenario.read(id);

      const res = await send({
        method: row.method,
        path: urlFor(row, id, scenario.query),
        bearer: userA.accessToken,
        body: scenario.body,
      });

      expect(res.status, JSON.stringify(res.body)).toBe(scenario.ownerStatus);
      expect(res.body.success).toBe(true);

      const after = await scenario.read(id);
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
      const before = await scenario.read(id);
      expect(before, 'the fixture must exist before the attempt').not.toBeNull();
      // B's own holdings, so the check below is "B's side is unchanged" rather
      // than "B owns nothing" — B legitimately owns a refresh-token session
      // from the moment its account exists.
      const intruderBefore = await scenario.count(userB.id);

      const res = await send({
        method: row.method,
        path: urlFor(row, id, scenario.query),
        bearer: userB.accessToken,
        body: scenario.body,
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
      const before = await scenario.read(id);

      const res = await send({
        method: row.method,
        path: urlFor(row, id, scenario.query),
        body: scenario.body,
      });

      expect(res.status).toBe(401);
      expect(String(res.body.message)).toMatch(NO_BEARER_MESSAGE);
      expect(await scenario.read(id)).toEqual(before);
    });

    it('rejects a malformed ObjectId with 400', async () => {
      const res = await send({
        method: row.method,
        path: urlFor(row, MALFORMED_ID, scenario.query),
        bearer: userB.accessToken,
        body: scenario.body,
      });

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(String(res.body.message)).toMatch(/invalid id format/i);
    });

    it('answers a well-formed id that belongs to nobody the same way as a foreign one', async () => {
      // The two must be indistinguishable, or the response is an oracle: a
      // different status for "exists but is not yours" than for "does not
      // exist" enumerates other users' ids one request at a time.
      const foreignId = await scenario.seed(userA.id);

      const foreign = await send({
        method: row.method,
        path: urlFor(row, foreignId, scenario.query),
        bearer: userB.accessToken,
        body: scenario.body,
      });
      const absent = await send({
        method: row.method,
        path: urlFor(row, ORPHAN_ID, scenario.query),
        bearer: userB.accessToken,
        body: scenario.body,
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
