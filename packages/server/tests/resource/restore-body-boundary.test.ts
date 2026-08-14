/**
 * The restore body boundary, from above.
 *
 * `restore-volume.test.ts` holds the side that must be ACCEPTED: a document
 * within the 25 MiB schema cap whose JSON-escaped body is larger than that. This
 * file holds the two refusals, and the distinction between them is the point —
 * they come from different layers and a change that collapses one into the other
 * is exactly the regression worth catching:
 *
 *   • `data` LONGER than `MAX_RESTORE_DATA_LENGTH`, in a body the 30 MB parser
 *     still accepts, must be refused by ZOD with 400. If this ever becomes a 413
 *     the parser has been narrowed to the schema's number and the accepted case
 *     above is dead.
 *   • a body larger than the parser's own limit must still be refused with 413.
 *     The parser is generous, not absent; without this the "30 MB" in
 *     `routes/backup.ts` could be raised to anything and nothing would notice.
 *
 * Neither case reaches the database, so neither is a memory or time budget: they
 * are cheap boundary assertions that live beside the expensive one.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { MAX_RESTORE_DATA_LENGTH } from '@hvault/shared';
import app from '../../src/app.js';
import { VaultItem } from '../../src/models/VaultItem.js';
import { createTestUser, authHeader, getCsrf, type TestUser } from '../helpers.js';
import { recordScenarioCase } from './measure.js';

/** The route's own parser limit, from `routes/backup.ts`. */
const PARSER_LIMIT_BYTES = 30 * 1024 * 1024;

describe('the restore body boundary', () => {
  let user: TestUser;

  // `beforeEach`: the global `afterEach` truncates every collection, so a user
  // created once would be gone by the second case and both refusals would come
  // from the authenticator rather than from the boundary under test.
  beforeEach(async () => {
    user = await createTestUser();
  });

  it('rejects data over the schema cap with 400, from Zod rather than the parser', async () => {
    // One byte past the cap, in a payload with no quotes in it at all — so the
    // wire body is ~26.2 MB, comfortably inside the 30 MB parser. Anything but a
    // 400 here means the parser refused it first.
    const data = 'd'.repeat(MAX_RESTORE_DATA_LENGTH + 1);
    const { token, cookie } = await getCsrf(request(app));
    const res = await request(app)
      .post('/api/v1/backup/restore')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', token)
      .set('Cookie', cookie)
      .send({ conflictStrategy: 'skip', data });

    recordScenarioCase('restore-body-boundary', 'data-over-schema-cap-is-400', {
      invariant:
        'a `data` value one byte past MAX_RESTORE_DATA_LENGTH, in a body the 30 MB parser accepts, is refused by Zod with 400 rather than by the parser with 413',
      dataBytes: data.length,
      status: res.status,
    });

    expect(res.status).toBe(400);
    expect(res.body).toMatchObject({ success: false, statusCode: 400 });
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
  }, 300_000);

  it('rejects a body over the route parser limit with 413', async () => {
    const data = 'd'.repeat(PARSER_LIMIT_BYTES + 1024 * 1024);
    const { token, cookie } = await getCsrf(request(app));
    const res = await request(app)
      .post('/api/v1/backup/restore')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', token)
      .set('Cookie', cookie)
      .send({ conflictStrategy: 'skip', data });

    recordScenarioCase('restore-body-boundary', 'body-over-parser-limit-is-413', {
      invariant:
        'a body larger than the route parser limit is still refused with 413, so the generous parser is generous rather than absent',
      parserLimitBytes: PARSER_LIMIT_BYTES,
      dataBytes: data.length,
      status: res.status,
    });

    expect(res.status).toBe(413);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
  }, 300_000);
});
