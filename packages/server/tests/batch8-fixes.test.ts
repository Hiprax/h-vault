/**
 * Tests for Batch 8 fixes:
 *
 * - MEDIUM-7: emptyTrash uses single bounded deleteMany (items trashed after startTime are excluded)
 * - MEDIUM-10: accountLimiter comment accuracy (documentation-only, no runtime test needed)
 * - MEDIUM-8: NoSQL injection comment accuracy (documentation-only, no runtime test needed)
 */
import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { createTestUser, sampleVaultItem, getCsrf as getCsrfBase } from './helpers.js';
import type { TestUser, CsrfPair } from './helpers.js';

async function getCsrf(agent: request.Agent): Promise<CsrfPair> {
  return getCsrfBase(agent);
}

function withCsrf(req: request.Test, csrf: CsrfPair, accessToken: string): request.Test {
  return req
    .set('x-csrf-token', csrf.token)
    .set('Cookie', csrf.cookie)
    .set('Authorization', `Bearer ${accessToken}`);
}

const API = '/api/v1';

// ---------------------------------------------------------------------------
// MEDIUM-7: emptyTrash bounded deleteMany
// ---------------------------------------------------------------------------
describe('MEDIUM-7: emptyTrash bounded deleteMany', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('should delete all trashed items in a single operation', async () => {
    // Create 3 items and soft-delete them
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) {
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      const res = await withCsrf(agent.post(`${API}/vault/items`), csrf, user.accessToken).send(
        sampleVaultItem(),
      );
      ids.push(res.body.data._id as string);
    }

    // Soft-delete all 3
    for (const id of ids) {
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      await withCsrf(agent.delete(`${API}/vault/items/${id}`), csrf, user.accessToken).expect(200);
    }

    // Verify trash has 3 items
    const trashRes = await request(app)
      .get(`${API}/vault/items/trash`)
      .set('Authorization', `Bearer ${user.accessToken}`)
      .expect(200);
    expect(trashRes.body.data).toHaveLength(3);

    // Empty trash
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const emptyRes = await withCsrf(
      agent.delete(`${API}/vault/items/trash/empty`),
      csrf,
      user.accessToken,
    ).expect(200);

    expect(emptyRes.body.success).toBe(true);
    expect(emptyRes.body.data.deletedCount).toBe(3);

    // Verify trash is empty
    const trashRes2 = await request(app)
      .get(`${API}/vault/items/trash`)
      .set('Authorization', `Bearer ${user.accessToken}`)
      .expect(200);
    expect(trashRes2.body.data).toHaveLength(0);
  });

  it('should only delete items trashed before the operation started (bounded by startTime)', async () => {
    // Create an item and soft-delete it by setting deletedAt directly
    const pastDate = new Date(Date.now() - 60_000);
    await VaultItem.create({
      userId: user.id,
      ...sampleVaultItem(),
      deletedAt: pastDate,
    });

    // Create another item with a far-future deletedAt to simulate an item
    // trashed concurrently after the operation's startTime snapshot.
    // The bounded deleteMany uses $lte: startTime, so this item should survive.
    const futureDate = new Date(Date.now() + 60 * 60 * 1000);
    await VaultItem.create({
      userId: user.id,
      ...sampleVaultItem(),
      deletedAt: futureDate,
    });

    // Empty trash
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const emptyRes = await withCsrf(
      agent.delete(`${API}/vault/items/trash/empty`),
      csrf,
      user.accessToken,
    ).expect(200);

    // Only the past-dated item should be deleted
    expect(emptyRes.body.data.deletedCount).toBe(1);

    // The future-dated item should still exist
    const remaining = await VaultItem.countDocuments({ userId: user.id });
    expect(remaining).toBe(1);
  });

  it('should return zero when trash is already empty', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const emptyRes = await withCsrf(
      agent.delete(`${API}/vault/items/trash/empty`),
      csrf,
      user.accessToken,
    ).expect(200);

    expect(emptyRes.body.success).toBe(true);
    expect(emptyRes.body.data.deletedCount).toBe(0);
  });

  it('should not delete active (non-trashed) items', async () => {
    // Create an active item (no deletedAt)
    const agent1 = request.agent(app);
    const csrf1 = await getCsrf(agent1);
    await withCsrf(agent1.post(`${API}/vault/items`), csrf1, user.accessToken)
      .send(sampleVaultItem())
      .expect(201);

    // Create a trashed item
    await VaultItem.create({
      userId: user.id,
      ...sampleVaultItem(),
      deletedAt: new Date(Date.now() - 1000),
    });

    // Empty trash
    const agent2 = request.agent(app);
    const csrf2 = await getCsrf(agent2);
    const emptyRes = await withCsrf(
      agent2.delete(`${API}/vault/items/trash/empty`),
      csrf2,
      user.accessToken,
    ).expect(200);

    expect(emptyRes.body.data.deletedCount).toBe(1);

    // Active item should still exist
    const remaining = await VaultItem.countDocuments({
      userId: user.id,
      deletedAt: { $exists: false },
    });
    expect(remaining).toBe(1);
  });
});
