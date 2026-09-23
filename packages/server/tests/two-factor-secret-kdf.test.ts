/**
 * How 2FA secrets are sealed at rest, and what enrolment does with the sealed
 * copy.
 *
 * The shared `cryptoManager` is the synchronous PBKDF2 path of
 * `@hiprax/crypto`, and its derivation runs on the event loop. Its write-side
 * iteration count is therefore a latency figure for every enrolment and every
 * 2FA sign-in, not only a security one, and it is set explicitly rather than
 * inherited from the library's password-grade default. What must NOT move with
 * it is the ability to read what earlier releases wrote: a v1 ciphertext
 * decrypts at the count in its own header, and the pre-1.0 v0 golden in
 * `crypto-manager.test.ts` decrypts at the legacy count, unchanged.
 *
 * Enrolment used to decrypt the pending secret, check the code, and then seal
 * the same plaintext again for permanent storage: a second full derivation for
 * a value it already held sealed. It now moves the pending ciphertext across
 * verbatim, which is what the byte-equality assertions below pin.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import { TOTP, Secret } from 'otpauth';
import { base64urlToBytes, KDF_ID_PBKDF2_SHA256, parseHeader } from '@hiprax/crypto';

import { BACKUP_CODES_COUNT } from '@hvault/shared';

import app from '../src/app.js';
import { User } from '../src/models/User.js';
import {
  cryptoManager,
  TWO_FACTOR_SECRET_PBKDF2_ITERATIONS,
  ValidationBypassCryptoManager,
} from '../src/utils/cryptoManager.js';
import { twoFactorEncryptionKey } from '../src/config/index.js';
import { createTestUser, authHeader, getCsrf, type CsrfPair, type TestUser } from './helpers.js';

const API = '/api/v1';
const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

/** The library's own default, i.e. what every secret stored before this change carries. */
const PREVIOUS_ITERATIONS = 600_000;

function headerOf(ciphertext: string) {
  return parseHeader(Buffer.from(base64urlToBytes(ciphertext)));
}

function totpFor(secret: string): TOTP {
  return new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret: Secret.fromBase32(secret) });
}

function withCsrf(req: request.Test, csrf: CsrfPair): request.Test {
  return req.set('x-csrf-token', csrf.token).set('Cookie', csrf.cookie);
}

describe('the 2FA-secret cipher', () => {
  it('seals with PBKDF2-SHA256 at TWO_FACTOR_SECRET_PBKDF2_ITERATIONS, far below the password-grade default', () => {
    const header = headerOf(cryptoManager.encryptTextSync(SECRET, twoFactorEncryptionKey));

    // The sync v1 lineage, never the Argon2id one the async family writes: the
    // two cannot read each other, so a swap would strand every stored secret.
    expect(header.kdfId).toBe(KDF_ID_PBKDF2_SHA256);
    expect(header.params).toEqual({
      kind: 'pbkdf2-sha256',
      iterations: TWO_FACTOR_SECRET_PBKDF2_ITERATIONS,
    });
    expect(TWO_FACTOR_SECRET_PBKDF2_ITERATIONS).toBe(10_000);
  });

  it('still decrypts a secret sealed at the previous 600,000-iteration default', () => {
    // Produced exactly as every release before this one produced it: the same
    // subclass, constructed with no options.
    const stored = new ValidationBypassCryptoManager().encryptTextSync(
      SECRET,
      twoFactorEncryptionKey,
    );
    expect(headerOf(stored).params).toEqual({
      kind: 'pbkdf2-sha256',
      iterations: PREVIOUS_ITERATIONS,
    });

    expect(cryptoManager.decryptTextSync(stored, twoFactorEncryptionKey)).toBe(SECRET);
  });

  it('refuses a stored secret under the wrong key, whatever count it was sealed at', () => {
    const lowered = cryptoManager.encryptTextSync(SECRET, twoFactorEncryptionKey);
    const previous = new ValidationBypassCryptoManager().encryptTextSync(
      SECRET,
      twoFactorEncryptionKey,
    );
    const wrongKey = `${twoFactorEncryptionKey}-rotated`;

    for (const stored of [lowered, previous]) {
      expect(() => cryptoManager.decryptTextSync(stored, wrongKey)).toThrow(
        expect.objectContaining({ type: 'DECRYPTION_FAILED' }),
      );
    }
  });
});

describe('POST /user/2fa/verify moves the pending ciphertext, it does not re-seal it', () => {
  let agent: request.Agent;
  let csrf: CsrfPair;
  let user: TestUser;

  beforeEach(async () => {
    agent = request.agent(app);
    csrf = await getCsrf(agent);
    user = await createTestUser();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  async function readSecrets() {
    const doc = await User.findById(user.id)
      .select('+twoFactorSecret +pendingTwoFactorSecret +pendingTwoFactorExpiry')
      .lean();
    expect(doc).not.toBeNull();
    return doc!;
  }

  function verify(code: string) {
    return withCsrf(
      agent
        .post(`${API}/user/2fa/verify`)
        .set('Authorization', authHeader(user.accessToken))
        .send({ code }),
      csrf,
    );
  }

  it('enrols with the exact bytes setup stored, sealing nothing a second time', async () => {
    const setup = await withCsrf(
      agent
        .post(`${API}/user/2fa/setup`)
        .set('Authorization', authHeader(user.accessToken))
        .send({ password: user.rawPassword }),
      csrf,
    );
    expect(setup.status).toBe(200);
    const shownSecret = setup.body.data.secret as string;

    const pending = (await readSecrets()).pendingTwoFactorSecret as string;
    expect(headerOf(pending).params).toEqual({
      kind: 'pbkdf2-sha256',
      iterations: TWO_FACTOR_SECRET_PBKDF2_ITERATIONS,
    });

    const encrypt = vi.spyOn(cryptoManager, 'encryptTextSync');
    const decrypt = vi.spyOn(cryptoManager, 'decryptTextSync');

    const res = await verify(totpFor(shownSecret).generate());
    expect(res.status).toBe(200);
    expect(res.body.data.backupCodes).toHaveLength(BACKUP_CODES_COUNT);

    const after = await readSecrets();
    expect(after.twoFactorEnabled).toBe(true);
    expect(after.twoFactorSecret).toBe(pending);
    expect(after.pendingTwoFactorSecret).toBeUndefined();
    expect(after.pendingTwoFactorExpiry).toBeUndefined();
    // One derivation to check the code, and none to store it.
    expect(decrypt).toHaveBeenCalledTimes(1);
    expect(encrypt).not.toHaveBeenCalled();
    expect(cryptoManager.decryptTextSync(after.twoFactorSecret!, twoFactorEncryptionKey)).toBe(
      shownSecret,
    );
  });

  it('carries a pending secret sealed at the previous count across unchanged, still readable', async () => {
    // A setup started before the upgrade and confirmed after it.
    const secret = new Secret().base32;
    const pending = new ValidationBypassCryptoManager().encryptTextSync(
      secret,
      twoFactorEncryptionKey,
    );
    await User.findByIdAndUpdate(user.id, {
      $set: {
        pendingTwoFactorSecret: pending,
        pendingTwoFactorExpiry: new Date(Date.now() + 10 * 60 * 1000),
      },
    });

    const res = await verify(totpFor(secret).generate());
    expect(res.status).toBe(200);

    const after = await readSecrets();
    expect(after.twoFactorEnabled).toBe(true);
    expect(after.twoFactorSecret).toBe(pending);
    expect(headerOf(after.twoFactorSecret!).params).toEqual({
      kind: 'pbkdf2-sha256',
      iterations: PREVIOUS_ITERATIONS,
    });
    expect(cryptoManager.decryptTextSync(after.twoFactorSecret!, twoFactorEncryptionKey)).toBe(
      secret,
    );
  });

  it('leaves the pending secret in place and stores nothing when the code is wrong', async () => {
    // A fixed secret, and a wrong code chosen to differ from every code the
    // server could accept: `verify2fa` validates with a window of one step either
    // side, and the request may land one step after these are computed, so the
    // codes two steps either side of now are excluded as well.
    const pending = cryptoManager.encryptTextSync(SECRET, twoFactorEncryptionKey);
    await User.findByIdAndUpdate(user.id, {
      $set: {
        pendingTwoFactorSecret: pending,
        pendingTwoFactorExpiry: new Date(Date.now() + 10 * 60 * 1000),
      },
    });
    const now = Date.now();
    const acceptable = new Set(
      [-2, -1, 0, 1, 2].map((step) => totpFor(SECRET).generate({ timestamp: now + step * 30_000 })),
    );
    const wrong = ['000000', '111111', '222222', '333333', '444444', '555555'].find(
      (code) => !acceptable.has(code),
    )!;

    const res = await verify(wrong);
    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/invalid verification code/i);

    const after = await readSecrets();
    expect(after.twoFactorEnabled).toBe(false);
    expect(after.twoFactorSecret).toBeUndefined();
    expect(after.pendingTwoFactorSecret).toBe(pending);
  });
});
