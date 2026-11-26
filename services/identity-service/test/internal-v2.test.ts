import assert from 'node:assert/strict';
import test from 'node:test';
import { Types } from 'mongoose';
import { generateNonce, signRequest, type KeyEntry } from '@pichu/internal-auth';
import type { NonceStore } from '@pichu/internal-auth-adapters/types';
import { createApp } from '../src/app.js';
import { JwtService } from '../src/security/jwt.js';

const userId = new Types.ObjectId().toHexString();
const sessionId = new Types.ObjectId().toHexString();
const jwt = new JwtService({
  secret: 'test-secret-with-at-least-32-bytes-long',
  issuer: 'pichu-test',
  audience: 'pichu-api',
  accessTokenTtlSeconds: 900,
});

function store(): NonceStore {
  const seen = new Set<string>();
  return {
    assertReady: async () => undefined,
    reserve: async ({ nonce }) => (seen.has(nonce) ? 'replay' : (seen.add(nonce), 'reserved')),
  };
}

function key(sender: 'vehicle-service' | 'device-service'): KeyEntry {
  return {
    environment: 'test',
    sender,
    audience: 'identity-service',
    keyId: `${sender}-test`,
    secret: Buffer.alloc(32, sender === 'vehicle-service' ? 1 : 2),
    notBefore: 1,
    notAfter: 9_000_000_000_000,
    state: 'active',
  };
}

async function signed(path: string, entry: KeyEntry, tokenUserId = userId) {
  const now = Date.now();
  const headers = {
    'x-internal-auth-version': '2' as const,
    'x-service-name': entry.sender,
    'x-service-audience': 'identity-service' as const,
    'x-service-key-id': entry.keyId,
    'x-contract-version': 'v1' as const,
    'x-timestamp': String(now),
    'x-nonce': generateNonce(),
    'x-request-id': `request-${entry.sender}`,
    'x-internal-deadline': String(now + 2000),
    authorization: `Bearer ${await jwt.createAccessToken(tokenUserId, sessionId)}`,
  };
  return {
    ...headers,
    'x-signature': signRequest(
      {
        environment: 'test',
        sender: entry.sender,
        audience: 'identity-service',
        keyring: [entry],
        now,
      },
      headers,
      { method: 'GET', target: path, body: Buffer.alloc(0) },
    ),
  };
}

function appFor(entries: readonly KeyEntry[], nonces: NonceStore = store()) {
  return createApp({
    jwtService: jwt,
    sessionService: { isSessionActive: async () => true } as never,
    userProfileService: { isEmailVerified: async () => true } as never,
    internalAuth: { environment: 'test', keyring: entries, nonces },
  });
}

test('Identity v2 denies missing/invalid HMAC, wrong operation, wrong actor, and replay', async (t) => {
  const entry = key('vehicle-service');
  const app = appFor([entry]);
  t.after(() => app.close());
  const path = `/internal/users/${userId}/verified`;
  assert.equal((await app.inject({ method: 'GET', url: path })).statusCode, 401);
  const valid = await signed(path, entry);
  const tampered = { ...valid, 'x-signature': 'A'.repeat(43) };
  assert.equal((await app.inject({ method: 'GET', url: path, headers: tampered })).statusCode, 401);
  const wrongActor = await signed(path, entry, new Types.ObjectId().toHexString());
  assert.equal(
    (await app.inject({ method: 'GET', url: path, headers: wrongActor })).statusCode,
    403,
  );
  const denied = await signed('/internal/users/' + userId + '/unknown', entry);
  assert.equal(
    (
      await app.inject({
        method: 'GET',
        url: '/internal/users/' + userId + '/unknown',
        headers: denied,
      })
    ).statusCode,
    404,
  );
  const first = await app.inject({ method: 'GET', url: path, headers: valid });
  const second = await app.inject({ method: 'GET', url: path, headers: valid });
  assert.equal(first.statusCode, 200);
  assert.equal(second.statusCode, 401);
});

test('Identity v2 permits Device only on verified lookup and keeps public routes outside the scope', async (t) => {
  const entry = key('device-service');
  const app = appFor([entry]);
  t.after(() => app.close());
  const path = `/internal/users/${userId}/verified`;
  const response = await app.inject({
    method: 'GET',
    url: path,
    headers: await signed(path, entry),
  });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { verified: true });
  const publicResponse = await app.inject({ method: 'GET', url: '/auth/me' });
  assert.equal(publicResponse.statusCode, 404);
});
