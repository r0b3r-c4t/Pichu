import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { signRequest, type KeyEntry } from '@pichu/internal-auth';
import type { InternalUnsignedHeadersV2 } from '@pichu/contracts';
import { isEd25519PublicKey } from '../src/app.js';

test('Ed25519 signs and verifies a challenge', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const challenge = Buffer.from('pichu-device-challenge');
  const signature = sign(null, challenge, privateKey);
  assert.equal(publicKey.asymmetricKeyType, 'ed25519');
  assert.equal(publicKey.asymmetricKeyType, 'ed25519');
  assert.equal(signature.length > 0, true);
  assert.equal(
    isEd25519PublicKey(publicKey.export({ type: 'spki', format: 'pem' }).toString()),
    true,
  );
  assert.equal(isEd25519PublicKey('not-a-public-key'), false);
});

test('pichu-s2s-v2 signature is deterministic and key-bound', () => {
  const key: KeyEntry = {
    environment: 'test',
    sender: 'vehicle-service',
    audience: 'device-service',
    keyId: 'k',
    secret: Buffer.alloc(32, 1),
    state: 'active',
    notBefore: 1,
    notAfter: 8000000000000000,
  };
  const headers: InternalUnsignedHeadersV2 = {
    'x-internal-auth-version': '2',
    'x-service-name': 'vehicle-service',
    'x-service-audience': 'device-service',
    'x-service-key-id': 'k',
    'x-contract-version': 'v1',
    'x-timestamp': '1000',
    'x-nonce': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    'x-request-id': 'req-1',
    'x-internal-deadline': '5000',
    'content-type': 'application/json',
  };
  const body = Buffer.from('{"device":"x"}');
  const first = signRequest({ ...key, keyring: [key], now: 1000 }, headers, {
    method: 'POST',
    target: '/internal/devices/register',
    body,
  });
  assert.equal(
    first,
    signRequest({ ...key, keyring: [key], now: 1000 }, headers, {
      method: 'POST',
      target: '/internal/devices/register',
      body,
    }),
  );
  const otherKey = { ...key, secret: Buffer.alloc(32, 2) };
  assert.notEqual(
    first,
    signRequest({ ...otherKey, keyring: [otherKey], now: 1000 }, headers, {
      method: 'POST',
      target: '/internal/devices/register',
      body,
    }),
  );
});

test('Mongo replay store integration is enabled when TEST_DATABASE_URL is configured', async (t) => {
  const url = process.env.TEST_DATABASE_URL;
  if (!url) {
    t.skip('TEST_DATABASE_URL is not configured');
    return;
  }
  const mongoose = await import('mongoose');
  const { InternalRequestModel } = await import('../src/models/internal-request.model.js');
  await mongoose.default.connect(url);
  try {
    const key = `test-${Date.now()}`;
    await InternalRequestModel.create({ key, expiresAt: new Date(Date.now() + 60_000) });
    await assert.rejects(() =>
      InternalRequestModel.create({ key, expiresAt: new Date(Date.now() + 60_000) }),
    );
  } finally {
    await mongoose.default.disconnect();
  }
});
