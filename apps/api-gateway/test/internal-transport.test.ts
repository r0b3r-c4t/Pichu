import assert from 'node:assert/strict';
import test from 'node:test';
import { CONTRACTS_VERSION, internalRequestHeadersSchema } from '@pichu/contracts';
import { createApp } from '../src/app.js';
import { GatewayConfigError, loadGatewayEnv } from '../src/config/env.js';
import { signInternalRequest } from '../src/security/internal-auth.js';

test('internal transport emits the shared header contract and retains signed requests', async () => {
  const env = loadGatewayEnv({
    INTERNAL_SERVICE_SECRET: 'i'.repeat(32),
    JWT_SECRET: 'j'.repeat(32),
    JWT_ISSUER: 'issuer',
    JWT_AUDIENCE: 'audience',
  });
  const app = createApp({ env });
  try {
    await app.ready();
    const body = { userId: '507f1f77bcf86cd799439011' };
    const createHeaders =
      app.getDecorator<(method: string, url: string, body: unknown) => Record<string, string>>(
        'createInternalHeaders',
      );
    const headers = createHeaders('POST', '/internal/vehicles', body);
    assert.equal(internalRequestHeadersSchema.safeParse(headers).success, true);
    assert.equal(headers['x-contract-version'], CONTRACTS_VERSION);
    const signature = (payload: unknown) =>
      signInternalRequest(
        env.INTERNAL_SERVICE_SECRET,
        'POST',
        '/internal/vehicles',
        payload,
        headers['x-timestamp']!,
        headers['x-request-id']!,
      );
    assert.equal(headers['x-signature'], signature(body));
    assert.notEqual(headers['x-signature'], signature({ ...body, extra: true }));
    assert.equal(
      internalRequestHeadersSchema.safeParse({ ...headers, 'x-signature': '' }).success,
      false,
    );
  } finally {
    await app.close();
  }
});

test('missing internal security configuration fails instead of enabling unsigned transport', () => {
  assert.throws(
    () =>
      loadGatewayEnv({
        JWT_SECRET: 'j'.repeat(32),
        JWT_ISSUER: 'issuer',
        JWT_AUDIENCE: 'audience',
      }),
    GatewayConfigError,
  );
});
