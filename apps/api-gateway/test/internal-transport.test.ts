import assert from 'node:assert/strict';
import test from 'node:test';
import { CONTRACTS_VERSION, internalRequestHeadersV2Schema } from '@pichu/contracts';
import { createApp } from '../src/app.js';
import { GatewayConfigError, loadGatewayEnv } from '../src/config/env.js';
import { testInternalAuthEnv } from './test-env.js';

test('internal transport emits the shared header contract and retains signed requests', async () => {
  const env = loadGatewayEnv({
    ...testInternalAuthEnv,
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
    assert.equal(internalRequestHeadersV2Schema.safeParse(headers).success, true);
    assert.equal(headers['x-internal-auth-version'], '2');
    assert.equal(headers['x-contract-version'], CONTRACTS_VERSION);
    assert.equal(typeof headers['x-signature'], 'string');
    assert.equal(headers['x-service-audience'], 'vehicle-service');
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
