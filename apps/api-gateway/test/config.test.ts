import assert from 'node:assert/strict';
import { test } from 'node:test';
import { GatewayConfigError, loadGatewayEnv } from '../src/config/env.js';

const validEnvironment = {
  HOST: '127.0.0.1',
  PORT: '3000',
  NODE_ENV: 'test',
  INTERNAL_SERVICE_SECRET: 'i'.repeat(32),
  JWT_SECRET: 'j'.repeat(32),
  JWT_ISSUER: 'issuer',
  JWT_AUDIENCE: 'audience',
  VEHICLE_SERVICE_URL: 'http://127.0.0.1:3002',
  DEVICE_SERVICE_URL: 'http://127.0.0.1:3003',
  PROXY_TIMEOUT_MS: '5000',
};

test('gateway configuration parses valid values', () => {
  const result = loadGatewayEnv(validEnvironment);
  assert.equal(result.PORT, 3000);
  assert.equal(result.PROXY_TIMEOUT_MS, 5000);
});

test('gateway configuration rejects short secrets and invalid URLs', () => {
  assert.throws(
    () =>
      loadGatewayEnv({
        ...validEnvironment,
        JWT_SECRET: 'short',
        VEHICLE_SERVICE_URL: 'ftp://bad',
      }),
    GatewayConfigError,
  );
});

test('gateway configuration rejects unknown environment properties', () => {
  assert.throws(
    () => loadGatewayEnv({ ...validEnvironment, UNKNOWN_SETTING: 'unexpected' }),
    GatewayConfigError,
  );
});
