import assert from 'node:assert/strict';
import { test } from 'node:test';
import { GatewayConfigError, loadGatewayEnv } from '../src/config/env.js';
import { testInternalAuthEnv } from './test-env.js';

const validEnvironment = {
  HOST: '127.0.0.1',
  PORT: '3000',
  NODE_ENV: 'test',
  ...testInternalAuthEnv,
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

test('gateway configuration validates the invitation issuance rate limits', () => {
  const defaults = loadGatewayEnv(validEnvironment);
  assert.equal(defaults.INVITATION_RATE_LIMIT_MAX, 10);
  assert.equal(defaults.INVITATION_RATE_LIMIT_WINDOW_SECONDS, 60);
  assert.equal(defaults.INVITATION_IP_RATE_LIMIT_MAX, 30);
  const custom = loadGatewayEnv({
    ...validEnvironment,
    INVITATION_RATE_LIMIT_MAX: '1000',
    INVITATION_RATE_LIMIT_WINDOW_SECONDS: '1',
    INVITATION_IP_RATE_LIMIT_MAX: '1',
  });
  assert.equal(custom.INVITATION_RATE_LIMIT_MAX, 1000);
  assert.equal(custom.INVITATION_RATE_LIMIT_WINDOW_SECONDS, 1);
  assert.equal(custom.INVITATION_IP_RATE_LIMIT_MAX, 1);
  for (const invalid of [
    { INVITATION_RATE_LIMIT_MAX: '0' },
    { INVITATION_RATE_LIMIT_MAX: '1001' },
    { INVITATION_RATE_LIMIT_MAX: '2.5' },
    { INVITATION_RATE_LIMIT_WINDOW_SECONDS: '0' },
    { INVITATION_RATE_LIMIT_WINDOW_SECONDS: '86401' },
    { INVITATION_IP_RATE_LIMIT_MAX: '0' },
    { INVITATION_IP_RATE_LIMIT_MAX: 'many' },
  ]) {
    assert.throws(
      () => loadGatewayEnv({ ...validEnvironment, ...invalid }),
      GatewayConfigError,
      JSON.stringify(invalid),
    );
  }
});

test('gateway configuration rejects unknown environment properties', () => {
  assert.throws(
    () => loadGatewayEnv({ ...validEnvironment, UNKNOWN_SETTING: 'unexpected' }),
    GatewayConfigError,
  );
});
