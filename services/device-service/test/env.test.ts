import assert from 'node:assert/strict';
import test from 'node:test';
import { loadEnv, parseInternalKeyring } from '../src/config/env.js';

const keyringEntry = (environment: string) => ({
  environment,
  sender: 'device-service',
  audience: 'identity-service',
  keyId: 'device-identity',
  secretBase64Url: Buffer.alloc(32, 3).toString('base64url'),
  notBefore: 1,
  notAfter: 8_000_000_000_000,
  state: 'active',
});

const base = {
  NODE_ENV: 'development',
  INTERNAL_AUTH_ENVIRONMENT: 'development',
  DATABASE_URL: 'mongodb://device_user:secret@localhost:27018/device_db?authSource=device_db',
  INTERNAL_AUTH_KEYRING_JSON: JSON.stringify([keyringEntry('development')]),
};

const production = {
  ...base,
  NODE_ENV: 'production',
  INTERNAL_AUTH_ENVIRONMENT: 'production',
  IDENTITY_SERVICE_URL: 'https://identity.internal:3001',
  INTERNAL_AUTH_KEYRING_JSON: JSON.stringify([keyringEntry('production')]),
  TLS_CERT_PATH: 'cert.pem',
  TLS_KEY_PATH: 'key.pem',
  TLS_CA_PATH: 'ca.pem',
};

test('accepts device_db configuration and an environment-consistent keyring', () => {
  const env = loadEnv(base);
  assert.equal(env.PORT, 3003);
  assert.equal(parseInternalKeyring(env).length, 1);
  assert.doesNotThrow(() => loadEnv(production));
});

test('rejects databases of other services, administrative databases and non-Mongo URLs', () => {
  for (const DATABASE_URL of [
    'mongodb://localhost:27018/vehicle_db',
    'mongodb://localhost:27018/identity_db',
    'mongodb://localhost:27018/automation_db',
    'mongodb://localhost:27018/admin',
    'mongodb://localhost:27018/device_db?dbName=vehicle_db',
    'mongodb://localhost:27018/other_db',
    'https://localhost/device_db',
    'not a url',
  ]) {
    assert.throws(() => loadEnv({ ...base, DATABASE_URL }), `${DATABASE_URL} must be rejected`);
  }
});

test('explicit test mode allows only isolated device databases', () => {
  const testEnv = { ...base, NODE_ENV: 'test' };
  for (const name of ['device_db', 'device_test_db', 'test', 'device_tkt014_abc']) {
    assert.doesNotThrow(() =>
      loadEnv({ ...testEnv, DATABASE_URL: `mongodb://localhost:27018/${name}` }),
    );
  }
  assert.throws(() =>
    loadEnv({ ...testEnv, DATABASE_URL: 'mongodb://localhost:27018/gateway_device_x' }),
  );
});

test('production requires credentials, HTTPS identity, production auth environment and TLS', () => {
  assert.throws(() =>
    loadEnv({ ...production, DATABASE_URL: 'mongodb://localhost:27018/device_db' }),
  );
  assert.throws(() => loadEnv({ ...production, IDENTITY_SERVICE_URL: 'http://identity:3001' }));
  assert.throws(() => loadEnv({ ...production, INTERNAL_AUTH_ENVIRONMENT: 'test' }));
  assert.throws(() => loadEnv({ ...production, TLS_CA_PATH: undefined }));
});

test('rejects malformed or environment-mismatched keyrings without exposing secrets', () => {
  const mismatched = loadEnv({
    ...base,
    INTERNAL_AUTH_KEYRING_JSON: JSON.stringify([keyringEntry('production')]),
  });
  assert.throws(
    () => parseInternalKeyring(mismatched),
    /^Error: Invalid internal authentication configuration$/,
  );
  for (const json of [
    '{"broken"',
    JSON.stringify([{ ...keyringEntry('development'), extra: 1 }]),
  ]) {
    const env = loadEnv({ ...base, INTERNAL_AUTH_KEYRING_JSON: json });
    assert.throws(
      () => parseInternalKeyring(env),
      (error: unknown) =>
        error instanceof Error && error.message === 'Invalid internal authentication configuration',
    );
  }
});
