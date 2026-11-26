import assert from 'node:assert/strict';
import test from 'node:test';
import { loadEnv, parseInternalKeyring } from '../src/config/env.js';

function makeKeyringJson(environment: 'development' | 'test' | 'staging' | 'production') {
  return JSON.stringify([
    {
      environment,
      sender: 'api-gateway',
      audience: 'vehicle-service',
      keyId: 'gw-veh-01',
      secretBase64Url: Buffer.alloc(32, 11).toString('base64url'),
      notBefore: 1,
      notAfter: 8_000_000_000_000_000,
      state: 'active',
    },
    {
      environment,
      sender: 'vehicle-service',
      audience: 'identity-service',
      keyId: 'veh-id-01',
      secretBase64Url: Buffer.alloc(32, 12).toString('base64url'),
      notBefore: 1,
      notAfter: 8_000_000_000_000_000,
      state: 'active',
    },
    {
      environment,
      sender: 'vehicle-service',
      audience: 'device-service',
      keyId: 'veh-dev-01',
      secretBase64Url: Buffer.alloc(32, 13).toString('base64url'),
      notBefore: 1,
      notAfter: 8_000_000_000_000_000,
      state: 'active',
    },
  ]);
}

test('loadEnv accepts vehicle_db in development without hardcoding MongoDB usernames', () => {
  const env = loadEnv({
    NODE_ENV: 'development',
    DATABASE_URL:
      'mongodb://custom_ephemeral_user:secret@127.0.0.1:27018/vehicle_db?authSource=vehicle_db&directConnection=true',
    INTERNAL_AUTH_ENVIRONMENT: 'development',
    INTERNAL_AUTH_KEYRING_JSON: makeKeyringJson('development'),
  });

  assert.equal(env.PORT, 3002);
  assert.equal(env.INVITATION_TTL_SECONDS, 7 * 86_400);
  const keyring = parseInternalKeyring(env);
  assert.equal(keyring.length, 3);
});

test('loadEnv permits isolated test databases in test mode and blocks cross-service databases everywhere', () => {
  for (const allowedTestUri of [
    'mongodb://127.0.0.1:27018/vehicle_test_db?directConnection=true',
    'mongodb://ephemeral_123:pw@127.0.0.1:27018/vehicle_db?authSource=vehicle_db',
    'mongodb://127.0.0.1:27017/vehicle_iso_99',
    'mongodb://127.0.0.1:27017/test',
    'mongodb://127.0.0.1:27017/?replicaSet=pichu_test&directConnection=true',
  ]) {
    const parsed = loadEnv({
      NODE_ENV: 'test',
      DATABASE_URL: allowedTestUri,
      INTERNAL_AUTH_ENVIRONMENT: 'test',
      INTERNAL_AUTH_KEYRING_JSON: makeKeyringJson('test'),
    });
    assert.equal(parsed.DATABASE_URL, allowedTestUri);
  }

  for (const forbiddenUri of [
    'mongodb://u:p@127.0.0.1:27018/identity_db',
    'mongodb://u:p@127.0.0.1:27018/device_db',
    'mongodb://u:p@127.0.0.1:27018/automation_db',
    'mongodb://u:p@127.0.0.1:27018/admin',
    'mongodb://u:p@127.0.0.1:27018/vehicle_db?dbName=identity_db',
    'postgres://u:p@127.0.0.1:5432/vehicle_db',
  ]) {
    assert.throws(
      () =>
        loadEnv({
          NODE_ENV: 'test',
          DATABASE_URL: forbiddenUri,
          INTERNAL_AUTH_ENVIRONMENT: 'test',
          INTERNAL_AUTH_KEYRING_JSON: makeKeyringJson('test'),
        }),
      undefined,
      `Expected ${forbiddenUri} to be rejected`,
    );
  }

  // Outside test mode, non-vehicle_db targets must be rejected.
  assert.throws(() =>
    loadEnv({
      NODE_ENV: 'development',
      DATABASE_URL: 'mongodb://u:p@127.0.0.1:27018/vehicle_test_db',
      INTERNAL_AUTH_ENVIRONMENT: 'development',
      INTERNAL_AUTH_KEYRING_JSON: makeKeyringJson('development'),
    }),
  );
});

test('production enforces HTTPS internal URLs, TLS paths, MongoDB credentials, and environment parity', () => {
  const validProd = {
    NODE_ENV: 'production',
    DATABASE_URL: 'mongodb+srv://atlas_vehicle_role:strong_pw@cluster.example.net/vehicle_db',
    IDENTITY_SERVICE_URL: 'https://pichu-identity.internal:3001',
    DEVICE_SERVICE_URL: 'https://pichu-device.internal:3003',
    INTERNAL_AUTH_ENVIRONMENT: 'production',
    INTERNAL_AUTH_KEYRING_JSON: makeKeyringJson('production'),
    TLS_CERT_PATH: '/etc/secrets/vehicle-cert.pem',
    TLS_KEY_PATH: '/etc/secrets/vehicle-key.pem',
    TLS_CA_PATH: '/etc/secrets/pichu-ca.pem',
  };

  assert.equal(loadEnv(validProd).NODE_ENV, 'production');

  // Reject HTTP internal URLs in production
  assert.throws(() =>
    loadEnv({ ...validProd, IDENTITY_SERVICE_URL: 'http://pichu-identity.internal:3001' }),
  );
  assert.throws(() =>
    loadEnv({ ...validProd, DEVICE_SERVICE_URL: 'http://pichu-device.internal:3003' }),
  );

  // Reject unauthenticated MongoDB URI in production
  assert.throws(() =>
    loadEnv({ ...validProd, DATABASE_URL: 'mongodb://mongo.internal:27017/vehicle_db' }),
  );

  // Reject missing TLS files in production
  assert.throws(() => loadEnv({ ...validProd, TLS_CA_PATH: undefined }));

  // Reject non-production internal auth environment in production
  assert.throws(() =>
    loadEnv({
      ...validProd,
      INTERNAL_AUTH_ENVIRONMENT: 'staging',
      INTERNAL_AUTH_KEYRING_JSON: makeKeyringJson('staging'),
    }),
  );
});

test('parseInternalKeyring rejects cross-environment entries and malformed secrets', () => {
  const env = loadEnv({
    NODE_ENV: 'development',
    DATABASE_URL: 'mongodb://u:p@127.0.0.1:27018/vehicle_db',
    INTERNAL_AUTH_ENVIRONMENT: 'development',
    INTERNAL_AUTH_KEYRING_JSON: makeKeyringJson('test'),
  });

  assert.throws(() => parseInternalKeyring(env), /Invalid internal authentication configuration/);

  const badSecretEnv = loadEnv({
    NODE_ENV: 'development',
    DATABASE_URL: 'mongodb://u:p@127.0.0.1:27018/vehicle_db',
    INTERNAL_AUTH_ENVIRONMENT: 'development',
    INTERNAL_AUTH_KEYRING_JSON: JSON.stringify([
      {
        environment: 'development',
        sender: 'api-gateway',
        audience: 'vehicle-service',
        keyId: 'k1',
        secretBase64Url: 'not-32-bytes',
        notBefore: 1,
        notAfter: 9999999999999,
        state: 'active',
      },
    ]),
  });
  assert.throws(
    () => parseInternalKeyring(badSecretEnv),
    /Invalid internal authentication configuration/,
  );
});
