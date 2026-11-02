import assert from 'node:assert/strict';
import test from 'node:test';
import { parseEnvironment } from '../src/config/env.js';

const validEnvironment = {
  HOST: '0.0.0.0',
  PORT: '3001',
  DOCUMENTATION_URL: 'http://localhost:3001/docs',
  RESEND_API_KEY: 're_test_key',
  RESEND_FROM_EMAIL: 'no-reply@example.com',
  RESEND_FROM_NAME: 'PICHU',
  EMAIL_VERIFICATION_URL: 'http://localhost:3000/verify-email',
  EMAIL_VERIFICATION_TOKEN_TTL_SECONDS: '86400',
  NODE_ENV: 'test',
  DATABASE_URL: 'mongodb://identity_user:local-password@localhost:27018/identity_db?authSource=identity_db',
};

test('parses valid service environment variables', () => {
  assert.deepEqual(parseEnvironment(validEnvironment), {
    ...validEnvironment,
    PORT: 3001,
    EMAIL_VERIFICATION_TOKEN_TTL_SECONDS: 86400,
  });
});

test('rejects invalid or missing environment variables', () => {
  assert.throws(() => parseEnvironment({ ...validEnvironment, PORT: '70000' }));
  assert.throws(() => parseEnvironment({ ...validEnvironment, NODE_ENV: 'local' }));
  assert.throws(() => parseEnvironment({ ...validEnvironment, DATABASE_URL: undefined }));
});

test('rejects database URLs for a different account or database', () => {
  assert.throws(() =>
    parseEnvironment({
      ...validEnvironment,
      DATABASE_URL: 'mongodb://admin:secret@localhost:27018/admin?authSource=admin',
    }),
  );
});

test('allows HTTPS verification URLs in every environment', () => {
  for (const nodeEnv of ['development', 'test', 'production'] as const) {
    assert.doesNotThrow(() =>
      parseEnvironment({
        ...validEnvironment,
        NODE_ENV: nodeEnv,
        EMAIL_VERIFICATION_URL: 'https://accounts.example.test/verify',
      }),
    );
  }
});

test('allows HTTP verification URLs only for localhost outside production', () => {
  assert.doesNotThrow(() => parseEnvironment(validEnvironment));
  assert.doesNotThrow(() =>
    parseEnvironment({
      ...validEnvironment,
      EMAIL_VERIFICATION_URL: 'http://127.0.0.1:3000/verify',
    }),
  );
  assert.doesNotThrow(() =>
    parseEnvironment({
      ...validEnvironment,
      EMAIL_VERIFICATION_URL: 'http://[::1]:3000/verify-email',
    }),
  );
  assert.throws(() =>
    parseEnvironment({
      ...validEnvironment,
      NODE_ENV: 'production',
    }),
  );
  assert.throws(() =>
    parseEnvironment({
      ...validEnvironment,
      EMAIL_VERIFICATION_URL: 'http://accounts.example.test/verify',
    }),
  );
  assert.throws(() =>
    parseEnvironment({
      ...validEnvironment,
      NODE_ENV: 'production',
      EMAIL_VERIFICATION_URL: 'http://[::1]:3000/verify-email',
    }),
  );
});

test('rejects unsupported verification URL protocols', () => {
  assert.throws(() =>
    parseEnvironment({
      ...validEnvironment,
      EMAIL_VERIFICATION_URL: 'ftp://localhost/verify',
    }),
  );
});
