import assert from 'node:assert/strict';
import test from 'node:test';
import { createApp } from '../src/app.js';
import { PasswordRecoveryServiceError } from '../src/services/password-recovery.service.js';

function createRecoveryApp(
  overrides: {
    requestRecovery?: (email: string) => Promise<{ accepted: true }>;
    confirmRecovery?: (token: string, password: string) => Promise<boolean>;
  } = {},
) {
  const service = {
    requestRecovery: overrides.requestRecovery ?? (async () => ({ accepted: true as const })),
    confirmRecovery: overrides.confirmRecovery ?? (async () => true),
  };
  return createApp({ passwordRecoveryService: service as never });
}

test('password reset request returns generic 202 for known and unknown emails', async (context) => {
  const app = createRecoveryApp();
  context.after(async () => app.close());

  const known = await app.inject({
    method: 'POST',
    url: '/auth/password-reset/request',
    payload: { email: 'ada@example.com' },
  });
  const unknown = await app.inject({
    method: 'POST',
    url: '/auth/password-reset/request',
    payload: { email: 'unknown@example.com' },
  });

  assert.equal(known.statusCode, 202);
  assert.deepEqual(known.json(), { accepted: true });
  assert.equal(unknown.statusCode, 202);
  assert.deepEqual(unknown.json(), { accepted: true });
});

test('password reset request validates email and applies the IP rate limit', async (context) => {
  const app = createRecoveryApp();
  context.after(async () => app.close());

  const invalid = await app.inject({
    method: 'POST',
    url: '/auth/password-reset/request',
    payload: { email: 'not-an-email' },
  });
  assert.equal(invalid.statusCode, 400);

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/password-reset/request',
      remoteAddress: '192.0.2.10',
      payload: { email: 'ada@example.com' },
    });
    assert.equal(response.statusCode, 202);
  }
  const limited = await app.inject({
    method: 'POST',
    url: '/auth/password-reset/request',
    remoteAddress: '192.0.2.10',
    payload: { email: 'ada@example.com' },
  });
  assert.equal(limited.statusCode, 429);
  assert.match(String(limited.headers['retry-after']), /^\d+$/);
});

test('password reset confirmation handles success, invalid tokens and operational failures generically', async (context) => {
  const app = createRecoveryApp({
    confirmRecovery: async (token) => token !== 'b'.repeat(64),
  });
  context.after(async () => app.close());

  const success = await app.inject({
    method: 'POST',
    url: '/auth/password-reset/confirm',
    payload: { token: 'a'.repeat(64), password: 'new secure password' },
  });
  const invalid = await app.inject({
    method: 'POST',
    url: '/auth/password-reset/confirm',
    payload: { token: 'b'.repeat(64), password: 'new secure password' },
  });
  const malformed = await app.inject({
    method: 'POST',
    url: '/auth/password-reset/confirm',
    payload: { token: 'bad', password: 'short' },
  });

  assert.equal(success.statusCode, 200);
  assert.deepEqual(success.json(), { reset: true });
  assert.equal(invalid.statusCode, 400);
  assert.deepEqual(invalid.json(), { message: 'Invalid or expired password reset token' });
  assert.equal(malformed.statusCode, 400);

  await app.close();
  const failingApp = createRecoveryApp({
    requestRecovery: async () => {
      throw new PasswordRecoveryServiceError('internal details');
    },
    confirmRecovery: async () => {
      throw new PasswordRecoveryServiceError('internal details');
    },
  });
  context.after(async () => failingApp.close());
  const requestFailure = await failingApp.inject({
    method: 'POST',
    url: '/auth/password-reset/request',
    payload: { email: 'ada@example.com' },
  });
  const confirmFailure = await failingApp.inject({
    method: 'POST',
    url: '/auth/password-reset/confirm',
    payload: { token: 'a'.repeat(64), password: 'new secure password' },
  });
  assert.equal(requestFailure.statusCode, 503);
  assert.equal(confirmFailure.statusCode, 503);
  assert.equal(requestFailure.body.includes('internal details'), false);
  assert.equal(confirmFailure.body.includes('internal details'), false);
});
