import assert from 'node:assert/strict';
import test from 'node:test';
import { createApp } from '../src/app.js';
import { RegistrationServiceError } from '../src/services/registration.service.js';
import { EmailVerificationServiceError } from '../src/services/email-verification.service.js';
import { PasswordRecoveryServiceError } from '../src/services/password-recovery.service.js';
import { LoginServiceError } from '../src/services/login.service.js';
import { assertApiError } from './error-assertion.js';

test('validation errors include safe field details and the forwarded request id', async (context) => {
  const app = createApp({
    registrationService: { register: async () => ({ accepted: true }) } as never,
  });
  context.after(async () => app.close());
  const response = await app.inject({
    method: 'POST',
    url: '/auth/register',
    headers: { 'x-request-id': 'gateway-request-123' },
    payload: { name: '', username: 'ada_01', email: 'invalid', password: 'short' },
  });

  assert.equal(response.statusCode, 400);
  const body = assertApiError(response, 'VALIDATION_ERROR', 'Invalid registration data');
  assert.equal(body.requestId, 'gateway-request-123');
  assert.deepEqual(
    body.details?.map(({ field }) => field),
    ['name', 'email', 'password'],
  );
  assert.equal(response.body.includes('short'), false);
});

test('login and refresh reject malformed input with field-level validation errors', async (context) => {
  const app = createApp({
    loginService: {
      login: async () => {
        throw new Error('unexpected login');
      },
    } as never,
    sessionService: { refreshTokenTtlSeconds: 3600 } as never,
    jwtService: {} as never,
    cookieOrigin: 'http://localhost:3000',
  });
  context.after(async () => app.close());
  const login = await app.inject({
    method: 'POST',
    url: '/auth/login',
    payload: { email: 'invalid', password: '' },
  });
  assert.equal(login.statusCode, 400);
  assert.deepEqual(
    assertApiError(login, 'VALIDATION_ERROR', 'Invalid login data').details?.map(
      ({ field }) => field,
    ),
    ['email', 'password'],
  );

  const refresh = await app.inject({
    method: 'POST',
    url: '/auth/refresh',
    payload: { refreshToken: 'invalid' },
  });
  assert.equal(refresh.statusCode, 400);
  assert.deepEqual(
    assertApiError(refresh, 'VALIDATION_ERROR', 'Invalid refresh token format').details,
    [{ field: 'body', message: 'Invalid value' }],
  );
});

test('invalid credentials stay generic and keep HTTP 401', async (context) => {
  const app = createApp({
    loginService: {
      login: async () => {
        throw new LoginServiceError();
      },
    } as never,
    sessionService: { refreshTokenTtlSeconds: 3600 } as never,
    jwtService: {} as never,
    cookieOrigin: 'http://localhost:3000',
  });
  context.after(async () => app.close());
  const response = await app.inject({
    method: 'POST',
    url: '/auth/login',
    headers: { origin: 'http://localhost:3000' },
    payload: { email: 'ada@example.com', password: 'incorrect-password' },
  });
  assert.equal(response.statusCode, 401);
  const error = assertApiError(response, 'INVALID_CREDENTIALS', 'Invalid credentials');
  assert.equal(error.details, undefined);
  assert.equal(response.body.includes('incorrect-password'), false);
});

test('malformed JSON and unknown routes use the same safe error envelope', async (context) => {
  const app = createApp();
  context.after(async () => app.close());
  const malformed = await app.inject({
    method: 'POST',
    url: '/internal/users/invalid/exists',
    headers: { 'content-type': 'application/json', 'x-request-id': 'bad id with spaces' },
    payload: '{',
  });
  assert.equal(malformed.statusCode, 400);
  const error = assertApiError(malformed, 'VALIDATION_ERROR', 'Invalid request');
  assert.deepEqual(error.details, [{ field: 'body', message: 'Invalid request body' }]);
  assert.notEqual(error.requestId, 'bad id with spaces');

  const unknown = await app.inject({ method: 'GET', url: '/missing?token=secret-token' });
  assert.equal(unknown.statusCode, 404);
  assertApiError(unknown, 'RESOURCE_NOT_FOUND', 'Resource not found');
  assert.equal(unknown.body.includes('secret-token'), false);
});

test('Fastify payload and content-type errors use the shared envelope', async (context) => {
  const app = createApp({
    registrationService: { register: async () => ({ accepted: true }) } as never,
  });
  context.after(async () => app.close());
  const oversized = await app.inject({
    method: 'POST',
    url: '/auth/register',
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify({ name: 'A'.repeat(1_100_000) }),
  });
  assert.equal(oversized.statusCode, 413);
  assertApiError(oversized, 'PAYLOAD_TOO_LARGE', 'Invalid request');

  const unsupported = await app.inject({
    method: 'POST',
    url: '/auth/register',
    headers: { 'content-type': 'application/xml' },
    payload: '<user />',
  });
  assert.equal(unsupported.statusCode, 415);
  assertApiError(unsupported, 'UNSUPPORTED_MEDIA_TYPE', 'Invalid request');
});

test('registration delivery failures remain indistinguishable from accepted accounts', async (context) => {
  const app = createApp({
    registrationService: {
      register: async () => {
        throw new RegistrationServiceError('Registration could not be completed', {
          stage: 'email.send',
          cause: new Error('secret api key and token'),
          providerCode: 'VALIDATION_ERROR',
        });
      },
    } as never,
  });
  context.after(async () => app.close());
  const response = await app.inject({
    method: 'POST',
    url: '/auth/register',
    payload: {
      name: 'Ada',
      username: 'ada_01',
      email: 'ada@example.com',
      password: 'correct horse battery staple',
    },
  });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { accepted: true });
  assert.equal(response.body.includes('secret api key'), false);
  assert.equal(response.body.includes('token'), false);
});

test('resend and recovery delivery failures preserve account-neutral success responses', async (context) => {
  const app = createApp({
    emailVerificationService: {
      resendVerification: async () => {
        throw new EmailVerificationServiceError({
          stage: 'email.send',
          cause: new Error('secret'),
        });
      },
    } as never,
    passwordRecoveryService: {
      requestRecovery: async () => {
        throw new PasswordRecoveryServiceError('email.send', new Error('secret'));
      },
    } as never,
  });
  context.after(async () => app.close());
  for (const url of ['/auth/verification/resend', '/auth/password-reset/request']) {
    const response = await app.inject({
      method: 'POST',
      url,
      payload: { email: 'ada@example.com' },
    });
    assert.equal(response.statusCode, 202);
    assert.deepEqual(response.json(), { accepted: true });
    assert.equal(response.body.includes('secret'), false);
  }
});

test('OpenAPI documents actual Identity paths, request fields and error envelopes', async (context) => {
  const app = createApp();
  context.after(async () => app.close());
  const response = await app.inject({ method: 'GET', url: '/docs/json' });
  assert.equal(response.statusCode, 200);
  const doc = response.json() as {
    paths: Record<
      string,
      Record<
        string,
        {
          responses: Record<
            string,
            { content?: Record<string, { schema: { properties?: Record<string, unknown> } }> }
          >;
          requestBody?: {
            content: Record<string, { schema: { properties?: Record<string, unknown> } }>;
          };
          security?: unknown;
        }
      >
    >;
  };
  assert.ok(
    doc.paths['/auth/register'].post.requestBody?.content['application/json'].schema.properties
      ?.email,
  );
  assert.ok(doc.paths['/sessions/{sessionId}'].delete.security);
  assert.ok(doc.paths['/auth/verification/resend'].post.responses['202']);
  assert.ok(
    doc.paths['/auth/verification/resend'].post.responses['503'].content?.['application/json']
      .schema.properties?.requestId,
  );
  assert.ok(doc.paths['/auth/login'].post.responses['401']);
  assert.ok(doc.paths['/auth/password-reset/confirm'].post.responses['400']);
  assert.equal(doc.paths['/auth/refresh'].post.requestBody, undefined);
  assert.deepEqual(doc.paths['/auth/refresh'].post.security, [{ refreshCookie: [] }]);
  assert.equal(
    JSON.stringify(doc.paths['/auth/login'].post).includes('x-refresh-token-transport'),
    false,
  );
  assert.ok(doc.paths['/auth/logout'].post.responses['403']);
  assert.equal(doc.paths['/auth/register'].post.responses['202'], undefined);
  assert.equal(
    doc.paths['/auth/register'].post.requestBody?.content['application/json'].schema.properties
      ?.password !== undefined,
    true,
  );
  const registerPasswordSchema = doc.paths['/auth/register'].post.requestBody?.content[
    'application/json'
  ].schema.properties?.password as { minLength?: number; maxLength?: number };
  const resetPasswordSchema = doc.paths['/auth/password-reset/confirm'].post.requestBody?.content[
    'application/json'
  ].schema.properties?.password as { minLength?: number; maxLength?: number };
  assert.equal(registerPasswordSchema.minLength, 8);
  assert.equal(registerPasswordSchema.maxLength, 256);
  assert.equal(resetPasswordSchema.minLength, 8);
  assert.equal(resetPasswordSchema.maxLength, 256);
  assert.equal(doc.paths['/profile'], undefined);
});
