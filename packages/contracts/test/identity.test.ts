import assert from 'node:assert/strict';
import test from 'node:test';
import {
  acceptedResponseSchema,
  emailVerificationRequestSchema,
  emailVerificationResponseSchema,
  internalUserExistenceParamsSchema,
  internalUserExistenceResponseSchema,
  loginBodyResponseSchema,
  loginCookieResponseSchema,
  loginRequestSchema,
  loginResponseSchema,
  loginTransportHeadersSchema,
  logoutAllRequestSchema,
  logoutAllResponseSchema,
  logoutRequestSchema,
  logoutResponseSchema,
  passwordResetConfirmSchema,
  passwordResetRequestSchema,
  refreshBodyRequestBodySchema,
  refreshBodyTransportHeadersSchema,
  refreshCookieRequestBodySchema,
  refreshRequestSchema,
  registerRequestSchema,
  registerResponseSchema,
  resetResponseSchema,
  sessionDeletionParamsSchema,
  sessionDeletionRequestSchema,
  sessionDeletionResponseSchema,
  sessionsResponseSchema,
  verificationResendRequestSchema,
  verificationResendResponseSchema,
} from '../src/index.js';

const objectId = '507f1f77bcf86cd799439011';
const token = 'a'.repeat(64);
const accessToken = 'signed-access-token';

test('login accepts real credentials and models transport through the header', () => {
  const request = loginRequestSchema.parse({
    email: '  driver@example.com  ',
    password: 'x',
  });
  assert.equal(request.email, 'driver@example.com');
  assert.equal(loginTransportHeadersSchema.parse({})['x-refresh-token-transport'], 'cookie');
  assert.equal(
    loginTransportHeadersSchema.parse({ 'x-refresh-token-transport': 'body' })[
      'x-refresh-token-transport'
    ],
    'body',
  );
  assert.equal(
    loginRequestSchema.safeParse({
      email: 'driver@example.com',
      password: 'valid-password',
      transport: 'body',
    }).success,
    false,
  );
});

test('login rejects invalid boundaries and unknown properties', () => {
  assert.equal(
    loginRequestSchema.safeParse({ email: 'not-an-email', password: 'x' }).success,
    false,
  );
  assert.equal(
    loginRequestSchema.safeParse({ email: 'driver@example.com', password: '' }).success,
    false,
  );
  assert.equal(
    loginRequestSchema.safeParse({ email: 'driver@example.com', password: 'x'.repeat(257) })
      .success,
    false,
  );
  assert.equal(loginTransportHeadersSchema.safeParse({ host: 'localhost' }).success, false);
});

test('login responses distinguish cookie and body transports without invented fields', () => {
  assert.equal(loginCookieResponseSchema.safeParse({ accessToken }).success, true);
  assert.equal(
    loginBodyResponseSchema.safeParse({ accessToken, refreshToken: token, sessionId: objectId })
      .success,
    true,
  );
  assert.equal(
    loginResponseSchema.safeParse({ accessToken, refreshToken: token, sessionId: objectId })
      .success,
    true,
  );
  assert.equal(loginResponseSchema.safeParse({ accessToken, expiresIn: 900 }).success, false);
  assert.equal(
    loginBodyResponseSchema.safeParse({ accessToken, refreshToken: token }).success,
    false,
  );
});

test('refresh enforces the selected transport and rejects mixed combinations', () => {
  const cookie = refreshRequestSchema.parse({ headers: {} });
  assert.equal(cookie.headers['x-refresh-token-transport'], 'cookie');
  assert.equal(
    refreshRequestSchema.safeParse({
      headers: { 'x-refresh-token-transport': 'body' },
      body: { refreshToken: token },
    }).success,
    true,
  );
  assert.equal(
    refreshRequestSchema.safeParse({
      headers: { 'x-refresh-token-transport': 'body' },
      body: {},
    }).success,
    false,
  );
  assert.equal(
    refreshRequestSchema.safeParse({ headers: {}, body: { refreshToken: token } }).success,
    false,
  );
  assert.equal(refreshCookieRequestBodySchema.safeParse(undefined).success, true);
  assert.equal(refreshCookieRequestBodySchema.safeParse({}).success, true);
  assert.equal(refreshCookieRequestBodySchema.safeParse({ refreshToken: token }).success, false);
  assert.equal(refreshBodyRequestBodySchema.safeParse({ refreshToken: token }).success, true);
  assert.equal(
    refreshBodyTransportHeadersSchema.safeParse({ 'x-refresh-token-transport': 'cookie' }).success,
    false,
  );
});

test('register validates creation policy, boundaries and closed DTOs', () => {
  assert.equal(
    registerRequestSchema.safeParse({
      name: 'A',
      email: 'driver@example.com',
      password: 'x'.repeat(12),
    }).success,
    true,
  );
  assert.equal(
    registerRequestSchema.safeParse({
      name: 'x'.repeat(120),
      email: 'driver@example.com',
      password: 'x'.repeat(256),
    }).success,
    true,
  );
  assert.equal(
    registerRequestSchema.safeParse({
      name: 'Driver',
      email: 'driver@example.com',
      password: 'x'.repeat(11),
    }).success,
    false,
  );
  assert.equal(
    registerRequestSchema.safeParse({
      name: 'Driver',
      email: 'driver@example.com',
      password: 'x'.repeat(12),
      role: 'admin',
    }).success,
    false,
  );
  assert.equal(registerResponseSchema.safeParse({ accepted: true }).success, true);
  assert.equal(registerResponseSchema.safeParse({ accepted: false }).success, false);
});

test('session contracts match the serialized active-session response', () => {
  const session = {
    sessionId: objectId,
    createdAt: '2026-11-03T12:00:00.000Z',
    lastActivityAt: '2026-11-03T12:05:00.000Z',
    expiresAt: '2026-12-03T12:00:00.000Z',
    userAgent: null,
    revokedAt: null,
    current: true,
  };
  assert.equal(sessionsResponseSchema.safeParse({ sessions: [session] }).success, true);
  assert.equal(
    sessionsResponseSchema.safeParse({
      sessions: [{ ...session, id: objectId, sessionId: undefined }],
    }).success,
    false,
  );
  assert.equal(
    sessionsResponseSchema.safeParse({ sessions: [{ ...session, revokedAt: session.createdAt }] })
      .success,
    false,
  );
  assert.equal(
    sessionsResponseSchema.safeParse({ sessions: [{ ...session, current: undefined }] }).success,
    false,
  );
});

test('verification and resend contracts validate requests and responses', () => {
  assert.equal(emailVerificationRequestSchema.safeParse({ token }).success, true);
  assert.equal(emailVerificationRequestSchema.safeParse({ token: token.slice(1) }).success, false);
  assert.equal(
    emailVerificationRequestSchema.safeParse({ token: token.toUpperCase() }).success,
    false,
  );
  assert.equal(emailVerificationResponseSchema.safeParse({ verified: true }).success, true);
  assert.equal(emailVerificationResponseSchema.safeParse({ verified: false }).success, false);
  assert.equal(
    verificationResendRequestSchema.safeParse({ email: 'driver@example.com' }).success,
    true,
  );
  assert.equal(
    verificationResendRequestSchema.safeParse({
      email: 'driver@example.com',
      unexpected: true,
    }).success,
    false,
  );
  assert.equal(verificationResendResponseSchema.safeParse({ accepted: true }).success, true);
});

test('logout and session deletion contracts are closed and use revoked responses', () => {
  assert.equal(logoutRequestSchema.safeParse(undefined).success, true);
  assert.equal(logoutRequestSchema.safeParse({}).success, false);
  assert.equal(logoutRequestSchema.safeParse({ refreshToken: token }).success, false);
  assert.equal(logoutAllRequestSchema.safeParse(undefined).success, true);
  assert.equal(logoutResponseSchema.safeParse({ revoked: true }).success, true);
  assert.equal(logoutAllResponseSchema.safeParse({ revoked: false }).success, false);
  assert.equal(sessionDeletionParamsSchema.safeParse({ sessionId: objectId }).success, true);
  assert.equal(sessionDeletionParamsSchema.safeParse({ sessionId: 'invalid' }).success, false);
  assert.equal(sessionDeletionRequestSchema.safeParse(undefined).success, true);
  assert.equal(sessionDeletionResponseSchema.safeParse({ revoked: true }).success, true);
});

test('password recovery keeps the implemented token and password constraints', () => {
  assert.equal(passwordResetRequestSchema.safeParse({ email: 'driver@example.com' }).success, true);
  assert.equal(
    passwordResetConfirmSchema.safeParse({ token, password: 'x'.repeat(12) }).success,
    true,
  );
  assert.equal(
    passwordResetConfirmSchema.safeParse({ token: token.slice(1), password: 'x'.repeat(12) })
      .success,
    false,
  );
  assert.equal(
    passwordResetConfirmSchema.safeParse({ token, password: 'x'.repeat(11) }).success,
    false,
  );
  assert.equal(
    passwordResetConfirmSchema.safeParse({
      token,
      password: 'x'.repeat(12),
      confirmation: 'x'.repeat(12),
    }).success,
    false,
  );
  assert.equal(acceptedResponseSchema.safeParse({ accepted: true }).success, true);
  assert.equal(resetResponseSchema.safeParse({ reset: true }).success, true);
});

test('internal user existence contracts validate params and both boolean responses', () => {
  assert.equal(internalUserExistenceParamsSchema.safeParse({ userId: objectId }).success, true);
  assert.equal(internalUserExistenceParamsSchema.safeParse({ userId: 'invalid' }).success, false);
  assert.equal(internalUserExistenceResponseSchema.safeParse({ exists: true }).success, true);
  assert.equal(internalUserExistenceResponseSchema.safeParse({ exists: false }).success, true);
  assert.equal(
    internalUserExistenceResponseSchema.safeParse({ exists: true, userId: objectId }).success,
    false,
  );
});
