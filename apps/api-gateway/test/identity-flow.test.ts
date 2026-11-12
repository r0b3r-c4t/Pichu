import assert from 'node:assert/strict';
import test from 'node:test';
import { createApp } from '../src/app.js';
import { createApp as createIdentity } from '../../../services/identity-service/src/app.js';
import {
  RefreshTokenInvalidError,
  RefreshTokenReuseError,
} from '../../../services/identity-service/src/services/session.service.js';

const origin = 'http://localhost:3000';
const token = 'a'.repeat(64);

test('Gateway preserves upstream error details and Retry-After, and envelopes network failures', async (t) => {
  for (const status of [400, 401, 429, 503, 502]) {
    const app = createApp({
      env: {
        NODE_ENV: 'test',
        INTERNAL_SERVICE_SECRET: 'i'.repeat(32),
        JWT_SECRET: 'j'.repeat(32),
        JWT_ISSUER: 'issuer',
        JWT_AUDIENCE: 'audience',
      } as never,
      fetchImpl: async (_url, init) => {
        assert.equal(new Headers(init?.headers).get('x-request-id'), 'propagated-123');
        if (status === 502) throw new Error('private network details');
        return new Response(
          JSON.stringify({
            error: status === 400 ? 'INVALID_TOKEN' : 'SERVICE_UNAVAILABLE',
            message: 'Safe upstream message',
            requestId: 'propagated-123',
          }),
          {
            status,
            headers: {
              'content-type': 'application/json',
              ...(status === 429 ? { 'retry-after': '60' } : {}),
            },
          },
        );
      },
    });
    t.after(async () => app.close());
    const response = await app.inject({
      method: 'POST',
      url: '/api/auth/refresh',
      headers: { origin, cookie: `pichu_refresh_token=${token}`, 'x-request-id': 'propagated-123' },
    });
    assert.equal(response.statusCode, status);
    assert.equal(response.json().requestId, 'propagated-123');
    assert.equal(response.headers['x-request-id'], 'propagated-123');
    assert.equal(
      response.json().error,
      status === 502 ? 'BAD_GATEWAY' : status === 400 ? 'INVALID_TOKEN' : 'SERVICE_UNAVAILABLE',
    );
    assert.equal(response.body.includes('private network details'), false);
    if (status === 429) assert.equal(response.headers['retry-after'], '60');
    if (status === 400) assert.equal(response.json().details, undefined);
  }
});

test('Gateway forwards registration conflicts and request IDs', async (t) => {
  const gateway = createApp({
    env: {
      NODE_ENV: 'test',
      INTERNAL_SERVICE_SECRET: 'i'.repeat(32),
      JWT_SECRET: 'j'.repeat(32),
      JWT_ISSUER: 'issuer',
      JWT_AUDIENCE: 'audience',
    } as never,
    fetchImpl: async () =>
      new Response(
        JSON.stringify({
          error: 'USERNAME_ALREADY_EXISTS',
          message: 'Username already in use',
          requestId: 'register-123',
        }),
        {
          status: 409,
          headers: { 'content-type': 'application/json', 'x-request-id': 'register-123' },
        },
      ),
  });
  t.after(async () => gateway.close());
  const response = await gateway.inject({
    method: 'POST',
    url: '/api/auth/register',
    headers: { 'x-request-id': 'register-123' },
    payload: { name: 'Ada', username: 'ada_01', email: 'ada@example.com', password: 'password123' },
  });
  assert.equal(response.statusCode, 409);
  assert.deepEqual(response.json(), {
    error: 'USERNAME_ALREADY_EXISTS',
    message: 'Username already in use',
    requestId: 'register-123',
  });
  assert.equal(response.headers['x-request-id'], 'register-123');
});

function fixture() {
  let revoked = false;
  const session = {
    _id: '507f1f77bcf86cd799439011',
    userId: '507f1f77bcf86cd799439012',
    expiresAt: new Date(Date.now() + 60_000),
  };
  const identity = createIdentity({
    loginService: {
      login: async () => ({
        accessToken: 'access',
        refreshToken: token,
        sessionId: String(session._id),
      }),
    } as never,
    sessionService: {
      refreshTokenTtlSeconds: 60,
      isSessionActive: async () => !revoked,
      revokeSession: async () => {
        revoked = true;
      },
      rotateRefreshToken: async (raw: string) => {
        if (revoked) throw new RefreshTokenInvalidError();
        if (raw === 'b'.repeat(64)) throw new RefreshTokenReuseError();
        if (raw !== token) throw new RefreshTokenInvalidError();
        return { session, refreshToken: 'c'.repeat(64) };
      },
    } as never,
    jwtService: {
      createAccessToken: async () => 'new-access',
      verifyAccessToken: async () => ({
        userId: session.userId,
        sessionId: session._id,
        issuedAt: 1,
        expiresAt: 2,
      }),
    } as never,
    passwordRecoveryService: { confirmRecovery: async (raw: string) => raw === token } as never,
    cookieOrigin: origin,
  });
  let upstreamCalls = 0;
  const gateway = createApp({
    env: {
      NODE_ENV: 'test',
      INTERNAL_SERVICE_SECRET: 'i'.repeat(32),
      JWT_SECRET: 'j'.repeat(32),
      JWT_ISSUER: 'issuer',
      JWT_AUDIENCE: 'audience',
      SENSITIVE_RATE_LIMIT_MAX: 100,
    } as never,
    fetchImpl: async (url, init) => {
      upstreamCalls++;
      const forwarded = new Headers(init?.headers);
      for (const name of ['x-service-name', 'x-signature', 'x-timestamp'])
        assert.equal(forwarded.has(name), false);
      const response = await identity.inject({
        method: 'POST',
        url: new URL(String(url)).pathname,
        remoteAddress: `192.0.2.${upstreamCalls}`,
        headers: Object.fromEntries(new Headers(init?.headers)),
        payload: init?.body as string | undefined,
      });
      const headers = new Headers({ 'content-type': 'application/json' });
      for (const cookie of [response.headers['set-cookie']].flat()) {
        if (cookie) headers.append('set-cookie', cookie);
      }
      return new Response(response.body, { status: response.statusCode, headers });
    },
  });
  return { gateway, identity, calls: () => upstreamCalls, revoked: () => revoked };
}

test('Gateway cookie login followed by refresh preserves cookie scope, attributes and request id', async (t) => {
  const { gateway, identity } = fixture();
  t.after(async () => {
    await gateway.close();
    await identity.close();
  });
  const login = await gateway.inject({
    method: 'POST',
    url: '/api/auth/login',
    headers: {
      origin,
      'x-service-name': 'vehicle-service',
      'x-signature': 'forged',
      'x-timestamp': '1',
    },
    payload: { email: 'ada@example.com', password: 'correct-password' },
  });
  assert.equal(login.statusCode, 200);
  assert.deepEqual(login.json(), { accessToken: 'access' });
  const cookie = String(login.headers['set-cookie']);
  assert.match(cookie, /Path=\/api\/auth(?:;|$)/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);
  const refreshed = await gateway.inject({
    method: 'POST',
    url: '/api/auth/refresh',
    headers: { origin, cookie: cookie.split(';')[0], 'x-request-id': 'flow-123' },
  });
  assert.equal(refreshed.statusCode, 200);
  assert.deepEqual(refreshed.json(), { accessToken: 'new-access' });
  assert.equal(refreshed.headers['x-request-id'], 'flow-123');
  assert.match(String(refreshed.headers['set-cookie']), /Path=\/api\/auth(?:;|$)/);
});

test('Gateway logout requires the allowed Origin, revokes the session and clears the cookie', async (t) => {
  const { gateway, identity, revoked } = fixture();
  t.after(async () => {
    await gateway.close();
    await identity.close();
  });
  const cookie = `pichu_refresh_token=${token}`;
  const rejected = await gateway.inject({
    method: 'POST',
    url: '/api/auth/logout',
    headers: { authorization: 'Bearer access', cookie },
  });
  assert.equal(rejected.statusCode, 403);
  assert.equal(revoked(), false);
  const response = await gateway.inject({
    method: 'POST',
    url: '/api/auth/logout',
    headers: { authorization: 'Bearer access', cookie, origin },
  });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { revoked: true });
  assert.equal(revoked(), true);
  assert.match(String(response.headers['set-cookie']), /Max-Age=0/);
  assert.match(String(response.headers['set-cookie']), /Path=\/api\/auth(?:;|$)/);
  const refreshed = await gateway.inject({
    method: 'POST',
    url: '/api/auth/refresh',
    headers: { cookie, origin },
  });
  assert.equal(refreshed.statusCode, 401);
});

test('refresh requires a cookie and rejects token data in JSON', async (t) => {
  const { gateway, identity } = fixture();
  t.after(async () => {
    await gateway.close();
    await identity.close();
  });
  for (const scenario of [
    { headers: { origin }, status: 401, error: 'UNAUTHORIZED' },
    {
      headers: { origin, 'x-refresh-token-transport': 'body' },
      status: 401,
      error: 'UNAUTHORIZED',
    },
    {
      headers: { origin },
      payload: { refreshToken: token },
      status: 400,
      error: 'VALIDATION_ERROR',
    },
    {
      headers: { origin, cookie: `pichu_refresh_token=${token}` },
      payload: { refreshToken: token },
      status: 400,
      error: 'VALIDATION_ERROR',
    },
    { headers: { origin: 'http://evil.test' }, status: 403, error: 'FORBIDDEN' },
    { headers: { cookie: `pichu_refresh_token=${token}` }, status: 403, error: 'FORBIDDEN' },
    ...['b', 'd'].map((char) => ({
      headers: { origin, cookie: `pichu_refresh_token=${char.repeat(64)}` },
      status: 401,
      error: 'INVALID_TOKEN',
    })),
    {
      headers: { origin, cookie: `pichu_refresh_token=${token}` },
      status: 200,
    },
  ]) {
    const result = await gateway.inject({ method: 'POST', url: '/api/auth/refresh', ...scenario });
    assert.equal(result.statusCode, scenario.status, result.body);
    if (scenario.error) assert.equal(result.json().error, scenario.error);
    assert.equal(result.body.includes(token), false);
  }
});

test('registration and password reset report the shared password policy before proxying', async (t) => {
  const { gateway, identity, calls } = fixture();
  t.after(async () => {
    await gateway.close();
    await identity.close();
  });
  for (const [url, payload] of [
    [
      '/api/auth/register',
      { name: 'Ada', username: 'ada_01', email: 'ada@example.com', password: 'x'.repeat(7) },
    ],
    [
      '/api/auth/register',
      { name: 'Ada', username: 'ada_01', email: 'ada@example.com', password: 'x'.repeat(257) },
    ],
    ['/api/auth/password-reset/confirm', { token, password: 'x'.repeat(7) }],
    ['/api/auth/password-reset/confirm', { token, password: 'x'.repeat(257) }],
  ]) {
    const invalid = await gateway.inject({
      method: 'POST',
      url,
      headers: { 'x-request-id': 'password-123' },
      payload,
    });
    assert.equal(invalid.statusCode, 400);
    assert.equal(invalid.json().error, 'VALIDATION_ERROR');
    assert.deepEqual(invalid.json().details, [
      { field: 'password', message: 'Password must contain 8 to 256 characters' },
    ]);
    assert.equal(invalid.json().requestId, 'password-123');
    assert.equal(calls(), 0);
  }
  for (const [raw, status] of [
    [token, 200],
    ['d'.repeat(64), 400],
  ] as const) {
    const response = await gateway.inject({
      method: 'POST',
      url: '/api/auth/password-reset/confirm',
      headers: { 'x-request-id': 'reset-123' },
      payload: { token: raw, password: 'new password value' },
    });
    assert.equal(response.statusCode, status);
    if (status === 400) {
      assert.equal(response.json().error, 'INVALID_TOKEN');
      assert.equal(response.json().details, undefined);
      assert.equal(response.json().requestId, 'reset-123');
    } else assert.deepEqual(response.json(), { reset: true });
  }
});

test('Gateway Swagger documents cookie-only refresh and credentialed CORS', async (t) => {
  const { gateway, identity } = fixture();
  t.after(async () => {
    await gateway.close();
    await identity.close();
  });
  const doc = (await gateway.inject('/docs/json')).json();
  for (const path of [
    '/api/auth/login',
    '/api/auth/refresh',
    '/api/auth/register',
    '/api/auth/password-reset/confirm',
  ]) {
    const operation = doc.paths[path].post;
    for (const status of [200, 400, 403, 413, 415, 429, 500, 502, 503, 504]) {
      assert.ok(operation.responses[status]?.description, `${path}: ${status}`);
      if (status !== 200)
        assert.ok(
          operation.responses[status].content['application/json'].schema.properties.details,
        );
    }
  }
  assert.ok(doc.paths['/api/auth/refresh'].post.responses['401']);
  assert.equal(doc.paths['/api/auth/refresh'].post.requestBody, undefined);
  assert.deepEqual(doc.paths['/api/auth/refresh'].post.security, [{ refreshCookie: [] }]);
  for (const path of ['/api/auth/login', '/api/auth/refresh']) {
    const success = doc.paths[path].post.responses['200'];
    assert.deepEqual(Object.keys(success.content['application/json'].schema.properties), [
      'accessToken',
    ]);
    assert.ok(success.headers['Set-Cookie']);
  }
  assert.equal(doc.paths['/api/auth/logout'].post.requestBody, undefined);
  assert.match(doc.paths['/api/auth/password-reset/confirm'].post.description, /8–256 characters/);
  assert.doesNotMatch(
    doc.paths['/api/auth/password-reset/confirm'].post.description,
    /12.{0,3}256 characters/,
  );
  const registerPasswordSchema =
    doc.paths['/api/auth/register'].post.requestBody.content['application/json'].schema.properties
      .password;
  assert.equal(registerPasswordSchema.minLength, 8);
  assert.equal(registerPasswordSchema.maxLength, 256);
  const register = doc.paths['/api/auth/register'].post;
  assert.ok(register.requestBody.content['application/json'].schema.required.includes('username'));
  assert.equal(
    register.requestBody.content['application/json'].schema.properties.username.minLength,
    3,
  );
  assert.equal(
    register.requestBody.content['application/json'].schema.properties.username.maxLength,
    30,
  );
  assert.ok(register.responses['409'].description);
  assert.deepEqual(
    register.responses['409'].content['application/json'].schema.properties.error.enum,
    ['USER_ALREADY_EXISTS', 'USERNAME_ALREADY_EXISTS'],
  );
  assert.ok(doc.paths['/api/auth/logout'].post.responses['200'].headers['Set-Cookie']);
  assert.ok(doc.paths['/api/auth/logout'].post.responses['403']);
  assert.equal(
    JSON.stringify(doc.paths['/api/auth/login'].post).includes('x-refresh-token-transport'),
    false,
  );
  const preflight = await gateway.inject({
    method: 'OPTIONS',
    url: '/api/auth/refresh',
    headers: { origin, 'access-control-request-headers': 'content-type' },
  });
  assert.equal(preflight.statusCode, 204);
  assert.doesNotMatch(
    String(preflight.headers['access-control-allow-headers']),
    /x-refresh-token-transport/,
  );
  assert.equal(preflight.headers['access-control-allow-credentials'], 'true');
});
