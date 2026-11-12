import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { test } from 'node:test';
import { GatewayJwtError, verifyGatewayAccessToken } from '../src/security/jwt.js';

function token(payload: Record<string, unknown>, secret = 's'.repeat(32), alg = 'HS256'): string {
  const header = Buffer.from(JSON.stringify({ alg, typ: 'JWT' })).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = createHmac('sha256', secret)
    .update(`${header}.${encodedPayload}`)
    .digest('base64url');
  return `${header}.${encodedPayload}.${signature}`;
}

const baseClaims = {
  sub: '507f1f77bcf86cd799439011',
  sid: '507f1f77bcf86cd799439012',
  iss: 'issuer',
  aud: 'audience',
  iat: 100,
  exp: 200,
};

test('JWT validation accepts Identity HS256 claims', () => {
  const claims = verifyGatewayAccessToken(
    token(baseClaims),
    's'.repeat(32),
    'issuer',
    'audience',
    150,
  );
  assert.equal(claims.userId, baseClaims.sub);
  assert.equal(claims.sessionId, baseClaims.sid);
});

test('JWT validation rejects expired, future and non-HS256 tokens', () => {
  assert.throws(
    () => verifyGatewayAccessToken(token(baseClaims), 's'.repeat(32), 'issuer', 'audience', 200),
    GatewayJwtError,
  );
  assert.throws(
    () =>
      verifyGatewayAccessToken(
        token({ ...baseClaims, nbf: 201 }),
        's'.repeat(32),
        'issuer',
        'audience',
        150,
      ),
    GatewayJwtError,
  );
  assert.throws(
    () =>
      verifyGatewayAccessToken(
        token(baseClaims, 's'.repeat(32), 'none'),
        's'.repeat(32),
        'issuer',
        'audience',
        150,
      ),
    GatewayJwtError,
  );
});
