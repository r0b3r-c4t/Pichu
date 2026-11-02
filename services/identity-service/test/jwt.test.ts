import assert from 'node:assert/strict';
import test from 'node:test';
import { JwtService } from '../src/security/jwt.js';

const configuration = {
  secret: 'a'.repeat(32),
  issuer: 'pichu-identity-service',
  audience: 'pichu-api',
  accessTokenTtlSeconds: 900,
};

test('JWT service signs and validates the required claims', async () => {
  const service = new JwtService(configuration);
  const token = await service.createAccessToken(
    '507f1f77bcf86cd799439011',
    '507f1f77bcf86cd799439012',
  );
  const claims = await service.verifyAccessToken(token);

  assert.equal(claims.userId, '507f1f77bcf86cd799439011');
  assert.equal(claims.sessionId, '507f1f77bcf86cd799439012');
  assert.ok(claims.expiresAt > claims.issuedAt);
});

test('JWT service rejects altered, expired, wrong-audience and non-HS256 tokens', async () => {
  const service = new JwtService(configuration);
  const token = await service.createAccessToken(
    '507f1f77bcf86cd799439011',
    '507f1f77bcf86cd799439012',
  );
  await assert.rejects(service.verifyAccessToken(`${token.slice(0, -1)}x`));

  const wrongAudience = new JwtService({ ...configuration, audience: 'other-service' });
  const wrongAudienceToken = await wrongAudience.createAccessToken(
    '507f1f77bcf86cd799439011',
    '507f1f77bcf86cd799439012',
  );
  await assert.rejects(service.verifyAccessToken(wrongAudienceToken));

  assert.throws(() => new JwtService({ ...configuration, secret: 'short' }));
});
