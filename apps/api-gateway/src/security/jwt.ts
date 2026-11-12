import { createHmac, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';

const claimsSchema = z.strictObject({
  sub: z.string().regex(/^[a-f0-9]{24}$/),
  sid: z.string().regex(/^[a-f0-9]{24}$/),
  iss: z.string().min(1),
  aud: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]),
  iat: z.number().int().nonnegative(),
  exp: z.number().int().positive(),
  nbf: z.number().int().nonnegative().optional(),
});

export interface GatewayAuthClaims {
  userId: string;
  sessionId: string;
  issuedAt: number;
  expiresAt: number;
}

export class GatewayJwtError extends Error {
  constructor() {
    super('Invalid access token');
    this.name = 'GatewayJwtError';
  }
}

export function verifyGatewayAccessToken(
  token: string,
  secret: string,
  issuer: string,
  audience: string,
  nowSeconds = Math.floor(Date.now() / 1000),
): GatewayAuthClaims {
  try {
    const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
    if (!encodedHeader || !encodedPayload || !encodedSignature) throw new GatewayJwtError();
    const header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString()) as {
      alg?: string;
      typ?: string;
    };
    if (header.alg !== 'HS256' || header.typ !== 'JWT') throw new GatewayJwtError();
    const expected = createHmac('sha256', secret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest();
    const actual = Buffer.from(encodedSignature, 'base64url');
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected))
      throw new GatewayJwtError();
    const claims = claimsSchema.parse(
      JSON.parse(Buffer.from(encodedPayload, 'base64url').toString()),
    );
    const audienceMatches = Array.isArray(claims.aud)
      ? claims.aud.includes(audience)
      : claims.aud === audience;
    if (
      claims.iss !== issuer ||
      !audienceMatches ||
      claims.exp <= nowSeconds ||
      (claims.nbf !== undefined && claims.nbf > nowSeconds)
    )
      throw new GatewayJwtError();
    return {
      userId: claims.sub,
      sessionId: claims.sid,
      issuedAt: claims.iat,
      expiresAt: claims.exp,
    };
  } catch {
    throw new GatewayJwtError();
  }
}
