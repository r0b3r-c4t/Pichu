import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import type { Types } from 'mongoose';

export interface JwtConfiguration {
  secret: string;
  issuer: string;
  audience: string;
  accessTokenTtlSeconds: number;
}

export interface AuthenticatedClaims {
  userId: string;
  sessionId: string;
  issuedAt: number;
  expiresAt: number;
}

export class JwtValidationError extends Error {
  readonly code = 'JWT_INVALID';

  constructor() {
    super('Invalid access token');
    this.name = 'JwtValidationError';
  }
}

function requiredString(payload: JWTPayload, claim: string): string {
  const value = payload[claim];
  if (typeof value !== 'string' || value.length === 0) {
    throw new JwtValidationError();
  }
  return value;
}

export class JwtService {
  private readonly key: Uint8Array;

  constructor(private readonly configuration: JwtConfiguration) {
    if (new TextEncoder().encode(configuration.secret).byteLength < 32) {
      throw new Error('JWT secret must contain at least 32 bytes');
    }
    this.key = new TextEncoder().encode(configuration.secret);
  }

  async createAccessToken(
    userId: Types.ObjectId | string,
    sessionId: Types.ObjectId | string,
  ): Promise<string> {
    const issuedAt = Math.floor(Date.now() / 1000);
    return new SignJWT({ sid: String(sessionId) })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setSubject(String(userId))
      .setIssuer(this.configuration.issuer)
      .setAudience(this.configuration.audience)
      .setIssuedAt(issuedAt)
      .setExpirationTime(issuedAt + this.configuration.accessTokenTtlSeconds)
      .sign(this.key);
  }

  async verifyAccessToken(token: string): Promise<AuthenticatedClaims> {
    try {
      const { payload } = await jwtVerify(token, this.key, {
        algorithms: ['HS256'],
        issuer: this.configuration.issuer,
        audience: this.configuration.audience,
      });
      const userId = requiredString(payload, 'sub');
      const sessionId = requiredString(payload, 'sid');
      if (typeof payload.iat !== 'number' || typeof payload.exp !== 'number') {
        throw new JwtValidationError();
      }
      return { userId, sessionId, issuedAt: payload.iat, expiresAt: payload.exp };
    } catch {
      throw new JwtValidationError();
    }
  }
}
