import type { FastifyReply, FastifyRequest } from 'fastify';
import { Types } from 'mongoose';
import { JwtService, type AuthenticatedClaims } from './jwt.js';
import { SessionService } from '../services/session.service.js';

declare module 'fastify' {
  interface FastifyRequest {
    auth?: AuthenticatedClaims;
  }
}

export function createAuthenticationGuard(jwtService: JwtService, sessionService: SessionService) {
  return async function authenticate(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const authorization = request.headers.authorization;
    if (!authorization?.startsWith('Bearer ')) {
      await reply.code(401).send({ message: 'Authentication required' });
      return;
    }

    let claims: AuthenticatedClaims;
    try {
      claims = await jwtService.verifyAccessToken(authorization.slice('Bearer '.length));
      if (!Types.ObjectId.isValid(claims.userId) || !Types.ObjectId.isValid(claims.sessionId)) {
        throw new Error('Invalid identity claims');
      }
    } catch {
      await reply.code(401).send({ message: 'Authentication required' });
      return;
    }

    let active: boolean;
    try {
      active = await sessionService.isSessionActive(
        new Types.ObjectId(claims.sessionId),
        new Types.ObjectId(claims.userId),
      );
    } catch {
      await reply.code(503).send({ message: 'Authentication service unavailable' });
      return;
    }
    if (!active) {
      await reply.code(401).send({ message: 'Authentication required' });
      return;
    }
    request.auth = claims;
  };
}
