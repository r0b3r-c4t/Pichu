import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { createPublicKey } from 'node:crypto';
import { z } from 'zod';
import { DeviceModel } from './models/device.model.js';
import { requireVerifiedEmail } from './security/email-verification.js';
import { completeDeviceLink, createDeviceChallenge } from './services/device-link.service.js';
import { docsRoutes } from './routes/docs.js';
import { internalAuthPlugin } from '@pichu/internal-auth-adapters/fastify';
import type { Keyring } from '@pichu/internal-auth';
import type { NonceStore } from '@pichu/internal-auth-adapters/types';
import type { ServerOptions } from 'node:https';

export interface DeviceAppDependencies {
  https?: ServerOptions;
  internalAuth?: {
    environment: 'development' | 'test' | 'staging' | 'production';
    keyring: Keyring;
    nonces: NonceStore;
    bodyLimit?: number;
  };
}

export function isEd25519PublicKey(value: string): boolean {
  try {
    return createPublicKey(value).asymmetricKeyType === 'ed25519';
  } catch {
    return false;
  }
}

export function createApp(dependencies: DeviceAppDependencies = {}): FastifyInstance {
  const app = Fastify({
    logger: true,
    ...(dependencies.https ? { https: dependencies.https } : {}),
  });
  const challengeAttempts = new Map<string, { count: number; resetAt: number }>();
  app.get('/health', async () => ({ status: 'ok', service: 'device-service' }));
  app.get('/health/ready', async (_request, reply) => {
    if (!dependencies.internalAuth) return reply.code(503).send({ status: 'unready' });
    try {
      await dependencies.internalAuth.nonces.assertReady();
      return { status: 'ready', service: 'device-service' };
    } catch {
      return reply.code(503).send({ status: 'unready', service: 'device-service' });
    }
  });
  void app.register(docsRoutes);
  const registerDevice = async (request: FastifyRequest, reply: FastifyReply) => {
    const parsed = z
      .object({
        identifier: z.string().trim().min(1).max(128),
        publicKey: z.string().trim().min(32).max(4096),
        vehicleId: z.string().regex(/^[a-f0-9]{24}$/),
        userId: z.string().regex(/^[a-f0-9]{24}$/),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ message: 'Invalid device data' });
    if (!isEd25519PublicKey(parsed.data.publicKey))
      return reply.code(400).send({ message: 'Invalid device key' });
    if (!(await requireVerifiedEmail(request, reply, parsed.data.userId))) return;
    try {
      const device = await DeviceModel.create({
        ...parsed.data,
        status: 'PENDING',
        algorithm: 'Ed25519',
      });
      return reply.code(201).send({ deviceId: String(device._id), status: device.status });
    } catch {
      return reply.code(503).send({ message: 'Device registration failed' });
    }
  };
  const registerProtectedRoutes = async (scope: FastifyInstance) => {
    scope.get<{ Params: { deviceId: string } }>(
      '/devices/:deviceId',
      { config: { internalOperation: 'deviceRead' } },
      async (request, reply) => {
        const parsed = z
          .object({ userId: z.string().regex(/^[a-f0-9]{24}$/) })
          .safeParse(request.query);
        if (!parsed.success || !/^[a-f0-9]{24}$/.test(request.params.deviceId))
          return reply.code(400).send({ message: 'Invalid device request' });
        if (!(await requireVerifiedEmail(request, reply, parsed.data.userId))) return;
        const device = await DeviceModel.findOne({
          _id: request.params.deviceId,
          linkedByUserId: parsed.data.userId,
          status: 'ACTIVE',
        });
        if (!device) return reply.code(404).send({ message: 'Device not found' });
        return {
          deviceId: String(device._id),
          identifier: device.identifier,
          vehicleId: device.vehicleId ? String(device.vehicleId) : null,
          status: device.status,
          lastSeenAt: device.lastSeenAt,
          requestId: request.headers['x-request-id'],
        };
      },
    );
  };
  if (dependencies.internalAuth) {
    const auth = dependencies.internalAuth;
    void app.register(internalAuthPlugin, {
      environment: auth.environment,
      audience: 'device-service',
      keyring: () => auth.keyring,
      nonces: auth.nonces,
      bodyLimit: auth.bodyLimit,
      policies: {
        deviceRegister: {
          method: 'POST',
          route: '/internal/devices/register',
          senders: ['vehicle-service'],
        },
        deviceRead: { method: 'GET', route: '/devices/:deviceId', senders: ['api-gateway'] },
      },
      routes: async (scope) => {
        scope.post(
          '/internal/devices/register',
          { config: { internalOperation: 'deviceRegister' } },
          registerDevice,
        );
        await registerProtectedRoutes(scope);
      },
    });
  }
  app.post<{ Params: { deviceId: string } }>(
    '/internal/devices/:deviceId/rotate-key',
    async (request, reply) => {
      return reply.code(404).send({ message: 'Not found' });
      const parsed = z
        .object({ publicKey: z.string().trim().min(32).max(4096) })
        .safeParse(request.body);
      if (!parsed.success || !isEd25519PublicKey(parsed.data!.publicKey))
        return reply.code(400).send({ message: 'Invalid device key' });
      const result = await DeviceModel.updateOne(
        { _id: request.params.deviceId, status: 'ACTIVE' },
        { $set: { publicKey: parsed.data!.publicKey } },
      );
      if (result.modifiedCount !== 1) return reply.code(404).send({ message: 'Device not found' });
      return { rotated: true };
    },
  );
  app.post<{ Params: { deviceId: string } }>(
    '/internal/devices/:deviceId/revoke',
    async (request, reply) => {
      return reply.code(404).send({ message: 'Not found' });
      const parsed = z
        .object({ reason: z.string().trim().min(1).max(256).optional() })
        .safeParse(request.body ?? {});
      if (!parsed.success) return reply.code(400).send({ message: 'Invalid revocation data' });
      const result = await DeviceModel.updateOne(
        { _id: request.params.deviceId, status: { $ne: 'REVOKED' } },
        { $set: { status: 'REVOKED' } },
      );
      if (result.modifiedCount !== 1) return reply.code(404).send({ message: 'Device not found' });
      return { revoked: true };
    },
  );
  app.post<{ Params: { deviceId: string } }>(
    '/devices/:deviceId/challenge',
    async (request, reply) => {
      const now = Date.now();
      const entry = challengeAttempts.get(request.ip);
      if (entry && entry.resetAt > now && entry.count >= 5) {
        reply.header('retry-after', Math.ceil((entry.resetAt - now) / 1000));
        return reply.code(429).send({ message: 'Too many requests' });
      }
      if (!entry || entry.resetAt <= now)
        challengeAttempts.set(request.ip, { count: 1, resetAt: now + 15 * 60_000 });
      else entry.count += 1;
      const parsed = z
        .object({ identifier: z.string().trim().min(1).max(128) })
        .safeParse(request.body);
      if (!parsed.success) return reply.code(400).send({ message: 'Invalid challenge request' });
      const device = await DeviceModel.findOne({
        _id: request.params.deviceId,
        identifier: parsed.data.identifier,
      });
      if (!device || device.status !== 'PENDING' || !device.vehicleId || !device.linkedByUserId) {
        return reply.code(404).send({ message: 'Device not found' });
      }
      const result = await createDeviceChallenge({
        deviceId: device._id,
        vehicleId: device.vehicleId,
        userId: device.linkedByUserId,
      });
      return { challenge: result.challenge, expiresAt: result.expiresAt };
    },
  );
  app.post<{ Params: { deviceId: string } }>('/devices/:deviceId/link', async (request, reply) => {
    const parsed = z
      .object({ challenge: z.string().min(32).max(512), signature: z.string().min(1).max(4096) })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ message: 'Invalid link proof' });
    const linked = await completeDeviceLink({
      challenge: parsed.data.challenge,
      signature: parsed.data.signature,
    });
    if (!linked) return reply.code(400).send({ message: 'Invalid or expired link challenge' });
    return { linked: true };
  });
  return app;
}
