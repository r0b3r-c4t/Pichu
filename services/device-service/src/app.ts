import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { z } from 'zod';
import { deviceRegistrationRequestSchema } from '@pichu/contracts';
import { internalAuthPlugin } from '@pichu/internal-auth-adapters/fastify';
import type { Keyring } from '@pichu/internal-auth';
import type { NonceStore } from '@pichu/internal-auth-adapters/types';
import type { ServerOptions } from 'node:https';
import { assertDeviceDatabaseReady } from './database/bootstrap.js';
import { guardedDeviceRead } from './database/transaction.js';
import { DeviceModel } from './models/device.model.js';
import { docsRoutes } from './routes/docs.js';
import { requireVerifiedEmail } from './security/email-verification.js';
import { DevicePublicKeyError, parseDevicePublicKey } from './security/device-public-key.js';
import { DeviceServiceError } from './services/device-errors.js';
import { registerDevice } from './services/device-registration.service.js';

export interface DeviceAppDependencies {
  https?: ServerOptions;
  internalAuth?: {
    environment: 'development' | 'test' | 'staging' | 'production';
    keyring: Keyring;
    nonces: NonceStore;
    bodyLimit?: number;
  };
  readinessCheck?: () => Promise<void>;
}

function correlationId(request: FastifyRequest): string {
  const forwarded = request.headers['x-request-id'];
  return typeof forwarded === 'string' ? forwarded : request.id;
}

function sendUnavailable(request: FastifyRequest, reply: FastifyReply) {
  return reply.code(503).send({
    error: 'DEVICE_DATABASE_UNAVAILABLE',
    message: 'Device database unavailable',
    requestId: correlationId(request),
  });
}

export function createApp(dependencies: DeviceAppDependencies = {}): FastifyInstance {
  const app = Fastify({
    logger: true,
    ...(dependencies.https ? { https: dependencies.https } : {}),
  });
  const readinessCheck = dependencies.readinessCheck ?? (() => assertDeviceDatabaseReady());

  app.get('/health', async () => ({ status: 'ok', service: 'device-service' }));
  app.get('/health/ready', async (_request, reply) => {
    if (!dependencies.internalAuth) {
      return reply.code(503).send({ status: 'unready', service: 'device-service' });
    }
    try {
      await Promise.all([dependencies.internalAuth.nonces.assertReady(), readinessCheck()]);
      return { status: 'ready', service: 'device-service' };
    } catch {
      return reply.code(503).send({ status: 'unready', service: 'device-service' });
    }
  });
  void app.register(docsRoutes);

  const registerDeviceRoute = async (request: FastifyRequest, reply: FastifyReply) => {
    const parsed = deviceRegistrationRequestSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ message: 'Invalid device data' });
    try {
      parseDevicePublicKey(parsed.data.publicKey);
    } catch (error) {
      if (error instanceof DevicePublicKeyError) {
        return reply.code(400).send({ message: 'Invalid device key' });
      }
      throw error;
    }
    if (!(await requireVerifiedEmail(request, reply, parsed.data.userId))) return;
    try {
      const device = await registerDevice({
        identifier: parsed.data.identifier,
        publicKey: parsed.data.publicKey,
        vehicleId: parsed.data.vehicleId,
        requestedByUserId: parsed.data.userId,
      });
      return reply.code(201).send({ deviceId: String(device.deviceId), status: device.status });
    } catch (error) {
      if (error instanceof DeviceServiceError) {
        if (error.code === 'INVALID_DEVICE_KEY') {
          return reply.code(400).send({ message: 'Invalid device key' });
        }
        if (error.code === 'DEVICE_ALREADY_REGISTERED') {
          return reply.code(409).send({
            error: 'DEVICE_ALREADY_REGISTERED',
            message: 'Device already registered',
            requestId: correlationId(request),
          });
        }
        if (error.code === 'DATABASE_UNAVAILABLE') return sendUnavailable(request, reply);
      }
      throw error;
    }
  };

  const registerProtectedRoutes = async (scope: FastifyInstance) => {
    scope.post(
      '/internal/devices/register',
      { config: { internalOperation: 'deviceRegister' } },
      registerDeviceRoute,
    );
    // Pending finding (TKT-013/TKT-014): authorization by linkedByUserId is audit data used as
    // access; it must move behind Vehicle's resource authorization in a later ticket.
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
        let device;
        try {
          device = await guardedDeviceRead(() =>
            DeviceModel.findOne({
              _id: request.params.deviceId,
              linkedByUserId: parsed.data.userId,
              status: 'ACTIVE',
            }),
          );
        } catch (error) {
          if (error instanceof DeviceServiceError && error.code === 'DATABASE_UNAVAILABLE') {
            return sendUnavailable(request, reply);
          }
          throw error;
        }
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
      routes: registerProtectedRoutes,
    });
  }
  // Link challenge/completion, key rotation and revocation have no HTTP route: no authenticated
  // caller re-authorizes the user in Vehicle yet, so exposing them would be unsafe.
  return app;
}
