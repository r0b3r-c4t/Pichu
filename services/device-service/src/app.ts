import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  deviceReferenceParamsSchema,
  deviceRegistrationRequestSchema,
  internalDeviceChallengeCreateRequestSchema,
  internalDeviceCollectionQuerySchema,
  internalDeviceLinkCompleteRequestSchema,
  internalDeviceMetadataUpdateRequestSchema,
  internalDeviceRevokeRequestSchema,
  vehicleParamsSchema,
} from '@pichu/contracts';
import { getInternalPrincipal, internalAuthPlugin } from '@pichu/internal-auth-adapters/fastify';
import type { Keyring } from '@pichu/internal-auth';
import type { NonceStore } from '@pichu/internal-auth-adapters/types';
import type { ServerOptions } from 'node:https';
import { assertDeviceDatabaseReady } from './database/bootstrap.js';
import { docsRoutes } from './routes/docs.js';
import { DevicePublicKeyError, parseDevicePublicKey } from './security/device-public-key.js';
import { DeviceServiceError } from './services/device-errors.js';
import { completeDeviceLink, createDeviceChallenge } from './services/device-link.service.js';
import { updateDeviceMetadata } from './services/device-metadata.service.js';
import {
  getInternalDeviceById,
  listInternalVehicleDevices,
} from './services/device-query.service.js';
import { registerDevice } from './services/device-registration.service.js';
import {
  revocationActorFromInternalPrincipal,
  revokeDevice,
} from './services/device-revocation.service.js';

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

const emptyQuerySchema = z.strictObject({});

function correlationId(request: FastifyRequest): string {
  const forwarded = request.headers['x-request-id'];
  return typeof forwarded === 'string' ? forwarded : request.id;
}

function sendError(
  request: FastifyRequest,
  reply: FastifyReply,
  statusCode: number,
  error: string,
  message: string,
) {
  return reply.code(statusCode).send({
    error,
    message,
    requestId: correlationId(request),
  });
}

function sendUnavailable(request: FastifyRequest, reply: FastifyReply) {
  return sendError(
    request,
    reply,
    503,
    'DEVICE_DATABASE_UNAVAILABLE',
    'Device database unavailable',
  );
}

function handleDomainError(request: FastifyRequest, reply: FastifyReply, error: unknown) {
  if (!(error instanceof DeviceServiceError)) throw error;
  switch (error.code) {
    case 'DATABASE_UNAVAILABLE':
      return sendUnavailable(request, reply);
    case 'INVALID_DEVICE_KEY':
      return sendError(request, reply, 400, 'INVALID_DEVICE_KEY', 'Invalid device key');
    case 'INVALID_PROOF':
      return sendError(request, reply, 400, 'INVALID_PROOF', 'Invalid device proof');
    case 'INVALID_REVOCATION_REQUEST':
      return sendError(
        request,
        reply,
        400,
        'INVALID_REVOCATION_REQUEST',
        'Invalid revocation request',
      );
    case 'ACTOR_MISMATCH':
    case 'UNTRUSTED_REVOCATION_ACTOR':
      return sendError(request, reply, 403, error.code, 'Enrollment or actor context mismatch');
    case 'DEVICE_NOT_FOUND':
    case 'CREDENTIAL_NOT_FOUND':
      return sendError(request, reply, 404, error.code, 'Device not found');
    case 'DEVICE_ALREADY_REGISTERED':
      return sendError(
        request,
        reply,
        409,
        'DEVICE_ALREADY_REGISTERED',
        'Device already registered',
      );
    case 'DEVICE_REVOKED':
      return sendError(request, reply, 409, 'DEVICE_REVOKED', 'Revoked devices cannot be modified');
    case 'DEVICE_NOT_LINKABLE':
    case 'UNVERIFIABLE_ENROLLMENT_CONTEXT':
    case 'INVALID_CHALLENGE':
    case 'CREDENTIAL_UNAVAILABLE':
    case 'INVALID_REVOCATION_STATE':
    case 'INCONSISTENT_DEVICE_STATE':
      return sendError(request, reply, 409, error.code, error.message);
  }
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

  const registerProtectedRoutes = async (scope: FastifyInstance) => {
    scope.post(
      '/internal/devices/register',
      { config: { internalOperation: 'deviceRegister' } },
      async (request, reply) => {
        const parsed = deviceRegistrationRequestSchema.safeParse(request.body);
        if (!parsed.success) {
          return sendError(request, reply, 400, 'VALIDATION_ERROR', 'Invalid device data');
        }
        try {
          parseDevicePublicKey(parsed.data.publicKey);
        } catch (error) {
          if (error instanceof DevicePublicKeyError) {
            return sendError(request, reply, 400, 'INVALID_DEVICE_KEY', 'Invalid device key');
          }
          throw error;
        }
        try {
          const device = await registerDevice({
            identifier: parsed.data.identifier,
            publicKey: parsed.data.publicKey,
            metadata: parsed.data.metadata,
            vehicleId: parsed.data.vehicleId,
            requestedByUserId: parsed.data.userId,
            requestedByMembershipId: parsed.data.membershipId,
          });
          return reply.code(201).send({
            deviceId: String(device.deviceId),
            status: device.status,
            data: device.record,
          });
        } catch (error) {
          return handleDomainError(request, reply, error);
        }
      },
    );

    scope.get<{ Params: { deviceId: string } }>(
      '/internal/devices/:deviceId',
      { config: { internalOperation: 'deviceDetailRead' } },
      async (request, reply) => {
        const params = deviceReferenceParamsSchema.safeParse(request.params);
        const query = emptyQuerySchema.safeParse(request.query);
        if (!params.success || !query.success) {
          return sendError(request, reply, 400, 'VALIDATION_ERROR', 'Invalid device request');
        }
        try {
          const record = await getInternalDeviceById(params.data.deviceId);
          if (!record) {
            return sendError(request, reply, 404, 'DEVICE_NOT_FOUND', 'Device not found');
          }
          return reply.code(200).send({ data: record });
        } catch (error) {
          return handleDomainError(request, reply, error);
        }
      },
    );

    scope.get<{ Params: { vehicleId: string } }>(
      '/internal/vehicles/:vehicleId/devices',
      { config: { internalOperation: 'deviceVehicleList' } },
      async (request, reply) => {
        const params = vehicleParamsSchema.safeParse(request.params);
        const query = internalDeviceCollectionQuerySchema.safeParse(request.query);
        if (!params.success || !query.success) {
          return sendError(request, reply, 400, 'VALIDATION_ERROR', 'Invalid device list request');
        }
        try {
          const page = await listInternalVehicleDevices({
            vehicleId: params.data.vehicleId,
            limit: query.data.limit,
            status: query.data.status,
            afterCreatedAt: query.data.afterCreatedAt,
            afterId: query.data.afterId,
          });
          return reply.code(200).send(page);
        } catch (error) {
          return handleDomainError(request, reply, error);
        }
      },
    );

    scope.patch<{ Params: { deviceId: string } }>(
      '/internal/devices/:deviceId',
      { config: { internalOperation: 'deviceMetadataUpdate' } },
      async (request, reply) => {
        const params = deviceReferenceParamsSchema.safeParse(request.params);
        const body = internalDeviceMetadataUpdateRequestSchema.safeParse(request.body);
        if (!params.success || !body.success) {
          return sendError(
            request,
            reply,
            400,
            'VALIDATION_ERROR',
            'Invalid device metadata update',
          );
        }
        try {
          const record = await updateDeviceMetadata({
            deviceId: params.data.deviceId,
            vehicleId: body.data.vehicleId,
            metadata: body.data.metadata,
          });
          return reply.code(200).send({ data: record });
        } catch (error) {
          return handleDomainError(request, reply, error);
        }
      },
    );

    scope.post<{ Params: { deviceId: string } }>(
      '/internal/devices/:deviceId/challenge',
      { config: { internalOperation: 'deviceChallengeCreate' } },
      async (request, reply) => {
        const params = deviceReferenceParamsSchema.safeParse(request.params);
        const body = internalDeviceChallengeCreateRequestSchema.safeParse(request.body);
        if (!params.success || !body.success) {
          return sendError(
            request,
            reply,
            400,
            'VALIDATION_ERROR',
            'Invalid challenge creation request',
          );
        }
        try {
          const outcome = await createDeviceChallenge({
            deviceId: params.data.deviceId,
            vehicleId: body.data.vehicleId,
            requestedByUserId: body.data.userId,
            requestedByMembershipId: body.data.membershipId,
          });
          if (!outcome.ok) {
            switch (outcome.reason) {
              case 'DEVICE_NOT_FOUND':
                return sendError(request, reply, 404, 'DEVICE_NOT_FOUND', 'Device not found');
              case 'ACTOR_MISMATCH':
                return sendError(
                  request,
                  reply,
                  403,
                  'ACTOR_MISMATCH',
                  'Enrollment context mismatch',
                );
              case 'DEVICE_NOT_LINKABLE':
              case 'UNVERIFIABLE_ENROLLMENT_CONTEXT':
              case 'CREDENTIAL_UNAVAILABLE':
                return sendError(
                  request,
                  reply,
                  409,
                  outcome.reason,
                  'Device cannot issue an enrollment challenge',
                );
            }
          }
          return reply.code(201).send({ data: outcome.data });
        } catch (error) {
          return handleDomainError(request, reply, error);
        }
      },
    );

    scope.post<{ Params: { deviceId: string } }>(
      '/internal/devices/:deviceId/link',
      { config: { internalOperation: 'deviceLinkComplete' } },
      async (request, reply) => {
        const params = deviceReferenceParamsSchema.safeParse(request.params);
        const body = internalDeviceLinkCompleteRequestSchema.safeParse(request.body);
        if (!params.success || !body.success) {
          return sendError(
            request,
            reply,
            400,
            'VALIDATION_ERROR',
            'Invalid link completion request',
          );
        }
        try {
          const result = await completeDeviceLink({
            deviceId: params.data.deviceId,
            vehicleId: body.data.vehicleId,
            challengeId: body.data.challengeId,
            challenge: body.data.challenge,
            signature: body.data.signature,
            actorUserId: body.data.userId,
            actorMembershipId: body.data.membershipId,
          });
          if (!result.linked) {
            switch (result.reason) {
              case 'DEVICE_NOT_FOUND':
                return sendError(request, reply, 404, 'DEVICE_NOT_FOUND', 'Device not found');
              case 'ACTOR_MISMATCH':
                return sendError(
                  request,
                  reply,
                  403,
                  'ACTOR_MISMATCH',
                  'Enrollment context mismatch',
                );
              case 'INVALID_PROOF':
                return sendError(request, reply, 400, 'INVALID_PROOF', 'Invalid device proof');
              case 'INVALID_CHALLENGE':
              case 'CREDENTIAL_UNAVAILABLE':
              case 'DEVICE_NOT_LINKABLE':
              case 'UNVERIFIABLE_ENROLLMENT_CONTEXT':
                return sendError(
                  request,
                  reply,
                  409,
                  result.reason,
                  'Device link cannot be completed',
                );
            }
          }
          return reply.code(200).send({ data: result.record });
        } catch (error) {
          return handleDomainError(request, reply, error);
        }
      },
    );

    scope.post<{ Params: { deviceId: string } }>(
      '/internal/devices/:deviceId/revoke',
      { config: { internalOperation: 'deviceRevoke' } },
      async (request, reply) => {
        const params = deviceReferenceParamsSchema.safeParse(request.params);
        const body = internalDeviceRevokeRequestSchema.safeParse(request.body);
        if (!params.success || !body.success) {
          return sendError(request, reply, 400, 'VALIDATION_ERROR', 'Invalid revocation request');
        }
        try {
          const principal = getInternalPrincipal(request);
          const actor = revocationActorFromInternalPrincipal(principal, body.data.userId);
          const outcome = await revokeDevice({
            deviceId: params.data.deviceId,
            expectedVehicleId: body.data.vehicleId,
            reason: body.data.reason,
            actor,
            requestId: principal.requestId,
          });
          if (!outcome.record) {
            throw new DeviceServiceError(
              'INCONSISTENT_DEVICE_STATE',
              'Revoked device record unavailable',
            );
          }
          return reply.code(200).send({ data: outcome.record });
        } catch (error) {
          return handleDomainError(request, reply, error);
        }
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
        deviceDetailRead: {
          method: 'GET',
          route: '/internal/devices/:deviceId',
          senders: ['vehicle-service'],
        },
        deviceVehicleList: {
          method: 'GET',
          route: '/internal/vehicles/:vehicleId/devices',
          senders: ['vehicle-service'],
        },
        deviceMetadataUpdate: {
          method: 'PATCH',
          route: '/internal/devices/:deviceId',
          senders: ['vehicle-service'],
        },
        deviceChallengeCreate: {
          method: 'POST',
          route: '/internal/devices/:deviceId/challenge',
          senders: ['vehicle-service'],
        },
        deviceLinkComplete: {
          method: 'POST',
          route: '/internal/devices/:deviceId/link',
          senders: ['vehicle-service'],
        },
        deviceRevoke: {
          method: 'POST',
          route: '/internal/devices/:deviceId/revoke',
          senders: ['vehicle-service'],
        },
      },
      routes: registerProtectedRoutes,
    });
  }

  return app;
}
