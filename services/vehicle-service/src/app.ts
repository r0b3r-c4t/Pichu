import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { z } from 'zod';
import mongoose, { Types } from 'mongoose';
import {
  acceptInvitation,
  canLinkDeviceToVehicle,
  createVehicle,
  getVehicleForUser,
  inviteMember,
  listOwnedVehicles,
  VehicleServiceError,
  type VehicleAuditLogger,
} from './services/vehicle.service.js';
import { loadEnv, parseInternalKeyring } from './config/env.js';
import {
  executeSignedInternalRequest,
  OutboundDeadlineExceededError,
  type InternalClientConfig,
} from './security/internal-v2.js';
import { requireVerifiedEmail } from './security/email-verification.js';
import { docsRoutes } from './routes/docs.js';
import {
  invitationPublicData,
  membershipPublicData,
  vehiclePublicData,
} from './schemas/vehicle-response.schema.js';
import { checkDatabaseConnection } from './database/connection.js';
import { assertCriticalVehicleIndexes } from './database/bootstrap.js';
import { internalAuthPlugin } from '@pichu/internal-auth-adapters/fastify';
import type { KeyEntry, Keyring } from '@pichu/internal-auth';
import type { NonceStore } from '@pichu/internal-auth-adapters/types';
import type { ServerOptions } from 'node:https';

export interface VehicleRuntimeConfig {
  readonly identityServiceUrl: string;
  readonly deviceServiceUrl: string;
  readonly invitationTtlMs: number;
  readonly tlsCaPath?: string;
  readonly outboundKeyring: Keyring;
}

export interface VehicleAppDependencies {
  internalAuth: {
    environment: 'development' | 'test' | 'staging' | 'production';
    keyring: Keyring;
    nonces: NonceStore;
    bodyLimit?: number;
  };
  runtimeConfig?: VehicleRuntimeConfig;
  readinessCheck?: () => Promise<void>;
  https?: ServerOptions;
}

export async function assertVehicleDatabaseReady(
  client: typeof mongoose = mongoose,
): Promise<void> {
  const connected = await checkDatabaseConnection();
  if (!connected || !client.connection.db) {
    throw new Error('Vehicle database connection is unavailable');
  }
  await assertCriticalVehicleIndexes(client.connection.db);
}

function responseRequestId(request: { id: string; headers: Record<string, unknown> }): string {
  const forwarded = request.headers['x-request-id'];
  return typeof forwarded === 'string' ? forwarded : request.id;
}

function createRequestAuditLogger(request: FastifyRequest): VehicleAuditLogger {
  const requestId = responseRequestId(request);
  return (event) => {
    const payload = {
      audit: true,
      requestId,
      action: event.action,
      actorUserId: event.actorUserId,
      ...(event.vehicleId ? { vehicleId: event.vehicleId } : {}),
      ...(event.targetId ? { targetId: event.targetId } : {}),
      outcome: event.outcome,
      ...(event.reason ? { reason: event.reason } : {}),
    };
    if (event.outcome === 'success') {
      request.log.info(payload, 'Vehicle domain audit event');
    } else {
      request.log.warn(payload, 'Vehicle domain audit event');
    }
  };
}

function sendDomainError(reply: FastifyReply, request: FastifyRequest, error: VehicleServiceError) {
  const requestId = responseRequestId(request);
  const statusByCode = {
    VALIDATION_ERROR: 400,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    CONFLICT: 409,
    DATABASE_UNAVAILABLE: 503,
  } as const;
  const status = statusByCode[error.code];
  const publicErrorCode =
    error.code === 'DATABASE_UNAVAILABLE' ? 'SERVICE_UNAVAILABLE' : error.code;
  const publicMessage =
    error.code === 'DATABASE_UNAVAILABLE' ? 'Vehicle database unavailable' : error.message;
  return reply.code(status).send({
    error: publicErrorCode,
    message: publicMessage,
    requestId,
  });
}

const vehicleCreateInputSchema = z.strictObject({
  userId: z.string().regex(/^[a-f0-9]{24}$/),
  name: z.string().trim().min(1).max(120),
  make: z.string().trim().max(80).nullable().optional(),
  model: z.string().trim().max(80).nullable().optional(),
  generation: z.string().trim().max(60).nullable().optional(),
  trim: z.string().trim().max(80).nullable().optional(),
  year: z.number().int().min(1886).max(2100).nullable().optional(),
  bodyStyle: z.string().trim().max(60).nullable().optional(),
  engine: z.string().trim().max(80).nullable().optional(),
  transmission: z.string().trim().max(60).nullable().optional(),
  fuelType: z.string().trim().max(60).nullable().optional(),
});

const vehicleListQueryInputSchema = z.strictObject({
  userId: z.string().regex(/^[a-f0-9]{24}$/),
  limit: z.coerce.number().int().min(1).max(100).optional(),
  cursor: z.string().trim().min(1).max(256).optional(),
});

const vehicleGetQueryInputSchema = z.strictObject({
  userId: z.string().regex(/^[a-f0-9]{24}$/),
});

const invitationCreateInputSchema = z.strictObject({
  inviterUserId: z.string().regex(/^[a-f0-9]{24}$/),
  inviteeUserId: z.string().regex(/^[a-f0-9]{24}$/),
  permissions: z.array(z.string().trim().min(1).max(64)).max(100),
});

const invitationAcceptInputSchema = z.strictObject({
  userId: z.string().regex(/^[a-f0-9]{24}$/),
});

const deviceLinkInputSchema = z.strictObject({
  userId: z.string().regex(/^[a-f0-9]{24}$/),
  deviceIdentifier: z.string().trim().min(1).max(128),
  publicKey: z.string().trim().min(32).max(4096),
});

export function createApp(dependencies?: VehicleAppDependencies): FastifyInstance {
  const app = Fastify({
    logger: true,
    ...(dependencies?.https ? { https: dependencies.https } : {}),
  });

  let cachedRuntimeConfig: VehicleRuntimeConfig | undefined = dependencies?.runtimeConfig;

  const resolveRuntimeConfig = (): VehicleRuntimeConfig => {
    if (cachedRuntimeConfig) {
      return cachedRuntimeConfig;
    }
    const env = loadEnv();
    const envKeyring = parseInternalKeyring(env);
    const seenKeys = new Set<string>();
    const mergedKeyring: KeyEntry[] = [];
    for (const entry of [...envKeyring, ...(dependencies?.internalAuth.keyring ?? [])]) {
      const id = `${entry.environment}:${entry.sender}:${entry.audience}:${entry.keyId}`;
      if (!seenKeys.has(id)) {
        seenKeys.add(id);
        mergedKeyring.push(entry);
      }
    }
    cachedRuntimeConfig = {
      identityServiceUrl: env.IDENTITY_SERVICE_URL,
      deviceServiceUrl: env.DEVICE_SERVICE_URL,
      invitationTtlMs: env.INVITATION_TTL_SECONDS * 1_000,
      tlsCaPath: env.TLS_CA_PATH,
      outboundKeyring: mergedKeyring,
    };
    return cachedRuntimeConfig;
  };

  const buildOutboundClientConfig = (runtime: VehicleRuntimeConfig): InternalClientConfig => ({
    environment: dependencies!.internalAuth.environment,
    keyring: runtime.outboundKeyring,
    sender: 'vehicle-service',
    identityServiceUrl: runtime.identityServiceUrl,
    deviceServiceUrl: runtime.deviceServiceUrl,
    tlsCaPath: runtime.tlsCaPath,
  });

  const readinessCheck = dependencies?.readinessCheck ?? (() => assertVehicleDatabaseReady());

  app.get('/health', async () => ({ status: 'ok', service: 'vehicle-service' }));
  app.get('/health/live', async () => ({ status: 'ok', service: 'vehicle-service' }));
  app.get('/health/ready', async (_request, reply) => {
    if (!dependencies?.internalAuth) {
      return reply.code(503).send({ status: 'unready', service: 'vehicle-service' });
    }
    try {
      await Promise.all([dependencies.internalAuth.nonces.assertReady(), readinessCheck()]);
      return { status: 'ready', service: 'vehicle-service' };
    } catch {
      return reply.code(503).send({ status: 'unready', service: 'vehicle-service' });
    }
  });

  void app.register(docsRoutes);

  const registerProtectedRoutes = async (scope: FastifyInstance) => {
    scope.post(
      '/vehicles',
      { config: { internalOperation: 'vehicleCreate' } },
      async (request, reply) => {
        const parsed = vehicleCreateInputSchema.safeParse(request.body);
        if (!parsed.success) {
          return reply.code(400).send({ message: 'Invalid vehicle data' });
        }
        const runtime = resolveRuntimeConfig();
        const clientConfig = buildOutboundClientConfig(runtime);
        if (!(await requireVerifiedEmail(request, reply, parsed.data.userId, clientConfig))) {
          return;
        }

        try {
          const vehicle = await createVehicle(new Types.ObjectId(parsed.data.userId), parsed.data, {
            audit: createRequestAuditLogger(request),
          });
          return reply.code(201).send({
            vehicleId: String(vehicle._id),
            message: 'Vehicle created',
            data: vehiclePublicData(vehicle),
            requestId: responseRequestId(request),
          });
        } catch (error) {
          if (error instanceof VehicleServiceError) {
            return sendDomainError(reply, request, error);
          }
          throw error;
        }
      },
    );

    scope.get(
      '/vehicles',
      { config: { internalOperation: 'vehicleList' } },
      async (request, reply) => {
        const parsed = vehicleListQueryInputSchema.safeParse(request.query);
        if (!parsed.success) {
          return reply.code(400).send({ message: 'Invalid user id' });
        }
        const runtime = resolveRuntimeConfig();
        const clientConfig = buildOutboundClientConfig(runtime);
        if (!(await requireVerifiedEmail(request, reply, parsed.data.userId, clientConfig))) {
          return;
        }
        const vehicles = await listOwnedVehicles(new Types.ObjectId(parsed.data.userId));
        return { vehicles: vehicles.map(vehiclePublicData), requestId: responseRequestId(request) };
      },
    );

    scope.get<{ Params: { vehicleId: string } }>(
      '/vehicles/:vehicleId',
      { config: { internalOperation: 'vehicleGet' } },
      async (request, reply) => {
        const parsed = vehicleGetQueryInputSchema.safeParse(request.query);
        if (!parsed.success || !Types.ObjectId.isValid(request.params.vehicleId)) {
          return reply.code(400).send({ message: 'Invalid vehicle request' });
        }
        const runtime = resolveRuntimeConfig();
        const clientConfig = buildOutboundClientConfig(runtime);
        if (!(await requireVerifiedEmail(request, reply, parsed.data.userId, clientConfig))) {
          return;
        }
        const vehicle = await getVehicleForUser(
          new Types.ObjectId(request.params.vehicleId),
          new Types.ObjectId(parsed.data.userId),
        );
        if (!vehicle) {
          return reply.code(404).send({ message: 'Vehicle not found' });
        }
        return { ...vehiclePublicData(vehicle), requestId: responseRequestId(request) };
      },
    );

    scope.post<{ Params: { vehicleId: string } }>(
      '/vehicles/:vehicleId/invitations',
      { config: { internalOperation: 'invitationCreate' } },
      async (request, reply) => {
        const parsed = invitationCreateInputSchema.safeParse(request.body);
        if (!parsed.success || !Types.ObjectId.isValid(request.params.vehicleId)) {
          return reply.code(400).send({ message: 'Invalid invitation data' });
        }
        if (parsed.data.inviterUserId === parsed.data.inviteeUserId) {
          return reply.code(400).send({ message: 'Self-invitations are not allowed' });
        }

        const runtime = resolveRuntimeConfig();
        const clientConfig = buildOutboundClientConfig(runtime);
        if (
          !(await requireVerifiedEmail(request, reply, parsed.data.inviterUserId, clientConfig))
        ) {
          return;
        }

        const identityPath = `/internal/users/${parsed.data.inviteeUserId}/exists`;
        let identityResponse;
        try {
          identityResponse = await executeSignedInternalRequest(request, clientConfig, {
            audience: 'identity-service',
            baseUrl: runtime.identityServiceUrl,
            method: 'GET',
            path: identityPath,
          });
        } catch (error) {
          if (error instanceof OutboundDeadlineExceededError) {
            return reply.code(504).send({ message: 'Identity service timed out' });
          }
          return reply.code(503).send({ message: 'Identity service unavailable' });
        }

        if (identityResponse.status === 504) {
          return reply.code(504).send({ message: 'Identity service timed out' });
        }
        if (identityResponse.status < 200 || identityResponse.status >= 300) {
          return reply.code(503).send({ message: 'Identity service unavailable' });
        }
        const identity = identityResponse.body as { exists?: boolean };
        if (!identity.exists) {
          return reply.code(404).send({ message: 'User not found' });
        }

        try {
          const invitation = await inviteMember(
            new Types.ObjectId(request.params.vehicleId),
            new Types.ObjectId(parsed.data.inviterUserId),
            new Types.ObjectId(parsed.data.inviteeUserId),
            parsed.data.permissions,
            {
              ttlMs: runtime.invitationTtlMs,
              audit: createRequestAuditLogger(request),
            },
          );
          if (!invitation) {
            return reply.code(404).send({ message: 'Vehicle not found' });
          }
          return reply.code(201).send({
            invitationId: String(invitation._id),
            status: invitation.status,
            message: 'Invitation created',
            data: invitationPublicData(invitation),
            requestId: responseRequestId(request),
          });
        } catch (error) {
          if (error instanceof VehicleServiceError) {
            return sendDomainError(reply, request, error);
          }
          throw error;
        }
      },
    );

    scope.post<{ Params: { invitationId: string } }>(
      '/invitations/:invitationId/accept',
      { config: { internalOperation: 'invitationAccept' } },
      async (request, reply) => {
        const parsed = invitationAcceptInputSchema.safeParse(request.body);
        if (!parsed.success || !Types.ObjectId.isValid(request.params.invitationId)) {
          return reply.code(400).send({ message: 'Invalid invitation data' });
        }
        const runtime = resolveRuntimeConfig();
        const clientConfig = buildOutboundClientConfig(runtime);
        if (!(await requireVerifiedEmail(request, reply, parsed.data.userId, clientConfig))) {
          return;
        }

        try {
          const membership = await acceptInvitation(
            new Types.ObjectId(request.params.invitationId),
            new Types.ObjectId(parsed.data.userId),
            { audit: createRequestAuditLogger(request) },
          );
          if (!membership) {
            return reply.code(404).send({ message: 'Invitation not found' });
          }
          return {
            accepted: true,
            vehicleId: String(membership.vehicleId),
            message: 'Invitation accepted',
            data: membershipPublicData(membership),
            requestId: responseRequestId(request),
          };
        } catch (error) {
          if (error instanceof VehicleServiceError) {
            return sendDomainError(reply, request, error);
          }
          throw error;
        }
      },
    );

    scope.post<{ Params: { vehicleId: string } }>(
      '/vehicles/:vehicleId/devices/link',
      { config: { internalOperation: 'deviceLink' } },
      async (request, reply) => {
        const parsed = deviceLinkInputSchema.safeParse(request.body);
        if (!parsed.success || !Types.ObjectId.isValid(request.params.vehicleId)) {
          return reply.code(400).send({ message: 'Invalid linking data' });
        }
        const runtime = resolveRuntimeConfig();
        const clientConfig = buildOutboundClientConfig(runtime);
        if (!(await requireVerifiedEmail(request, reply, parsed.data.userId, clientConfig))) {
          return;
        }

        const vehicleId = request.params.vehicleId;
        const identityPath = `/internal/users/${parsed.data.userId}/exists`;
        let identityResponse;
        try {
          identityResponse = await executeSignedInternalRequest(request, clientConfig, {
            audience: 'identity-service',
            baseUrl: runtime.identityServiceUrl,
            method: 'GET',
            path: identityPath,
          });
        } catch (error) {
          if (error instanceof OutboundDeadlineExceededError) {
            return reply.code(504).send({ message: 'Identity service timed out' });
          }
          return reply.code(503).send({ message: 'Identity service unavailable' });
        }

        if (identityResponse.status === 504) {
          return reply.code(504).send({ message: 'Identity service timed out' });
        }
        if (identityResponse.status < 200 || identityResponse.status >= 300) {
          return reply.code(503).send({ message: 'Identity service unavailable' });
        }
        const identity = identityResponse.body as { exists?: boolean };
        if (!identity.exists) {
          return reply.code(404).send({ message: 'User or vehicle not found' });
        }

        const allowed = await canLinkDeviceToVehicle(
          new Types.ObjectId(vehicleId),
          new Types.ObjectId(parsed.data.userId),
        );
        if (!allowed) {
          createRequestAuditLogger(request)({
            action: 'device.link_authorize',
            actorUserId: parsed.data.userId,
            vehicleId,
            outcome: 'denied',
            reason: 'insufficient_vehicle_authorization',
          });
          return reply.code(404).send({ message: 'User or vehicle not found' });
        }

        const body = {
          identifier: parsed.data.deviceIdentifier,
          publicKey: parsed.data.publicKey,
          vehicleId,
          userId: parsed.data.userId,
        };
        const payloadBytes = Buffer.from(JSON.stringify(body));

        let deviceResponse;
        try {
          deviceResponse = await executeSignedInternalRequest(request, clientConfig, {
            audience: 'device-service',
            baseUrl: runtime.deviceServiceUrl,
            method: 'POST',
            path: '/internal/devices/register',
            body: payloadBytes,
          });
        } catch (error) {
          if (error instanceof OutboundDeadlineExceededError) {
            return reply.code(504).send({ message: 'Device service timed out' });
          }
          return reply.code(503).send({ message: 'Device service unavailable' });
        }

        if (deviceResponse.status === 504) {
          return reply.code(504).send({ message: 'Device service timed out' });
        }
        if (deviceResponse.status < 200 || deviceResponse.status >= 300) {
          return reply.code(503).send({ message: 'Device service unavailable' });
        }

        const deviceResult: unknown = deviceResponse.body;
        if (
          typeof deviceResult !== 'object' ||
          deviceResult === null ||
          !('deviceId' in deviceResult) ||
          typeof deviceResult.deviceId !== 'string' ||
          !Types.ObjectId.isValid(deviceResult.deviceId) ||
          !('status' in deviceResult) ||
          deviceResult.status !== 'PENDING'
        ) {
          return reply.code(503).send({ message: 'Device service unavailable' });
        }

        createRequestAuditLogger(request)({
          action: 'device.link_authorize',
          actorUserId: parsed.data.userId,
          vehicleId,
          targetId: deviceResult.deviceId,
          outcome: 'success',
        });

        return reply.code(201).send({
          deviceId: deviceResult.deviceId,
          status: deviceResult.status,
          message: 'Device registration accepted',
          data: { deviceId: deviceResult.deviceId, vehicleId, status: deviceResult.status },
          requestId: responseRequestId(request),
        });
      },
    );
  };

  if (dependencies) {
    void app.register(internalAuthPlugin, {
      environment: dependencies.internalAuth.environment,
      audience: 'vehicle-service',
      keyring: () => dependencies.internalAuth.keyring,
      nonces: dependencies.internalAuth.nonces,
      bodyLimit: dependencies.internalAuth.bodyLimit,
      policies: {
        vehicleCreate: { method: 'POST', route: '/vehicles', senders: ['api-gateway'] },
        vehicleList: { method: 'GET', route: '/vehicles', senders: ['api-gateway'] },
        vehicleGet: { method: 'GET', route: '/vehicles/:vehicleId', senders: ['api-gateway'] },
        invitationCreate: {
          method: 'POST',
          route: '/vehicles/:vehicleId/invitations',
          senders: ['api-gateway'],
        },
        invitationAccept: {
          method: 'POST',
          route: '/invitations/:invitationId/accept',
          senders: ['api-gateway'],
        },
        deviceLink: {
          method: 'POST',
          route: '/vehicles/:vehicleId/devices/link',
          senders: ['api-gateway'],
        },
      },
      routes: registerProtectedRoutes,
    });
  }

  return app;
}
