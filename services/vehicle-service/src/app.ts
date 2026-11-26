import Fastify, { type FastifyInstance } from 'fastify';
import { z } from 'zod';
import { Types } from 'mongoose';
import { MembershipModel } from './models/membership.model.js';
import {
  acceptInvitation,
  createVehicle,
  getVehicleForUser,
  inviteMember,
  listOwnedVehicles,
} from './services/vehicle.service.js';
import { loadEnv, parseInternalKeyring } from './config/env.js';
import { signedHeaders } from './security/internal-v2.js';
import { requireVerifiedEmail } from './security/email-verification.js';
import { docsRoutes } from './routes/docs.js';
import {
  invitationPublicData,
  membershipPublicData,
  vehiclePublicData,
} from './schemas/vehicle-response.schema.js';
import { internalAuthPlugin } from '@pichu/internal-auth-adapters/fastify';
import type { Keyring } from '@pichu/internal-auth';
import type { NonceStore } from '@pichu/internal-auth-adapters/types';
import type { ServerOptions } from 'node:https';
import { internalJsonRequest } from '@pichu/internal-auth-adapters/tls';

export interface VehicleAppDependencies {
  internalAuth: {
    environment: 'development' | 'test' | 'staging' | 'production';
    keyring: Keyring;
    nonces: NonceStore;
    bodyLimit?: number;
  };
  https?: ServerOptions;
}

function responseRequestId(request: { id: string; headers: Record<string, unknown> }): string {
  const forwarded = request.headers['x-request-id'];
  return typeof forwarded === 'string' ? forwarded : request.id;
}

export function createApp(dependencies?: VehicleAppDependencies): FastifyInstance {
  const app = Fastify({
    logger: true,
    ...(dependencies?.https ? { https: dependencies.https } : {}),
  });
  app.get('/health', async () => ({ status: 'ok', service: 'vehicle-service' }));
  app.get('/health/ready', async (_request, reply) => {
    if (!dependencies?.internalAuth) return reply.code(503).send({ status: 'unready' });
    try {
      await dependencies.internalAuth.nonces.assertReady();
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
        const parsed = z
          .object({
            userId: z.string().regex(/^[a-f0-9]{24}$/),
            name: z.string().trim().min(1).max(120),
            make: z.string().trim().max(80).nullable().optional(),
            model: z.string().trim().max(80).nullable().optional(),
            year: z.number().int().min(1886).max(2100).nullable().optional(),
            engine: z.string().trim().max(40).nullable().optional(),
          })
          .safeParse(request.body);
        if (!parsed.success) return reply.code(400).send({ message: 'Invalid vehicle data' });
        if (!(await requireVerifiedEmail(request, reply, parsed.data.userId))) return;
        const vehicle = await createVehicle(new Types.ObjectId(parsed.data.userId), parsed.data);
        return reply.code(201).send({
          vehicleId: String(vehicle._id),
          message: 'Vehicle created',
          data: vehiclePublicData(vehicle),
          requestId: responseRequestId(request),
        });
      },
    );
    scope.get(
      '/vehicles',
      { config: { internalOperation: 'vehicleList' } },
      async (request, reply) => {
        const parsed = z
          .object({ userId: z.string().regex(/^[a-f0-9]{24}$/) })
          .safeParse(request.query);
        if (!parsed.success) return reply.code(400).send({ message: 'Invalid user id' });
        if (!(await requireVerifiedEmail(request, reply, parsed.data.userId))) return;
        const vehicles = await listOwnedVehicles(new Types.ObjectId(parsed.data.userId));
        return { vehicles: vehicles.map(vehiclePublicData), requestId: responseRequestId(request) };
      },
    );
    scope.get<{ Params: { vehicleId: string } }>(
      '/vehicles/:vehicleId',
      { config: { internalOperation: 'vehicleGet' } },
      async (request, reply) => {
        const parsed = z
          .object({ userId: z.string().regex(/^[a-f0-9]{24}$/) })
          .safeParse(request.query);
        if (!parsed.success || !Types.ObjectId.isValid(request.params.vehicleId))
          return reply.code(400).send({ message: 'Invalid vehicle request' });
        if (!(await requireVerifiedEmail(request, reply, parsed.data.userId))) return;
        const vehicle = await getVehicleForUser(
          new Types.ObjectId(request.params.vehicleId),
          new Types.ObjectId(parsed.data.userId),
        );
        if (!vehicle) return reply.code(404).send({ message: 'Vehicle not found' });
        return { ...vehiclePublicData(vehicle), requestId: responseRequestId(request) };
      },
    );
    scope.post<{ Params: { vehicleId: string } }>(
      '/vehicles/:vehicleId/invitations',
      { config: { internalOperation: 'invitationCreate' } },
      async (request, reply) => {
        const parsed = z
          .object({
            inviterUserId: z.string().regex(/^[a-f0-9]{24}$/),
            inviteeUserId: z.string().regex(/^[a-f0-9]{24}$/),
            permissions: z.array(z.string().trim().min(1).max(64)).max(100),
          })
          .safeParse(request.body);
        if (!parsed.success || !Types.ObjectId.isValid(request.params.vehicleId))
          return reply.code(400).send({ message: 'Invalid invitation data' });
        if (!(await requireVerifiedEmail(request, reply, parsed.data.inviterUserId))) return;
        const identityUrl = `${process.env.IDENTITY_SERVICE_URL ?? 'http://127.0.0.1:3001'}/internal/users/${parsed.data.inviteeUserId}/exists`;
        const identityPath = new URL(identityUrl).pathname;
        const env = loadEnv();
        const authorization =
          typeof request.headers.authorization === 'string'
            ? request.headers.authorization
            : undefined;
        const identityHeaders = signedHeaders(
          {
            environment: env.INTERNAL_AUTH_ENVIRONMENT,
            keyring: parseInternalKeyring(env),
            sender: 'vehicle-service',
          },
          'identity-service',
          'GET',
          identityPath,
          Buffer.alloc(0),
          authorization,
        );
        const identityResponse = await internalJsonRequest({
          url: identityUrl,
          signal: AbortSignal.timeout(4_000),
          headers: identityHeaders,
          timeoutMs: 4_000,
          tls: { caPath: process.env.TLS_CA_PATH ?? '' },
        });
        if (identityResponse.status < 200 || identityResponse.status >= 300)
          return reply.code(503).send({ message: 'Identity service unavailable' });
        const identity = identityResponse.body as { exists?: boolean };
        if (!identity.exists) return reply.code(404).send({ message: 'User not found' });
        const invitation = await inviteMember(
          new Types.ObjectId(request.params.vehicleId),
          new Types.ObjectId(parsed.data.inviterUserId),
          new Types.ObjectId(parsed.data.inviteeUserId),
          parsed.data.permissions,
        );
        if (!invitation) return reply.code(404).send({ message: 'Vehicle not found' });
        return reply.code(201).send({
          invitationId: String(invitation._id),
          status: invitation.status,
          message: 'Invitation created',
          data: invitationPublicData(invitation),
          requestId: responseRequestId(request),
        });
      },
    );
    scope.post<{ Params: { invitationId: string } }>(
      '/invitations/:invitationId/accept',
      { config: { internalOperation: 'invitationAccept' } },
      async (request, reply) => {
        const parsed = z
          .object({ userId: z.string().regex(/^[a-f0-9]{24}$/) })
          .safeParse(request.body);
        if (!parsed.success || !Types.ObjectId.isValid(request.params.invitationId))
          return reply.code(400).send({ message: 'Invalid invitation data' });
        if (!(await requireVerifiedEmail(request, reply, parsed.data.userId))) return;
        const membership = await acceptInvitation(
          new Types.ObjectId(request.params.invitationId),
          new Types.ObjectId(parsed.data.userId),
        );
        if (!membership) return reply.code(404).send({ message: 'Invitation not found' });
        return {
          accepted: true,
          vehicleId: String(membership.vehicleId),
          message: 'Invitation accepted',
          data: membershipPublicData(membership),
          requestId: responseRequestId(request),
        };
      },
    );
    scope.post<{ Params: { vehicleId: string } }>(
      '/vehicles/:vehicleId/devices/link',
      { config: { internalOperation: 'deviceLink' } },
      async (request, reply) => {
        const parsed = z
          .object({
            userId: z.string().regex(/^[a-f0-9]{24}$/),
            deviceIdentifier: z.string().trim().min(1).max(128),
            publicKey: z.string().trim().min(32).max(4096),
          })
          .safeParse(request.body);
        if (!parsed.success || !Types.ObjectId.isValid(request.params.vehicleId)) {
          return reply.code(400).send({ message: 'Invalid linking data' });
        }
        if (!(await requireVerifiedEmail(request, reply, parsed.data.userId))) return;
        const vehicleId = request.params.vehicleId;
        const identityUrl = `${process.env.IDENTITY_SERVICE_URL ?? 'http://127.0.0.1:3001'}/internal/users/${parsed.data.userId}/exists`;
        const identityPath = new URL(identityUrl).pathname;
        const env = loadEnv();
        const authorization =
          typeof request.headers.authorization === 'string'
            ? request.headers.authorization
            : undefined;
        const identityHeaders = signedHeaders(
          {
            environment: env.INTERNAL_AUTH_ENVIRONMENT,
            keyring: parseInternalKeyring(env),
            sender: 'vehicle-service',
          },
          'identity-service',
          'GET',
          identityPath,
          Buffer.alloc(0),
          authorization,
        );
        const identityResponse = await internalJsonRequest({
          url: identityUrl,
          signal: AbortSignal.timeout(4_000),
          headers: identityHeaders,
          timeoutMs: 4_000,
          tls: { caPath: process.env.TLS_CA_PATH ?? '' },
        });
        if (identityResponse.status < 200 || identityResponse.status >= 300)
          return reply.code(503).send({ message: 'Identity service unavailable' });
        const identity = identityResponse.body as { exists?: boolean };
        if (!identity.exists) return reply.code(404).send({ message: 'User or vehicle not found' });
        const membership = await MembershipModel.findOne({ vehicleId, userId: parsed.data.userId });
        if (
          !membership ||
          (membership.role !== 'OWNER' && !membership.permissions.includes('vehicle:manage'))
        ) {
          return reply.code(404).send({ message: 'User or vehicle not found' });
        }
        const body = {
          identifier: parsed.data.deviceIdentifier,
          publicKey: parsed.data.publicKey,
          vehicleId,
          userId: parsed.data.userId,
        };
        const deviceUrl = `${process.env.DEVICE_SERVICE_URL ?? 'http://127.0.0.1:3003'}/internal/devices/register`;
        const devicePath = new URL(deviceUrl).pathname;
        const deviceHeaders = signedHeaders(
          {
            environment: env.INTERNAL_AUTH_ENVIRONMENT,
            keyring: parseInternalKeyring(env),
            sender: 'vehicle-service',
          },
          'device-service',
          'POST',
          devicePath,
          Buffer.from(JSON.stringify(body)),
          authorization,
        );
        const deviceResponse = await internalJsonRequest({
          url: deviceUrl,
          method: 'POST',
          signal: AbortSignal.timeout(4_000),
          headers: deviceHeaders,
          body: Buffer.from(JSON.stringify(body)),
          timeoutMs: 4_000,
          tls: { caPath: process.env.TLS_CA_PATH ?? '' },
        });
        if (deviceResponse.status < 200 || deviceResponse.status >= 300)
          return reply.code(503).send({ message: 'Device service unavailable' });
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
  if (dependencies)
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
  return app;
}
