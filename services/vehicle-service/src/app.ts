import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { z } from 'zod';
import mongoose, { Types } from 'mongoose';
import {
  internalInvitationCreateRequestSchema,
  internalInvitationRevokeRequestSchema,
  internalMemberLeaveRequestSchema,
  internalMemberListQuerySchema,
  internalMemberPermissionsUpdateRequestSchema,
  internalMemberReactivateRequestSchema,
  internalMemberTransitionRequestSchema,
  internalReceivedInvitationListQuerySchema,
  internalVehicleArchiveRequestSchema,
  internalVehicleCreateRequestSchema,
  internalVehicleGetQuerySchema,
  internalVehicleInvitationListQuerySchema,
  internalVehicleListQuerySchema,
  internalVehicleUpdateRequestSchema,
  invitationAcceptRequestSchema,
  invitationParamsSchema,
  invitationRevokeParamsSchema,
  memberParamsSchema,
  vehicleParamsSchema,
} from '@pichu/contracts';
import {
  acceptInvitation,
  archiveVehicle,
  canLinkDeviceToVehicle,
  createVehicle,
  getAccessibleVehicle,
  inviteMember,
  leaveVehicle,
  listAccessibleVehicles,
  listReceivedInvitations,
  listVehicleInvitations,
  listVehicleMembers,
  reactivateMembership,
  revokeInvitation,
  revokeMembership,
  suspendMembership,
  updateMembershipPermissions,
  updateVehicle,
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
  invitationAdminViewData,
  memberViewData,
  membershipPublicData,
  receivedInvitationViewData,
  vehicleAccessPublicData,
  vehicleArchivePublicData,
  vehicleOwnerPublicData,
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

function sendValidationError(reply: FastifyReply, request: FastifyRequest, message: string) {
  return reply.code(400).send({
    error: 'VALIDATION_ERROR',
    message,
    requestId: responseRequestId(request),
  });
}

/** Identity could not confirm the invitee; mapped to 503/504 without disclosing existence. */
class InviteeLookupError extends Error {
  constructor(public readonly status: 503 | 504) {
    super('Invitee lookup failed');
    this.name = 'InviteeLookupError';
  }
}

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
        const parsed = internalVehicleCreateRequestSchema.safeParse(request.body);
        if (!parsed.success) {
          return sendValidationError(reply, request, 'Invalid vehicle data');
        }
        const runtime = resolveRuntimeConfig();
        const clientConfig = buildOutboundClientConfig(runtime);
        if (!(await requireVerifiedEmail(request, reply, parsed.data.userId, clientConfig))) {
          return;
        }

        const { userId, ...fields } = parsed.data;
        try {
          const vehicle = await createVehicle(new Types.ObjectId(userId), fields, {
            audit: createRequestAuditLogger(request),
          });
          return reply.code(201).send({
            vehicleId: String(vehicle._id),
            message: 'Vehicle created',
            data: vehicleOwnerPublicData(vehicle),
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
        const parsed = internalVehicleListQuerySchema.safeParse(request.query);
        if (!parsed.success) {
          return sendValidationError(reply, request, 'Invalid vehicle query');
        }
        const runtime = resolveRuntimeConfig();
        const clientConfig = buildOutboundClientConfig(runtime);
        if (!(await requireVerifiedEmail(request, reply, parsed.data.userId, clientConfig))) {
          return;
        }
        try {
          const page = await listAccessibleVehicles(new Types.ObjectId(parsed.data.userId), {
            limit: parsed.data.limit,
            cursor: parsed.data.cursor,
            role: parsed.data.role,
          });
          return {
            vehicles: page.items.map((item) => vehicleAccessPublicData(item.vehicle, item.role)),
            page: { nextCursor: page.nextCursor },
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

    scope.get<{ Params: { vehicleId: string } }>(
      '/vehicles/:vehicleId',
      { config: { internalOperation: 'vehicleGet' } },
      async (request, reply) => {
        const params = vehicleParamsSchema.safeParse(request.params);
        const parsed = internalVehicleGetQuerySchema.safeParse(request.query);
        if (!params.success || !parsed.success) {
          return sendValidationError(reply, request, 'Invalid vehicle request');
        }
        const runtime = resolveRuntimeConfig();
        const clientConfig = buildOutboundClientConfig(runtime);
        if (!(await requireVerifiedEmail(request, reply, parsed.data.userId, clientConfig))) {
          return;
        }
        try {
          const accessible = await getAccessibleVehicle(
            new Types.ObjectId(params.data.vehicleId),
            new Types.ObjectId(parsed.data.userId),
            { audit: createRequestAuditLogger(request) },
          );
          return {
            ...vehicleAccessPublicData(accessible.vehicle, accessible.role),
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

    scope.patch<{ Params: { vehicleId: string } }>(
      '/vehicles/:vehicleId',
      { config: { internalOperation: 'vehicleUpdate' } },
      async (request, reply) => {
        const params = vehicleParamsSchema.safeParse(request.params);
        const parsed = internalVehicleUpdateRequestSchema.safeParse(request.body);
        if (!params.success || !parsed.success) {
          return sendValidationError(reply, request, 'Invalid vehicle data');
        }
        const runtime = resolveRuntimeConfig();
        const clientConfig = buildOutboundClientConfig(runtime);
        if (!(await requireVerifiedEmail(request, reply, parsed.data.userId, clientConfig))) {
          return;
        }

        const { userId, ...changes } = parsed.data;
        try {
          const vehicle = await updateVehicle({
            vehicleId: new Types.ObjectId(params.data.vehicleId),
            actorUserId: new Types.ObjectId(userId),
            changes,
            audit: createRequestAuditLogger(request),
          });
          return {
            vehicleId: String(vehicle._id),
            message: 'Vehicle updated',
            data: vehicleOwnerPublicData(vehicle),
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

    scope.delete<{ Params: { vehicleId: string } }>(
      '/vehicles/:vehicleId',
      { config: { internalOperation: 'vehicleArchive' } },
      async (request, reply) => {
        const params = vehicleParamsSchema.safeParse(request.params);
        const parsed = internalVehicleArchiveRequestSchema.safeParse(request.body);
        if (!params.success || !parsed.success) {
          return sendValidationError(reply, request, 'Invalid vehicle archive request');
        }
        const runtime = resolveRuntimeConfig();
        const clientConfig = buildOutboundClientConfig(runtime);
        if (!(await requireVerifiedEmail(request, reply, parsed.data.userId, clientConfig))) {
          return;
        }

        try {
          const result = await archiveVehicle({
            vehicleId: new Types.ObjectId(params.data.vehicleId),
            actorUserId: new Types.ObjectId(parsed.data.userId),
            reason: parsed.data.reason,
            audit: createRequestAuditLogger(request),
          });
          return {
            ...vehicleArchivePublicData(result.vehicle),
            message: result.alreadyArchived ? 'Vehicle already archived' : 'Vehicle archived',
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

    const authenticateActor = async (
      request: FastifyRequest,
      reply: FastifyReply,
      userId: string,
    ): Promise<{ runtime: VehicleRuntimeConfig; clientConfig: InternalClientConfig } | null> => {
      const runtime = resolveRuntimeConfig();
      const clientConfig = buildOutboundClientConfig(runtime);
      if (!(await requireVerifiedEmail(request, reply, userId, clientConfig))) {
        return null;
      }
      return { runtime, clientConfig };
    };

    scope.post<{ Params: { vehicleId: string } }>(
      '/vehicles/:vehicleId/invitations',
      { config: { internalOperation: 'invitationCreate' } },
      async (request, reply) => {
        const params = vehicleParamsSchema.safeParse(request.params);
        const parsed = internalInvitationCreateRequestSchema.safeParse(request.body);
        if (!params.success || !parsed.success) {
          return sendValidationError(reply, request, 'Invalid invitation data');
        }
        if (parsed.data.inviterUserId === parsed.data.inviteeUserId) {
          return sendValidationError(reply, request, 'Self-invitations are not allowed');
        }
        const actor = await authenticateActor(request, reply, parsed.data.inviterUserId);
        if (!actor) {
          return;
        }

        // Runs only after the domain has authorized the issuer and the delegated permissions.
        const confirmInviteeExists = async (): Promise<boolean> => {
          let identityResponse;
          try {
            identityResponse = await executeSignedInternalRequest(request, actor.clientConfig, {
              audience: 'identity-service',
              baseUrl: actor.runtime.identityServiceUrl,
              method: 'GET',
              path: `/internal/users/${parsed.data.inviteeUserId}/exists`,
            });
          } catch (error) {
            throw new InviteeLookupError(
              error instanceof OutboundDeadlineExceededError ? 504 : 503,
            );
          }
          if (identityResponse.status === 504) {
            throw new InviteeLookupError(504);
          }
          if (identityResponse.status < 200 || identityResponse.status >= 300) {
            throw new InviteeLookupError(503);
          }
          return (identityResponse.body as { exists?: unknown }).exists === true;
        };

        try {
          const invitation = await inviteMember(
            new Types.ObjectId(params.data.vehicleId),
            new Types.ObjectId(parsed.data.inviterUserId),
            new Types.ObjectId(parsed.data.inviteeUserId),
            parsed.data.permissions,
            {
              ttlMs: actor.runtime.invitationTtlMs,
              audit: createRequestAuditLogger(request),
              confirmInviteeExists,
            },
          );
          if (!invitation) {
            return sendDomainError(
              reply,
              request,
              new VehicleServiceError('NOT_FOUND', 'Vehicle not found'),
            );
          }
          return reply.code(201).send({
            invitationId: String(invitation._id),
            status: invitation.status,
            message: 'Invitation created',
            data: invitationAdminViewData(invitation, invitation.status),
            requestId: responseRequestId(request),
          });
        } catch (error) {
          if (error instanceof InviteeLookupError) {
            return reply.code(error.status).send({
              message:
                error.status === 504
                  ? 'Identity service timed out'
                  : 'Identity service unavailable',
              requestId: responseRequestId(request),
            });
          }
          if (error instanceof VehicleServiceError) {
            return sendDomainError(reply, request, error);
          }
          throw error;
        }
      },
    );

    scope.get<{ Params: { vehicleId: string } }>(
      '/vehicles/:vehicleId/invitations',
      { config: { internalOperation: 'invitationList' } },
      async (request, reply) => {
        const params = vehicleParamsSchema.safeParse(request.params);
        const parsed = internalVehicleInvitationListQuerySchema.safeParse(request.query);
        if (!params.success || !parsed.success) {
          return sendValidationError(reply, request, 'Invalid invitation query');
        }
        if (!(await authenticateActor(request, reply, parsed.data.userId))) {
          return;
        }
        try {
          const page = await listVehicleInvitations(
            new Types.ObjectId(params.data.vehicleId),
            new Types.ObjectId(parsed.data.userId),
            {
              limit: parsed.data.limit,
              cursor: parsed.data.cursor,
              status: parsed.data.status,
              audit: createRequestAuditLogger(request),
            },
          );
          return {
            invitations: page.items.map((item) =>
              invitationAdminViewData(item.invitation, item.status),
            ),
            page: { nextCursor: page.nextCursor },
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

    scope.get(
      '/invitations',
      { config: { internalOperation: 'invitationReceivedList' } },
      async (request, reply) => {
        const parsed = internalReceivedInvitationListQuerySchema.safeParse(request.query);
        if (!parsed.success) {
          return sendValidationError(reply, request, 'Invalid invitation query');
        }
        if (!(await authenticateActor(request, reply, parsed.data.userId))) {
          return;
        }
        try {
          const page = await listReceivedInvitations(new Types.ObjectId(parsed.data.userId), {
            limit: parsed.data.limit,
            cursor: parsed.data.cursor,
            status: parsed.data.status,
          });
          return {
            invitations: page.items.map((item) =>
              receivedInvitationViewData(item.invitation, item.status, item.vehicleName),
            ),
            page: { nextCursor: page.nextCursor },
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

    scope.post<{ Params: { invitationId: string } }>(
      '/invitations/:invitationId/accept',
      { config: { internalOperation: 'invitationAccept' } },
      async (request, reply) => {
        const params = invitationParamsSchema.safeParse(request.params);
        const parsed = invitationAcceptRequestSchema.safeParse(request.body);
        if (!params.success || !parsed.success) {
          return sendValidationError(reply, request, 'Invalid invitation data');
        }
        if (!(await authenticateActor(request, reply, parsed.data.userId))) {
          return;
        }
        try {
          const membership = await acceptInvitation(
            new Types.ObjectId(params.data.invitationId),
            new Types.ObjectId(parsed.data.userId),
            { audit: createRequestAuditLogger(request) },
          );
          if (!membership) {
            return sendDomainError(
              reply,
              request,
              new VehicleServiceError('NOT_FOUND', 'Invitation not found'),
            );
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

    scope.delete<{ Params: { vehicleId: string; invitationId: string } }>(
      '/vehicles/:vehicleId/invitations/:invitationId',
      { config: { internalOperation: 'invitationRevoke' } },
      async (request, reply) => {
        const params = invitationRevokeParamsSchema.safeParse(request.params);
        const parsed = internalInvitationRevokeRequestSchema.safeParse(request.body);
        if (!params.success || !parsed.success) {
          return sendValidationError(reply, request, 'Invalid invitation revocation request');
        }
        if (!(await authenticateActor(request, reply, parsed.data.userId))) {
          return;
        }
        try {
          const result = await revokeInvitation({
            vehicleId: new Types.ObjectId(params.data.vehicleId),
            invitationId: new Types.ObjectId(params.data.invitationId),
            actorUserId: new Types.ObjectId(parsed.data.userId),
            reason: parsed.data.reason,
            audit: createRequestAuditLogger(request),
          });
          return {
            invitationId: String(result.invitation._id),
            status: 'REVOKED',
            message: result.alreadyRevoked ? 'Invitation already revoked' : 'Invitation revoked',
            data: invitationAdminViewData(result.invitation, 'REVOKED'),
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

    scope.get<{ Params: { vehicleId: string } }>(
      '/vehicles/:vehicleId/members',
      { config: { internalOperation: 'memberList' } },
      async (request, reply) => {
        const params = vehicleParamsSchema.safeParse(request.params);
        const parsed = internalMemberListQuerySchema.safeParse(request.query);
        if (!params.success || !parsed.success) {
          return sendValidationError(reply, request, 'Invalid member query');
        }
        if (!(await authenticateActor(request, reply, parsed.data.userId))) {
          return;
        }
        try {
          const page = await listVehicleMembers(
            new Types.ObjectId(params.data.vehicleId),
            new Types.ObjectId(parsed.data.userId),
            {
              limit: parsed.data.limit,
              cursor: parsed.data.cursor,
              status: parsed.data.status,
              audit: createRequestAuditLogger(request),
            },
          );
          return {
            members: page.items.map((membership) => memberViewData(membership)),
            page: { nextCursor: page.nextCursor },
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

    const memberMutationResponse = (
      request: FastifyRequest,
      membership: Parameters<typeof memberViewData>[0],
      message: string,
    ) => {
      const data = memberViewData(membership);
      return {
        membershipId: data.membershipId,
        status: data.status,
        message,
        data,
        requestId: responseRequestId(request),
      };
    };

    scope.patch<{ Params: { vehicleId: string; membershipId: string } }>(
      '/vehicles/:vehicleId/members/:membershipId',
      { config: { internalOperation: 'memberUpdate' } },
      async (request, reply) => {
        const params = memberParamsSchema.safeParse(request.params);
        const parsed = internalMemberPermissionsUpdateRequestSchema.safeParse(request.body);
        if (!params.success || !parsed.success) {
          return sendValidationError(reply, request, 'Invalid member permissions');
        }
        if (!(await authenticateActor(request, reply, parsed.data.userId))) {
          return;
        }
        try {
          const result = await updateMembershipPermissions({
            vehicleId: new Types.ObjectId(params.data.vehicleId),
            membershipId: new Types.ObjectId(params.data.membershipId),
            actorUserId: new Types.ObjectId(parsed.data.userId),
            permissions: parsed.data.permissions,
            audit: createRequestAuditLogger(request),
          });
          return memberMutationResponse(
            request,
            result.membership,
            result.changed ? 'Member permissions updated' : 'Member permissions unchanged',
          );
        } catch (error) {
          if (error instanceof VehicleServiceError) {
            return sendDomainError(reply, request, error);
          }
          throw error;
        }
      },
    );

    scope.post<{ Params: { vehicleId: string; membershipId: string } }>(
      '/vehicles/:vehicleId/members/:membershipId/suspend',
      { config: { internalOperation: 'memberSuspend' } },
      async (request, reply) => {
        const params = memberParamsSchema.safeParse(request.params);
        const parsed = internalMemberTransitionRequestSchema.safeParse(request.body);
        if (!params.success || !parsed.success) {
          return sendValidationError(reply, request, 'Invalid member suspension request');
        }
        if (!(await authenticateActor(request, reply, parsed.data.userId))) {
          return;
        }
        try {
          const result = await suspendMembership({
            vehicleId: new Types.ObjectId(params.data.vehicleId),
            membershipId: new Types.ObjectId(params.data.membershipId),
            actorUserId: new Types.ObjectId(parsed.data.userId),
            reason: parsed.data.reason,
            audit: createRequestAuditLogger(request),
          });
          return memberMutationResponse(request, result.membership, 'Member suspended');
        } catch (error) {
          if (error instanceof VehicleServiceError) {
            return sendDomainError(reply, request, error);
          }
          throw error;
        }
      },
    );

    scope.post<{ Params: { vehicleId: string; membershipId: string } }>(
      '/vehicles/:vehicleId/members/:membershipId/reactivate',
      { config: { internalOperation: 'memberReactivate' } },
      async (request, reply) => {
        const params = memberParamsSchema.safeParse(request.params);
        const parsed = internalMemberReactivateRequestSchema.safeParse(request.body);
        if (!params.success || !parsed.success) {
          return sendValidationError(reply, request, 'Invalid member reactivation request');
        }
        if (!(await authenticateActor(request, reply, parsed.data.userId))) {
          return;
        }
        try {
          const membership = await reactivateMembership({
            vehicleId: new Types.ObjectId(params.data.vehicleId),
            membershipId: new Types.ObjectId(params.data.membershipId),
            actorUserId: new Types.ObjectId(parsed.data.userId),
            audit: createRequestAuditLogger(request),
          });
          return memberMutationResponse(request, membership, 'Member reactivated');
        } catch (error) {
          if (error instanceof VehicleServiceError) {
            return sendDomainError(reply, request, error);
          }
          throw error;
        }
      },
    );

    scope.delete<{ Params: { vehicleId: string; membershipId: string } }>(
      '/vehicles/:vehicleId/members/:membershipId',
      { config: { internalOperation: 'memberRevoke' } },
      async (request, reply) => {
        const params = memberParamsSchema.safeParse(request.params);
        const parsed = internalMemberTransitionRequestSchema.safeParse(request.body);
        if (!params.success || !parsed.success) {
          return sendValidationError(reply, request, 'Invalid member revocation request');
        }
        if (!(await authenticateActor(request, reply, parsed.data.userId))) {
          return;
        }
        try {
          const result = await revokeMembership({
            vehicleId: new Types.ObjectId(params.data.vehicleId),
            membershipId: new Types.ObjectId(params.data.membershipId),
            actorUserId: new Types.ObjectId(parsed.data.userId),
            reason: parsed.data.reason,
            audit: createRequestAuditLogger(request),
          });
          return memberMutationResponse(
            request,
            result.membership,
            result.alreadyRevoked ? 'Member already revoked' : 'Member revoked',
          );
        } catch (error) {
          if (error instanceof VehicleServiceError) {
            return sendDomainError(reply, request, error);
          }
          throw error;
        }
      },
    );

    scope.post<{ Params: { vehicleId: string } }>(
      '/vehicles/:vehicleId/members/leave',
      { config: { internalOperation: 'memberLeave' } },
      async (request, reply) => {
        const params = vehicleParamsSchema.safeParse(request.params);
        const parsed = internalMemberLeaveRequestSchema.safeParse(request.body);
        if (!params.success || !parsed.success) {
          return sendValidationError(reply, request, 'Invalid leave request');
        }
        if (!(await authenticateActor(request, reply, parsed.data.userId))) {
          return;
        }
        try {
          const result = await leaveVehicle({
            vehicleId: new Types.ObjectId(params.data.vehicleId),
            actorUserId: new Types.ObjectId(parsed.data.userId),
            membershipId: new Types.ObjectId(parsed.data.membershipId),
            audit: createRequestAuditLogger(request),
          });
          return {
            membershipId: String(result.membership._id),
            status: 'REVOKED',
            message: result.alreadyRevoked ? 'Membership already revoked' : 'Left vehicle',
            data: membershipPublicData(result.membership),
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
        vehicleUpdate: {
          method: 'PATCH',
          route: '/vehicles/:vehicleId',
          senders: ['api-gateway'],
        },
        vehicleArchive: {
          method: 'DELETE',
          route: '/vehicles/:vehicleId',
          senders: ['api-gateway'],
        },
        invitationCreate: {
          method: 'POST',
          route: '/vehicles/:vehicleId/invitations',
          senders: ['api-gateway'],
        },
        invitationList: {
          method: 'GET',
          route: '/vehicles/:vehicleId/invitations',
          senders: ['api-gateway'],
        },
        invitationReceivedList: {
          method: 'GET',
          route: '/invitations',
          senders: ['api-gateway'],
        },
        invitationAccept: {
          method: 'POST',
          route: '/invitations/:invitationId/accept',
          senders: ['api-gateway'],
        },
        invitationRevoke: {
          method: 'DELETE',
          route: '/vehicles/:vehicleId/invitations/:invitationId',
          senders: ['api-gateway'],
        },
        memberList: {
          method: 'GET',
          route: '/vehicles/:vehicleId/members',
          senders: ['api-gateway'],
        },
        memberUpdate: {
          method: 'PATCH',
          route: '/vehicles/:vehicleId/members/:membershipId',
          senders: ['api-gateway'],
        },
        memberSuspend: {
          method: 'POST',
          route: '/vehicles/:vehicleId/members/:membershipId/suspend',
          senders: ['api-gateway'],
        },
        memberReactivate: {
          method: 'POST',
          route: '/vehicles/:vehicleId/members/:membershipId/reactivate',
          senders: ['api-gateway'],
        },
        memberRevoke: {
          method: 'DELETE',
          route: '/vehicles/:vehicleId/members/:membershipId',
          senders: ['api-gateway'],
        },
        memberLeave: {
          method: 'POST',
          route: '/vehicles/:vehicleId/members/leave',
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
