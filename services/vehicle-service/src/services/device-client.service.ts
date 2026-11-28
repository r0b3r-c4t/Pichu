import type { FastifyRequest } from 'fastify';
import { Types } from 'mongoose';
import { z } from 'zod';
import {
  deviceDetailSchema,
  deviceRegistrationResponseSchema,
  internalDeviceChallengeResponseSchema,
  internalDeviceCollectionResponseSchema,
  internalDeviceDetailResponseSchema,
  type DeviceDetail,
  type DeviceLinkChallenge,
  type DeviceMetadataInput,
  type DeviceMetadataUpdateRequest,
  type DeviceRevocationReason,
  type DeviceStatus,
  type InternalDeviceRecord,
} from '@pichu/contracts';
import type { HttpsJsonResponse } from '@pichu/internal-auth-adapters/tls';
import {
  executeSignedInternalRequest,
  OutboundDeadlineExceededError,
  type InternalClientConfig,
} from '../security/internal-v2.js';
import {
  createVerifiedExternalResourceBinding,
  type VerifiedExternalResourceBinding,
} from './resource-authorization.service.js';

export type UpstreamDeviceErrorCode =
  | 'VALIDATION_ERROR'
  | 'INVALID_DEVICE_KEY'
  | 'INVALID_PROOF'
  | 'INVALID_REVOCATION_REQUEST'
  | 'ACTOR_MISMATCH'
  | 'UNTRUSTED_REVOCATION_ACTOR'
  | 'DEVICE_NOT_FOUND'
  | 'CREDENTIAL_NOT_FOUND'
  | 'DEVICE_ALREADY_REGISTERED'
  | 'DEVICE_REVOKED'
  | 'DEVICE_NOT_LINKABLE'
  | 'UNVERIFIABLE_ENROLLMENT_CONTEXT'
  | 'INVALID_CHALLENGE'
  | 'CREDENTIAL_UNAVAILABLE'
  | 'INVALID_REVOCATION_STATE'
  | 'INCONSISTENT_DEVICE_STATE';

const upstreamErrorEnvelopeSchema = z.object({
  error: z.enum([
    'VALIDATION_ERROR',
    'INVALID_DEVICE_KEY',
    'INVALID_PROOF',
    'INVALID_REVOCATION_REQUEST',
    'ACTOR_MISMATCH',
    'UNTRUSTED_REVOCATION_ACTOR',
    'DEVICE_NOT_FOUND',
    'CREDENTIAL_NOT_FOUND',
    'DEVICE_ALREADY_REGISTERED',
    'DEVICE_REVOKED',
    'DEVICE_NOT_LINKABLE',
    'UNVERIFIABLE_ENROLLMENT_CONTEXT',
    'INVALID_CHALLENGE',
    'CREDENTIAL_UNAVAILABLE',
    'INVALID_REVOCATION_STATE',
    'INCONSISTENT_DEVICE_STATE',
    'DEVICE_DATABASE_UNAVAILABLE',
  ]),
});

export class DeviceUpstreamTimeoutError extends Error {
  constructor() {
    super('Device service timed out');
    this.name = 'DeviceUpstreamTimeoutError';
  }
}

export class DeviceUpstreamUnavailableError extends Error {
  readonly reason: 'UNAVAILABLE' | 'PROTOCOL_ERROR';
  constructor(
    message = 'Device service unavailable',
    reason: 'UNAVAILABLE' | 'PROTOCOL_ERROR' = 'UNAVAILABLE',
  ) {
    super(message);
    this.name = 'DeviceUpstreamUnavailableError';
    this.reason = reason;
  }
}

export class DeviceUpstreamDomainError extends Error {
  constructor(
    readonly status: 400 | 403 | 404 | 409,
    readonly code: UpstreamDeviceErrorCode,
  ) {
    super(`Device domain error: ${code}`);
    this.name = 'DeviceUpstreamDomainError';
  }
}

export interface VerifiedDeviceSnapshot {
  readonly record: InternalDeviceRecord;
  readonly publicDetail: DeviceDetail;
  /**
   * Point-in-time authoritative evidence issued ONLY when the device is ACTIVE, consistent, and
   * holds a usable ACTIVE credential. Never a permanent authorization guarantee across services.
   */
  readonly activeBinding: VerifiedExternalResourceBinding | null;
}

/** Strips internal enrollment/audit context and validates the public `DeviceDetail` contract. */
export function toPublicDeviceDetail(record: InternalDeviceRecord): DeviceDetail {
  const publicCandidate: DeviceDetail = {
    deviceId: record.deviceId,
    vehicleId: record.vehicleId,
    identifier: record.identifier,
    status: record.status,
    operational: record.operational,
    credential: record.credential,
    connectivity: record.connectivity,
    metadata: record.metadata,
    linkedAt: record.linkedAt,
    revokedAt: record.revokedAt,
    revocationReason: record.revocationReason,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  };
  const parsed = deviceDetailSchema.safeParse(publicCandidate);
  if (!parsed.success) {
    throw new DeviceUpstreamUnavailableError('Invalid public device projection', 'PROTOCOL_ERROR');
  }
  return parsed.data;
}

function buildVerifiedSnapshot(
  record: InternalDeviceRecord,
  expectations: { expectedDeviceId?: string; expectedVehicleId?: string },
): VerifiedDeviceSnapshot {
  if (
    expectations.expectedDeviceId !== undefined &&
    record.deviceId !== expectations.expectedDeviceId
  ) {
    throw new DeviceUpstreamUnavailableError('Upstream deviceId mismatch', 'PROTOCOL_ERROR');
  }
  if (
    expectations.expectedVehicleId !== undefined &&
    record.vehicleId !== expectations.expectedVehicleId
  ) {
    throw new DeviceUpstreamUnavailableError('Upstream vehicleId mismatch', 'PROTOCOL_ERROR');
  }

  // Structural coherence guard before minting any VerifiedExternalResourceBinding:
  const eligibleForActiveEvidence =
    record.status === 'ACTIVE' &&
    record.operational === true &&
    record.revokedAt === null &&
    record.revocationReason === null &&
    record.credential.status === 'ACTIVE' &&
    record.credential.usable === true &&
    record.credential.revokedAt === null;

  if (record.operational && !eligibleForActiveEvidence) {
    throw new DeviceUpstreamUnavailableError(
      'Inconsistent operational flag from upstream Device',
      'PROTOCOL_ERROR',
    );
  }

  const activeBinding = eligibleForActiveEvidence
    ? createVerifiedExternalResourceBinding({
        scopeType: 'DEVICE',
        resourceId: Types.ObjectId.createFromHexString(record.deviceId),
        vehicleId: Types.ObjectId.createFromHexString(record.vehicleId),
        isActive: true,
      })
    : null;

  return Object.freeze({
    record,
    publicDetail: toPublicDeviceDetail(record),
    activeBinding,
  });
}

function throwForNon2xx(response: HttpsJsonResponse): never {
  if (response.status === 504) {
    throw new DeviceUpstreamTimeoutError();
  }
  if (response.status === 502 || response.status === 503) {
    throw new DeviceUpstreamUnavailableError();
  }
  if (
    response.status === 400 ||
    response.status === 403 ||
    response.status === 404 ||
    response.status === 409
  ) {
    const parsed = upstreamErrorEnvelopeSchema.safeParse(response.body);
    if (parsed.success && parsed.data.error !== 'DEVICE_DATABASE_UNAVAILABLE') {
      throw new DeviceUpstreamDomainError(response.status, parsed.data.error);
    }
    if (parsed.success && parsed.data.error === 'DEVICE_DATABASE_UNAVAILABLE') {
      throw new DeviceUpstreamUnavailableError();
    }
    // Closed fallback by HTTP status without leaking upstream raw messages
    const defaultCodeByStatus: Record<400 | 403 | 404 | 409, UpstreamDeviceErrorCode> = {
      400: 'VALIDATION_ERROR',
      403: 'ACTOR_MISMATCH',
      404: 'DEVICE_NOT_FOUND',
      409: 'DEVICE_NOT_LINKABLE',
    };
    throw new DeviceUpstreamDomainError(response.status, defaultCodeByStatus[response.status]);
  }
  throw new DeviceUpstreamUnavailableError(
    'Unexpected upstream status from Device',
    'PROTOCOL_ERROR',
  );
}

export interface DeviceServiceClient {
  registerDevice(input: {
    identifier: string;
    publicKey: string;
    metadata?: DeviceMetadataInput;
    vehicleId: string;
    userId: string;
    membershipId: string;
  }): Promise<VerifiedDeviceSnapshot>;
  getDeviceById(deviceId: string): Promise<VerifiedDeviceSnapshot | null>;
  listVehicleDevicesBatch(input: {
    vehicleId: string;
    limit: number;
    status?: DeviceStatus;
    afterCreatedAt?: string;
    afterId?: string;
  }): Promise<{ items: VerifiedDeviceSnapshot[]; hasMore: boolean }>;
  updateDeviceMetadata(input: {
    deviceId: string;
    vehicleId: string;
    userId: string;
    metadata: DeviceMetadataUpdateRequest;
  }): Promise<VerifiedDeviceSnapshot>;
  createChallenge(input: {
    deviceId: string;
    vehicleId: string;
    userId: string;
    membershipId: string;
  }): Promise<DeviceLinkChallenge>;
  completeLink(input: {
    deviceId: string;
    vehicleId: string;
    userId: string;
    membershipId: string;
    challengeId: string;
    challenge: string;
    signature: string;
  }): Promise<VerifiedDeviceSnapshot>;
  revokeDevice(input: {
    deviceId: string;
    vehicleId: string;
    userId: string;
    reason: DeviceRevocationReason;
  }): Promise<VerifiedDeviceSnapshot>;
}

export function createDeviceServiceClient(
  request: FastifyRequest,
  clientConfig: InternalClientConfig,
  deviceBaseUrl: string,
): DeviceServiceClient {
  async function callDevice(
    method: 'GET' | 'POST' | 'PATCH',
    path: string,
    payload?: unknown,
  ): Promise<HttpsJsonResponse> {
    const body = payload === undefined ? undefined : Buffer.from(JSON.stringify(payload));
    try {
      return await executeSignedInternalRequest(request, clientConfig, {
        audience: 'device-service',
        baseUrl: deviceBaseUrl,
        method,
        path,
        ...(body ? { body } : {}),
      });
    } catch (error) {
      if (error instanceof OutboundDeadlineExceededError) {
        throw new DeviceUpstreamTimeoutError();
      }
      throw new DeviceUpstreamUnavailableError();
    }
  }

  return {
    async registerDevice(input) {
      const response = await callDevice('POST', '/internal/devices/register', input);
      if (response.status !== 201) throwForNon2xx(response);
      const parsed = deviceRegistrationResponseSchema.safeParse(response.body);
      if (!parsed.success || parsed.data.deviceId !== parsed.data.data.deviceId) {
        throw new DeviceUpstreamUnavailableError(
          'Invalid registration response from Device',
          'PROTOCOL_ERROR',
        );
      }
      return buildVerifiedSnapshot(parsed.data.data, {
        expectedDeviceId: parsed.data.deviceId,
        expectedVehicleId: input.vehicleId,
      });
    },

    async getDeviceById(deviceId) {
      const response = await callDevice('GET', `/internal/devices/${deviceId}`);
      if (response.status === 404) return null;
      if (response.status !== 200) throwForNon2xx(response);
      const parsed = internalDeviceDetailResponseSchema.safeParse(response.body);
      if (!parsed.success) {
        throw new DeviceUpstreamUnavailableError(
          'Invalid device detail response from Device',
          'PROTOCOL_ERROR',
        );
      }
      return buildVerifiedSnapshot(parsed.data.data, { expectedDeviceId: deviceId });
    },

    async listVehicleDevicesBatch(input) {
      const search = new URLSearchParams({ limit: String(input.limit) });
      if (input.status !== undefined) search.set('status', input.status);
      if (input.afterCreatedAt !== undefined && input.afterId !== undefined) {
        search.set('afterCreatedAt', input.afterCreatedAt);
        search.set('afterId', input.afterId);
      }
      const response = await callDevice(
        'GET',
        `/internal/vehicles/${input.vehicleId}/devices?${search.toString()}`,
      );
      if (response.status !== 200) throwForNon2xx(response);
      const parsed = internalDeviceCollectionResponseSchema.safeParse(response.body);
      if (
        !parsed.success ||
        parsed.data.devices.length > input.limit ||
        (parsed.data.devices.length === 0 && parsed.data.hasMore)
      ) {
        throw new DeviceUpstreamUnavailableError(
          'Invalid device list response from Device',
          'PROTOCOL_ERROR',
        );
      }
      const items = parsed.data.devices.map((record) =>
        buildVerifiedSnapshot(record, { expectedVehicleId: input.vehicleId }),
      );
      return { items, hasMore: parsed.data.hasMore };
    },

    async updateDeviceMetadata(input) {
      const response = await callDevice('PATCH', `/internal/devices/${input.deviceId}`, {
        vehicleId: input.vehicleId,
        userId: input.userId,
        metadata: input.metadata,
      });
      if (response.status !== 200) throwForNon2xx(response);
      const parsed = internalDeviceDetailResponseSchema.safeParse(response.body);
      if (!parsed.success) {
        throw new DeviceUpstreamUnavailableError(
          'Invalid metadata update response from Device',
          'PROTOCOL_ERROR',
        );
      }
      return buildVerifiedSnapshot(parsed.data.data, {
        expectedDeviceId: input.deviceId,
        expectedVehicleId: input.vehicleId,
      });
    },

    async createChallenge(input) {
      const response = await callDevice('POST', `/internal/devices/${input.deviceId}/challenge`, {
        vehicleId: input.vehicleId,
        userId: input.userId,
        membershipId: input.membershipId,
      });
      if (response.status !== 201) throwForNon2xx(response);
      const parsed = internalDeviceChallengeResponseSchema.safeParse(response.body);
      if (
        !parsed.success ||
        parsed.data.data.deviceId !== input.deviceId ||
        parsed.data.data.vehicleId !== input.vehicleId ||
        parsed.data.data.requestedByUserId !== input.userId
      ) {
        throw new DeviceUpstreamUnavailableError(
          'Invalid challenge response from Device',
          'PROTOCOL_ERROR',
        );
      }
      return parsed.data.data;
    },

    async completeLink(input) {
      const response = await callDevice('POST', `/internal/devices/${input.deviceId}/link`, {
        vehicleId: input.vehicleId,
        userId: input.userId,
        membershipId: input.membershipId,
        challengeId: input.challengeId,
        challenge: input.challenge,
        signature: input.signature,
      });
      if (response.status !== 200) throwForNon2xx(response);
      const parsed = internalDeviceDetailResponseSchema.safeParse(response.body);
      if (!parsed.success || parsed.data.data.status !== 'ACTIVE') {
        throw new DeviceUpstreamUnavailableError(
          'Invalid link completion response from Device',
          'PROTOCOL_ERROR',
        );
      }
      return buildVerifiedSnapshot(parsed.data.data, {
        expectedDeviceId: input.deviceId,
        expectedVehicleId: input.vehicleId,
      });
    },

    async revokeDevice(input) {
      const response = await callDevice('POST', `/internal/devices/${input.deviceId}/revoke`, {
        vehicleId: input.vehicleId,
        userId: input.userId,
        reason: input.reason,
      });
      if (response.status !== 200) throwForNon2xx(response);
      const parsed = internalDeviceDetailResponseSchema.safeParse(response.body);
      if (!parsed.success || parsed.data.data.status !== 'REVOKED') {
        throw new DeviceUpstreamUnavailableError(
          'Invalid revocation response from Device',
          'PROTOCOL_ERROR',
        );
      }
      return buildVerifiedSnapshot(parsed.data.data, {
        expectedDeviceId: input.deviceId,
        expectedVehicleId: input.vehicleId,
      });
    },
  };
}
