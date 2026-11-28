import { createHash } from 'node:crypto';
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
  type DeviceMetadata,
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

function protocolError(message: string): DeviceUpstreamUnavailableError {
  return new DeviceUpstreamUnavailableError(message, 'PROTOCOL_ERROR');
}

/**
 * Structural coherence of an upstream record. Credential expiry and usability are Device's
 * observation at its own clock and are never recomputed with Vehicle's clock; only combinations
 * that no consistent Device state can produce are rejected. Historical records stay valid:
 * ACTIVE without `linkedAt`, requester-less records, and USER-less (SERVICE/SYSTEM) revocations.
 */
function assertCoherentDeviceRecord(record: InternalDeviceRecord): void {
  const { credential } = record;
  if ((credential.status === 'REVOKED') !== (credential.revokedAt !== null)) {
    throw protocolError('Inconsistent credential revocation from upstream Device');
  }
  if (credential.status === 'EXPIRED' && credential.expiresAt === null) {
    throw protocolError('Expired upstream credential lacks expiresAt');
  }
  if (credential.usable && credential.status !== 'ACTIVE') {
    throw protocolError('Unusable credential state reported as usable by upstream Device');
  }
  if (record.operational !== (record.status === 'ACTIVE' && credential.usable)) {
    throw protocolError('Inconsistent operational flag from upstream Device');
  }
  if (record.requestedByMembershipId !== null && record.requestedByUserId === null) {
    throw protocolError('Upstream enrollment membership lacks its requester');
  }
  if (
    record.status !== 'REVOKED' &&
    (record.revokedAt !== null ||
      record.revocationReason !== null ||
      record.revokedByUserId !== null)
  ) {
    throw protocolError('Revocation audit on a non-revoked upstream device');
  }
  if (record.status === 'PENDING' && record.linkedAt !== null) {
    throw protocolError('Link audit on a PENDING upstream device');
  }
  if (
    record.status === 'REVOKED' &&
    (record.revokedAt === null ||
      record.revocationReason === null ||
      credential.status !== 'REVOKED')
  ) {
    throw protocolError('Incomplete revocation state from upstream Device');
  }
}

interface RecordExpectations {
  expectedDeviceId?: string;
  expectedVehicleId?: string;
  expectedStatuses?: readonly DeviceStatus[];
  expectedRequester?: { userId: string; membershipId: string };
}

/**
 * Sole issuer of VerifiedExternalResourceBinding for devices. Every upstream record is validated
 * for identity, operation context and structural coherence before any evidence is minted, so a
 * contradictory response fails closed even when it would not produce evidence.
 */
function buildVerifiedSnapshot(
  record: InternalDeviceRecord,
  expectations: RecordExpectations,
): VerifiedDeviceSnapshot {
  if (
    expectations.expectedDeviceId !== undefined &&
    record.deviceId !== expectations.expectedDeviceId
  ) {
    throw protocolError('Upstream deviceId mismatch');
  }
  if (
    expectations.expectedVehicleId !== undefined &&
    record.vehicleId !== expectations.expectedVehicleId
  ) {
    throw protocolError('Upstream vehicleId mismatch');
  }
  if (
    expectations.expectedStatuses !== undefined &&
    !expectations.expectedStatuses.includes(record.status)
  ) {
    throw protocolError('Unexpected upstream device status for the operation');
  }
  if (
    expectations.expectedRequester !== undefined &&
    (record.requestedByUserId !== expectations.expectedRequester.userId ||
      record.requestedByMembershipId !== expectations.expectedRequester.membershipId)
  ) {
    throw protocolError('Upstream enrollment context mismatch');
  }
  assertCoherentDeviceRecord(record);

  const eligibleForActiveEvidence = record.status === 'ACTIVE' && record.operational;
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

const SPKI_PEM_ARMOR =
  /^-----BEGIN PUBLIC KEY-----\s+([A-Za-z0-9+/=\s]+?)\s+-----END PUBLIC KEY-----$/;

/** Device fingerprints are `sha256:` over the SPKI DER carried by the submitted PEM. */
function submittedKeyFingerprint(publicKey: string): string | null {
  const body = SPKI_PEM_ARMOR.exec(publicKey.trim())?.[1];
  if (body === undefined) return null;
  const der = Buffer.from(body.replace(/\s+/g, ''), 'base64');
  return `sha256:${createHash('sha256').update(der).digest('hex')}`;
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
      if (
        !parsed.success ||
        parsed.data.deviceId !== parsed.data.data.deviceId ||
        parsed.data.data.identifier !== input.identifier.trim() ||
        parsed.data.data.credential.status !== 'ACTIVE' ||
        parsed.data.data.credential.fingerprint !== submittedKeyFingerprint(input.publicKey)
      ) {
        throw new DeviceUpstreamUnavailableError(
          'Invalid registration response from Device',
          'PROTOCOL_ERROR',
        );
      }
      return buildVerifiedSnapshot(parsed.data.data, {
        expectedDeviceId: parsed.data.deviceId,
        expectedVehicleId: input.vehicleId,
        expectedStatuses: ['PENDING'],
        expectedRequester: { userId: input.userId, membershipId: input.membershipId },
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
        (parsed.data.devices.length === 0 && parsed.data.hasMore) ||
        new Set(parsed.data.devices.map((record) => record.deviceId)).size !==
          parsed.data.devices.length
      ) {
        throw new DeviceUpstreamUnavailableError(
          'Invalid device list response from Device',
          'PROTOCOL_ERROR',
        );
      }
      const items = parsed.data.devices.map((record) =>
        buildVerifiedSnapshot(record, {
          expectedVehicleId: input.vehicleId,
          ...(input.status !== undefined ? { expectedStatuses: [input.status] } : {}),
        }),
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
      if (
        !parsed.success ||
        Object.entries(input.metadata).some(
          ([field, value]) =>
            value !== undefined &&
            parsed.data.data.metadata[field as keyof DeviceMetadata] !==
              (typeof value === 'string' ? value.trim() : value),
        )
      ) {
        throw new DeviceUpstreamUnavailableError(
          'Invalid metadata update response from Device',
          'PROTOCOL_ERROR',
        );
      }
      return buildVerifiedSnapshot(parsed.data.data, {
        expectedDeviceId: input.deviceId,
        expectedVehicleId: input.vehicleId,
        expectedStatuses: ['PENDING', 'ACTIVE'],
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
      if (
        !parsed.success ||
        parsed.data.data.status !== 'ACTIVE' ||
        !parsed.data.data.operational ||
        parsed.data.data.linkedAt === null
      ) {
        throw new DeviceUpstreamUnavailableError(
          'Invalid link completion response from Device',
          'PROTOCOL_ERROR',
        );
      }
      return buildVerifiedSnapshot(parsed.data.data, {
        expectedDeviceId: input.deviceId,
        expectedVehicleId: input.vehicleId,
        expectedStatuses: ['ACTIVE'],
        expectedRequester: { userId: input.userId, membershipId: input.membershipId },
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
        expectedStatuses: ['REVOKED'],
      });
    },
  };
}
