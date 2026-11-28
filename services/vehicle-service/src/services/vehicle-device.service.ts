import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import mongoose, { Types } from 'mongoose';
import { z } from 'zod';
import type {
  DeviceDetail,
  DeviceLinkChallenge,
  DeviceMetadataInput,
  DeviceMetadataUpdateRequest,
  DeviceRevocationReason,
  DeviceStatus,
} from '@pichu/contracts';
import { AccessGrantModel } from '../models/access-grant.model.js';
import {
  DeviceUpstreamDomainError,
  DeviceUpstreamTimeoutError,
  DeviceUpstreamUnavailableError,
  type DeviceServiceClient,
  type VerifiedDeviceSnapshot,
} from './device-client.service.js';
import {
  databaseUnavailableError,
  isDatabaseUnavailableError,
  resourceAuthorization,
  type MembershipRecord,
  type VehicleRecord,
} from './resource-authorization.service.js';
import {
  defaultAuditLogger,
  VehicleServiceError,
  type VehicleAuditLogger,
} from './vehicle-errors.js';

const DEVICE_CURSOR_VERSION = 1 as const;
const MAX_CURSOR_LENGTH = 256;
const CURSOR_PATTERN = /^[A-Za-z0-9_-]+$/;
const CURSOR_IV_BYTES = 12;
const CURSOR_AUTH_TAG_BYTES = 16;
const FALLBACK_PROCESS_CURSOR_SECRET = randomBytes(32);
const DEFAULT_PAGE_LIMIT = 20;
const MAX_PAGE_LIMIT = 100;
/** Bounded upper limit on Device batch round-trips per page to prevent unbounded scans. */
export const MAX_DEVICE_SCAN_BATCHES = 5;
const MAX_DEVICE_GRANTS_QUERY_LIMIT = 1_000;

const deviceCursorPlaintextSchema = z.strictObject({
  c: z.string().datetime({ offset: true }),
  i: z.string().regex(/^[a-f0-9]{24}$/),
});

interface DeviceCursorScope {
  actorUserId: Types.ObjectId;
  vehicleId: Types.ObjectId;
  statusFilter: DeviceStatus | 'ALL';
}

interface DeviceCursorPosition {
  createdAtIso: string;
  id: string;
}

function invalidCursorError(): VehicleServiceError {
  return new VehicleServiceError('VALIDATION_ERROR', 'Invalid pagination cursor');
}

function cursorAad(scope: DeviceCursorScope): Buffer {
  return Buffer.from(
    `pichu:collection-cursor:v${DEVICE_CURSOR_VERSION}:vehicle-devices:${String(scope.actorUserId)}:${String(scope.vehicleId)}:${scope.statusFilter}`,
    'utf8',
  );
}

function resolveCursorSecrets(secrets: readonly Buffer[] | undefined): readonly Buffer[] {
  const valid = (secrets ?? []).filter((secret) => Buffer.isBuffer(secret) && secret.length === 32);
  return valid.length > 0 ? valid : [FALLBACK_PROCESS_CURSOR_SECRET];
}

function encodeDeviceCursor(
  scope: DeviceCursorScope,
  position: DeviceCursorPosition,
  secrets: readonly Buffer[] | undefined,
): string {
  const [key] = resolveCursorSecrets(secrets);
  const iv = randomBytes(CURSOR_IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key!, iv);
  cipher.setAAD(cursorAad(scope));
  const plaintext = Buffer.from(
    JSON.stringify({ c: position.createdAtIso, i: position.id }),
    'utf8',
  );
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from([DEVICE_CURSOR_VERSION]), iv, tag, ciphertext]).toString(
    'base64url',
  );
}

function decodeDeviceCursor(
  cursor: string,
  scope: DeviceCursorScope,
  secrets: readonly Buffer[] | undefined,
): DeviceCursorPosition {
  if (cursor.length === 0 || cursor.length > MAX_CURSOR_LENGTH || !CURSOR_PATTERN.test(cursor)) {
    throw invalidCursorError();
  }
  const token = Buffer.from(cursor, 'base64url');
  if (
    token.toString('base64url') !== cursor ||
    token.length < 1 + CURSOR_IV_BYTES + CURSOR_AUTH_TAG_BYTES + 1 ||
    token[0] !== DEVICE_CURSOR_VERSION
  ) {
    throw invalidCursorError();
  }
  const iv = token.subarray(1, 1 + CURSOR_IV_BYTES);
  const tag = token.subarray(1 + CURSOR_IV_BYTES, 1 + CURSOR_IV_BYTES + CURSOR_AUTH_TAG_BYTES);
  const ciphertext = token.subarray(1 + CURSOR_IV_BYTES + CURSOR_AUTH_TAG_BYTES);
  const aad = cursorAad(scope);

  let decodedJson: unknown;
  let decrypted = false;
  for (const key of resolveCursorSecrets(secrets)) {
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAAD(aad);
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      decodedJson = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
      decrypted = true;
      break;
    } catch {
      // Try next valid key in keyring rotation window or reject below
    }
  }
  if (!decrypted) {
    throw invalidCursorError();
  }
  const parsed = deviceCursorPlaintextSchema.safeParse(decodedJson);
  if (!parsed.success) {
    throw invalidCursorError();
  }
  const parsedDate = new Date(parsed.data.c);
  if (Number.isNaN(parsedDate.getTime()) || parsedDate.toISOString() !== parsed.data.c) {
    throw invalidCursorError();
  }
  return { createdAtIso: parsed.data.c, id: parsed.data.i };
}

function validatePageLimit(limit: number | undefined): number {
  const value = limit ?? DEFAULT_PAGE_LIMIT;
  if (!Number.isInteger(value) || value < 1 || value > MAX_PAGE_LIMIT) {
    throw new VehicleServiceError('VALIDATION_ERROR', 'Invalid pagination limit');
  }
  return value;
}

interface ActiveSubjectContext {
  vehicle: VehicleRecord;
  membership: MembershipRecord;
}

async function guardedVehicleDb<T>(work: () => Promise<T>): Promise<T> {
  if (mongoose.connection.readyState !== 1) {
    throw databaseUnavailableError();
  }
  try {
    return await work();
  } catch (error) {
    if (error instanceof VehicleServiceError) throw error;
    if (isDatabaseUnavailableError(error)) throw databaseUnavailableError(error);
    throw error;
  }
}

async function loadActiveVehicleSubject(
  vehicleId: Types.ObjectId,
  actorUserId: Types.ObjectId,
  audit: VehicleAuditLogger,
): Promise<ActiveSubjectContext | null> {
  const resolution = await resourceAuthorization.resolveSubject(vehicleId, actorUserId, { audit });
  if (!resolution.resolved) {
    return null;
  }
  return {
    vehicle: resolution.subject.vehicle,
    membership: resolution.subject.membership,
  };
}

function hasBasePermission(membership: MembershipRecord, permission: string): boolean {
  return membership.role === 'MEMBER' && membership.permissions.includes(permission);
}

function isOriginalRequesterInCurrentMembership(
  snapshot: VerifiedDeviceSnapshot,
  actorUserId: Types.ObjectId,
  membershipId: Types.ObjectId,
): boolean {
  return (
    snapshot.record.requestedByUserId !== null &&
    snapshot.record.requestedByMembershipId !== null &&
    snapshot.record.requestedByUserId === String(actorUserId) &&
    snapshot.record.requestedByMembershipId === String(membershipId)
  );
}

/**
 * Evaluates whether `subject` may read `snapshot` under TKT-015 §6 rules without ever deriving
 * access solely from `requestedByUserId` or `linkedByUserId`, and without turning diagnostic reads
 * into active resource bindings.
 */
async function canSubjectReadDeviceSnapshot(
  subject: ActiveSubjectContext,
  actorUserId: Types.ObjectId,
  snapshot: VerifiedDeviceSnapshot,
  now: Date,
): Promise<boolean> {
  const { vehicle, membership } = subject;
  if (membership.role === 'OWNER' || hasBasePermission(membership, 'vehicle:manage')) {
    return true;
  }

  if (snapshot.record.status === 'ACTIVE') {
    if (snapshot.activeBinding !== null) {
      const decision = await resourceAuthorization.evaluate(
        {
          actorUserId,
          vehicleId: vehicle._id,
          resource: {
            type: 'DEVICE',
            resourceId: Types.ObjectId.createFromHexString(snapshot.record.deviceId),
            binding: snapshot.activeBinding,
          },
          permission: 'device:read',
          channel: 'ONLINE',
        },
        { clock: () => now },
      );
      return decision.allowed;
    }
    // Degraded ACTIVE device (expired or revoked credential): diagnostic read for base device:read only
    return hasBasePermission(membership, 'device:read');
  }

  if (snapshot.record.status === 'PENDING') {
    if (!isOriginalRequesterInCurrentMembership(snapshot, actorUserId, membership._id)) {
      return false;
    }
    const linkDecision = await resourceAuthorization.evaluateAnyOf(
      {
        actorUserId,
        vehicleId: vehicle._id,
        resource: { type: 'VEHICLE' },
        channel: 'ONLINE',
      },
      ['vehicle:manage', 'device:link'],
      { clock: () => now },
    );
    return linkDecision.allowed && linkDecision.membershipId.equals(membership._id);
  }

  // REVOKED devices are visible only to OWNER or MEMBER with base vehicle:manage (handled above)
  return false;
}

function mapDomainErrorForMutation(error: DeviceUpstreamDomainError): VehicleServiceError {
  switch (error.code) {
    case 'INVALID_DEVICE_KEY':
      return new VehicleServiceError('VALIDATION_ERROR', 'Invalid device public key');
    case 'INVALID_PROOF':
      return new VehicleServiceError('VALIDATION_ERROR', 'Invalid device cryptographic proof');
    case 'VALIDATION_ERROR':
    case 'INVALID_REVOCATION_REQUEST':
      return new VehicleServiceError('VALIDATION_ERROR', 'Invalid device request');
    case 'DEVICE_NOT_FOUND':
    case 'CREDENTIAL_NOT_FOUND':
      return new VehicleServiceError('NOT_FOUND', 'Device not found');
    case 'ACTOR_MISMATCH':
    case 'UNTRUSTED_REVOCATION_ACTOR':
      return new VehicleServiceError('FORBIDDEN', 'Insufficient permissions for this device');
    case 'DEVICE_ALREADY_REGISTERED':
      return new VehicleServiceError(
        'CONFLICT',
        'Device identifier or public key is already registered',
      );
    case 'DEVICE_REVOKED':
      return new VehicleServiceError('CONFLICT', 'Revoked devices cannot be modified');
    case 'INVALID_CHALLENGE':
      return new VehicleServiceError(
        'CONFLICT',
        'Enrollment challenge is invalid, expired, or already used',
      );
    case 'CREDENTIAL_UNAVAILABLE':
      return new VehicleServiceError('CONFLICT', 'Device credential is not usable');
    case 'UNVERIFIABLE_ENROLLMENT_CONTEXT':
      return new VehicleServiceError(
        'CONFLICT',
        'Historical pending device lacks verifiable enrollment context',
      );
    case 'INVALID_REVOCATION_STATE':
      return new VehicleServiceError(
        'CONFLICT',
        'REGISTRATION_CANCELLED applies only to PENDING devices',
      );
    case 'DEVICE_NOT_LINKABLE':
    case 'INCONSISTENT_DEVICE_STATE':
      return new VehicleServiceError('CONFLICT', 'Device cannot complete the requested transition');
  }
}

export interface VehicleDeviceOperationContext {
  deviceClient: DeviceServiceClient;
  audit?: VehicleAuditLogger;
  now?: Date;
  /** Server-side 32-byte keys used to encrypt and authenticate opaque device list cursors. */
  cursorSecrets?: readonly Buffer[];
}

export async function registerVehicleDevice(
  vehicleId: Types.ObjectId,
  actorUserId: Types.ObjectId,
  input: {
    identifier: string;
    publicKey: string;
    metadata?: DeviceMetadataInput;
  },
  ctx: VehicleDeviceOperationContext,
): Promise<DeviceDetail> {
  const audit = ctx.audit ?? defaultAuditLogger;
  const now = ctx.now ?? new Date();

  const decision = await resourceAuthorization.evaluateAnyOf(
    {
      actorUserId,
      vehicleId,
      resource: { type: 'VEHICLE' },
      channel: 'ONLINE',
    },
    ['vehicle:manage', 'device:link'],
    { clock: () => now, audit },
  );

  if (!decision.allowed) {
    if (decision.category === 'INVALID_CONTEXT') {
      throw new VehicleServiceError('VALIDATION_ERROR', 'Invalid authorization context');
    }
    const readable = await resourceAuthorization.hasVehicleReadAccess(vehicleId, actorUserId, {
      clock: () => now,
      audit,
    });
    audit({
      action: 'device.register',
      actorUserId: String(actorUserId),
      vehicleId: String(vehicleId),
      outcome: 'denied',
      reason: decision.reason,
    });
    if (readable) {
      throw new VehicleServiceError('FORBIDDEN', 'Insufficient permissions to register devices');
    }
    throw new VehicleServiceError('NOT_FOUND', 'Vehicle not found');
  }

  try {
    const snapshot = await ctx.deviceClient.registerDevice({
      identifier: input.identifier,
      publicKey: input.publicKey,
      metadata: input.metadata,
      vehicleId: String(vehicleId),
      userId: String(actorUserId),
      membershipId: String(decision.membershipId),
    });
    audit({
      action: 'device.register',
      actorUserId: String(actorUserId),
      vehicleId: String(vehicleId),
      targetId: snapshot.record.deviceId,
      outcome: 'success',
    });
    return snapshot.publicDetail;
  } catch (error) {
    if (error instanceof DeviceUpstreamDomainError) {
      throw mapDomainErrorForMutation(error);
    }
    throw error;
  }
}

export async function getVehicleScopedDeviceDetail(
  vehicleId: Types.ObjectId,
  deviceId: Types.ObjectId,
  actorUserId: Types.ObjectId,
  ctx: VehicleDeviceOperationContext,
): Promise<DeviceDetail> {
  const audit = ctx.audit ?? defaultAuditLogger;
  const now = ctx.now ?? new Date();

  const subject = await loadActiveVehicleSubject(vehicleId, actorUserId, audit);
  if (!subject) {
    throw new VehicleServiceError('NOT_FOUND', 'Device not found');
  }

  let snapshot: VerifiedDeviceSnapshot | null;
  try {
    snapshot = await ctx.deviceClient.getDeviceById(String(deviceId));
  } catch (error) {
    if (error instanceof DeviceUpstreamDomainError && error.code === 'INCONSISTENT_DEVICE_STATE') {
      audit({
        action: 'device.read',
        actorUserId: String(actorUserId),
        vehicleId: String(vehicleId),
        targetId: String(deviceId),
        outcome: 'denied',
        reason: 'inconsistent_device_state',
      });
      throw new VehicleServiceError('NOT_FOUND', 'Device not found');
    }
    if (error instanceof DeviceUpstreamDomainError && error.status === 404) {
      throw new VehicleServiceError('NOT_FOUND', 'Device not found');
    }
    throw error;
  }

  if (!snapshot || snapshot.record.vehicleId !== String(vehicleId)) {
    throw new VehicleServiceError('NOT_FOUND', 'Device not found');
  }

  const allowed = await canSubjectReadDeviceSnapshot(subject, actorUserId, snapshot, now);
  if (!allowed) {
    throw new VehicleServiceError('NOT_FOUND', 'Device not found');
  }
  return snapshot.publicDetail;
}

export async function getDirectDeviceDetail(
  deviceId: Types.ObjectId,
  actorUserId: Types.ObjectId,
  ctx: VehicleDeviceOperationContext,
): Promise<DeviceDetail> {
  const audit = ctx.audit ?? defaultAuditLogger;
  const now = ctx.now ?? new Date();

  let snapshot: VerifiedDeviceSnapshot | null;
  try {
    snapshot = await ctx.deviceClient.getDeviceById(String(deviceId));
  } catch (error) {
    if (error instanceof DeviceUpstreamDomainError && error.code === 'INCONSISTENT_DEVICE_STATE') {
      audit({
        action: 'device.read',
        actorUserId: String(actorUserId),
        targetId: String(deviceId),
        outcome: 'denied',
        reason: 'inconsistent_device_state',
      });
      throw new VehicleServiceError('NOT_FOUND', 'Device not found');
    }
    if (error instanceof DeviceUpstreamDomainError && error.status === 404) {
      throw new VehicleServiceError('NOT_FOUND', 'Device not found');
    }
    throw error;
  }

  if (!snapshot) {
    throw new VehicleServiceError('NOT_FOUND', 'Device not found');
  }

  const vehicleId = Types.ObjectId.createFromHexString(snapshot.record.vehicleId);
  const subject = await loadActiveVehicleSubject(vehicleId, actorUserId, audit);
  if (!subject) {
    throw new VehicleServiceError('NOT_FOUND', 'Device not found');
  }

  const allowed = await canSubjectReadDeviceSnapshot(subject, actorUserId, snapshot, now);
  if (!allowed) {
    throw new VehicleServiceError('NOT_FOUND', 'Device not found');
  }
  return snapshot.publicDetail;
}

export async function listVehicleDevices(
  vehicleId: Types.ObjectId,
  actorUserId: Types.ObjectId,
  query: { limit?: number; cursor?: string; status?: DeviceStatus },
  ctx: VehicleDeviceOperationContext,
): Promise<{ devices: DeviceDetail[]; nextCursor: string | null }> {
  const audit = ctx.audit ?? defaultAuditLogger;
  const now = ctx.now ?? new Date();
  const limit = validatePageLimit(query.limit);
  const statusFilter: DeviceStatus | 'ALL' = query.status ?? 'ALL';
  const cursorScope: DeviceCursorScope = { actorUserId, vehicleId, statusFilter };
  const initialPosition =
    query.cursor === undefined
      ? null
      : decodeDeviceCursor(query.cursor, cursorScope, ctx.cursorSecrets);

  const subject = await loadActiveVehicleSubject(vehicleId, actorUserId, audit);
  if (!subject) {
    throw new VehicleServiceError('NOT_FOUND', 'Vehicle not found');
  }
  const { membership } = subject;

  const isOwnerOrManage =
    membership.role === 'OWNER' || hasBasePermission(membership, 'vehicle:manage');
  const hasBaseDeviceRead = hasBasePermission(membership, 'device:read');

  let hasLinkAuthority = isOwnerOrManage || hasBasePermission(membership, 'device:link');
  if (!hasLinkAuthority) {
    const linkDecision = await resourceAuthorization.evaluate(
      {
        actorUserId,
        vehicleId,
        resource: { type: 'VEHICLE' },
        permission: 'device:link',
        channel: 'ONLINE',
      },
      { clock: () => now, audit },
    );
    hasLinkAuthority = linkDecision.allowed && linkDecision.membershipId.equals(membership._id);
  }

  // Single bounded query for all ONLINE/ANY DEVICE-scoped device:read AccessGrants of this member
  let grantedDeviceIds = new Set<string>();
  if (!isOwnerOrManage && !hasBaseDeviceRead) {
    const grants = await guardedVehicleDb(() =>
      AccessGrantModel.find(
        {
          vehicleId,
          membershipId: membership._id,
          subjectUserId: actorUserId,
          scopeType: 'DEVICE',
          scopeResourceId: { $ne: null },
          channel: { $in: ['ONLINE', 'ANY'] },
          status: 'ACTIVE',
          revokedAt: null,
          expiredAt: null,
          startsAt: { $lte: now },
          $or: [{ expiresAt: { $gt: now } }, { expiresAt: null, channel: 'ONLINE' }],
          permissions: 'device:read',
        },
        { scopeResourceId: 1 },
      )
        .limit(MAX_DEVICE_GRANTS_QUERY_LIMIT)
        .lean<Array<{ scopeResourceId: Types.ObjectId | null }>>(),
    );
    grantedDeviceIds = new Set(
      grants
        .filter((grant) => grant.scopeResourceId !== null)
        .map((grant) => String(grant.scopeResourceId)),
    );
  }

  const hasAnyListAuthority =
    isOwnerOrManage || hasBaseDeviceRead || hasLinkAuthority || grantedDeviceIds.size > 0;
  if (!hasAnyListAuthority) {
    const readableVehicle = await resourceAuthorization.hasVehicleReadAccess(
      vehicleId,
      actorUserId,
      { clock: () => now, audit },
    );
    if (readableVehicle) {
      throw new VehicleServiceError('FORBIDDEN', 'Insufficient permissions to list devices');
    }
    throw new VehicleServiceError('NOT_FOUND', 'Vehicle not found');
  }

  // Fast-path when status filter cannot possibly match any device visible to this actor
  if (!isOwnerOrManage) {
    if (query.status === 'REVOKED') {
      return { devices: [], nextCursor: null };
    }
    if (query.status === 'PENDING' && !hasLinkAuthority) {
      return { devices: [], nextCursor: null };
    }
    if (query.status === 'ACTIVE' && !hasBaseDeviceRead && grantedDeviceIds.size === 0) {
      return { devices: [], nextCursor: null };
    }
  }

  // Narrow upstream status query when actor can only ever see a single status
  let upstreamStatus: DeviceStatus | undefined = query.status;
  if (upstreamStatus === undefined && !isOwnerOrManage) {
    const canSeeActive = hasBaseDeviceRead || grantedDeviceIds.size > 0;
    const canSeePending = hasLinkAuthority;
    if (canSeeActive && !canSeePending) upstreamStatus = 'ACTIVE';
    else if (canSeePending && !canSeeActive) upstreamStatus = 'PENDING';
  }

  function isSnapshotVisibleInList(snapshot: VerifiedDeviceSnapshot): boolean {
    if (isOwnerOrManage) return true;
    if (snapshot.record.status === 'ACTIVE') {
      if (hasBaseDeviceRead) return true;
      return snapshot.activeBinding !== null && grantedDeviceIds.has(snapshot.record.deviceId);
    }
    if (snapshot.record.status === 'PENDING') {
      return (
        hasLinkAuthority &&
        isOriginalRequesterInCurrentMembership(snapshot, actorUserId, membership._id)
      );
    }
    return false;
  }

  const visibleItems: VerifiedDeviceSnapshot[] = [];
  let scanPosition: DeviceCursorPosition | null = initialPosition;
  const batchSize = isOwnerOrManage
    ? Math.min(MAX_PAGE_LIMIT, limit + 1)
    : Math.min(MAX_PAGE_LIMIT, Math.max(limit * 2, 25));

  for (let batchIndex = 0; batchIndex < MAX_DEVICE_SCAN_BATCHES; batchIndex += 1) {
    let batch;
    try {
      batch = await ctx.deviceClient.listVehicleDevicesBatch({
        vehicleId: String(vehicleId),
        limit: batchSize,
        ...(upstreamStatus ? { status: upstreamStatus } : {}),
        ...(scanPosition
          ? { afterCreatedAt: scanPosition.createdAtIso, afterId: scanPosition.id }
          : {}),
      });
    } catch (error) {
      if (
        error instanceof DeviceUpstreamDomainError &&
        error.code === 'INCONSISTENT_DEVICE_STATE'
      ) {
        audit({
          action: 'device.list',
          actorUserId: String(actorUserId),
          vehicleId: String(vehicleId),
          outcome: 'denied',
          reason: 'inconsistent_device_state',
        });
        throw new VehicleUpstreamInconsistentError();
      }
      throw error;
    }

    for (const item of batch.items) {
      if (isSnapshotVisibleInList(item)) {
        visibleItems.push(item);
        if (visibleItems.length >= limit + 1) {
          break;
        }
      }
    }

    if (visibleItems.length >= limit + 1) {
      const pageSlice = visibleItems.slice(0, limit);
      const lastVisible = pageSlice[pageSlice.length - 1]!;
      return {
        devices: pageSlice.map((entry) => entry.publicDetail),
        nextCursor: encodeDeviceCursor(
          cursorScope,
          {
            createdAtIso: lastVisible.record.createdAt,
            id: lastVisible.record.deviceId,
          },
          ctx.cursorSecrets,
        ),
      };
    }

    if (!batch.hasMore || batch.items.length === 0) {
      return {
        devices: visibleItems.map((entry) => entry.publicDetail),
        nextCursor: null,
      };
    }

    const lastScanned = batch.items[batch.items.length - 1]!;
    const nextScanPosition: DeviceCursorPosition = {
      createdAtIso: lastScanned.record.createdAt,
      id: lastScanned.record.deviceId,
    };

    if (batchIndex + 1 === MAX_DEVICE_SCAN_BATCHES) {
      // MAX_DEVICE_SCAN_BATCHES exhausted with <= limit visible items (including 0) and
      // upstream candidates still remaining. Return an encrypted opaque cursor anchored at
      // `nextScanPosition` so progress is guaranteed without loops or leaking hidden devices.
      return {
        devices: visibleItems.map((entry) => entry.publicDetail),
        nextCursor: encodeDeviceCursor(cursorScope, nextScanPosition, ctx.cursorSecrets),
      };
    }

    scanPosition = nextScanPosition;
  }

  return { devices: [], nextCursor: null };
}

class VehicleUpstreamInconsistentError extends DeviceUpstreamUnavailableError {
  constructor() {
    super('Device persistence state inconsistent', 'PROTOCOL_ERROR');
  }
}

export async function updateVehicleDeviceMetadata(
  vehicleId: Types.ObjectId,
  deviceId: Types.ObjectId,
  actorUserId: Types.ObjectId,
  metadata: DeviceMetadataUpdateRequest,
  ctx: VehicleDeviceOperationContext,
): Promise<DeviceDetail> {
  const audit = ctx.audit ?? defaultAuditLogger;
  const now = ctx.now ?? new Date();

  const subject = await loadActiveVehicleSubject(vehicleId, actorUserId, audit);
  if (!subject) {
    throw new VehicleServiceError('NOT_FOUND', 'Vehicle not found');
  }

  const canEditMetadata =
    subject.membership.role === 'OWNER' || hasBasePermission(subject.membership, 'vehicle:manage');

  let currentSnapshot: VerifiedDeviceSnapshot | null;
  try {
    currentSnapshot = await ctx.deviceClient.getDeviceById(String(deviceId));
  } catch (error) {
    if (error instanceof DeviceUpstreamDomainError) {
      throw mapDomainErrorForMutation(error);
    }
    throw error;
  }

  if (!currentSnapshot || currentSnapshot.record.vehicleId !== String(vehicleId)) {
    throw new VehicleServiceError('NOT_FOUND', 'Device not found');
  }

  if (!canEditMetadata) {
    const canSeeDevice = await canSubjectReadDeviceSnapshot(
      subject,
      actorUserId,
      currentSnapshot,
      now,
    );
    const canSeeVehicle =
      canSeeDevice ||
      (await resourceAuthorization.hasVehicleReadAccess(vehicleId, actorUserId, {
        clock: () => now,
        audit,
      }));
    audit({
      action: 'device.metadata_update',
      actorUserId: String(actorUserId),
      vehicleId: String(vehicleId),
      targetId: String(deviceId),
      outcome: 'denied',
      reason: 'insufficient_metadata_authority',
    });
    if (canSeeDevice) {
      throw new VehicleServiceError(
        'FORBIDDEN',
        'Only the vehicle owner or a member with base vehicle:manage may update device metadata',
      );
    }
    if (canSeeVehicle) {
      // Do not disclose whether an invisible deviceId exists on the vehicle
      throw new VehicleServiceError('NOT_FOUND', 'Device not found');
    }
    throw new VehicleServiceError('NOT_FOUND', 'Device not found');
  }

  if (currentSnapshot.record.status === 'REVOKED') {
    throw new VehicleServiceError('CONFLICT', 'Revoked devices cannot be modified');
  }

  try {
    const updated = await ctx.deviceClient.updateDeviceMetadata({
      deviceId: String(deviceId),
      vehicleId: String(vehicleId),
      userId: String(actorUserId),
      metadata,
    });
    audit({
      action: 'device.metadata_update',
      actorUserId: String(actorUserId),
      vehicleId: String(vehicleId),
      targetId: String(deviceId),
      outcome: 'success',
    });
    return updated.publicDetail;
  } catch (error) {
    if (error instanceof DeviceUpstreamDomainError) {
      throw mapDomainErrorForMutation(error);
    }
    throw error;
  }
}

async function authorizeEnrollmentStep(
  action: 'device.challenge_issue' | 'device.link_complete',
  vehicleId: Types.ObjectId,
  deviceId: Types.ObjectId,
  actorUserId: Types.ObjectId,
  ctx: VehicleDeviceOperationContext,
): Promise<{ membershipId: Types.ObjectId; snapshot: VerifiedDeviceSnapshot }> {
  const audit = ctx.audit ?? defaultAuditLogger;
  const now = ctx.now ?? new Date();

  const subject = await loadActiveVehicleSubject(vehicleId, actorUserId, audit);
  if (!subject) {
    throw new VehicleServiceError('NOT_FOUND', 'Vehicle not found');
  }

  const linkDecision = await resourceAuthorization.evaluateAnyOf(
    {
      actorUserId,
      vehicleId,
      resource: { type: 'VEHICLE' },
      channel: 'ONLINE',
    },
    ['vehicle:manage', 'device:link'],
    { clock: () => now, audit },
  );

  let snapshot: VerifiedDeviceSnapshot | null;
  try {
    snapshot = await ctx.deviceClient.getDeviceById(String(deviceId));
  } catch (error) {
    if (error instanceof DeviceUpstreamDomainError) {
      throw mapDomainErrorForMutation(error);
    }
    throw error;
  }

  if (!snapshot || snapshot.record.vehicleId !== String(vehicleId)) {
    throw new VehicleServiceError('NOT_FOUND', 'Device not found');
  }

  const deviceVisibleToActor = await canSubjectReadDeviceSnapshot(
    subject,
    actorUserId,
    snapshot,
    now,
  );

  if (!linkDecision.allowed) {
    audit({
      action,
      actorUserId: String(actorUserId),
      vehicleId: String(vehicleId),
      targetId: String(deviceId),
      outcome: 'denied',
      reason: linkDecision.reason,
    });
    if (deviceVisibleToActor) {
      throw new VehicleServiceError('FORBIDDEN', 'Insufficient permissions to enroll devices');
    }
    throw new VehicleServiceError('NOT_FOUND', 'Device not found');
  }

  if (snapshot.record.status !== 'PENDING') {
    if (!deviceVisibleToActor) {
      throw new VehicleServiceError('NOT_FOUND', 'Device not found');
    }
    throw new VehicleServiceError('CONFLICT', 'Device is not pending enrollment');
  }

  if (
    snapshot.record.requestedByUserId === null ||
    snapshot.record.requestedByMembershipId === null
  ) {
    if (!deviceVisibleToActor) {
      throw new VehicleServiceError('NOT_FOUND', 'Device not found');
    }
    throw new VehicleServiceError(
      'CONFLICT',
      'Historical pending device lacks verifiable enrollment context',
    );
  }

  if (
    snapshot.record.requestedByUserId !== String(actorUserId) ||
    snapshot.record.requestedByMembershipId !== String(linkDecision.membershipId)
  ) {
    audit({
      action,
      actorUserId: String(actorUserId),
      vehicleId: String(vehicleId),
      targetId: String(deviceId),
      outcome: 'denied',
      reason: 'enrollment_membership_or_requester_mismatch',
    });
    if (deviceVisibleToActor) {
      throw new VehicleServiceError(
        'FORBIDDEN',
        'Only the original requester under their original active membership may enroll this device',
      );
    }
    throw new VehicleServiceError('NOT_FOUND', 'Device not found');
  }

  return { membershipId: linkDecision.membershipId, snapshot };
}

export async function issueVehicleDeviceChallenge(
  vehicleId: Types.ObjectId,
  deviceId: Types.ObjectId,
  actorUserId: Types.ObjectId,
  ctx: VehicleDeviceOperationContext,
): Promise<DeviceLinkChallenge> {
  const audit = ctx.audit ?? defaultAuditLogger;
  const { membershipId } = await authorizeEnrollmentStep(
    'device.challenge_issue',
    vehicleId,
    deviceId,
    actorUserId,
    ctx,
  );

  try {
    const challenge = await ctx.deviceClient.createChallenge({
      deviceId: String(deviceId),
      vehicleId: String(vehicleId),
      userId: String(actorUserId),
      membershipId: String(membershipId),
    });
    audit({
      action: 'device.challenge_issue',
      actorUserId: String(actorUserId),
      vehicleId: String(vehicleId),
      targetId: String(deviceId),
      outcome: 'success',
    });
    return challenge;
  } catch (error) {
    if (error instanceof DeviceUpstreamDomainError) {
      throw mapDomainErrorForMutation(error);
    }
    throw error;
  }
}

export async function completeVehicleDeviceLink(
  vehicleId: Types.ObjectId,
  deviceId: Types.ObjectId,
  actorUserId: Types.ObjectId,
  input: { challengeId: string; challenge: string; signature: string },
  ctx: VehicleDeviceOperationContext,
): Promise<DeviceDetail> {
  const audit = ctx.audit ?? defaultAuditLogger;
  const { membershipId } = await authorizeEnrollmentStep(
    'device.link_complete',
    vehicleId,
    deviceId,
    actorUserId,
    ctx,
  );

  try {
    const linked = await ctx.deviceClient.completeLink({
      deviceId: String(deviceId),
      vehicleId: String(vehicleId),
      userId: String(actorUserId),
      membershipId: String(membershipId),
      challengeId: input.challengeId,
      challenge: input.challenge,
      signature: input.signature,
    });
    audit({
      action: 'device.link_complete',
      actorUserId: String(actorUserId),
      vehicleId: String(vehicleId),
      targetId: String(deviceId),
      outcome: 'success',
    });
    return linked.publicDetail;
  } catch (error) {
    if (error instanceof DeviceUpstreamDomainError) {
      throw mapDomainErrorForMutation(error);
    }
    throw error;
  }
}

export async function revokeVehicleDevice(
  vehicleId: Types.ObjectId,
  deviceId: Types.ObjectId,
  actorUserId: Types.ObjectId,
  reason: DeviceRevocationReason,
  ctx: VehicleDeviceOperationContext,
): Promise<DeviceDetail> {
  const audit = ctx.audit ?? defaultAuditLogger;
  const now = ctx.now ?? new Date();

  const subject = await loadActiveVehicleSubject(vehicleId, actorUserId, audit);
  if (!subject) {
    throw new VehicleServiceError('NOT_FOUND', 'Vehicle not found');
  }

  let snapshot: VerifiedDeviceSnapshot | null;
  try {
    snapshot = await ctx.deviceClient.getDeviceById(String(deviceId));
  } catch (error) {
    if (error instanceof DeviceUpstreamDomainError) {
      throw mapDomainErrorForMutation(error);
    }
    throw error;
  }

  if (!snapshot || snapshot.record.vehicleId !== String(vehicleId)) {
    throw new VehicleServiceError('NOT_FOUND', 'Device not found');
  }

  const isCanonicalOwner = subject.membership.role === 'OWNER';

  if (!isCanonicalOwner) {
    // Non-owner exception (§6): ONLY the original requester under their SAME active membership,
    // holding valid link authorization (`vehicle:manage` or `device:link`), with reason
    // `REGISTRATION_CANCELLED`, on their own PENDING device (or idempotent repeat of their own
    // prior `REGISTRATION_CANCELLED` revocation).
    const linkDecision = await resourceAuthorization.evaluateAnyOf(
      {
        actorUserId,
        vehicleId,
        resource: { type: 'VEHICLE' },
        channel: 'ONLINE',
      },
      ['vehicle:manage', 'device:link'],
      { clock: () => now, audit },
    );

    const sameEnrollmentContext =
      linkDecision.allowed &&
      isOriginalRequesterInCurrentMembership(snapshot, actorUserId, linkDecision.membershipId);

    const isFirstOwnPendingCancel =
      sameEnrollmentContext &&
      reason === 'REGISTRATION_CANCELLED' &&
      snapshot.record.status === 'PENDING';

    const isIdempotentRepeatOfOwnCancel =
      sameEnrollmentContext &&
      reason === 'REGISTRATION_CANCELLED' &&
      snapshot.record.status === 'REVOKED' &&
      snapshot.record.revocationReason === 'REGISTRATION_CANCELLED' &&
      snapshot.record.revokedByUserId === String(actorUserId);

    if (!isFirstOwnPendingCancel && !isIdempotentRepeatOfOwnCancel) {
      const deviceVisible =
        (await canSubjectReadDeviceSnapshot(subject, actorUserId, snapshot, now)) ||
        (sameEnrollmentContext && snapshot.record.revokedByUserId === String(actorUserId));
      audit({
        action: 'device.revoke',
        actorUserId: String(actorUserId),
        vehicleId: String(vehicleId),
        targetId: String(deviceId),
        outcome: 'denied',
        reason: 'owner_required_or_invalid_self_cancellation',
      });
      if (deviceVisible) {
        if (
          sameEnrollmentContext &&
          snapshot.record.status === 'ACTIVE' &&
          reason === 'REGISTRATION_CANCELLED'
        ) {
          throw new VehicleServiceError(
            'FORBIDDEN',
            'Only the canonical vehicle owner may revoke an active device',
          );
        }
        throw new VehicleServiceError(
          'FORBIDDEN',
          'Only the canonical vehicle owner may perform administrative device revocation',
        );
      }
      throw new VehicleServiceError('NOT_FOUND', 'Device not found');
    }
  } else if (snapshot.record.status === 'ACTIVE' && reason === 'REGISTRATION_CANCELLED') {
    throw new VehicleServiceError(
      'CONFLICT',
      'REGISTRATION_CANCELLED applies only to PENDING devices',
    );
  }

  try {
    const revoked = await ctx.deviceClient.revokeDevice({
      deviceId: String(deviceId),
      vehicleId: String(vehicleId),
      userId: String(actorUserId),
      reason,
    });
    audit({
      action: 'device.revoke',
      actorUserId: String(actorUserId),
      vehicleId: String(vehicleId),
      targetId: String(deviceId),
      outcome: 'success',
      reason,
    });
    return revoked.publicDetail;
  } catch (error) {
    if (error instanceof DeviceUpstreamDomainError) {
      throw mapDomainErrorForMutation(error);
    }
    throw error;
  }
}

export { DeviceUpstreamTimeoutError, DeviceUpstreamUnavailableError };
