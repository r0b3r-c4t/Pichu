import { Types, type ClientSession } from 'mongoose';
import {
  DEVICE_METADATA_FIELDS,
  DEVICE_REVOCATION_REASONS,
  internalDeviceRecordSchema,
  type DeviceCredentialEffectiveStatus,
  type DeviceMetadata,
  type DeviceRevocationReason,
  type InternalDeviceRecord,
} from '@pichu/contracts';
import { runInDeviceTransaction } from '../database/transaction.js';
import {
  DeviceCredentialModel,
  isCredentialUsable,
  type DeviceCredential,
} from '../models/device-credential.model.js';
import { DeviceRevocationModel, type DeviceRevocation } from '../models/device-revocation.model.js';
import { DEVICE_STATUSES, DeviceModel, type Device } from '../models/device.model.js';
import { DeviceServiceError } from './device-errors.js';

const OBJECT_ID_PATTERN = /^[a-f0-9]{24}$/;

export type PersistedDeviceDoc = Omit<Device, 'metadata' | 'requestedByMembershipId'> & {
  _id: Types.ObjectId;
  requestedByMembershipId?: Types.ObjectId | null;
  metadata?: Partial<Record<keyof DeviceMetadata, string | null>> | null;
};

export type PersistedCredentialDoc = DeviceCredential & { _id: Types.ObjectId };
export type PersistedRevocationDoc = DeviceRevocation & { _id: Types.ObjectId };

function inconsistent(detail: string): DeviceServiceError {
  return new DeviceServiceError('INCONSISTENT_DEVICE_STATE', detail);
}

/** Normalizes persisted metadata, backfilling `null` on historical documents lacking `metadata`. */
export function normalizePersistedMetadata(
  raw: PersistedDeviceDoc['metadata'] | undefined,
): DeviceMetadata {
  const result: Record<string, string | null> = {};
  for (const field of DEVICE_METADATA_FIELDS) {
    const value = raw?.[field];
    result[field] = typeof value === 'string' ? value : null;
  }
  return result as DeviceMetadata;
}

function isKnownRevocationReason(value: unknown): value is DeviceRevocationReason {
  return (
    typeof value === 'string' && (DEVICE_REVOCATION_REASONS as readonly string[]).includes(value)
  );
}

function compareRevokedCredentialsDeterministically(
  left: PersistedCredentialDoc,
  right: PersistedCredentialDoc,
): number {
  const leftRevoked = left.revokedAt ? left.revokedAt.getTime() : 0;
  const rightRevoked = right.revokedAt ? right.revokedAt.getTime() : 0;
  if (rightRevoked !== leftRevoked) return rightRevoked - leftRevoked;

  const leftActivated = left.activatedAt.getTime();
  const rightActivated = right.activatedAt.getTime();
  if (rightActivated !== leftActivated) return rightActivated - leftActivated;

  return String(right._id).localeCompare(String(left._id));
}

/**
 * Deterministically selects the single credential represented in `deviceDetailSchema` and validates
 * structural invariants across Device, DeviceCredential[], and DeviceRevocation. Any corrupted or
 * contradictory state fails closed (`INCONSISTENT_DEVICE_STATE`).
 */
export function assembleInternalDeviceRecord(
  device: PersistedDeviceDoc,
  credentials: readonly PersistedCredentialDoc[],
  deviceRevocation: PersistedRevocationDoc | null,
  now: Date,
): InternalDeviceRecord {
  if (!(DEVICE_STATUSES as readonly string[]).includes(device.status)) {
    throw inconsistent('Unknown device status');
  }
  if (!device.vehicleId) {
    throw inconsistent('Device lacks vehicleId');
  }
  if (!(device.createdAt instanceof Date) || !(device.updatedAt instanceof Date)) {
    throw inconsistent('Device lacks valid timestamps');
  }

  if (device.status === 'PENDING') {
    if (
      device.linkedByUserId !== null ||
      device.linkedAt !== null ||
      device.revokedAt !== null ||
      device.revocationId !== null ||
      deviceRevocation !== null
    ) {
      throw inconsistent('PENDING device carries link or revocation state');
    }
  } else if (device.status === 'ACTIVE') {
    if (
      device.linkedByUserId === null ||
      device.revokedAt !== null ||
      device.revocationId !== null ||
      deviceRevocation !== null
    ) {
      throw inconsistent('ACTIVE device lacks link actor or carries revocation state');
    }
  } else if (device.status === 'REVOKED') {
    if (
      device.revokedAt === null ||
      device.revocationId === null ||
      !deviceRevocation ||
      !deviceRevocation._id.equals(device.revocationId) ||
      deviceRevocation.targetType !== 'DEVICE' ||
      !deviceRevocation.deviceId.equals(device._id) ||
      !isKnownRevocationReason(deviceRevocation.reason)
    ) {
      throw inconsistent('REVOKED device lacks coherent DeviceRevocation record');
    }
  }

  if (credentials.length === 0) {
    throw inconsistent('Device has no credentials');
  }

  for (const cred of credentials) {
    if (!cred.deviceId.equals(device._id) || cred.algorithm !== 'Ed25519') {
      throw inconsistent('Credential invariant mismatch');
    }
    if (cred.status === 'ACTIVE' && (cred.revokedAt !== null || cred.revocationId !== null)) {
      throw inconsistent('ACTIVE credential carries revocation fields');
    }
    if (cred.status === 'REVOKED' && (cred.revokedAt === null || cred.revocationId === null)) {
      throw inconsistent('REVOKED credential lacks revocation fields');
    }
  }

  const activeCredentials = credentials.filter((cred) => cred.status === 'ACTIVE');
  if (activeCredentials.length > 1) {
    throw inconsistent('Device has multiple ACTIVE credentials');
  }
  if (device.status === 'REVOKED' && activeCredentials.length > 0) {
    throw inconsistent('REVOKED device still holds an ACTIVE credential');
  }

  let selected: PersistedCredentialDoc;
  if (activeCredentials.length === 1) {
    selected = activeCredentials[0]!;
  } else {
    const revokedCredentials = [...credentials].sort(compareRevokedCredentialsDeterministically);
    if (device.status === 'REVOKED' && device.revocationId) {
      const revokedWithDevice = revokedCredentials.find(
        (cred) => cred.revocationId !== null && cred.revocationId.equals(device.revocationId!),
      );
      selected = revokedWithDevice ?? revokedCredentials[0]!;
    } else {
      selected = revokedCredentials[0]!;
    }
  }

  const usable = isCredentialUsable(selected, now);
  let effectiveCredStatus: DeviceCredentialEffectiveStatus;
  if (selected.status === 'REVOKED') {
    effectiveCredStatus = 'REVOKED';
  } else if (selected.expiresAt !== null && selected.expiresAt.getTime() <= now.getTime()) {
    effectiveCredStatus = 'EXPIRED';
  } else {
    effectiveCredStatus = 'ACTIVE';
  }

  const operational = device.status === 'ACTIVE' && usable;
  const revokedByUserId =
    deviceRevocation?.actor.type === 'USER' && deviceRevocation.actor.userId
      ? String(deviceRevocation.actor.userId)
      : null;

  const candidate: InternalDeviceRecord = {
    deviceId: String(device._id),
    vehicleId: String(device.vehicleId),
    identifier: device.identifier,
    status: device.status,
    operational,
    credential: {
      credentialId: String(selected._id),
      keyId: selected.keyId,
      algorithm: 'Ed25519',
      fingerprint: selected.fingerprint,
      status: effectiveCredStatus,
      usable,
      activatedAt: selected.activatedAt.toISOString(),
      expiresAt: selected.expiresAt ? selected.expiresAt.toISOString() : null,
      revokedAt: selected.revokedAt ? selected.revokedAt.toISOString() : null,
    },
    connectivity: {
      lastSeenAt: device.lastSeenAt ? device.lastSeenAt.toISOString() : null,
    },
    metadata: normalizePersistedMetadata(device.metadata),
    createdAt: device.createdAt.toISOString(),
    updatedAt: device.updatedAt.toISOString(),
    linkedAt: device.linkedAt ? device.linkedAt.toISOString() : null,
    revokedAt: device.revokedAt ? device.revokedAt.toISOString() : null,
    revocationReason:
      device.status === 'REVOKED' && deviceRevocation
        ? (deviceRevocation.reason as DeviceRevocationReason)
        : null,
    requestedByUserId: device.requestedByUserId ? String(device.requestedByUserId) : null,
    requestedByMembershipId: device.requestedByMembershipId
      ? String(device.requestedByMembershipId)
      : null,
    revokedByUserId,
  };

  const parsed = internalDeviceRecordSchema.safeParse(candidate);
  if (!parsed.success) {
    throw inconsistent('Persisted device failed canonical output validation');
  }
  return parsed.data;
}

export async function loadInternalDeviceInSession(
  deviceId: Types.ObjectId,
  session: ClientSession,
  now: Date,
): Promise<InternalDeviceRecord | null> {
  const device = await DeviceModel.findById(deviceId).session(session).lean<PersistedDeviceDoc>();
  if (!device) return null;
  const [credentials, revocation] = await Promise.all([
    DeviceCredentialModel.find({ deviceId }).session(session).lean<PersistedCredentialDoc[]>(),
    DeviceRevocationModel.findOne({ targetType: 'DEVICE', deviceId })
      .session(session)
      .lean<PersistedRevocationDoc>(),
  ]);
  return assembleInternalDeviceRecord(device, credentials, revocation ?? null, now);
}

export async function getInternalDeviceById(
  deviceId: string,
  options: { now?: Date } = {},
): Promise<InternalDeviceRecord | null> {
  if (!OBJECT_ID_PATTERN.test(deviceId)) return null;
  const id = new Types.ObjectId(deviceId);
  const now = options.now ?? new Date();
  return runInDeviceTransaction((session) => loadInternalDeviceInSession(id, session, now));
}

export interface ListInternalVehicleDevicesInput {
  vehicleId: string;
  limit: number;
  status?: 'PENDING' | 'ACTIVE' | 'REVOKED';
  afterCreatedAt?: string;
  afterId?: string;
}

/**
 * Keyset batch read ordered by `(createdAt ASC, _id ASC)` inside one snapshot transaction.
 * Performs exactly 3 bounded collection reads regardless of `limit` (zero N+1).
 */
export async function listInternalVehicleDevices(
  input: ListInternalVehicleDevicesInput,
  options: { now?: Date } = {},
): Promise<{ devices: InternalDeviceRecord[]; hasMore: boolean }> {
  if (!OBJECT_ID_PATTERN.test(input.vehicleId)) {
    return { devices: [], hasMore: false };
  }
  const vehicleId = new Types.ObjectId(input.vehicleId);
  const limit = Math.min(Math.max(Math.trunc(input.limit), 1), 100);
  const now = options.now ?? new Date();

  const filter: Record<string, unknown> = { vehicleId };
  if (input.status !== undefined) {
    filter.status = input.status;
  }
  if (input.afterCreatedAt !== undefined && input.afterId !== undefined) {
    const afterDate = new Date(input.afterCreatedAt);
    const afterObjectId = new Types.ObjectId(input.afterId);
    filter.$or = [
      { createdAt: { $gt: afterDate } },
      { createdAt: afterDate, _id: { $gt: afterObjectId } },
    ];
  }

  return runInDeviceTransaction(async (session) => {
    const rows = await DeviceModel.find(filter)
      .sort({ createdAt: 1, _id: 1 })
      .limit(limit + 1)
      .session(session)
      .lean<PersistedDeviceDoc[]>();

    const hasMore = rows.length > limit;
    const pageRows = rows.slice(0, limit);
    if (pageRows.length === 0) {
      return { devices: [], hasMore: false };
    }

    const ids = pageRows.map((row) => row._id);
    const [allCredentials, allRevocations] = await Promise.all([
      DeviceCredentialModel.find({ deviceId: { $in: ids } })
        .session(session)
        .lean<PersistedCredentialDoc[]>(),
      DeviceRevocationModel.find({ targetType: 'DEVICE', deviceId: { $in: ids } })
        .session(session)
        .lean<PersistedRevocationDoc[]>(),
    ]);

    const credsByDevice = new Map<string, PersistedCredentialDoc[]>();
    for (const cred of allCredentials) {
      const key = String(cred.deviceId);
      const list = credsByDevice.get(key);
      if (list) list.push(cred);
      else credsByDevice.set(key, [cred]);
    }
    const revByDevice = new Map<string, PersistedRevocationDoc>();
    for (const rev of allRevocations) {
      revByDevice.set(String(rev.deviceId), rev);
    }

    const devices = pageRows.map((row) =>
      assembleInternalDeviceRecord(
        row,
        credsByDevice.get(String(row._id)) ?? [],
        revByDevice.get(String(row._id)) ?? null,
        now,
      ),
    );
    return { devices, hasMore };
  });
}
