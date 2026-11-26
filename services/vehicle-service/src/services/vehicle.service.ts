import mongoose, { type ClientSession, type Model, Types } from 'mongoose';
import { AccessGrantModel, type AccessGrant } from '../models/access-grant.model.js';
import { InvitationModel, type Invitation } from '../models/invitation.model.js';
import { MembershipModel, type Membership } from '../models/membership.model.js';
import {
  containsControlCharacter,
  DEFAULT_INVITATION_TTL_MS,
  isAccessGrantPermissionForScope,
  isDelegableMembershipPermission,
  isKnownPermission,
  isOwnerReservedPermission,
  normalizeOptionalText,
  validatePermissionSet,
  type AccessGrantChannel,
  type AccessGrantScopeType,
} from '../models/vehicle-constants.js';
import { VehicleModel, type Vehicle } from '../models/vehicle.model.js';

export type VehicleDomainErrorCode =
  'VALIDATION_ERROR' | 'FORBIDDEN' | 'NOT_FOUND' | 'CONFLICT' | 'DATABASE_UNAVAILABLE';

export class VehicleServiceError extends Error {
  constructor(
    public readonly code: VehicleDomainErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = 'VehicleServiceError';
  }
}

export interface VehicleAuditEvent {
  action: string;
  actorUserId: string;
  vehicleId?: string;
  targetId?: string;
  outcome: 'success' | 'denied' | 'conflict' | 'error';
  reason?: string;
}

export type VehicleAuditLogger = (event: VehicleAuditEvent) => void;

const defaultAuditLogger: VehicleAuditLogger = () => undefined;

export interface CreateVehicleInput {
  name: string;
  make?: string | null;
  model?: string | null;
  generation?: string | null;
  trim?: string | null;
  year?: number | null;
  bodyStyle?: string | null;
  engine?: string | null;
  transmission?: string | null;
  fuelType?: string | null;
}

const VERIFIED_RESOURCE_BINDING_BRAND: unique symbol = Symbol('VerifiedExternalResourceBinding');

export interface VerifiedExternalResourceBinding {
  readonly [VERIFIED_RESOURCE_BINDING_BRAND]: true;
  readonly scopeType: 'DEVICE' | 'MODULE';
  readonly resourceId: Types.ObjectId;
  readonly vehicleId: Types.ObjectId;
  readonly isActive: boolean;
}

/**
 * Trusted internal factory for owner-service resource bindings (Device / Automation).
 * Plain JSON objects (e.g., deserialized from untrusted HTTP input) cannot carry the
 * module-private brand symbol and are always rejected fail-closed.
 */
export function createVerifiedExternalResourceBinding(input: {
  scopeType: 'DEVICE' | 'MODULE';
  resourceId: Types.ObjectId;
  vehicleId: Types.ObjectId;
  isActive: boolean;
}): VerifiedExternalResourceBinding {
  return Object.freeze({
    [VERIFIED_RESOURCE_BINDING_BRAND]: true as const,
    scopeType: input.scopeType,
    resourceId: input.resourceId,
    vehicleId: input.vehicleId,
    isActive: input.isActive,
  });
}

function isTrustedVerifiedResourceBinding(
  value: unknown,
): value is VerifiedExternalResourceBinding {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as Record<symbol, unknown>)[VERIFIED_RESOURCE_BINDING_BRAND] === true
  );
}

export interface EvaluateVehiclePermissionInput {
  vehicleId: Types.ObjectId;
  userId: Types.ObjectId;
  permission: string;
  scopeType?: AccessGrantScopeType;
  scopeResourceId?: Types.ObjectId | null;
  channel?: 'ONLINE' | 'BLE_OFFLINE';
  verifiedResourceBinding?: VerifiedExternalResourceBinding;
  now?: Date;
}

export type PermissionDecisionReason =
  | 'ALLOWED'
  | 'UNKNOWN_OR_INVALID_PERMISSION'
  | 'INVALID_SCOPE'
  | 'UNVERIFIED_EXTERNAL_RESOURCE'
  | 'VEHICLE_UNAVAILABLE_OR_INCONSISTENT'
  | 'MEMBERSHIP_INACTIVE_OR_MISSING'
  | 'OWNERSHIP_MISMATCH'
  | 'OWNER_PERMISSION_FORBIDDEN'
  | 'BLE_OWNER_GRANT_REQUIRED'
  | 'PERMISSION_NOT_GRANTED';

export interface PermissionEvaluationResult {
  allowed: boolean;
  reason: PermissionDecisionReason;
  source?: 'OWNER_ROLE' | 'MEMBERSHIP_PERMISSION' | 'ACCESS_GRANT';
  membershipId?: Types.ObjectId;
  grantId?: Types.ObjectId;
}

export interface CreateAccessGrantInput {
  vehicleId: Types.ObjectId;
  membershipId: Types.ObjectId;
  subjectUserId: Types.ObjectId;
  actorUserId: Types.ObjectId;
  scopeType: AccessGrantScopeType;
  scopeResourceId?: Types.ObjectId | null;
  channel?: AccessGrantChannel;
  permissions: string[];
  startsAt?: Date;
  expiresAt?: Date | null;
  now?: Date;
  audit?: VehicleAuditLogger;
}

const TRANSACTION_OPTIONS = {
  readPreference: 'primary',
  readConcern: { level: 'snapshot' },
  writeConcern: { w: 'majority' },
} as const;

class TransactionAbortDomainError extends Error {
  constructor(
    public readonly code: VehicleDomainErrorCode | 'REJECT_NULL',
    message: string,
  ) {
    super(message);
    this.name = 'TransactionAbortDomainError';
  }
}

function isDuplicateKeyError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === 11000
  );
}

function isDetachedUnitTestModelStub(): boolean {
  return (
    mongoose.connection.readyState === 0 &&
    (VehicleModel.create !== mongoose.Model.create ||
      MembershipModel.create !== mongoose.Model.create)
  );
}

async function runInVehicleTransaction<T>(
  work: (session: ClientSession | undefined) => Promise<T>,
): Promise<T> {
  if (mongoose.connection.readyState === 1) {
    const session = await mongoose.connection.startSession();
    try {
      let outcome!: T;
      await session.withTransaction(async () => {
        outcome = await work(session);
      }, TRANSACTION_OPTIONS);
      return outcome;
    } finally {
      await session.endSession();
    }
  }

  if (isDetachedUnitTestModelStub()) {
    return work(undefined);
  }

  throw new VehicleServiceError('DATABASE_UNAVAILABLE', 'Vehicle database is not connected');
}

async function createDocumentWithSession<TSchema>(
  modelInstance: Model<TSchema>,
  payload: Record<string, unknown>,
  session: ClientSession | undefined,
) {
  if (!session) {
    return modelInstance.create(payload as never);
  }
  const created = await modelInstance.create([payload as never], { session });
  return created[0]!;
}

function validateCreateVehicleInput(input: CreateVehicleInput): Required<CreateVehicleInput> {
  const trimmedName = typeof input.name === 'string' ? input.name.trim() : '';
  if (trimmedName.length < 1 || trimmedName.length > 120 || containsControlCharacter(trimmedName)) {
    throw new VehicleServiceError('VALIDATION_ERROR', 'Invalid vehicle name');
  }

  const optionalSpecs: Array<[keyof Omit<CreateVehicleInput, 'name' | 'year'>, number]> = [
    ['make', 80],
    ['model', 80],
    ['generation', 60],
    ['trim', 80],
    ['bodyStyle', 60],
    ['engine', 80],
    ['transmission', 60],
    ['fuelType', 60],
  ];

  const normalizedStrings: Record<string, string | null> = {};
  for (const [field, maxLen] of optionalSpecs) {
    const raw = input[field];
    if (raw !== undefined && raw !== null && typeof raw !== 'string') {
      throw new VehicleServiceError('VALIDATION_ERROR', `Invalid vehicle ${field}`);
    }
    const normalized = normalizeOptionalText(raw);
    if (
      normalized !== null &&
      (normalized.length > maxLen || containsControlCharacter(normalized))
    ) {
      throw new VehicleServiceError('VALIDATION_ERROR', `Invalid vehicle ${field}`);
    }
    normalizedStrings[field] = normalized;
  }

  const year = input.year ?? null;
  if (year !== null && (!Number.isInteger(year) || year < 1886 || year > 2100)) {
    throw new VehicleServiceError('VALIDATION_ERROR', 'Invalid vehicle year');
  }

  return {
    name: trimmedName,
    make: normalizedStrings.make ?? null,
    model: normalizedStrings.model ?? null,
    generation: normalizedStrings.generation ?? null,
    trim: normalizedStrings.trim ?? null,
    year,
    bodyStyle: normalizedStrings.bodyStyle ?? null,
    engine: normalizedStrings.engine ?? null,
    transmission: normalizedStrings.transmission ?? null,
    fuelType: normalizedStrings.fuelType ?? null,
  };
}

function validateOptionalAuditReason(reason: string | null | undefined): string | null {
  if (reason === undefined || reason === null) {
    return null;
  }
  if (typeof reason !== 'string') {
    throw new VehicleServiceError('VALIDATION_ERROR', 'Invalid audit reason');
  }
  const normalized = normalizeOptionalText(reason);
  if (normalized !== null && (normalized.length > 256 || containsControlCharacter(normalized))) {
    throw new VehicleServiceError('VALIDATION_ERROR', 'Invalid audit reason');
  }
  return normalized;
}

/**
 * Loads an ACTIVE vehicle and verifies canonical ownership consistency:
 * Vehicle.ownerUserId MUST match a single ACTIVE, unrevoked, unsuspended OWNER Membership.
 * Any discrepancy fails closed and returns null.
 */
export async function loadVerifiedActiveVehicle(
  vehicleId: Types.ObjectId,
  options: {
    session?: ClientSession;
    audit?: VehicleAuditLogger;
    actorUserId?: Types.ObjectId;
  } = {},
): Promise<(Vehicle & { _id: Types.ObjectId }) | null> {
  const audit = options.audit ?? defaultAuditLogger;
  const vehicleQuery = VehicleModel.findOne({ _id: vehicleId, status: 'ACTIVE' });
  if (options.session) {
    vehicleQuery.session(options.session);
  }
  const vehicle = (await vehicleQuery.lean()) as (Vehicle & { _id: Types.ObjectId }) | null;
  if (!vehicle) {
    return null;
  }

  const ownerMembershipsQuery = MembershipModel.find({
    vehicleId,
    role: 'OWNER',
    revokedAt: null,
  });
  if (options.session) {
    ownerMembershipsQuery.session(options.session);
  }
  const ownerMemberships = (await ownerMembershipsQuery.lean()) as Array<
    Membership & { _id: Types.ObjectId }
  >;

  const ownerRecord = ownerMemberships[0];
  const isConsistent =
    ownerMemberships.length === 1 &&
    ownerRecord !== undefined &&
    ownerRecord.status === 'ACTIVE' &&
    ownerRecord.suspendedAt === null &&
    ownerRecord.revokedAt === null &&
    ownerRecord.userId.equals(vehicle.ownerUserId);

  if (!isConsistent) {
    audit({
      action: 'vehicle.ownership_inconsistency',
      actorUserId: options.actorUserId ? String(options.actorUserId) : 'system',
      vehicleId: String(vehicleId),
      outcome: 'denied',
      reason: 'canonical_owner_mismatch',
    });
    return null;
  }

  return vehicle;
}

/**
 * Acquires a write-conflict barrier on the ACTIVE Vehicle document and its canonical
 * ACTIVE OWNER Membership inside a MongoDB transaction.
 *
 * Snapshot isolation alone does NOT prevent write skew across distinct documents when a
 * transaction only reads a parent document. Performing a conditional write on Vehicle
 * and the OWNER Membership guarantees WiredTiger WriteConflict serialization against
 * concurrent archiveVehicle / ownership state changes, triggering automatic retry in
 * session.withTransaction with a fresh snapshot.
 */
async function lockVerifiedActiveVehicle(
  vehicleId: Types.ObjectId,
  session: ClientSession | undefined,
  options: {
    now?: Date;
    audit?: VehicleAuditLogger;
    actorUserId?: Types.ObjectId;
  } = {},
): Promise<(Vehicle & { _id: Types.ObjectId }) | null> {
  if (!session) {
    return loadVerifiedActiveVehicle(vehicleId, options);
  }

  const audit = options.audit ?? defaultAuditLogger;
  const now = options.now ?? new Date();

  const lockedVehicle = (await VehicleModel.findOneAndUpdate(
    { _id: vehicleId, status: 'ACTIVE' },
    { $set: { updatedAt: now } },
    { returnDocument: 'after', session },
  ).lean()) as (Vehicle & { _id: Types.ObjectId }) | null;

  if (!lockedVehicle) {
    return null;
  }

  const ownerMemberships = (await MembershipModel.find({
    vehicleId,
    role: 'OWNER',
    revokedAt: null,
  })
    .session(session)
    .lean()) as Array<Membership & { _id: Types.ObjectId }>;

  const ownerRecord = ownerMemberships[0];
  const isConsistent =
    ownerMemberships.length === 1 &&
    ownerRecord !== undefined &&
    ownerRecord.status === 'ACTIVE' &&
    ownerRecord.suspendedAt === null &&
    ownerRecord.revokedAt === null &&
    ownerRecord.userId.equals(lockedVehicle.ownerUserId);

  if (!isConsistent) {
    audit({
      action: 'vehicle.ownership_inconsistency',
      actorUserId: options.actorUserId ? String(options.actorUserId) : 'system',
      vehicleId: String(vehicleId),
      outcome: 'denied',
      reason: 'canonical_owner_mismatch',
    });
    return null;
  }

  const lockedOwner = await MembershipModel.findOneAndUpdate(
    {
      _id: ownerRecord._id,
      vehicleId,
      userId: lockedVehicle.ownerUserId,
      role: 'OWNER',
      status: 'ACTIVE',
      suspendedAt: null,
      revokedAt: null,
    },
    { $set: { updatedAt: now } },
    { returnDocument: 'after', session },
  ).lean();

  if (!lockedOwner) {
    return null;
  }

  return lockedVehicle;
}

export async function createVehicle(
  userId: Types.ObjectId,
  input: CreateVehicleInput,
  options: { audit?: VehicleAuditLogger } = {},
) {
  const audit = options.audit ?? defaultAuditLogger;
  const validated = validateCreateVehicleInput(input);

  const createdVehicle = await runInVehicleTransaction(async (session) => {
    const vehicle = await createDocumentWithSession(
      VehicleModel,
      {
        ...validated,
        ownerUserId: userId,
        status: 'ACTIVE',
        createdByUserId: userId,
        updatedByUserId: null,
        archivedAt: null,
        archivedByUserId: null,
        archiveReason: null,
      },
      session,
    );

    await createDocumentWithSession(
      MembershipModel,
      {
        vehicleId: vehicle._id,
        userId,
        role: 'OWNER',
        permissions: ['vehicle:manage'],
        status: 'ACTIVE',
        sourceInvitationId: null,
        grantedByUserId: userId,
        updatedByUserId: null,
        suspendedAt: null,
        suspendedByUserId: null,
        suspensionReason: null,
        revokedAt: null,
        revokedByUserId: null,
        revokeReason: null,
      },
      session,
    );

    return vehicle;
  });

  audit({
    action: 'vehicle.create',
    actorUserId: String(userId),
    vehicleId: String(createdVehicle._id),
    outcome: 'success',
  });

  return createdVehicle;
}

export async function evaluateVehiclePermission(
  input: EvaluateVehiclePermissionInput,
): Promise<PermissionEvaluationResult> {
  const scopeType = input.scopeType ?? 'VEHICLE';
  const scopeResourceId = input.scopeResourceId ?? null;
  const channel = input.channel ?? 'ONLINE';
  const now = input.now ?? new Date();

  if (!isKnownPermission(input.permission)) {
    return { allowed: false, reason: 'UNKNOWN_OR_INVALID_PERMISSION' };
  }

  if (scopeType === 'VEHICLE' && scopeResourceId !== null) {
    return { allowed: false, reason: 'INVALID_SCOPE' };
  }

  if ((scopeType === 'DEVICE' || scopeType === 'MODULE') && scopeResourceId === null) {
    return { allowed: false, reason: 'INVALID_SCOPE' };
  }

  if (scopeType === 'DEVICE' || scopeType === 'MODULE') {
    const binding = input.verifiedResourceBinding;
    if (
      !isTrustedVerifiedResourceBinding(binding) ||
      !binding.isActive ||
      binding.scopeType !== scopeType ||
      !binding.resourceId.equals(scopeResourceId!) ||
      !binding.vehicleId.equals(input.vehicleId)
    ) {
      return { allowed: false, reason: 'UNVERIFIED_EXTERNAL_RESOURCE' };
    }
  }

  const vehicle = await loadVerifiedActiveVehicle(input.vehicleId, { actorUserId: input.userId });
  if (!vehicle) {
    return { allowed: false, reason: 'VEHICLE_UNAVAILABLE_OR_INCONSISTENT' };
  }

  const membership = (await MembershipModel.findOne({
    vehicleId: input.vehicleId,
    userId: input.userId,
    status: 'ACTIVE',
    suspendedAt: null,
    revokedAt: null,
  }).lean()) as (Membership & { _id: Types.ObjectId }) | null;

  if (!membership) {
    return { allowed: false, reason: 'MEMBERSHIP_INACTIVE_OR_MISSING' };
  }

  if (membership.role === 'OWNER') {
    if (!vehicle.ownerUserId.equals(input.userId)) {
      return { allowed: false, reason: 'OWNERSHIP_MISMATCH' };
    }
    if (channel === 'BLE_OFFLINE') {
      return { allowed: false, reason: 'BLE_OWNER_GRANT_REQUIRED' };
    }
    return {
      allowed: true,
      reason: 'ALLOWED',
      source: 'OWNER_ROLE',
      membershipId: membership._id,
    };
  }

  if (vehicle.ownerUserId.equals(input.userId)) {
    // Owner without OWNER role indicates corrupted state; fail closed.
    return { allowed: false, reason: 'OWNERSHIP_MISMATCH' };
  }

  if (isOwnerReservedPermission(input.permission)) {
    return { allowed: false, reason: 'OWNER_PERMISSION_FORBIDDEN' };
  }

  if (
    scopeType === 'VEHICLE' &&
    channel === 'ONLINE' &&
    membership.permissions.includes(input.permission)
  ) {
    return {
      allowed: true,
      reason: 'ALLOWED',
      source: 'MEMBERSHIP_PERMISSION',
      membershipId: membership._id,
    };
  }

  if (!isAccessGrantPermissionForScope(scopeType, input.permission)) {
    return { allowed: false, reason: 'PERMISSION_NOT_GRANTED' };
  }

  const allowedChannels: AccessGrantChannel[] =
    channel === 'BLE_OFFLINE' ? ['BLE_OFFLINE', 'ANY'] : ['ONLINE', 'ANY'];

  const grant = (await AccessGrantModel.findOne({
    vehicleId: input.vehicleId,
    membershipId: membership._id,
    subjectUserId: input.userId,
    scopeType,
    scopeResourceId: scopeType === 'VEHICLE' ? null : scopeResourceId,
    channel: { $in: allowedChannels },
    status: 'ACTIVE',
    revokedAt: null,
    expiredAt: null,
    startsAt: { $lte: now },
    $or: [{ expiresAt: null }, { expiresAt: { $gt: now } }],
    permissions: input.permission,
  }).lean()) as (AccessGrant & { _id: Types.ObjectId }) | null;

  if (!grant) {
    return { allowed: false, reason: 'PERMISSION_NOT_GRANTED' };
  }

  return {
    allowed: true,
    reason: 'ALLOWED',
    source: 'ACCESS_GRANT',
    membershipId: membership._id,
    grantId: grant._id,
  };
}

export async function canAccessVehicle(
  vehicleId: Types.ObjectId,
  userId: Types.ObjectId,
  permission?: string,
): Promise<boolean> {
  if (!permission) {
    const vehicle = await loadVerifiedActiveVehicle(vehicleId, { actorUserId: userId });
    if (!vehicle) {
      return false;
    }
    const membership = await MembershipModel.findOne({
      vehicleId,
      userId,
      status: 'ACTIVE',
      suspendedAt: null,
      revokedAt: null,
    }).lean();
    if (!membership) {
      return false;
    }
    if (membership.role === 'OWNER' && !vehicle.ownerUserId.equals(userId)) {
      return false;
    }
    if (membership.role !== 'OWNER' && vehicle.ownerUserId.equals(userId)) {
      return false;
    }
    return true;
  }

  const evaluation = await evaluateVehiclePermission({
    vehicleId,
    userId,
    permission,
    scopeType: 'VEHICLE',
    channel: 'ONLINE',
  });
  return evaluation.allowed;
}

export async function canLinkDeviceToVehicle(
  vehicleId: Types.ObjectId,
  userId: Types.ObjectId,
): Promise<boolean> {
  const byManage = await evaluateVehiclePermission({
    vehicleId,
    userId,
    permission: 'vehicle:manage',
    scopeType: 'VEHICLE',
    channel: 'ONLINE',
  });
  if (byManage.allowed) {
    return true;
  }

  const byDeviceLink = await evaluateVehiclePermission({
    vehicleId,
    userId,
    permission: 'device:link',
    scopeType: 'VEHICLE',
    channel: 'ONLINE',
  });
  return byDeviceLink.allowed;
}

export async function listOwnedVehicles(
  userId: Types.ObjectId,
): Promise<Array<Vehicle & { _id: Types.ObjectId }>> {
  const candidates = (await VehicleModel.find({
    ownerUserId: userId,
    status: 'ACTIVE',
  })
    .sort({ createdAt: 1, _id: 1 })
    .lean()) as Array<Vehicle & { _id: Types.ObjectId }>;

  if (candidates.length === 0) {
    return [];
  }

  const vehicleIds = candidates.map((vehicle) => vehicle._id);
  const ownerMemberships = (await MembershipModel.find({
    vehicleId: { $in: vehicleIds },
    role: 'OWNER',
    revokedAt: null,
  }).lean()) as Array<Membership & { _id: Types.ObjectId }>;

  const ownersByVehicle = new Map<string, Array<Membership & { _id: Types.ObjectId }>>();
  for (const membership of ownerMemberships) {
    const key = String(membership.vehicleId);
    const group = ownersByVehicle.get(key) ?? [];
    group.push(membership);
    ownersByVehicle.set(key, group);
  }

  return candidates.filter((vehicle) => {
    const owners = ownersByVehicle.get(String(vehicle._id)) ?? [];
    const owner = owners[0];
    return (
      owners.length === 1 &&
      owner !== undefined &&
      owner.status === 'ACTIVE' &&
      owner.suspendedAt === null &&
      owner.revokedAt === null &&
      owner.userId.equals(userId)
    );
  });
}

/**
 * Prepared domain query returning all ACTIVE, ownership-consistent vehicles
 * where the user holds an ACTIVE Membership (OWNER or MEMBER), isolated per vehicle.
 */
export async function listAccessibleVehicles(userId: Types.ObjectId): Promise<
  Array<{
    vehicle: Vehicle & { _id: Types.ObjectId };
    membership: Membership & { _id: Types.ObjectId };
  }>
> {
  const activeMemberships = (await MembershipModel.find({
    userId,
    status: 'ACTIVE',
    suspendedAt: null,
    revokedAt: null,
  }).lean()) as Array<Membership & { _id: Types.ObjectId }>;

  if (activeMemberships.length === 0) {
    return [];
  }

  const vehicleIds = activeMemberships.map((membership) => membership.vehicleId);
  const [vehicles, ownerMemberships] = await Promise.all([
    VehicleModel.find({ _id: { $in: vehicleIds }, status: 'ACTIVE' })
      .sort({ createdAt: 1, _id: 1 })
      .lean() as Promise<Array<Vehicle & { _id: Types.ObjectId }>>,
    MembershipModel.find({
      vehicleId: { $in: vehicleIds },
      role: 'OWNER',
      revokedAt: null,
    }).lean() as Promise<Array<Membership & { _id: Types.ObjectId }>>,
  ]);

  const membershipByVehicle = new Map<string, Membership & { _id: Types.ObjectId }>();
  for (const membership of activeMemberships) {
    membershipByVehicle.set(String(membership.vehicleId), membership);
  }

  const ownersByVehicle = new Map<string, Array<Membership & { _id: Types.ObjectId }>>();
  for (const owner of ownerMemberships) {
    const key = String(owner.vehicleId);
    const list = ownersByVehicle.get(key) ?? [];
    list.push(owner);
    ownersByVehicle.set(key, list);
  }

  const accessible: Array<{
    vehicle: Vehicle & { _id: Types.ObjectId };
    membership: Membership & { _id: Types.ObjectId };
  }> = [];

  for (const vehicle of vehicles) {
    const key = String(vehicle._id);
    const membership = membershipByVehicle.get(key);
    const owners = ownersByVehicle.get(key) ?? [];
    const owner = owners[0];
    if (
      !membership ||
      owners.length !== 1 ||
      !owner ||
      owner.status !== 'ACTIVE' ||
      owner.suspendedAt !== null ||
      owner.revokedAt !== null ||
      !owner.userId.equals(vehicle.ownerUserId)
    ) {
      continue;
    }

    if (membership.role === 'OWNER' && !vehicle.ownerUserId.equals(userId)) {
      continue;
    }
    if (membership.role !== 'OWNER' && vehicle.ownerUserId.equals(userId)) {
      continue;
    }

    accessible.push({ vehicle, membership });
  }

  return accessible;
}

export async function getVehicleForUser(
  vehicleId: Types.ObjectId,
  userId: Types.ObjectId,
): Promise<(Vehicle & { _id: Types.ObjectId }) | null> {
  const vehicle = await loadVerifiedActiveVehicle(vehicleId, { actorUserId: userId });
  if (!vehicle) {
    return null;
  }

  const membership = await MembershipModel.findOne({
    vehicleId,
    userId,
    status: 'ACTIVE',
    suspendedAt: null,
    revokedAt: null,
  }).lean();

  if (!membership) {
    return null;
  }

  if (membership.role === 'OWNER' && !vehicle.ownerUserId.equals(userId)) {
    return null;
  }
  if (membership.role !== 'OWNER' && vehicle.ownerUserId.equals(userId)) {
    return null;
  }

  return vehicle;
}

export async function inviteMember(
  vehicleId: Types.ObjectId,
  inviterUserId: Types.ObjectId,
  inviteeUserId: Types.ObjectId,
  permissions: string[],
  options: { ttlMs?: number; now?: Date; audit?: VehicleAuditLogger } = {},
): Promise<(Invitation & { _id: Types.ObjectId }) | null> {
  const audit = options.audit ?? defaultAuditLogger;
  const now = options.now ?? new Date();
  const ttlMs = options.ttlMs ?? DEFAULT_INVITATION_TTL_MS;

  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) {
    throw new VehicleServiceError('VALIDATION_ERROR', 'Invalid invitation TTL');
  }

  if (inviterUserId.equals(inviteeUserId)) {
    throw new VehicleServiceError('VALIDATION_ERROR', 'Self-invitations are not allowed');
  }

  if (
    !validatePermissionSet(permissions, {
      maxItems: 100,
      allowPermission: isDelegableMembershipPermission,
    })
  ) {
    throw new VehicleServiceError(
      'VALIDATION_ERROR',
      'Invitation permissions must be unique, known, non-wildcard, and delegable to MEMBER',
    );
  }

  // Persist transition of any elapsed PENDING invitations BEFORE starting an abortable
  // transaction so EXPIRED history is preserved even if domain validation/conflicts fail.
  await InvitationModel.updateMany(
    {
      vehicleId,
      inviteeUserId,
      status: 'PENDING',
      expiresAt: { $lte: now },
    },
    {
      $set: {
        status: 'EXPIRED',
        expiredAt: now,
      },
    },
  );

  const expiresAt = new Date(now.getTime() + ttlMs);

  try {
    const outcome = await runInVehicleTransaction(async (session) => {
      const vehicle = await lockVerifiedActiveVehicle(vehicleId, session, {
        now,
        actorUserId: inviterUserId,
        audit,
      });
      if (!vehicle) {
        return null;
      }

      if (!vehicle.ownerUserId.equals(inviterUserId)) {
        const inviterMembership = session
          ? ((await MembershipModel.findOneAndUpdate(
              {
                vehicleId,
                userId: inviterUserId,
                role: 'MEMBER',
                status: 'ACTIVE',
                suspendedAt: null,
                revokedAt: null,
              },
              { $set: { updatedAt: now } },
              { returnDocument: 'after', session },
            ).lean()) as (Membership & { _id: Types.ObjectId }) | null)
          : ((await MembershipModel.findOne({
              vehicleId,
              userId: inviterUserId,
              role: 'MEMBER',
              status: 'ACTIVE',
              suspendedAt: null,
              revokedAt: null,
            }).lean()) as (Membership & { _id: Types.ObjectId }) | null);

        const canInviteViaMembership =
          inviterMembership !== null &&
          (inviterMembership.permissions.includes('vehicle:manage') ||
            inviterMembership.permissions.includes('invitation:create'));

        if (!canInviteViaMembership) {
          throw new TransactionAbortDomainError('REJECT_NULL', 'insufficient_permissions');
        }
      }

      if (vehicle.ownerUserId.equals(inviteeUserId)) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'Vehicle owner cannot be invited as a member',
        );
      }

      const existingMembershipQuery = MembershipModel.findOne({
        vehicleId,
        userId: inviteeUserId,
        revokedAt: null,
      });
      if (session) {
        existingMembershipQuery.session(session);
      }
      const existingMembership = await existingMembershipQuery.lean();

      if (existingMembership) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'Invitee already holds an active or suspended membership for this vehicle',
        );
      }

      const updateQuery = InvitationModel.findOneAndUpdate(
        {
          vehicleId,
          inviteeUserId,
          status: 'PENDING',
          expiresAt: { $gt: now },
        },
        {
          $set: {
            permissions,
            expiresAt,
            updatedByUserId: inviterUserId,
          },
        },
        { returnDocument: 'after', runValidators: true, session },
      );

      const updatedExistingPending = (await updateQuery.lean()) as
        (Invitation & { _id: Types.ObjectId }) | null;

      if (updatedExistingPending) {
        return { invitation: updatedExistingPending, refreshed: true };
      }

      const created = await createDocumentWithSession(
        InvitationModel,
        {
          vehicleId,
          inviterUserId,
          inviteeUserId,
          targetRole: 'MEMBER',
          permissions,
          status: 'PENDING',
          expiresAt,
          acceptedAt: null,
          acceptedByUserId: null,
          revokedAt: null,
          revokedByUserId: null,
          revokeReason: null,
          expiredAt: null,
          updatedByUserId: null,
        },
        session,
      );

      const invitation = (
        typeof created.toObject === 'function' ? created.toObject() : created
      ) as Invitation & { _id: Types.ObjectId };

      return { invitation, refreshed: false };
    });

    if (!outcome) {
      return null;
    }

    audit({
      action: outcome.refreshed ? 'invitation.refresh_pending' : 'invitation.create',
      actorUserId: String(inviterUserId),
      vehicleId: String(vehicleId),
      targetId: String(outcome.invitation._id),
      outcome: 'success',
    });

    return outcome.invitation;
  } catch (error) {
    if (error instanceof TransactionAbortDomainError) {
      if (error.code === 'REJECT_NULL') {
        audit({
          action: 'invitation.create',
          actorUserId: String(inviterUserId),
          vehicleId: String(vehicleId),
          targetId: String(inviteeUserId),
          outcome: 'denied',
          reason: error.message,
        });
        return null;
      }
      audit({
        action: 'invitation.create',
        actorUserId: String(inviterUserId),
        vehicleId: String(vehicleId),
        targetId: String(inviteeUserId),
        outcome: 'conflict',
        reason: error.message,
      });
      throw new VehicleServiceError(error.code, error.message);
    }
    if (isDuplicateKeyError(error)) {
      const concurrent = (await InvitationModel.findOne({
        vehicleId,
        inviteeUserId,
        status: 'PENDING',
        expiresAt: { $gt: now },
      }).lean()) as (Invitation & { _id: Types.ObjectId }) | null;
      if (concurrent) {
        const activeVehicle = await loadVerifiedActiveVehicle(vehicleId, {
          actorUserId: inviterUserId,
        });
        if (activeVehicle) {
          return concurrent;
        }
        return null;
      }
      throw new VehicleServiceError('CONFLICT', 'Concurrent pending invitation conflict', {
        cause: error,
      });
    }
    throw error;
  }
}

export async function acceptInvitation(
  invitationId: Types.ObjectId,
  userId: Types.ObjectId,
  options: { now?: Date; audit?: VehicleAuditLogger } = {},
): Promise<(Membership & { _id: Types.ObjectId }) | null> {
  const audit = options.audit ?? defaultAuditLogger;
  const now = options.now ?? new Date();

  // Persist EXPIRED outside the acceptance transaction so it is never lost on rollback.
  const newlyExpired = await InvitationModel.findOneAndUpdate(
    {
      _id: invitationId,
      inviteeUserId: userId,
      status: 'PENDING',
      expiresAt: { $lte: now },
    },
    {
      $set: {
        status: 'EXPIRED',
        expiredAt: now,
      },
    },
    { returnDocument: 'after' },
  ).lean();

  if (newlyExpired) {
    audit({
      action: 'invitation.accept',
      actorUserId: String(userId),
      vehicleId: String(newlyExpired.vehicleId),
      targetId: String(invitationId),
      outcome: 'denied',
      reason: 'invitation_expired',
    });
    return null;
  }

  try {
    const createdMembership = await runInVehicleTransaction(async (session) => {
      const claimQuery = InvitationModel.findOneAndUpdate(
        {
          _id: invitationId,
          inviteeUserId: userId,
          targetRole: 'MEMBER',
          status: 'PENDING',
          expiresAt: { $gt: now },
        },
        {
          $set: {
            status: 'ACCEPTED',
            acceptedAt: now,
            acceptedByUserId: userId,
            updatedByUserId: userId,
          },
        },
        { returnDocument: 'after', runValidators: true, session },
      );

      const invitation = (await claimQuery.lean()) as (Invitation & { _id: Types.ObjectId }) | null;
      if (!invitation) {
        return null;
      }

      if (
        invitation.targetRole !== 'MEMBER' ||
        !validatePermissionSet(invitation.permissions, {
          maxItems: 100,
          allowPermission: isDelegableMembershipPermission,
        })
      ) {
        throw new TransactionAbortDomainError(
          'VALIDATION_ERROR',
          'Invitation contains invalid role or permissions',
        );
      }

      const vehicle = await lockVerifiedActiveVehicle(invitation.vehicleId, session, {
        now,
        actorUserId: userId,
        audit,
      });
      if (!vehicle) {
        throw new TransactionAbortDomainError(
          'REJECT_NULL',
          'Target vehicle is unavailable, archived, or ownership-inconsistent',
        );
      }

      if (vehicle.ownerUserId.equals(userId)) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'Canonical vehicle owner cannot accept a member invitation',
        );
      }

      const existingMembershipQuery = MembershipModel.findOne({
        vehicleId: invitation.vehicleId,
        userId,
        revokedAt: null,
      });
      if (session) {
        existingMembershipQuery.session(session);
      }
      const existingMembership = await existingMembershipQuery.lean();
      if (existingMembership) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'User already holds a non-revoked membership for this vehicle',
        );
      }

      const membershipDoc = await createDocumentWithSession(
        MembershipModel,
        {
          vehicleId: invitation.vehicleId,
          userId,
          role: 'MEMBER',
          permissions: invitation.permissions,
          status: 'ACTIVE',
          sourceInvitationId: invitation._id,
          grantedByUserId: invitation.inviterUserId,
          updatedByUserId: null,
          suspendedAt: null,
          suspendedByUserId: null,
          suspensionReason: null,
          revokedAt: null,
          revokedByUserId: null,
          revokeReason: null,
        },
        session,
      );

      return (
        typeof membershipDoc.toObject === 'function' ? membershipDoc.toObject() : membershipDoc
      ) as Membership & { _id: Types.ObjectId };
    });

    if (createdMembership) {
      audit({
        action: 'invitation.accept',
        actorUserId: String(userId),
        vehicleId: String(createdMembership.vehicleId),
        targetId: String(invitationId),
        outcome: 'success',
      });
    }

    return createdMembership;
  } catch (error) {
    if (error instanceof TransactionAbortDomainError) {
      if (error.code === 'REJECT_NULL') {
        return null;
      }
      throw new VehicleServiceError(error.code, error.message);
    }
    if (isDuplicateKeyError(error)) {
      throw new VehicleServiceError(
        'CONFLICT',
        'Concurrent membership creation conflict during invitation acceptance',
        { cause: error },
      );
    }
    throw error;
  }
}

export async function revokeInvitation(input: {
  vehicleId: Types.ObjectId;
  invitationId: Types.ObjectId;
  actorUserId: Types.ObjectId;
  reason?: string | null;
  now?: Date;
  audit?: VehicleAuditLogger;
}): Promise<(Invitation & { _id: Types.ObjectId }) | null> {
  const audit = input.audit ?? defaultAuditLogger;
  const now = input.now ?? new Date();
  const reason = validateOptionalAuditReason(input.reason);

  const vehicle = await loadVerifiedActiveVehicle(input.vehicleId, {
    actorUserId: input.actorUserId,
    audit,
  });
  if (!vehicle || !vehicle.ownerUserId.equals(input.actorUserId)) {
    return null;
  }

  // If the invitation already elapsed, record EXPIRED rather than falsely marking REVOKED.
  const newlyExpired = await InvitationModel.findOneAndUpdate(
    {
      _id: input.invitationId,
      vehicleId: input.vehicleId,
      status: 'PENDING',
      expiresAt: { $lte: now },
    },
    {
      $set: {
        status: 'EXPIRED',
        expiredAt: now,
      },
    },
    { returnDocument: 'after' },
  ).lean();

  if (newlyExpired) {
    return null;
  }

  const revoked = (await InvitationModel.findOneAndUpdate(
    {
      _id: input.invitationId,
      vehicleId: input.vehicleId,
      status: 'PENDING',
      expiresAt: { $gt: now },
    },
    {
      $set: {
        status: 'REVOKED',
        revokedAt: now,
        revokedByUserId: input.actorUserId,
        revokeReason: reason,
        updatedByUserId: input.actorUserId,
      },
    },
    { returnDocument: 'after', runValidators: true },
  ).lean()) as (Invitation & { _id: Types.ObjectId }) | null;

  if (revoked) {
    audit({
      action: 'invitation.revoke',
      actorUserId: String(input.actorUserId),
      vehicleId: String(input.vehicleId),
      targetId: String(input.invitationId),
      outcome: 'success',
      reason: reason ?? undefined,
    });
  }

  return revoked;
}

export async function suspendMembership(input: {
  vehicleId: Types.ObjectId;
  membershipId: Types.ObjectId;
  actorUserId: Types.ObjectId;
  reason?: string | null;
  now?: Date;
  audit?: VehicleAuditLogger;
}): Promise<(Membership & { _id: Types.ObjectId }) | null> {
  const audit = input.audit ?? defaultAuditLogger;
  const now = input.now ?? new Date();
  const reason = validateOptionalAuditReason(input.reason);

  const vehicle = await loadVerifiedActiveVehicle(input.vehicleId, {
    actorUserId: input.actorUserId,
    audit,
  });
  if (!vehicle || !vehicle.ownerUserId.equals(input.actorUserId)) {
    throw new VehicleServiceError(
      'FORBIDDEN',
      'Only the canonical vehicle owner may suspend members',
    );
  }

  const target = await MembershipModel.findOne({
    _id: input.membershipId,
    vehicleId: input.vehicleId,
  }).lean();
  if (!target) {
    return null;
  }
  if (target.role === 'OWNER' || target.userId.equals(vehicle.ownerUserId)) {
    throw new VehicleServiceError('CONFLICT', 'OWNER membership cannot be suspended');
  }
  if (target.status !== 'ACTIVE' || target.revokedAt !== null) {
    throw new VehicleServiceError(
      'CONFLICT',
      `Cannot suspend membership in status ${target.status}`,
    );
  }

  const suspended = (await MembershipModel.findOneAndUpdate(
    {
      _id: input.membershipId,
      vehicleId: input.vehicleId,
      role: 'MEMBER',
      status: 'ACTIVE',
      suspendedAt: null,
      revokedAt: null,
    },
    {
      $set: {
        status: 'SUSPENDED',
        suspendedAt: now,
        suspendedByUserId: input.actorUserId,
        suspensionReason: reason,
        updatedByUserId: input.actorUserId,
      },
    },
    { returnDocument: 'after', runValidators: true },
  ).lean()) as (Membership & { _id: Types.ObjectId }) | null;

  if (suspended) {
    audit({
      action: 'membership.suspend',
      actorUserId: String(input.actorUserId),
      vehicleId: String(input.vehicleId),
      targetId: String(input.membershipId),
      outcome: 'success',
      reason: reason ?? undefined,
    });
  }

  return suspended;
}

export async function reactivateMembership(input: {
  vehicleId: Types.ObjectId;
  membershipId: Types.ObjectId;
  actorUserId: Types.ObjectId;
  now?: Date;
  audit?: VehicleAuditLogger;
}): Promise<(Membership & { _id: Types.ObjectId }) | null> {
  const audit = input.audit ?? defaultAuditLogger;

  const vehicle = await loadVerifiedActiveVehicle(input.vehicleId, {
    actorUserId: input.actorUserId,
    audit,
  });
  if (!vehicle || !vehicle.ownerUserId.equals(input.actorUserId)) {
    throw new VehicleServiceError(
      'FORBIDDEN',
      'Only the canonical vehicle owner may reactivate suspended members',
    );
  }

  const target = await MembershipModel.findOne({
    _id: input.membershipId,
    vehicleId: input.vehicleId,
  }).lean();
  if (!target) {
    return null;
  }
  if (target.role === 'OWNER') {
    throw new VehicleServiceError('CONFLICT', 'OWNER membership is already permanently active');
  }
  if (target.status !== 'SUSPENDED' || target.revokedAt !== null) {
    throw new VehicleServiceError(
      'CONFLICT',
      `Cannot reactivate membership in status ${target.status}`,
    );
  }

  const reactivated = (await MembershipModel.findOneAndUpdate(
    {
      _id: input.membershipId,
      vehicleId: input.vehicleId,
      role: 'MEMBER',
      status: 'SUSPENDED',
      revokedAt: null,
    },
    {
      $set: {
        status: 'ACTIVE',
        suspendedAt: null,
        suspendedByUserId: null,
        suspensionReason: null,
        updatedByUserId: input.actorUserId,
      },
    },
    { returnDocument: 'after', runValidators: true },
  ).lean()) as (Membership & { _id: Types.ObjectId }) | null;

  if (reactivated) {
    audit({
      action: 'membership.reactivate',
      actorUserId: String(input.actorUserId),
      vehicleId: String(input.vehicleId),
      targetId: String(input.membershipId),
      outcome: 'success',
    });
  }

  return reactivated;
}

export async function revokeMembership(input: {
  vehicleId: Types.ObjectId;
  membershipId: Types.ObjectId;
  actorUserId: Types.ObjectId;
  reason?: string | null;
  now?: Date;
  audit?: VehicleAuditLogger;
}): Promise<{
  membership: Membership & { _id: Types.ObjectId };
  revokedGrantsCount: number;
} | null> {
  const audit = input.audit ?? defaultAuditLogger;
  const now = input.now ?? new Date();
  const reason = validateOptionalAuditReason(input.reason);

  try {
    const result = await runInVehicleTransaction(async (session) => {
      const vehicle = await lockVerifiedActiveVehicle(input.vehicleId, session, {
        now,
        actorUserId: input.actorUserId,
        audit,
      });
      if (!vehicle || !vehicle.ownerUserId.equals(input.actorUserId)) {
        throw new TransactionAbortDomainError(
          'FORBIDDEN',
          'Only the canonical vehicle owner may revoke memberships',
        );
      }

      const targetQuery = MembershipModel.findOne({
        _id: input.membershipId,
        vehicleId: input.vehicleId,
      });
      if (session) {
        targetQuery.session(session);
      }
      const target = await targetQuery.lean();
      if (!target) {
        return null;
      }
      if (target.role === 'OWNER' || target.userId.equals(vehicle.ownerUserId)) {
        throw new TransactionAbortDomainError('CONFLICT', 'OWNER membership cannot be revoked');
      }
      if (target.status === 'REVOKED' || target.revokedAt !== null) {
        throw new TransactionAbortDomainError('CONFLICT', 'Membership is already REVOKED');
      }

      const revokedMembership = (await MembershipModel.findOneAndUpdate(
        {
          _id: input.membershipId,
          vehicleId: input.vehicleId,
          role: 'MEMBER',
          status: { $in: ['ACTIVE', 'SUSPENDED'] },
          revokedAt: null,
        },
        {
          $set: {
            status: 'REVOKED',
            revokedAt: now,
            revokedByUserId: input.actorUserId,
            revokeReason: reason,
            updatedByUserId: input.actorUserId,
          },
        },
        { returnDocument: 'after', runValidators: true, session },
      ).lean()) as (Membership & { _id: Types.ObjectId }) | null;

      if (!revokedMembership) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'Concurrent state change prevented membership revocation',
        );
      }

      const cascadeReason = reason ?? 'membership_revoked';
      const grantCascade = await AccessGrantModel.updateMany(
        {
          vehicleId: input.vehicleId,
          membershipId: revokedMembership._id,
          status: 'ACTIVE',
          revokedAt: null,
        },
        {
          $set: {
            status: 'REVOKED',
            revokedAt: now,
            revokedByUserId: input.actorUserId,
            revokeReason: cascadeReason,
            updatedByUserId: input.actorUserId,
          },
        },
        { session },
      );

      return {
        membership: revokedMembership,
        revokedGrantsCount: grantCascade.modifiedCount,
      };
    });

    if (result) {
      audit({
        action: 'membership.revoke',
        actorUserId: String(input.actorUserId),
        vehicleId: String(input.vehicleId),
        targetId: String(input.membershipId),
        outcome: 'success',
        reason: reason ?? undefined,
      });
    }

    return result;
  } catch (error) {
    if (error instanceof TransactionAbortDomainError && error.code !== 'REJECT_NULL') {
      throw new VehicleServiceError(error.code, error.message);
    }
    throw error;
  }
}

export async function createAccessGrant(
  input: CreateAccessGrantInput,
): Promise<AccessGrant & { _id: Types.ObjectId }> {
  const audit = input.audit ?? defaultAuditLogger;
  const now = input.now ?? new Date();
  const channel = input.channel ?? 'ONLINE';
  const startsAt = input.startsAt ?? now;
  const expiresAt = input.expiresAt ?? null;
  const scopeResourceId = input.scopeResourceId ?? null;

  if (input.scopeType === 'VEHICLE' && scopeResourceId !== null) {
    throw new VehicleServiceError(
      'VALIDATION_ERROR',
      'VEHICLE scope grants cannot specify a scopeResourceId',
    );
  }
  if ((input.scopeType === 'DEVICE' || input.scopeType === 'MODULE') && scopeResourceId === null) {
    throw new VehicleServiceError(
      'VALIDATION_ERROR',
      `${input.scopeType} scope grants require a scopeResourceId`,
    );
  }

  if ((channel === 'BLE_OFFLINE' || channel === 'ANY') && !(expiresAt instanceof Date)) {
    throw new VehicleServiceError(
      'VALIDATION_ERROR',
      `${channel} grants require an explicit expiresAt timestamp`,
    );
  }

  if (expiresAt !== null) {
    if (expiresAt.getTime() <= startsAt.getTime() || expiresAt.getTime() <= now.getTime()) {
      throw new VehicleServiceError(
        'VALIDATION_ERROR',
        'AccessGrant expiresAt must be in the future and strictly greater than startsAt',
      );
    }
  }

  if (
    !validatePermissionSet(input.permissions, {
      minItems: 1,
      maxItems: 50,
      allowPermission: (permission) => isAccessGrantPermissionForScope(input.scopeType, permission),
    })
  ) {
    throw new VehicleServiceError(
      'VALIDATION_ERROR',
      'AccessGrant permissions must be known, non-wildcard, non-owner-reserved, unique, and valid for scopeType',
    );
  }

  try {
    const createdGrant = await runInVehicleTransaction(async (session) => {
      const vehicle = await lockVerifiedActiveVehicle(input.vehicleId, session, {
        now,
        actorUserId: input.actorUserId,
        audit,
      });
      if (!vehicle) {
        throw new TransactionAbortDomainError('NOT_FOUND', 'Active vehicle not found');
      }

      // Only the canonical OWNER may issue AccessGrants in TKT-010 (MEMBER delegation is prohibited).
      if (!vehicle.ownerUserId.equals(input.actorUserId)) {
        throw new TransactionAbortDomainError(
          'FORBIDDEN',
          'Only the canonical vehicle owner may issue grants',
        );
      }

      if (vehicle.ownerUserId.equals(input.subjectUserId)) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'Canonical vehicle owner does not receive MEMBER AccessGrants',
        );
      }

      const membershipQuery = MembershipModel.findOne({ _id: input.membershipId });
      if (session) {
        membershipQuery.session(session);
      }
      const membership = (await membershipQuery.lean()) as
        (Membership & { _id: Types.ObjectId }) | null;

      if (
        !membership ||
        !membership.vehicleId.equals(input.vehicleId) ||
        !membership.userId.equals(input.subjectUserId)
      ) {
        throw new TransactionAbortDomainError(
          'VALIDATION_ERROR',
          'Membership must belong to the exact same vehicleId and subjectUserId',
        );
      }

      if (membership.role !== 'MEMBER') {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'AccessGrants can only target MEMBER memberships',
        );
      }

      if (
        membership.status !== 'ACTIVE' ||
        membership.suspendedAt !== null ||
        membership.revokedAt !== null
      ) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          `Cannot issue AccessGrant for membership in status ${membership.status}`,
        );
      }

      // Acquire a write-lock on the ACTIVE Membership document so concurrent
      // revokeMembership / suspendMembership serializes via WiredTiger WriteConflict
      // rather than permitting snapshot write skew.
      const lockedMembership = session
        ? ((await MembershipModel.findOneAndUpdate(
            {
              _id: membership._id,
              vehicleId: input.vehicleId,
              userId: input.subjectUserId,
              role: 'MEMBER',
              status: 'ACTIVE',
              suspendedAt: null,
              revokedAt: null,
            },
            { $set: { updatedAt: now } },
            { returnDocument: 'after', session },
          ).lean()) as (Membership & { _id: Types.ObjectId }) | null)
        : membership;

      if (!lockedMembership) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'Membership is no longer ACTIVE and cannot receive AccessGrants',
        );
      }

      const created = await createDocumentWithSession(
        AccessGrantModel,
        {
          vehicleId: input.vehicleId,
          membershipId: lockedMembership._id,
          subjectUserId: input.subjectUserId,
          scopeType: input.scopeType,
          scopeResourceId,
          channel,
          permissions: input.permissions,
          status: 'ACTIVE',
          startsAt,
          expiresAt,
          grantedByUserId: input.actorUserId,
          updatedByUserId: null,
          revokedAt: null,
          revokedByUserId: null,
          revokeReason: null,
          expiredAt: null,
        },
        session,
      );

      return (
        typeof created.toObject === 'function' ? created.toObject() : created
      ) as AccessGrant & { _id: Types.ObjectId };
    });

    audit({
      action: 'access_grant.create',
      actorUserId: String(input.actorUserId),
      vehicleId: String(input.vehicleId),
      targetId: String(createdGrant._id),
      outcome: 'success',
    });

    return createdGrant;
  } catch (error) {
    if (error instanceof TransactionAbortDomainError && error.code !== 'REJECT_NULL') {
      if (error.code === 'FORBIDDEN') {
        audit({
          action: 'access_grant.create',
          actorUserId: String(input.actorUserId),
          vehicleId: String(input.vehicleId),
          targetId: String(input.subjectUserId),
          outcome: 'denied',
          reason: 'member_grant_delegation_forbidden',
        });
      }
      throw new VehicleServiceError(error.code, error.message);
    }
    throw error;
  }
}

export async function revokeAccessGrant(input: {
  vehicleId: Types.ObjectId;
  grantId: Types.ObjectId;
  actorUserId: Types.ObjectId;
  reason?: string | null;
  now?: Date;
  audit?: VehicleAuditLogger;
}): Promise<(AccessGrant & { _id: Types.ObjectId }) | null> {
  const audit = input.audit ?? defaultAuditLogger;
  const now = input.now ?? new Date();
  const reason = validateOptionalAuditReason(input.reason);

  const vehicle = await loadVerifiedActiveVehicle(input.vehicleId, {
    actorUserId: input.actorUserId,
    audit,
  });
  if (!vehicle) {
    throw new VehicleServiceError('NOT_FOUND', 'Active vehicle not found');
  }
  if (!vehicle.ownerUserId.equals(input.actorUserId)) {
    throw new VehicleServiceError(
      'FORBIDDEN',
      'Only the canonical vehicle owner may revoke grants',
    );
  }

  // Persist EXPIRED first if the grant already elapsed rather than overwriting expiration history.
  const newlyExpired = await AccessGrantModel.findOneAndUpdate(
    {
      _id: input.grantId,
      vehicleId: input.vehicleId,
      status: 'ACTIVE',
      expiresAt: { $ne: null, $lte: now },
    },
    {
      $set: {
        status: 'EXPIRED',
        expiredAt: now,
      },
    },
    { returnDocument: 'after' },
  ).lean();

  if (newlyExpired) {
    throw new VehicleServiceError('CONFLICT', 'AccessGrant has already expired');
  }

  const existing = await AccessGrantModel.findOne({
    _id: input.grantId,
    vehicleId: input.vehicleId,
  }).lean();
  if (!existing) {
    return null;
  }
  if (existing.status !== 'ACTIVE') {
    throw new VehicleServiceError(
      'CONFLICT',
      `Cannot revoke AccessGrant in terminal status ${existing.status}`,
    );
  }

  const revoked = (await AccessGrantModel.findOneAndUpdate(
    {
      _id: input.grantId,
      vehicleId: input.vehicleId,
      status: 'ACTIVE',
      revokedAt: null,
      expiredAt: null,
      $or: [{ expiresAt: null }, { expiresAt: { $gt: now } }],
    },
    {
      $set: {
        status: 'REVOKED',
        revokedAt: now,
        revokedByUserId: input.actorUserId,
        revokeReason: reason,
        updatedByUserId: input.actorUserId,
      },
    },
    { returnDocument: 'after', runValidators: true },
  ).lean()) as (AccessGrant & { _id: Types.ObjectId }) | null;

  if (revoked) {
    audit({
      action: 'access_grant.revoke',
      actorUserId: String(input.actorUserId),
      vehicleId: String(input.vehicleId),
      targetId: String(input.grantId),
      outcome: 'success',
      reason: reason ?? undefined,
    });
  }

  return revoked;
}

export async function expireElapsedAccessGrants(
  vehicleId: Types.ObjectId,
  now: Date = new Date(),
): Promise<number> {
  const result = await AccessGrantModel.updateMany(
    {
      vehicleId,
      status: 'ACTIVE',
      expiresAt: { $ne: null, $lte: now },
    },
    {
      $set: {
        status: 'EXPIRED',
        expiredAt: now,
      },
    },
  );
  return result.modifiedCount;
}

export async function archiveVehicle(input: {
  vehicleId: Types.ObjectId;
  actorUserId: Types.ObjectId;
  reason?: string | null;
  now?: Date;
  audit?: VehicleAuditLogger;
}): Promise<(Vehicle & { _id: Types.ObjectId }) | null> {
  const audit = input.audit ?? defaultAuditLogger;
  const now = input.now ?? new Date();
  const reason = validateOptionalAuditReason(input.reason);

  try {
    const archived = await runInVehicleTransaction(async (session) => {
      const verified = await loadVerifiedActiveVehicle(input.vehicleId, {
        session,
        actorUserId: input.actorUserId,
        audit,
      });
      if (!verified) {
        return null;
      }
      if (!verified.ownerUserId.equals(input.actorUserId)) {
        throw new TransactionAbortDomainError(
          'FORBIDDEN',
          'Only the canonical vehicle owner may archive the vehicle',
        );
      }

      const updatedVehicle = (await VehicleModel.findOneAndUpdate(
        {
          _id: input.vehicleId,
          ownerUserId: input.actorUserId,
          status: 'ACTIVE',
        },
        {
          $set: {
            status: 'ARCHIVED',
            archivedAt: now,
            archivedByUserId: input.actorUserId,
            archiveReason: reason,
            updatedByUserId: input.actorUserId,
          },
        },
        { returnDocument: 'after', runValidators: true, session },
      ).lean()) as (Vehicle & { _id: Types.ObjectId }) | null;

      if (!updatedVehicle) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'Concurrent state change prevented archiving vehicle',
        );
      }

      const cascadeReason = reason ?? 'vehicle_archived';

      await InvitationModel.updateMany(
        {
          vehicleId: input.vehicleId,
          status: 'PENDING',
        },
        {
          $set: {
            status: 'REVOKED',
            revokedAt: now,
            revokedByUserId: input.actorUserId,
            revokeReason: cascadeReason,
            updatedByUserId: input.actorUserId,
          },
        },
        { session },
      );

      await AccessGrantModel.updateMany(
        {
          vehicleId: input.vehicleId,
          status: 'ACTIVE',
          revokedAt: null,
        },
        {
          $set: {
            status: 'REVOKED',
            revokedAt: now,
            revokedByUserId: input.actorUserId,
            revokeReason: cascadeReason,
            updatedByUserId: input.actorUserId,
          },
        },
        { session },
      );

      return updatedVehicle;
    });

    if (archived) {
      audit({
        action: 'vehicle.archive',
        actorUserId: String(input.actorUserId),
        vehicleId: String(input.vehicleId),
        outcome: 'success',
        reason: reason ?? undefined,
      });
    }

    return archived;
  } catch (error) {
    if (error instanceof TransactionAbortDomainError && error.code !== 'REJECT_NULL') {
      throw new VehicleServiceError(error.code, error.message);
    }
    throw error;
  }
}
