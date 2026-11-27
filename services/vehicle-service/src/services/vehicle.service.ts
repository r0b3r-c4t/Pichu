import { createHash } from 'node:crypto';
import mongoose, {
  type ClientSession,
  type Model,
  type PipelineStage,
  type QueryFilter,
  Types,
} from 'mongoose';
import { z } from 'zod';
import {
  VEHICLE_MUTABLE_FIELDS,
  VEHICLE_TEXT_LIMITS,
  VEHICLE_YEAR_RANGE,
  type VehicleMutableField,
} from '@pichu/contracts';
import { AccessGrantModel, type AccessGrant } from '../models/access-grant.model.js';
import { InvitationModel, type Invitation } from '../models/invitation.model.js';
import { MembershipModel, type Membership } from '../models/membership.model.js';
import {
  containsControlCharacter,
  DEFAULT_INVITATION_TTL_MS,
  INVITATION_AUTHORITY_PERMISSIONS,
  INVITATION_STATUSES,
  isAccessGrantPermissionForScope,
  isDelegableMembershipPermission,
  isKnownPermission,
  isOwnerReservedPermission,
  MEMBER_DELEGABLE_INVITATION_PERMISSIONS,
  MEMBERSHIP_STATUSES,
  normalizeOptionalText,
  MEMBERSHIP_ROLES,
  validatePermissionSet,
  type AccessGrantChannel,
  type AccessGrantScopeType,
  type InvitationStatus,
  type MembershipRole,
  type MembershipStatus,
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

/** Partial update: omitted fields are preserved and `null` clears an optional field. */
export type UpdateVehicleInput = Partial<CreateVehicleInput>;

type VehicleFieldChanges = Partial<
  { name: string; year: number | null } & Record<VehicleOptionalTextField, string | null>
>;

type VehicleRecord = Vehicle & { _id: Types.ObjectId };
type MembershipRecord = Membership & { _id: Types.ObjectId };
type InvitationRecord = Invitation & { _id: Types.ObjectId };

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

type VehicleOptionalTextField = Exclude<VehicleMutableField, 'name' | 'year'>;

const VEHICLE_OPTIONAL_TEXT_FIELDS: readonly VehicleOptionalTextField[] = [
  'make',
  'model',
  'generation',
  'trim',
  'bodyStyle',
  'engine',
  'transmission',
  'fuelType',
];

const mutableVehicleFieldSet = new Set<string>(VEHICLE_MUTABLE_FIELDS);

function invalidVehicleField(field: string): VehicleServiceError {
  return new VehicleServiceError('VALIDATION_ERROR', `Invalid vehicle ${field}`);
}

/** Control characters are rejected before trimming; empty or whitespace-only text is invalid. */
function normalizeVehicleText(value: unknown, field: string, maxLength: number): string {
  if (typeof value !== 'string' || containsControlCharacter(value)) {
    throw invalidVehicleField(field);
  }
  const trimmed = value.trim();
  if (trimmed.length < 1 || trimmed.length > maxLength) {
    throw invalidVehicleField(field);
  }
  return trimmed;
}

function normalizeVehicleYear(value: unknown): number | null {
  if (value === null) {
    return null;
  }
  if (
    typeof value !== 'number' ||
    !Number.isInteger(value) ||
    value < VEHICLE_YEAR_RANGE.min ||
    value > VEHICLE_YEAR_RANGE.max
  ) {
    throw invalidVehicleField('year');
  }
  return value;
}

/**
 * Shared create/update validation over the closed list of mutable fields. Omitted fields are
 * not returned; `null` clears optional fields and is never accepted for `name`.
 */
function normalizeVehicleFields(input: object): VehicleFieldChanges {
  const source = input as Record<string, unknown>;
  for (const key of Object.keys(source)) {
    if (!mutableVehicleFieldSet.has(key)) {
      throw new VehicleServiceError('VALIDATION_ERROR', 'Unsupported vehicle field');
    }
  }

  const changes: VehicleFieldChanges = {};
  if (source.name !== undefined) {
    changes.name = normalizeVehicleText(source.name, 'name', VEHICLE_TEXT_LIMITS.name);
  }
  for (const field of VEHICLE_OPTIONAL_TEXT_FIELDS) {
    const raw = source[field];
    if (raw !== undefined) {
      changes[field] =
        raw === null ? null : normalizeVehicleText(raw, field, VEHICLE_TEXT_LIMITS[field]);
    }
  }
  if (source.year !== undefined) {
    changes.year = normalizeVehicleYear(source.year);
  }
  return changes;
}

function validateCreateVehicleInput(input: CreateVehicleInput): Required<CreateVehicleInput> {
  const changes = normalizeVehicleFields(input);
  if (changes.name === undefined) {
    throw invalidVehicleField('name');
  }
  return {
    name: changes.name,
    make: changes.make ?? null,
    model: changes.model ?? null,
    generation: changes.generation ?? null,
    trim: changes.trim ?? null,
    year: changes.year ?? null,
    bodyStyle: changes.bodyStyle ?? null,
    engine: changes.engine ?? null,
    transmission: changes.transmission ?? null,
    fuelType: changes.fuelType ?? null,
  };
}

function validateUpdateVehicleInput(input: UpdateVehicleInput): VehicleFieldChanges {
  const changes = normalizeVehicleFields(input);
  if (Object.keys(changes).length === 0) {
    throw new VehicleServiceError('VALIDATION_ERROR', 'At least one vehicle field is required');
  }
  return changes;
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

const ACTIVE_MEMBERSHIP_CRITERIA = {
  status: 'ACTIVE',
  suspendedAt: null,
  revokedAt: null,
} as const;

/**
 * Canonical ownership invariant: Vehicle.ownerUserId MUST match exactly one ACTIVE,
 * unrevoked, unsuspended OWNER Membership. `ownerMemberships` must contain every unrevoked
 * OWNER membership of the vehicle.
 */
function isCanonicalOwnershipConsistent(
  vehicle: VehicleRecord,
  ownerMemberships: readonly MembershipRecord[],
): boolean {
  const ownerRecord = ownerMemberships[0];
  return (
    ownerMemberships.length === 1 &&
    ownerRecord !== undefined &&
    ownerRecord.status === 'ACTIVE' &&
    ownerRecord.suspendedAt === null &&
    ownerRecord.revokedAt === null &&
    ownerRecord.userId.equals(vehicle.ownerUserId)
  );
}

function auditOwnershipInconsistency(
  audit: VehicleAuditLogger,
  vehicleId: Types.ObjectId,
  actorUserId: Types.ObjectId | undefined,
): void {
  audit({
    action: 'vehicle.ownership_inconsistency',
    actorUserId: actorUserId ? String(actorUserId) : 'system',
    vehicleId: String(vehicleId),
    outcome: 'denied',
    reason: 'canonical_owner_mismatch',
  });
}

async function loadOwnerMembershipsByVehicle(
  vehicleIds: readonly Types.ObjectId[],
  session?: ClientSession,
): Promise<Map<string, MembershipRecord[]>> {
  const ownersByVehicle = new Map<string, MembershipRecord[]>();
  if (vehicleIds.length === 0) {
    return ownersByVehicle;
  }
  const owners = (await MembershipModel.find({
    vehicleId: { $in: vehicleIds },
    role: 'OWNER',
    revokedAt: null,
  })
    .session(session ?? null)
    .lean()) as MembershipRecord[];
  for (const owner of owners) {
    const key = String(owner.vehicleId);
    const group = ownersByVehicle.get(key) ?? [];
    group.push(owner);
    ownersByVehicle.set(key, group);
  }
  return ownersByVehicle;
}

/**
 * Loads a vehicle in any lifecycle state and verifies canonical ownership consistency.
 * Any discrepancy fails closed and returns null.
 */
async function loadVerifiedVehicle(
  vehicleId: Types.ObjectId,
  options: {
    status?: Vehicle['status'];
    session?: ClientSession;
    audit?: VehicleAuditLogger;
    actorUserId?: Types.ObjectId;
  } = {},
): Promise<VehicleRecord | null> {
  const audit = options.audit ?? defaultAuditLogger;
  const vehicle = (await VehicleModel.findOne({
    _id: vehicleId,
    ...(options.status ? { status: options.status } : {}),
  })
    .session(options.session ?? null)
    .lean()) as VehicleRecord | null;
  if (!vehicle) {
    return null;
  }

  const ownersByVehicle = await loadOwnerMembershipsByVehicle([vehicleId], options.session);
  if (!isCanonicalOwnershipConsistent(vehicle, ownersByVehicle.get(String(vehicleId)) ?? [])) {
    auditOwnershipInconsistency(audit, vehicleId, options.actorUserId);
    return null;
  }

  return vehicle;
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
): Promise<VehicleRecord | null> {
  return loadVerifiedVehicle(vehicleId, { ...options, status: 'ACTIVE' });
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
  return (await lockVerifiedActiveVehicleWithOwner(vehicleId, session, options))?.vehicle ?? null;
}

interface LockedVehicle {
  vehicle: VehicleRecord;
  ownerMembership: MembershipRecord;
}

/** Same barrier as `lockVerifiedActiveVehicle`, also returning the canonical OWNER membership. */
async function lockVerifiedActiveVehicleWithOwner(
  vehicleId: Types.ObjectId,
  session: ClientSession | undefined,
  options: {
    now?: Date;
    audit?: VehicleAuditLogger;
    actorUserId?: Types.ObjectId;
  } = {},
): Promise<LockedVehicle | null> {
  if (!session) {
    const vehicle = await loadVerifiedActiveVehicle(vehicleId, options);
    if (!vehicle) {
      return null;
    }
    const ownerMembership = (await loadOwnerMembershipsByVehicle([vehicleId])).get(
      String(vehicleId),
    )?.[0];
    return ownerMembership ? { vehicle, ownerMembership } : null;
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

  const ownerMemberships =
    (await loadOwnerMembershipsByVehicle([vehicleId], session)).get(String(vehicleId)) ?? [];
  const ownerRecord = ownerMemberships[0];
  if (!ownerRecord || !isCanonicalOwnershipConsistent(lockedVehicle, ownerMemberships)) {
    auditOwnershipInconsistency(audit, vehicleId, options.actorUserId);
    return null;
  }

  const lockedOwner = (await MembershipModel.findOneAndUpdate(
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
  ).lean()) as MembershipRecord | null;

  if (!lockedOwner) {
    return null;
  }

  return { vehicle: lockedVehicle, ownerMembership: lockedOwner };
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
    ...ACTIVE_MEMBERSHIP_CRITERIA,
  }).lean()) as MembershipRecord | null;

  const request: PermissionRequest = {
    permission: input.permission,
    scopeType,
    scopeResourceId,
    channel,
  };
  const decision = decideMembershipPermission(vehicle, membership, input.userId, request);
  if (decision.kind === 'DECIDED') {
    return decision.result;
  }

  const grant = (await AccessGrantModel.findOne({
    vehicleId: input.vehicleId,
    membershipId: decision.membershipId,
    ...activeAccessGrantCriteria(input.userId, request, now),
  }).lean()) as (AccessGrant & { _id: Types.ObjectId }) | null;

  if (!grant) {
    return { allowed: false, reason: 'PERMISSION_NOT_GRANTED' };
  }

  return {
    allowed: true,
    reason: 'ALLOWED',
    source: 'ACCESS_GRANT',
    membershipId: decision.membershipId,
    grantId: grant._id,
  };
}

interface PermissionRequest {
  permission: string;
  scopeType: AccessGrantScopeType;
  scopeResourceId: Types.ObjectId | null;
  channel: 'ONLINE' | 'BLE_OFFLINE';
}

type MembershipPermissionDecision =
  | { kind: 'DECIDED'; result: PermissionEvaluationResult }
  | { kind: 'ACCESS_GRANT_REQUIRED'; membershipId: Types.ObjectId };

/**
 * Single source of truth for membership-level authorization over an already verified,
 * ownership-consistent ACTIVE vehicle. When only an AccessGrant can still authorize the
 * request, the caller must look it up with `activeAccessGrantCriteria`.
 */
function decideMembershipPermission(
  vehicle: VehicleRecord,
  membership: MembershipRecord | null,
  userId: Types.ObjectId,
  request: PermissionRequest,
): MembershipPermissionDecision {
  const decided = (result: PermissionEvaluationResult): MembershipPermissionDecision => ({
    kind: 'DECIDED',
    result,
  });

  if (!membership) {
    return decided({ allowed: false, reason: 'MEMBERSHIP_INACTIVE_OR_MISSING' });
  }

  if (membership.role === 'OWNER') {
    if (!vehicle.ownerUserId.equals(userId)) {
      return decided({ allowed: false, reason: 'OWNERSHIP_MISMATCH' });
    }
    if (request.channel === 'BLE_OFFLINE') {
      return decided({ allowed: false, reason: 'BLE_OWNER_GRANT_REQUIRED' });
    }
    return decided({
      allowed: true,
      reason: 'ALLOWED',
      source: 'OWNER_ROLE',
      membershipId: membership._id,
    });
  }

  if (vehicle.ownerUserId.equals(userId)) {
    // Owner without OWNER role indicates corrupted state; fail closed.
    return decided({ allowed: false, reason: 'OWNERSHIP_MISMATCH' });
  }

  if (isOwnerReservedPermission(request.permission)) {
    return decided({ allowed: false, reason: 'OWNER_PERMISSION_FORBIDDEN' });
  }

  if (
    request.scopeType === 'VEHICLE' &&
    request.channel === 'ONLINE' &&
    membership.permissions.includes(request.permission)
  ) {
    return decided({
      allowed: true,
      reason: 'ALLOWED',
      source: 'MEMBERSHIP_PERMISSION',
      membershipId: membership._id,
    });
  }

  if (!isAccessGrantPermissionForScope(request.scopeType, request.permission)) {
    return decided({ allowed: false, reason: 'PERMISSION_NOT_GRANTED' });
  }

  return { kind: 'ACCESS_GRANT_REQUIRED', membershipId: membership._id };
}

/** AccessGrant filter shared by single and batched evaluation (vehicle/membership excluded). */
function activeAccessGrantCriteria(userId: Types.ObjectId, request: PermissionRequest, now: Date) {
  const allowedChannels: AccessGrantChannel[] =
    request.channel === 'BLE_OFFLINE' ? ['BLE_OFFLINE', 'ANY'] : ['ONLINE', 'ANY'];
  return {
    subjectUserId: userId,
    scopeType: request.scopeType,
    scopeResourceId: request.scopeType === 'VEHICLE' ? null : request.scopeResourceId,
    channel: { $in: allowedChannels },
    status: 'ACTIVE' as const,
    revokedAt: null,
    expiredAt: null,
    startsAt: { $lte: now },
    $or: [{ expiresAt: null }, { expiresAt: { $gt: now } }],
    permissions: request.permission,
  };
}

/**
 * Effective online read access to a vehicle: canonical OWNER, or MEMBER holding
 * `vehicle:read` / `vehicle:manage` directly, or a current VEHICLE-scoped ONLINE/ANY
 * AccessGrant with `vehicle:read` bound to the current membership. DEVICE, MODULE, and
 * BLE_OFFLINE grants never confer vehicle read access.
 */
const VEHICLE_READ_PERMISSIONS = ['vehicle:read', 'vehicle:manage'] as const;

interface VehicleAccessCandidate {
  vehicle: VehicleRecord;
  membership: MembershipRecord;
}

/**
 * Batched read authorization over ownership-consistent ACTIVE vehicles. Applies the same
 * `decideMembershipPermission` / `activeAccessGrantCriteria` rules as
 * `evaluateVehiclePermission`, with at most one AccessGrant query per read permission.
 * Input order is preserved.
 */
async function filterReadableVehicleCandidates(
  userId: Types.ObjectId,
  candidates: readonly VehicleAccessCandidate[],
  now: Date,
  session?: ClientSession,
): Promise<VehicleAccessCandidate[]> {
  const readable = new Set<VehicleAccessCandidate>();
  const pendingByPermission = new Map<string, VehicleAccessCandidate[]>();

  for (const candidate of candidates) {
    for (const permission of VEHICLE_READ_PERMISSIONS) {
      const decision = decideMembershipPermission(candidate.vehicle, candidate.membership, userId, {
        permission,
        scopeType: 'VEHICLE',
        scopeResourceId: null,
        channel: 'ONLINE',
      });
      if (decision.kind === 'DECIDED') {
        if (decision.result.allowed) {
          readable.add(candidate);
          break;
        }
        continue;
      }
      const pending = pendingByPermission.get(permission) ?? [];
      pending.push(candidate);
      pendingByPermission.set(permission, pending);
    }
  }

  for (const [permission, pending] of pendingByPermission) {
    const unresolved = pending.filter((candidate) => !readable.has(candidate));
    if (unresolved.length === 0) {
      continue;
    }
    const grants = (await AccessGrantModel.find(
      {
        vehicleId: { $in: unresolved.map((candidate) => candidate.vehicle._id) },
        membershipId: { $in: unresolved.map((candidate) => candidate.membership._id) },
        ...activeAccessGrantCriteria(
          userId,
          { permission, scopeType: 'VEHICLE', scopeResourceId: null, channel: 'ONLINE' },
          now,
        ),
      },
      { vehicleId: 1, membershipId: 1 },
    )
      .session(session ?? null)
      .lean()) as Array<Pick<AccessGrant, 'vehicleId' | 'membershipId'>>;
    const grantKeys = new Set(
      grants.map((grant) => `${String(grant.vehicleId)}:${String(grant.membershipId)}`),
    );
    for (const candidate of unresolved) {
      if (grantKeys.has(`${String(candidate.vehicle._id)}:${String(candidate.membership._id)}`)) {
        readable.add(candidate);
      }
    }
  }

  return candidates.filter((candidate) => readable.has(candidate));
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

  const ownersByVehicle = await loadOwnerMembershipsByVehicle(
    candidates.map((vehicle) => vehicle._id),
  );
  return candidates.filter(
    (vehicle) =>
      vehicle.ownerUserId.equals(userId) &&
      isCanonicalOwnershipConsistent(vehicle, ownersByVehicle.get(String(vehicle._id)) ?? []),
  );
}

export const DEFAULT_VEHICLE_PAGE_LIMIT = 20;
export const MAX_VEHICLE_PAGE_LIMIT = 100;
const MAX_VEHICLE_CURSOR_LENGTH = 256;
const VEHICLE_CURSOR_VERSION = 1;

type VehicleListRoleFilter = MembershipRole | 'ALL';

interface VehicleListPosition {
  createdAt: Date;
  vehicleId: Types.ObjectId;
}

const vehicleListCursorPayloadSchema = z.strictObject({
  v: z.literal(VEHICLE_CURSOR_VERSION),
  u: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
  r: z.enum(['ALL', ...MEMBERSHIP_ROLES]),
  c: z.string().max(32),
  i: z.string().regex(/^[a-f0-9]{24}$/),
});

/** Binds a cursor to its user without exposing the raw identifier. Not a secret. */
function vehicleCursorUserBinding(userId: Types.ObjectId): string {
  return createHash('sha256')
    .update(`pichu:vehicle-list-cursor:v${VEHICLE_CURSOR_VERSION}:${String(userId)}`)
    .digest('base64url')
    .slice(0, 22);
}

function invalidVehicleCursor(): VehicleServiceError {
  return new VehicleServiceError('VALIDATION_ERROR', 'Invalid pagination cursor');
}

/**
 * Keyset cursor `(vehicle.createdAt, vehicle._id)` encoded as base64url JSON. It is neither
 * encrypted nor signed and never grants access: authorization is re-evaluated on each page.
 */
function encodeVehicleListCursor(
  userId: Types.ObjectId,
  role: VehicleListRoleFilter,
  position: VehicleListPosition,
): string {
  const payload = {
    v: VEHICLE_CURSOR_VERSION,
    u: vehicleCursorUserBinding(userId),
    r: role,
    c: position.createdAt.toISOString(),
    i: String(position.vehicleId),
  };
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
}

/** Strict base64url JSON decoding shared by every keyset cursor; any anomaly is rejected. */
function decodeCursorJson(cursor: string): unknown {
  if (
    typeof cursor !== 'string' ||
    cursor.length < 1 ||
    cursor.length > MAX_VEHICLE_CURSOR_LENGTH ||
    !/^[A-Za-z0-9_-]+$/.test(cursor)
  ) {
    throw invalidVehicleCursor();
  }
  const bytes = Buffer.from(cursor, 'base64url');
  if (bytes.toString('base64url') !== cursor) {
    throw invalidVehicleCursor();
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw invalidVehicleCursor();
  }
}

function decodeCursorTimestamp(value: string): Date {
  const createdAt = new Date(value);
  if (Number.isNaN(createdAt.getTime()) || createdAt.toISOString() !== value) {
    throw invalidVehicleCursor();
  }
  return createdAt;
}

function decodeVehicleListCursor(
  cursor: string,
  userId: Types.ObjectId,
  role: VehicleListRoleFilter,
): VehicleListPosition {
  const parsed = vehicleListCursorPayloadSchema.safeParse(decodeCursorJson(cursor));
  if (!parsed.success) {
    throw invalidVehicleCursor();
  }
  const createdAt = decodeCursorTimestamp(parsed.data.c);
  if (parsed.data.u !== vehicleCursorUserBinding(userId) || parsed.data.r !== role) {
    throw invalidVehicleCursor();
  }
  return { createdAt, vehicleId: Types.ObjectId.createFromHexString(parsed.data.i) };
}

export interface ListAccessibleVehiclesOptions {
  limit?: number;
  cursor?: string;
  role?: MembershipRole;
  now?: Date;
}

export interface AccessibleVehicle {
  vehicle: VehicleRecord;
  membership: MembershipRecord;
  role: MembershipRole;
}

export interface AccessibleVehiclePage {
  items: AccessibleVehicle[];
  nextCursor: string | null;
}

interface MembershipWithVehicle extends MembershipRecord {
  vehicle: VehicleRecord;
}

/** Upper bound for one scan batch when discarded entries force the batch to grow. */
const MAX_VEHICLE_SCAN_BATCH = 4 * MAX_VEHICLE_PAGE_LIMIT + 1;

/**
 * Server-side scan of the user's memberships ordered by `(vehicle.createdAt, vehicle._id)`.
 * Besides the keyset, it applies a read prefilter that is never stricter than
 * `decideMembershipPermission` + `activeAccessGrantCriteria` (the final decision is still
 * made in `filterReadableVehicleCandidates`), so entries are only discarded after the scan
 * on concurrent changes or corrupted ownership.
 */
function accessibleVehicleBatchPipeline(
  userId: Types.ObjectId,
  role: VehicleListRoleFilter,
  position: VehicleListPosition | null,
  batchSize: number,
  now: Date,
): PipelineStage[] {
  return [
    // membership_user_status_vehicle_idx { userId, status, vehicleId }
    {
      $match: {
        userId,
        ...ACTIVE_MEMBERSHIP_CRITERIA,
        ...(role === 'ALL' ? {} : { role }),
      },
    },
    // Primary-key lookup per membership; only ACTIVE vehicles with a valid keyset timestamp.
    {
      $lookup: {
        from: VehicleModel.collection.collectionName,
        localField: 'vehicleId',
        foreignField: '_id',
        pipeline: [{ $match: { status: 'ACTIVE', createdAt: { $type: 'date' } } }],
        as: 'vehicle',
      },
    },
    { $unwind: '$vehicle' },
    ...(position
      ? [
          {
            $match: {
              $or: [
                { 'vehicle.createdAt': { $gt: position.createdAt } },
                {
                  'vehicle.createdAt': position.createdAt,
                  'vehicle._id': { $gt: position.vehicleId },
                },
              ],
            },
          },
        ]
      : []),
    // OWNER memberships require vehicle.ownerUserId === userId; MEMBER ones require the opposite.
    {
      $match: {
        $expr: {
          $cond: [
            { $eq: ['$role', 'OWNER'] },
            { $eq: ['$vehicle.ownerUserId', '$userId'] },
            { $ne: ['$vehicle.ownerUserId', '$userId'] },
          ],
        },
      },
    },
    // access_grant_membership_status_idx { membershipId, status }; at most one grant per entry.
    {
      $lookup: {
        from: AccessGrantModel.collection.collectionName,
        localField: '_id',
        foreignField: 'membershipId',
        pipeline: [
          {
            $match: {
              status: 'ACTIVE',
              scopeType: 'VEHICLE',
              channel: { $in: ['ONLINE', 'ANY'] },
              permissions: { $in: [...VEHICLE_READ_PERMISSIONS] },
              revokedAt: null,
              expiredAt: null,
              startsAt: { $lte: now },
              $or: [{ expiresAt: null }, { expiresAt: { $gt: now } }],
            },
          },
          { $limit: 1 },
          { $project: { _id: 1 } },
        ],
        as: 'readGrantProbe',
      },
    },
    {
      $match: {
        $or: [
          { role: 'OWNER' },
          { permissions: { $in: [...VEHICLE_READ_PERMISSIONS] } },
          { 'readGrantProbe.0': { $exists: true } },
        ],
      },
    },
    // $sort followed by $limit is a bounded top-k sort (batchSize documents in memory).
    { $sort: { 'vehicle.createdAt': 1, 'vehicle._id': 1 } },
    { $limit: batchSize },
    { $project: { readGrantProbe: 0 } },
  ];
}

/**
 * Keyset-paginated list of ACTIVE, ownership-consistent vehicles the user can read, ordered by
 * `vehicle.createdAt ASC, vehicle._id ASC`. Memberships are scanned server-side in bounded
 * batches (`limit + 1`, doubling up to `MAX_VEHICLE_SCAN_BATCH` only after discards) with a
 * constant number of queries per batch; inconsistent or unreadable entries are skipped and
 * the next cursor is the last delivered authorized vehicle.
 * Pages are not an immutable snapshot: concurrent changes between pages are reflected.
 */
export async function listAccessibleVehicles(
  userId: Types.ObjectId,
  options: ListAccessibleVehiclesOptions = {},
): Promise<AccessibleVehiclePage> {
  const limit = options.limit ?? DEFAULT_VEHICLE_PAGE_LIMIT;
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_VEHICLE_PAGE_LIMIT) {
    throw new VehicleServiceError('VALIDATION_ERROR', 'Invalid pagination limit');
  }
  if (options.role !== undefined && !MEMBERSHIP_ROLES.includes(options.role)) {
    throw new VehicleServiceError('VALIDATION_ERROR', 'Invalid role filter');
  }
  const role: VehicleListRoleFilter = options.role ?? 'ALL';
  let position =
    options.cursor === undefined ? null : decodeVehicleListCursor(options.cursor, userId, role);
  const now = options.now ?? new Date();
  let batchSize = limit + 1;
  const authorized: AccessibleVehicle[] = [];

  while (authorized.length <= limit) {
    const batch = await MembershipModel.aggregate<MembershipWithVehicle>(
      accessibleVehicleBatchPipeline(userId, role, position, batchSize, now),
    );
    if (batch.length === 0) {
      break;
    }

    const ownersByVehicle = await loadOwnerMembershipsByVehicle(
      batch.map((entry) => entry.vehicle._id),
    );
    const consistent: VehicleAccessCandidate[] = [];
    for (const { vehicle, ...membership } of batch) {
      if (isCanonicalOwnershipConsistent(vehicle, ownersByVehicle.get(String(vehicle._id)) ?? [])) {
        consistent.push({ vehicle, membership });
      }
    }
    const readable = await filterReadableVehicleCandidates(userId, consistent, now);
    for (const candidate of readable) {
      authorized.push({ ...candidate, role: candidate.membership.role });
    }

    const lastScanned = batch[batch.length - 1]!;
    position = { createdAt: lastScanned.vehicle.createdAt, vehicleId: lastScanned.vehicle._id };
    if (batch.length < batchSize) {
      break;
    }
    if (readable.length < batch.length) {
      batchSize = Math.min(batchSize * 2, MAX_VEHICLE_SCAN_BATCH);
    }
  }

  const items = authorized.slice(0, limit);
  const lastDelivered = items[items.length - 1];
  const nextCursor =
    authorized.length > limit && lastDelivered
      ? encodeVehicleListCursor(userId, role, {
          createdAt: lastDelivered.vehicle.createdAt,
          vehicleId: lastDelivered.vehicle._id,
        })
      : null;
  return { items, nextCursor };
}

/**
 * Relationship between an actor and a vehicle, resolved fail-closed. Inexistent,
 * ownership-inconsistent, and non-readable vehicles all collapse into `NONE`.
 */
type VehicleRelation =
  | { kind: 'OWNER'; vehicle: VehicleRecord; membership: MembershipRecord }
  | { kind: 'READER'; vehicle: VehicleRecord; membership: MembershipRecord }
  | { kind: 'ARCHIVED_OWNER'; vehicle: VehicleRecord }
  | { kind: 'NONE' };

async function resolveVehicleRelation(
  vehicleId: Types.ObjectId,
  userId: Types.ObjectId,
  options: { now?: Date; audit?: VehicleAuditLogger } = {},
): Promise<VehicleRelation> {
  const vehicle = await loadVerifiedVehicle(vehicleId, {
    audit: options.audit,
    actorUserId: userId,
  });
  if (!vehicle) {
    return { kind: 'NONE' };
  }
  if (vehicle.status === 'ARCHIVED') {
    return vehicle.ownerUserId.equals(userId)
      ? { kind: 'ARCHIVED_OWNER', vehicle }
      : { kind: 'NONE' };
  }
  if (vehicle.status !== 'ACTIVE') {
    return { kind: 'NONE' };
  }

  const membership = (await MembershipModel.findOne({
    vehicleId,
    userId,
    ...ACTIVE_MEMBERSHIP_CRITERIA,
  }).lean()) as MembershipRecord | null;
  if (!membership) {
    return { kind: 'NONE' };
  }
  const [readable] = await filterReadableVehicleCandidates(
    userId,
    [{ vehicle, membership }],
    options.now ?? new Date(),
  );
  if (!readable) {
    return { kind: 'NONE' };
  }
  return membership.role === 'OWNER'
    ? { kind: 'OWNER', vehicle, membership }
    : { kind: 'READER', vehicle, membership };
}

type OwnerMutationAction =
  | 'vehicle.update'
  | 'vehicle.archive'
  | 'membership.update'
  | 'membership.suspend'
  | 'membership.reactivate'
  | 'membership.revoke';

/**
 * Central translation of non-owner relations into domain errors for owner-only mutations:
 * no visibility → NOT_FOUND, legitimate reader → FORBIDDEN, archived owner → CONFLICT.
 * Ownership inconsistencies are never disclosed.
 */
function denyOwnerMutation(
  relation: Exclude<VehicleRelation, { kind: 'OWNER' }>,
  context: {
    action: OwnerMutationAction;
    vehicleId: Types.ObjectId;
    actorUserId: Types.ObjectId;
    audit: VehicleAuditLogger;
  },
): never {
  const error =
    relation.kind === 'READER'
      ? new VehicleServiceError(
          'FORBIDDEN',
          'Only the canonical vehicle owner may perform this operation',
        )
      : relation.kind === 'ARCHIVED_OWNER'
        ? new VehicleServiceError('CONFLICT', 'Archived vehicles cannot be modified')
        : new VehicleServiceError('NOT_FOUND', 'Vehicle not found');
  context.audit({
    action: context.action,
    actorUserId: String(context.actorUserId),
    vehicleId: String(context.vehicleId),
    outcome: error.code === 'CONFLICT' ? 'conflict' : 'denied',
    reason: relation.kind === 'READER' ? 'not_canonical_owner' : relation.kind.toLowerCase(),
  });
  throw error;
}

/**
 * Detail lookup with effective read authorization. Inexistent, archived, inconsistent, and
 * non-readable vehicles uniformly raise NOT_FOUND.
 */
export async function getAccessibleVehicle(
  vehicleId: Types.ObjectId,
  userId: Types.ObjectId,
  options: { now?: Date; audit?: VehicleAuditLogger } = {},
): Promise<AccessibleVehicle> {
  const relation = await resolveVehicleRelation(vehicleId, userId, options);
  if (relation.kind !== 'OWNER' && relation.kind !== 'READER') {
    throw new VehicleServiceError('NOT_FOUND', 'Vehicle not found');
  }
  return {
    vehicle: relation.vehicle,
    membership: relation.membership,
    role: relation.membership.role,
  };
}

export async function getVehicleForUser(
  vehicleId: Types.ObjectId,
  userId: Types.ObjectId,
): Promise<VehicleRecord | null> {
  const relation = await resolveVehicleRelation(vehicleId, userId);
  return relation.kind === 'OWNER' || relation.kind === 'READER' ? relation.vehicle : null;
}

// ---------------------------------------------------------------------------
// Invitations and membership administration
// ---------------------------------------------------------------------------

/** Revocation reason for invitations whose issuer no longer holds the delegated authority. */
export const INVITATION_ISSUER_AUTHORITY_LOST_REASON = 'issuer_authority_lost';
/** Revocation reason of a membership ended by its own holder. */
export const MEMBER_LEFT_REASON = 'member_left';

const memberDelegableInvitationSet = new Set<string>(MEMBER_DELEGABLE_INVITATION_PERMISSIONS);

function holdsInvitationAuthority(permissions: readonly string[]): boolean {
  return INVITATION_AUTHORITY_PERMISSIONS.some((permission) => permissions.includes(permission));
}

/** A MEMBER may only delegate member-delegable permissions held directly in their membership. */
function isMemberDelegationAllowed(
  permissions: readonly string[],
  issuerPermissions: readonly string[],
): boolean {
  return permissions.every(
    (permission) =>
      memberDelegableInvitationSet.has(permission) && issuerPermissions.includes(permission),
  );
}

type InvitationIssuerResolution =
  | { kind: 'OWNER'; vehicle: VehicleRecord; membership: MembershipRecord }
  | { kind: 'DELEGATE'; vehicle: VehicleRecord; membership: MembershipRecord }
  | { kind: 'VISIBLE_WITHOUT_AUTHORITY' }
  | { kind: 'NONE' };

/**
 * Read-only issuer resolution: the canonical OWNER, or an ACTIVE MEMBER holding
 * `vehicle:manage` / `invitation:create` directly (AccessGrants never confer it). Callers
 * without authority are split into visible readers (FORBIDDEN) and everyone else (NOT_FOUND).
 */
async function resolveInvitationIssuer(
  vehicleId: Types.ObjectId,
  actorUserId: Types.ObjectId,
  options: { now: Date; audit: VehicleAuditLogger },
): Promise<InvitationIssuerResolution> {
  const vehicle = await loadVerifiedActiveVehicle(vehicleId, {
    audit: options.audit,
    actorUserId,
  });
  if (!vehicle) {
    return { kind: 'NONE' };
  }
  const membership = (await MembershipModel.findOne({
    vehicleId,
    userId: actorUserId,
    ...ACTIVE_MEMBERSHIP_CRITERIA,
  }).lean()) as MembershipRecord | null;
  if (!membership) {
    return { kind: 'NONE' };
  }
  const isOwner = vehicle.ownerUserId.equals(actorUserId);
  if (membership.role === 'OWNER') {
    return isOwner ? { kind: 'OWNER', vehicle, membership } : { kind: 'NONE' };
  }
  if (isOwner) {
    return { kind: 'NONE' };
  }
  if (holdsInvitationAuthority(membership.permissions)) {
    return { kind: 'DELEGATE', vehicle, membership };
  }
  const [readable] = await filterReadableVehicleCandidates(
    actorUserId,
    [{ vehicle, membership }],
    options.now,
  );
  return readable ? { kind: 'VISIBLE_WITHOUT_AUTHORITY' } : { kind: 'NONE' };
}

/**
 * Whether the issuer of a PENDING invitation still holds the authority it was issued with.
 * Owner invitations stay valid while bound to the canonical OWNER membership (or unbound legacy
 * documents). Delegate invitations require the exact issuing membership to remain ACTIVE, keep
 * invitation authority, and still hold every delegated permission directly; a new membership of
 * the same user never revalidates them. Unbound legacy delegate invitations fail closed.
 */
function isInvitationIssuerAuthorityCurrent(
  invitation: InvitationRecord,
  locked: LockedVehicle,
  issuerMembership: MembershipRecord | null,
): boolean {
  const issuerMembershipId = invitation.issuerMembershipId ?? null;
  if (locked.vehicle.ownerUserId.equals(invitation.inviterUserId)) {
    return issuerMembershipId === null || issuerMembershipId.equals(locked.ownerMembership._id);
  }
  if (issuerMembershipId === null || issuerMembership === null) {
    return false;
  }
  return (
    issuerMembership._id.equals(issuerMembershipId) &&
    issuerMembership.vehicleId.equals(invitation.vehicleId) &&
    issuerMembership.userId.equals(invitation.inviterUserId) &&
    issuerMembership.role === 'MEMBER' &&
    issuerMembership.status === 'ACTIVE' &&
    issuerMembership.suspendedAt === null &&
    issuerMembership.revokedAt === null &&
    holdsInvitationAuthority(issuerMembership.permissions) &&
    isMemberDelegationAllowed(invitation.permissions, issuerMembership.permissions)
  );
}

type InvitationFilter = QueryFilter<Invitation>;

async function persistElapsedInvitations(
  filter: InvitationFilter,
  now: Date,
  session?: ClientSession,
): Promise<void> {
  await InvitationModel.updateMany(
    { $and: [filter, { status: 'PENDING', expiresAt: { $lte: now } }] },
    { $set: { status: 'EXPIRED', expiredAt: now } },
    { session },
  );
}

/**
 * PENDING invitations issued through `membership`, including unbound legacy invitations of the
 * same non-owner user (which can never be accepted). Elapsed ones become EXPIRED; the rest are
 * REVOKED with `issuer_authority_lost`. `extraFilter` narrows the revoked subset.
 */
async function revokeIssuedInvitations(
  session: ClientSession | undefined,
  input: {
    vehicleId: Types.ObjectId;
    membership: MembershipRecord;
    actorUserId: Types.ObjectId;
    now: Date;
    extraFilter?: InvitationFilter;
  },
): Promise<number> {
  const issued: InvitationFilter = {
    vehicleId: input.vehicleId,
    status: 'PENDING',
    $or: [
      { issuerMembershipId: input.membership._id },
      { issuerMembershipId: null, inviterUserId: input.membership.userId },
    ],
  };
  await InvitationModel.updateMany(
    { $and: [issued, { expiresAt: { $lte: input.now } }] },
    { $set: { status: 'EXPIRED', expiredAt: input.now } },
    { session },
  );
  const revoked = await InvitationModel.updateMany(
    { $and: [issued, { expiresAt: { $gt: input.now } }, input.extraFilter ?? {}] },
    {
      $set: {
        status: 'REVOKED',
        revokedAt: input.now,
        revokedByUserId: input.actorUserId,
        revokeReason: INVITATION_ISSUER_AUTHORITY_LOST_REASON,
        updatedByUserId: input.actorUserId,
      },
    },
    { session },
  );
  return revoked.modifiedCount;
}

/** Elapsed AccessGrants of the membership become EXPIRED; the remaining ACTIVE ones REVOKED. */
async function revokeMembershipGrants(
  session: ClientSession | undefined,
  input: {
    vehicleId: Types.ObjectId;
    membershipId: Types.ObjectId;
    actorUserId: Types.ObjectId;
    now: Date;
    reason: string;
  },
): Promise<number> {
  const scope = {
    vehicleId: input.vehicleId,
    membershipId: input.membershipId,
    status: 'ACTIVE' as const,
  };
  await AccessGrantModel.updateMany(
    { ...scope, expiresAt: { $ne: null, $lte: input.now } },
    { $set: { status: 'EXPIRED', expiredAt: input.now } },
    { session },
  );
  const revoked = await AccessGrantModel.updateMany(
    { ...scope, revokedAt: null },
    {
      $set: {
        status: 'REVOKED',
        revokedAt: input.now,
        revokedByUserId: input.actorUserId,
        revokeReason: input.reason,
        updatedByUserId: input.actorUserId,
      },
    },
    { session },
  );
  return revoked.modifiedCount;
}

export interface InviteMemberOptions {
  ttlMs?: number;
  now?: Date;
  audit?: VehicleAuditLogger;
  /**
   * Recipient existence check (Identity). Invoked only after the issuer is authorized and the
   * delegated permissions are validated, so unauthorized callers never trigger a lookup.
   */
  confirmInviteeExists?: () => Promise<boolean>;
}

/**
 * Issues a MEMBER invitation. Returns null when the vehicle is not visible to the issuer.
 * Duplicate valid PENDING invitations are a CONFLICT and are never overwritten; to change an
 * invitation it must be revoked and issued again.
 */
export async function inviteMember(
  vehicleId: Types.ObjectId,
  inviterUserId: Types.ObjectId,
  inviteeUserId: Types.ObjectId,
  permissions: string[],
  options: InviteMemberOptions = {},
): Promise<InvitationRecord | null> {
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

  const record = (outcome: VehicleAuditEvent['outcome'], reason?: string): void =>
    audit({
      action: 'invitation.create',
      actorUserId: String(inviterUserId),
      vehicleId: String(vehicleId),
      targetId: String(inviteeUserId),
      outcome,
      reason,
    });

  const issuer = await resolveInvitationIssuer(vehicleId, inviterUserId, { now, audit });
  if (issuer.kind === 'NONE') {
    record('denied', 'vehicle_not_visible');
    return null;
  }
  if (issuer.kind === 'VISIBLE_WITHOUT_AUTHORITY') {
    record('denied', 'insufficient_permissions');
    throw new VehicleServiceError('FORBIDDEN', 'Insufficient permissions to invite members');
  }
  if (
    issuer.kind === 'DELEGATE' &&
    !isMemberDelegationAllowed(permissions, issuer.membership.permissions)
  ) {
    record('denied', 'delegation_not_allowed');
    throw new VehicleServiceError(
      'FORBIDDEN',
      'Members may only delegate vehicle:read, device:read or module:read permissions they hold directly',
    );
  }

  if (options.confirmInviteeExists && !(await options.confirmInviteeExists())) {
    record('denied', 'invitee_not_found');
    throw new VehicleServiceError('NOT_FOUND', 'User not found');
  }

  // Durable EXPIRED transition outside the abortable transaction; only authorized issuers get here.
  await persistElapsedInvitations({ vehicleId, inviteeUserId }, now);

  const expiresAt = new Date(now.getTime() + ttlMs);

  let invitation: InvitationRecord;
  try {
    invitation = await runInVehicleTransaction(async (session) => {
      const locked = await lockVerifiedActiveVehicleWithOwner(vehicleId, session, {
        now,
        actorUserId: inviterUserId,
        audit,
      });
      if (!locked) {
        throw new TransactionAbortDomainError('REJECT_NULL', 'vehicle_unavailable');
      }

      let issuerMembershipId: Types.ObjectId;
      let issuedByDelegate = false;
      if (locked.vehicle.ownerUserId.equals(inviterUserId)) {
        issuerMembershipId = locked.ownerMembership._id;
      } else {
        // Conditional write on the issuing membership: serializes against concurrent
        // suspension, revocation, or permission changes of the issuer.
        const issuerMembership = (await MembershipModel.findOneAndUpdate(
          { vehicleId, userId: inviterUserId, role: 'MEMBER', ...ACTIVE_MEMBERSHIP_CRITERIA },
          { $set: { updatedAt: now } },
          { returnDocument: 'after', session },
        ).lean()) as MembershipRecord | null;
        if (!issuerMembership || !holdsInvitationAuthority(issuerMembership.permissions)) {
          throw new TransactionAbortDomainError(
            'FORBIDDEN',
            'Insufficient permissions to invite members',
          );
        }
        if (!isMemberDelegationAllowed(permissions, issuerMembership.permissions)) {
          throw new TransactionAbortDomainError(
            'FORBIDDEN',
            'Members may only delegate vehicle:read, device:read or module:read permissions they hold directly',
          );
        }
        issuerMembershipId = issuerMembership._id;
        issuedByDelegate = true;
      }

      if (locked.vehicle.ownerUserId.equals(inviteeUserId)) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'Vehicle owner cannot be invited as a member',
        );
      }

      const existingMembership = await MembershipModel.findOne({
        vehicleId,
        userId: inviteeUserId,
        revokedAt: null,
      })
        .session(session ?? null)
        .lean();
      if (existingMembership) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'Invitee already holds an active or suspended membership for this vehicle',
        );
      }

      if (issuedByDelegate) {
        const previouslyRevoked = await MembershipModel.exists({
          vehicleId,
          userId: inviteeUserId,
          status: 'REVOKED',
        }).session(session ?? null);
        if (previouslyRevoked) {
          throw new TransactionAbortDomainError(
            'FORBIDDEN',
            'Only the vehicle owner may invite a user whose membership was revoked',
          );
        }
      }

      await persistElapsedInvitations({ vehicleId, inviteeUserId }, now, session);
      const pending = await InvitationModel.exists({
        vehicleId,
        inviteeUserId,
        status: 'PENDING',
      }).session(session ?? null);
      if (pending) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'A pending invitation already exists for this user',
        );
      }

      const created = await createDocumentWithSession(
        InvitationModel,
        {
          vehicleId,
          inviterUserId,
          inviteeUserId,
          issuerMembershipId,
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
      return (
        typeof created.toObject === 'function' ? created.toObject() : created
      ) as InvitationRecord;
    });
  } catch (error) {
    if (error instanceof TransactionAbortDomainError) {
      if (error.code === 'REJECT_NULL') {
        record('denied', error.message);
        return null;
      }
      record(error.code === 'CONFLICT' ? 'conflict' : 'denied', error.message);
      throw new VehicleServiceError(error.code, error.message);
    }
    if (isDuplicateKeyError(error)) {
      record('conflict', 'concurrent_pending_invitation');
      throw new VehicleServiceError(
        'CONFLICT',
        'A pending invitation already exists for this user',
        {
          cause: error,
        },
      );
    }
    throw error;
  }

  audit({
    action: 'invitation.create',
    actorUserId: String(inviterUserId),
    vehicleId: String(vehicleId),
    targetId: String(invitation._id),
    outcome: 'success',
  });
  return invitation;
}

type AcceptInvitationOutcome =
  | { kind: 'NOT_FOUND' }
  | { kind: 'AUTHORITY_LOST'; vehicleId: Types.ObjectId }
  | { kind: 'ACCEPTED'; membership: MembershipRecord };

/**
 * Accepts the caller's own invitation. Returns null for inexistent, foreign, or invisible
 * invitations. Own non-pending or elapsed invitations raise CONFLICT (elapsed ones are durably
 * persisted as EXPIRED first). When the issuer no longer holds the delegated authority, the
 * invitation is durably REVOKED with `issuer_authority_lost` in a committed transaction and
 * the acceptance is rejected with CONFLICT.
 */
export async function acceptInvitation(
  invitationId: Types.ObjectId,
  userId: Types.ObjectId,
  options: { now?: Date; audit?: VehicleAuditLogger } = {},
): Promise<MembershipRecord | null> {
  const audit = options.audit ?? defaultAuditLogger;
  const now = options.now ?? new Date();
  const record = (
    vehicleId: Types.ObjectId | undefined,
    outcome: VehicleAuditEvent['outcome'],
    reason?: string,
  ): void =>
    audit({
      action: 'invitation.accept',
      actorUserId: String(userId),
      vehicleId: vehicleId ? String(vehicleId) : undefined,
      targetId: String(invitationId),
      outcome,
      reason,
    });

  // Persist EXPIRED outside the acceptance transaction so it is never lost on rollback.
  const newlyExpired = (await InvitationModel.findOneAndUpdate(
    { _id: invitationId, inviteeUserId: userId, status: 'PENDING', expiresAt: { $lte: now } },
    { $set: { status: 'EXPIRED', expiredAt: now } },
    { returnDocument: 'after' },
  ).lean()) as InvitationRecord | null;
  if (newlyExpired) {
    record(newlyExpired.vehicleId, 'conflict', 'invitation_expired');
    throw new VehicleServiceError('CONFLICT', 'Invitation is no longer pending');
  }

  let outcome: AcceptInvitationOutcome;
  try {
    outcome = await runInVehicleTransaction(async (session): Promise<AcceptInvitationOutcome> => {
      const invitation = (await InvitationModel.findOne({
        _id: invitationId,
        inviteeUserId: userId,
      })
        .session(session ?? null)
        .lean()) as InvitationRecord | null;
      if (!invitation) {
        return { kind: 'NOT_FOUND' };
      }
      if (invitation.status !== 'PENDING' || invitation.expiresAt.getTime() <= now.getTime()) {
        throw new TransactionAbortDomainError('CONFLICT', 'Invitation is no longer pending');
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

      const locked = await lockVerifiedActiveVehicleWithOwner(invitation.vehicleId, session, {
        now,
        actorUserId: userId,
        audit,
      });
      if (!locked) {
        return { kind: 'NOT_FOUND' };
      }
      if (locked.vehicle.ownerUserId.equals(userId)) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'Canonical vehicle owner cannot accept a member invitation',
        );
      }

      const issuerMembershipId = invitation.issuerMembershipId ?? null;
      const issuerMembership =
        issuerMembershipId !== null && !locked.vehicle.ownerUserId.equals(invitation.inviterUserId)
          ? ((await MembershipModel.findOne({ _id: issuerMembershipId })
              .session(session ?? null)
              .lean()) as MembershipRecord | null)
          : null;
      if (!isInvitationIssuerAuthorityCurrent(invitation, locked, issuerMembership)) {
        // Committed (not aborted) so the revocation survives the rejected acceptance.
        const revoked = await InvitationModel.findOneAndUpdate(
          {
            _id: invitation._id,
            inviteeUserId: userId,
            status: 'PENDING',
            expiresAt: { $gt: now },
          },
          {
            $set: {
              status: 'REVOKED',
              revokedAt: now,
              revokedByUserId: userId,
              revokeReason: INVITATION_ISSUER_AUTHORITY_LOST_REASON,
              updatedByUserId: userId,
            },
          },
          { returnDocument: 'after', runValidators: true, session },
        ).lean();
        if (!revoked) {
          throw new TransactionAbortDomainError(
            'CONFLICT',
            'Concurrent state change prevented invitation acceptance',
          );
        }
        return { kind: 'AUTHORITY_LOST', vehicleId: invitation.vehicleId };
      }

      const existingMembership = await MembershipModel.findOne({
        vehicleId: invitation.vehicleId,
        userId,
        revokedAt: null,
      })
        .session(session ?? null)
        .lean();
      if (existingMembership) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'User already holds a non-revoked membership for this vehicle',
        );
      }

      const claimed = await InvitationModel.findOneAndUpdate(
        {
          _id: invitation._id,
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
      ).lean();
      if (!claimed) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'Concurrent state change prevented invitation acceptance',
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
      return {
        kind: 'ACCEPTED',
        membership: (typeof membershipDoc.toObject === 'function'
          ? membershipDoc.toObject()
          : membershipDoc) as MembershipRecord,
      };
    });
  } catch (error) {
    if (error instanceof TransactionAbortDomainError) {
      record(undefined, error.code === 'CONFLICT' ? 'conflict' : 'denied', error.message);
      if (error.code === 'REJECT_NULL') {
        return null;
      }
      throw new VehicleServiceError(error.code, error.message);
    }
    if (isDuplicateKeyError(error)) {
      record(undefined, 'conflict', 'concurrent_membership_creation');
      throw new VehicleServiceError(
        'CONFLICT',
        'Concurrent membership creation conflict during invitation acceptance',
        { cause: error },
      );
    }
    throw error;
  }

  if (outcome.kind === 'NOT_FOUND') {
    record(undefined, 'denied', 'invitation_not_visible');
    return null;
  }
  if (outcome.kind === 'AUTHORITY_LOST') {
    audit({
      action: 'invitation.revoke',
      actorUserId: String(userId),
      vehicleId: String(outcome.vehicleId),
      targetId: String(invitationId),
      outcome: 'success',
      reason: INVITATION_ISSUER_AUTHORITY_LOST_REASON,
    });
    record(outcome.vehicleId, 'conflict', INVITATION_ISSUER_AUTHORITY_LOST_REASON);
    throw new VehicleServiceError(
      'CONFLICT',
      'The invitation issuer no longer holds the required authority; the invitation was revoked',
    );
  }
  record(outcome.membership.vehicleId, 'success');
  return outcome.membership;
}

export interface RevokeInvitationResult {
  invitation: InvitationRecord;
  /** True when the invitation was already REVOKED; the original record is returned unchanged. */
  alreadyRevoked: boolean;
}

/**
 * Revokes a PENDING invitation. The OWNER may revoke any invitation of the vehicle; an
 * authorized delegate only those issued through their current membership. Anything else is
 * NOT_FOUND (or FORBIDDEN for visible readers without invitation authority).
 */
export async function revokeInvitation(input: {
  vehicleId: Types.ObjectId;
  invitationId: Types.ObjectId;
  actorUserId: Types.ObjectId;
  reason?: string | null;
  now?: Date;
  audit?: VehicleAuditLogger;
}): Promise<RevokeInvitationResult> {
  const audit = input.audit ?? defaultAuditLogger;
  const now = input.now ?? new Date();
  const reason = validateOptionalAuditReason(input.reason);
  const record = (outcome: VehicleAuditEvent['outcome'], auditReason?: string): void =>
    audit({
      action: 'invitation.revoke',
      actorUserId: String(input.actorUserId),
      vehicleId: String(input.vehicleId),
      targetId: String(input.invitationId),
      outcome,
      reason: auditReason,
    });
  const notFound = (): VehicleServiceError =>
    new VehicleServiceError('NOT_FOUND', 'Invitation not found');

  const issuer = await resolveInvitationIssuer(input.vehicleId, input.actorUserId, {
    now,
    audit,
  });
  if (issuer.kind === 'NONE') {
    record('denied', 'vehicle_not_visible');
    throw notFound();
  }
  if (issuer.kind === 'VISIBLE_WITHOUT_AUTHORITY') {
    record('denied', 'insufficient_permissions');
    throw new VehicleServiceError('FORBIDDEN', 'Insufficient permissions to revoke invitations');
  }

  const scope =
    issuer.kind === 'OWNER'
      ? { _id: input.invitationId, vehicleId: input.vehicleId }
      : {
          _id: input.invitationId,
          vehicleId: input.vehicleId,
          issuerMembershipId: issuer.membership._id,
        };
  const current = (await InvitationModel.findOne(scope).lean()) as InvitationRecord | null;
  if (!current) {
    record('denied', 'invitation_not_visible');
    throw notFound();
  }
  if (current.status === 'REVOKED') {
    return { invitation: current, alreadyRevoked: true };
  }
  if (current.status === 'PENDING' && current.expiresAt.getTime() <= now.getTime()) {
    await persistElapsedInvitations(scope, now);
    record('conflict', 'invitation_expired');
    throw new VehicleServiceError('CONFLICT', 'Invitation already expired');
  }
  if (current.status !== 'PENDING') {
    record('conflict', `invitation_${current.status.toLowerCase()}`);
    throw new VehicleServiceError('CONFLICT', `Invitation is already ${current.status}`);
  }

  let result: RevokeInvitationResult;
  try {
    result = await runInVehicleTransaction(async (session) => {
      const locked = await lockVerifiedActiveVehicleWithOwner(input.vehicleId, session, {
        now,
        actorUserId: input.actorUserId,
        audit,
      });
      if (!locked) {
        throw new TransactionAbortDomainError('REJECT_NULL', 'vehicle_unavailable');
      }
      if (issuer.kind === 'OWNER') {
        if (!locked.vehicle.ownerUserId.equals(input.actorUserId)) {
          throw new TransactionAbortDomainError('REJECT_NULL', 'ownership_changed');
        }
      } else {
        const issuerMembership = (await MembershipModel.findOneAndUpdate(
          {
            _id: issuer.membership._id,
            vehicleId: input.vehicleId,
            userId: input.actorUserId,
            role: 'MEMBER',
            ...ACTIVE_MEMBERSHIP_CRITERIA,
          },
          { $set: { updatedAt: now } },
          { returnDocument: 'after', session },
        ).lean()) as MembershipRecord | null;
        if (!issuerMembership || !holdsInvitationAuthority(issuerMembership.permissions)) {
          throw new TransactionAbortDomainError('REJECT_NULL', 'issuer_authority_lost');
        }
      }

      const revoked = (await InvitationModel.findOneAndUpdate(
        { ...scope, status: 'PENDING', expiresAt: { $gt: now } },
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
      ).lean()) as InvitationRecord | null;
      if (revoked) {
        return { invitation: revoked, alreadyRevoked: false };
      }
      const latest = (await InvitationModel.findOne(scope)
        .session(session ?? null)
        .lean()) as InvitationRecord | null;
      if (latest?.status === 'REVOKED') {
        return { invitation: latest, alreadyRevoked: true };
      }
      throw new TransactionAbortDomainError('CONFLICT', 'Invitation is no longer pending');
    });
  } catch (error) {
    if (error instanceof TransactionAbortDomainError) {
      if (error.code === 'REJECT_NULL') {
        record('denied', error.message);
        throw notFound();
      }
      record('conflict', error.message);
      throw new VehicleServiceError(error.code, error.message);
    }
    throw error;
  }

  if (!result.alreadyRevoked) {
    record('success', reason ?? undefined);
  }
  return result;
}

export interface MembershipTransitionResult {
  membership: MembershipRecord;
  revokedGrantsCount: number;
  revokedInvitationsCount: number;
}

export interface MembershipRevocationResult extends MembershipTransitionResult {
  /** True when the membership was already REVOKED; the original record is returned unchanged. */
  alreadyRevoked: boolean;
}

export interface MembershipPermissionsUpdateResult {
  membership: MembershipRecord;
  /** False when the requested set equals the current one; nothing is written. */
  changed: boolean;
  revokedInvitationsCount: number;
}

interface OwnerMembershipMutationInput {
  vehicleId: Types.ObjectId;
  membershipId: Types.ObjectId;
  actorUserId: Types.ObjectId;
  now: Date;
  audit: VehicleAuditLogger;
  action: OwnerMutationAction;
}

/**
 * Shared frame for OWNER-only membership administration: read-only pre-authorization (no
 * persistent effects for unauthorized callers), then a transaction that locks the vehicle and
 * canonical owner membership before reading the target, which must be a MEMBER of the same
 * vehicle. The OWNER membership is never a valid target.
 */
async function runOwnerMembershipMutation<T>(
  input: OwnerMembershipMutationInput,
  work: (
    session: ClientSession | undefined,
    context: { locked: LockedVehicle; target: MembershipRecord },
  ) => Promise<T>,
): Promise<T> {
  const context = {
    action: input.action,
    vehicleId: input.vehicleId,
    actorUserId: input.actorUserId,
    audit: input.audit,
  };
  const relation = await resolveVehicleRelation(input.vehicleId, input.actorUserId, {
    now: input.now,
    audit: input.audit,
  });
  if (relation.kind !== 'OWNER') {
    denyOwnerMutation(relation, context);
  }

  try {
    return await runInVehicleTransaction(async (session) => {
      const locked = await lockVerifiedActiveVehicleWithOwner(input.vehicleId, session, {
        now: input.now,
        audit: input.audit,
        actorUserId: input.actorUserId,
      });
      if (!locked || !locked.vehicle.ownerUserId.equals(input.actorUserId)) {
        throw new TransactionAbortDomainError('REJECT_NULL', 'Vehicle state changed');
      }
      const target = (await MembershipModel.findOne({
        _id: input.membershipId,
        vehicleId: input.vehicleId,
      })
        .session(session ?? null)
        .lean()) as MembershipRecord | null;
      if (!target) {
        throw new TransactionAbortDomainError('NOT_FOUND', 'Membership not found');
      }
      if (target.role === 'OWNER' || target.userId.equals(locked.vehicle.ownerUserId)) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'The OWNER membership cannot be modified through member administration',
        );
      }
      return work(session, { locked, target });
    });
  } catch (error) {
    if (error instanceof TransactionAbortDomainError) {
      if (error.code === 'REJECT_NULL') {
        const current = await resolveVehicleRelation(input.vehicleId, input.actorUserId, {
          now: input.now,
          audit: input.audit,
        });
        if (current.kind !== 'OWNER') {
          denyOwnerMutation(current, context);
        }
        throw new VehicleServiceError(
          'CONFLICT',
          'Concurrent state change prevented the membership operation',
        );
      }
      input.audit({
        action: input.action,
        actorUserId: String(input.actorUserId),
        vehicleId: String(input.vehicleId),
        targetId: String(input.membershipId),
        outcome: error.code === 'CONFLICT' ? 'conflict' : 'denied',
        reason: error.message,
      });
      throw new VehicleServiceError(error.code, error.message);
    }
    throw error;
  }
}

function auditMembershipSuccess(
  input:
    | OwnerMembershipMutationInput
    | (Omit<OwnerMembershipMutationInput, 'action'> & {
        action: 'membership.leave';
      }),
  reason?: string | null,
): void {
  input.audit({
    action: input.action,
    actorUserId: String(input.actorUserId),
    vehicleId: String(input.vehicleId),
    targetId: String(input.membershipId),
    outcome: 'success',
    reason: reason ?? undefined,
  });
}

/**
 * OWNER-only ACTIVE → SUSPENDED. In the same transaction the membership's ACTIVE AccessGrants
 * are revoked (elapsed ones expire) and its PENDING issued invitations are revoked. Base
 * permissions and history are preserved; reactivation restores neither grants nor invitations.
 */
export async function suspendMembership(input: {
  vehicleId: Types.ObjectId;
  membershipId: Types.ObjectId;
  actorUserId: Types.ObjectId;
  reason?: string | null;
  now?: Date;
  audit?: VehicleAuditLogger;
}): Promise<MembershipTransitionResult> {
  const reason = validateOptionalAuditReason(input.reason);
  const frame: OwnerMembershipMutationInput = {
    vehicleId: input.vehicleId,
    membershipId: input.membershipId,
    actorUserId: input.actorUserId,
    now: input.now ?? new Date(),
    audit: input.audit ?? defaultAuditLogger,
    action: 'membership.suspend',
  };
  const result = await runOwnerMembershipMutation(frame, async (session, { target }) => {
    if (target.status !== 'ACTIVE' || target.suspendedAt !== null || target.revokedAt !== null) {
      throw new TransactionAbortDomainError(
        'CONFLICT',
        `Cannot suspend membership in status ${target.status}`,
      );
    }
    const suspended = (await MembershipModel.findOneAndUpdate(
      {
        _id: target._id,
        vehicleId: input.vehicleId,
        role: 'MEMBER',
        ...ACTIVE_MEMBERSHIP_CRITERIA,
      },
      {
        $set: {
          status: 'SUSPENDED',
          suspendedAt: frame.now,
          suspendedByUserId: input.actorUserId,
          suspensionReason: reason,
          updatedByUserId: input.actorUserId,
        },
      },
      { returnDocument: 'after', runValidators: true, session },
    ).lean()) as MembershipRecord | null;
    if (!suspended) {
      throw new TransactionAbortDomainError(
        'CONFLICT',
        'Concurrent state change prevented membership suspension',
      );
    }
    const revokedGrantsCount = await revokeMembershipGrants(session, {
      vehicleId: input.vehicleId,
      membershipId: suspended._id,
      actorUserId: input.actorUserId,
      now: frame.now,
      reason: reason ?? 'membership_suspended',
    });
    const revokedInvitationsCount = await revokeIssuedInvitations(session, {
      vehicleId: input.vehicleId,
      membership: suspended,
      actorUserId: input.actorUserId,
      now: frame.now,
    });
    return { membership: suspended, revokedGrantsCount, revokedInvitationsCount };
  });
  auditMembershipSuccess(frame, reason);
  return result;
}

/**
 * OWNER-only SUSPENDED → ACTIVE. Only the current base permissions apply again; AccessGrants
 * and invitations revoked by the suspension stay revoked. REVOKED is terminal.
 */
export async function reactivateMembership(input: {
  vehicleId: Types.ObjectId;
  membershipId: Types.ObjectId;
  actorUserId: Types.ObjectId;
  now?: Date;
  audit?: VehicleAuditLogger;
}): Promise<MembershipRecord> {
  const frame: OwnerMembershipMutationInput = {
    vehicleId: input.vehicleId,
    membershipId: input.membershipId,
    actorUserId: input.actorUserId,
    now: input.now ?? new Date(),
    audit: input.audit ?? defaultAuditLogger,
    action: 'membership.reactivate',
  };
  const reactivated = await runOwnerMembershipMutation(frame, async (session, { target }) => {
    if (target.status !== 'SUSPENDED' || target.revokedAt !== null) {
      throw new TransactionAbortDomainError(
        'CONFLICT',
        `Cannot reactivate membership in status ${target.status}`,
      );
    }
    const updated = (await MembershipModel.findOneAndUpdate(
      {
        _id: target._id,
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
      { returnDocument: 'after', runValidators: true, session },
    ).lean()) as MembershipRecord | null;
    if (!updated) {
      throw new TransactionAbortDomainError(
        'CONFLICT',
        'Concurrent state change prevented membership reactivation',
      );
    }
    return updated;
  });
  auditMembershipSuccess(frame);
  return reactivated;
}

/**
 * OWNER-only revocation of an ACTIVE or SUSPENDED MEMBER membership, revoking its AccessGrants
 * and PENDING issued invitations in the same transaction. Repeating it returns the original
 * revocation without rewriting audit fields or repeating cascades.
 */
export async function revokeMembership(input: {
  vehicleId: Types.ObjectId;
  membershipId: Types.ObjectId;
  actorUserId: Types.ObjectId;
  reason?: string | null;
  now?: Date;
  audit?: VehicleAuditLogger;
}): Promise<MembershipRevocationResult> {
  const reason = validateOptionalAuditReason(input.reason);
  const frame: OwnerMembershipMutationInput = {
    vehicleId: input.vehicleId,
    membershipId: input.membershipId,
    actorUserId: input.actorUserId,
    now: input.now ?? new Date(),
    audit: input.audit ?? defaultAuditLogger,
    action: 'membership.revoke',
  };
  const result = await runOwnerMembershipMutation(
    frame,
    async (session, { target }): Promise<MembershipRevocationResult> => {
      if (target.status === 'REVOKED' || target.revokedAt !== null) {
        return {
          membership: target,
          revokedGrantsCount: 0,
          revokedInvitationsCount: 0,
          alreadyRevoked: true,
        };
      }
      const revoked = (await MembershipModel.findOneAndUpdate(
        {
          _id: target._id,
          vehicleId: input.vehicleId,
          role: 'MEMBER',
          status: { $in: ['ACTIVE', 'SUSPENDED'] },
          revokedAt: null,
        },
        {
          $set: {
            status: 'REVOKED',
            revokedAt: frame.now,
            revokedByUserId: input.actorUserId,
            revokeReason: reason,
            updatedByUserId: input.actorUserId,
          },
        },
        { returnDocument: 'after', runValidators: true, session },
      ).lean()) as MembershipRecord | null;
      if (!revoked) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'Concurrent state change prevented membership revocation',
        );
      }
      const revokedGrantsCount = await revokeMembershipGrants(session, {
        vehicleId: input.vehicleId,
        membershipId: revoked._id,
        actorUserId: input.actorUserId,
        now: frame.now,
        reason: reason ?? 'membership_revoked',
      });
      const revokedInvitationsCount = await revokeIssuedInvitations(session, {
        vehicleId: input.vehicleId,
        membership: revoked,
        actorUserId: input.actorUserId,
        now: frame.now,
      });
      return {
        membership: revoked,
        revokedGrantsCount,
        revokedInvitationsCount,
        alreadyRevoked: false,
      };
    },
  );
  if (!result.alreadyRevoked) {
    auditMembershipSuccess(frame, reason);
  }
  return result;
}

function samePermissionSet(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((permission) => right.includes(permission));
}

/**
 * OWNER-only full replacement of a MEMBER's base permissions (ACTIVE or SUSPENDED). Role,
 * identity, status, and audit fields are not editable. AccessGrants are independent and are
 * not revoked implicitly. PENDING invitations issued by the member that the new set no longer
 * authorizes are revoked in the same transaction.
 */
export async function updateMembershipPermissions(input: {
  vehicleId: Types.ObjectId;
  membershipId: Types.ObjectId;
  actorUserId: Types.ObjectId;
  permissions: string[];
  now?: Date;
  audit?: VehicleAuditLogger;
}): Promise<MembershipPermissionsUpdateResult> {
  if (
    !validatePermissionSet(input.permissions, {
      maxItems: 100,
      allowPermission: isDelegableMembershipPermission,
    })
  ) {
    throw new VehicleServiceError(
      'VALIDATION_ERROR',
      'Membership permissions must be unique, known, non-wildcard, and delegable to MEMBER',
    );
  }
  const permissions = [...input.permissions];
  const frame: OwnerMembershipMutationInput = {
    vehicleId: input.vehicleId,
    membershipId: input.membershipId,
    actorUserId: input.actorUserId,
    now: input.now ?? new Date(),
    audit: input.audit ?? defaultAuditLogger,
    action: 'membership.update',
  };
  const result = await runOwnerMembershipMutation(
    frame,
    async (session, { target }): Promise<MembershipPermissionsUpdateResult> => {
      if (target.status === 'REVOKED' || target.revokedAt !== null) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'Cannot update permissions of a REVOKED membership',
        );
      }
      if (samePermissionSet(target.permissions, permissions)) {
        return { membership: target, changed: false, revokedInvitationsCount: 0 };
      }
      const updated = (await MembershipModel.findOneAndUpdate(
        {
          _id: target._id,
          vehicleId: input.vehicleId,
          role: 'MEMBER',
          status: { $in: ['ACTIVE', 'SUSPENDED'] },
          revokedAt: null,
        },
        { $set: { permissions, updatedByUserId: input.actorUserId } },
        { returnDocument: 'after', runValidators: true, session },
      ).lean()) as MembershipRecord | null;
      if (!updated) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'Concurrent state change prevented the permission update',
        );
      }
      const stillDelegable = holdsInvitationAuthority(permissions)
        ? permissions.filter((permission) => memberDelegableInvitationSet.has(permission))
        : null;
      const revokedInvitationsCount = await revokeIssuedInvitations(session, {
        vehicleId: input.vehicleId,
        membership: updated,
        actorUserId: input.actorUserId,
        now: frame.now,
        extraFilter:
          stillDelegable === null
            ? undefined
            : { permissions: { $elemMatch: { $nin: stillDelegable } } },
      });
      return { membership: updated, changed: true, revokedInvitationsCount };
    },
  );
  if (result.changed) {
    auditMembershipSuccess(frame);
  }
  return result;
}

export interface LeaveVehicleResult {
  membership: MembershipRecord;
  /** True when the targeted membership was already REVOKED; it is returned unchanged. */
  alreadyRevoked: boolean;
  revokedGrantsCount: number;
  revokedInvitationsCount: number;
}

/**
 * Voluntary leave of the caller's own MEMBER membership (ACTIVE or SUSPENDED), always identified
 * explicitly: it must belong to the caller and to the vehicle. Repeating returns it unchanged
 * once REVOKED, and a retried request never resolves to a later membership of the same user.
 * The canonical OWNER cannot leave.
 */
export async function leaveVehicle(input: {
  vehicleId: Types.ObjectId;
  actorUserId: Types.ObjectId;
  membershipId: Types.ObjectId;
  now?: Date;
  audit?: VehicleAuditLogger;
}): Promise<LeaveVehicleResult> {
  const audit = input.audit ?? defaultAuditLogger;
  const now = input.now ?? new Date();
  const notFound = (): VehicleServiceError =>
    new VehicleServiceError('NOT_FOUND', 'Membership not found');
  const ownerCannotLeave = (): VehicleServiceError =>
    new VehicleServiceError('CONFLICT', 'The vehicle owner cannot leave the vehicle');

  const target = (await MembershipModel.findOne({
    _id: input.membershipId,
    vehicleId: input.vehicleId,
    userId: input.actorUserId,
  }).lean()) as MembershipRecord | null;
  if (!target) {
    throw notFound();
  }
  if (target.role === 'OWNER') {
    throw ownerCannotLeave();
  }
  if (target.status === 'REVOKED' || target.revokedAt !== null) {
    return {
      membership: target,
      alreadyRevoked: true,
      revokedGrantsCount: 0,
      revokedInvitationsCount: 0,
    };
  }

  let result: LeaveVehicleResult;
  try {
    result = await runInVehicleTransaction(async (session): Promise<LeaveVehicleResult> => {
      const locked = await lockVerifiedActiveVehicleWithOwner(input.vehicleId, session, {
        now,
        audit,
        actorUserId: input.actorUserId,
      });
      if (!locked) {
        throw new TransactionAbortDomainError('NOT_FOUND', 'Membership not found');
      }
      if (locked.vehicle.ownerUserId.equals(input.actorUserId)) {
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'The vehicle owner cannot leave the vehicle',
        );
      }
      const left = (await MembershipModel.findOneAndUpdate(
        {
          _id: target._id,
          vehicleId: input.vehicleId,
          userId: input.actorUserId,
          role: 'MEMBER',
          status: { $in: ['ACTIVE', 'SUSPENDED'] },
          revokedAt: null,
        },
        {
          $set: {
            status: 'REVOKED',
            revokedAt: now,
            revokedByUserId: input.actorUserId,
            revokeReason: MEMBER_LEFT_REASON,
            updatedByUserId: input.actorUserId,
          },
        },
        { returnDocument: 'after', runValidators: true, session },
      ).lean()) as MembershipRecord | null;
      if (!left) {
        const latest = (await MembershipModel.findOne({ _id: target._id })
          .session(session ?? null)
          .lean()) as MembershipRecord | null;
        if (latest && (latest.status === 'REVOKED' || latest.revokedAt !== null)) {
          return {
            membership: latest,
            alreadyRevoked: true,
            revokedGrantsCount: 0,
            revokedInvitationsCount: 0,
          };
        }
        throw new TransactionAbortDomainError(
          'CONFLICT',
          'Concurrent state change prevented leaving the vehicle',
        );
      }
      const revokedGrantsCount = await revokeMembershipGrants(session, {
        vehicleId: input.vehicleId,
        membershipId: left._id,
        actorUserId: input.actorUserId,
        now,
        reason: MEMBER_LEFT_REASON,
      });
      const revokedInvitationsCount = await revokeIssuedInvitations(session, {
        vehicleId: input.vehicleId,
        membership: left,
        actorUserId: input.actorUserId,
        now,
      });
      return {
        membership: left,
        alreadyRevoked: false,
        revokedGrantsCount,
        revokedInvitationsCount,
      };
    });
  } catch (error) {
    if (error instanceof TransactionAbortDomainError) {
      audit({
        action: 'membership.leave',
        actorUserId: String(input.actorUserId),
        vehicleId: String(input.vehicleId),
        targetId: String(target._id),
        outcome: error.code === 'CONFLICT' ? 'conflict' : 'denied',
        reason: error.message,
      });
      if (error.code === 'REJECT_NULL') {
        throw notFound();
      }
      throw new VehicleServiceError(error.code, error.message);
    }
    throw error;
  }

  if (!result.alreadyRevoked) {
    auditMembershipSuccess(
      {
        vehicleId: input.vehicleId,
        membershipId: result.membership._id,
        actorUserId: input.actorUserId,
        now,
        audit,
        action: 'membership.leave',
      },
      MEMBER_LEFT_REASON,
    );
  }
  return result;
}

// ---------------------------------------------------------------------------
// Keyset listings of invitations and members
// ---------------------------------------------------------------------------

const COLLECTION_CURSOR_VERSION = 1;
const COLLECTION_LIST_KINDS = ['vehicle-invitations', 'received-invitations', 'members'] as const;
type CollectionListKind = (typeof COLLECTION_LIST_KINDS)[number];

const collectionCursorPayloadSchema = z.strictObject({
  v: z.literal(COLLECTION_CURSOR_VERSION),
  k: z.enum(COLLECTION_LIST_KINDS),
  b: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
  c: z.string().max(32),
  i: z.string().regex(/^[a-f0-9]{24}$/),
});

interface CollectionCursorScope {
  kind: CollectionListKind;
  actorUserId: Types.ObjectId;
  /** Listed resource (vehicle id, or `self` for received invitations). */
  resource: string;
  /** Canonical filter description; a cursor is only valid for the same filters. */
  filter: string;
}

interface CollectionListPosition {
  createdAt: Date;
  id: Types.ObjectId;
}

/** Binds a cursor to actor, resource, list kind, and filters. Not a secret. */
function collectionCursorBinding(scope: CollectionCursorScope): string {
  return createHash('sha256')
    .update(
      `pichu:collection-cursor:v${COLLECTION_CURSOR_VERSION}:${scope.kind}:${String(scope.actorUserId)}:${scope.resource}:${scope.filter}`,
    )
    .digest('base64url')
    .slice(0, 22);
}

/**
 * Keyset cursor `(createdAt, _id)` for invitation and member lists. Neither encrypted nor
 * signed and never grants access: authorization is re-evaluated on each page.
 */
function encodeCollectionCursor(
  scope: CollectionCursorScope,
  position: CollectionListPosition,
): string {
  const payload = {
    v: COLLECTION_CURSOR_VERSION,
    k: scope.kind,
    b: collectionCursorBinding(scope),
    c: position.createdAt.toISOString(),
    i: String(position.id),
  };
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
}

function decodeCollectionCursor(
  cursor: string,
  scope: CollectionCursorScope,
): CollectionListPosition {
  const parsed = collectionCursorPayloadSchema.safeParse(decodeCursorJson(cursor));
  if (!parsed.success) {
    throw invalidVehicleCursor();
  }
  const createdAt = decodeCursorTimestamp(parsed.data.c);
  if (parsed.data.k !== scope.kind || parsed.data.b !== collectionCursorBinding(scope)) {
    throw invalidVehicleCursor();
  }
  return { createdAt, id: Types.ObjectId.createFromHexString(parsed.data.i) };
}

function validateCollectionLimit(limit: number | undefined): number {
  const value = limit ?? DEFAULT_VEHICLE_PAGE_LIMIT;
  if (!Number.isInteger(value) || value < 1 || value > MAX_VEHICLE_PAGE_LIMIT) {
    throw new VehicleServiceError('VALIDATION_ERROR', 'Invalid pagination limit');
  }
  return value;
}

function keysetAfter(position: CollectionListPosition | null): Record<string, unknown> {
  return position
    ? {
        $or: [
          { createdAt: { $gt: position.createdAt } },
          { createdAt: position.createdAt, _id: { $gt: position.id } },
        ],
      }
    : {};
}

/** Fetches at most `limit + 1` rows in `(createdAt ASC, _id ASC)` order; read-only. */
async function fetchKeysetPage<TSchema extends { createdAt: Date }>(
  model: Model<TSchema>,
  criteria: QueryFilter<TSchema>[],
  scope: CollectionCursorScope,
  options: { limit?: number; cursor?: string },
): Promise<{ rows: Array<TSchema & { _id: Types.ObjectId }>; nextCursor: string | null }> {
  const limit = validateCollectionLimit(options.limit);
  const position =
    options.cursor === undefined ? null : decodeCollectionCursor(options.cursor, scope);
  const rows = (await model
    .find({ $and: [...criteria, keysetAfter(position)] } as QueryFilter<TSchema>)
    .sort({ createdAt: 1, _id: 1 })
    .limit(limit + 1)
    .lean()) as unknown as Array<TSchema & { _id: Types.ObjectId }>;
  const page = rows.slice(0, limit);
  const last = page[page.length - 1];
  return {
    rows: page,
    nextCursor:
      rows.length > limit && last
        ? encodeCollectionCursor(scope, { createdAt: last.createdAt, id: last._id })
        : null,
  };
}

/** Effective status: an elapsed PENDING invitation is EXPIRED even before it is persisted. */
export function effectiveInvitationStatus(
  invitation: Pick<Invitation, 'status' | 'expiresAt'>,
  now: Date,
): InvitationStatus {
  return invitation.status === 'PENDING' && invitation.expiresAt.getTime() <= now.getTime()
    ? 'EXPIRED'
    : invitation.status;
}

function invitationStatusCriteria(
  status: InvitationStatus | undefined,
  now: Date,
): InvitationFilter {
  switch (status) {
    case undefined:
      return {};
    case 'PENDING':
      return { status: 'PENDING', expiresAt: { $gt: now } };
    case 'EXPIRED':
      return { $or: [{ status: 'EXPIRED' }, { status: 'PENDING', expiresAt: { $lte: now } }] };
    default:
      return { status };
  }
}

function validateInvitationStatusFilter(status: InvitationStatus | undefined): void {
  if (status !== undefined && !INVITATION_STATUSES.includes(status)) {
    throw new VehicleServiceError('VALIDATION_ERROR', 'Invalid status filter');
  }
}

export interface CollectionListOptions<TStatus extends string> {
  limit?: number;
  cursor?: string;
  status?: TStatus;
  now?: Date;
  audit?: VehicleAuditLogger;
}

export interface CollectionPage<TItem> {
  items: TItem[];
  nextCursor: string | null;
}

export interface InvitationListItem {
  invitation: InvitationRecord;
  status: InvitationStatus;
}

export interface ReceivedInvitationListItem extends InvitationListItem {
  vehicleName: string | null;
}

/**
 * Invitations issued for a vehicle. The OWNER sees all of them; an authorized delegate only
 * those issued through their current membership. Without `status`, every state is listed.
 */
export async function listVehicleInvitations(
  vehicleId: Types.ObjectId,
  actorUserId: Types.ObjectId,
  options: CollectionListOptions<InvitationStatus> = {},
): Promise<CollectionPage<InvitationListItem>> {
  const audit = options.audit ?? defaultAuditLogger;
  const now = options.now ?? new Date();
  validateInvitationStatusFilter(options.status);
  validateCollectionLimit(options.limit);

  const issuer = await resolveInvitationIssuer(vehicleId, actorUserId, { now, audit });
  if (issuer.kind === 'NONE') {
    throw new VehicleServiceError('NOT_FOUND', 'Vehicle not found');
  }
  if (issuer.kind === 'VISIBLE_WITHOUT_AUTHORITY') {
    audit({
      action: 'invitation.list',
      actorUserId: String(actorUserId),
      vehicleId: String(vehicleId),
      outcome: 'denied',
      reason: 'insufficient_permissions',
    });
    throw new VehicleServiceError('FORBIDDEN', 'Insufficient permissions to list invitations');
  }

  const scopeCriteria =
    issuer.kind === 'OWNER'
      ? { vehicleId }
      : { vehicleId, issuerMembershipId: issuer.membership._id };
  const { rows, nextCursor } = await fetchKeysetPage(
    InvitationModel,
    [scopeCriteria, invitationStatusCriteria(options.status, now)],
    {
      kind: 'vehicle-invitations',
      actorUserId,
      resource: String(vehicleId),
      filter: options.status ?? 'ALL',
    },
    options,
  );
  return {
    items: rows.map((invitation) => ({
      invitation,
      status: effectiveInvitationStatus(invitation, now),
    })),
    nextCursor,
  };
}

/**
 * The caller's own received invitations; no membership is required. Without `status` only
 * effective PENDING invitations are listed. Vehicle names are resolved in one batch and are
 * withheld (null) for vehicles that are not ACTIVE or not ownership-consistent.
 */
export async function listReceivedInvitations(
  userId: Types.ObjectId,
  options: CollectionListOptions<InvitationStatus> = {},
): Promise<CollectionPage<ReceivedInvitationListItem>> {
  const now = options.now ?? new Date();
  validateInvitationStatusFilter(options.status);
  const status = options.status ?? 'PENDING';
  const { rows, nextCursor } = await fetchKeysetPage(
    InvitationModel,
    [{ inviteeUserId: userId }, invitationStatusCriteria(status, now)],
    { kind: 'received-invitations', actorUserId: userId, resource: 'self', filter: status },
    options,
  );

  const vehicleIds = [
    ...new Map(rows.map((row) => [String(row.vehicleId), row.vehicleId])).values(),
  ];
  const names = new Map<string, string>();
  if (vehicleIds.length > 0) {
    const vehicles = (await VehicleModel.find(
      { _id: { $in: vehicleIds }, status: 'ACTIVE' },
      { name: 1, ownerUserId: 1, status: 1 },
    ).lean()) as VehicleRecord[];
    const ownersByVehicle = await loadOwnerMembershipsByVehicle(
      vehicles.map((vehicle) => vehicle._id),
    );
    for (const vehicle of vehicles) {
      if (isCanonicalOwnershipConsistent(vehicle, ownersByVehicle.get(String(vehicle._id)) ?? [])) {
        names.set(String(vehicle._id), vehicle.name);
      }
    }
  }

  return {
    items: rows.map((invitation) => ({
      invitation,
      status: effectiveInvitationStatus(invitation, now),
      vehicleName: names.get(String(invitation.vehicleId)) ?? null,
    })),
    nextCursor,
  };
}

/**
 * OWNER-only member listing. Defaults to ACTIVE and SUSPENDED; REVOKED history requires an
 * explicit filter.
 */
export async function listVehicleMembers(
  vehicleId: Types.ObjectId,
  actorUserId: Types.ObjectId,
  options: CollectionListOptions<MembershipStatus> = {},
): Promise<CollectionPage<MembershipRecord>> {
  const audit = options.audit ?? defaultAuditLogger;
  const now = options.now ?? new Date();
  if (options.status !== undefined && !MEMBERSHIP_STATUSES.includes(options.status)) {
    throw new VehicleServiceError('VALIDATION_ERROR', 'Invalid status filter');
  }
  validateCollectionLimit(options.limit);

  const relation = await resolveVehicleRelation(vehicleId, actorUserId, { now, audit });
  if (relation.kind !== 'OWNER') {
    if (relation.kind === 'READER') {
      audit({
        action: 'membership.list',
        actorUserId: String(actorUserId),
        vehicleId: String(vehicleId),
        outcome: 'denied',
        reason: 'not_canonical_owner',
      });
      throw new VehicleServiceError(
        'FORBIDDEN',
        'Only the canonical vehicle owner may list members',
      );
    }
    throw new VehicleServiceError('NOT_FOUND', 'Vehicle not found');
  }

  const statusCriteria: QueryFilter<Membership> =
    options.status === undefined
      ? { status: { $in: ['ACTIVE', 'SUSPENDED'] as MembershipStatus[] } }
      : { status: options.status };
  const { rows, nextCursor } = await fetchKeysetPage(
    MembershipModel,
    [{ vehicleId }, statusCriteria],
    {
      kind: 'members',
      actorUserId,
      resource: String(vehicleId),
      filter: options.status ?? 'DEFAULT',
    },
    options,
  );
  return { items: rows, nextCursor };
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

/**
 * Owner-only partial update of descriptive vehicle fields. Authorization is resolved before any
 * write; the transaction then locks the ACTIVE vehicle and its canonical OWNER membership so a
 * concurrent archive either serializes before (→ CONFLICT) or after this update.
 */
export async function updateVehicle(input: {
  vehicleId: Types.ObjectId;
  actorUserId: Types.ObjectId;
  changes: UpdateVehicleInput;
  now?: Date;
  audit?: VehicleAuditLogger;
}): Promise<VehicleRecord> {
  const audit = input.audit ?? defaultAuditLogger;
  const now = input.now ?? new Date();
  const changes = validateUpdateVehicleInput(input.changes);
  const context = {
    action: 'vehicle.update' as const,
    vehicleId: input.vehicleId,
    actorUserId: input.actorUserId,
    audit,
  };

  const relation = await resolveVehicleRelation(input.vehicleId, input.actorUserId, {
    now,
    audit,
  });
  if (relation.kind !== 'OWNER') {
    denyOwnerMutation(relation, context);
  }

  let updated: VehicleRecord;
  try {
    updated = await runInVehicleTransaction(async (session) => {
      const locked = await lockVerifiedActiveVehicle(input.vehicleId, session, {
        now,
        audit,
        actorUserId: input.actorUserId,
      });
      if (!locked || !locked.ownerUserId.equals(input.actorUserId)) {
        throw new TransactionAbortDomainError('REJECT_NULL', 'Vehicle state changed');
      }

      const result = (await VehicleModel.findOneAndUpdate(
        { _id: input.vehicleId, ownerUserId: input.actorUserId, status: 'ACTIVE' },
        { $set: { ...changes, updatedByUserId: input.actorUserId } },
        { returnDocument: 'after', runValidators: true, session },
      ).lean()) as VehicleRecord | null;
      if (!result) {
        throw new TransactionAbortDomainError('REJECT_NULL', 'Vehicle state changed');
      }
      return result;
    });
  } catch (error) {
    if (error instanceof TransactionAbortDomainError && error.code === 'REJECT_NULL') {
      const current = await resolveVehicleRelation(input.vehicleId, input.actorUserId, {
        now,
        audit,
      });
      if (current.kind !== 'OWNER') {
        denyOwnerMutation(current, context);
      }
      throw new VehicleServiceError(
        'CONFLICT',
        'Concurrent state change prevented updating vehicle',
      );
    }
    throw error;
  }

  audit({
    action: 'vehicle.update',
    actorUserId: String(input.actorUserId),
    vehicleId: String(input.vehicleId),
    outcome: 'success',
  });
  return updated;
}

export interface ArchiveVehicleResult {
  vehicle: VehicleRecord;
  /** True when the vehicle was already archived; the original archive record is returned. */
  alreadyArchived: boolean;
}

/**
 * Owner-only logical archive. Idempotent: archiving an already ARCHIVED vehicle returns the
 * original record without overwriting archivedAt, archivedByUserId, or archiveReason.
 * Memberships and history are preserved; within the same transaction, elapsed PENDING
 * invitations and AccessGrants become EXPIRED and the remaining ones are REVOKED.
 */
export async function archiveVehicle(input: {
  vehicleId: Types.ObjectId;
  actorUserId: Types.ObjectId;
  reason?: string | null;
  now?: Date;
  audit?: VehicleAuditLogger;
}): Promise<ArchiveVehicleResult> {
  const audit = input.audit ?? defaultAuditLogger;
  const now = input.now ?? new Date();
  if (typeof input.reason === 'string' && containsControlCharacter(input.reason)) {
    throw new VehicleServiceError('VALIDATION_ERROR', 'Invalid audit reason');
  }
  const reason = validateOptionalAuditReason(input.reason);
  const context = {
    action: 'vehicle.archive' as const,
    vehicleId: input.vehicleId,
    actorUserId: input.actorUserId,
    audit,
  };

  const relation = await resolveVehicleRelation(input.vehicleId, input.actorUserId, {
    now,
    audit,
  });
  if (relation.kind === 'ARCHIVED_OWNER') {
    return { vehicle: relation.vehicle, alreadyArchived: true };
  }
  if (relation.kind !== 'OWNER') {
    denyOwnerMutation(relation, context);
  }

  let archived: VehicleRecord;
  try {
    archived = await runInVehicleTransaction(async (session) => {
      const locked = await lockVerifiedActiveVehicle(input.vehicleId, session, {
        now,
        audit,
        actorUserId: input.actorUserId,
      });
      if (!locked || !locked.ownerUserId.equals(input.actorUserId)) {
        throw new TransactionAbortDomainError('REJECT_NULL', 'Vehicle state changed');
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
      ).lean()) as VehicleRecord | null;

      if (!updatedVehicle) {
        throw new TransactionAbortDomainError('REJECT_NULL', 'Vehicle state changed');
      }

      const cascadeReason = reason ?? 'vehicle_archived';

      await InvitationModel.updateMany(
        { vehicleId: input.vehicleId, status: 'PENDING', expiresAt: { $lte: now } },
        { $set: { status: 'EXPIRED', expiredAt: now } },
        { session },
      );
      await InvitationModel.updateMany(
        { vehicleId: input.vehicleId, status: 'PENDING' },
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
          expiresAt: { $ne: null, $lte: now },
        },
        { $set: { status: 'EXPIRED', expiredAt: now } },
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
  } catch (error) {
    if (error instanceof TransactionAbortDomainError && error.code === 'REJECT_NULL') {
      const current = await resolveVehicleRelation(input.vehicleId, input.actorUserId, {
        now,
        audit,
      });
      if (current.kind === 'ARCHIVED_OWNER') {
        return { vehicle: current.vehicle, alreadyArchived: true };
      }
      if (current.kind !== 'OWNER') {
        denyOwnerMutation(current, context);
      }
      throw new VehicleServiceError(
        'CONFLICT',
        'Concurrent state change prevented archiving vehicle',
      );
    }
    throw error;
  }

  audit({
    action: 'vehicle.archive',
    actorUserId: String(input.actorUserId),
    vehicleId: String(input.vehicleId),
    outcome: 'success',
    reason: reason ?? undefined,
  });
  return { vehicle: archived, alreadyArchived: false };
}
