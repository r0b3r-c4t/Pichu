import { createHash } from 'node:crypto';
import mongoose, { type ClientSession, type Model, type PipelineStage, Types } from 'mongoose';
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
  isAccessGrantPermissionForScope,
  isDelegableMembershipPermission,
  isKnownPermission,
  isOwnerReservedPermission,
  normalizeOptionalText,
  MEMBERSHIP_ROLES,
  validatePermissionSet,
  type AccessGrantChannel,
  type AccessGrantScopeType,
  type MembershipRole,
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

  const ownerMemberships =
    (await loadOwnerMembershipsByVehicle([vehicleId], session)).get(String(vehicleId)) ?? [];
  const ownerRecord = ownerMemberships[0];
  if (!ownerRecord || !isCanonicalOwnershipConsistent(lockedVehicle, ownerMemberships)) {
    auditOwnershipInconsistency(audit, vehicleId, options.actorUserId);
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

function decodeVehicleListCursor(
  cursor: string,
  userId: Types.ObjectId,
  role: VehicleListRoleFilter,
): VehicleListPosition {
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
  let decoded: unknown;
  try {
    decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw invalidVehicleCursor();
  }
  const parsed = vehicleListCursorPayloadSchema.safeParse(decoded);
  if (!parsed.success) {
    throw invalidVehicleCursor();
  }
  const createdAt = new Date(parsed.data.c);
  if (Number.isNaN(createdAt.getTime()) || createdAt.toISOString() !== parsed.data.c) {
    throw invalidVehicleCursor();
  }
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

type OwnerMutationAction = 'vehicle.update' | 'vehicle.archive';

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

/**
 * Read-only invitation authorization mirroring the in-transaction check of `inviteMember`:
 * the canonical OWNER, or an ACTIVE MEMBER holding `vehicle:manage` or `invitation:create`.
 */
async function authorizeInvitationIssuer(
  vehicleId: Types.ObjectId,
  inviterUserId: Types.ObjectId,
  audit: VehicleAuditLogger,
): Promise<'ALLOWED' | 'DENIED' | 'VEHICLE_UNAVAILABLE'> {
  const vehicle = await loadVerifiedActiveVehicle(vehicleId, {
    audit,
    actorUserId: inviterUserId,
  });
  if (!vehicle) {
    return 'VEHICLE_UNAVAILABLE';
  }
  if (vehicle.ownerUserId.equals(inviterUserId)) {
    return 'ALLOWED';
  }
  const membership = (await MembershipModel.findOne({
    vehicleId,
    userId: inviterUserId,
    role: 'MEMBER',
    ...ACTIVE_MEMBERSHIP_CRITERIA,
  }).lean()) as MembershipRecord | null;
  return membership !== null &&
    (membership.permissions.includes('vehicle:manage') ||
      membership.permissions.includes('invitation:create'))
    ? 'ALLOWED'
    : 'DENIED';
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

  const preAuthorization = await authorizeInvitationIssuer(vehicleId, inviterUserId, audit);
  if (preAuthorization !== 'ALLOWED') {
    if (preAuthorization === 'DENIED') {
      audit({
        action: 'invitation.create',
        actorUserId: String(inviterUserId),
        vehicleId: String(vehicleId),
        targetId: String(inviteeUserId),
        outcome: 'denied',
        reason: 'insufficient_permissions',
      });
    }
    return null;
  }

  // Persist transition of any elapsed PENDING invitations BEFORE starting an abortable
  // transaction so EXPIRED history is preserved even if domain validation/conflicts fail.
  // Only reached by authorized issuers; the transaction re-checks authorization under lock.
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
