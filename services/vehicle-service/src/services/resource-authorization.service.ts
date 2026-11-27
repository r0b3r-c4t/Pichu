import mongoose, { type ClientSession, Types } from 'mongoose';
import { AccessGrantModel } from '../models/access-grant.model.js';
import { MembershipModel, type Membership } from '../models/membership.model.js';
import { VehicleModel, type Vehicle } from '../models/vehicle.model.js';
import {
  AUTHORIZATION_RESOURCE_TYPES,
  isIssuableAccessGrantPermission,
  isKnownPermission,
  isOwnerReservedPermission,
  isPermissionApplicableToResource,
  MEMBERSHIP_ROLES,
  type AccessGrantChannel,
  type AuthorizationResourceType,
  type KnownVehiclePermission,
  type MembershipRole,
  type VehicleStatus,
} from '../models/vehicle-constants.js';
import {
  defaultAuditLogger,
  VehicleServiceError,
  type VehicleAuditLogger,
} from './vehicle-errors.js';

/**
 * Resource authorization core of the Vehicle Service, the authority on ownership, memberships,
 * and permissions. Every decision flows through one pipeline:
 *
 *   context validation → external resource evidence → subject resolution (ACTIVE vehicle with
 *   canonical ownership + ACTIVE membership) → `decideMembershipPermission` → effective
 *   AccessGrant lookup (`activeAccessGrantCriteria`).
 *
 * Default deny: anything not explicitly allowed is denied. A decision answers one point in time
 * and is never a lasting authorization; operation-specific policies (owner-only mutations,
 * invitation delegation, ...) stay in their operations and are never replaced by a generic ALLOW.
 */

export type VehicleRecord = Vehicle & { _id: Types.ObjectId };
export type MembershipRecord = Membership & { _id: Types.ObjectId };

// ---------------------------------------------------------------------------
// External resource ownership evidence
// ---------------------------------------------------------------------------

export type ExternalResourceType = Exclude<AuthorizationResourceType, 'VEHICLE'>;

const externalResourceTypes: ReadonlySet<string> = new Set<ExternalResourceType>([
  'DEVICE',
  'MODULE',
]);

const VERIFIED_RESOURCE_BINDING_BRAND: unique symbol = Symbol('VerifiedExternalResourceBinding');

/** Facts captured at issuance; verification never reads the (caller-reachable) public fields. */
interface IssuedBindingFacts {
  readonly scopeType: ExternalResourceType;
  readonly resourceId: string;
  readonly vehicleId: string;
  readonly isActive: boolean;
}
const issuedResourceBindings = new WeakMap<object, IssuedBindingFacts>();

function frozenObjectIdCopy(id: Types.ObjectId): Types.ObjectId {
  return Object.freeze(new Types.ObjectId(id.toHexString()));
}

export interface VerifiedExternalResourceBinding {
  readonly [VERIFIED_RESOURCE_BINDING_BRAND]: true;
  readonly scopeType: ExternalResourceType;
  readonly resourceId: Types.ObjectId;
  readonly vehicleId: Types.ObjectId;
  readonly isActive: boolean;
}

/**
 * Internal construction of ownership evidence for a DEVICE or MODULE. It does NOT verify
 * ownership: the facts must come from the resource's owning service (Device / Automation) over
 * an authenticated internal channel. No such authoritative source exists yet, so no production
 * module calls this factory and DEVICE / MODULE authorization fails closed in production.
 * Only frozen objects issued here are accepted; JSON payloads, copies, and look-alikes never are.
 * Identifiers are copied and frozen, and verification uses the facts captured at issuance, so
 * mutating the caller's ObjectId instances afterwards cannot change the effective evidence.
 */
export function createVerifiedExternalResourceBinding(input: {
  scopeType: ExternalResourceType;
  resourceId: Types.ObjectId;
  vehicleId: Types.ObjectId;
  isActive: boolean;
}): VerifiedExternalResourceBinding {
  if (
    !externalResourceTypes.has(input.scopeType) ||
    !(input.resourceId instanceof Types.ObjectId) ||
    !(input.vehicleId instanceof Types.ObjectId) ||
    typeof input.isActive !== 'boolean'
  ) {
    throw new TypeError('Invalid external resource ownership facts');
  }
  const facts: IssuedBindingFacts = Object.freeze({
    scopeType: input.scopeType,
    resourceId: input.resourceId.toHexString(),
    vehicleId: input.vehicleId.toHexString(),
    isActive: input.isActive,
  });
  const binding: VerifiedExternalResourceBinding = Object.freeze({
    [VERIFIED_RESOURCE_BINDING_BRAND]: true as const,
    scopeType: facts.scopeType,
    resourceId: frozenObjectIdCopy(input.resourceId),
    vehicleId: frozenObjectIdCopy(input.vehicleId),
    isActive: facts.isActive,
  });
  issuedResourceBindings.set(binding, facts);
  return binding;
}

function issuedBindingFacts(value: unknown): IssuedBindingFacts | undefined {
  return typeof value === 'object' && value !== null
    ? issuedResourceBindings.get(value)
    : undefined;
}

/** Evidence must be issued internally, active, and match resource type, resourceId and vehicle. */
export function verifyExternalResourceBinding(
  vehicleId: Types.ObjectId,
  resource: ExternalAuthorizationResource,
): boolean {
  const facts = issuedBindingFacts(resource.binding);
  return (
    facts !== undefined &&
    facts.isActive &&
    facts.scopeType === resource.type &&
    resource.resourceId instanceof Types.ObjectId &&
    vehicleId instanceof Types.ObjectId &&
    facts.resourceId === resource.resourceId.toHexString() &&
    facts.vehicleId === vehicleId.toHexString()
  );
}

// ---------------------------------------------------------------------------
// Context, decisions, and options
// ---------------------------------------------------------------------------

export const AUTHORIZATION_CHANNELS = ['ONLINE', 'BLE_OFFLINE'] as const;
export type AuthorizationChannel = (typeof AUTHORIZATION_CHANNELS)[number];

const authorizationChannels: ReadonlySet<string> = new Set<string>(AUTHORIZATION_CHANNELS);
const authorizationResourceTypes: ReadonlySet<string> = new Set<string>(
  AUTHORIZATION_RESOURCE_TYPES,
);
const membershipRoles: ReadonlySet<string> = new Set<string>(MEMBERSHIP_ROLES);

interface ExternalResourceReference<TType extends ExternalResourceType> {
  readonly type: TType;
  readonly resourceId: Types.ObjectId;
  /** Ownership evidence built from the owning service; never from client input. */
  readonly binding?: VerifiedExternalResourceBinding;
}

export type ExternalAuthorizationResource =
  ExternalResourceReference<'DEVICE'> | ExternalResourceReference<'MODULE'>;

/** VEHICLE always targets the canonical `vehicleId` of the context. */
export type AuthorizationResource = { readonly type: 'VEHICLE' } | ExternalAuthorizationResource;

export interface AuthorizationTarget {
  /** Actor from the verified authentication context; never a client-supplied identifier. */
  readonly actorUserId: Types.ObjectId;
  readonly vehicleId: Types.ObjectId;
  readonly resource: AuthorizationResource;
  readonly channel: AuthorizationChannel;
}

export interface AuthorizationContext extends AuthorizationTarget {
  readonly permission: KnownVehiclePermission;
}

export type AuthorizationDenialReason =
  | 'INVALID_CONTEXT'
  | 'UNKNOWN_OR_INVALID_PERMISSION'
  | 'INVALID_SCOPE'
  | 'PERMISSION_RESOURCE_MISMATCH'
  | 'UNVERIFIED_EXTERNAL_RESOURCE'
  | 'VEHICLE_UNAVAILABLE_OR_INCONSISTENT'
  | 'MEMBERSHIP_INACTIVE_OR_MISSING'
  | 'OWNERSHIP_MISMATCH'
  | 'OWNER_PERMISSION_FORBIDDEN'
  | 'BLE_OWNER_GRANT_REQUIRED'
  | 'PERMISSION_NOT_GRANTED';

export type PermissionDecisionReason = 'ALLOWED' | AuthorizationDenialReason;

export type AuthorizationSource = 'OWNER_ROLE' | 'MEMBERSHIP_PERMISSION' | 'ACCESS_GRANT';

/**
 * INVALID_CONTEXT: malformed request assembled by server code. DENIED: authorization refused.
 * INCONSISTENT_STATE: corrupted persistence detected and failed closed. An unavailable database
 * is never a decision: it raises `DATABASE_UNAVAILABLE`.
 */
export type AuthorizationDenialCategory = 'INVALID_CONTEXT' | 'DENIED' | 'INCONSISTENT_STATE';

export interface AuthorizationAllowed {
  readonly allowed: true;
  readonly reason: 'ALLOWED';
  readonly source: AuthorizationSource;
  readonly membershipId: Types.ObjectId;
  readonly grantId: Types.ObjectId | null;
  readonly evaluatedAt: Date;
}

export interface AuthorizationDenied {
  readonly allowed: false;
  readonly reason: AuthorizationDenialReason;
  readonly category: AuthorizationDenialCategory;
  readonly evaluatedAt: Date;
}

export type AuthorizationDecision = AuthorizationAllowed | AuthorizationDenied;

/** Server-controlled time source; injectable for tests, never fed from client input. */
export type AuthorizationClock = () => Date;

export const systemAuthorizationClock: AuthorizationClock = () => new Date();

export interface AuthorizationOptions {
  /**
   * Propagated to every query of the evaluation. Reads inside a transaction see its snapshot
   * but never act as a write barrier: mutations still need their locks and conditional writes.
   */
  readonly session?: ClientSession;
  readonly clock?: AuthorizationClock;
  readonly audit?: VehicleAuditLogger;
}

export interface AssertPermissionOptions extends AuthorizationOptions {
  /** Audit action recorded on denial. */
  readonly action?: string;
}

const invalidContextReasons: ReadonlySet<AuthorizationDenialReason> = new Set([
  'INVALID_CONTEXT',
  'UNKNOWN_OR_INVALID_PERMISSION',
  'INVALID_SCOPE',
  'PERMISSION_RESOURCE_MISMATCH',
]);

function denialCategory(reason: AuthorizationDenialReason): AuthorizationDenialCategory {
  if (invalidContextReasons.has(reason)) {
    return 'INVALID_CONTEXT';
  }
  return reason === 'OWNERSHIP_MISMATCH' ? 'INCONSISTENT_STATE' : 'DENIED';
}

function deny(
  reason: AuthorizationDenialReason,
  evaluatedAt: Date,
  category: AuthorizationDenialCategory = denialCategory(reason),
): AuthorizationDenied {
  return { allowed: false, reason, category, evaluatedAt };
}

function allow(
  source: AuthorizationSource,
  membershipId: Types.ObjectId,
  grantId: Types.ObjectId | null,
  evaluatedAt: Date,
): AuthorizationAllowed {
  return { allowed: true, reason: 'ALLOWED', source, membershipId, grantId, evaluatedAt };
}

/** Single time reference per evaluation, copied so later clock changes cannot affect it. */
export function captureEvaluationTime(clock: AuthorizationClock = systemAuthorizationClock): Date {
  const value: unknown = clock();
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    throw new TypeError('Authorization clock returned an invalid date');
  }
  return new Date(value.getTime());
}

/**
 * Runtime validation of a target and its candidate permissions, independent of static types.
 * Returns the first denial reason, or null when the context is well-formed.
 */
export function validateAuthorizationTarget(
  target: AuthorizationTarget,
  permissions: readonly string[],
): AuthorizationDenialReason | null {
  if (
    !(target.actorUserId instanceof Types.ObjectId) ||
    !(target.vehicleId instanceof Types.ObjectId) ||
    !authorizationChannels.has(target.channel)
  ) {
    return 'INVALID_CONTEXT';
  }
  if (
    permissions.length === 0 ||
    !permissions.every((permission) => isKnownPermission(permission))
  ) {
    return 'UNKNOWN_OR_INVALID_PERMISSION';
  }
  const resource: unknown = target.resource;
  if (
    typeof resource !== 'object' ||
    resource === null ||
    !('type' in resource) ||
    typeof resource.type !== 'string' ||
    !authorizationResourceTypes.has(resource.type)
  ) {
    return 'INVALID_SCOPE';
  }
  const resourceId = 'resourceId' in resource ? resource.resourceId : undefined;
  if (resource.type === 'VEHICLE') {
    if (resourceId !== undefined && resourceId !== null) {
      return 'INVALID_SCOPE';
    }
  } else if (!(resourceId instanceof Types.ObjectId)) {
    return 'INVALID_SCOPE';
  }
  if (
    !permissions.every((permission) =>
      isPermissionApplicableToResource(target.resource.type, permission),
    )
  ) {
    return 'PERMISSION_RESOURCE_MISMATCH';
  }
  return null;
}

// ---------------------------------------------------------------------------
// Pure decision core
// ---------------------------------------------------------------------------

export const ACTIVE_MEMBERSHIP_CRITERIA = {
  status: 'ACTIVE',
  suspendedAt: null,
  revokedAt: null,
} as const;

/**
 * Canonical ownership invariant: Vehicle.ownerUserId MUST match exactly one ACTIVE,
 * unrevoked, unsuspended OWNER Membership. `ownerMemberships` must contain every unrevoked
 * OWNER membership of the vehicle.
 */
export function isCanonicalOwnershipConsistent(
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

export interface AuthorizationSubject {
  readonly role: MembershipRole;
  readonly vehicle: VehicleRecord;
  readonly membership: MembershipRecord;
}

export type SubjectResolution =
  | { readonly resolved: true; readonly subject: AuthorizationSubject }
  | {
      readonly resolved: false;
      readonly reason: AuthorizationDenialReason;
      readonly category: AuthorizationDenialCategory;
    };

function unresolved(
  reason: AuthorizationDenialReason,
  category: AuthorizationDenialCategory = denialCategory(reason),
): SubjectResolution {
  return { resolved: false, reason, category };
}

/**
 * Exact role of an actor over an ownership-verified vehicle. OWNER requires the canonical owner
 * with the OWNER membership; MEMBER requires a non-owner with a MEMBER membership. Any other
 * combination is corrupted state and fails closed.
 */
export function classifySubject(
  vehicle: VehicleRecord,
  membership: MembershipRecord | null,
  actorUserId: Types.ObjectId,
): SubjectResolution {
  if (vehicle.status !== 'ACTIVE') {
    return unresolved('VEHICLE_UNAVAILABLE_OR_INCONSISTENT', 'DENIED');
  }
  if (
    !membership ||
    membership.status !== 'ACTIVE' ||
    membership.suspendedAt !== null ||
    membership.revokedAt !== null
  ) {
    return unresolved('MEMBERSHIP_INACTIVE_OR_MISSING');
  }
  if (!membership.vehicleId.equals(vehicle._id) || !membership.userId.equals(actorUserId)) {
    return unresolved('MEMBERSHIP_INACTIVE_OR_MISSING', 'INCONSISTENT_STATE');
  }
  const isCanonicalOwner = vehicle.ownerUserId.equals(actorUserId);
  if (membership.role === 'OWNER' && isCanonicalOwner) {
    return { resolved: true, subject: { role: 'OWNER', vehicle, membership } };
  }
  if (membership.role === 'MEMBER' && !isCanonicalOwner) {
    return { resolved: true, subject: { role: 'MEMBER', vehicle, membership } };
  }
  return unresolved('OWNERSHIP_MISMATCH');
}

export interface PermissionRequest {
  readonly permission: KnownVehiclePermission;
  readonly resourceType: AuthorizationResourceType;
  readonly channel: AuthorizationChannel;
}

export type MembershipPermissionDecision =
  | { readonly kind: 'ALLOWED'; readonly source: 'OWNER_ROLE' | 'MEMBERSHIP_PERMISSION' }
  | { readonly kind: 'DENIED'; readonly reason: AuthorizationDenialReason }
  | { readonly kind: 'ACCESS_GRANT_REQUIRED' };

/**
 * Single source of truth for role and base-permission authorization of a resolved subject.
 * OWNER: every evaluable permission ONLINE; BLE_OFFLINE is provisionally denied. MEMBER: never
 * owner-reserved permissions; base permissions apply ONLINE to compatible resources; otherwise
 * only a current AccessGrant (looked up with `activeAccessGrantCriteria`) can still authorize.
 */
export function decideMembershipPermission(
  subject: AuthorizationSubject,
  request: PermissionRequest,
): MembershipPermissionDecision {
  if (!isPermissionApplicableToResource(request.resourceType, request.permission)) {
    return { kind: 'DENIED', reason: 'PERMISSION_RESOURCE_MISMATCH' };
  }
  if (subject.role === 'OWNER') {
    return request.channel === 'BLE_OFFLINE'
      ? { kind: 'DENIED', reason: 'BLE_OWNER_GRANT_REQUIRED' }
      : { kind: 'ALLOWED', source: 'OWNER_ROLE' };
  }
  if (isOwnerReservedPermission(request.permission)) {
    return { kind: 'DENIED', reason: 'OWNER_PERMISSION_FORBIDDEN' };
  }
  if (request.channel === 'ONLINE' && subject.membership.permissions.includes(request.permission)) {
    return { kind: 'ALLOWED', source: 'MEMBERSHIP_PERMISSION' };
  }
  if (!isIssuableAccessGrantPermission(request.resourceType, request.permission)) {
    return { kind: 'DENIED', reason: 'PERMISSION_NOT_GRANTED' };
  }
  return { kind: 'ACCESS_GRANT_REQUIRED' };
}

export interface EffectiveGrantRequest {
  readonly subjectUserId: Types.ObjectId;
  readonly resource: AuthorizationResource;
  readonly channel: AuthorizationChannel;
  readonly permissions: readonly KnownVehiclePermission[];
}

/**
 * AccessGrant filter shared by single, batched, and prefiltered evaluation (vehicle and
 * membership keys are added by the caller): exact subject, scope and resource, compatible
 * channel, ACTIVE without terminal markers, inclusive start, exclusive expiry. Grants without
 * expiry only count on the ONLINE channel, matching the model invariant for BLE_OFFLINE / ANY.
 */
export function activeAccessGrantCriteria(request: EffectiveGrantRequest, now: Date) {
  const allowedChannels: AccessGrantChannel[] =
    request.channel === 'BLE_OFFLINE' ? ['BLE_OFFLINE', 'ANY'] : ['ONLINE', 'ANY'];
  return {
    subjectUserId: request.subjectUserId,
    scopeType: request.resource.type,
    scopeResourceId: request.resource.type === 'VEHICLE' ? null : request.resource.resourceId,
    channel: { $in: allowedChannels },
    status: 'ACTIVE' as const,
    revokedAt: null,
    expiredAt: null,
    startsAt: { $lte: now },
    $or: [{ expiresAt: { $gt: now } }, { expiresAt: null, channel: 'ONLINE' as const }],
    permissions: { $in: [...request.permissions] },
  };
}

/**
 * Effective online read access to a vehicle: canonical OWNER, or MEMBER holding
 * `vehicle:read` / `vehicle:manage` directly, or a current VEHICLE-scoped ONLINE/ANY
 * AccessGrant with `vehicle:read` bound to the current membership. DEVICE, MODULE, and
 * BLE_OFFLINE grants never confer vehicle read access.
 */
export const VEHICLE_READ_PERMISSIONS = [
  'vehicle:read',
  'vehicle:manage',
] as const satisfies readonly KnownVehiclePermission[];

// ---------------------------------------------------------------------------
// Persistence port and its MongoDB implementation
// ---------------------------------------------------------------------------

export interface GrantBindingKey {
  readonly vehicleId: Types.ObjectId;
  readonly membershipId: Types.ObjectId;
}

export interface AuthorizationPersistence {
  findVehicle(
    vehicleId: Types.ObjectId,
    status: VehicleStatus | undefined,
    session: ClientSession | undefined,
  ): Promise<VehicleRecord | null>;
  findUnrevokedOwnerMemberships(
    vehicleIds: readonly Types.ObjectId[],
    session: ClientSession | undefined,
  ): Promise<MembershipRecord[]>;
  findActiveMembership(
    vehicleId: Types.ObjectId,
    userId: Types.ObjectId,
    session: ClientSession | undefined,
  ): Promise<MembershipRecord | null>;
  findEffectiveGrantId(
    key: GrantBindingKey,
    request: EffectiveGrantRequest,
    now: Date,
    session: ClientSession | undefined,
  ): Promise<Types.ObjectId | null>;
  findEffectiveGrantKeys(
    keys: readonly GrantBindingKey[],
    request: EffectiveGrantRequest,
    now: Date,
    session: ClientSession | undefined,
  ): Promise<GrantBindingKey[]>;
}

/** Connectivity failures of MongoDB, as opposed to programming or validation errors. */
export function isDatabaseUnavailableError(error: unknown): boolean {
  return (
    error instanceof mongoose.mongo.MongoNetworkError ||
    error instanceof mongoose.mongo.MongoServerSelectionError ||
    error instanceof mongoose.mongo.MongoNotConnectedError ||
    error instanceof mongoose.mongo.MongoTopologyClosedError ||
    error instanceof mongoose.mongo.MongoServerClosedError ||
    error instanceof mongoose.Error.MongooseServerSelectionError
  );
}

export function databaseUnavailableError(cause?: unknown): VehicleServiceError {
  return new VehicleServiceError(
    'DATABASE_UNAVAILABLE',
    'Vehicle database unavailable',
    cause === undefined ? undefined : { cause },
  );
}

async function guardedRead<T>(
  session: ClientSession | undefined,
  read: () => Promise<T>,
): Promise<T> {
  if (mongoose.connection.readyState !== 1) {
    throw databaseUnavailableError();
  }
  try {
    return await read();
  } catch (error) {
    // Inside a transaction the driver error must reach withTransaction untouched (retry labels).
    if (session === undefined && isDatabaseUnavailableError(error)) {
      throw databaseUnavailableError(error);
    }
    throw error;
  }
}

export const mongoAuthorizationPersistence: AuthorizationPersistence = {
  findVehicle: (vehicleId, status, session) =>
    guardedRead(
      session,
      async () =>
        (await VehicleModel.findOne({ _id: vehicleId, ...(status ? { status } : {}) })
          .session(session ?? null)
          .lean()) as VehicleRecord | null,
    ),
  findUnrevokedOwnerMemberships: (vehicleIds, session) =>
    guardedRead(
      session,
      async () =>
        (await MembershipModel.find({
          vehicleId: { $in: [...vehicleIds] },
          role: 'OWNER',
          revokedAt: null,
        })
          .session(session ?? null)
          .lean()) as MembershipRecord[],
    ),
  findActiveMembership: (vehicleId, userId, session) =>
    guardedRead(
      session,
      async () =>
        (await MembershipModel.findOne({ vehicleId, userId, ...ACTIVE_MEMBERSHIP_CRITERIA })
          .session(session ?? null)
          .lean()) as MembershipRecord | null,
    ),
  findEffectiveGrantId: (key, request, now, session) =>
    guardedRead(session, async () => {
      const grant = (await AccessGrantModel.findOne(
        {
          vehicleId: key.vehicleId,
          membershipId: key.membershipId,
          ...activeAccessGrantCriteria(request, now),
        },
        { _id: 1 },
      )
        .session(session ?? null)
        .lean()) as { _id: Types.ObjectId } | null;
      return grant?._id ?? null;
    }),
  findEffectiveGrantKeys: (keys, request, now, session) =>
    guardedRead(
      session,
      async () =>
        (await AccessGrantModel.find(
          {
            vehicleId: { $in: keys.map((key) => key.vehicleId) },
            membershipId: { $in: keys.map((key) => key.membershipId) },
            ...activeAccessGrantCriteria(request, now),
          },
          { vehicleId: 1, membershipId: 1 },
        )
          .session(session ?? null)
          .lean()) as GrantBindingKey[],
    ),
};

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export interface VehicleAccessCandidate {
  vehicle: VehicleRecord;
  membership: MembershipRecord;
}

export interface VerifiedVehicleLoadOptions {
  status?: VehicleStatus;
  session?: ClientSession;
  audit?: VehicleAuditLogger;
  actorUserId?: Types.ObjectId;
}

export type SubjectOptions = Pick<AuthorizationOptions, 'session' | 'audit'>;

export interface ResourceAuthorizationService {
  /** Full decision for one permission on one resource. */
  evaluate(
    context: AuthorizationContext,
    options?: AuthorizationOptions,
  ): Promise<AuthorizationDecision>;
  /** Allowed when any candidate permission is allowed; one subject resolution, one grant query. */
  evaluateAnyOf(
    target: AuthorizationTarget,
    permissions: readonly KnownVehiclePermission[],
    options?: AuthorizationOptions,
  ): Promise<AuthorizationDecision>;
  hasPermission(context: AuthorizationContext, options?: AuthorizationOptions): Promise<boolean>;
  /**
   * Returns the ALLOW decision or throws: VALIDATION_ERROR for an invalid context, FORBIDDEN when
   * the actor can read the vehicle, NOT_FOUND otherwise, DATABASE_UNAVAILABLE on outages.
   */
  assertPermission(
    context: AuthorizationContext,
    options?: AssertPermissionOptions,
  ): Promise<AuthorizationAllowed>;
  resolveSubject(
    vehicleId: Types.ObjectId,
    actorUserId: Types.ObjectId,
    options?: SubjectOptions,
  ): Promise<SubjectResolution>;
  /** Canonical OWNER with a consistent ACTIVE OWNER membership on an ACTIVE vehicle. */
  isOwner(
    vehicleId: Types.ObjectId,
    actorUserId: Types.ObjectId,
    options?: SubjectOptions,
  ): Promise<boolean>;
  /**
   * Holder of a consistent ACTIVE membership on an ACTIVE vehicle, of any role: the canonical
   * OWNER is a member. Use `hasRole` to distinguish OWNER from MEMBER.
   */
  isMember(
    vehicleId: Types.ObjectId,
    actorUserId: Types.ObjectId,
    options?: SubjectOptions,
  ): Promise<boolean>;
  /** Exact role match; an invalid role is never matched. */
  hasRole(
    vehicleId: Types.ObjectId,
    actorUserId: Types.ObjectId,
    role: MembershipRole,
    options?: SubjectOptions,
  ): Promise<boolean>;
  /** TKT-011 read semantics (see `VEHICLE_READ_PERMISSIONS`). */
  hasVehicleReadAccess(
    vehicleId: Types.ObjectId,
    actorUserId: Types.ObjectId,
    options?: AuthorizationOptions,
  ): Promise<boolean>;
  /**
   * Batched read authorization over ownership-consistent candidates with the same core rules,
   * at most one AccessGrant query per grantable read permission. Input order is preserved.
   */
  filterReadableCandidates(
    actorUserId: Types.ObjectId,
    candidates: readonly VehicleAccessCandidate[],
    options: { now: Date; session?: ClientSession },
  ): Promise<VehicleAccessCandidate[]>;
  /** Vehicle in the requested lifecycle state with canonical ownership; null otherwise. */
  loadVerifiedVehicle(
    vehicleId: Types.ObjectId,
    options?: VerifiedVehicleLoadOptions,
  ): Promise<VehicleRecord | null>;
  loadOwnerMembershipsByVehicle(
    vehicleIds: readonly Types.ObjectId[],
    session?: ClientSession,
  ): Promise<Map<string, MembershipRecord[]>>;
  findActiveMembership(
    vehicleId: Types.ObjectId,
    userId: Types.ObjectId,
    session?: ClientSession,
  ): Promise<MembershipRecord | null>;
}

export function auditOwnershipInconsistency(
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

type VerifiedVehicleLookup =
  { kind: 'VERIFIED'; vehicle: VehicleRecord } | { kind: 'MISSING' } | { kind: 'INCONSISTENT' };

/**
 * Evaluations issue sequential queries (never in parallel, as required inside MongoDB
 * transactions). Without a session they are independent reads, not one consistent snapshot.
 */
export function createResourceAuthorizationService(
  persistence: AuthorizationPersistence,
): ResourceAuthorizationService {
  async function loadOwnerMembershipsByVehicle(
    vehicleIds: readonly Types.ObjectId[],
    session?: ClientSession,
  ): Promise<Map<string, MembershipRecord[]>> {
    const ownersByVehicle = new Map<string, MembershipRecord[]>();
    if (vehicleIds.length === 0) {
      return ownersByVehicle;
    }
    for (const owner of await persistence.findUnrevokedOwnerMemberships(vehicleIds, session)) {
      const key = String(owner.vehicleId);
      const group = ownersByVehicle.get(key) ?? [];
      group.push(owner);
      ownersByVehicle.set(key, group);
    }
    return ownersByVehicle;
  }

  async function lookupVerifiedVehicle(
    vehicleId: Types.ObjectId,
    options: VerifiedVehicleLoadOptions,
  ): Promise<VerifiedVehicleLookup> {
    const vehicle = await persistence.findVehicle(vehicleId, options.status, options.session);
    if (!vehicle) {
      return { kind: 'MISSING' };
    }
    const owners =
      (await loadOwnerMembershipsByVehicle([vehicleId], options.session)).get(String(vehicleId)) ??
      [];
    if (!isCanonicalOwnershipConsistent(vehicle, owners)) {
      auditOwnershipInconsistency(
        options.audit ?? defaultAuditLogger,
        vehicleId,
        options.actorUserId,
      );
      return { kind: 'INCONSISTENT' };
    }
    return { kind: 'VERIFIED', vehicle };
  }

  async function resolveSubject(
    vehicleId: Types.ObjectId,
    actorUserId: Types.ObjectId,
    options: SubjectOptions = {},
  ): Promise<SubjectResolution> {
    if (!(vehicleId instanceof Types.ObjectId) || !(actorUserId instanceof Types.ObjectId)) {
      return unresolved('INVALID_CONTEXT');
    }
    const lookup = await lookupVerifiedVehicle(vehicleId, {
      status: 'ACTIVE',
      session: options.session,
      audit: options.audit,
      actorUserId,
    });
    if (lookup.kind !== 'VERIFIED') {
      return unresolved(
        'VEHICLE_UNAVAILABLE_OR_INCONSISTENT',
        lookup.kind === 'INCONSISTENT' ? 'INCONSISTENT_STATE' : 'DENIED',
      );
    }
    const membership = await persistence.findActiveMembership(
      vehicleId,
      actorUserId,
      options.session,
    );
    return classifySubject(lookup.vehicle, membership, actorUserId);
  }

  async function evaluateWithSubject(
    target: AuthorizationTarget,
    permissions: readonly KnownVehiclePermission[],
    evaluatedAt: Date,
    options: AuthorizationOptions,
  ): Promise<{ decision: AuthorizationDecision; subject: AuthorizationSubject | null }> {
    const invalid = validateAuthorizationTarget(target, permissions);
    if (invalid) {
      return { decision: deny(invalid, evaluatedAt), subject: null };
    }
    const resource = target.resource;
    if (resource.type !== 'VEHICLE' && !verifyExternalResourceBinding(target.vehicleId, resource)) {
      return { decision: deny('UNVERIFIED_EXTERNAL_RESOURCE', evaluatedAt), subject: null };
    }

    const resolution = await resolveSubject(target.vehicleId, target.actorUserId, options);
    if (!resolution.resolved) {
      return {
        decision: deny(resolution.reason, evaluatedAt, resolution.category),
        subject: null,
      };
    }
    const { subject } = resolution;

    let denial: AuthorizationDenialReason | null = null;
    const grantCandidates: KnownVehiclePermission[] = [];
    for (const permission of permissions) {
      const decision = decideMembershipPermission(subject, {
        permission,
        resourceType: resource.type,
        channel: target.channel,
      });
      if (decision.kind === 'ALLOWED') {
        return {
          decision: allow(decision.source, subject.membership._id, null, evaluatedAt),
          subject,
        };
      }
      if (decision.kind === 'DENIED') {
        denial ??= decision.reason;
      } else {
        grantCandidates.push(permission);
      }
    }

    if (grantCandidates.length > 0) {
      const grantId = await persistence.findEffectiveGrantId(
        { vehicleId: subject.vehicle._id, membershipId: subject.membership._id },
        {
          subjectUserId: target.actorUserId,
          resource,
          channel: target.channel,
          permissions: grantCandidates,
        },
        evaluatedAt,
        options.session,
      );
      if (grantId) {
        return {
          decision: allow('ACCESS_GRANT', subject.membership._id, grantId, evaluatedAt),
          subject,
        };
      }
    }
    return { decision: deny(denial ?? 'PERMISSION_NOT_GRANTED', evaluatedAt), subject };
  }

  async function evaluateAnyOf(
    target: AuthorizationTarget,
    permissions: readonly KnownVehiclePermission[],
    options: AuthorizationOptions = {},
  ): Promise<AuthorizationDecision> {
    const evaluatedAt = captureEvaluationTime(options.clock);
    return (await evaluateWithSubject(target, permissions, evaluatedAt, options)).decision;
  }

  async function evaluate(
    context: AuthorizationContext,
    options: AuthorizationOptions = {},
  ): Promise<AuthorizationDecision> {
    return evaluateAnyOf(context, [context.permission], options);
  }

  async function filterReadableCandidates(
    actorUserId: Types.ObjectId,
    candidates: readonly VehicleAccessCandidate[],
    options: { now: Date; session?: ClientSession },
  ): Promise<VehicleAccessCandidate[]> {
    const readable = new Set<VehicleAccessCandidate>();
    const pendingByPermission = new Map<KnownVehiclePermission, VehicleAccessCandidate[]>();

    for (const candidate of candidates) {
      const resolution = classifySubject(candidate.vehicle, candidate.membership, actorUserId);
      if (!resolution.resolved) {
        continue;
      }
      for (const permission of VEHICLE_READ_PERMISSIONS) {
        const decision = decideMembershipPermission(resolution.subject, {
          permission,
          resourceType: 'VEHICLE',
          channel: 'ONLINE',
        });
        if (decision.kind === 'ALLOWED') {
          readable.add(candidate);
          break;
        }
        if (decision.kind === 'ACCESS_GRANT_REQUIRED') {
          const pending = pendingByPermission.get(permission) ?? [];
          pending.push(candidate);
          pendingByPermission.set(permission, pending);
        }
      }
    }

    for (const [permission, pending] of pendingByPermission) {
      const unresolvedCandidates = pending.filter((candidate) => !readable.has(candidate));
      if (unresolvedCandidates.length === 0) {
        continue;
      }
      const grants = await persistence.findEffectiveGrantKeys(
        unresolvedCandidates.map((candidate) => ({
          vehicleId: candidate.vehicle._id,
          membershipId: candidate.membership._id,
        })),
        {
          subjectUserId: actorUserId,
          resource: { type: 'VEHICLE' },
          channel: 'ONLINE',
          permissions: [permission],
        },
        options.now,
        options.session,
      );
      const grantKeys = new Set(
        grants.map((grant) => `${String(grant.vehicleId)}:${String(grant.membershipId)}`),
      );
      for (const candidate of unresolvedCandidates) {
        if (grantKeys.has(`${String(candidate.vehicle._id)}:${String(candidate.membership._id)}`)) {
          readable.add(candidate);
        }
      }
    }

    return candidates.filter((candidate) => readable.has(candidate));
  }

  async function isSubjectReadable(
    actorUserId: Types.ObjectId,
    subject: AuthorizationSubject,
    now: Date,
    session: ClientSession | undefined,
  ): Promise<boolean> {
    const readable = await filterReadableCandidates(
      actorUserId,
      [{ vehicle: subject.vehicle, membership: subject.membership }],
      { now, session },
    );
    return readable.length === 1;
  }

  async function hasRole(
    vehicleId: Types.ObjectId,
    actorUserId: Types.ObjectId,
    role: MembershipRole,
    options: SubjectOptions = {},
  ): Promise<boolean> {
    if (!membershipRoles.has(role)) {
      return false;
    }
    const resolution = await resolveSubject(vehicleId, actorUserId, options);
    return resolution.resolved && resolution.subject.role === role;
  }

  return {
    evaluate,
    evaluateAnyOf,
    async hasPermission(context, options) {
      return (await evaluate(context, options)).allowed;
    },
    async assertPermission(context, options = {}) {
      const evaluatedAt = captureEvaluationTime(options.clock);
      const { decision, subject } = await evaluateWithSubject(
        context,
        [context.permission],
        evaluatedAt,
        options,
      );
      if (decision.allowed) {
        return decision;
      }
      (options.audit ?? defaultAuditLogger)({
        action: options.action ?? 'authorization.assert',
        actorUserId: String(context.actorUserId),
        vehicleId: String(context.vehicleId),
        outcome: 'denied',
        reason: decision.reason.toLowerCase(),
      });
      if (decision.category === 'INVALID_CONTEXT') {
        throw new VehicleServiceError('VALIDATION_ERROR', 'Invalid authorization request');
      }
      if (
        subject &&
        (await isSubjectReadable(context.actorUserId, subject, evaluatedAt, options.session))
      ) {
        throw new VehicleServiceError('FORBIDDEN', 'Insufficient permissions');
      }
      throw new VehicleServiceError('NOT_FOUND', 'Vehicle not found');
    },
    resolveSubject,
    isOwner: (vehicleId, actorUserId, options) => hasRole(vehicleId, actorUserId, 'OWNER', options),
    async isMember(vehicleId, actorUserId, options) {
      return (await resolveSubject(vehicleId, actorUserId, options)).resolved;
    },
    hasRole,
    async hasVehicleReadAccess(vehicleId, actorUserId, options = {}) {
      const now = captureEvaluationTime(options.clock);
      const resolution = await resolveSubject(vehicleId, actorUserId, options);
      return (
        resolution.resolved &&
        (await isSubjectReadable(actorUserId, resolution.subject, now, options.session))
      );
    },
    filterReadableCandidates,
    async loadVerifiedVehicle(vehicleId, options = {}) {
      const lookup = await lookupVerifiedVehicle(vehicleId, options);
      return lookup.kind === 'VERIFIED' ? lookup.vehicle : null;
    },
    loadOwnerMembershipsByVehicle,
    findActiveMembership: (vehicleId, userId, session) =>
      persistence.findActiveMembership(vehicleId, userId, session),
  };
}

export const resourceAuthorization: ResourceAuthorizationService =
  createResourceAuthorizationService(mongoAuthorizationPersistence);
