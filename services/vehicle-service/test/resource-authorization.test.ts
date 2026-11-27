import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import mongoose, { type ClientSession, Types } from 'mongoose';
import type { AccessGrant } from '../src/models/access-grant.model.js';
import {
  ACCESS_GRANT_DEVICE_PERMISSIONS,
  ACCESS_GRANT_MODULE_PERMISSIONS,
  ACCESS_GRANT_VEHICLE_PERMISSIONS,
  ALL_KNOWN_PERMISSIONS,
  AUTHORIZATION_RESOURCE_TYPES,
  EVALUABLE_PERMISSIONS_BY_RESOURCE,
  isAccessGrantPermissionForScope,
  isIssuableAccessGrantPermission,
  isOwnerReservedPermission,
  isPermissionApplicableToResource,
  OWNER_RESERVED_PERMISSIONS,
  type AuthorizationResourceType,
  type KnownVehiclePermission,
} from '../src/models/vehicle-constants.js';
import {
  activeAccessGrantCriteria,
  captureEvaluationTime,
  classifySubject,
  createResourceAuthorizationService,
  createVerifiedExternalResourceBinding,
  decideMembershipPermission,
  isDatabaseUnavailableError,
  resourceAuthorization,
  validateAuthorizationTarget,
  verifyExternalResourceBinding,
  type AuthorizationContext,
  type AuthorizationPersistence,
  type AuthorizationResource,
  type AuthorizationSubject,
  type EffectiveGrantRequest,
  type GrantBindingKey,
  type MembershipRecord,
  type VehicleRecord,
} from '../src/services/resource-authorization.service.js';
import { VehicleServiceError, type VehicleAuditEvent } from '../src/services/vehicle-errors.js';
import { createAccessGrant, createVehicle } from '../src/services/vehicle.service.js';
import { createVehicleTestApp, v2Headers } from './v2-fixture.js';

const NOW = new Date('2026-11-26T12:00:00.000Z');
const fixedClock = () => NOW;

type GrantRecord = AccessGrant & { _id: Types.ObjectId };

function vehicleRecord(ownerUserId: Types.ObjectId, overrides: Partial<VehicleRecord> = {}) {
  const record: VehicleRecord = {
    _id: new Types.ObjectId(),
    name: 'Unit Sedan',
    make: null,
    model: null,
    generation: null,
    trim: null,
    year: null,
    bodyStyle: null,
    engine: null,
    transmission: null,
    fuelType: null,
    ownerUserId,
    status: 'ACTIVE',
    createdByUserId: ownerUserId,
    updatedByUserId: null,
    archivedAt: null,
    archivedByUserId: null,
    archiveReason: null,
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
  return record;
}

function membershipRecord(
  vehicle: VehicleRecord,
  userId: Types.ObjectId,
  overrides: Partial<MembershipRecord> = {},
): MembershipRecord {
  return {
    _id: new Types.ObjectId(),
    vehicleId: vehicle._id,
    userId,
    role: 'MEMBER',
    permissions: [],
    status: 'ACTIVE',
    sourceInvitationId: null,
    grantedByUserId: vehicle.ownerUserId,
    updatedByUserId: null,
    suspendedAt: null,
    suspendedByUserId: null,
    suspensionReason: null,
    revokedAt: null,
    revokedByUserId: null,
    revokeReason: null,
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
}

function grantRecord(
  membership: MembershipRecord,
  overrides: Partial<GrantRecord> = {},
): GrantRecord {
  return {
    _id: new Types.ObjectId(),
    vehicleId: membership.vehicleId,
    membershipId: membership._id,
    subjectUserId: membership.userId,
    scopeType: 'VEHICLE',
    scopeResourceId: null,
    channel: 'ONLINE',
    permissions: ['vehicle:read'],
    status: 'ACTIVE',
    startsAt: new Date(NOW.getTime() - 60_000),
    expiresAt: null,
    grantedByUserId: membership.grantedByUserId,
    updatedByUserId: null,
    revokedAt: null,
    revokedByUserId: null,
    revokeReason: null,
    expiredAt: null,
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
}

/** Same semantics as `activeAccessGrantCriteria`, evaluated in memory. */
function isEffectiveGrant(
  grant: GrantRecord,
  key: GrantBindingKey,
  request: EffectiveGrantRequest,
  now: Date,
): boolean {
  const channels = request.channel === 'BLE_OFFLINE' ? ['BLE_OFFLINE', 'ANY'] : ['ONLINE', 'ANY'];
  const resourceId = request.resource.type === 'VEHICLE' ? null : request.resource.resourceId;
  return (
    grant.vehicleId.equals(key.vehicleId) &&
    grant.membershipId.equals(key.membershipId) &&
    grant.subjectUserId.equals(request.subjectUserId) &&
    grant.scopeType === request.resource.type &&
    (resourceId === null
      ? grant.scopeResourceId === null
      : grant.scopeResourceId?.equals(resourceId) === true) &&
    channels.includes(grant.channel) &&
    grant.status === 'ACTIVE' &&
    grant.revokedAt === null &&
    grant.expiredAt === null &&
    grant.startsAt.getTime() <= now.getTime() &&
    (grant.expiresAt === null
      ? grant.channel === 'ONLINE'
      : grant.expiresAt.getTime() > now.getTime()) &&
    request.permissions.some((permission) => grant.permissions.includes(permission))
  );
}

class InMemoryAuthorizationPersistence implements AuthorizationPersistence {
  vehicles: VehicleRecord[] = [];
  memberships: MembershipRecord[] = [];
  grants: GrantRecord[] = [];
  calls: string[] = [];
  sessions: Array<ClientSession | undefined> = [];
  grantRequests: EffectiveGrantRequest[] = [];
  failure: unknown = null;

  private record(call: string, session: ClientSession | undefined): void {
    this.calls.push(call);
    this.sessions.push(session);
    if (this.failure !== null) {
      throw this.failure;
    }
  }

  async findVehicle(
    vehicleId: Types.ObjectId,
    status: VehicleRecord['status'] | undefined,
    session: ClientSession | undefined,
  ) {
    this.record('findVehicle', session);
    return (
      this.vehicles.find(
        (vehicle) => vehicle._id.equals(vehicleId) && (!status || vehicle.status === status),
      ) ?? null
    );
  }

  async findUnrevokedOwnerMemberships(
    vehicleIds: readonly Types.ObjectId[],
    session: ClientSession | undefined,
  ) {
    this.record('findUnrevokedOwnerMemberships', session);
    return this.memberships.filter(
      (membership) =>
        membership.role === 'OWNER' &&
        membership.revokedAt === null &&
        vehicleIds.some((vehicleId) => vehicleId.equals(membership.vehicleId)),
    );
  }

  async findActiveMembership(
    vehicleId: Types.ObjectId,
    userId: Types.ObjectId,
    session: ClientSession | undefined,
  ) {
    this.record('findActiveMembership', session);
    return (
      this.memberships.find(
        (membership) =>
          membership.vehicleId.equals(vehicleId) &&
          membership.userId.equals(userId) &&
          membership.status === 'ACTIVE' &&
          membership.suspendedAt === null &&
          membership.revokedAt === null,
      ) ?? null
    );
  }

  async findEffectiveGrantId(
    key: GrantBindingKey,
    request: EffectiveGrantRequest,
    now: Date,
    session: ClientSession | undefined,
  ) {
    this.record('findEffectiveGrantId', session);
    this.grantRequests.push(request);
    return this.grants.find((grant) => isEffectiveGrant(grant, key, request, now))?._id ?? null;
  }

  async findEffectiveGrantKeys(
    keys: readonly GrantBindingKey[],
    request: EffectiveGrantRequest,
    now: Date,
    session: ClientSession | undefined,
  ) {
    this.record('findEffectiveGrantKeys', session);
    this.grantRequests.push(request);
    return keys.filter((key) =>
      this.grants.some((grant) => isEffectiveGrant(grant, key, request, now)),
    );
  }
}

interface World {
  persistence: InMemoryAuthorizationPersistence;
  service: ReturnType<typeof createResourceAuthorizationService>;
  ownerId: Types.ObjectId;
  vehicle: VehicleRecord;
  ownerMembership: MembershipRecord;
  addMember: (permissions: string[], overrides?: Partial<MembershipRecord>) => MembershipRecord;
}

function createWorld(): World {
  const persistence = new InMemoryAuthorizationPersistence();
  const ownerId = new Types.ObjectId();
  const vehicle = vehicleRecord(ownerId);
  const ownerMembership = membershipRecord(vehicle, ownerId, {
    role: 'OWNER',
    permissions: ['vehicle:manage'],
  });
  persistence.vehicles.push(vehicle);
  persistence.memberships.push(ownerMembership);
  return {
    persistence,
    service: createResourceAuthorizationService(persistence),
    ownerId,
    vehicle,
    ownerMembership,
    addMember(permissions, overrides = {}) {
      const membership = membershipRecord(vehicle, new Types.ObjectId(), {
        permissions,
        ...overrides,
      });
      persistence.memberships.push(membership);
      return membership;
    },
  };
}

function context(
  world: World,
  actorUserId: Types.ObjectId,
  permission: KnownVehiclePermission,
  overrides: Partial<AuthorizationContext> = {},
): AuthorizationContext {
  return {
    actorUserId,
    vehicleId: world.vehicle._id,
    resource: { type: 'VEHICLE' },
    permission,
    channel: 'ONLINE',
    ...overrides,
  };
}

function externalResource(
  world: World,
  type: 'DEVICE' | 'MODULE',
  resourceId = new Types.ObjectId(),
): AuthorizationResource {
  const binding = createVerifiedExternalResourceBinding({
    scopeType: type,
    resourceId,
    vehicleId: world.vehicle._id,
    isActive: true,
  });
  return type === 'DEVICE'
    ? { type: 'DEVICE', resourceId, binding }
    : { type: 'MODULE', resourceId, binding };
}

function subjectOf(world: World, membership: MembershipRecord): AuthorizationSubject {
  const resolution = classifySubject(world.vehicle, membership, membership.userId);
  assert.ok(resolution.resolved);
  return resolution.subject;
}

test('permission/resource catalog: every known permission is evaluable on exactly one resource and grant catalogs are not widened', () => {
  const evaluable = AUTHORIZATION_RESOURCE_TYPES.flatMap(
    (type) => EVALUABLE_PERMISSIONS_BY_RESOURCE[type],
  );
  assert.deepEqual([...evaluable].sort(), [...ALL_KNOWN_PERMISSIONS].sort());
  assert.equal(new Set(evaluable).size, evaluable.length, 'no permission on two resource types');

  assert.deepEqual(EVALUABLE_PERMISSIONS_BY_RESOURCE.DEVICE, [
    'device:read',
    'device:connect',
    'device:command',
  ]);
  assert.deepEqual(EVALUABLE_PERMISSIONS_BY_RESOURCE.MODULE, [
    'module:read',
    'module:configure',
    'module:actuate',
  ]);
  for (const permission of [
    ...OWNER_RESERVED_PERMISSIONS,
    'vehicle:read',
    'vehicle:update',
    'vehicle:manage',
    'invitation:create',
    'device:link',
  ] as const) {
    assert.equal(isPermissionApplicableToResource('VEHICLE', permission), true, permission);
    assert.equal(isPermissionApplicableToResource('DEVICE', permission), false, permission);
    assert.equal(isPermissionApplicableToResource('MODULE', permission), false, permission);
  }

  // Grant storage catalogs are unchanged; VEHICLE-scoped device:read stays valid on stored
  // records but is neither evaluable nor issuable.
  assert.deepEqual(ACCESS_GRANT_VEHICLE_PERMISSIONS, [
    'vehicle:read',
    'vehicle:update',
    'device:read',
    'device:link',
  ]);
  assert.deepEqual(ACCESS_GRANT_DEVICE_PERMISSIONS, [
    'device:read',
    'device:connect',
    'device:command',
  ]);
  assert.deepEqual(ACCESS_GRANT_MODULE_PERMISSIONS, [
    'module:read',
    'module:configure',
    'module:actuate',
  ]);
  assert.equal(isAccessGrantPermissionForScope('VEHICLE', 'device:read'), true);
  assert.equal(isPermissionApplicableToResource('VEHICLE', 'device:read'), false);

  // Creation catalog: issuable = storable for the scope AND evaluable on that resource; the only
  // storable-but-not-issuable combination is the historical VEHICLE-scoped device:read.
  const storableOnly: string[] = [];
  for (const scope of AUTHORIZATION_RESOURCE_TYPES) {
    for (const permission of ALL_KNOWN_PERMISSIONS) {
      const storable = isAccessGrantPermissionForScope(scope, permission);
      const issuable = isIssuableAccessGrantPermission(scope, permission);
      assert.equal(
        issuable,
        storable && isPermissionApplicableToResource(scope, permission),
        `${scope} ${permission}`,
      );
      if (storable && !issuable) {
        storableOnly.push(`${scope} ${permission}`);
      }
      if (issuable) {
        assert.equal(isOwnerReservedPermission(permission), false, permission);
      }
    }
  }
  assert.deepEqual(storableOnly, ['VEHICLE device:read']);
  for (const invalid of ['', 'vehicle:*', '*', 'device:read ', 'vehicle:owner']) {
    for (const scope of AUTHORIZATION_RESOURCE_TYPES) {
      assert.equal(isIssuableAccessGrantPermission(scope, invalid), false, invalid);
    }
  }

  for (const invalid of ['', ' vehicle:read', 'vehicle:*', '*', 'vehicle:read\n', 'sunroof:open']) {
    for (const type of AUTHORIZATION_RESOURCE_TYPES) {
      assert.equal(isPermissionApplicableToResource(type, invalid), false, invalid);
    }
  }
  assert.equal(
    isPermissionApplicableToResource(
      'CABIN' as unknown as AuthorizationResourceType,
      'vehicle:read',
    ),
    false,
  );
});

test('runtime context validation rejects malformed actors, channels, permissions, scopes, and permission/resource mismatches', () => {
  const world = createWorld();
  const target = {
    actorUserId: world.ownerId,
    vehicleId: world.vehicle._id,
    resource: { type: 'VEHICLE' } as const,
    channel: 'ONLINE' as const,
  };
  assert.equal(validateAuthorizationTarget(target, ['vehicle:read']), null);

  const runtime = (value: unknown) => value as never;
  assert.equal(
    validateAuthorizationTarget({ ...target, actorUserId: runtime(String(world.ownerId)) }, [
      'vehicle:read',
    ]),
    'INVALID_CONTEXT',
  );
  assert.equal(
    validateAuthorizationTarget({ ...target, vehicleId: runtime(null) }, ['vehicle:read']),
    'INVALID_CONTEXT',
  );
  for (const channel of ['ANY', '', 'online', 'WIFI']) {
    assert.equal(
      validateAuthorizationTarget({ ...target, channel: runtime(channel) }, ['vehicle:read']),
      'INVALID_CONTEXT',
      channel,
    );
  }
  for (const permission of [
    '',
    '*',
    'vehicle:*',
    ' vehicle:read',
    'vehicle:read\u0000',
    'x'.repeat(65),
    'sunroof:override_safety',
  ]) {
    assert.equal(
      validateAuthorizationTarget(target, [permission]),
      'UNKNOWN_OR_INVALID_PERMISSION',
    );
  }
  assert.equal(validateAuthorizationTarget(target, []), 'UNKNOWN_OR_INVALID_PERMISSION');
  assert.equal(validateAuthorizationTarget(target, [runtime(42)]), 'UNKNOWN_OR_INVALID_PERMISSION');

  const deviceId = new Types.ObjectId();
  for (const resource of [
    { type: 'VEHICLE', resourceId: deviceId },
    { type: 'DEVICE' },
    { type: 'DEVICE', resourceId: String(deviceId) },
    { type: 'MODULE', resourceId: null },
    { type: 'CABIN', resourceId: deviceId },
    null,
  ]) {
    assert.equal(
      validateAuthorizationTarget({ ...target, resource: runtime(resource) }, ['device:read']),
      'INVALID_SCOPE',
      JSON.stringify(resource),
    );
  }

  const cases: Array<[AuthorizationResource, KnownVehiclePermission]> = [
    [{ type: 'VEHICLE' }, 'device:read'],
    [{ type: 'VEHICLE' }, 'device:command'],
    [{ type: 'VEHICLE' }, 'module:actuate'],
    [{ type: 'DEVICE', resourceId: deviceId }, 'vehicle:read'],
    [{ type: 'DEVICE', resourceId: deviceId }, 'device:link'],
    [{ type: 'DEVICE', resourceId: deviceId }, 'module:read'],
    [{ type: 'MODULE', resourceId: deviceId }, 'device:read'],
    [{ type: 'MODULE', resourceId: deviceId }, 'vehicle:owner'],
  ];
  for (const [resource, permission] of cases) {
    assert.equal(
      validateAuthorizationTarget({ ...target, resource }, [permission]),
      'PERMISSION_RESOURCE_MISMATCH',
      `${resource.type} ${permission}`,
    );
  }
});

test('subject classification: canonical OWNER, MEMBER, exact roles, inactive memberships, and inconsistent ownership', () => {
  const world = createWorld();
  const member = world.addMember(['vehicle:read']);

  const owner = classifySubject(world.vehicle, world.ownerMembership, world.ownerId);
  assert.ok(owner.resolved && owner.subject.role === 'OWNER');
  const asMember = classifySubject(world.vehicle, member, member.userId);
  assert.ok(asMember.resolved && asMember.subject.role === 'MEMBER');

  const suspended = { ...member, status: 'SUSPENDED' as const, suspendedAt: NOW };
  const revoked = { ...member, status: 'REVOKED' as const, revokedAt: NOW };
  for (const inactive of [null, suspended, revoked]) {
    assert.deepEqual(classifySubject(world.vehicle, inactive, member.userId), {
      resolved: false,
      reason: 'MEMBERSHIP_INACTIVE_OR_MISSING',
      category: 'DENIED',
    });
  }

  // OWNER role held by a non-canonical user, or the canonical owner holding a MEMBER role.
  assert.deepEqual(classifySubject(world.vehicle, { ...member, role: 'OWNER' }, member.userId), {
    resolved: false,
    reason: 'OWNERSHIP_MISMATCH',
    category: 'INCONSISTENT_STATE',
  });
  assert.deepEqual(
    classifySubject(world.vehicle, { ...world.ownerMembership, role: 'MEMBER' }, world.ownerId),
    { resolved: false, reason: 'OWNERSHIP_MISMATCH', category: 'INCONSISTENT_STATE' },
  );
  // Memberships of another user or vehicle never resolve.
  assert.equal(classifySubject(world.vehicle, member, world.ownerId).resolved, false);
  const otherVehicle = vehicleRecord(world.ownerId);
  assert.equal(classifySubject(otherVehicle, member, member.userId).resolved, false);
  assert.deepEqual(
    classifySubject({ ...world.vehicle, status: 'ARCHIVED' }, world.ownerMembership, world.ownerId),
    { resolved: false, reason: 'VEHICLE_UNAVAILABLE_OR_INCONSISTENT', category: 'DENIED' },
  );
});

test('decision matrix: OWNER, reserved permissions, base permissions ONLINE, BLE_OFFLINE, and grant eligibility', () => {
  const world = createWorld();
  const owner = subjectOf(world, world.ownerMembership);
  const member = subjectOf(
    world,
    world.addMember([
      'vehicle:read',
      'vehicle:manage',
      'device:read',
      'device:command',
      'module:actuate',
    ]),
  );
  const bare = subjectOf(world, world.addMember([]));

  for (const type of AUTHORIZATION_RESOURCE_TYPES) {
    for (const permission of EVALUABLE_PERMISSIONS_BY_RESOURCE[type]) {
      assert.deepEqual(
        decideMembershipPermission(owner, { permission, resourceType: type, channel: 'ONLINE' }),
        { kind: 'ALLOWED', source: 'OWNER_ROLE' },
        `${type} ${permission}`,
      );
      assert.deepEqual(
        decideMembershipPermission(owner, {
          permission,
          resourceType: type,
          channel: 'BLE_OFFLINE',
        }),
        { kind: 'DENIED', reason: 'BLE_OWNER_GRANT_REQUIRED' },
      );
    }
  }
  // Even the OWNER is denied for permissions outside the resource's catalog.
  assert.deepEqual(
    decideMembershipPermission(owner, {
      permission: 'module:actuate',
      resourceType: 'VEHICLE',
      channel: 'ONLINE',
    }),
    { kind: 'DENIED', reason: 'PERMISSION_RESOURCE_MISMATCH' },
  );

  for (const permission of OWNER_RESERVED_PERMISSIONS) {
    assert.deepEqual(
      decideMembershipPermission(member, {
        permission,
        resourceType: 'VEHICLE',
        channel: 'ONLINE',
      }),
      { kind: 'DENIED', reason: 'OWNER_PERMISSION_FORBIDDEN' },
    );
  }

  const baseOnline: Array<[AuthorizationResourceType, KnownVehiclePermission]> = [
    ['VEHICLE', 'vehicle:read'],
    ['VEHICLE', 'vehicle:manage'],
    ['DEVICE', 'device:read'],
    ['DEVICE', 'device:command'],
    ['MODULE', 'module:actuate'],
  ];
  for (const [resourceType, permission] of baseOnline) {
    assert.deepEqual(
      decideMembershipPermission(member, { permission, resourceType, channel: 'ONLINE' }),
      { kind: 'ALLOWED', source: 'MEMBERSHIP_PERMISSION' },
      `${resourceType} ${permission}`,
    );
    // Base permissions never authorize BLE_OFFLINE: only a grant can, when grantable.
    const offline = decideMembershipPermission(member, {
      permission,
      resourceType,
      channel: 'BLE_OFFLINE',
    });
    assert.notEqual(offline.kind, 'ALLOWED', `${resourceType} ${permission} BLE_OFFLINE`);
  }
  assert.deepEqual(
    decideMembershipPermission(member, {
      permission: 'vehicle:manage',
      resourceType: 'VEHICLE',
      channel: 'BLE_OFFLINE',
    }),
    { kind: 'DENIED', reason: 'PERMISSION_NOT_GRANTED' },
  );
  // Base device:read was historically evaluated on VEHICLE; it now only applies to DEVICE.
  assert.deepEqual(
    decideMembershipPermission(member, {
      permission: 'device:read',
      resourceType: 'VEHICLE',
      channel: 'ONLINE',
    }),
    { kind: 'DENIED', reason: 'PERMISSION_RESOURCE_MISMATCH' },
  );

  // Without base permission only grantable permissions may still be authorized by a grant.
  for (const [resourceType, permission, expected] of [
    ['VEHICLE', 'vehicle:read', 'ACCESS_GRANT_REQUIRED'],
    ['VEHICLE', 'device:link', 'ACCESS_GRANT_REQUIRED'],
    ['VEHICLE', 'vehicle:manage', 'DENIED'],
    ['VEHICLE', 'invitation:create', 'DENIED'],
    ['DEVICE', 'device:connect', 'ACCESS_GRANT_REQUIRED'],
    ['MODULE', 'module:configure', 'ACCESS_GRANT_REQUIRED'],
  ] as const) {
    assert.equal(
      decideMembershipPermission(bare, { permission, resourceType, channel: 'ONLINE' }).kind,
      expected,
      `${resourceType} ${permission}`,
    );
  }
});

test('grant criteria pin exact subject, scope, resource, channel, window, and expiry-by-channel semantics', () => {
  const subjectUserId = new Types.ObjectId();
  const resourceId = new Types.ObjectId();
  assert.deepEqual(
    activeAccessGrantCriteria(
      {
        subjectUserId,
        resource: { type: 'DEVICE', resourceId },
        channel: 'BLE_OFFLINE',
        permissions: ['device:connect'],
      },
      NOW,
    ),
    {
      subjectUserId,
      scopeType: 'DEVICE',
      scopeResourceId: resourceId,
      channel: { $in: ['BLE_OFFLINE', 'ANY'] },
      status: 'ACTIVE',
      revokedAt: null,
      expiredAt: null,
      startsAt: { $lte: NOW },
      $or: [{ expiresAt: { $gt: NOW } }, { expiresAt: null, channel: 'ONLINE' }],
      permissions: { $in: ['device:connect'] },
    },
  );
  const vehicleCriteria = activeAccessGrantCriteria(
    {
      subjectUserId,
      resource: { type: 'VEHICLE' },
      channel: 'ONLINE',
      permissions: ['vehicle:read'],
    },
    NOW,
  );
  assert.equal(vehicleCriteria.scopeResourceId, null);
  assert.deepEqual(vehicleCriteria.channel, { $in: ['ONLINE', 'ANY'] });
});

test('service: OWNER and MEMBER decisions, base permissions on verified DEVICE/MODULE, effective grants, and default deny', async () => {
  const world = createWorld();
  const { service, persistence } = world;

  const ownerRead = await service.evaluate(context(world, world.ownerId, 'vehicle:archive'), {
    clock: fixedClock,
  });
  assert.deepEqual(ownerRead, {
    allowed: true,
    reason: 'ALLOWED',
    source: 'OWNER_ROLE',
    membershipId: world.ownerMembership._id,
    grantId: null,
    evaluatedAt: NOW,
  });

  const deviceReader = world.addMember(['vehicle:read', 'device:read', 'module:actuate']);
  const device = externalResource(world, 'DEVICE');
  const moduleResource = externalResource(world, 'MODULE');
  const deviceRead = await service.evaluate(
    context(world, deviceReader.userId, 'device:read', { resource: device }),
  );
  assert.ok(deviceRead.allowed && deviceRead.source === 'MEMBERSHIP_PERMISSION');
  const moduleActuate = await service.evaluate(
    context(world, deviceReader.userId, 'module:actuate', { resource: moduleResource }),
  );
  assert.ok(moduleActuate.allowed && moduleActuate.source === 'MEMBERSHIP_PERMISSION');
  assert.equal(
    persistence.calls.includes('findEffectiveGrantId'),
    false,
    'base ONLINE permission needs no additional AccessGrant',
  );

  const offlineBase = await service.evaluate(
    context(world, deviceReader.userId, 'device:read', {
      resource: device,
      channel: 'BLE_OFFLINE',
    }),
  );
  assert.deepEqual(
    { allowed: offlineBase.allowed, reason: offlineBase.reason },
    { allowed: false, reason: 'PERMISSION_NOT_GRANTED' },
  );

  const grantee = world.addMember([]);
  const deviceId = device.type === 'DEVICE' ? device.resourceId : new Types.ObjectId();
  const bleGrant = grantRecord(grantee, {
    scopeType: 'DEVICE',
    scopeResourceId: deviceId,
    channel: 'BLE_OFFLINE',
    permissions: ['device:connect'],
    expiresAt: new Date(NOW.getTime() + 60_000),
  });
  persistence.grants.push(bleGrant);
  const offlineGrant = await service.evaluate(
    context(world, grantee.userId, 'device:connect', { resource: device, channel: 'BLE_OFFLINE' }),
    { clock: fixedClock },
  );
  assert.ok(offlineGrant.allowed && offlineGrant.source === 'ACCESS_GRANT');
  assert.equal(offlineGrant.grantId?.equals(bleGrant._id), true);
  // Incompatible channel: a BLE_OFFLINE grant never authorizes ONLINE.
  const onlineWithBleGrant = await service.evaluate(
    context(world, grantee.userId, 'device:connect', { resource: device }),
    { clock: fixedClock },
  );
  assert.equal(onlineWithBleGrant.allowed, false);
  // VEHICLE grants never extend to DEVICE / MODULE resources.
  persistence.grants.push(grantRecord(grantee, { permissions: ['vehicle:read', 'device:read'] }));
  const deviceViaVehicleGrant = await service.evaluate(
    context(world, grantee.userId, 'device:read', { resource: device }),
    { clock: fixedClock },
  );
  assert.equal(deviceViaVehicleGrant.allowed, false);

  const outsider = await service.evaluate(context(world, new Types.ObjectId(), 'vehicle:read'));
  assert.deepEqual(
    { allowed: outsider.allowed, reason: outsider.reason },
    { allowed: false, reason: 'MEMBERSHIP_INACTIVE_OR_MISSING' },
  );
  const bare = await service.evaluate(context(world, world.addMember([]).userId, 'vehicle:read'));
  assert.deepEqual(
    { allowed: bare.allowed, reason: bare.reason },
    { allowed: false, reason: 'PERMISSION_NOT_GRANTED' },
  );
});

test('service: bindings that are missing, forged, copied, inactive, or foreign deny before any persistence access', async () => {
  const world = createWorld();
  const { service, persistence } = world;
  const member = world.addMember(['device:read']);
  const resourceId = new Types.ObjectId();
  const genuine = createVerifiedExternalResourceBinding({
    scopeType: 'DEVICE',
    resourceId,
    vehicleId: world.vehicle._id,
    isActive: true,
  });
  assert.equal(
    verifyExternalResourceBinding(world.vehicle._id, {
      type: 'DEVICE',
      resourceId,
      binding: genuine,
    }),
    true,
  );

  const forgedJson: unknown = JSON.parse(
    JSON.stringify({
      scopeType: 'DEVICE',
      resourceId: String(resourceId),
      vehicleId: String(world.vehicle._id),
      isActive: true,
    }),
  );
  const copied = { ...genuine };
  const lookalike = Object.freeze({
    scopeType: 'DEVICE',
    resourceId,
    vehicleId: world.vehicle._id,
    isActive: true,
  });
  const otherVehicle = createVerifiedExternalResourceBinding({
    scopeType: 'DEVICE',
    resourceId,
    vehicleId: new Types.ObjectId(),
    isActive: true,
  });
  const otherResource = createVerifiedExternalResourceBinding({
    scopeType: 'DEVICE',
    resourceId: new Types.ObjectId(),
    vehicleId: world.vehicle._id,
    isActive: true,
  });
  const moduleType = createVerifiedExternalResourceBinding({
    scopeType: 'MODULE',
    resourceId,
    vehicleId: world.vehicle._id,
    isActive: true,
  });
  const inactive = createVerifiedExternalResourceBinding({
    scopeType: 'DEVICE',
    resourceId,
    vehicleId: world.vehicle._id,
    isActive: false,
  });
  for (const binding of [
    undefined,
    forgedJson,
    copied,
    lookalike,
    otherVehicle,
    otherResource,
    moduleType,
    inactive,
  ]) {
    const decision = await service.evaluate(
      context(world, member.userId, 'device:read', {
        resource: { type: 'DEVICE', resourceId, binding: binding as never },
      }),
    );
    assert.deepEqual(
      { allowed: decision.allowed, reason: decision.reason },
      { allowed: false, reason: 'UNVERIFIED_EXTERNAL_RESOURCE' },
    );
  }
  assert.deepEqual(persistence.calls, [], 'no persistence access without verified evidence');

  assert.throws(
    () =>
      createVerifiedExternalResourceBinding({
        scopeType: 'VEHICLE' as never,
        resourceId,
        vehicleId: world.vehicle._id,
        isActive: true,
      }),
    TypeError,
  );
  assert.throws(
    () =>
      createVerifiedExternalResourceBinding({
        scopeType: 'DEVICE',
        resourceId: String(resourceId) as never,
        vehicleId: world.vehicle._id,
        isActive: true,
      }),
    TypeError,
  );
  assert.equal(Object.isFrozen(genuine), true);
});

/** Overwrites every own field of an ObjectId in place (works for numeric or byte storage). */
function mutateObjectIdInPlace(id: Types.ObjectId): void {
  const fields = id as unknown as Record<PropertyKey, unknown>;
  for (const key of Reflect.ownKeys(id)) {
    const value = fields[key];
    if (typeof value === 'number') {
      fields[key] = value ^ 0x5a5a5a5a;
    } else if (value instanceof Uint8Array) {
      value.fill(0xa5);
    }
  }
}

test('evidence identifiers cannot change after issuance, even through mutable ObjectId instances', () => {
  const resourceId = new Types.ObjectId();
  const vehicleId = new Types.ObjectId();
  const resourceHex = resourceId.toHexString();
  const vehicleHex = vehicleId.toHexString();
  const binding = createVerifiedExternalResourceBinding({
    scopeType: 'DEVICE',
    resourceId,
    vehicleId,
    isActive: true,
  });
  const originalResource = new Types.ObjectId(resourceHex);
  const originalVehicle = new Types.ObjectId(vehicleHex);
  const verifies = (vehicle: Types.ObjectId, resource: Types.ObjectId) =>
    verifyExternalResourceBinding(vehicle, { type: 'DEVICE', resourceId: resource, binding });

  // The caller keeps references to the inputs and mutates them after issuance.
  mutateObjectIdInPlace(resourceId);
  mutateObjectIdInPlace(vehicleId);
  assert.notEqual(resourceId.toHexString(), resourceHex, 'precondition: inputs are mutable');
  assert.notEqual(vehicleId.toHexString(), vehicleHex, 'precondition: inputs are mutable');
  assert.equal(verifies(originalVehicle, originalResource), true);
  assert.equal(verifies(vehicleId, resourceId), false);
  assert.equal(binding.resourceId.toHexString(), resourceHex);
  assert.equal(binding.vehicleId.toHexString(), vehicleHex);
  assert.notEqual(binding.resourceId, resourceId, 'identifiers are defensive copies');

  // The exposed identifiers are frozen; attempts to rewrite them never change the evidence.
  assert.equal(Object.isFrozen(binding.resourceId), true);
  assert.equal(Object.isFrozen(binding.vehicleId), true);
  assert.throws(() => mutateObjectIdInPlace(binding.resourceId), TypeError);
  assert.equal(binding.resourceId.toHexString(), resourceHex);
  assert.equal(verifies(originalVehicle, originalResource), true);
  const foreign = new Types.ObjectId();
  assert.equal(verifies(originalVehicle, foreign), false);
  assert.equal(verifies(foreign, originalResource), false);
});

test('exhaustive matrix: every incompatible permission/resource pair is denied even for the OWNER; DEVICE/MODULE base permissions need valid evidence', async () => {
  const world = createWorld();
  const { service, persistence } = world;
  const holder = world.addMember([
    'vehicle:read',
    'device:read',
    'device:connect',
    'device:command',
    'module:read',
    'module:configure',
    'module:actuate',
  ]);
  const resourceFor = (type: AuthorizationResourceType): AuthorizationResource =>
    type === 'VEHICLE' ? { type: 'VEHICLE' } : externalResource(world, type);

  for (const type of AUTHORIZATION_RESOURCE_TYPES) {
    for (const permission of ALL_KNOWN_PERMISSIONS) {
      if (isPermissionApplicableToResource(type, permission)) {
        continue;
      }
      for (const actor of [world.ownerId, holder.userId]) {
        for (const channel of ['ONLINE', 'BLE_OFFLINE'] as const) {
          const decision = await service.evaluate(
            context(world, actor, permission, { resource: resourceFor(type), channel }),
          );
          assert.deepEqual(
            {
              allowed: decision.allowed,
              reason: decision.reason,
              category: decision.allowed ? null : decision.category,
            },
            {
              allowed: false,
              reason: 'PERMISSION_RESOURCE_MISMATCH',
              category: 'INVALID_CONTEXT',
            },
            `${type} ${permission} ${channel}`,
          );
        }
      }
    }
  }
  assert.deepEqual(persistence.calls, [], 'incompatible pairs never reach persistence');

  for (const type of ['DEVICE', 'MODULE'] as const) {
    for (const permission of EVALUABLE_PERMISSIONS_BY_RESOURCE[type]) {
      const resourceId = new Types.ObjectId();
      const verified = await service.evaluate(
        context(world, holder.userId, permission, {
          resource: externalResource(world, type, resourceId),
        }),
      );
      assert.equal(verified.allowed && verified.source, 'MEMBERSHIP_PERMISSION', permission);
      const unverified = await service.evaluate(
        context(world, holder.userId, permission, {
          resource: { type, resourceId } as AuthorizationResource,
        }),
      );
      assert.equal(unverified.reason, 'UNVERIFIED_EXTERNAL_RESOURCE', permission);
      const ownerUnverified = await service.evaluate(
        context(world, world.ownerId, permission, {
          resource: { type, resourceId } as AuthorizationResource,
        }),
      );
      assert.equal(ownerUnverified.reason, 'UNVERIFIED_EXTERNAL_RESOURCE', permission);
    }
  }
});

test('service: inconsistent ownership, missing and archived vehicles fail closed with audited categories', async () => {
  const world = createWorld();
  const audits: VehicleAuditEvent[] = [];
  const member = world.addMember(['vehicle:read']);

  world.vehicle.ownerUserId = new Types.ObjectId();
  const inconsistent = await world.service.evaluate(context(world, world.ownerId, 'vehicle:read'), {
    audit: (event) => audits.push(event),
  });
  assert.ok(!inconsistent.allowed);
  assert.equal(inconsistent.reason, 'VEHICLE_UNAVAILABLE_OR_INCONSISTENT');
  assert.equal(inconsistent.category, 'INCONSISTENT_STATE');
  assert.equal(audits[0]?.action, 'vehicle.ownership_inconsistency');
  assert.equal(await world.service.isMember(world.vehicle._id, member.userId), false);

  const missing = await world.service.evaluate({
    ...context(world, world.ownerId, 'vehicle:read'),
    vehicleId: new Types.ObjectId(),
  });
  assert.ok(!missing.allowed && missing.category === 'DENIED');

  const archivedWorld = createWorld();
  archivedWorld.vehicle.status = 'ARCHIVED';
  const archived = await archivedWorld.service.evaluate(
    context(archivedWorld, archivedWorld.ownerId, 'vehicle:read'),
  );
  assert.ok(!archived.allowed && archived.reason === 'VEHICLE_UNAVAILABLE_OR_INCONSISTENT');

  const secondOwner = createWorld();
  secondOwner.persistence.memberships.push(
    membershipRecord(secondOwner.vehicle, new Types.ObjectId(), { role: 'OWNER' }),
  );
  assert.equal(
    await secondOwner.service.isOwner(secondOwner.vehicle._id, secondOwner.ownerId),
    false,
  );
});

test('service: derived methods share the core; isMember includes the OWNER and hasRole is exact', async () => {
  const world = createWorld();
  const reader = world.addMember(['vehicle:read']);
  const manager = world.addMember(['vehicle:manage']);
  const noRead = world.addMember(['device:read']);
  const suspended = world.addMember(['vehicle:read'], { status: 'SUSPENDED', suspendedAt: NOW });
  const outsider = new Types.ObjectId();
  const { service } = world;
  const vehicleId = world.vehicle._id;

  assert.equal(await service.isOwner(vehicleId, world.ownerId), true);
  assert.equal(await service.isOwner(vehicleId, reader.userId), false);
  assert.equal(await service.isMember(vehicleId, world.ownerId), true);
  assert.equal(await service.isMember(vehicleId, reader.userId), true);
  assert.equal(await service.isMember(vehicleId, suspended.userId), false);
  assert.equal(await service.isMember(vehicleId, outsider), false);
  assert.equal(await service.hasRole(vehicleId, world.ownerId, 'OWNER'), true);
  assert.equal(await service.hasRole(vehicleId, world.ownerId, 'MEMBER'), false);
  assert.equal(await service.hasRole(vehicleId, reader.userId, 'MEMBER'), true);
  assert.equal(await service.hasRole(vehicleId, reader.userId, 'OWNER'), false);
  assert.equal(
    await Reflect.apply(service.hasRole, service, [vehicleId, world.ownerId, 'ADMIN']),
    false,
  );
  assert.equal(await service.isMember(String(vehicleId) as never, world.ownerId), false);

  assert.equal(await service.hasPermission(context(world, reader.userId, 'vehicle:read')), true);
  assert.equal(await service.hasPermission(context(world, reader.userId, 'vehicle:update')), false);
  assert.equal(await service.hasVehicleReadAccess(vehicleId, manager.userId), true);
  assert.equal(await service.hasVehicleReadAccess(vehicleId, noRead.userId), false);
  assert.equal(await service.hasVehicleReadAccess(vehicleId, world.ownerId), true);

  world.persistence.grants.push(grantRecord(noRead));
  assert.equal(await service.hasVehicleReadAccess(vehicleId, noRead.userId), true);

  // evaluateAnyOf: one subject resolution and a single grant query for grantable candidates.
  const linker = world.addMember([]);
  world.persistence.grants.push(grantRecord(linker, { permissions: ['device:link'] }));
  world.persistence.calls = [];
  world.persistence.grantRequests = [];
  const link = await service.evaluateAnyOf(
    { actorUserId: linker.userId, vehicleId, resource: { type: 'VEHICLE' }, channel: 'ONLINE' },
    ['vehicle:manage', 'device:link'],
  );
  assert.ok(link.allowed && link.source === 'ACCESS_GRANT');
  assert.deepEqual(world.persistence.calls, [
    'findVehicle',
    'findUnrevokedOwnerMemberships',
    'findActiveMembership',
    'findEffectiveGrantId',
  ]);
  assert.deepEqual(world.persistence.grantRequests[0]?.permissions, ['device:link']);
});

test('assertPermission maps denials to VALIDATION_ERROR / FORBIDDEN / NOT_FOUND without exposing reasons', async () => {
  const world = createWorld();
  const reader = world.addMember(['vehicle:read']);
  const audits: VehicleAuditEvent[] = [];
  const audit = (event: VehicleAuditEvent) => audits.push(event);
  const { service } = world;

  const allowed = await service.assertPermission(context(world, world.ownerId, 'vehicle:update'));
  assert.equal(allowed.source, 'OWNER_ROLE');

  const expectCode = async (ctx: AuthorizationContext, code: string, message: string) => {
    await assert.rejects(
      () => service.assertPermission(ctx, { audit, action: 'unit.assert' }),
      (error: unknown) =>
        error instanceof VehicleServiceError && error.code === code && error.message === message,
    );
  };
  await expectCode(
    context(world, reader.userId, 'vehicle:update'),
    'FORBIDDEN',
    'Insufficient permissions',
  );
  await expectCode(
    context(world, new Types.ObjectId(), 'vehicle:update'),
    'NOT_FOUND',
    'Vehicle not found',
  );
  await expectCode(
    context(world, world.addMember(['device:read']).userId, 'vehicle:update'),
    'NOT_FOUND',
    'Vehicle not found',
  );
  await expectCode(
    context(world, reader.userId, 'device:read', {
      resource: { type: 'DEVICE', resourceId: new Types.ObjectId() },
    }),
    'NOT_FOUND',
    'Vehicle not found',
  );
  await expectCode(
    context(world, world.ownerId, 'device:read'),
    'VALIDATION_ERROR',
    'Invalid authorization request',
  );
  assert.deepEqual(
    audits.map((event) => [event.action, event.outcome, event.reason]),
    [
      ['unit.assert', 'denied', 'permission_not_granted'],
      ['unit.assert', 'denied', 'membership_inactive_or_missing'],
      ['unit.assert', 'denied', 'permission_not_granted'],
      ['unit.assert', 'denied', 'unverified_external_resource'],
      ['unit.assert', 'denied', 'permission_resource_mismatch'],
    ],
  );
});

test('clock: a single server-side time reference per evaluation; invalid clocks are programming errors', async () => {
  const world = createWorld();
  const member = world.addMember([]);
  world.persistence.grants.push(
    grantRecord(member, {
      startsAt: NOW,
      expiresAt: new Date(NOW.getTime() + 1_000),
    }),
  );
  let reads = 0;
  const countingClock = () => {
    reads += 1;
    return new Date(NOW.getTime());
  };
  const decision = await world.service.evaluate(context(world, member.userId, 'vehicle:read'), {
    clock: countingClock,
  });
  assert.equal(reads, 1);
  assert.ok(decision.allowed, 'startsAt equal to now is inclusive');
  const atExpiry = await world.service.evaluate(context(world, member.userId, 'vehicle:read'), {
    clock: () => new Date(NOW.getTime() + 1_000),
  });
  assert.equal(atExpiry.allowed, false, 'expiresAt equal to now is exclusive');

  const mutable = new Date(NOW.getTime());
  const captured = captureEvaluationTime(() => mutable);
  mutable.setFullYear(2000);
  assert.equal(captured.getTime(), NOW.getTime());
  assert.throws(() => captureEvaluationTime(() => new Date(Number.NaN)), TypeError);
  assert.throws(() => captureEvaluationTime(() => 'now' as never), TypeError);
  await assert.rejects(
    () =>
      world.service.evaluate(context(world, member.userId, 'vehicle:read'), {
        clock: () => new Date('invalid'),
      }),
    TypeError,
  );
});

test('session is propagated to every persistence call of an evaluation, sequentially', async () => {
  const world = createWorld();
  const member = world.addMember([]);
  const client = new mongoose.mongo.MongoClient('mongodb://127.0.0.1:1');
  const session = client.startSession();
  try {
    const device = externalResource(world, 'DEVICE');
    await world.service.evaluate(
      context(world, member.userId, 'device:connect', { resource: device }),
      { session },
    );
    await world.service.filterReadableCandidates(
      member.userId,
      [{ vehicle: world.vehicle, membership: member }],
      { now: NOW, session },
    );
    assert.deepEqual(world.persistence.calls, [
      'findVehicle',
      'findUnrevokedOwnerMemberships',
      'findActiveMembership',
      'findEffectiveGrantId',
      'findEffectiveGrantKeys',
    ]);
    assert.ok(world.persistence.sessions.every((used) => used === session));
  } finally {
    await session.endSession();
    await client.close();
  }
});

test('availability: unavailable dependencies never ALLOW; programming errors are not turned into 503', async () => {
  const world = createWorld();
  world.persistence.failure = new VehicleServiceError('DATABASE_UNAVAILABLE', 'down');
  const ctx = context(world, world.ownerId, 'vehicle:read');
  const isUnavailable = (error: unknown) =>
    error instanceof VehicleServiceError && error.code === 'DATABASE_UNAVAILABLE';
  await assert.rejects(() => world.service.evaluate(ctx), isUnavailable);
  await assert.rejects(() => world.service.hasPermission(ctx), isUnavailable);
  await assert.rejects(() => world.service.assertPermission(ctx), isUnavailable);
  await assert.rejects(
    () => world.service.isOwner(world.vehicle._id, world.ownerId),
    isUnavailable,
  );

  world.persistence.failure = new TypeError('bug');
  await assert.rejects(() => world.service.evaluate(ctx), TypeError);

  assert.equal(isDatabaseUnavailableError(new mongoose.mongo.MongoNetworkError('reset')), true);
  assert.equal(
    isDatabaseUnavailableError(new mongoose.mongo.MongoNetworkTimeoutError('timeout')),
    true,
  );
  assert.equal(
    isDatabaseUnavailableError(new mongoose.mongo.MongoNotConnectedError('closed')),
    true,
  );
  assert.equal(isDatabaseUnavailableError(new Error('generic')), false);
  assert.equal(isDatabaseUnavailableError(new mongoose.mongo.MongoError('duplicate')), false);

  // The MongoDB adapter fails fast with DATABASE_UNAVAILABLE while disconnected.
  assert.notEqual(mongoose.connection.readyState, 1);
  await assert.rejects(
    () =>
      resourceAuthorization.evaluate({
        actorUserId: new Types.ObjectId(),
        vehicleId: new Types.ObjectId(),
        resource: { type: 'VEHICLE' },
        permission: 'vehicle:read',
        channel: 'ONLINE',
      }),
    isUnavailable,
  );
});

test('deviceLink answers 503 without contacting Device when the authorization store is unavailable', async (t) => {
  const deviceCalls = { count: 0 };
  t.mock.method(globalThis, 'fetch', async (url: string | URL | Request) => {
    const target = String(url instanceof Request ? url.url : url);
    if (target.includes('/internal/devices/')) {
      deviceCalls.count += 1;
    }
    const body = target.endsWith('/verified') ? { verified: true } : { exists: true };
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  });
  const app = createVehicleTestApp();
  t.after(async () => app.close());
  const vehicleId = String(new Types.ObjectId());
  const target = `/vehicles/${vehicleId}/devices/link`;
  const payload = Buffer.from(
    JSON.stringify({
      userId: String(new Types.ObjectId()),
      deviceIdentifier: 'esp32-unit',
      publicKey: 'k'.repeat(44),
    }),
  );
  const response = await app.inject({
    method: 'POST',
    url: target,
    headers: v2Headers(payload, 'POST', target),
    payload,
  });
  assert.equal(response.statusCode, 503);
  assert.equal(response.json().error, 'SERVICE_UNAVAILABLE');
  assert.equal(deviceCalls.count, 0);
});

interface FakeTransactionControl {
  /** Error raised once withTransaction gives up (after the driver's own retries). */
  failure: unknown;
  /** Error raised by startSession instead of returning a session. */
  startFailure: unknown;
  attempts: number;
  sessionsEnded: number;
}

/**
 * Presents the default connection as connected and replaces sessions with a fake whose
 * withTransaction rejects with `control.failure` without running the work (no real I/O).
 */
function simulateConnectedTransactions(t: TestContext): FakeTransactionControl {
  const control: FakeTransactionControl = {
    failure: undefined,
    startFailure: undefined,
    attempts: 0,
    sessionsEnded: 0,
  };
  const connection = mongoose.connection;
  Object.defineProperty(connection, 'readyState', { configurable: true, get: () => 1 });
  t.after(() => {
    Reflect.deleteProperty(connection, 'readyState');
  });
  t.mock.method(connection, 'startSession', async () => {
    if (control.startFailure !== undefined) {
      throw control.startFailure;
    }
    const session = {
      async withTransaction() {
        control.attempts += 1;
        throw control.failure;
      },
      async endSession() {
        control.sessionsEnded += 1;
      },
    };
    return session as unknown as ClientSession;
  });
  return control;
}

test('runInVehicleTransaction: confirmed connectivity failures become DATABASE_UNAVAILABLE; other errors pass through unchanged', async (t) => {
  const control = simulateConnectedTransactions(t);
  const ownerId = new Types.ObjectId();
  const isUnavailable = (error: unknown) =>
    error instanceof VehicleServiceError &&
    error.code === 'DATABASE_UNAVAILABLE' &&
    error.message === 'Vehicle database unavailable';

  const unavailable = [
    new mongoose.mongo.MongoNetworkError('connection reset'),
    new mongoose.mongo.MongoNetworkTimeoutError('socket timeout'),
    new mongoose.mongo.MongoNotConnectedError('client not connected'),
    new mongoose.mongo.MongoTopologyClosedError('topology closed'),
  ];
  for (const failure of unavailable) {
    control.failure = failure;
    await assert.rejects(() => createVehicle(ownerId, { name: 'Outage Sedan' }), isUnavailable);
  }

  // Write conflicts that outlast the driver retries, business errors, and programming errors
  // are not availability problems and keep their identity.
  const writeConflict = new mongoose.mongo.MongoServerError({
    message: 'WriteConflict',
    code: 112,
    errorLabels: ['TransientTransactionError'],
  });
  const duplicate = new mongoose.mongo.MongoServerError({ message: 'E11000', code: 11000 });
  const business = new VehicleServiceError('CONFLICT', 'Vehicle state changed');
  const bug = new TypeError('bug');
  const generic = new mongoose.mongo.MongoError('generic driver error');
  for (const failure of [writeConflict, duplicate, business, bug, generic]) {
    control.failure = failure;
    await assert.rejects(
      () => createVehicle(ownerId, { name: 'Passthrough Sedan' }),
      (error: unknown) => error === failure,
    );
  }
  assert.equal(control.sessionsEnded, control.attempts, 'every session is ended');

  // Validation happens before any transaction and is never reclassified.
  const attemptsBefore = control.attempts;
  await assert.rejects(
    () => createVehicle(ownerId, { name: '' }),
    (error: unknown) => error instanceof VehicleServiceError && error.code === 'VALIDATION_ERROR',
  );
  assert.equal(control.attempts, attemptsBefore);

  // A session that cannot even be started is classified the same way.
  control.startFailure = new mongoose.mongo.MongoNotConnectedError('client closed');
  await assert.rejects(() => createVehicle(ownerId, { name: 'No Session Sedan' }), isUnavailable);
  control.startFailure = new TypeError('session bug');
  await assert.rejects(
    () => createVehicle(ownerId, { name: 'No Session Sedan' }),
    (error: unknown) => error === control.startFailure,
  );
});

test('runInVehicleTransaction: other transactional operations share the classification (createAccessGrant)', async (t) => {
  const control = simulateConnectedTransactions(t);
  const vehicleId = new Types.ObjectId();
  const resourceId = new Types.ObjectId();
  const input = {
    vehicleId,
    membershipId: new Types.ObjectId(),
    subjectUserId: new Types.ObjectId(),
    actorUserId: new Types.ObjectId(),
    scopeType: 'DEVICE' as const,
    scopeResourceId: resourceId,
    verifiedResourceBinding: createVerifiedExternalResourceBinding({
      scopeType: 'DEVICE',
      resourceId,
      vehicleId,
      isActive: true,
    }),
    permissions: ['device:read'],
  };
  control.failure = new mongoose.mongo.MongoNetworkError('reset');
  await assert.rejects(
    () => createAccessGrant(input),
    (error: unknown) =>
      error instanceof VehicleServiceError && error.code === 'DATABASE_UNAVAILABLE',
  );
  assert.equal(control.attempts, 1);

  // Incompatible permissions are rejected before any transaction is attempted.
  await assert.rejects(
    () =>
      createAccessGrant({
        ...input,
        scopeType: 'VEHICLE',
        scopeResourceId: null,
        verifiedResourceBinding: undefined,
        permissions: ['device:read'],
      }),
    (error: unknown) => error instanceof VehicleServiceError && error.code === 'VALIDATION_ERROR',
  );
  assert.equal(control.attempts, 1);
});

test('POST /vehicles maps a transactional outage to 503 and a programming error to 500', async (t) => {
  t.mock.method(globalThis, 'fetch', async (url: string | URL | Request) => {
    const target = String(url instanceof Request ? url.url : url);
    const body = target.endsWith('/verified') ? { verified: true } : { exists: true };
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  });
  const control = simulateConnectedTransactions(t);
  const app = createVehicleTestApp();
  t.after(async () => app.close());
  const create = () => {
    const payload = Buffer.from(
      JSON.stringify({ userId: String(new Types.ObjectId()), name: 'Route Sedan' }),
    );
    return app.inject({
      method: 'POST',
      url: '/vehicles',
      headers: v2Headers(payload, 'POST', '/vehicles'),
      payload,
    });
  };

  control.failure = new mongoose.mongo.MongoNetworkError('reset');
  const outage = await create();
  assert.equal(outage.statusCode, 503);
  assert.equal(outage.json().error, 'SERVICE_UNAVAILABLE');
  assert.equal(outage.json().message, 'Vehicle database unavailable');
  assert.doesNotMatch(outage.body, /reset/);

  control.failure = new TypeError('bug');
  const bug = await create();
  assert.equal(bug.statusCode, 500);
  assert.equal(control.attempts, 2);
});

test('no production module fabricates external resource bindings (no authoritative source exists yet)', async () => {
  const sourceRoot = path.resolve(import.meta.dirname, '../src');
  const files: string[] = [];
  const walk = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
      } else if (entry.name.endsWith('.ts')) {
        files.push(full);
      }
    }
  };
  await walk(sourceRoot);
  // Any mention (call, alias import, re-export) outside the two known places is a new consumer.
  const mentions = new Map<string, number>();
  for (const file of files) {
    const source = await readFile(file, 'utf8');
    const count = source.match(/createVerifiedExternalResourceBinding/g)?.length ?? 0;
    if (count > 0) {
      mentions.set(path.relative(sourceRoot, file).replaceAll('\\', '/'), count);
    }
  }
  assert.deepEqual([...mentions.keys()].sort(), [
    'services/resource-authorization.service.ts',
    'services/vehicle.service.ts',
  ]);
  const definition = await readFile(
    path.join(sourceRoot, 'services/resource-authorization.service.ts'),
    'utf8',
  );
  assert.equal(
    definition.match(/createVerifiedExternalResourceBinding\s*\(/g)?.length,
    1,
    'only the definition itself',
  );
  // vehicle.service.ts only re-exports the factory for test fixtures; it never calls it.
  const adapter = await readFile(path.join(sourceRoot, 'services/vehicle.service.ts'), 'utf8');
  assert.equal(mentions.get('services/vehicle.service.ts'), 1);
  assert.match(
    adapter,
    /export \{\s*createVerifiedExternalResourceBinding,[^}]*\} from '\.\/resource-authorization\.service\.js';/,
  );
  assert.doesNotMatch(adapter, /createVerifiedExternalResourceBinding\s*\(/);
});
