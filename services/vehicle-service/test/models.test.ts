import assert from 'node:assert/strict';
import test from 'node:test';
import { Types } from 'mongoose';
import { AccessGrantModel } from '../src/models/access-grant.model.js';
import { InvitationModel } from '../src/models/invitation.model.js';
import { MembershipModel } from '../src/models/membership.model.js';
import {
  canTransitionAccessGrantStatus,
  canTransitionInvitationStatus,
  canTransitionMembershipStatus,
  canTransitionVehicleStatus,
} from '../src/models/vehicle-constants.js';
import { VehicleModel } from '../src/models/vehicle.model.js';

test('Vehicle supports multi-brand configurations, incomplete technical specs, and has no Mazda defaults', async () => {
  const ownerId = new Types.ObjectId();

  // Incomplete technical info: only name + owner + explicit creator audit
  const minimal = new VehicleModel({
    name: '  Project Car  ',
    ownerUserId: ownerId,
    createdByUserId: ownerId,
  });
  await minimal.validate();
  assert.equal(minimal.name, 'Project Car');
  assert.equal(minimal.make, null);
  assert.equal(minimal.model, null);
  assert.equal(minimal.generation, null);
  assert.equal(minimal.trim, null);
  assert.equal(minimal.year, null);
  assert.equal(minimal.bodyStyle, null);
  assert.equal(minimal.engine, null);
  assert.equal(minimal.transmission, null);
  assert.equal(minimal.fuelType, null);
  assert.equal(minimal.status, 'ACTIVE');
  assert.equal(minimal.archivedAt, null);

  // Diverse manufacturers, body styles, powertrains, transmissions, and fuels
  const configs = [
    {
      name: 'Work Pickup',
      make: 'Ford',
      model: 'Ranger',
      generation: 'T6',
      trim: 'XLT 4x4',
      year: 2022,
      bodyStyle: 'pickup',
      engine: '3.2L Duratorq TDCi',
      transmission: '6-speed manual',
      fuelType: 'diesel',
    },
    {
      name: 'Family Crossover',
      make: 'Toyota',
      model: 'RAV4',
      generation: 'XA50',
      trim: 'Limited Hybrid',
      year: 2023,
      bodyStyle: 'suv',
      engine: '2.5L A25A-FXS Hybrid',
      transmission: 'e-CVT',
      fuelType: 'hybrid',
    },
    {
      name: 'City EV',
      make: 'BYD',
      model: 'Dolphin',
      generation: 'EA1',
      trim: 'GS',
      year: 2025,
      bodyStyle: 'hatchback',
      engine: '70 kW Permanent Magnet',
      transmission: 'single-speed reduction',
      fuelType: 'electric',
    },
  ];

  for (const spec of configs) {
    const doc = new VehicleModel({ ...spec, ownerUserId: ownerId, createdByUserId: ownerId });
    await doc.validate();
    assert.equal(doc.make, spec.make);
    assert.equal(doc.bodyStyle, spec.bodyStyle);
    assert.equal(doc.transmission, spec.transmission);
    assert.equal(doc.fuelType, spec.fuelType);
  }
});

test('Vehicle requires explicit createdByUserId and enforces ACTIVE vs ARCHIVED lifecycle invariants', async () => {
  const ownerId = new Types.ObjectId();

  // Do NOT fabricate createdByUserId automatically from ownerUserId
  const missingAuditActor = new VehicleModel({
    name: 'Unattributed Vehicle',
    ownerUserId: ownerId,
  });
  await assert.rejects(missingAuditActor.validate());

  // Non-integer year rejected
  const floatYear = new VehicleModel({
    name: 'Float Year',
    year: 2020.5,
    ownerUserId: ownerId,
    createdByUserId: ownerId,
  });
  await assert.rejects(floatYear.validate());

  // ARCHIVED without audit fields rejected
  const invalidArchived = new VehicleModel({
    name: 'Archived Without Actor',
    ownerUserId: ownerId,
    createdByUserId: ownerId,
    status: 'ARCHIVED',
  });
  await assert.rejects(invalidArchived.validate());

  // Valid ARCHIVED state
  const validArchived = new VehicleModel({
    name: 'Retired Coupe',
    ownerUserId: ownerId,
    createdByUserId: ownerId,
    status: 'ARCHIVED',
    archivedAt: new Date(),
    archivedByUserId: ownerId,
    archiveReason: 'Sold vehicle',
  });
  await validArchived.validate();
});

test('Membership enforces OWNER protection, explicit audit actors, and known non-wildcard permissions', async () => {
  const vehicleId = new Types.ObjectId();
  const ownerId = new Types.ObjectId();
  const memberId = new Types.ObjectId();

  // Missing grantedByUserId must fail (no fabricated default)
  const missingGrantActor = new MembershipModel({
    vehicleId,
    userId: memberId,
    role: 'MEMBER',
    permissions: ['vehicle:read'],
  });
  await assert.rejects(missingGrantActor.validate());

  // OWNER cannot be SUSPENDED or REVOKED
  for (const invalidStatus of ['SUSPENDED', 'REVOKED'] as const) {
    const badOwner = new MembershipModel({
      vehicleId,
      userId: ownerId,
      role: 'OWNER',
      status: invalidStatus,
      grantedByUserId: ownerId,
      suspendedAt: invalidStatus === 'SUSPENDED' ? new Date() : null,
      suspendedByUserId: invalidStatus === 'SUSPENDED' ? ownerId : null,
      revokedAt: invalidStatus === 'REVOKED' ? new Date() : null,
      revokedByUserId: invalidStatus === 'REVOKED' ? ownerId : null,
    });
    await assert.rejects(badOwner.validate());
  }

  // MEMBER cannot hold owner-reserved, wildcard, duplicate, or unknown permissions
  for (const badPerms of [
    ['*'],
    ['vehicle:*'],
    ['vehicle:owner'],
    ['vehicle:archive'],
    ['membership:manage'],
    ['access-grant:manage'],
    ['unknown:capability'],
    ['vehicle:read', 'vehicle:read'],
  ]) {
    const badMember = new MembershipModel({
      vehicleId,
      userId: memberId,
      role: 'MEMBER',
      permissions: badPerms,
      grantedByUserId: ownerId,
    });
    await assert.rejects(
      badMember.validate(),
      `Expected rejection for ${JSON.stringify(badPerms)}`,
    );
  }

  // Valid SUSPENDED and REVOKED MEMBER states
  const suspended = new MembershipModel({
    vehicleId,
    userId: memberId,
    role: 'MEMBER',
    permissions: ['vehicle:read'],
    status: 'SUSPENDED',
    grantedByUserId: ownerId,
    suspendedAt: new Date(),
    suspendedByUserId: ownerId,
    suspensionReason: 'Temporary hold',
  });
  await suspended.validate();

  const revoked = new MembershipModel({
    vehicleId,
    userId: memberId,
    role: 'MEMBER',
    permissions: ['vehicle:read'],
    status: 'REVOKED',
    grantedByUserId: ownerId,
    revokedAt: new Date(),
    revokedByUserId: ownerId,
    revokeReason: 'Access ended',
  });
  await revoked.validate();
});

test('Invitation blocks self-invitations, enforces MEMBER targetRole, and omits destructive TTL index', async () => {
  const vehicleId = new Types.ObjectId();
  const inviterId = new Types.ObjectId();
  const inviteeId = new Types.ObjectId();
  const expiresAt = new Date(Date.now() + 86_400_000);

  const selfInvite = new InvitationModel({
    vehicleId,
    inviterUserId: inviterId,
    inviteeUserId: inviterId,
    permissions: ['vehicle:read'],
    expiresAt,
  });
  await assert.rejects(selfInvite.validate());

  const acceptedMismatch = new InvitationModel({
    vehicleId,
    inviterUserId: inviterId,
    inviteeUserId: inviteeId,
    permissions: ['vehicle:read'],
    status: 'ACCEPTED',
    acceptedAt: new Date(),
    acceptedByUserId: inviterId,
    expiresAt,
  });
  await assert.rejects(acceptedMismatch.validate());

  const validPending = new InvitationModel({
    vehicleId,
    inviterUserId: inviterId,
    inviteeUserId: inviteeId,
    permissions: ['vehicle:read'],
    expiresAt,
  });
  await validPending.validate();
  assert.equal(validPending.targetRole, 'MEMBER');

  const invitationIndexes = InvitationModel.schema.indexes();
  assert.equal(
    invitationIndexes.some(([, options]) => options?.expireAfterSeconds !== undefined),
    false,
    'Invitation schema must not declare any destructive TTL index',
  );
  assert.equal(
    invitationIndexes.some(
      ([fields, options]) =>
        fields.vehicleId === 1 &&
        fields.inviteeUserId === 1 &&
        options?.unique === true &&
        JSON.stringify(options.partialFilterExpression) === JSON.stringify({ status: 'PENDING' }),
    ),
    true,
  );
});

test('AccessGrant enforces scopeResourceId rules, BLE expiration, known permissions, and non-restrictive indexes', async () => {
  const vehicleId = new Types.ObjectId();
  const membershipId = new Types.ObjectId();
  const ownerId = new Types.ObjectId();
  const memberId = new Types.ObjectId();
  const deviceId = new Types.ObjectId();
  const moduleId = new Types.ObjectId();
  const now = new Date();
  const future = new Date(now.getTime() + 3_600_000);

  // Valid DEVICE BLE_OFFLINE grant with explicit expiration
  const bleDeviceGrant = new AccessGrantModel({
    vehicleId,
    membershipId,
    subjectUserId: memberId,
    scopeType: 'DEVICE',
    scopeResourceId: deviceId,
    channel: 'BLE_OFFLINE',
    permissions: ['device:connect', 'device:command'],
    startsAt: now,
    expiresAt: future,
    grantedByUserId: ownerId,
  });
  await bleDeviceGrant.validate();

  // Valid MODULE ONLINE grant without expiration
  const onlineModuleGrant = new AccessGrantModel({
    vehicleId,
    membershipId,
    subjectUserId: memberId,
    scopeType: 'MODULE',
    scopeResourceId: moduleId,
    channel: 'ONLINE',
    permissions: ['module:read', 'module:actuate'],
    startsAt: now,
    expiresAt: null,
    grantedByUserId: ownerId,
  });
  await onlineModuleGrant.validate();

  // BLE_OFFLINE and ANY without expiresAt must fail
  for (const channel of ['BLE_OFFLINE', 'ANY'] as const) {
    const missingExpiry = new AccessGrantModel({
      vehicleId,
      membershipId,
      subjectUserId: memberId,
      scopeType: 'DEVICE',
      scopeResourceId: deviceId,
      channel,
      permissions: ['device:connect'],
      startsAt: now,
      expiresAt: null,
      grantedByUserId: ownerId,
    });
    await assert.rejects(missingExpiry.validate());
  }

  // VEHICLE scope with non-null scopeResourceId must fail; DEVICE/MODULE with null must fail
  await assert.rejects(
    new AccessGrantModel({
      vehicleId,
      membershipId,
      subjectUserId: memberId,
      scopeType: 'VEHICLE',
      scopeResourceId: deviceId,
      channel: 'ONLINE',
      permissions: ['vehicle:read'],
      grantedByUserId: ownerId,
    }).validate(),
  );
  await assert.rejects(
    new AccessGrantModel({
      vehicleId,
      membershipId,
      subjectUserId: memberId,
      scopeType: 'DEVICE',
      scopeResourceId: null,
      channel: 'ONLINE',
      permissions: ['device:read'],
      grantedByUserId: ownerId,
    }).validate(),
  );

  // Cross-scope, wildcard, owner-reserved, or unknown permissions must fail
  for (const badPerms of [
    [],
    ['*'],
    ['device:*'],
    ['vehicle:owner'],
    ['vehicle:manage'],
    ['module:actuate'], // invalid for DEVICE scope
    ['unknown:action'],
  ]) {
    await assert.rejects(
      new AccessGrantModel({
        vehicleId,
        membershipId,
        subjectUserId: memberId,
        scopeType: 'DEVICE',
        scopeResourceId: deviceId,
        channel: 'ONLINE',
        permissions: badPerms,
        grantedByUserId: ownerId,
      }).validate(),
    );
  }

  // Verify no unique index restricts multiple grants per scope/channel, and no unique index on userId/ownerUserId alone
  const grantIndexes = AccessGrantModel.schema.indexes();
  assert.equal(
    grantIndexes.some(([, options]) => options?.unique === true),
    false,
  );

  const vehicleIndexes = VehicleModel.schema.indexes();
  assert.equal(
    vehicleIndexes.some(([, options]) => options?.unique === true),
    false,
  );

  const membershipIndexes = MembershipModel.schema.indexes();
  assert.equal(
    membershipIndexes.some(
      ([fields, options]) =>
        fields.userId === 1 && Object.keys(fields).length === 1 && options?.unique,
    ),
    false,
  );
});

test('explicit transition matrices enforce terminal states across all four models', () => {
  assert.equal(canTransitionVehicleStatus('ACTIVE', 'ARCHIVED'), true);
  assert.equal(canTransitionVehicleStatus('ARCHIVED', 'ACTIVE'), false);

  assert.equal(canTransitionMembershipStatus('ACTIVE', 'SUSPENDED'), true);
  assert.equal(canTransitionMembershipStatus('SUSPENDED', 'ACTIVE'), true);
  assert.equal(canTransitionMembershipStatus('SUSPENDED', 'REVOKED'), true);
  assert.equal(canTransitionMembershipStatus('REVOKED', 'ACTIVE'), false);
  assert.equal(canTransitionMembershipStatus('REVOKED', 'SUSPENDED'), false);

  assert.equal(canTransitionInvitationStatus('PENDING', 'ACCEPTED'), true);
  assert.equal(canTransitionInvitationStatus('PENDING', 'REVOKED'), true);
  assert.equal(canTransitionInvitationStatus('PENDING', 'EXPIRED'), true);
  assert.equal(canTransitionInvitationStatus('ACCEPTED', 'PENDING'), false);
  assert.equal(canTransitionInvitationStatus('REVOKED', 'PENDING'), false);
  assert.equal(canTransitionInvitationStatus('EXPIRED', 'ACCEPTED'), false);

  assert.equal(canTransitionAccessGrantStatus('ACTIVE', 'REVOKED'), true);
  assert.equal(canTransitionAccessGrantStatus('ACTIVE', 'EXPIRED'), true);
  assert.equal(canTransitionAccessGrantStatus('REVOKED', 'ACTIVE'), false);
  assert.equal(canTransitionAccessGrantStatus('EXPIRED', 'ACTIVE'), false);
});
