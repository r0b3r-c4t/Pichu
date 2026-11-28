import assert from 'node:assert/strict';
import test from 'node:test';
import {
  DEVICE_LINK_PROTOCOL_VERSION,
  DEVICE_METADATA_FIELDS,
  DEVICE_REVOCATION_REASONS,
  deviceDetailResponseSchema,
  deviceDetailSchema,
  deviceIdentityResponseSchema,
  deviceIdentifierSchema,
  deviceLinkChallengeSchema,
  deviceLinkCompletionSchema,
  deviceMetadataInputSchema,
  deviceMetadataSchema,
  deviceMetadataUpdateRequestSchema,
  deviceReferenceParamsSchema,
  deviceRegistrationRequestSchema,
  deviceRegistrationResponseSchema,
  deviceRevocationRequestSchema,
  deviceRevocationResponseSchema,
  deviceRevocationSchema,
  deviceSummarySchema,
  internalDeviceCollectionQuerySchema,
  internalDeviceRecordSchema,
  internalVehicleDeviceMetadataUpdateRequestSchema,
  publicDeviceChallengeRequestSchema,
  publicDeviceRegistrationRequestSchema,
  vehicleDeviceChallengeResponseSchema,
  vehicleDeviceLinkResponseSchema,
  vehicleDeviceListQuerySchema,
  vehicleDeviceListResponseSchema,
  vehicleDeviceMetadataUpdateResponseSchema,
  vehicleDeviceParamsSchema,
  vehicleDeviceRevokeResponseSchema,
  invitationAcceptRequestSchema,
  invitationAcceptResponseSchema,
  internalInvitationCreateRequestSchema,
  invitationParamsSchema,
  publicInvitationCreateRequestSchema,
  invitationCreateResponseSchema,
  internalVehicleArchiveRequestSchema,
  internalVehicleCreateRequestSchema,
  internalVehicleGetQuerySchema,
  internalVehicleListQuerySchema,
  internalVehicleUpdateRequestSchema,
  internalInvitationRevokeRequestSchema,
  internalMemberLeaveRequestSchema,
  internalMemberListQuerySchema,
  internalMemberPermissionsUpdateRequestSchema,
  internalMemberReactivateRequestSchema,
  internalMemberTransitionRequestSchema,
  internalReceivedInvitationListQuerySchema,
  internalVehicleInvitationListQuerySchema,
  invitationAdminViewSchema,
  invitationRevokeParamsSchema,
  invitationRevokeRequestSchema,
  invitationRevokeResponseSchema,
  memberLeaveRequestSchema,
  memberLeaveResponseSchema,
  memberListQuerySchema,
  memberListResponseSchema,
  memberMutationResponseSchema,
  memberParamsSchema,
  memberPermissionsUpdateRequestSchema,
  memberReactivateRequestSchema,
  memberTransitionRequestSchema,
  memberViewSchema,
  membershipSchema,
  membershipPermissionSchema,
  membershipRoleSchema,
  membershipStatusSchema,
  receivedInvitationListQuerySchema,
  receivedInvitationListResponseSchema,
  receivedInvitationViewSchema,
  vehicleInvitationListQuerySchema,
  vehicleInvitationListResponseSchema,
  VEHICLE_MUTABLE_FIELDS,
  vehicleAccessViewSchema,
  vehicleArchiveRequestSchema,
  vehicleArchiveResponseSchema,
  vehicleCreateRequestSchema,
  vehicleCreateResponseSchema,
  vehicleDetailResponseSchema,
  vehicleDeviceRegistrationResponseSchema,
  vehicleListQuerySchema,
  vehicleListResponseSchema,
  vehicleOwnerViewSchema,
  vehicleParamsSchema,
  vehicleSummarySchema,
  vehicleUpdateRequestSchema,
  vehicleUpdateResponseSchema,
} from '../src/index.js';

const vehicleId = '507f1f77bcf86cd799439011';
const userId = '507f1f77bcf86cd799439012';
const deviceId = '507f1f77bcf86cd799439013';
const credentialId = '507f1f77bcf86cd799439014';
const membershipId = '507f1f77bcf86cd799439015';
const challengeId = '507f1f77bcf86cd799439016';
const publicKey = '-----BEGIN PUBLIC KEY-----\n' + 'A'.repeat(80) + '\n-----END PUBLIC KEY-----';

const sampleDeviceDetail = {
  deviceId,
  vehicleId,
  identifier: 'esp32-mazda-3',
  status: 'PENDING' as const,
  operational: false,
  credential: {
    credentialId,
    keyId: `dk_${'A'.repeat(22)}`,
    algorithm: 'Ed25519' as const,
    fingerprint: `sha256:${'a'.repeat(64)}`,
    status: 'ACTIVE' as const,
    usable: true,
    activatedAt: '2026-11-26T12:00:00.000Z',
    expiresAt: null,
    revokedAt: null,
  },
  connectivity: { lastSeenAt: null },
  metadata: {
    name: null,
    manufacturer: null,
    hardwareModel: null,
    hardwareRevision: null,
    firmwareVersion: null,
    serialNumber: null,
  },
  createdAt: '2026-11-26T12:00:00.000Z',
  updatedAt: '2026-11-26T12:00:00.000Z',
  linkedAt: null,
  revokedAt: null,
  revocationReason: null,
};

const summary = {
  id: vehicleId,
  name: 'Persisted Mazda 3',
  make: 'Mazda',
  model: '3',
  generation: 'BL',
  trim: 's',
  year: 2011,
  bodyStyle: 'sedan',
  engine: '2.0 MZR',
  transmission: 'automatic',
  fuelType: 'gasoline',
  ownerUserId: userId,
};

const textLimits: Array<[string, number]> = [
  ['make', 80],
  ['model', 80],
  ['generation', 60],
  ['trim', 80],
  ['bodyStyle', 60],
  ['engine', 80],
  ['transmission', 60],
  ['fuelType', 60],
];

test('enriched vehicle responses expose ten intrinsic fields plus a contextual role', () => {
  const data = { ...summary, role: 'OWNER' as const };
  assert.equal(
    vehicleCreateResponseSchema.safeParse({
      vehicleId,
      message: 'Vehicle created',
      data,
      requestId: 'request-42',
    }).success,
    true,
  );
  assert.equal(
    vehicleDetailResponseSchema.safeParse({ ...data, requestId: 'request-42' }).success,
    true,
  );
  assert.equal(
    vehicleDetailResponseSchema.safeParse({ ...summary, role: 'MEMBER', requestId: 'r' }).success,
    true,
  );
  assert.equal(vehicleDetailResponseSchema.safeParse({ ...summary }).success, false);
  assert.equal(vehicleAccessViewSchema.safeParse({ ...summary, role: 'ADMIN' }).success, false);
  assert.equal(vehicleOwnerViewSchema.safeParse({ ...summary, role: 'MEMBER' }).success, false);
  assert.equal(vehicleSummarySchema.safeParse(summary).success, true);
  assert.equal(vehicleSummarySchema.safeParse({ ...summary, role: 'OWNER' }).success, false);
  assert.equal(
    vehicleCreateResponseSchema.safeParse({ vehicleId, data: { ...data, __v: 1 } }).success,
    false,
  );
  assert.equal(
    vehicleCreateResponseSchema.safeParse({ vehicleId, data: { ...summary, role: 'MEMBER' } })
      .success,
    false,
  );
  assert.equal(
    vehicleUpdateResponseSchema.safeParse({ vehicleId, data, requestId: 'r' }).success,
    true,
  );
  assert.equal(vehicleUpdateResponseSchema.safeParse({ vehicleId }).success, false);
  assert.equal(
    vehicleArchiveResponseSchema.safeParse({
      vehicleId,
      status: 'ARCHIVED',
      archivedAt: '2026-11-26T12:00:00.000Z',
      message: 'Vehicle archived',
      requestId: 'r',
    }).success,
    true,
  );
  assert.equal(
    vehicleArchiveResponseSchema.safeParse({
      vehicleId,
      status: 'ACTIVE',
      archivedAt: '2026-11-26T12:00:00.000Z',
    }).success,
    false,
  );
  for (const field of Object.keys(summary)) {
    const withoutField = Object.fromEntries(
      Object.entries(summary).filter(([key]) => key !== field),
    );
    assert.equal(
      vehicleSummarySchema.safeParse(withoutField).success,
      false,
      `${field} must be required in the summary`,
    );
  }
  assert.equal(
    vehicleDeviceRegistrationResponseSchema.safeParse({
      deviceId,
      status: 'PENDING',
      message: 'Device registration accepted',
      data: sampleDeviceDetail,
      requestId: 'request-42',
    }).success,
    true,
  );
});

test('vehicle creation and summary use explicit identifiers and closed DTOs', () => {
  assert.deepEqual(
    vehicleCreateRequestSchema.parse({
      name: ' Mazda 3 ',
      make: 'Mazda',
      model: '3',
      year: 2011,
      engine: '2.0',
    }),
    { name: 'Mazda 3', make: 'Mazda', model: '3', year: 2011, engine: '2.0' },
  );
  assert.equal(vehicleCreateRequestSchema.safeParse({ name: 'Mazda 3', userId }).success, false);
  for (const forbidden of ['ownerUserId', 'status', 'role', 'createdByUserId', 'archivedAt']) {
    assert.equal(
      vehicleCreateRequestSchema.safeParse({ name: 'Mazda 3', [forbidden]: userId }).success,
      false,
      `${forbidden} must be rejected on create`,
    );
  }
  assert.equal(vehicleCreateRequestSchema.safeParse({ name: '' }).success, false);
  assert.equal(vehicleCreateRequestSchema.safeParse({ name: '   ' }).success, false);
  assert.equal(vehicleCreateRequestSchema.safeParse({ name: null }).success, false);
  assert.equal(vehicleCreateRequestSchema.safeParse({}).success, false);
  assert.equal(vehicleCreateRequestSchema.safeParse({ name: 'x'.repeat(120) }).success, true);
  assert.equal(vehicleCreateRequestSchema.safeParse({ name: 'x'.repeat(121) }).success, false);
  assert.equal(
    vehicleCreateRequestSchema.safeParse({ name: `  ${'x'.repeat(120)}  ` }).success,
    true,
  );
  assert.equal(vehicleCreateRequestSchema.safeParse({ name: 'Mazda\t3' }).success, false);
  assert.equal(vehicleCreateRequestSchema.safeParse({ name: 'Mazda 3\n' }).success, false);
  assert.equal(vehicleCreateRequestSchema.safeParse({ name: '\u0000Mazda' }).success, false);
  assert.equal(vehicleCreateRequestSchema.safeParse({ name: 'Mazda\u007f' }).success, false);
  assert.equal(vehicleCreateResponseSchema.safeParse({ vehicleId }).success, true);
  assert.equal(
    vehicleSummarySchema.safeParse({ ...summary, id: undefined, vehicleId }).success,
    false,
  );

  for (const [field, max] of textLimits) {
    assert.equal(
      vehicleCreateRequestSchema.safeParse({ name: 'Car', [field]: 'x'.repeat(max) }).success,
      true,
      `${field} accepts ${max} characters`,
    );
    assert.equal(
      vehicleCreateRequestSchema.safeParse({ name: 'Car', [field]: 'x'.repeat(max + 1) }).success,
      false,
      `${field} rejects ${max + 1} characters`,
    );
    assert.equal(
      vehicleCreateRequestSchema.safeParse({ name: 'Car', [field]: null }).success,
      true,
      `${field} accepts null`,
    );
    assert.equal(
      vehicleCreateRequestSchema.safeParse({ name: 'Car', [field]: ' ' }).success,
      false,
      `${field} rejects whitespace-only values`,
    );
    assert.equal(
      vehicleCreateRequestSchema.safeParse({ name: 'Car', [field]: '\tvalue' }).success,
      false,
      `${field} rejects control characters before trimming`,
    );
  }
  for (const [year, valid] of [
    [1886, true],
    [2100, true],
    [1885, false],
    [2101, false],
    [2011.5, false],
  ] as const) {
    assert.equal(vehicleCreateRequestSchema.safeParse({ name: 'Car', year }).success, valid);
  }
  assert.equal(vehicleCreateRequestSchema.safeParse({ name: 'Car', year: '2011' }).success, false);
  assert.equal(internalVehicleCreateRequestSchema.safeParse({ name: 'Car', userId }).success, true);
  assert.equal(internalVehicleCreateRequestSchema.safeParse({ name: 'Car' }).success, false);
});

test('vehicle update requires at least one closed descriptive field and keeps null semantics', () => {
  assert.deepEqual(VEHICLE_MUTABLE_FIELDS, [
    'name',
    'make',
    'model',
    'generation',
    'trim',
    'year',
    'bodyStyle',
    'engine',
    'transmission',
    'fuelType',
  ]);
  assert.equal(vehicleUpdateRequestSchema.safeParse({}).success, false);
  assert.deepEqual(vehicleUpdateRequestSchema.parse({ make: null }), { make: null });
  assert.deepEqual(vehicleUpdateRequestSchema.parse({ name: ' Daily ' }), { name: 'Daily' });
  assert.equal(vehicleUpdateRequestSchema.safeParse({ name: null }).success, false);
  assert.equal(vehicleUpdateRequestSchema.safeParse({ name: '  ' }).success, false);
  assert.equal(vehicleUpdateRequestSchema.safeParse({ trim: 'S\r' }).success, false);
  assert.equal(vehicleUpdateRequestSchema.safeParse({ year: null }).success, true);
  for (const forbidden of ['userId', 'ownerUserId', 'status', 'role', 'updatedByUserId', 'id']) {
    assert.equal(
      vehicleUpdateRequestSchema.safeParse({ name: 'Car', [forbidden]: userId }).success,
      false,
      `${forbidden} must be rejected on update`,
    );
  }
  assert.equal(internalVehicleUpdateRequestSchema.safeParse({ userId }).success, false);
  assert.equal(
    internalVehicleUpdateRequestSchema.safeParse({ userId, fuelType: null }).success,
    true,
  );
  assert.equal(
    internalVehicleUpdateRequestSchema.safeParse({ userId, name: 'Car', status: 'ARCHIVED' })
      .success,
    false,
  );
});

test('vehicle archive accepts an optional bounded reason only', () => {
  assert.equal(vehicleArchiveRequestSchema.safeParse({}).success, true);
  assert.deepEqual(vehicleArchiveRequestSchema.parse({ reason: ' Sold ' }), { reason: 'Sold' });
  assert.equal(vehicleArchiveRequestSchema.safeParse({ reason: 'x'.repeat(256) }).success, true);
  assert.equal(vehicleArchiveRequestSchema.safeParse({ reason: 'x'.repeat(257) }).success, false);
  assert.equal(vehicleArchiveRequestSchema.safeParse({ reason: '' }).success, false);
  assert.equal(vehicleArchiveRequestSchema.safeParse({ reason: null }).success, false);
  assert.equal(vehicleArchiveRequestSchema.safeParse({ reason: 'Sold\n' }).success, false);
  assert.equal(vehicleArchiveRequestSchema.safeParse({ userId }).success, false);
  assert.equal(vehicleArchiveRequestSchema.safeParse({ status: 'ARCHIVED' }).success, false);
  assert.equal(internalVehicleArchiveRequestSchema.safeParse({ userId }).success, true);
  assert.equal(
    internalVehicleArchiveRequestSchema.safeParse({ userId, reason: 'Sold' }).success,
    true,
  );
});

test('vehicle pagination and invitation DTOs validate boundaries', () => {
  assert.deepEqual(vehicleListQuerySchema.parse({}), { limit: 20 });
  assert.deepEqual(vehicleListQuerySchema.parse({ limit: '1' }), { limit: 1 });
  assert.equal(vehicleListQuerySchema.safeParse({ limit: 0 }).success, false);
  assert.equal(vehicleListQuerySchema.safeParse({ limit: 100 }).success, true);
  assert.equal(vehicleListQuerySchema.safeParse({ limit: 101 }).success, false);
  assert.equal(vehicleListQuerySchema.safeParse({ userId }).success, false);
  assert.equal(vehicleListQuerySchema.safeParse({ role: 'OWNER' }).success, true);
  assert.equal(vehicleListQuerySchema.safeParse({ role: 'MEMBER' }).success, true);
  assert.equal(vehicleListQuerySchema.safeParse({ role: 'ADMIN' }).success, false);
  assert.equal(vehicleListQuerySchema.safeParse({ cursor: 'eyJ2IjoxfQ' }).success, true);
  assert.equal(vehicleListQuerySchema.safeParse({ cursor: 'a'.repeat(256) }).success, true);
  assert.equal(vehicleListQuerySchema.safeParse({ cursor: 'a'.repeat(257) }).success, false);
  assert.equal(vehicleListQuerySchema.safeParse({ cursor: 'abc+/=' }).success, false);
  assert.equal(vehicleListQuerySchema.safeParse({ cursor: '' }).success, false);
  assert.equal(
    internalVehicleListQuerySchema.safeParse({ userId, limit: '5', role: 'MEMBER' }).success,
    true,
  );
  assert.equal(internalVehicleGetQuerySchema.safeParse({ userId }).success, true);
  assert.equal(internalVehicleGetQuerySchema.safeParse({ userId, extra: '1' }).success, false);
  assert.equal(
    vehicleListResponseSchema.safeParse({ vehicles: [], page: { nextCursor: null } }).success,
    true,
  );
  assert.equal(
    vehicleListResponseSchema.safeParse({
      vehicles: [{ ...summary, role: 'MEMBER' }],
      page: { nextCursor: 'eyJ2IjoxfQ' },
      requestId: 'r',
    }).success,
    true,
  );
  assert.equal(
    vehicleListResponseSchema.safeParse({ vehicles: [summary], page: { nextCursor: null } })
      .success,
    false,
  );
  assert.equal(vehicleListResponseSchema.safeParse({ vehicles: [] }).success, false);
  assert.equal(
    publicInvitationCreateRequestSchema.safeParse({
      inviteeUserId: '507f1f77bcf86cd799439014',
      permissions: ['vehicle:read'],
    }).success,
    true,
  );
  assert.equal(
    publicInvitationCreateRequestSchema.safeParse({
      inviterUserId: userId,
      inviteeUserId: '507f1f77bcf86cd799439014',
      permissions: ['vehicle:read'],
    }).success,
    false,
  );
  assert.equal(
    publicInvitationCreateRequestSchema.safeParse({
      inviteeUserId: '507f1f77bcf86cd799439014',
      permissions: ['vehicle:read'],
      extra: true,
    }).success,
    false,
  );
  assert.equal(
    internalInvitationCreateRequestSchema.safeParse({
      inviterUserId: userId,
      inviteeUserId: userId,
      permissions: ['vehicle:read'],
    }).success,
    true,
  );
  assert.equal(
    internalInvitationCreateRequestSchema.safeParse({
      inviterUserId: userId,
      inviteeUserId: userId,
      permissions: ['x'.repeat(65)],
    }).success,
    false,
  );
  assert.equal(
    invitationCreateResponseSchema.safeParse({ invitationId: vehicleId, status: 'PENDING' })
      .success,
    true,
  );
  assert.equal(invitationAcceptRequestSchema.safeParse({ userId }).success, true);
  assert.equal(
    invitationAcceptResponseSchema.safeParse({ accepted: true, vehicleId }).success,
    true,
  );
  assert.equal(
    invitationAcceptResponseSchema.safeParse({ accepted: true, vehicleId, extra: true }).success,
    false,
  );
  assert.equal(vehicleParamsSchema.safeParse({ vehicleId }).success, true);
  assert.equal(vehicleParamsSchema.safeParse({ vehicleId: 'invalid' }).success, false);
  assert.equal(invitationParamsSchema.safeParse({ invitationId: vehicleId }).success, true);
  assert.equal(invitationParamsSchema.safeParse({ invitationId: 'invalid' }).success, false);
});

test('membership roles and permissions are bounded and explicit', () => {
  assert.equal(membershipRoleSchema.safeParse('OWNER').success, true);
  assert.equal(membershipRoleSchema.safeParse('ADMIN').success, false);
  assert.equal(membershipPermissionSchema.safeParse('vehicle:read').success, true);
  assert.equal(membershipPermissionSchema.safeParse('').success, false);
  const membership = {
    membershipId: deviceId,
    vehicleId,
    userId,
    role: 'MEMBER',
    permissions: ['vehicle:read'],
    status: 'ACTIVE',
  };
  assert.equal(membershipSchema.safeParse(membership).success, true);
  assert.equal(membershipSchema.safeParse({ ...membership, permissions: [] }).success, true);
  assert.equal(membershipSchema.safeParse({ ...membership, owner: true }).success, false);
  assert.equal(membershipSchema.safeParse({ ...membership, id: deviceId }).success, false);
  assert.equal(membershipSchema.safeParse({ ...membership, status: 'DELETED' }).success, false);
  const withoutId: Record<string, unknown> = { ...membership };
  delete withoutId.membershipId;
  assert.equal(membershipSchema.safeParse(withoutId).success, false);
  assert.equal(membershipStatusSchema.safeParse('SUSPENDED').success, true);
  assert.equal(membershipStatusSchema.safeParse('PENDING').success, false);
  const memberView = {
    ...membership,
    createdAt: '2026-11-26T12:00:00.000Z',
    suspendedAt: null,
    revokedAt: null,
  };
  assert.equal(memberViewSchema.safeParse(memberView).success, true);
  assert.equal(
    memberViewSchema.safeParse({ ...memberView, suspendedByUserId: userId }).success,
    false,
  );
  assert.equal(
    memberMutationResponseSchema.safeParse({
      membershipId: deviceId,
      status: 'SUSPENDED',
      data: { ...memberView, status: 'SUSPENDED', suspendedAt: '2026-11-26T12:00:00.000Z' },
    }).success,
    true,
  );
  assert.equal(
    memberLeaveResponseSchema.safeParse({
      membershipId: deviceId,
      status: 'ACTIVE',
      data: membership,
    }).success,
    false,
  );
});

test('membership administration requests reject actor, role, status and audit fields', () => {
  assert.deepEqual(memberPermissionsUpdateRequestSchema.parse({ permissions: [] }), {
    permissions: [],
  });
  assert.equal(
    memberPermissionsUpdateRequestSchema.safeParse({ permissions: ['vehicle:read'] }).success,
    true,
  );
  for (const forbidden of [
    { userId },
    { role: 'OWNER' },
    { status: 'ACTIVE' },
    { vehicleId },
    { grantedByUserId: userId },
    { updatedByUserId: userId },
    { createdAt: '2026-01-01T00:00:00.000Z' },
    { updatedAt: '2026-01-01T00:00:00.000Z' },
    { revokedByUserId: userId },
  ]) {
    assert.equal(
      memberPermissionsUpdateRequestSchema.safeParse({ permissions: [], ...forbidden }).success,
      false,
    );
  }
  assert.equal(memberPermissionsUpdateRequestSchema.safeParse({}).success, false);
  assert.equal(
    memberPermissionsUpdateRequestSchema.safeParse({
      permissions: Array.from({ length: 101 }, () => 'vehicle:read'),
    }).success,
    false,
  );
  assert.equal(
    internalMemberPermissionsUpdateRequestSchema.safeParse({ userId, permissions: [] }).success,
    true,
  );
  assert.equal(memberTransitionRequestSchema.safeParse({}).success, true);
  assert.equal(memberTransitionRequestSchema.safeParse({ reason: 'Lost key' }).success, true);
  assert.equal(memberTransitionRequestSchema.safeParse({ reason: 'x'.repeat(257) }).success, false);
  assert.equal(memberTransitionRequestSchema.safeParse({ reason: 'a\u0000b' }).success, false);
  assert.equal(memberTransitionRequestSchema.safeParse({ userId }).success, false);
  assert.equal(
    internalMemberTransitionRequestSchema.safeParse({ userId, reason: 'Lost key' }).success,
    true,
  );
  assert.equal(memberReactivateRequestSchema.safeParse({}).success, true);
  assert.equal(memberReactivateRequestSchema.safeParse({ reason: 'x' }).success, false);
  assert.equal(internalMemberReactivateRequestSchema.safeParse({ userId }).success, true);
  assert.equal(memberLeaveRequestSchema.safeParse({}).success, false);
  assert.equal(memberLeaveRequestSchema.safeParse(undefined).success, false);
  assert.equal(memberLeaveRequestSchema.safeParse({ membershipId: deviceId }).success, true);
  assert.equal(memberLeaveRequestSchema.safeParse({ membershipId: 'invalid' }).success, false);
  assert.equal(memberLeaveRequestSchema.safeParse({ userId }).success, false);
  assert.equal(
    internalMemberLeaveRequestSchema.safeParse({ userId, membershipId: deviceId }).success,
    true,
  );
  assert.equal(memberParamsSchema.safeParse({ vehicleId, membershipId: deviceId }).success, true);
  assert.equal(memberParamsSchema.safeParse({ vehicleId, membershipId: 'leave' }).success, false);
  assert.equal(invitationRevokeRequestSchema.safeParse({}).success, true);
  assert.equal(invitationRevokeRequestSchema.safeParse({ userId }).success, false);
  assert.equal(
    internalInvitationRevokeRequestSchema.safeParse({ userId, reason: 'Wrong person' }).success,
    true,
  );
  assert.equal(
    invitationRevokeParamsSchema.safeParse({ vehicleId, invitationId: deviceId }).success,
    true,
  );
});

test('invitation and member list queries are bounded and strict', () => {
  for (const schema of [vehicleInvitationListQuerySchema, receivedInvitationListQuerySchema]) {
    assert.deepEqual(schema.parse({}), { limit: 20 });
    assert.equal(schema.safeParse({ limit: '100' }).success, true);
    assert.equal(schema.safeParse({ limit: '101' }).success, false);
    assert.equal(schema.safeParse({ limit: '0' }).success, false);
    assert.equal(schema.safeParse({ status: 'EXPIRED' }).success, true);
    assert.equal(schema.safeParse({ status: 'DECLINED' }).success, false);
    assert.equal(schema.safeParse({ cursor: 'a'.repeat(257) }).success, false);
    assert.equal(schema.safeParse({ userId }).success, false);
  }
  assert.deepEqual(memberListQuerySchema.parse({}), { limit: 20 });
  assert.equal(memberListQuerySchema.safeParse({ status: 'REVOKED' }).success, true);
  assert.equal(memberListQuerySchema.safeParse({ status: 'PENDING' }).success, false);
  assert.equal(memberListQuerySchema.safeParse({ userId }).success, false);
  assert.equal(internalMemberListQuerySchema.safeParse({ userId, limit: '5' }).success, true);
  assert.equal(
    internalVehicleInvitationListQuerySchema.safeParse({ userId, status: 'PENDING' }).success,
    true,
  );
  assert.equal(internalReceivedInvitationListQuerySchema.safeParse({}).success, false);
  const adminView = {
    invitationId: deviceId,
    vehicleId,
    inviterUserId: userId,
    inviteeUserId: '507f1f77bcf86cd799439014',
    permissions: ['vehicle:read'],
    status: 'PENDING',
    expiresAt: '2026-12-03T12:00:00.000Z',
    createdAt: '2026-11-26T12:00:00.000Z',
    acceptedAt: null,
    revokedAt: null,
    revokeReason: null,
  };
  assert.equal(invitationAdminViewSchema.safeParse(adminView).success, true);
  assert.equal(invitationAdminViewSchema.safeParse({ ...adminView, id: deviceId }).success, false);
  assert.equal(
    vehicleInvitationListResponseSchema.safeParse({
      invitations: [adminView],
      page: { nextCursor: null },
    }).success,
    true,
  );
  const receivedView = {
    invitationId: deviceId,
    vehicleId,
    vehicleName: 'Mazda',
    permissions: ['vehicle:read'],
    status: 'PENDING',
    expiresAt: '2026-12-03T12:00:00.000Z',
    createdAt: '2026-11-26T12:00:00.000Z',
  };
  assert.equal(receivedInvitationViewSchema.safeParse(receivedView).success, true);
  assert.equal(
    receivedInvitationViewSchema.safeParse({ ...receivedView, vehicleName: null }).success,
    true,
  );
  assert.equal(
    receivedInvitationViewSchema.safeParse({ ...receivedView, inviterUserId: userId }).success,
    false,
  );
  assert.equal(
    receivedInvitationListResponseSchema.safeParse({ invitations: [receivedView] }).success,
    false,
  );
  assert.equal(
    memberListResponseSchema.safeParse({ members: [], page: { nextCursor: 'eyJ2IjoxfQ' } }).success,
    true,
  );
  assert.equal(
    invitationRevokeResponseSchema.safeParse({
      invitationId: deviceId,
      status: 'REVOKED',
      data: { ...adminView, status: 'REVOKED', revokedAt: adminView.createdAt },
    }).success,
    true,
  );
  assert.equal(
    invitationCreateResponseSchema.safeParse({
      invitationId: deviceId,
      status: 'PENDING',
      data: adminView,
    }).success,
    true,
  );
});

test('device identity is composed consistently around deviceId', () => {
  const identity = {
    deviceId,
    vehicleId,
    identifier: 'esp32-mazda-3',
    status: 'PENDING',
  } as const;
  assert.equal(deviceIdentityResponseSchema.safeParse(identity).success, true);
  assert.equal(deviceSummarySchema.safeParse({ ...identity, lastSeenAt: null }).success, true);
  assert.equal(
    deviceSummarySchema.safeParse({ id: deviceId, ...identity, lastSeenAt: null }).success,
    false,
  );
  assert.equal(deviceIdentifierSchema.safeParse('').success, false);
  assert.equal(deviceIdentifierSchema.safeParse('x'.repeat(129)).success, false);
  assert.equal(deviceReferenceParamsSchema.safeParse({ deviceId }).success, true);
  assert.equal(deviceReferenceParamsSchema.safeParse({ deviceId: 'invalid' }).success, false);
});

test('device registration and revocation DTOs separate identity from textual identifiers', () => {
  const internalRecord = {
    ...sampleDeviceDetail,
    requestedByUserId: userId,
    requestedByMembershipId: membershipId,
    revokedByUserId: null,
  };
  assert.equal(
    publicDeviceRegistrationRequestSchema.safeParse({
      identifier: ' esp32-01 ',
      publicKey,
    }).success,
    true,
  );
  assert.equal(
    publicDeviceRegistrationRequestSchema.safeParse({
      identifier: 'esp32-01',
      publicKey,
      userId,
    }).success,
    false,
  );
  assert.equal(
    deviceRegistrationRequestSchema.safeParse({
      identifier: 'esp32-01',
      publicKey,
      vehicleId,
      userId,
      membershipId,
    }).success,
    true,
  );
  assert.equal(
    deviceRegistrationRequestSchema.safeParse({
      identifier: 'esp32-01',
      publicKey,
      vehicleId,
      userId,
    }).success,
    false,
  );
  assert.equal(
    deviceRegistrationRequestSchema.safeParse({
      identifier: 'esp32-01',
      publicKey,
      vehicleId,
      userId,
      membershipId,
      extra: true,
    }).success,
    false,
  );
  assert.equal(deviceIdentifierSchema.safeParse('esp32\t01').success, false);
  assert.equal(deviceIdentifierSchema.safeParse('   ').success, false);
  assert.equal(
    deviceRegistrationResponseSchema.safeParse({
      deviceId,
      status: 'PENDING',
      data: internalRecord,
    }).success,
    true,
  );
  for (const reason of DEVICE_REVOCATION_REASONS) {
    assert.equal(deviceRevocationRequestSchema.safeParse({ reason }).success, true, reason);
  }
  assert.equal(
    deviceRevocationRequestSchema.safeParse({ reason: 'device-replaced' }).success,
    false,
  );
  assert.equal(deviceRevocationRequestSchema.safeParse({ reason: '' }).success, false);
  assert.equal(deviceRevocationRequestSchema.safeParse({}).success, false);
  assert.equal(deviceRevocationResponseSchema.safeParse({ revoked: true }).success, true);
  assert.equal(
    deviceRevocationSchema.safeParse({
      deviceId,
      revokedAt: '2026-11-03T12:00:00.000Z',
      reason: 'SECURITY_COMPROMISE',
    }).success,
    true,
  );
});

test('device metadata, detail, pagination and canonical enrollment contracts enforce strict bounds', () => {
  assert.deepEqual(DEVICE_METADATA_FIELDS, [
    'name',
    'manufacturer',
    'hardwareModel',
    'hardwareRevision',
    'firmwareVersion',
    'serialNumber',
  ]);
  assert.deepEqual(
    deviceMetadataInputSchema.parse({
      name: '  Sunroof Node  ',
      manufacturer: ' Espressif ',
      hardwareModel: ' ESP32-S3-WROOM-1 ',
      hardwareRevision: ' rev_1.2+a/b - 01 ',
      firmwareVersion: ' 1.4.0-rc.1+build7 ',
      serialNumber: ' SN:2026_001-A.9 ',
    }),
    {
      name: 'Sunroof Node',
      manufacturer: 'Espressif',
      hardwareModel: 'ESP32-S3-WROOM-1',
      hardwareRevision: 'rev_1.2+a/b - 01',
      firmwareVersion: '1.4.0-rc.1+build7',
      serialNumber: 'SN:2026_001-A.9',
    },
  );
  const metadataLimits: Array<[string, number, string]> = [
    ['name', 80, 'a'],
    ['manufacturer', 64, 'a'],
    ['hardwareModel', 64, 'a'],
    ['hardwareRevision', 32, 'a'],
    ['firmwareVersion', 64, 'a'],
    ['serialNumber', 64, 'a'],
  ];
  for (const [field, max, ch] of metadataLimits) {
    assert.equal(
      deviceMetadataInputSchema.safeParse({ [field]: ch.repeat(max) }).success,
      true,
      `${field} max ${max}`,
    );
    assert.equal(
      deviceMetadataInputSchema.safeParse({ [field]: ch.repeat(max + 1) }).success,
      false,
      `${field} over max ${max + 1}`,
    );
    assert.equal(
      deviceMetadataInputSchema.safeParse({ [field]: null }).success,
      true,
      `${field} nullable`,
    );
    assert.equal(
      deviceMetadataInputSchema.safeParse({ [field]: '   ' }).success,
      false,
      `${field} rejects whitespace only`,
    );
    assert.equal(
      deviceMetadataInputSchema.safeParse({ [field]: `\t${ch}` }).success,
      false,
      `${field} rejects control chars before trim`,
    );
    assert.equal(
      deviceMetadataInputSchema.safeParse({ [field]: `${ch}\n` }).success,
      false,
      `${field} rejects trailing newline before trim`,
    );
  }
  assert.equal(
    deviceMetadataInputSchema.safeParse({ firmwareVersion: '1.0.0 beta' }).success,
    false,
  );
  assert.equal(deviceMetadataInputSchema.safeParse({ serialNumber: 'SN/001' }).success, false);
  assert.equal(deviceMetadataInputSchema.safeParse({ hardwareRevision: 'rev:1' }).success, false);
  assert.equal(deviceMetadataInputSchema.safeParse({ trusted: true }).success, false);

  // PATCH metadata: non-empty, null clears, omitted preserves, userId does not count as field
  assert.equal(deviceMetadataUpdateRequestSchema.safeParse({}).success, false);
  assert.deepEqual(deviceMetadataUpdateRequestSchema.parse({ serialNumber: null }), {
    serialNumber: null,
  });
  assert.equal(
    internalVehicleDeviceMetadataUpdateRequestSchema.safeParse({ userId }).success,
    false,
  );
  assert.equal(
    internalVehicleDeviceMetadataUpdateRequestSchema.safeParse({ userId, name: 'Cabin' }).success,
    true,
  );
  assert.equal(deviceMetadataSchema.safeParse(sampleDeviceDetail.metadata).success, true);

  // Detail schema separates status, credential, operational, connectivity, metadata and strips secrets
  assert.equal(deviceDetailSchema.safeParse(sampleDeviceDetail).success, true);
  assert.equal(
    deviceDetailResponseSchema.safeParse({ ...sampleDeviceDetail, requestId: 'req-1' }).success,
    true,
  );
  for (const forbidden of [
    { publicKey },
    { challengeHash: 'a'.repeat(64) },
    { requestedByUserId: userId },
    { requestedByMembershipId: membershipId },
    { linkedByUserId: userId },
  ]) {
    assert.equal(
      deviceDetailSchema.safeParse({ ...sampleDeviceDetail, ...forbidden }).success,
      false,
    );
  }
  assert.equal(
    deviceDetailSchema.safeParse({
      ...sampleDeviceDetail,
      credential: { ...sampleDeviceDetail.credential, publicKey },
    }).success,
    false,
  );
  assert.equal(
    internalDeviceRecordSchema.safeParse({
      ...sampleDeviceDetail,
      requestedByUserId: userId,
      requestedByMembershipId: membershipId,
      revokedByUserId: null,
    }).success,
    true,
  );

  // Canonical enrollment challenge and completion contracts
  const canonicalChallenge = `${'A'.repeat(42)}A`;
  const canonicalSignature = `${'A'.repeat(85)}A`;
  const challengePayload = {
    protocol: DEVICE_LINK_PROTOCOL_VERSION,
    challengeId,
    deviceId,
    vehicleId,
    credentialId,
    requestedByUserId: userId,
    challenge: canonicalChallenge,
    expiresAt: '2026-11-26T12:05:00.000Z',
  };
  assert.equal(deviceLinkChallengeSchema.safeParse(challengePayload).success, true);
  assert.equal(
    deviceLinkChallengeSchema.safeParse({ ...challengePayload, challenge: `${'A'.repeat(42)}B` })
      .success,
    false,
  );
  assert.equal(publicDeviceChallengeRequestSchema.safeParse({}).success, true);
  assert.equal(publicDeviceChallengeRequestSchema.safeParse({ extra: 1 }).success, false);
  assert.equal(
    deviceLinkCompletionSchema.safeParse({
      challengeId,
      challenge: canonicalChallenge,
      signature: canonicalSignature,
    }).success,
    true,
  );
  // Non-zero tail bits in 64-byte base64url signature must be rejected
  assert.equal(
    deviceLinkCompletionSchema.safeParse({
      challengeId,
      challenge: canonicalChallenge,
      signature: `${'A'.repeat(85)}B`,
    }).success,
    false,
  );
  assert.equal(
    deviceLinkCompletionSchema.safeParse({
      challengeId,
      challenge: canonicalChallenge,
      signature: canonicalSignature,
      message: 'forged',
    }).success,
    false,
  );

  // Response envelopes and cursor pagination queries
  assert.equal(
    vehicleDeviceChallengeResponseSchema.safeParse({
      challengeId,
      status: 'PENDING',
      message: 'Challenge issued',
      data: challengePayload,
      requestId: 'req-1',
    }).success,
    true,
  );
  assert.equal(
    vehicleDeviceLinkResponseSchema.safeParse({
      deviceId,
      status: 'ACTIVE',
      message: 'Device linked',
      data: {
        ...sampleDeviceDetail,
        status: 'ACTIVE',
        operational: true,
        linkedAt: '2026-11-26T12:01:00.000Z',
      },
      requestId: 'req-1',
    }).success,
    true,
  );
  assert.equal(
    vehicleDeviceMetadataUpdateResponseSchema.safeParse({
      deviceId,
      status: 'PENDING',
      message: 'Device metadata updated',
      data: sampleDeviceDetail,
      requestId: 'req-1',
    }).success,
    true,
  );
  assert.equal(
    vehicleDeviceRevokeResponseSchema.safeParse({
      deviceId,
      status: 'REVOKED',
      message: 'Device revoked',
      data: {
        ...sampleDeviceDetail,
        status: 'REVOKED',
        credential: {
          ...sampleDeviceDetail.credential,
          status: 'REVOKED',
          usable: false,
          revokedAt: '2026-11-26T12:02:00.000Z',
        },
        revokedAt: '2026-11-26T12:02:00.000Z',
        revocationReason: 'ADMINISTRATIVE',
      },
      requestId: 'req-1',
    }).success,
    true,
  );
  assert.equal(vehicleDeviceParamsSchema.safeParse({ vehicleId, deviceId }).success, true);
  assert.deepEqual(vehicleDeviceListQuerySchema.parse({}), { limit: 20 });
  assert.equal(
    vehicleDeviceListQuerySchema.safeParse({ limit: 100, status: 'ACTIVE' }).success,
    true,
  );
  assert.equal(vehicleDeviceListQuerySchema.safeParse({ limit: 101 }).success, false);
  assert.equal(vehicleDeviceListQuerySchema.safeParse({ userId }).success, false);
  assert.equal(
    vehicleDeviceListResponseSchema.safeParse({
      devices: [sampleDeviceDetail],
      page: { nextCursor: null },
      requestId: 'req-1',
    }).success,
    true,
  );
  assert.equal(
    internalDeviceCollectionQuerySchema.safeParse({
      limit: 50,
      afterCreatedAt: '2026-11-26T12:00:00.000Z',
    }).success,
    false,
  );
  assert.equal(
    internalDeviceCollectionQuerySchema.safeParse({
      limit: 50,
      afterCreatedAt: '2026-11-26T12:00:00.000Z',
      afterId: deviceId,
    }).success,
    true,
  );
});
