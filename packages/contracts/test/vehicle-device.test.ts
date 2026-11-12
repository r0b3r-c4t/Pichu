import assert from 'node:assert/strict';
import test from 'node:test';
import {
  deviceIdentityResponseSchema,
  deviceIdentifierSchema,
  deviceLinkChallengeSchema,
  deviceLinkCompletionSchema,
  deviceLinkResponseSchema,
  deviceReferenceParamsSchema,
  deviceRegistrationRequestSchema,
  deviceRegistrationResponseSchema,
  deviceRevocationRequestSchema,
  deviceRevocationResponseSchema,
  deviceRevocationSchema,
  deviceSummarySchema,
  invitationAcceptRequestSchema,
  invitationAcceptResponseSchema,
  internalInvitationCreateRequestSchema,
  invitationParamsSchema,
  publicInvitationCreateRequestSchema,
  invitationCreateResponseSchema,
  membershipSchema,
  membershipPermissionSchema,
  membershipRoleSchema,
  vehicleCreateRequestSchema,
  vehicleCreateResponseSchema,
  vehicleDetailResponseSchema,
  vehicleDeviceRegistrationResponseSchema,
  vehicleListQuerySchema,
  vehicleListResponseSchema,
  vehicleParamsSchema,
  vehicleSummarySchema,
} from '../src/index.js';

const vehicleId = '507f1f77bcf86cd799439011';
const userId = '507f1f77bcf86cd799439012';
const deviceId = '507f1f77bcf86cd799439013';
const publicKey = '-----BEGIN PUBLIC KEY-----\n' + 'A'.repeat(80) + '\n-----END PUBLIC KEY-----';

test('enriched vehicle responses retain legacy fields and reject private properties', () => {
  const data = {
    id: vehicleId,
    name: 'Persisted Mazda 3',
    make: 'Mazda',
    model: '3',
    year: 2011,
    engine: '2.0',
    ownerUserId: userId,
  };
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
    vehicleCreateResponseSchema.safeParse({ vehicleId, data: { ...data, __v: 1 } }).success,
    false,
  );
  assert.equal(
    vehicleDeviceRegistrationResponseSchema.safeParse({
      deviceId,
      status: 'PENDING',
      message: 'Device registration accepted',
      data: { deviceId, vehicleId, status: 'PENDING' },
      requestId: 'request-42',
    }).success,
    true,
  );
});

test('vehicle creation and summary use explicit identifiers and closed DTOs', () => {
  assert.equal(
    vehicleCreateRequestSchema.safeParse({
      name: ' Mazda 3 ',
      make: 'Mazda',
      model: '3',
      year: 2011,
      engine: '2.0',
    }).success,
    true,
  );
  assert.equal(vehicleCreateRequestSchema.safeParse({ name: 'Mazda 3', userId }).success, false);
  assert.equal(vehicleCreateRequestSchema.safeParse({ name: '' }).success, false);
  assert.equal(vehicleCreateRequestSchema.safeParse({ name: 'x'.repeat(121) }).success, false);
  assert.equal(vehicleCreateResponseSchema.safeParse({ vehicleId }).success, true);
  assert.equal(
    vehicleSummarySchema.safeParse({
      id: vehicleId,
      name: 'Mazda 3',
      make: 'Mazda',
      model: '3',
      year: 2011,
      engine: '2.0',
      ownerUserId: userId,
    }).success,
    true,
  );
  assert.equal(
    vehicleSummarySchema.safeParse({
      vehicleId,
      name: 'Mazda 3',
      make: null,
      model: null,
      year: null,
      engine: null,
      ownerUserId: userId,
    }).success,
    false,
  );
});

test('vehicle pagination and invitation DTOs validate boundaries', () => {
  assert.deepEqual(vehicleListQuerySchema.parse({}), { limit: 20 });
  assert.equal(vehicleListQuerySchema.safeParse({ limit: 101 }).success, false);
  assert.equal(vehicleListQuerySchema.safeParse({ userId }).success, false);
  assert.equal(
    vehicleListResponseSchema.safeParse({ vehicles: [], page: { nextCursor: null } }).success,
    true,
  );
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
  assert.equal(
    membershipSchema.safeParse({
      vehicleId,
      userId,
      role: 'MEMBER',
      permissions: ['vehicle:read'],
    }).success,
    true,
  );
  assert.equal(
    membershipSchema.safeParse({
      vehicleId,
      userId,
      role: 'MEMBER',
      permissions: [],
      owner: true,
    }).success,
    false,
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
  assert.equal(
    deviceRegistrationRequestSchema.safeParse({
      identifier: 'esp32-01',
      publicKey,
      vehicleId,
      userId,
    }).success,
    true,
  );
  assert.equal(
    deviceRegistrationRequestSchema.safeParse({ identifier: 'esp32-01', vehicleId, userId })
      .success,
    false,
  );
  assert.equal(
    deviceRegistrationRequestSchema.safeParse({
      identifier: 'esp32-01',
      publicKey,
      vehicleId,
      userId,
      extra: true,
    }).success,
    false,
  );
  assert.equal(
    deviceRegistrationResponseSchema.safeParse({ deviceId, status: 'PENDING' }).success,
    true,
  );
  assert.equal(
    deviceRevocationRequestSchema.safeParse({ reason: 'device-replaced' }).success,
    true,
  );
  assert.equal(deviceRevocationRequestSchema.safeParse({ reason: '' }).success, false);
  assert.equal(deviceRevocationResponseSchema.safeParse({ revoked: true }).success, true);
  assert.equal(
    deviceRevocationSchema.safeParse({
      deviceId,
      revokedAt: '2026-11-03T12:00:00.000Z',
    }).success,
    true,
  );
});

test('challenge and completion remain provisional and strictly shaped', () => {
  assert.equal(
    deviceLinkChallengeSchema.safeParse({
      challengeId: deviceId,
      challenge: 'A'.repeat(32),
      expiresAt: '2026-11-03T12:00:00.000Z',
    }).success,
    true,
  );
  assert.equal(
    deviceLinkCompletionSchema.safeParse({ challengeId: deviceId, proof: 'signed-proof' }).success,
    true,
  );
  assert.equal(
    deviceLinkCompletionSchema.safeParse({
      challengeId: deviceId,
      proof: 'signed-proof',
      algorithm: 'Ed25519',
    }).success,
    false,
  );
  assert.equal(deviceLinkResponseSchema.safeParse({ linked: true }).success, true);
});
