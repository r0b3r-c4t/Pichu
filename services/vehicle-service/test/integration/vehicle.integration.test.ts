import assert from 'node:assert/strict';
import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { createHmac, generateKeyPairSync, randomUUID, sign as signDetached } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { promisify } from 'node:util';
import mongoose, { Types } from 'mongoose';
import { MongoNonceStore } from '@pichu/internal-auth-adapters/mongodb';
import { httpsJsonRequest } from '@pichu/internal-auth-adapters/tls';
import { generateNonce, signRequest, type KeyEntry } from '@pichu/internal-auth';
import { startAuthenticatedMongo } from '../../../../scripts/helpers/authenticated-mongo.js';
import { assertVehicleDatabaseReady, createApp } from '../../src/app.js';
import {
  assertCriticalVehicleIndexes,
  ensureDevelopmentDatabaseSchema,
  VehicleSchemaNotReadyError,
} from '../../src/database/bootstrap.js';
import { closeDatabase, connectDatabase } from '../../src/database/connection.js';
import {
  applyControlledVehicleMigration,
  inspectVehicleMigrationPreflight,
  VehicleMigrationBlockedError,
} from '../../src/database/migration.js';
import { AccessGrantModel } from '../../src/models/access-grant.model.js';
import { InvitationModel } from '../../src/models/invitation.model.js';
import { MembershipModel } from '../../src/models/membership.model.js';
import { VehicleModel } from '../../src/models/vehicle.model.js';
import {
  acceptInvitation,
  archiveVehicle,
  canAccessVehicle,
  canLinkDeviceToVehicle,
  createAccessGrant,
  createVehicle,
  createVerifiedExternalResourceBinding,
  evaluateVehiclePermission,
  expireElapsedAccessGrants,
  getAccessibleVehicle,
  getVehicleForUser,
  INVITATION_ISSUER_AUTHORITY_LOST_REASON,
  inviteMember,
  leaveVehicle,
  listAccessibleVehicles,
  listOwnedVehicles,
  listReceivedInvitations,
  listVehicleInvitations,
  listVehicleMembers,
  MEMBER_LEFT_REASON,
  reactivateMembership,
  revokeAccessGrant,
  revokeInvitation,
  revokeMembership,
  suspendMembership,
  updateMembershipPermissions,
  updateVehicle,
  VehicleServiceError,
  type VehicleAuditEvent,
} from '../../src/services/vehicle.service.js';
import {
  resourceAuthorization,
  type AuthorizationContext,
  type VehicleAccessCandidate,
} from '../../src/services/resource-authorization.service.js';
import {
  DeviceUpstreamDomainError,
  toPublicDeviceDetail,
  type DeviceServiceClient,
  type VerifiedDeviceSnapshot,
} from '../../src/services/device-client.service.js';
import {
  getDirectDeviceDetail,
  getVehicleScopedDeviceDetail,
  listVehicleDevices,
  revokeVehicleDevice,
  updateVehicleDeviceMetadata,
} from '../../src/services/vehicle-device.service.js';
import type { InternalDeviceRecord } from '@pichu/contracts';
import { setupVehicleTestAuth } from '../v2-fixture.js';

const execFileAsync = promisify(execFile);
const repoRoot = path.resolve(import.meta.dirname, '../../../..');

async function resolveOpenSslBinary(): Promise<string> {
  const candidates =
    process.platform === 'win32'
      ? ['C:/Program Files/Git/usr/bin/openssl.exe', 'openssl']
      : ['openssl'];
  for (const candidate of candidates) {
    try {
      await execFileAsync(candidate, ['version']);
      return candidate;
    } catch {
      // try next candidate
    }
  }
  throw new Error('openssl binary is required for HTTPS integration tests');
}

function isDuplicateKeyError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === 11000
  );
}

let mongoCluster: Awaited<ReturnType<typeof startAuthenticatedMongo>> | undefined;
let rootClient: mongoose.mongo.MongoClient | undefined;
let vehicleUri = '';

before(async () => {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      mongoCluster = await startAuthenticatedMongo();
      break;
    } catch (error) {
      if (attempt === 1) throw error;
    }
  }
  assert.ok(mongoCluster);
  vehicleUri = mongoCluster.uri('vehicle');
  rootClient = new mongoose.mongo.MongoClient(mongoCluster.rootUri, {
    serverSelectionTimeoutMS: 5_000,
  });
  await rootClient.connect();
  await connectDatabase(vehicleUri);
  await ensureDevelopmentDatabaseSchema(() => undefined);
});

after(async () => {
  await closeDatabase().catch(() => undefined);
  await rootClient?.close().catch(() => undefined);
  await mongoCluster?.cleanup().catch(() => undefined);
});

async function resetVehicleCollections(): Promise<void> {
  await Promise.all([
    VehicleModel.deleteMany({}),
    MembershipModel.deleteMany({}),
    InvitationModel.deleteMany({}),
    AccessGrantModel.deleteMany({}),
  ]);
}

/** Explicit test fixture of verified ownership evidence (no authoritative source exists yet). */
function testOwnershipEvidence(
  scopeType: 'DEVICE' | 'MODULE',
  resourceId: Types.ObjectId,
  vehicleId: Types.ObjectId,
) {
  return createVerifiedExternalResourceBinding({
    scopeType,
    resourceId,
    vehicleId,
    isActive: true,
  });
}

test('1. Multi-brand vehicles and incomplete technical metadata persist without Mazda assumptions', async () => {
  await resetVehicleCollections();
  const ownerA = new Types.ObjectId();
  const ownerB = new Types.ObjectId();

  const toyota = await createVehicle(ownerA, {
    name: 'Daily Hybrid Crossover',
    make: 'Toyota',
    model: 'Corolla Cross',
    generation: 'XG10',
    trim: 'XSE Hybrid',
    year: 2024,
    bodyStyle: 'suv',
    engine: '2.0L M20A-FXS Hybrid',
    transmission: 'e-CVT',
    fuelType: 'hybrid',
  });

  const ford = await createVehicle(ownerA, {
    name: 'Ranch Truck',
    make: 'Ford',
    model: 'F-150',
    generation: 'P702',
    trim: 'XLT 4x4',
    year: 2022,
    bodyStyle: 'pickup',
    engine: '3.5L EcoBoost V6',
    transmission: '10-speed automatic',
    fuelType: 'gasoline',
  });

  const byd = await createVehicle(ownerB, {
    name: 'Urban Electric Sedan',
    make: 'BYD',
    model: 'Seal',
    year: 2025,
    bodyStyle: 'sedan',
    engine: '230 kW Rear Motor',
    transmission: 'single-speed',
    fuelType: 'electric',
  });

  // Incomplete technical info: only name provided
  const incomplete = await createVehicle(ownerB, {
    name: 'Mystery Track Build',
  });

  assert.equal(toyota.make, 'Toyota');
  assert.equal(toyota.fuelType, 'hybrid');
  assert.equal(ford.bodyStyle, 'pickup');
  assert.equal(byd.fuelType, 'electric');
  assert.equal(incomplete.make, null);
  assert.equal(incomplete.model, null);
  assert.equal(incomplete.generation, null);
  assert.equal(incomplete.trim, null);
  assert.equal(incomplete.year, null);
  assert.equal(incomplete.bodyStyle, null);
  assert.equal(incomplete.engine, null);
  assert.equal(incomplete.transmission, null);
  assert.equal(incomplete.fuelType, null);
  assert.equal(incomplete.createdByUserId.equals(ownerB), true);
});

test('2. Multi-vehicle ownership, multi-vehicle membership, and strict cross-vehicle permission isolation', async () => {
  await resetVehicleCollections();
  const ownerA = new Types.ObjectId();
  const ownerB = new Types.ObjectId();
  const sharedMember = new Types.ObjectId();
  const outsider = new Types.ObjectId();

  // Single owner owns multiple vehicles simultaneously
  const vehicleA1 = await createVehicle(ownerA, {
    name: 'Volkswagen Golf GTI',
    make: 'Volkswagen',
    model: 'Golf',
  });
  const vehicleA2 = await createVehicle(ownerA, {
    name: 'Honda CR-V',
    make: 'Honda',
    model: 'CR-V',
  });
  const vehicleB1 = await createVehicle(ownerB, {
    name: 'Subaru Outback',
    make: 'Subaru',
    model: 'Outback',
  });

  const ownedByA = await listOwnedVehicles(ownerA);
  assert.equal(ownedByA.length, 2);

  // Single user becomes active MEMBER of multiple vehicles across different owners
  const invA1 = await inviteMember(vehicleA1._id, ownerA, sharedMember, [
    'vehicle:read',
    'device:link',
  ]);
  const invB1 = await inviteMember(vehicleB1._id, ownerB, sharedMember, ['vehicle:read']);
  assert.ok(invA1 && invB1);
  await acceptInvitation(invA1._id, sharedMember);
  await acceptInvitation(invB1._id, sharedMember);

  const accessibleToShared = await listAccessibleVehicles(sharedMember);
  assert.equal(accessibleToShared.items.length, 2);

  // Isolation: sharedMember has device:link on A1, NOT on B1, and zero access on A2
  assert.equal(await canLinkDeviceToVehicle(vehicleA1._id, sharedMember), true);
  assert.equal(await canLinkDeviceToVehicle(vehicleB1._id, sharedMember), false);
  assert.equal(await canAccessVehicle(vehicleA2._id, sharedMember), false);
  assert.equal(await getVehicleForUser(vehicleA2._id, sharedMember), null);

  // Isolation: ownerA has full authority on A1/A2, zero authority on B1
  assert.equal(await canAccessVehicle(vehicleB1._id, ownerA), false);
  assert.equal(await inviteMember(vehicleB1._id, ownerA, outsider, ['vehicle:read']), null);
});

test('3. Canonical ownership protection and fail-closed denial on Vehicle <-> OWNER Membership inconsistency', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const otherId = new Types.ObjectId();

  const vehicle = await createVehicle(ownerId, { name: 'Protected Owner Sedan' });
  const ownerMembership = await MembershipModel.findOne({ vehicleId: vehicle._id, role: 'OWNER' });
  assert.ok(ownerMembership);

  // Self-invitation and inviting the canonical owner are rejected
  await assert.rejects(
    () => inviteMember(vehicle._id, ownerId, ownerId, ['vehicle:read']),
    (err: unknown) => err instanceof VehicleServiceError && err.code === 'VALIDATION_ERROR',
  );

  // Add a member who has invitation:create so we test inviting the canonical owner explicitly
  const delegatorId = new Types.ObjectId();
  const delegatorInv = await inviteMember(vehicle._id, ownerId, delegatorId, [
    'vehicle:read',
    'invitation:create',
  ]);
  assert.ok(delegatorInv);
  await acceptInvitation(delegatorInv._id, delegatorId);

  await assert.rejects(
    () => inviteMember(vehicle._id, delegatorId, ownerId, ['vehicle:read']),
    (err: unknown) => err instanceof VehicleServiceError && err.code === 'CONFLICT',
  );

  // Suspending or revoking the OWNER membership is forbidden
  await assert.rejects(
    () =>
      suspendMembership({
        vehicleId: vehicle._id,
        membershipId: ownerMembership._id,
        actorUserId: ownerId,
        reason: 'accidental lock',
      }),
    (err: unknown) => err instanceof VehicleServiceError && err.code === 'CONFLICT',
  );
  await assert.rejects(
    () =>
      revokeMembership({
        vehicleId: vehicle._id,
        membershipId: ownerMembership._id,
        actorUserId: ownerId,
        reason: 'accidental revoke',
      }),
    (err: unknown) => err instanceof VehicleServiceError && err.code === 'CONFLICT',
  );

  // Simulate database corruption: mismatch Vehicle.ownerUserId vs OWNER Membership.userId
  await VehicleModel.collection.updateOne({ _id: vehicle._id }, { $set: { ownerUserId: otherId } });

  // Fail-closed: neither original owner nor corrupted ownerUserId gets access
  assert.equal(await canAccessVehicle(vehicle._id, ownerId), false);
  assert.equal(await canAccessVehicle(vehicle._id, otherId), false);
  assert.equal(await getVehicleForUser(vehicle._id, ownerId), null);
  assert.equal(await getVehicleForUser(vehicle._id, otherId), null);
  assert.equal((await listOwnedVehicles(otherId)).length, 0);
  const decision = await evaluateVehiclePermission({
    vehicleId: vehicle._id,
    userId: otherId,
    permission: 'vehicle:read',
  });
  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, 'VEHICLE_UNAVAILABLE_OR_INCONSISTENT');
});

test('4. Real MongoDB transaction rollbacks on createVehicle and acceptInvitation failures', async (t) => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const inviteeId = new Types.ObjectId();

  // 4a. Rollback createVehicle if Membership OWNER creation throws inside transaction
  const membershipCreateMock = t.mock.method(MembershipModel, 'create', async () => {
    throw new Error('simulated membership write failure');
  });

  await assert.rejects(
    () => createVehicle(ownerId, { name: 'Must Roll Back' }),
    /simulated membership write failure/,
  );
  membershipCreateMock.mock.restore();

  assert.equal(await VehicleModel.countDocuments({}), 0);
  assert.equal(await MembershipModel.countDocuments({}), 0);

  // 4b. Rollback acceptInvitation if Membership MEMBER creation throws inside transaction
  const vehicle = await createVehicle(ownerId, { name: 'Transactional Vehicle' });
  const invitation = await inviteMember(vehicle._id, ownerId, inviteeId, ['vehicle:read']);
  assert.ok(invitation);

  const failAcceptMock = t.mock.method(MembershipModel, 'create', async () => {
    throw new Error('simulated member insert failure');
  });

  await assert.rejects(
    () => acceptInvitation(invitation._id, inviteeId),
    /simulated member insert failure/,
  );
  failAcceptMock.mock.restore();

  const reloadedInvitation = await InvitationModel.findById(invitation._id).lean();
  assert.equal(reloadedInvitation?.status, 'PENDING');
  assert.equal(reloadedInvitation?.acceptedAt, null);
  assert.equal(
    await MembershipModel.countDocuments({ vehicleId: vehicle._id, userId: inviteeId }),
    0,
  );
});

test('5. Concurrent invitation acceptance allows exactly one winner and creates a single Membership', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const inviteeId = new Types.ObjectId();

  const vehicle = await createVehicle(ownerId, { name: 'Concurrency Hatchback' });
  const invitation = await inviteMember(vehicle._id, ownerId, inviteeId, ['vehicle:read']);
  assert.ok(invitation);

  const attempts = await Promise.allSettled(
    Array.from({ length: 6 }, () => acceptInvitation(invitation._id, inviteeId)),
  );

  const winners = attempts.filter(
    (
      res,
    ): res is PromiseFulfilledResult<NonNullable<Awaited<ReturnType<typeof acceptInvitation>>>> =>
      res.status === 'fulfilled' && res.value !== null,
  );
  assert.equal(winners.length, 1);

  const memberships = await MembershipModel.find({
    vehicleId: vehicle._id,
    userId: inviteeId,
  }).lean();
  assert.equal(memberships.length, 1);
  assert.equal(memberships[0]?.role, 'MEMBER');
  assert.equal(memberships[0]?.status, 'ACTIVE');

  const finalInvitation = await InvitationModel.findById(invitation._id).lean();
  assert.equal(finalInvitation?.status, 'ACCEPTED');
  assert.equal(finalInvitation?.acceptedByUserId?.equals(inviteeId), true);
});

test('6. Expired invitations persist EXPIRED outside rollback, allow re-issuance, and preserve full history', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const inviteeA = new Types.ObjectId();
  const inviteeB = new Types.ObjectId();

  const vehicle = await createVehicle(ownerId, { name: 'History Wagon' });

  // Create an already-elapsed PENDING invitation (e.g., TTL elapsed without MongoDB background delete)
  const pastNow = new Date(Date.now() - 120_000);
  const expiredInvite = await inviteMember(vehicle._id, ownerId, inviteeA, ['vehicle:read'], {
    now: pastNow,
    ttlMs: 60_000,
  });
  assert.ok(expiredInvite);

  // Accepting an own invitation after expiry is a CONFLICT AND durably persists EXPIRED
  await assert.rejects(
    () => acceptInvitation(expiredInvite._id, inviteeA),
    (err: unknown) => err instanceof VehicleServiceError && err.code === 'CONFLICT',
  );

  const persistedExpired = await InvitationModel.findById(expiredInvite._id).lean();
  assert.equal(persistedExpired?.status, 'EXPIRED');
  assert.ok(persistedExpired?.expiredAt instanceof Date);

  // Also test lazy expiration during re-issuance when a PENDING invitation expired untouched
  const untouchedExpired = await inviteMember(vehicle._id, ownerId, inviteeB, ['vehicle:read'], {
    now: pastNow,
    ttlMs: 30_000,
  });
  assert.ok(untouchedExpired);

  const reissued = await inviteMember(vehicle._id, ownerId, inviteeB, [
    'vehicle:read',
    'device:read',
  ]);
  assert.ok(reissued);
  assert.equal(reissued._id.equals(untouchedExpired._id), false);

  // Revoke reissued invitation, then issue a third one and accept it -> all 3 historical rows remain!
  const revoked = await revokeInvitation({
    vehicleId: vehicle._id,
    invitationId: reissued._id,
    actorUserId: ownerId,
    reason: 'Changed permissions',
  });
  assert.equal(revoked.invitation.status, 'REVOKED');
  assert.equal(revoked.alreadyRevoked, false);

  // Cannot reopen terminal REVOKED or EXPIRED invitations
  await assert.rejects(
    () => acceptInvitation(reissued._id, inviteeB),
    (err: unknown) => err instanceof VehicleServiceError && err.code === 'CONFLICT',
  );
  await assert.rejects(
    () =>
      revokeInvitation({
        vehicleId: vehicle._id,
        invitationId: expiredInvite._id,
        actorUserId: ownerId,
      }),
    (err: unknown) => err instanceof VehicleServiceError && err.code === 'CONFLICT',
  );

  const third = await inviteMember(vehicle._id, ownerId, inviteeB, ['vehicle:read']);
  assert.ok(third);
  const acceptedMembership = await acceptInvitation(third._id, inviteeB);
  assert.ok(acceptedMembership);

  const historyForB = await InvitationModel.find({
    vehicleId: vehicle._id,
    inviteeUserId: inviteeB,
  })
    .sort({ createdAt: 1, _id: 1 })
    .lean();

  assert.deepEqual(
    historyForB.map((item) => item.status),
    ['EXPIRED', 'REVOKED', 'ACCEPTED'],
  );
});

test('7. Real MongoDB partial unique indexes enforce integrity while allowing post-revocation re-membership', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const secondUser = new Types.ObjectId();

  const vehicle = await createVehicle(ownerId, { name: 'Index Integrity Truck' });

  // 7a. Duplicate active OWNER on same vehicle rejected with E11000
  await assert.rejects(
    () =>
      MembershipModel.create({
        vehicleId: vehicle._id,
        userId: secondUser,
        role: 'OWNER',
        status: 'ACTIVE',
        permissions: ['vehicle:manage'],
        grantedByUserId: ownerId,
      }),
    isDuplicateKeyError,
  );

  // 7b. Duplicate non-revoked Membership for same (vehicleId, userId) rejected with E11000
  const m1 = await MembershipModel.create({
    vehicleId: vehicle._id,
    userId: secondUser,
    role: 'MEMBER',
    status: 'SUSPENDED',
    permissions: ['vehicle:read'],
    grantedByUserId: ownerId,
    suspendedAt: new Date(),
    suspendedByUserId: ownerId,
  });
  await assert.rejects(
    () =>
      MembershipModel.create({
        vehicleId: vehicle._id,
        userId: secondUser,
        role: 'MEMBER',
        status: 'ACTIVE',
        permissions: ['vehicle:read'],
        grantedByUserId: ownerId,
      }),
    isDuplicateKeyError,
  );

  // 7c. Duplicate PENDING Invitation for same (vehicleId, inviteeUserId) rejected with E11000
  const otherInvitee = new Types.ObjectId();
  await InvitationModel.create({
    vehicleId: vehicle._id,
    inviterUserId: ownerId,
    inviteeUserId: otherInvitee,
    permissions: ['vehicle:read'],
    expiresAt: new Date(Date.now() + 86_400_000),
  });
  await assert.rejects(
    () =>
      InvitationModel.create({
        vehicleId: vehicle._id,
        inviterUserId: ownerId,
        inviteeUserId: otherInvitee,
        permissions: ['vehicle:read'],
        expiresAt: new Date(Date.now() + 86_400_000),
      }),
    isDuplicateKeyError,
  );

  // 7d. Revoking m1 allows creating a fresh Membership for same (vehicleId, userId) while keeping history
  await revokeMembership({
    vehicleId: vehicle._id,
    membershipId: m1._id,
    actorUserId: ownerId,
    reason: 'Ended first stint',
  });

  const reinvite = await inviteMember(vehicle._id, ownerId, secondUser, ['vehicle:read']);
  assert.ok(reinvite);
  const m2 = await acceptInvitation(reinvite._id, secondUser);
  assert.ok(m2);
  assert.equal(m2._id.equals(m1._id), false);

  const allMemberships = await MembershipModel.find({
    vehicleId: vehicle._id,
    userId: secondUser,
  }).lean();
  assert.equal(allMemberships.length, 2);
});

test('8. AccessGrant rules: multiple grants, cascade revocation, non-inheritance, future/expired windows, cross-entity checks, and verified resource bindings', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const memberA = new Types.ObjectId();
  const memberB = new Types.ObjectId();
  const device1 = new Types.ObjectId();
  const device2 = new Types.ObjectId();
  const moduleSunroof = new Types.ObjectId();

  const vehicle1 = await createVehicle(ownerId, { name: 'Multi-Device Vehicle 1' });
  const vehicle2 = await createVehicle(ownerId, { name: 'Multi-Device Vehicle 2' });

  const invA = await inviteMember(vehicle1._id, ownerId, memberA, ['vehicle:read']);
  const invB = await inviteMember(vehicle2._id, ownerId, memberB, ['vehicle:read']);
  assert.ok(invA && invB);
  const memA = await acceptInvitation(invA._id, memberA);
  const memB = await acceptInvitation(invB._id, memberB);
  assert.ok(memA && memB);

  const now = new Date();
  const inOneHour = new Date(now.getTime() + 3_600_000);
  const inTwoHours = new Date(now.getTime() + 7_200_000);

  // 8a. MEMBER cannot delegate grants in this phase
  await assert.rejects(
    () =>
      createAccessGrant({
        vehicleId: vehicle1._id,
        membershipId: memA._id,
        subjectUserId: memberA,
        actorUserId: memberA,
        scopeType: 'DEVICE',
        scopeResourceId: device1,
        verifiedResourceBinding: testOwnershipEvidence('DEVICE', device1, vehicle1._id),
        channel: 'ONLINE',
        permissions: ['device:read'],
        now,
      }),
    (err: unknown) => err instanceof VehicleServiceError && err.code === 'FORBIDDEN',
  );

  // 8b. Cross-mismatch between vehicleId, membershipId, and subjectUserId is rejected
  await assert.rejects(
    () =>
      createAccessGrant({
        vehicleId: vehicle1._id,
        membershipId: memB._id, // belongs to vehicle2 / memberB
        subjectUserId: memberA,
        actorUserId: ownerId,
        scopeType: 'VEHICLE',
        channel: 'ONLINE',
        permissions: ['device:link'],
        now,
      }),
    (err: unknown) => err instanceof VehicleServiceError && err.code === 'VALIDATION_ERROR',
  );
  await assert.rejects(
    () =>
      createAccessGrant({
        vehicleId: vehicle1._id,
        membershipId: memA._id,
        subjectUserId: memberB, // wrong subjectUserId
        actorUserId: ownerId,
        scopeType: 'VEHICLE',
        channel: 'ONLINE',
        permissions: ['device:link'],
        now,
      }),
    (err: unknown) => err instanceof VehicleServiceError && err.code === 'VALIDATION_ERROR',
  );

  // 8c. Multiple independent grants on same vehicle, multiple devices, and overlapping scopes/channels
  const grantDev1Online = await createAccessGrant({
    vehicleId: vehicle1._id,
    membershipId: memA._id,
    subjectUserId: memberA,
    actorUserId: ownerId,
    scopeType: 'DEVICE',
    scopeResourceId: device1,
    verifiedResourceBinding: testOwnershipEvidence('DEVICE', device1, vehicle1._id),
    channel: 'ONLINE',
    permissions: ['device:read', 'device:command'],
    startsAt: now,
    expiresAt: inTwoHours,
    now,
  });

  const grantDev1Ble = await createAccessGrant({
    vehicleId: vehicle1._id,
    membershipId: memA._id,
    subjectUserId: memberA,
    actorUserId: ownerId,
    scopeType: 'DEVICE',
    scopeResourceId: device1,
    verifiedResourceBinding: testOwnershipEvidence('DEVICE', device1, vehicle1._id),
    channel: 'BLE_OFFLINE',
    permissions: ['device:connect', 'device:command'],
    startsAt: now,
    expiresAt: inOneHour,
    now,
  });

  const grantDev2Online = await createAccessGrant({
    vehicleId: vehicle1._id,
    membershipId: memA._id,
    subjectUserId: memberA,
    actorUserId: ownerId,
    scopeType: 'DEVICE',
    scopeResourceId: device2,
    verifiedResourceBinding: testOwnershipEvidence('DEVICE', device2, vehicle1._id),
    channel: 'ONLINE',
    permissions: ['device:read'],
    startsAt: now,
    expiresAt: null,
    now,
  });

  const grantModuleFuture = await createAccessGrant({
    vehicleId: vehicle1._id,
    membershipId: memA._id,
    subjectUserId: memberA,
    actorUserId: ownerId,
    scopeType: 'MODULE',
    scopeResourceId: moduleSunroof,
    verifiedResourceBinding: testOwnershipEvidence('MODULE', moduleSunroof, vehicle1._id),
    channel: 'ONLINE',
    permissions: ['module:actuate'],
    startsAt: inOneHour,
    expiresAt: inTwoHours,
    now,
  });

  // 8d. Unverified DEVICE/MODULE resource bindings MUST be denied even with an active grant
  const unverifiedDev = await evaluateVehiclePermission({
    vehicleId: vehicle1._id,
    userId: memberA,
    permission: 'device:command',
    scopeType: 'DEVICE',
    scopeResourceId: device1,
    channel: 'ONLINE',
    now,
  });
  assert.deepEqual(unverifiedDev, { allowed: false, reason: 'UNVERIFIED_EXTERNAL_RESOURCE' });

  // Plain deserialized JSON objects (e.g., from an untrusted HTTP payload) lack the internal
  // module-private brand symbol and MUST always be rejected fail-closed.
  const spoofedClientBinding = JSON.parse(
    JSON.stringify({
      scopeType: 'DEVICE',
      resourceId: String(device1),
      vehicleId: String(vehicle1._id),
      isActive: true,
    }),
  ) as unknown;
  const forgedObjectIdBinding = {
    scopeType: 'DEVICE' as const,
    resourceId: device1,
    vehicleId: vehicle1._id,
    isActive: true,
  };
  for (const untrusted of [spoofedClientBinding, forgedObjectIdBinding]) {
    const forgedDecision = await evaluateVehiclePermission({
      vehicleId: vehicle1._id,
      userId: memberA,
      permission: 'device:command',
      scopeType: 'DEVICE',
      scopeResourceId: device1,
      channel: 'ONLINE',
      verifiedResourceBinding: untrusted as never,
      now,
    });
    assert.deepEqual(forgedDecision, { allowed: false, reason: 'UNVERIFIED_EXTERNAL_RESOURCE' });
  }

  // Wrong vehicleId or inactive binding in verifiedResourceBinding is also denied
  const wrongVehicleBinding = await evaluateVehiclePermission({
    vehicleId: vehicle1._id,
    userId: memberA,
    permission: 'device:command',
    scopeType: 'DEVICE',
    scopeResourceId: device1,
    channel: 'ONLINE',
    verifiedResourceBinding: createVerifiedExternalResourceBinding({
      scopeType: 'DEVICE',
      resourceId: device1,
      vehicleId: vehicle2._id,
      isActive: true,
    }),
    now,
  });
  assert.deepEqual(wrongVehicleBinding, { allowed: false, reason: 'UNVERIFIED_EXTERNAL_RESOURCE' });

  const inactiveBinding = await evaluateVehiclePermission({
    vehicleId: vehicle1._id,
    userId: memberA,
    permission: 'device:command',
    scopeType: 'DEVICE',
    scopeResourceId: device1,
    channel: 'ONLINE',
    verifiedResourceBinding: createVerifiedExternalResourceBinding({
      scopeType: 'DEVICE',
      resourceId: device1,
      vehicleId: vehicle1._id,
      isActive: false,
    }),
    now,
  });
  assert.deepEqual(inactiveBinding, { allowed: false, reason: 'UNVERIFIED_EXTERNAL_RESOURCE' });

  // Verified binding grants access on matching channel
  const verifiedOnline = await evaluateVehiclePermission({
    vehicleId: vehicle1._id,
    userId: memberA,
    permission: 'device:command',
    scopeType: 'DEVICE',
    scopeResourceId: device1,
    channel: 'ONLINE',
    verifiedResourceBinding: createVerifiedExternalResourceBinding({
      scopeType: 'DEVICE',
      resourceId: device1,
      vehicleId: vehicle1._id,
      isActive: true,
    }),
    now,
  });
  assert.equal(verifiedOnline.allowed, true);
  assert.equal(verifiedOnline.source, 'ACCESS_GRANT');

  // Unknown permissions are always denied immediately
  const unknownPerm = await evaluateVehiclePermission({
    vehicleId: vehicle1._id,
    userId: ownerId,
    permission: 'sunroof:override_safety',
  });
  assert.deepEqual(unknownPerm, { allowed: false, reason: 'UNKNOWN_OR_INVALID_PERMISSION' });

  // Future grant (startsAt > now) and expired evaluation time (now >= expiresAt) deny access
  const beforeStart = await evaluateVehiclePermission({
    vehicleId: vehicle1._id,
    userId: memberA,
    permission: 'module:actuate',
    scopeType: 'MODULE',
    scopeResourceId: moduleSunroof,
    channel: 'ONLINE',
    verifiedResourceBinding: createVerifiedExternalResourceBinding({
      scopeType: 'MODULE',
      resourceId: moduleSunroof,
      vehicleId: vehicle1._id,
      isActive: true,
    }),
    now,
  });
  assert.equal(beforeStart.allowed, false);

  const afterBleExpiry = await evaluateVehiclePermission({
    vehicleId: vehicle1._id,
    userId: memberA,
    permission: 'device:connect',
    scopeType: 'DEVICE',
    scopeResourceId: device1,
    channel: 'BLE_OFFLINE',
    verifiedResourceBinding: createVerifiedExternalResourceBinding({
      scopeType: 'DEVICE',
      resourceId: device1,
      vehicleId: vehicle1._id,
      isActive: true,
    }),
    now: new Date(inOneHour.getTime() + 1_000),
  });
  assert.equal(afterBleExpiry.allowed, false);

  // Batch expiration marks elapsed ACTIVE grants as EXPIRED
  const expiredCount = await expireElapsedAccessGrants(
    vehicle1._id,
    new Date(inOneHour.getTime() + 1_000),
  );
  assert.equal(expiredCount, 1);
  assert.equal((await AccessGrantModel.findById(grantDev1Ble._id))?.status, 'EXPIRED');

  // 8e. Revoking one grant leaves independent grants untouched
  await revokeAccessGrant({
    vehicleId: vehicle1._id,
    grantId: grantDev1Online._id,
    actorUserId: ownerId,
    reason: 'Revoke device 1 online only',
    now,
  });
  assert.equal((await AccessGrantModel.findById(grantDev1Online._id))?.status, 'REVOKED');
  assert.equal((await AccessGrantModel.findById(grantDev2Online._id))?.status, 'ACTIVE');
  assert.equal((await AccessGrantModel.findById(grantModuleFuture._id))?.status, 'ACTIVE');

  // 8f. TKT-012: suspending a Membership revokes its active AccessGrants (current and future
  // windows) in the same transaction; reactivation restores base permissions only.
  const suspendOutcome = await suspendMembership({
    vehicleId: vehicle1._id,
    membershipId: memA._id,
    actorUserId: ownerId,
    reason: 'Temporary travel pause',
    now,
  });
  assert.equal(suspendOutcome.membership.status, 'SUSPENDED');
  assert.equal(suspendOutcome.revokedGrantsCount, 2); // grantDev2Online + grantModuleFuture
  for (const grantId of [grantDev2Online._id, grantModuleFuture._id]) {
    const grant = await AccessGrantModel.findById(grantId).lean();
    assert.equal(grant?.status, 'REVOKED');
    assert.equal(grant?.revokeReason, 'Temporary travel pause');
    assert.equal(grant?.revokedByUserId?.equals(ownerId), true);
  }
  assert.equal((await AccessGrantModel.findById(grantDev1Ble._id).lean())?.status, 'EXPIRED');
  const whileSuspended = await evaluateVehiclePermission({
    vehicleId: vehicle1._id,
    userId: memberA,
    permission: 'device:read',
    scopeType: 'DEVICE',
    scopeResourceId: device2,
    channel: 'ONLINE',
    verifiedResourceBinding: createVerifiedExternalResourceBinding({
      scopeType: 'DEVICE',
      resourceId: device2,
      vehicleId: vehicle1._id,
      isActive: true,
    }),
    now,
  });
  assert.deepEqual(whileSuspended, { allowed: false, reason: 'MEMBERSHIP_INACTIVE_OR_MISSING' });

  await reactivateMembership({
    vehicleId: vehicle1._id,
    membershipId: memA._id,
    actorUserId: ownerId,
    now,
  });
  const afterReactivate = await evaluateVehiclePermission({
    vehicleId: vehicle1._id,
    userId: memberA,
    permission: 'device:read',
    scopeType: 'DEVICE',
    scopeResourceId: device2,
    channel: 'ONLINE',
    verifiedResourceBinding: createVerifiedExternalResourceBinding({
      scopeType: 'DEVICE',
      resourceId: device2,
      vehicleId: vehicle1._id,
      isActive: true,
    }),
    now,
  });
  assert.equal(afterReactivate.allowed, false);
  assert.equal((await AccessGrantModel.findById(grantDev2Online._id).lean())?.status, 'REVOKED');
  const baseAfterReactivate = await evaluateVehiclePermission({
    vehicleId: vehicle1._id,
    userId: memberA,
    permission: 'vehicle:read',
    now,
  });
  assert.equal(baseAfterReactivate.allowed, true);

  // 8g. Revoking Membership cascades to remaining ACTIVE grants (none left after suspension) AND
  // a new Membership does NOT inherit old grants
  const lateGrant = await createAccessGrant({
    vehicleId: vehicle1._id,
    membershipId: memA._id,
    subjectUserId: memberA,
    actorUserId: ownerId,
    scopeType: 'VEHICLE',
    channel: 'ONLINE',
    permissions: ['vehicle:read'],
    now,
  });
  const revokeOutcome = await revokeMembership({
    vehicleId: vehicle1._id,
    membershipId: memA._id,
    actorUserId: ownerId,
    reason: 'End membership',
    now,
  });
  assert.equal(revokeOutcome.revokedGrantsCount, 1);
  assert.equal(revokeOutcome.alreadyRevoked, false);
  assert.equal((await AccessGrantModel.findById(lateGrant._id).lean())?.status, 'REVOKED');

  // Terminal REVOKED membership cannot be reactivated
  await assert.rejects(
    () =>
      reactivateMembership({
        vehicleId: vehicle1._id,
        membershipId: memA._id,
        actorUserId: ownerId,
      }),
    (err: unknown) => err instanceof VehicleServiceError && err.code === 'CONFLICT',
  );

  // Re-invite memberA -> new Membership gets new _id and does NOT inherit grants tied to old membershipId
  const reinviteA = await inviteMember(vehicle1._id, ownerId, memberA, ['vehicle:read']);
  assert.ok(reinviteA);
  const memA2 = await acceptInvitation(reinviteA._id, memberA);
  assert.ok(memA2);

  // Even if an attacker/legacy bug left an ACTIVE grant pointing to old memA._id, evaluation rejects it!
  await AccessGrantModel.collection.insertOne({
    vehicleId: vehicle1._id,
    membershipId: memA._id, // old REVOKED membershipId
    subjectUserId: memberA,
    scopeType: 'DEVICE',
    scopeResourceId: device2,
    channel: 'ONLINE',
    permissions: ['device:read'],
    status: 'ACTIVE',
    startsAt: now,
    expiresAt: null,
    grantedByUserId: ownerId,
    revokedAt: null,
    revokedByUserId: null,
    revokeReason: null,
    expiredAt: null,
    createdAt: now,
    updatedAt: now,
  });

  const nonInheritedCheck = await evaluateVehiclePermission({
    vehicleId: vehicle1._id,
    userId: memberA,
    permission: 'device:read',
    scopeType: 'DEVICE',
    scopeResourceId: device2,
    channel: 'ONLINE',
    verifiedResourceBinding: createVerifiedExternalResourceBinding({
      scopeType: 'DEVICE',
      resourceId: device2,
      vehicleId: vehicle1._id,
      isActive: true,
    }),
    now,
  });
  assert.equal(nonInheritedCheck.allowed, false);
});

test('9. Archived vehicles revoke pending invitations and active grants and deny all operational actions', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const memberId = new Types.ObjectId();
  const pendingInviteeId = new Types.ObjectId();

  const vehicle = await createVehicle(ownerId, { name: 'Soon Archived Sedan' });

  const invMember = await inviteMember(vehicle._id, ownerId, memberId, [
    'vehicle:read',
    'device:link',
  ]);
  const invPending = await inviteMember(vehicle._id, ownerId, pendingInviteeId, ['vehicle:read']);
  assert.ok(invMember && invPending);
  const mem = await acceptInvitation(invMember._id, memberId);
  assert.ok(mem);

  const activeGrant = await createAccessGrant({
    vehicleId: vehicle._id,
    membershipId: mem._id,
    subjectUserId: memberId,
    actorUserId: ownerId,
    scopeType: 'VEHICLE',
    channel: 'ONLINE',
    permissions: ['vehicle:update'],
  });

  const archived = await archiveVehicle({
    vehicleId: vehicle._id,
    actorUserId: ownerId,
    reason: 'Vehicle sold',
  });
  assert.equal(archived.vehicle.status, 'ARCHIVED');
  assert.equal(archived.alreadyArchived, false);
  assert.equal((await InvitationModel.findById(invPending._id))?.status, 'REVOKED');
  assert.equal((await AccessGrantModel.findById(activeGrant._id))?.status, 'REVOKED');

  // Denials across read, list, device linking, invitation creation, invitation acceptance, and new grants
  assert.equal(await canAccessVehicle(vehicle._id, ownerId), false);
  assert.equal(await canLinkDeviceToVehicle(vehicle._id, ownerId), false);
  assert.equal(await canLinkDeviceToVehicle(vehicle._id, memberId), false);
  assert.equal(await getVehicleForUser(vehicle._id, ownerId), null);
  assert.equal((await listOwnedVehicles(ownerId)).length, 0);
  assert.equal((await listAccessibleVehicles(memberId)).items.length, 0);
  assert.equal(
    await inviteMember(vehicle._id, ownerId, new Types.ObjectId(), ['vehicle:read']),
    null,
  );
  await assert.rejects(
    () => acceptInvitation(invPending._id, pendingInviteeId),
    (err: unknown) => err instanceof VehicleServiceError && err.code === 'CONFLICT',
  );

  await assert.rejects(
    () =>
      createAccessGrant({
        vehicleId: vehicle._id,
        membershipId: mem._id,
        subjectUserId: memberId,
        actorUserId: ownerId,
        scopeType: 'VEHICLE',
        channel: 'ONLINE',
        permissions: ['device:link'],
      }),
    (err: unknown) => err instanceof VehicleServiceError && err.code === 'NOT_FOUND',
  );
});

test('10. Controlled migration and readiness: detects legacy TTL & inconsistencies, refuses fabricated audit actors, and restores readiness', async () => {
  assert.ok(rootClient);
  const isolatedDb = rootClient.db('vehicle_legacy_migration_test');
  await isolatedDb.dropDatabase();

  // Seed legacy pre-TKT-010 schema state:
  // - unfiltered unique index on memberships { vehicleId: 1, userId: 1 }
  // - destructive TTL index on invitations { expiresAt: 1 } with expireAfterSeconds: 0
  const vehiclesCol = isolatedDb.collection('vehicles');
  const membershipsCol = isolatedDb.collection('memberships');
  const invitationsCol = isolatedDb.collection('invitations');

  await membershipsCol.createIndex(
    { vehicleId: 1, userId: 1 },
    { unique: true, name: 'vehicleId_1_userId_1' },
  );
  await invitationsCol.createIndex(
    { expiresAt: 1 },
    { expireAfterSeconds: 0, name: 'expiresAt_1' },
  );

  // Critical index check must fail while legacy indexes are present and critical partial indexes are missing
  await assert.rejects(
    () => assertCriticalVehicleIndexes(isolatedDb as never),
    VehicleSchemaNotReadyError,
  );

  // Case A: Legacy vehicle missing createdByUserId must be flagged by preflight and BLOCK automatic migration
  const orphanAuditVehicleId = new Types.ObjectId();
  const ownerId = new Types.ObjectId();
  await vehiclesCol.insertOne({
    _id: orphanAuditVehicleId,
    name: 'Legacy Unaudited Car',
    ownerUserId: ownerId,
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  await membershipsCol.insertOne({
    vehicleId: orphanAuditVehicleId,
    userId: ownerId,
    role: 'OWNER',
    permissions: ['*'], // legacy wildcard on OWNER before TKT-010
    grantedByUserId: ownerId,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  const blockedReport = await inspectVehicleMigrationPreflight(isolatedDb as never);
  assert.equal(blockedReport.canAutoMigrateSafely, false);
  assert.deepEqual(blockedReport.destructiveInvitationTtlIndexNames, ['expiresAt_1']);
  assert.deepEqual(blockedReport.legacyUnfilteredMembershipUniqueIndexNames, [
    'vehicleId_1_userId_1',
  ]);
  assert.equal(blockedReport.vehiclesMissingAuditActorCount, 1);

  await assert.rejects(
    () => applyControlledVehicleMigration(isolatedDb as never),
    VehicleMigrationBlockedError,
  );

  // Administrator explicitly attributes verified audit actor and normalizes OWNER permissions
  await vehiclesCol.updateOne(
    { _id: orphanAuditVehicleId },
    { $set: { createdByUserId: ownerId } },
  );
  await membershipsCol.updateOne(
    { vehicleId: orphanAuditVehicleId, role: 'OWNER' },
    { $set: { permissions: ['vehicle:manage'] } },
  );

  // Also insert an expired legacy PENDING invitation to verify migration transitions it to EXPIRED safely
  const legacyExpiredInvId = new Types.ObjectId();
  await invitationsCol.insertOne({
    _id: legacyExpiredInvId,
    vehicleId: orphanAuditVehicleId,
    inviterUserId: ownerId,
    inviteeUserId: new Types.ObjectId(),
    permissions: ['vehicle:read'],
    status: 'PENDING',
    expiresAt: new Date(Date.now() - 60_000),
    createdAt: new Date(Date.now() - 120_000),
    updatedAt: new Date(Date.now() - 120_000),
  });

  const readyToMigrate = await inspectVehicleMigrationPreflight(isolatedDb as never);
  assert.equal(readyToMigrate.canAutoMigrateSafely, true);
  assert.equal(readyToMigrate.expiredPendingInvitationsCount, 1);

  // Case B: Simulate interrupted partial migration right after dropping destructive TTL index.
  // Readiness MUST remain negative (503) while migration is incomplete!
  await assert.rejects(
    () =>
      applyControlledVehicleMigration(isolatedDb as never, {
        onStep: async (step) => {
          if (step === 'after_drop_destructive_ttl') {
            throw new Error('simulated crash mid-migration');
          }
        },
      }),
    /simulated crash mid-migration/,
  );

  await assert.rejects(
    () => assertCriticalVehicleIndexes(isolatedDb as never),
    VehicleSchemaNotReadyError,
  );
  const midCrashApp = createApp({
    ...setupVehicleTestAuth(),
    readinessCheck: async () => {
      await assertCriticalVehicleIndexes(isolatedDb as never);
    },
  });
  assert.equal((await midCrashApp.inject('/health/ready')).statusCode, 503);
  await midCrashApp.close();

  // Case C: Resume partial migration AND verify zero unsafe uniqueness window during index replacement
  let bothUniqueIndexesObservedSimultaneously = false;
  const postMigrationReport = await applyControlledVehicleMigration(isolatedDb as never, {
    onStep: async (step) => {
      if (step === 'after_create_replacement_indexes') {
        const currentMembershipIndexes = await membershipsCol.listIndexes().toArray();
        const hasNewPartial = currentMembershipIndexes.some(
          (idx) => idx.name === 'membership_active_vehicle_user_unique',
        );
        const hasOldUnfiltered = currentMembershipIndexes.some(
          (idx) => idx.name === 'vehicleId_1_userId_1',
        );
        bothUniqueIndexesObservedSimultaneously = hasNewPartial && hasOldUnfiltered;
      }
    },
  });
  assert.equal(
    bothUniqueIndexesObservedSimultaneously,
    true,
    'Replacement partial unique index must be active BEFORE legacy unique index is dropped',
  );
  assert.deepEqual(postMigrationReport.destructiveInvitationTtlIndexNames, []);
  assert.deepEqual(postMigrationReport.legacyUnfilteredMembershipUniqueIndexNames, []);
  assert.equal(postMigrationReport.expiredPendingInvitationsCount, 0);
  assert.deepEqual(postMigrationReport.missingOrInvalidIndexIssues, []);

  // Case D: Idempotency — re-running applyControlledVehicleMigration produces identical safe state
  const idempotentSecondRun = await applyControlledVehicleMigration(isolatedDb as never);
  const idempotentThirdRun = await applyControlledVehicleMigration(isolatedDb as never);
  assert.deepEqual(idempotentSecondRun.missingOrInvalidIndexIssues, []);
  assert.deepEqual(idempotentThirdRun.missingOrInvalidIndexIssues, []);
  assert.equal(idempotentThirdRun.vehiclesMissingStatusCount, 0);
  assert.equal(idempotentThirdRun.membershipsMissingStatusCount, 0);

  // Critical indexes now pass!
  await assert.doesNotReject(() => assertCriticalVehicleIndexes(isolatedDb as never));
  const migratedInv = await invitationsCol.findOne({ _id: legacyExpiredInvId });
  assert.equal(migratedInv?.status, 'EXPIRED');

  // Verify HTTP /health/ready reflects real MongoDB + critical index checks
  const liveReadyApp = createApp({
    ...setupVehicleTestAuth(),
    readinessCheck: () => assertVehicleDatabaseReady(mongoose),
  });
  assert.equal((await liveReadyApp.inject('/health/ready')).statusCode, 200);
  await liveReadyApp.close();

  await isolatedDb.dropDatabase();
});

test('10b. Cross-document concurrent integrity: AccessGrant vs revokeMembership, Invitation vs archiveVehicle, and AccessGrant vs archiveVehicle', async () => {
  await resetVehicleCollections();

  // 1. Concurrent createAccessGrant || revokeMembership (multiple rounds to exercise interleavings)
  for (let round = 0; round < 5; round += 1) {
    const ownerId = new Types.ObjectId();
    const memberId = new Types.ObjectId();
    const deviceId = new Types.ObjectId();

    const vehicle = await createVehicle(ownerId, { name: `Race Grant vs Revoke #${round}` });
    const inv = await inviteMember(vehicle._id, ownerId, memberId, ['vehicle:read']);
    assert.ok(inv);
    const membership = await acceptInvitation(inv._id, memberId);
    assert.ok(membership);

    await Promise.allSettled([
      createAccessGrant({
        vehicleId: vehicle._id,
        membershipId: membership._id,
        subjectUserId: memberId,
        actorUserId: ownerId,
        scopeType: 'DEVICE',
        scopeResourceId: deviceId,
        verifiedResourceBinding: testOwnershipEvidence('DEVICE', deviceId, vehicle._id),
        channel: 'ONLINE',
        permissions: ['device:read', 'device:command'],
      }),
      revokeMembership({
        vehicleId: vehicle._id,
        membershipId: membership._id,
        actorUserId: ownerId,
        reason: 'Concurrent revocation',
      }),
    ]);

    const finalMembership = await MembershipModel.findById(membership._id).lean();
    assert.equal(finalMembership?.status, 'REVOKED');

    const activeGrantsLeft = await AccessGrantModel.countDocuments({
      membershipId: membership._id,
      status: 'ACTIVE',
    });
    assert.equal(
      activeGrantsLeft,
      0,
      'No ACTIVE AccessGrant may remain after concurrent revokeMembership',
    );
  }

  // 2. Concurrent createAccessGrant || archiveVehicle
  for (let round = 0; round < 5; round += 1) {
    const ownerId = new Types.ObjectId();
    const memberId = new Types.ObjectId();
    const deviceId = new Types.ObjectId();

    const vehicle = await createVehicle(ownerId, { name: `Race Grant vs Archive #${round}` });
    const inv = await inviteMember(vehicle._id, ownerId, memberId, ['vehicle:read']);
    assert.ok(inv);
    const membership = await acceptInvitation(inv._id, memberId);
    assert.ok(membership);

    await Promise.allSettled([
      createAccessGrant({
        vehicleId: vehicle._id,
        membershipId: membership._id,
        subjectUserId: memberId,
        actorUserId: ownerId,
        scopeType: 'DEVICE',
        scopeResourceId: deviceId,
        verifiedResourceBinding: testOwnershipEvidence('DEVICE', deviceId, vehicle._id),
        channel: 'ONLINE',
        permissions: ['device:read'],
      }),
      archiveVehicle({
        vehicleId: vehicle._id,
        actorUserId: ownerId,
        reason: 'Concurrent archive',
      }),
    ]);

    const finalVehicle = await VehicleModel.findById(vehicle._id).lean();
    assert.equal(finalVehicle?.status, 'ARCHIVED');

    const activeGrantsLeft = await AccessGrantModel.countDocuments({
      vehicleId: vehicle._id,
      status: 'ACTIVE',
    });
    assert.equal(
      activeGrantsLeft,
      0,
      'No ACTIVE AccessGrant may remain after concurrent archiveVehicle',
    );
  }

  // 3. Concurrent inviteMember || archiveVehicle AND acceptInvitation || archiveVehicle
  for (let round = 0; round < 5; round += 1) {
    const ownerId = new Types.ObjectId();
    const inviteeCreateRace = new Types.ObjectId();
    const inviteeAcceptRace = new Types.ObjectId();

    const vehicle = await createVehicle(ownerId, { name: `Race Invite vs Archive #${round}` });
    const preExistingInv = await inviteMember(vehicle._id, ownerId, inviteeAcceptRace, [
      'vehicle:read',
    ]);
    assert.ok(preExistingInv);

    await Promise.allSettled([
      inviteMember(vehicle._id, ownerId, inviteeCreateRace, ['vehicle:read']),
      acceptInvitation(preExistingInv._id, inviteeAcceptRace),
      archiveVehicle({
        vehicleId: vehicle._id,
        actorUserId: ownerId,
        reason: 'Concurrent vehicle retirement',
      }),
    ]);

    const finalVehicle = await VehicleModel.findById(vehicle._id).lean();
    assert.equal(finalVehicle?.status, 'ARCHIVED');

    const pendingInvitationsLeft = await InvitationModel.countDocuments({
      vehicleId: vehicle._id,
      status: 'PENDING',
    });
    assert.equal(
      pendingInvitationsLeft,
      0,
      'No PENDING Invitation may remain on an ARCHIVED vehicle',
    );

    // Effective authorization must always check current vehicle & membership states and deny!
    assert.equal(await canAccessVehicle(vehicle._id, ownerId), false);
    assert.equal(await canAccessVehicle(vehicle._id, inviteeCreateRace), false);
    assert.equal(await canAccessVehicle(vehicle._id, inviteeAcceptRace), false);
    assert.equal(await getVehicleForUser(vehicle._id, inviteeAcceptRace), null);
  }
});

async function rejectsWithCode(work: () => Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(
    work,
    (err: unknown) => err instanceof VehicleServiceError && err.code === code,
    `Expected ${code}`,
  );
}

async function addAcceptedMember(
  vehicleId: Types.ObjectId,
  ownerId: Types.ObjectId,
  permissions: string[],
): Promise<{ memberId: Types.ObjectId; membershipId: Types.ObjectId }> {
  const memberId = new Types.ObjectId();
  const invitation = await inviteMember(vehicleId, ownerId, memberId, permissions);
  assert.ok(invitation);
  const membership = await acceptInvitation(invitation._id, memberId);
  assert.ok(membership);
  return { memberId, membershipId: membership._id };
}

async function vehiclePersistenceSnapshot(vehicleId: Types.ObjectId): Promise<string> {
  const [vehicle, memberships, invitations, grants] = await Promise.all([
    VehicleModel.findById(vehicleId).lean(),
    MembershipModel.find({ vehicleId }).sort({ _id: 1 }).lean(),
    InvitationModel.find({ vehicleId }).sort({ _id: 1 }).lean(),
    AccessGrantModel.find({ vehicleId }).sort({ _id: 1 }).lean(),
  ]);
  return JSON.stringify({ vehicle, memberships, invitations, grants });
}

async function insertRawPendingInvitation(
  vehicleId: Types.ObjectId,
  inviterUserId: Types.ObjectId,
  expiresAt: Date,
): Promise<Types.ObjectId> {
  const _id = new Types.ObjectId();
  await InvitationModel.collection.insertOne({
    _id,
    vehicleId,
    inviterUserId,
    inviteeUserId: new Types.ObjectId(),
    targetRole: 'MEMBER',
    permissions: ['vehicle:read'],
    status: 'PENDING',
    expiresAt,
    acceptedAt: null,
    acceptedByUserId: null,
    revokedAt: null,
    revokedByUserId: null,
    revokeReason: null,
    expiredAt: null,
    updatedByUserId: null,
    createdAt: new Date(expiresAt.getTime() - 60_000),
    updatedAt: new Date(expiresAt.getTime() - 60_000),
  });
  return _id;
}

async function insertRawActiveGrant(input: {
  vehicleId: Types.ObjectId;
  membershipId: Types.ObjectId;
  subjectUserId: Types.ObjectId;
  grantedByUserId: Types.ObjectId;
  permissions: string[];
  expiresAt: Date | null;
  channel?: 'ONLINE' | 'ANY';
}): Promise<Types.ObjectId> {
  const _id = new Types.ObjectId();
  const created = new Date(Date.now() - 120_000);
  await AccessGrantModel.collection.insertOne({
    _id,
    vehicleId: input.vehicleId,
    membershipId: input.membershipId,
    subjectUserId: input.subjectUserId,
    scopeType: 'VEHICLE',
    scopeResourceId: null,
    channel: input.channel ?? 'ONLINE',
    permissions: input.permissions,
    status: 'ACTIVE',
    startsAt: created,
    expiresAt: input.expiresAt,
    grantedByUserId: input.grantedByUserId,
    updatedByUserId: null,
    revokedAt: null,
    revokedByUserId: null,
    revokeReason: null,
    expiredAt: null,
    createdAt: created,
    updatedAt: created,
  });
  return _id;
}

test('12. TKT-011 create/update validation and PATCH semantics are strict, closed, and side-effect free on rejection', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, {
    name: 'Daily Driver',
    make: 'Mazda',
    model: '3',
    generation: 'BL',
    trim: 's',
    year: 2011,
    bodyStyle: 'sedan',
    engine: '2.0 MZR',
    transmission: 'automatic',
    fuelType: 'gasoline',
  });
  const before = await VehicleModel.findById(vehicle._id).lean();
  assert.ok(before);
  await new Promise((resolve) => setTimeout(resolve, 5));

  const updated = await updateVehicle({
    vehicleId: vehicle._id,
    actorUserId: ownerId,
    changes: { name: '  Weekend Car  ', trim: null, year: 2012 },
  });
  assert.equal(updated.name, 'Weekend Car');
  assert.equal(updated.trim, null);
  assert.equal(updated.year, 2012);
  assert.equal(updated.make, 'Mazda');
  assert.equal(updated.model, '3');
  assert.equal(updated.generation, 'BL');
  assert.equal(updated.bodyStyle, 'sedan');
  assert.equal(updated.engine, '2.0 MZR');
  assert.equal(updated.transmission, 'automatic');
  assert.equal(updated.fuelType, 'gasoline');
  assert.equal(updated.status, 'ACTIVE');
  assert.equal(updated.updatedByUserId?.equals(ownerId), true);
  assert.equal(updated.createdByUserId.equals(ownerId), true);
  assert.equal(updated.ownerUserId.equals(ownerId), true);
  assert.ok(updated.updatedAt.getTime() > before.updatedAt.getTime());
  assert.equal(updated.createdAt.getTime(), before.createdAt.getTime());

  const cleared = await updateVehicle({
    vehicleId: vehicle._id,
    actorUserId: ownerId,
    changes: {
      make: null,
      model: null,
      generation: null,
      year: null,
      bodyStyle: null,
      engine: null,
      transmission: null,
      fuelType: null,
    },
  });
  assert.equal(cleared.name, 'Weekend Car');
  for (const field of ['make', 'model', 'generation', 'trim', 'year', 'bodyStyle'] as const) {
    assert.equal(cleared[field], null, `${field} cleared`);
  }
  for (const field of ['engine', 'transmission', 'fuelType'] as const) {
    assert.equal(cleared[field], null, `${field} cleared`);
  }

  const snapshot = await vehiclePersistenceSnapshot(vehicle._id);
  const invalidChanges: unknown[] = [
    {},
    { userId: ownerId },
    { name: null },
    { name: '   ' },
    { name: 'x'.repeat(121) },
    { make: '' },
    { make: '\tMazda' },
    { model: 'Mazda 3\n' },
    { trim: 'x\u007f' },
    { engine: 'x'.repeat(81) },
    { year: 1885 },
    { year: 2101 },
    { year: 2011.5 },
    { year: '2011' },
    { ownerUserId: new Types.ObjectId() },
    { status: 'ARCHIVED' },
    { archivedAt: new Date() },
    { createdByUserId: ownerId },
  ];
  for (const changes of invalidChanges) {
    await rejectsWithCode(
      () =>
        updateVehicle({
          vehicleId: vehicle._id,
          actorUserId: ownerId,
          changes: changes as never,
        }),
      'VALIDATION_ERROR',
    );
  }
  assert.equal(await vehiclePersistenceSnapshot(vehicle._id), snapshot);

  const invalidCreates: unknown[] = [
    { name: '\tCar' },
    { name: 'Car\r' },
    { name: '' },
    { name: 'Car', make: ' ' },
    { name: 'Car', fuelType: 'gas\u0000' },
    { name: 'Car', engine: 'x'.repeat(81) },
    { name: 'Car', bodyStyle: 'x'.repeat(61) },
    { name: 'Car', userId: ownerId },
    { name: 'Car', status: 'ARCHIVED' },
  ];
  for (const input of invalidCreates) {
    await rejectsWithCode(() => createVehicle(ownerId, input as never), 'VALIDATION_ERROR');
  }
  assert.equal(await VehicleModel.countDocuments({}), 1);
  assert.equal(await MembershipModel.countDocuments({}), 1);

  // No single-vehicle limit and no brand assumptions: the same owner may hold many vehicles.
  for (const name of ['Second Car', 'Third Car', 'Fourth Car']) {
    await createVehicle(ownerId, { name });
  }
  assert.equal((await listOwnedVehicles(ownerId)).length, 4);
});

test('13. TKT-011 owner-only mutations: MEMBER with vehicle:update/manage gets FORBIDDEN, no visibility gets NOT_FOUND, no side effects', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Protected Family SUV' });
  const updater = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read', 'vehicle:update']);
  const manager = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:manage']);
  const grantUpdater = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read']);
  await createAccessGrant({
    vehicleId: vehicle._id,
    membershipId: grantUpdater.membershipId,
    subjectUserId: grantUpdater.memberId,
    actorUserId: ownerId,
    scopeType: 'VEHICLE',
    channel: 'ONLINE',
    permissions: ['vehicle:update'],
  });
  const noRead = await addAcceptedMember(vehicle._id, ownerId, ['device:read']);
  const outsider = new Types.ObjectId();
  const elapsedInvitationId = await insertRawPendingInvitation(
    vehicle._id,
    ownerId,
    new Date(Date.now() - 60_000),
  );

  assert.equal((await getAccessibleVehicle(vehicle._id, ownerId)).role, 'OWNER');
  assert.equal((await getAccessibleVehicle(vehicle._id, updater.memberId)).role, 'MEMBER');
  assert.equal((await getAccessibleVehicle(vehicle._id, manager.memberId)).role, 'MEMBER');
  await rejectsWithCode(() => getAccessibleVehicle(vehicle._id, noRead.memberId), 'NOT_FOUND');
  await rejectsWithCode(() => getAccessibleVehicle(vehicle._id, outsider), 'NOT_FOUND');

  const snapshot = await vehiclePersistenceSnapshot(vehicle._id);
  for (const reader of [updater, manager, grantUpdater]) {
    await rejectsWithCode(
      () =>
        updateVehicle({
          vehicleId: vehicle._id,
          actorUserId: reader.memberId,
          changes: { name: 'Hijacked' },
        }),
      'FORBIDDEN',
    );
    await rejectsWithCode(
      () => archiveVehicle({ vehicleId: vehicle._id, actorUserId: reader.memberId }),
      'FORBIDDEN',
    );
  }
  for (const invisible of [noRead.memberId, outsider]) {
    await rejectsWithCode(
      () =>
        updateVehicle({
          vehicleId: vehicle._id,
          actorUserId: invisible,
          changes: { name: 'Hijacked' },
        }),
      'NOT_FOUND',
    );
    await rejectsWithCode(
      () => archiveVehicle({ vehicleId: vehicle._id, actorUserId: invisible }),
      'NOT_FOUND',
    );
  }
  const missingVehicleId = new Types.ObjectId();
  await rejectsWithCode(
    () =>
      updateVehicle({ vehicleId: missingVehicleId, actorUserId: ownerId, changes: { name: 'X' } }),
    'NOT_FOUND',
  );
  await rejectsWithCode(
    () => archiveVehicle({ vehicleId: missingVehicleId, actorUserId: ownerId }),
    'NOT_FOUND',
  );
  await rejectsWithCode(() => getAccessibleVehicle(missingVehicleId, ownerId), 'NOT_FOUND');

  // Rejections never touch Vehicle, memberships, grants, or elapsed invitations.
  assert.equal(await vehiclePersistenceSnapshot(vehicle._id), snapshot);
  assert.equal((await InvitationModel.findById(elapsedInvitationId).lean())?.status, 'PENDING');

  // Canonical ownership inconsistency: the owner itself sees NOT_FOUND everywhere (fail closed).
  await MembershipModel.collection.updateOne(
    { vehicleId: vehicle._id, role: 'OWNER' },
    { $set: { status: 'SUSPENDED', suspendedAt: new Date(), suspendedByUserId: ownerId } },
  );
  const corruptedSnapshot = await vehiclePersistenceSnapshot(vehicle._id);
  await rejectsWithCode(() => getAccessibleVehicle(vehicle._id, ownerId), 'NOT_FOUND');
  await rejectsWithCode(() => getAccessibleVehicle(vehicle._id, updater.memberId), 'NOT_FOUND');
  await rejectsWithCode(
    () => updateVehicle({ vehicleId: vehicle._id, actorUserId: ownerId, changes: { name: 'X' } }),
    'NOT_FOUND',
  );
  await rejectsWithCode(
    () => archiveVehicle({ vehicleId: vehicle._id, actorUserId: ownerId }),
    'NOT_FOUND',
  );
  await rejectsWithCode(
    () =>
      updateVehicle({
        vehicleId: vehicle._id,
        actorUserId: updater.memberId,
        changes: { name: 'X' },
      }),
    'NOT_FOUND',
  );
  assert.equal((await listAccessibleVehicles(ownerId)).items.length, 0);
  assert.equal((await listAccessibleVehicles(updater.memberId)).items.length, 0);
  assert.equal(await vehiclePersistenceSnapshot(vehicle._id), corruptedSnapshot);
});

test('14. TKT-011 read access: only current VEHICLE ONLINE/ANY grants with vehicle:read bound to the current membership confer visibility', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Grant Matrix Coupe' });
  const member = await addAcceptedMember(vehicle._id, ownerId, ['device:read']);
  const now = new Date();

  const isVisible = async (at: Date = new Date()): Promise<boolean> => {
    const listed = (await listAccessibleVehicles(member.memberId, { now: at })).items.some((item) =>
      item.vehicle._id.equals(vehicle._id),
    );
    const detail = await getAccessibleVehicle(vehicle._id, member.memberId, { now: at }).then(
      () => true,
      (err: unknown) => {
        assert.ok(err instanceof VehicleServiceError && err.code === 'NOT_FOUND');
        return false;
      },
    );
    const evaluated = await evaluateVehiclePermission({
      vehicleId: vehicle._id,
      userId: member.memberId,
      permission: 'vehicle:read',
      now: at,
    });
    assert.equal(listed, detail, 'list and detail must agree');
    assert.equal(detail, evaluated.allowed, 'detail must agree with evaluateVehiclePermission');
    return detail;
  };

  assert.equal(await isVisible(), false);
  const deviceId = new Types.ObjectId();
  const moduleId = new Types.ObjectId();
  await createAccessGrant({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: member.memberId,
    actorUserId: ownerId,
    scopeType: 'DEVICE',
    scopeResourceId: deviceId,
    verifiedResourceBinding: testOwnershipEvidence('DEVICE', deviceId, vehicle._id),
    channel: 'ONLINE',
    permissions: ['device:read'],
  });
  await createAccessGrant({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: member.memberId,
    actorUserId: ownerId,
    scopeType: 'MODULE',
    scopeResourceId: moduleId,
    verifiedResourceBinding: testOwnershipEvidence('MODULE', moduleId, vehicle._id),
    channel: 'ONLINE',
    permissions: ['module:read'],
  });
  await createAccessGrant({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: member.memberId,
    actorUserId: ownerId,
    scopeType: 'VEHICLE',
    channel: 'BLE_OFFLINE',
    permissions: ['vehicle:read'],
    expiresAt: new Date(now.getTime() + 3_600_000),
  });
  await createAccessGrant({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: member.memberId,
    actorUserId: ownerId,
    scopeType: 'VEHICLE',
    channel: 'ONLINE',
    permissions: ['vehicle:update'],
  });
  await createAccessGrant({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: member.memberId,
    actorUserId: ownerId,
    scopeType: 'VEHICLE',
    channel: 'ONLINE',
    permissions: ['vehicle:read'],
    startsAt: new Date(now.getTime() + 3_600_000),
  });
  // Stale binding: an ACTIVE grant for this user/vehicle but a different (non-current) membership.
  await insertRawActiveGrant({
    vehicleId: vehicle._id,
    membershipId: new Types.ObjectId(),
    subjectUserId: member.memberId,
    grantedByUserId: ownerId,
    permissions: ['vehicle:read'],
    expiresAt: null,
  });
  assert.equal(await isVisible(), false, 'DEVICE/MODULE/BLE_OFFLINE/future/stale grants deny');

  const anyGrant = await createAccessGrant({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: member.memberId,
    actorUserId: ownerId,
    scopeType: 'VEHICLE',
    channel: 'ANY',
    permissions: ['vehicle:read'],
    expiresAt: new Date(now.getTime() + 60_000),
  });
  assert.equal(await isVisible(), true, 'VEHICLE ANY grant with vehicle:read confers read');
  assert.equal((await getAccessibleVehicle(vehicle._id, member.memberId)).role, 'MEMBER');
  assert.equal(
    await isVisible(new Date(now.getTime() + 120_000)),
    false,
    'elapsed grant no longer confers read even before it is marked EXPIRED',
  );
  await revokeAccessGrant({
    vehicleId: vehicle._id,
    grantId: anyGrant._id,
    actorUserId: ownerId,
  });
  assert.equal(await isVisible(), false);

  const onlineGrant = await createAccessGrant({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: member.memberId,
    actorUserId: ownerId,
    scopeType: 'VEHICLE',
    channel: 'ONLINE',
    permissions: ['vehicle:read'],
  });
  assert.equal(await isVisible(), true);
  await suspendMembership({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    actorUserId: ownerId,
  });
  assert.equal(await isVisible(), false, 'suspended membership denies even with a live grant');
  await reactivateMembership({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    actorUserId: ownerId,
  });
  assert.equal(
    (await AccessGrantModel.findById(onlineGrant._id).lean())?.status === 'ACTIVE',
    await isVisible(),
  );
});

test('15. TKT-011 keyset pagination: stable order, identical timestamps, skipped inconsistencies, bound cursors, and per-page reauthorization', async () => {
  await resetVehicleCollections();
  const userId = new Types.ObjectId();
  const otherOwner = new Types.ObjectId();
  const base = Date.parse('2026-01-01T00:00:00.000Z');
  const sameInstant = new Date(base + 1_000);

  const setCreatedAt = async (vehicleId: Types.ObjectId, createdAt: Date) => {
    await VehicleModel.collection.updateOne({ _id: vehicleId }, { $set: { createdAt } });
  };

  const owned: Array<Types.ObjectId> = [];
  for (let index = 0; index < 5; index += 1) {
    const created = await createVehicle(userId, { name: `Owned ${index}` });
    owned.push(created._id);
  }
  // Three owned vehicles share exactly the same createdAt (ties broken by _id).
  await setCreatedAt(owned[0]!, new Date(base + 3_000));
  await setCreatedAt(owned[1]!, sameInstant);
  await setCreatedAt(owned[2]!, sameInstant);
  await setCreatedAt(owned[3]!, sameInstant);
  await setCreatedAt(owned[4]!, new Date(base + 6_000));

  const shared: Array<{ vehicleId: Types.ObjectId; membershipId: Types.ObjectId }> = [];
  for (let index = 0; index < 3; index += 1) {
    const created = await createVehicle(otherOwner, { name: `Shared ${index}` });
    const invitation = await inviteMember(created._id, otherOwner, userId, ['vehicle:read']);
    assert.ok(invitation);
    const membership = await acceptInvitation(invitation._id, userId);
    assert.ok(membership);
    shared.push({ vehicleId: created._id, membershipId: membership._id });
    await setCreatedAt(created._id, new Date(base + 2_000 + index * 2_000));
  }

  // Interleaved non-visible records: archived, ownership-inconsistent, and shared without read.
  const archived = await createVehicle(userId, { name: 'Archived Owned' });
  await setCreatedAt(archived._id, new Date(base + 2_500));
  await archiveVehicle({ vehicleId: archived._id, actorUserId: userId });
  const inconsistent = await createVehicle(userId, { name: 'Inconsistent Owned' });
  await setCreatedAt(inconsistent._id, sameInstant);
  await VehicleModel.collection.updateOne(
    { _id: inconsistent._id },
    { $set: { ownerUserId: new Types.ObjectId() } },
  );
  const noRead = await createVehicle(otherOwner, { name: 'Shared Without Read' });
  const noReadInvitation = await inviteMember(noRead._id, otherOwner, userId, ['device:read']);
  assert.ok(noReadInvitation);
  await acceptInvitation(noReadInvitation._id, userId);
  await setCreatedAt(noRead._id, new Date(base + 4_500));

  const visible = await VehicleModel.find({
    _id: { $in: [...owned, ...shared.map((entry) => entry.vehicleId)] },
  })
    .sort({ createdAt: 1, _id: 1 })
    .lean();
  const expectedOrder = visible.map((vehicle) => String(vehicle._id));
  assert.equal(expectedOrder.length, 8);

  const collect = async (limit: number, role?: 'OWNER' | 'MEMBER') => {
    const ids: string[] = [];
    let cursor: string | undefined;
    let pages = 0;
    for (;;) {
      const page = await listAccessibleVehicles(userId, { limit, cursor, role });
      pages += 1;
      assert.ok(page.items.length <= limit);
      for (const item of page.items) {
        assert.equal(item.role, item.membership.role);
        ids.push(String(item.vehicle._id));
      }
      if (page.nextCursor === null) break;
      assert.equal(page.items.length, limit, 'non-final pages are full');
      assert.ok(page.nextCursor.length <= 256);
      cursor = page.nextCursor;
      assert.ok(pages < 50);
    }
    return { ids, pages };
  };

  for (const limit of [1, 2, 3, 7, 8, 100]) {
    const { ids, pages } = await collect(limit);
    assert.deepEqual(ids, expectedOrder, `limit ${limit} keeps order without omissions`);
    assert.equal(new Set(ids).size, ids.length);
    assert.equal(pages, Math.max(1, Math.ceil(expectedOrder.length / limit)));
  }
  const defaultPage = await listAccessibleVehicles(userId);
  assert.equal(defaultPage.items.length, 8);
  assert.equal(defaultPage.nextCursor, null);

  const ownedOnly = await collect(2, 'OWNER');
  assert.deepEqual(
    ownedOnly.ids,
    expectedOrder.filter((id) => owned.some((ownedId) => String(ownedId) === id)),
  );
  const sharedOnly = await collect(1, 'MEMBER');
  assert.deepEqual(
    sharedOnly.ids,
    expectedOrder.filter((id) => shared.some((entry) => String(entry.vehicleId) === id)),
  );

  for (const limit of [0, 101, 1.5, Number.NaN]) {
    await rejectsWithCode(() => listAccessibleVehicles(userId, { limit }), 'VALIDATION_ERROR');
  }

  // Cursor binding and validation.
  const firstPage = await listAccessibleVehicles(userId, { limit: 2 });
  assert.ok(firstPage.nextCursor);
  const validCursor = firstPage.nextCursor;
  await rejectsWithCode(
    () => listAccessibleVehicles(otherOwner, { limit: 2, cursor: validCursor }),
    'VALIDATION_ERROR',
  );
  await rejectsWithCode(
    () => listAccessibleVehicles(userId, { limit: 2, cursor: validCursor, role: 'OWNER' }),
    'VALIDATION_ERROR',
  );
  const payload = JSON.parse(Buffer.from(validCursor, 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const invalidCursors = [
    'not base64!',
    'a'.repeat(257),
    Buffer.from('not json').toString('base64url'),
    encode({ ...payload, v: 2 }),
    encode({ ...payload, extra: true }),
    encode({ ...payload, c: 'bogus' }),
    encode({ ...payload, c: '2026-01-01T00:00:01Z' }),
    encode({ ...payload, i: 'zzzz' }),
    encode({ ...payload, r: 'OWNER' }),
    encode({ ...payload, u: 'A'.repeat(22) }),
    encode([payload]),
    `${validCursor}A`,
  ];
  for (const cursor of invalidCursors) {
    await rejectsWithCode(
      () => listAccessibleVehicles(userId, { limit: 2, cursor }),
      'VALIDATION_ERROR',
    );
  }

  // Authorization is re-evaluated on every page: revoke a membership and a grant between pages.
  const memberPage1 = await listAccessibleVehicles(userId, { limit: 1, role: 'MEMBER' });
  assert.equal(String(memberPage1.items[0]?.vehicle._id), String(shared[0]!.vehicleId));
  await revokeMembership({
    vehicleId: shared[1]!.vehicleId,
    membershipId: shared[1]!.membershipId,
    actorUserId: otherOwner,
  });
  assert.ok(memberPage1.nextCursor);
  const memberPage2 = await listAccessibleVehicles(userId, {
    limit: 1,
    role: 'MEMBER',
    cursor: memberPage1.nextCursor,
  });
  assert.equal(String(memberPage2.items[0]?.vehicle._id), String(shared[2]!.vehicleId));
  assert.equal(memberPage2.nextCursor, null);

  const grantReader = await addAcceptedMember(noRead._id, otherOwner, ['device:read']);
  const grant = await createAccessGrant({
    vehicleId: noRead._id,
    membershipId: grantReader.membershipId,
    subjectUserId: grantReader.memberId,
    actorUserId: otherOwner,
    scopeType: 'VEHICLE',
    channel: 'ONLINE',
    permissions: ['vehicle:read'],
  });
  const earlierVehicle = await createVehicle(otherOwner, { name: 'Earlier Shared Vehicle' });
  const earlierInvitation = await inviteMember(
    earlierVehicle._id,
    otherOwner,
    grantReader.memberId,
    ['vehicle:read'],
  );
  assert.ok(earlierInvitation);
  await acceptInvitation(earlierInvitation._id, grantReader.memberId);
  await setCreatedAt(earlierVehicle._id, new Date(base + 500));
  const grantPage1 = await listAccessibleVehicles(grantReader.memberId, { limit: 1 });
  assert.equal(String(grantPage1.items[0]?.vehicle._id), String(earlierVehicle._id));
  assert.ok(grantPage1.nextCursor, 'grant-visible vehicle is announced as the next page');
  await revokeAccessGrant({ vehicleId: noRead._id, grantId: grant._id, actorUserId: otherOwner });
  const grantPage2 = await listAccessibleVehicles(grantReader.memberId, {
    limit: 1,
    cursor: grantPage1.nextCursor,
  });
  assert.equal(grantPage2.items.length, 0, 'a cursor never carries authorization forward');
  assert.equal(grantPage2.nextCursor, null);

  // Query plan: the bounded membership scan uses the existing user/status index (no new index).
  const explain = (await MembershipModel.collection
    .aggregate([
      { $match: { userId, status: 'ACTIVE', suspendedAt: null, revokedAt: null } },
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
      { $sort: { 'vehicle.createdAt': 1, 'vehicle._id': 1 } },
      { $limit: 3 },
    ])
    .explain('queryPlanner')) as unknown;
  assert.match(JSON.stringify(explain), /membership_user_status_vehicle_idx/);
});

test('16. TKT-011 archive: idempotent DELETE keeps the original record, cascades within the transaction, and preserves memberships', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Retiring Wagon' });
  const member = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read', 'device:link']);
  const pending = await inviteMember(vehicle._id, ownerId, new Types.ObjectId(), ['vehicle:read']);
  assert.ok(pending);
  const elapsedInvitationId = await insertRawPendingInvitation(
    vehicle._id,
    ownerId,
    new Date(Date.now() - 60_000),
  );
  const activeGrant = await createAccessGrant({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: member.memberId,
    actorUserId: ownerId,
    scopeType: 'VEHICLE',
    channel: 'ONLINE',
    permissions: ['vehicle:update'],
  });
  const elapsedGrantId = await insertRawActiveGrant({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: member.memberId,
    grantedByUserId: ownerId,
    permissions: ['device:read'],
    expiresAt: new Date(Date.now() - 30_000),
  });

  const beforeDenied = await vehiclePersistenceSnapshot(vehicle._id);
  await rejectsWithCode(
    () => archiveVehicle({ vehicleId: vehicle._id, actorUserId: member.memberId }),
    'FORBIDDEN',
  );
  await rejectsWithCode(
    () => archiveVehicle({ vehicleId: vehicle._id, actorUserId: ownerId, reason: 'bad\treason' }),
    'VALIDATION_ERROR',
  );
  assert.equal(await vehiclePersistenceSnapshot(vehicle._id), beforeDenied);

  const archivedAt = new Date();
  const first = await archiveVehicle({
    vehicleId: vehicle._id,
    actorUserId: ownerId,
    reason: '  Vehicle sold  ',
    now: archivedAt,
  });
  assert.equal(first.alreadyArchived, false);
  assert.equal(first.vehicle.status, 'ARCHIVED');
  assert.equal(first.vehicle.archivedAt?.getTime(), archivedAt.getTime());
  assert.equal(first.vehicle.archivedByUserId?.equals(ownerId), true);
  assert.equal(first.vehicle.archiveReason, 'Vehicle sold');
  assert.equal(first.vehicle.updatedByUserId?.equals(ownerId), true);

  const pendingAfter = await InvitationModel.findById(pending._id).lean();
  assert.equal(pendingAfter?.status, 'REVOKED');
  assert.equal(pendingAfter?.revokeReason, 'Vehicle sold');
  const elapsedAfter = await InvitationModel.findById(elapsedInvitationId).lean();
  assert.equal(elapsedAfter?.status, 'EXPIRED');
  assert.equal(elapsedAfter?.expiredAt?.getTime(), archivedAt.getTime());
  assert.equal(elapsedAfter?.revokedAt, null);
  assert.equal((await AccessGrantModel.findById(activeGrant._id).lean())?.status, 'REVOKED');
  const elapsedGrant = await AccessGrantModel.findById(elapsedGrantId).lean();
  assert.equal(elapsedGrant?.status, 'EXPIRED');
  assert.equal(elapsedGrant?.revokedAt, null);
  assert.equal(
    await MembershipModel.countDocuments({ vehicleId: vehicle._id, status: 'ACTIVE' }),
    2,
  );
  assert.equal(await VehicleModel.countDocuments({ _id: vehicle._id }), 1);

  const afterArchive = await vehiclePersistenceSnapshot(vehicle._id);
  const repeated = await archiveVehicle({
    vehicleId: vehicle._id,
    actorUserId: ownerId,
    reason: 'Different reason',
    now: new Date(archivedAt.getTime() + 60_000),
  });
  assert.equal(repeated.alreadyArchived, true);
  assert.equal(repeated.vehicle.archivedAt?.getTime(), archivedAt.getTime());
  assert.equal(repeated.vehicle.archiveReason, 'Vehicle sold');
  const repeatedWithoutReason = await archiveVehicle({
    vehicleId: vehicle._id,
    actorUserId: ownerId,
  });
  assert.equal(repeatedWithoutReason.alreadyArchived, true);
  assert.equal(await vehiclePersistenceSnapshot(vehicle._id), afterArchive);

  // Archived: GET → NOT_FOUND, PATCH by owner → CONFLICT, others → NOT_FOUND; nothing changes.
  await rejectsWithCode(() => getAccessibleVehicle(vehicle._id, ownerId), 'NOT_FOUND');
  await rejectsWithCode(() => getAccessibleVehicle(vehicle._id, member.memberId), 'NOT_FOUND');
  await rejectsWithCode(
    () => updateVehicle({ vehicleId: vehicle._id, actorUserId: ownerId, changes: { name: 'X' } }),
    'CONFLICT',
  );
  await rejectsWithCode(
    () =>
      updateVehicle({
        vehicleId: vehicle._id,
        actorUserId: member.memberId,
        changes: { name: 'X' },
      }),
    'NOT_FOUND',
  );
  await rejectsWithCode(
    () => archiveVehicle({ vehicleId: vehicle._id, actorUserId: member.memberId }),
    'NOT_FOUND',
  );
  await rejectsWithCode(
    () => archiveVehicle({ vehicleId: vehicle._id, actorUserId: new Types.ObjectId() }),
    'NOT_FOUND',
  );
  assert.equal((await listAccessibleVehicles(ownerId)).items.length, 0);
  assert.equal(await canLinkDeviceToVehicle(vehicle._id, member.memberId), false);
  assert.equal(await vehiclePersistenceSnapshot(vehicle._id), afterArchive);

  // Archived owner branch also verifies canonical ownership: corruption collapses to NOT_FOUND.
  await MembershipModel.collection.updateOne(
    { vehicleId: vehicle._id, role: 'OWNER' },
    { $set: { userId: new Types.ObjectId() } },
  );
  await rejectsWithCode(
    () => archiveVehicle({ vehicleId: vehicle._id, actorUserId: ownerId }),
    'NOT_FOUND',
  );
  await rejectsWithCode(
    () => updateVehicle({ vehicleId: vehicle._id, actorUserId: ownerId, changes: { name: 'X' } }),
    'NOT_FOUND',
  );
});

test('17. TKT-011 concurrency: simultaneous DELETE requests archive once and all return the winner record', async () => {
  await resetVehicleCollections();
  for (let round = 0; round < 5; round += 1) {
    const ownerId = new Types.ObjectId();
    const vehicle = await createVehicle(ownerId, { name: `Double Archive #${round}` });
    const results = await Promise.allSettled(
      ['first', 'second', 'third'].map((reason) =>
        archiveVehicle({ vehicleId: vehicle._id, actorUserId: ownerId, reason }),
      ),
    );
    const fulfilled = results.flatMap((result) =>
      result.status === 'fulfilled' ? [result.value] : [],
    );
    assert.equal(fulfilled.length, 3, 'concurrent DELETE requests all resolve idempotently');
    const winners = fulfilled.filter((result) => !result.alreadyArchived);
    assert.equal(winners.length, 1, 'exactly one request performs the archive');
    const persisted = await VehicleModel.findById(vehicle._id).lean();
    assert.equal(persisted?.status, 'ARCHIVED');
    assert.equal(persisted?.archiveReason, winners[0]?.vehicle.archiveReason);
    for (const result of fulfilled) {
      assert.equal(result.vehicle.archivedAt?.getTime(), persisted?.archivedAt?.getTime());
      assert.equal(result.vehicle.archiveReason, persisted?.archiveReason);
    }
  }
});

/**
 * Opens a real transaction that writes the vehicle document and keeps it uncommitted, so any
 * concurrent transactional write on that vehicle hits WriteConflict until `commit()`.
 */
async function holdVehicleWrite(
  vehicleId: Types.ObjectId,
  update: Record<string, unknown>,
): Promise<{ commit: () => Promise<void> }> {
  const session = await mongoose.startSession();
  session.startTransaction({ readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' } });
  await VehicleModel.updateOne({ _id: vehicleId }, { $set: update }, { session });
  return {
    commit: async () => {
      await session.commitTransaction();
      await session.endSession();
    },
  };
}

async function stillPendingAfter(work: Promise<unknown>, ms: number): Promise<boolean> {
  const timeout = Symbol('timeout');
  const winner = await Promise.race([
    work.then(
      () => 'settled',
      () => 'settled',
    ),
    new Promise((resolve) => setTimeout(() => resolve(timeout), ms)),
  ]);
  return winner === timeout;
}

test('17b. TKT-011 deterministic PATCH/DELETE interleavings re-validate ownership and state inside the transaction', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();

  // Sequential: PATCH ok → DELETE ok → PATCH rejected → repeated DELETE keeps original audit.
  const sequential = await createVehicle(ownerId, { name: 'Sequential Sedan' });
  const patched = await updateVehicle({
    vehicleId: sequential._id,
    actorUserId: ownerId,
    changes: { trim: 'Touring' },
  });
  assert.equal(patched.trim, 'Touring');
  const archivedAt = new Date();
  const archived = await archiveVehicle({
    vehicleId: sequential._id,
    actorUserId: ownerId,
    reason: 'Original reason',
    now: archivedAt,
  });
  assert.equal(archived.alreadyArchived, false);
  assert.equal(archived.vehicle.trim, 'Touring');
  await rejectsWithCode(
    () =>
      updateVehicle({ vehicleId: sequential._id, actorUserId: ownerId, changes: { trim: 'X' } }),
    'CONFLICT',
  );
  const repeated = await archiveVehicle({
    vehicleId: sequential._id,
    actorUserId: ownerId,
    reason: 'Later reason',
  });
  assert.equal(repeated.alreadyArchived, true);
  assert.equal(repeated.vehicle.archivedAt?.getTime(), archivedAt.getTime());
  assert.equal(repeated.vehicle.archiveReason, 'Original reason');
  assert.equal((await VehicleModel.findById(sequential._id).lean())?.trim, 'Touring');

  const archiveFields = (reason: string, at: Date) => ({
    status: 'ARCHIVED',
    archivedAt: at,
    archivedByUserId: ownerId,
    archiveReason: reason,
    updatedByUserId: ownerId,
  });

  // DELETE in flight ‖ PATCH: the pre-check passes (vehicle still ACTIVE), the PATCH blocks on
  // the write barrier and, once DELETE commits, the in-transaction re-check rejects it.
  const patchAfterDelete = await createVehicle(ownerId, { name: 'Barrier Coupe' });
  const firstArchiveAt = new Date();
  const inflightDelete = await holdVehicleWrite(
    patchAfterDelete._id,
    archiveFields('In-flight delete', firstArchiveAt),
  );
  const blockedPatch = updateVehicle({
    vehicleId: patchAfterDelete._id,
    actorUserId: ownerId,
    changes: { name: 'Should never apply' },
  });
  blockedPatch.catch(() => undefined);
  assert.equal(await stillPendingAfter(blockedPatch, 400), true, 'PATCH waits on the barrier');
  await inflightDelete.commit();
  await rejectsWithCode(() => blockedPatch, 'CONFLICT');
  const afterBlockedPatch = await VehicleModel.findById(patchAfterDelete._id).lean();
  assert.equal(afterBlockedPatch?.name, 'Barrier Coupe');
  assert.equal(afterBlockedPatch?.status, 'ARCHIVED');
  assert.equal(afterBlockedPatch?.archiveReason, 'In-flight delete');

  // DELETE in flight ‖ DELETE: the second DELETE returns the winner's original audit record.
  const doubleDelete = await createVehicle(ownerId, { name: 'Barrier Wagon' });
  const winnerAt = new Date();
  const inflightWinner = await holdVehicleWrite(
    doubleDelete._id,
    archiveFields('Winner reason', winnerAt),
  );
  const blockedDelete = archiveVehicle({
    vehicleId: doubleDelete._id,
    actorUserId: ownerId,
    reason: 'Loser reason',
  });
  blockedDelete.catch(() => undefined);
  assert.equal(await stillPendingAfter(blockedDelete, 400), true, 'DELETE waits on the barrier');
  await inflightWinner.commit();
  const loser = await blockedDelete;
  assert.equal(loser.alreadyArchived, true);
  assert.equal(loser.vehicle.archivedAt?.getTime(), winnerAt.getTime());
  assert.equal(loser.vehicle.archiveReason, 'Winner reason');
  assert.equal(
    (await VehicleModel.findById(doubleDelete._id).lean())?.archiveReason,
    'Winner reason',
  );

  // PATCH in flight ‖ DELETE: DELETE serializes after the PATCH and archives the patched state.
  const deleteAfterPatch = await createVehicle(ownerId, { name: 'Barrier Hatch' });
  const inflightPatch = await holdVehicleWrite(deleteAfterPatch._id, {
    name: 'Patched In Flight',
    updatedByUserId: ownerId,
  });
  const blockedArchive = archiveVehicle({
    vehicleId: deleteAfterPatch._id,
    actorUserId: ownerId,
    reason: 'After patch',
  });
  blockedArchive.catch(() => undefined);
  assert.equal(await stillPendingAfter(blockedArchive, 400), true, 'DELETE waits on the barrier');
  await inflightPatch.commit();
  const archivedAfterPatch = await blockedArchive;
  assert.equal(archivedAfterPatch.alreadyArchived, false);
  assert.equal(archivedAfterPatch.vehicle.name, 'Patched In Flight');
  assert.equal(archivedAfterPatch.vehicle.status, 'ARCHIVED');
  assert.equal(archivedAfterPatch.vehicle.archiveReason, 'After patch');
});

test('18. TKT-011 inviteMember authorizes before persisting expirations: unauthorized callers mutate nothing', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Invitation Guard Van' });
  const reader = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read']);
  const delegate = await addAcceptedMember(vehicle._id, ownerId, [
    'invitation:create',
    'vehicle:read',
  ]);
  const outsider = new Types.ObjectId();
  const elapsedInvitee = new Types.ObjectId();
  const elapsedInvitationId = new Types.ObjectId();
  const elapsedAt = new Date(Date.now() - 60_000);
  await InvitationModel.collection.insertOne({
    _id: elapsedInvitationId,
    vehicleId: vehicle._id,
    inviterUserId: ownerId,
    inviteeUserId: elapsedInvitee,
    targetRole: 'MEMBER',
    permissions: ['vehicle:read'],
    status: 'PENDING',
    expiresAt: elapsedAt,
    acceptedAt: null,
    acceptedByUserId: null,
    revokedAt: null,
    revokedByUserId: null,
    revokeReason: null,
    expiredAt: null,
    updatedByUserId: null,
    createdAt: new Date(elapsedAt.getTime() - 60_000),
    updatedAt: new Date(elapsedAt.getTime() - 60_000),
  });

  const snapshot = await vehiclePersistenceSnapshot(vehicle._id);
  assert.equal(await inviteMember(vehicle._id, outsider, elapsedInvitee, ['vehicle:read']), null);
  // TKT-012: a member who can see the vehicle but lacks invite authority gets FORBIDDEN.
  await rejectsWithCode(
    () => inviteMember(vehicle._id, reader.memberId, elapsedInvitee, ['vehicle:read']),
    'FORBIDDEN',
  );
  assert.equal(
    await inviteMember(new Types.ObjectId(), ownerId, elapsedInvitee, ['vehicle:read']),
    null,
  );
  assert.equal(await vehiclePersistenceSnapshot(vehicle._id), snapshot);
  assert.equal((await InvitationModel.findById(elapsedInvitationId).lean())?.status, 'PENDING');

  // Authorized issuers keep the durable expiration semantics of TKT-010.
  const issued = await inviteMember(vehicle._id, delegate.memberId, elapsedInvitee, [
    'vehicle:read',
  ]);
  assert.ok(issued);
  const expired = await InvitationModel.findById(elapsedInvitationId).lean();
  assert.equal(expired?.status, 'EXPIRED');
  assert.ok(expired?.expiredAt instanceof Date);
  assert.equal(issued.status, 'PENDING');
  assert.notEqual(String(issued._id), String(elapsedInvitationId));
});

test('19. TKT-011 listing cost: constant queries per page, read prefilter avoids rescans, bounded batch growth on discards', async () => {
  await resetVehicleCollections();
  const userId = new Types.ObjectId();
  const otherOwner = new Types.ObjectId();
  const base = Date.parse('2026-02-01T00:00:00.000Z');
  const setCreatedAt = (vehicleId: Types.ObjectId, offset: number) =>
    VehicleModel.collection.updateOne(
      { _id: vehicleId },
      { $set: { createdAt: new Date(base + offset) } },
    );

  // 30 shared vehicles without read access interleaved with 6 readable ones.
  const readable: string[] = [];
  for (let index = 0; index < 36; index += 1) {
    const vehicle = await createVehicle(otherOwner, { name: `Fleet ${index}` });
    const canRead = index % 6 === 5;
    const invitation = await inviteMember(vehicle._id, otherOwner, userId, [
      canRead ? 'vehicle:read' : 'device:read',
    ]);
    assert.ok(invitation);
    await acceptInvitation(invitation._id, userId);
    await setCreatedAt(vehicle._id, index * 1_000);
    if (canRead) readable.push(String(vehicle._id));
  }

  const counters = { aggregate: 0, membershipFind: 0, grantFind: 0 };
  const originalAggregate = MembershipModel.aggregate;
  const originalMembershipFind = MembershipModel.find;
  const originalGrantFind = AccessGrantModel.find;
  const countCalls = async <T>(work: () => Promise<T>): Promise<T> => {
    counters.aggregate = 0;
    counters.membershipFind = 0;
    counters.grantFind = 0;
    return work();
  };
  MembershipModel.aggregate = function (this: unknown, ...args: unknown[]) {
    counters.aggregate += 1;
    return (originalAggregate as (...input: unknown[]) => unknown).apply(this, args);
  } as typeof MembershipModel.aggregate;
  MembershipModel.find = function (this: unknown, ...args: unknown[]) {
    counters.membershipFind += 1;
    return (originalMembershipFind as (...input: unknown[]) => unknown).apply(this, args);
  } as typeof MembershipModel.find;
  AccessGrantModel.find = function (this: unknown, ...args: unknown[]) {
    counters.grantFind += 1;
    return (originalGrantFind as (...input: unknown[]) => unknown).apply(this, args);
  } as typeof AccessGrantModel.find;

  try {
    const collected: string[] = [];
    let cursor: string | undefined;
    for (;;) {
      const page = await countCalls(() => listAccessibleVehicles(userId, { limit: 2, cursor }));
      assert.equal(counters.aggregate, 1, 'non-readable memberships are filtered in one scan');
      assert.ok(counters.membershipFind <= 1, 'owner memberships resolved in one batched query');
      assert.ok(counters.grantFind <= 2, 'grants resolved with at most one query per permission');
      collected.push(...page.items.map((item) => String(item.vehicle._id)));
      if (!page.nextCursor) break;
      cursor = page.nextCursor;
    }
    assert.deepEqual(collected, readable);

    // Ownership corruption is only detectable after the scan: discards grow the batch (bounded).
    const owner = new Types.ObjectId();
    const corrupted: Types.ObjectId[] = [];
    for (let index = 0; index < 12; index += 1) {
      const vehicle = await createVehicle(owner, { name: `Corrupted ${index}` });
      await setCreatedAt(vehicle._id, -100_000 + index);
      await MembershipModel.collection.insertOne({
        vehicleId: vehicle._id,
        userId: new Types.ObjectId(),
        role: 'OWNER',
        permissions: [],
        status: 'SUSPENDED',
        sourceInvitationId: null,
        suspendedAt: new Date(),
        suspendedByUserId: owner,
        revokedAt: null,
        revokedByUserId: null,
        revokeReason: null,
        updatedByUserId: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      corrupted.push(vehicle._id);
    }
    const healthy: string[] = [];
    for (let index = 0; index < 3; index += 1) {
      const vehicle = await createVehicle(owner, { name: `Healthy ${index}` });
      await setCreatedAt(vehicle._id, -50_000 + index);
      healthy.push(String(vehicle._id));
    }
    const page = await countCalls(() => listAccessibleVehicles(owner, { limit: 2 }));
    assert.deepEqual(
      page.items.map((item) => String(item.vehicle._id)),
      healthy.slice(0, 2),
    );
    assert.ok(page.nextCursor);
    assert.equal(counters.aggregate, 3, 'batches of 3, 6 and 12 cover 12 discards');
    const rest = await listAccessibleVehicles(owner, { limit: 2, cursor: page.nextCursor });
    assert.deepEqual(
      rest.items.map((item) => String(item.vehicle._id)),
      healthy.slice(2),
    );
    assert.equal(rest.nextCursor, null);
    assert.equal(corrupted.length, 12);
  } finally {
    MembershipModel.aggregate = originalAggregate;
    MembershipModel.find = originalMembershipFind;
    AccessGrantModel.find = originalGrantFind;
  }
});

test('11. End-to-end Gateway -> Vehicle -> Identity/Device over real HTTPS, HMAC v2, JWT, email verification, and invitation lifecycle', async () => {
  assert.ok(mongoCluster && rootClient);
  const openssl = await resolveOpenSslBinary();
  const tlsDir = await mkdtemp(path.join(tmpdir(), 'pichu-tkt010-tls-'));
  const caKey = path.join(tlsDir, 'ca.key');
  const caCert = path.join(tlsDir, 'ca.crt');
  const certKey = path.join(tlsDir, 'server.key');
  const csr = path.join(tlsDir, 'server.csr');
  const cert = path.join(tlsDir, 'server.crt');
  const ext = path.join(tlsDir, 'server.ext');

  const children: ChildProcess[] = [];

  async function freePort(): Promise<number> {
    const server = createServer();
    await new Promise<void>((resolve) =>
      server.listen({ host: '127.0.0.1', port: 0 }, () => resolve()),
    );
    const port = (server.address() as { port: number }).port;
    await new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    );
    return port;
  }

  function spawnTsxService(cwd: string, env: NodeJS.ProcessEnv): ChildProcess {
    return spawn(process.execPath, ['--import', 'tsx', 'src/server.ts'], {
      cwd,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
  }

  async function stopChild(child?: ChildProcess): Promise<void> {
    if (!child || child.exitCode !== null) return;
    child.kill('SIGTERM');
    await Promise.race([
      new Promise<void>((resolve) => child.once('exit', () => resolve())),
      new Promise<void>((resolve) => setTimeout(resolve, 3_000)),
    ]);
    if (child.exitCode === null) child.kill('SIGKILL');
  }

  function signUserJwt(sub: string, sid: string, secret: string): string {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({
        sub,
        sid,
        iss: 'pichu-test-issuer',
        aud: 'pichu-test-aud',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 600,
      }),
    ).toString('base64url');
    const sig = createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
    return `${header}.${payload}.${sig}`;
  }

  try {
    await execFileAsync(openssl, [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      caKey,
      '-out',
      caCert,
      '-subj',
      '/CN=PICHU TKT-010 Test CA',
      '-days',
      '1',
    ]);
    await execFileAsync(openssl, [
      'req',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      certKey,
      '-out',
      csr,
      '-subj',
      '/CN=localhost',
    ]);
    await writeFile(ext, 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
    await execFileAsync(openssl, [
      'x509',
      '-req',
      '-in',
      csr,
      '-CA',
      caCert,
      '-CAkey',
      caKey,
      '-CAcreateserial',
      '-out',
      cert,
      '-days',
      '1',
      '-extfile',
      ext,
    ]);

    const ownerId = String(new Types.ObjectId());
    const ownerSessionId = String(new Types.ObjectId());
    const inviteeId = String(new Types.ObjectId());
    const inviteeSessionId = String(new Types.ObjectId());
    const unverifiedId = String(new Types.ObjectId());
    const unverifiedSessionId = String(new Types.ObjectId());
    const delegateId = String(new Types.ObjectId());
    const delegateSessionId = String(new Types.ObjectId());
    const jwtSecret = 'k'.repeat(32);

    const identityDb = rootClient.db('identity_db');
    await identityDb.collection('users').deleteMany({});
    await identityDb.collection('sessions').deleteMany({});

    await identityDb.collection('users').insertMany([
      {
        _id: new Types.ObjectId(ownerId),
        name: 'Owner Verified',
        username: 'owner_verified',
        normalizedUsername: 'owner_verified',
        email: 'owner@example.com',
        normalizedEmail: 'owner@example.com',
        passwordHash: 'unused',
        emailVerifiedAt: new Date(),
        passwordRecoverySequence: 0,
        passwordRecoveryGeneration: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        _id: new Types.ObjectId(inviteeId),
        name: 'Invitee Verified',
        username: 'invitee_verified',
        normalizedUsername: 'invitee_verified',
        email: 'invitee@example.com',
        normalizedEmail: 'invitee@example.com',
        passwordHash: 'unused',
        emailVerifiedAt: new Date(),
        passwordRecoverySequence: 0,
        passwordRecoveryGeneration: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        _id: new Types.ObjectId(unverifiedId),
        name: 'Unverified Driver',
        username: 'unverified_driver',
        normalizedUsername: 'unverified_driver',
        email: 'unverified@example.com',
        normalizedEmail: 'unverified@example.com',
        passwordHash: 'unused',
        emailVerifiedAt: null,
        passwordRecoverySequence: 0,
        passwordRecoveryGeneration: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        _id: new Types.ObjectId(delegateId),
        name: 'Delegate Verified',
        username: 'delegate_verified',
        normalizedUsername: 'delegate_verified',
        email: 'delegate@example.com',
        normalizedEmail: 'delegate@example.com',
        passwordHash: 'unused',
        emailVerifiedAt: new Date(),
        passwordRecoverySequence: 0,
        passwordRecoveryGeneration: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ]);

    await identityDb.collection('sessions').insertMany([
      {
        _id: new Types.ObjectId(ownerSessionId),
        userId: new Types.ObjectId(ownerId),
        familyId: randomUUID(),
        createdAt: new Date(),
        lastActivityAt: new Date(),
        expiresAt: new Date(Date.now() + 600_000),
        revokedAt: null,
        revokeReason: null,
        userAgent: 'tkt010-e2e',
      },
      {
        _id: new Types.ObjectId(inviteeSessionId),
        userId: new Types.ObjectId(inviteeId),
        familyId: randomUUID(),
        createdAt: new Date(),
        lastActivityAt: new Date(),
        expiresAt: new Date(Date.now() + 600_000),
        revokedAt: null,
        revokeReason: null,
        userAgent: 'tkt010-e2e',
      },
      {
        _id: new Types.ObjectId(unverifiedSessionId),
        userId: new Types.ObjectId(unverifiedId),
        familyId: randomUUID(),
        createdAt: new Date(),
        lastActivityAt: new Date(),
        expiresAt: new Date(Date.now() + 600_000),
        revokedAt: null,
        revokeReason: null,
        userAgent: 'tkt010-e2e',
      },
      {
        _id: new Types.ObjectId(delegateSessionId),
        userId: new Types.ObjectId(delegateId),
        familyId: randomUUID(),
        createdAt: new Date(),
        lastActivityAt: new Date(),
        expiresAt: new Date(Date.now() + 600_000),
        revokedAt: null,
        revokeReason: null,
        userAgent: 'tkt012-e2e',
      },
    ]);

    const makeKey = (
      sender: KeyEntry['sender'],
      audience: KeyEntry['audience'],
      fill: number,
    ): KeyEntry => ({
      environment: 'test',
      sender,
      audience,
      keyId: `${sender}-${audience}`,
      secret: Buffer.alloc(32, fill),
      state: 'active',
      notBefore: 1,
      notAfter: 8_000_000_000_000_000,
    });

    const keys = [
      makeKey('api-gateway', 'vehicle-service', 41),
      makeKey('api-gateway', 'device-service', 42),
      makeKey('vehicle-service', 'identity-service', 43),
      makeKey('vehicle-service', 'device-service', 44),
      makeKey('device-service', 'identity-service', 45),
    ];

    const fullKeyringJson = JSON.stringify(
      keys.map(({ secret, ...rest }) => ({
        ...rest,
        secretBase64Url: Buffer.from(secret).toString('base64url'),
      })),
    );
    const gatewayKeyringJson = JSON.stringify(
      keys
        .filter((entry) => entry.sender === 'api-gateway')
        .map(({ secret, ...rest }) => ({
          ...rest,
          secretBase64Url: Buffer.from(secret).toString('base64url'),
        })),
    );

    const ports = {
      identity: await freePort(),
      vehicle: await freePort(),
      device: await freePort(),
      gateway: await freePort(),
    };

    const sharedEnv = {
      NODE_ENV: 'test',
      HOST: '127.0.0.1',
      JWT_SECRET: jwtSecret,
      JWT_ISSUER: 'pichu-test-issuer',
      JWT_AUDIENCE: 'pichu-test-aud',
      INTERNAL_AUTH_ENVIRONMENT: 'test',
      INTERNAL_AUTH_KEYRING_JSON: fullKeyringJson,
      INTERNAL_AUTH_BODY_LIMIT: '1048576',
      TLS_CERT_PATH: cert,
      TLS_KEY_PATH: certKey,
      TLS_CA_PATH: caCert,
    };

    const identityChild = spawnTsxService(path.join(repoRoot, 'services/identity-service'), {
      ...process.env,
      ...sharedEnv,
      PORT: String(ports.identity),
      DOCUMENTATION_URL: 'https://localhost/docs',
      RESEND_API_KEY: 'test',
      RESEND_FROM_EMAIL: 'test@example.com',
      RESEND_FROM_NAME: 'PICHU',
      EMAIL_VERIFICATION_URL: 'https://localhost/verify',
      EMAIL_VERIFICATION_TOKEN_TTL_SECONDS: '3600',
      PASSWORD_RESET_URL: 'https://localhost/reset',
      PASSWORD_RESET_TOKEN_TTL_SECONDS: '3600',
      ACCESS_TOKEN_TTL_SECONDS: '300',
      REFRESH_TOKEN_TTL_SECONDS: '3600',
      AUTH_COOKIE_ORIGIN: 'https://localhost',
      DATABASE_URL: mongoCluster.uri('identity'),
    });
    children.push(identityChild);

    const vehicleChild = spawnTsxService(path.join(repoRoot, 'services/vehicle-service'), {
      ...process.env,
      ...sharedEnv,
      PORT: String(ports.vehicle),
      DATABASE_URL: mongoCluster.uri('vehicle'),
      IDENTITY_SERVICE_URL: `https://localhost:${ports.identity}`,
      DEVICE_SERVICE_URL: `https://localhost:${ports.device}`,
    });
    children.push(vehicleChild);

    const deviceChild = spawnTsxService(path.join(repoRoot, 'services/device-service'), {
      ...process.env,
      ...sharedEnv,
      PORT: String(ports.device),
      DATABASE_URL: mongoCluster.uri('device'),
      IDENTITY_SERVICE_URL: `https://localhost:${ports.identity}`,
    });
    children.push(deviceChild);

    for (const [url, proc] of [
      [`https://localhost:${ports.identity}/health/ready`, identityChild],
      [`https://localhost:${ports.vehicle}/health/ready`, vehicleChild],
      [`https://localhost:${ports.device}/health/ready`, deviceChild],
    ] as const) {
      let ready = false;
      for (let i = 0; i < 100; i++) {
        if (proc.exitCode !== null) throw new Error(`Service exited early for ${url}`);
        try {
          const res = await httpsJsonRequest({
            url,
            timeoutMs: 500,
            tls: { caPath: caCert, servername: 'localhost' },
          });
          if (res.status === 200) {
            ready = true;
            break;
          }
        } catch {
          // retry
        }
        await new Promise((r) => setTimeout(r, 200));
      }
      assert.equal(ready, true, `Timed out waiting for readiness of ${url}`);
    }

    const gatewayChild = spawnTsxService(path.join(repoRoot, 'apps/api-gateway'), {
      ...process.env,
      NODE_ENV: 'test',
      HOST: '127.0.0.1',
      PORT: String(ports.gateway),
      JWT_SECRET: jwtSecret,
      JWT_ISSUER: 'pichu-test-issuer',
      JWT_AUDIENCE: 'pichu-test-aud',
      INTERNAL_AUTH_ENVIRONMENT: 'test',
      INTERNAL_AUTH_KEYRING_JSON: gatewayKeyringJson,
      IDENTITY_SERVICE_URL: `https://localhost:${ports.identity}`,
      VEHICLE_SERVICE_URL: `https://localhost:${ports.vehicle}`,
      DEVICE_SERVICE_URL: `https://localhost:${ports.device}`,
      TLS_CA_PATH: caCert,
      PROXY_TIMEOUT_MS: '5000',
      RATE_LIMIT_MAX: '500',
      SENSITIVE_RATE_LIMIT_MAX: '200',
      INVITATION_RATE_LIMIT_MAX: '100',
      INVITATION_IP_RATE_LIMIT_MAX: '100',
    });
    children.push(gatewayChild);

    let gatewayReady = false;
    for (let i = 0; i < 100; i++) {
      try {
        const res = await fetch(`http://127.0.0.1:${ports.gateway}/health/ready`);
        if (res.status === 200) {
          gatewayReady = true;
          break;
        }
      } catch {
        // retry
      }
      await new Promise((r) => setTimeout(r, 200));
    }
    assert.equal(
      gatewayReady,
      true,
      'Gateway readiness should be 200 once all upstreams are ready',
    );

    const gatewayUrl = `http://127.0.0.1:${ports.gateway}`;
    const ownerJwt = signUserJwt(ownerId, ownerSessionId, jwtSecret);
    const inviteeJwt = signUserJwt(inviteeId, inviteeSessionId, jwtSecret);
    const unverifiedJwt = signUserJwt(unverifiedId, unverifiedSessionId, jwtSecret);
    const delegateJwt = signUserJwt(delegateId, delegateSessionId, jwtSecret);

    // Unverified user blocked with 403 EMAIL_NOT_VERIFIED
    const unverifiedCreate = await fetch(`${gatewayUrl}/api/vehicles`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${unverifiedJwt}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ name: 'Blocked Car' }),
    });
    assert.equal(unverifiedCreate.status, 403);

    // Owner creates multi-brand vehicle through Gateway
    const createRes = await fetch(`${gatewayUrl}/api/vehicles`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${ownerJwt}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        name: 'Gateway Hyundai Ioniq 5',
        make: 'Hyundai',
        model: 'Ioniq 5',
        year: 2024,
        engine: 'Dual Motor AWD',
      }),
    });
    assert.equal(createRes.status, 201);
    const { vehicleId } = (await createRes.json()) as { vehicleId: string };

    // Real invitation creation through Gateway -> Vehicle -> Identity (exercises inviterUserId fix!)
    const inviteRes = await fetch(`${gatewayUrl}/api/vehicles/${vehicleId}/invitations`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${ownerJwt}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        inviteeUserId: inviteeId,
        permissions: ['vehicle:read', 'device:link'],
      }),
    });
    assert.equal(inviteRes.status, 201);
    const { invitationId } = (await inviteRes.json()) as { invitationId: string };

    // Invitee accepts invitation through Gateway -> atomic transaction creates MEMBER
    const acceptRes = await fetch(`${gatewayUrl}/api/invitations/${invitationId}/accept`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${inviteeJwt}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({}),
    });
    assert.equal(acceptRes.status, 200);

    // Invitee can now read the vehicle and link multiple ESP32 devices to the same vehicle
    const memberRead = await fetch(`${gatewayUrl}/api/vehicles/${vehicleId}`, {
      headers: { authorization: `Bearer ${inviteeJwt}` },
    });
    assert.equal(memberRead.status, 200);

    // Alias retirado en TKT-015: POST /api/vehicles/:vehicleId/devices/link -> 404
    const retiredLinkAlias = await fetch(`${gatewayUrl}/api/vehicles/${vehicleId}/devices/link`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${inviteeJwt}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        identifier: `esp32-retired-${randomUUID().slice(0, 8)}`,
        publicKey: generateKeyPairSync('ed25519')
          .publicKey.export({ type: 'spki', format: 'pem' })
          .toString(),
      }),
    });
    assert.equal(retiredLinkAlias.status, 404);

    for (const espSuffix of ['cabin-esp32', 'trunk-esp32']) {
      const registerRes = await fetch(`${gatewayUrl}/api/vehicles/${vehicleId}/devices`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${inviteeJwt}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          identifier: `esp32-${espSuffix}-${randomUUID().slice(0, 8)}`,
          publicKey: generateKeyPairSync('ed25519')
            .publicKey.export({ type: 'spki', format: 'pem' })
            .toString(),
        }),
      });
      assert.equal(registerRes.status, 201);
    }

    // TKT-013: the canonical OWNER registers through OWNER_ROLE; without authorization the
    // response is a uniform 404 and Device is never reached.
    const registerAs = (jwt: string, targetVehicleId: string) =>
      fetch(`${gatewayUrl}/api/vehicles/${targetVehicleId}/devices`, {
        method: 'POST',
        headers: { authorization: `Bearer ${jwt}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          identifier: `esp32-tkt013-${randomUUID().slice(0, 8)}`,
          publicKey: generateKeyPairSync('ed25519')
            .publicKey.export({ type: 'spki', format: 'pem' })
            .toString(),
        }),
      });
    assert.equal((await registerAs(ownerJwt, vehicleId)).status, 201);
    const deniedRegister = await registerAs(inviteeJwt, String(new Types.ObjectId()));
    assert.equal(deniedRegister.status, 404);

    // HMAC v2 replay rejection directly against Vehicle HTTPS endpoint
    const gwVehKey = keys.find(
      (k) => k.sender === 'api-gateway' && k.audience === 'vehicle-service',
    )!;
    const now = Date.now();
    const replayPayload = Buffer.from(JSON.stringify({ userId: ownerId, name: 'Replay Probe' }));
    const unsigned = {
      'x-internal-auth-version': '2' as const,
      'x-service-name': 'api-gateway' as const,
      'x-service-audience': 'vehicle-service' as const,
      'x-service-key-id': gwVehKey.keyId,
      'x-contract-version': 'v1' as const,
      'x-timestamp': String(now),
      'x-nonce': generateNonce(),
      'x-request-id': randomUUID(),
      'x-internal-deadline': String(now + 5_000),
      authorization: `Bearer ${ownerJwt}`,
      'content-type': 'application/json' as const,
    };
    const signedHeaders = {
      ...unsigned,
      'x-signature': signRequest(
        {
          environment: 'test',
          sender: 'api-gateway',
          audience: 'vehicle-service',
          keyring: [gwVehKey],
          now,
        },
        unsigned,
        { method: 'POST', target: '/vehicles', body: replayPayload },
      ),
    };
    const first = await httpsJsonRequest({
      url: `https://localhost:${ports.vehicle}/vehicles`,
      method: 'POST',
      headers: signedHeaders,
      body: replayPayload,
      timeoutMs: 5_000,
      tls: { caPath: caCert, servername: 'localhost' },
    });
    const replay = await httpsJsonRequest({
      url: `https://localhost:${ports.vehicle}/vehicles`,
      method: 'POST',
      headers: signedHeaders,
      body: replayPayload,
      timeoutMs: 5_000,
      tls: { caPath: caCert, servername: 'localhost' },
    });
    assert.equal(first.status, 201);
    assert.equal(replay.status, 401);
    const probeVehicleId = (first.body as { vehicleId: string }).vehicleId;

    // TKT-011: the five public vehicle endpoints over Gateway -> HTTPS + HMAC v2 -> Vehicle.
    const gw = async (
      method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
      pathAndQuery: string,
      jwt: string,
      body?: unknown,
    ) => {
      const response = await fetch(`${gatewayUrl}${pathAndQuery}`, {
        method,
        headers: {
          authorization: `Bearer ${jwt}`,
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      return { status: response.status, body: (await response.json()) as Record<string, unknown> };
    };

    const ownerList = await gw('GET', '/api/vehicles?limit=1', ownerJwt);
    assert.equal(ownerList.status, 200);
    const ownerListVehicles = ownerList.body.vehicles as Array<Record<string, unknown>>;
    assert.equal(ownerListVehicles.length, 1);
    assert.equal(ownerListVehicles[0]?.role, 'OWNER');
    const ownerCursor = (ownerList.body.page as { nextCursor: string | null }).nextCursor;
    assert.ok(ownerCursor);
    const ownerList2 = await gw(
      'GET',
      `/api/vehicles?limit=1&cursor=${encodeURIComponent(ownerCursor)}`,
      ownerJwt,
    );
    assert.equal(ownerList2.status, 200);
    assert.equal((ownerList2.body.page as { nextCursor: string | null }).nextCursor, null);
    assert.deepEqual(
      [...ownerListVehicles, ...(ownerList2.body.vehicles as Array<Record<string, unknown>>)]
        .map((vehicle) => vehicle.id)
        .sort(),
      [vehicleId, probeVehicleId].sort(),
    );
    const stolenCursor = await gw(
      'GET',
      `/api/vehicles?limit=1&cursor=${encodeURIComponent(ownerCursor)}`,
      inviteeJwt,
    );
    assert.equal(stolenCursor.status, 400);

    const memberList = await gw('GET', '/api/vehicles?role=MEMBER', inviteeJwt);
    assert.equal(memberList.status, 200);
    assert.deepEqual(
      (memberList.body.vehicles as Array<Record<string, unknown>>).map((v) => [v.id, v.role]),
      [[vehicleId, 'MEMBER']],
    );
    const memberAsOwner = await gw('GET', '/api/vehicles?role=OWNER', inviteeJwt);
    assert.deepEqual(memberAsOwner.body.vehicles, []);

    const ownerPatch = await gw('PATCH', `/api/vehicles/${vehicleId}`, ownerJwt, {
      trim: '  Limited  ',
      engine: null,
    });
    assert.equal(ownerPatch.status, 200);
    const patchedData = ownerPatch.body.data as Record<string, unknown>;
    assert.equal(patchedData.trim, 'Limited');
    assert.equal(patchedData.engine, null);
    assert.equal(patchedData.make, 'Hyundai');
    assert.equal(patchedData.role, 'OWNER');
    for (const invalid of [{}, { userId: inviteeId }, { name: null }, { status: 'ARCHIVED' }]) {
      assert.equal(
        (await gw('PATCH', `/api/vehicles/${vehicleId}`, ownerJwt, invalid)).status,
        400,
      );
    }

    const memberDetail = await gw('GET', `/api/vehicles/${vehicleId}`, inviteeJwt);
    assert.equal(memberDetail.status, 200);
    assert.equal(memberDetail.body.role, 'MEMBER');
    assert.equal(memberDetail.body.trim, 'Limited');
    const memberPatch = await gw('PATCH', `/api/vehicles/${vehicleId}`, inviteeJwt, {
      name: 'Hijacked',
    });
    assert.equal(memberPatch.status, 403);
    assert.equal(memberPatch.body.error, 'FORBIDDEN');
    const memberDelete = await gw('DELETE', `/api/vehicles/${vehicleId}`, inviteeJwt);
    assert.equal(memberDelete.status, 403);

    const outsiderDetail = await gw('GET', `/api/vehicles/${probeVehicleId}`, inviteeJwt);
    const outsiderPatch = await gw('PATCH', `/api/vehicles/${probeVehicleId}`, inviteeJwt, {
      name: 'Hijacked',
    });
    const outsiderDelete = await gw('DELETE', `/api/vehicles/${probeVehicleId}`, inviteeJwt);
    const missing = await gw('GET', `/api/vehicles/${String(new Types.ObjectId())}`, ownerJwt);
    for (const notFound of [outsiderDetail, outsiderPatch, outsiderDelete, missing]) {
      assert.equal(notFound.status, 404);
      assert.equal(notFound.body.error, 'NOT_FOUND');
      assert.equal(notFound.body.message, 'Vehicle not found');
    }

    // Manipulated internal requests directly against Vehicle HTTPS.
    const signedDirect = (
      method: 'PATCH' | 'DELETE',
      target: string,
      bodyObject: Record<string, unknown>,
      jwt: string,
      signedBodyObject: Record<string, unknown> = bodyObject,
    ) => {
      const at = Date.now();
      const headers = {
        'x-internal-auth-version': '2' as const,
        'x-service-name': 'api-gateway' as const,
        'x-service-audience': 'vehicle-service' as const,
        'x-service-key-id': gwVehKey.keyId,
        'x-contract-version': 'v1' as const,
        'x-timestamp': String(at),
        'x-nonce': generateNonce(),
        'x-request-id': randomUUID(),
        'x-internal-deadline': String(at + 5_000),
        authorization: `Bearer ${jwt}`,
        'content-type': 'application/json' as const,
      };
      const body = Buffer.from(JSON.stringify(bodyObject));
      const signature = signRequest(
        {
          environment: 'test',
          sender: 'api-gateway',
          audience: 'vehicle-service',
          keyring: [gwVehKey],
          now: at,
        },
        headers,
        { method, target, body: Buffer.from(JSON.stringify(signedBodyObject)) },
      );
      return () =>
        httpsJsonRequest({
          url: `https://localhost:${ports.vehicle}${target}`,
          method,
          headers: {
            ...headers,
            'x-signature': signature,
            'content-length': String(body.length),
          },
          body,
          timeoutMs: 5_000,
          tls: { caPath: caCert, servername: 'localhost' },
        });
    };
    const tamperedBody = await signedDirect(
      'PATCH',
      `/vehicles/${vehicleId}`,
      { userId: ownerId, name: 'Tampered' },
      ownerJwt,
      { userId: ownerId, name: 'Signed' },
    )();
    assert.equal(tamperedBody.status, 401);
    const identityMismatch = await signedDirect(
      'PATCH',
      `/vehicles/${vehicleId}`,
      { userId: inviteeId, name: 'Mismatch' },
      ownerJwt,
    )();
    assert.equal(identityMismatch.status, 403);
    const impersonatedOwner = await signedDirect(
      'DELETE',
      `/vehicles/${vehicleId}`,
      { userId: ownerId },
      inviteeJwt,
    )();
    assert.equal(impersonatedOwner.status, 403);
    const directPatch = signedDirect(
      'PATCH',
      `/vehicles/${vehicleId}`,
      { userId: ownerId, generation: 'NE1' },
      ownerJwt,
    );
    assert.equal((await directPatch()).status, 200);
    assert.equal((await directPatch()).status, 401, 'replayed PATCH is rejected');
    const afterManipulation = await gw('GET', `/api/vehicles/${vehicleId}`, ownerJwt);
    assert.equal(afterManipulation.body.name, 'Gateway Hyundai Ioniq 5');
    assert.equal(afterManipulation.body.generation, 'NE1');
    assert.equal(afterManipulation.body.status, undefined);

    // Multibyte bodies: Content-Length and the HMAC v2 signature cover the exact UTF-8 bytes.
    const multibyte = 'Automática — Ñandú 🚗 東京';
    const multibytePatch = await gw('PATCH', `/api/vehicles/${vehicleId}`, ownerJwt, {
      transmission: multibyte,
    });
    assert.equal(multibytePatch.status, 200);
    assert.equal((multibytePatch.body.data as Record<string, unknown>).transmission, multibyte);
    assert.equal((await VehicleModel.findById(vehicleId).lean())?.transmission, multibyte);

    // Same trimmed-length outcome at the Gateway and directly at Vehicle.
    const padded = (length: number) => `   ${'b'.repeat(length)}   `;
    const gatewayPaddedOk = await gw('PATCH', `/api/vehicles/${vehicleId}`, ownerJwt, {
      bodyStyle: padded(60),
    });
    const directPaddedOk = await signedDirect(
      'PATCH',
      `/vehicles/${vehicleId}`,
      { userId: ownerId, bodyStyle: padded(60) },
      ownerJwt,
    )();
    assert.equal(gatewayPaddedOk.status, 200);
    assert.equal(directPaddedOk.status, 200);
    assert.equal((await VehicleModel.findById(vehicleId).lean())?.bodyStyle, 'b'.repeat(60));
    const gatewayPaddedTooLong = await gw('PATCH', `/api/vehicles/${vehicleId}`, ownerJwt, {
      bodyStyle: padded(61),
    });
    const directPaddedTooLong = await signedDirect(
      'PATCH',
      `/vehicles/${vehicleId}`,
      { userId: ownerId, bodyStyle: padded(61) },
      ownerJwt,
    )();
    assert.equal(gatewayPaddedTooLong.status, 400);
    assert.equal(directPaddedTooLong.status, 400);
    assert.equal((await VehicleModel.findById(vehicleId).lean())?.bodyStyle, 'b'.repeat(60));

    // TKT-012: the eleven membership/invitation endpoints over Gateway -> HTTPS + HMAC v2.
    const auditFields = [
      'issuerMembershipId',
      'revokedByUserId',
      'suspendedByUserId',
      'userIdHash',
    ];
    const assertNoAuditFields = (body: unknown) => {
      const text = JSON.stringify(body);
      for (const field of auditFields) assert.equal(text.includes(`"${field}"`), false, field);
    };

    const delegateInvite = await gw('POST', `/api/vehicles/${vehicleId}/invitations`, ownerJwt, {
      inviteeUserId: delegateId,
      permissions: ['vehicle:read', 'invitation:create'],
    });
    assert.equal(delegateInvite.status, 201);
    assertNoAuditFields(delegateInvite.body);
    const delegateInvitation = delegateInvite.body.data as Record<string, unknown>;
    assert.equal(delegateInvitation.inviterUserId, ownerId);
    assert.equal(delegateInvitation.status, 'PENDING');
    assert.equal(delegateInvite.body.invitationId, delegateInvitation.invitationId);

    const received = await gw('GET', '/api/invitations', delegateJwt);
    assert.equal(received.status, 200);
    assert.deepEqual(
      (received.body.invitations as Array<Record<string, unknown>>).map((item) => [
        item.invitationId,
        item.vehicleName,
        item.status,
      ]),
      [[delegateInvitation.invitationId, 'Gateway Hyundai Ioniq 5', 'PENDING']],
    );
    assert.equal(JSON.stringify(received.body).includes('inviterUserId'), false);
    assert.deepEqual((await gw('GET', '/api/invitations', unverifiedJwt)).status, 403);

    const delegateAccept = await gw(
      'POST',
      `/api/invitations/${String(delegateInvitation.invitationId)}/accept`,
      delegateJwt,
      {},
    );
    assert.equal(delegateAccept.status, 200);
    const delegateMembership = delegateAccept.body.data as Record<string, unknown>;
    assert.equal(delegateMembership.status, 'ACTIVE');
    assert.equal(delegateMembership.role, 'MEMBER');
    const delegateMembershipId = String(delegateMembership.membershipId);
    const acceptAgain = await gw(
      'POST',
      `/api/invitations/${String(delegateInvitation.invitationId)}/accept`,
      delegateJwt,
      {},
    );
    assert.equal(acceptAgain.status, 409);
    const foreignAccept = await gw(
      'POST',
      `/api/invitations/${String(delegateInvitation.invitationId)}/accept`,
      inviteeJwt,
      {},
    );
    assert.equal(foreignAccept.status, 404);

    // Delegate issues a read-only invitation; duplicates and physical permissions are rejected.
    const delegatedInvite = await gw(
      'POST',
      `/api/vehicles/${vehicleId}/invitations`,
      delegateJwt,
      {
        inviteeUserId: unverifiedId,
        permissions: ['vehicle:read'],
      },
    );
    assert.equal(delegatedInvite.status, 201);
    const delegatedInvitationId = String(delegatedInvite.body.invitationId);
    const duplicateInvite = await gw(
      'POST',
      `/api/vehicles/${vehicleId}/invitations`,
      delegateJwt,
      {
        inviteeUserId: unverifiedId,
        permissions: ['vehicle:read'],
      },
    );
    assert.equal(duplicateInvite.status, 409);
    const physicalDelegation = await gw(
      'POST',
      `/api/vehicles/${vehicleId}/invitations`,
      delegateJwt,
      { inviteeUserId: String(new Types.ObjectId()), permissions: ['device:link'] },
    );
    assert.equal(physicalDelegation.status, 403);
    const readerInvite = await gw('POST', `/api/vehicles/${vehicleId}/invitations`, inviteeJwt, {
      inviteeUserId: String(new Types.ObjectId()),
      permissions: ['vehicle:read'],
    });
    assert.equal(readerInvite.status, 403);
    const unknownInvitee = await gw('POST', `/api/vehicles/${vehicleId}/invitations`, ownerJwt, {
      inviteeUserId: String(new Types.ObjectId()),
      permissions: ['vehicle:read'],
    });
    assert.equal(unknownInvitee.status, 404);

    // Unverified invitees cannot accept until their email is verified.
    const unverifiedAccept = await gw(
      'POST',
      `/api/invitations/${delegatedInvitationId}/accept`,
      unverifiedJwt,
      {},
    );
    assert.equal(unverifiedAccept.status, 403);
    assert.equal(unverifiedAccept.body.error, 'EMAIL_NOT_VERIFIED');

    // Issued invitations: the owner pages through all, the delegate sees only their own.
    const ownerInvitationIds: string[] = [];
    let invitationCursor: string | null = null;
    do {
      const page = await gw(
        'GET',
        `/api/vehicles/${vehicleId}/invitations?limit=1${
          invitationCursor ? `&cursor=${encodeURIComponent(invitationCursor)}` : ''
        }`,
        ownerJwt,
      );
      assert.equal(page.status, 200);
      assertNoAuditFields(page.body);
      for (const item of page.body.invitations as Array<Record<string, unknown>>)
        ownerInvitationIds.push(String(item.invitationId));
      invitationCursor = (page.body.page as { nextCursor: string | null }).nextCursor;
      if (invitationCursor && ownerInvitationIds.length === 1) {
        const stolen = await gw(
          'GET',
          `/api/vehicles/${vehicleId}/invitations?limit=1&cursor=${encodeURIComponent(invitationCursor)}`,
          delegateJwt,
        );
        assert.equal(stolen.status, 400);
        const mismatched = await gw(
          'GET',
          `/api/vehicles/${vehicleId}/invitations?limit=1&status=PENDING&cursor=${encodeURIComponent(invitationCursor)}`,
          ownerJwt,
        );
        assert.equal(mismatched.status, 400);
      }
    } while (invitationCursor);
    assert.equal(ownerInvitationIds.length, 3);
    assert.equal(new Set(ownerInvitationIds).size, 3);
    assert.ok(ownerInvitationIds.includes(delegatedInvitationId));
    const delegateIssued = await gw('GET', `/api/vehicles/${vehicleId}/invitations`, delegateJwt);
    assert.equal(delegateIssued.status, 200);
    assert.deepEqual(
      (delegateIssued.body.invitations as Array<Record<string, unknown>>).map(
        (item) => item.invitationId,
      ),
      [delegatedInvitationId],
    );
    assert.equal(
      (await gw('GET', `/api/vehicles/${vehicleId}/invitations`, inviteeJwt)).status,
      403,
    );
    assert.equal(
      (await gw('GET', `/api/vehicles/${probeVehicleId}/invitations`, inviteeJwt)).status,
      404,
    );

    // Members: owner-only listing with ACTIVE+SUSPENDED by default.
    const members = await gw('GET', `/api/vehicles/${vehicleId}/members`, ownerJwt);
    assert.equal(members.status, 200);
    assertNoAuditFields(members.body);
    const memberRows = members.body.members as Array<Record<string, unknown>>;
    assert.deepEqual(
      memberRows.map((row) => [row.userId, row.role, row.status]),
      [
        [ownerId, 'OWNER', 'ACTIVE'],
        [inviteeId, 'MEMBER', 'ACTIVE'],
        [delegateId, 'MEMBER', 'ACTIVE'],
      ],
    );
    const ownerMembershipId = String(memberRows[0]?.membershipId);
    const inviteeMembershipId = String(memberRows[1]?.membershipId);
    assert.equal(memberRows[2]?.membershipId, delegateMembershipId);
    assert.equal((await gw('GET', `/api/vehicles/${vehicleId}/members`, delegateJwt)).status, 403);
    assert.deepEqual(
      (await gw('GET', `/api/vehicles/${vehicleId}/members?status=REVOKED`, ownerJwt)).body.members,
      [],
    );

    // PATCH replaces base permissions; the OWNER membership and reserved fields are protected.
    const memberBase = `/api/vehicles/${vehicleId}/members`;
    const narrowed = await gw('PATCH', `${memberBase}/${inviteeMembershipId}`, ownerJwt, {
      permissions: ['vehicle:read'],
    });
    assert.equal(narrowed.status, 200);
    assert.deepEqual((narrowed.body.data as Record<string, unknown>).permissions, ['vehicle:read']);
    assertNoAuditFields(narrowed.body);
    assert.equal(
      (await gw('PATCH', `${memberBase}/${ownerMembershipId}`, ownerJwt, { permissions: [] }))
        .status,
      409,
    );
    assert.equal(
      (
        await gw('PATCH', `${memberBase}/${inviteeMembershipId}`, ownerJwt, {
          permissions: ['vehicle:read'],
          role: 'OWNER',
        })
      ).status,
      400,
    );
    assert.equal(
      (
        await gw('PATCH', `${memberBase}/${inviteeMembershipId}`, delegateJwt, {
          permissions: ['vehicle:read', 'device:link'],
        })
      ).status,
      403,
    );

    // Suspend blocks access, reactivate restores base permissions only.
    const suspended = await gw('POST', `${memberBase}/${inviteeMembershipId}/suspend`, ownerJwt, {
      reason: 'Temporary pause',
    });
    assert.equal(suspended.status, 200);
    assert.equal(suspended.body.status, 'SUSPENDED');
    assert.ok((suspended.body.data as Record<string, unknown>).suspendedAt);
    assert.equal((await gw('GET', `/api/vehicles/${vehicleId}`, inviteeJwt)).status, 404);
    assert.equal(
      (await gw('POST', `${memberBase}/${inviteeMembershipId}/suspend`, ownerJwt)).status,
      409,
    );
    assert.equal(
      (await gw('POST', `${memberBase}/${ownerMembershipId}/suspend`, ownerJwt)).status,
      409,
    );
    const reactivated = await gw(
      'POST',
      `${memberBase}/${inviteeMembershipId}/reactivate`,
      ownerJwt,
    );
    assert.equal(reactivated.status, 200);
    assert.equal(reactivated.body.status, 'ACTIVE');
    assert.equal((await gw('GET', `/api/vehicles/${vehicleId}`, inviteeJwt)).status, 200);

    // Removing invitation:create from the delegate revokes their pending issued invitation.
    const demoted = await gw('PATCH', `${memberBase}/${delegateMembershipId}`, ownerJwt, {
      permissions: ['vehicle:read'],
    });
    assert.equal(demoted.status, 200);
    const cascaded = await InvitationModel.findById(delegatedInvitationId).lean();
    assert.equal(cascaded?.status, 'REVOKED');
    assert.equal(cascaded?.revokeReason, 'issuer_authority_lost');

    // DELETE invitation: owner revokes; repeated DELETE returns the original revocation.
    const ownerReinvite = await gw('POST', `/api/vehicles/${vehicleId}/invitations`, ownerJwt, {
      inviteeUserId: unverifiedId,
      permissions: ['vehicle:read', 'device:read'],
    });
    assert.equal(ownerReinvite.status, 201);
    const reinviteId = String(ownerReinvite.body.invitationId);
    assert.equal(
      (await gw('DELETE', `/api/vehicles/${vehicleId}/invitations/${reinviteId}`, delegateJwt))
        .status,
      403,
    );
    const revokedInvitation = await gw(
      'DELETE',
      `/api/vehicles/${vehicleId}/invitations/${reinviteId}`,
      ownerJwt,
      { reason: 'Wrong recipient' },
    );
    assert.equal(revokedInvitation.status, 200);
    assert.equal(revokedInvitation.body.status, 'REVOKED');
    const revokedData = revokedInvitation.body.data as Record<string, unknown>;
    assert.equal(revokedData.revokeReason, 'Wrong recipient');
    assertNoAuditFields(revokedInvitation.body);
    const revokedAgain = await gw(
      'DELETE',
      `/api/vehicles/${vehicleId}/invitations/${reinviteId}`,
      ownerJwt,
      { reason: 'Second reason' },
    );
    assert.equal(revokedAgain.status, 200);
    assert.equal(revokedAgain.body.message, 'Invitation already revoked');
    assert.equal(
      (revokedAgain.body.data as Record<string, unknown>).revokedAt,
      revokedData.revokedAt,
    );
    assert.equal(
      (revokedAgain.body.data as Record<string, unknown>).revokeReason,
      'Wrong recipient',
    );
    assert.equal(
      (await gw('DELETE', `/api/vehicles/${probeVehicleId}/invitations/${reinviteId}`, ownerJwt))
        .status,
      404,
    );

    // Voluntary leave: explicit membershipId, idempotent, never affects a later membership.
    assert.equal((await gw('POST', `${memberBase}/leave`, inviteeJwt, {})).status, 400);
    assert.equal(
      (
        await gw('POST', `${memberBase}/leave`, inviteeJwt, {
          membershipId: delegateMembershipId,
        })
      ).status,
      404,
    );
    assert.equal(
      (
        await gw('POST', `/api/vehicles/${probeVehicleId}/members/leave`, inviteeJwt, {
          membershipId: inviteeMembershipId,
        })
      ).status,
      404,
    );
    const left = await gw('POST', `${memberBase}/leave`, inviteeJwt, {
      membershipId: inviteeMembershipId,
    });
    assert.equal(left.status, 200);
    assert.equal(left.body.status, 'REVOKED');
    assert.equal(left.body.membershipId, inviteeMembershipId);
    assert.equal(left.body.message, 'Left vehicle');
    const leftRecord = await MembershipModel.findById(inviteeMembershipId).lean();
    assert.equal(leftRecord?.revokeReason, 'member_left');
    assert.equal(String(leftRecord?.revokedByUserId), inviteeId);
    const leftAgain = await gw('POST', `${memberBase}/leave`, inviteeJwt, {
      membershipId: inviteeMembershipId,
    });
    assert.equal(leftAgain.status, 200);
    assert.equal(leftAgain.body.message, 'Membership already revoked');
    assert.equal((await gw('GET', `/api/vehicles/${vehicleId}`, inviteeJwt)).status, 404);
    assert.equal(
      (
        await gw('POST', `${memberBase}/leave`, ownerJwt, {
          membershipId: ownerMembershipId,
        })
      ).status,
      409,
    );
    const rejoinInvite = await gw('POST', `/api/vehicles/${vehicleId}/invitations`, ownerJwt, {
      inviteeUserId: inviteeId,
      permissions: ['vehicle:read', 'device:read'],
    });
    assert.equal(rejoinInvite.status, 201);
    const rejoined = await gw(
      'POST',
      `/api/invitations/${String(rejoinInvite.body.invitationId)}/accept`,
      inviteeJwt,
      {},
    );
    assert.equal(rejoined.status, 200);
    const rejoinedMembershipId = String(
      (rejoined.body.data as Record<string, unknown>).membershipId,
    );
    assert.notEqual(rejoinedMembershipId, inviteeMembershipId);
    const replayedLeave = await gw('POST', `${memberBase}/leave`, inviteeJwt, {
      membershipId: inviteeMembershipId,
    });
    assert.equal(replayedLeave.status, 200);
    assert.equal(replayedLeave.body.membershipId, inviteeMembershipId);
    assert.equal(replayedLeave.body.message, 'Membership already revoked');
    const rejoinedRecord = await MembershipModel.findById(rejoinedMembershipId).lean();
    assert.equal(rejoinedRecord?.status, 'ACTIVE');
    assert.deepEqual(rejoinedRecord?.permissions, ['vehicle:read', 'device:read']);
    assert.deepEqual(await MembershipModel.findById(inviteeMembershipId).lean(), leftRecord);
    assert.equal((await gw('GET', `/api/vehicles/${vehicleId}`, inviteeJwt)).status, 200);

    // Owner revokes the delegate; repeated DELETE keeps the original audit and REVOKED is terminal.
    const revokedMember = await gw('DELETE', `${memberBase}/${delegateMembershipId}`, ownerJwt, {
      reason: 'No longer drives',
    });
    assert.equal(revokedMember.status, 200);
    assert.equal(revokedMember.body.status, 'REVOKED');
    const revokedMemberAt = (revokedMember.body.data as Record<string, unknown>).revokedAt;
    const revokedMemberAgain = await gw(
      'DELETE',
      `${memberBase}/${delegateMembershipId}`,
      ownerJwt,
      { reason: 'Overwrite attempt' },
    );
    assert.equal(revokedMemberAgain.status, 200);
    assert.equal(revokedMemberAgain.body.message, 'Member already revoked');
    assert.equal(
      (revokedMemberAgain.body.data as Record<string, unknown>).revokedAt,
      revokedMemberAt,
    );
    assert.equal(
      (await MembershipModel.findById(delegateMembershipId).lean())?.revokeReason,
      'No longer drives',
    );
    assert.equal(
      (await gw('POST', `${memberBase}/${delegateMembershipId}/reactivate`, ownerJwt)).status,
      409,
    );
    assert.equal(
      (
        await gw(
          'DELETE',
          `/api/vehicles/${probeVehicleId}/members/${delegateMembershipId}`,
          ownerJwt,
        )
      ).status,
      404,
    );
    const revokedMembers = await gw('GET', `${memberBase}?status=REVOKED`, ownerJwt);
    assert.deepEqual(
      (revokedMembers.body.members as Array<Record<string, unknown>>)
        .map((row) => row.membershipId)
        .sort(),
      [inviteeMembershipId, delegateMembershipId].sort(),
    );
    const inviteeHistory = await gw('GET', '/api/invitations?status=ACCEPTED', inviteeJwt);
    assert.equal(inviteeHistory.status, 200);
    assert.equal((inviteeHistory.body.invitations as unknown[]).length, 2);

    // DELETE without body, then repeated DELETE with a reason: idempotent and unchanged.
    const archiveNoBody = await gw('DELETE', `/api/vehicles/${probeVehicleId}`, ownerJwt);
    assert.equal(archiveNoBody.status, 200);
    assert.equal(archiveNoBody.body.status, 'ARCHIVED');
    assert.equal(archiveNoBody.body.message, 'Vehicle archived');
    const archiveAgain = await gw('DELETE', `/api/vehicles/${probeVehicleId}`, ownerJwt, {
      reason: 'Second attempt',
    });
    assert.equal(archiveAgain.status, 200);
    assert.equal(archiveAgain.body.archivedAt, archiveNoBody.body.archivedAt);
    assert.equal(archiveAgain.body.message, 'Vehicle already archived');
    assert.equal(
      (await gw('DELETE', `/api/vehicles/${vehicleId}`, ownerJwt, { reason: 'bad\treason' }))
        .status,
      400,
    );
    const archiveWithReason = await gw('DELETE', `/api/vehicles/${vehicleId}`, ownerJwt, {
      reason: 'Vendido a un amigo — Ñandú 🚗',
    });
    assert.equal(archiveWithReason.status, 200);
    const archivedVehicle = await VehicleModel.findById(vehicleId).lean();
    assert.equal(archivedVehicle?.archiveReason, 'Vendido a un amigo — Ñandú 🚗');
    assert.equal(
      (await VehicleModel.findById(probeVehicleId).lean())?.archiveReason,
      null,
      'repeated DELETE does not overwrite the original archive reason',
    );

    const archivedDetail = await gw('GET', `/api/vehicles/${vehicleId}`, ownerJwt);
    assert.equal(archivedDetail.status, 404);
    const archivedPatch = await gw('PATCH', `/api/vehicles/${vehicleId}`, ownerJwt, {
      name: 'Too late',
    });
    assert.equal(archivedPatch.status, 409);
    assert.equal(archivedPatch.body.error, 'CONFLICT');
    const memberArchivedDelete = await gw('DELETE', `/api/vehicles/${vehicleId}`, inviteeJwt);
    assert.equal(memberArchivedDelete.status, 404);
    const listAfterArchive = await gw('GET', '/api/vehicles', ownerJwt);
    assert.deepEqual(listAfterArchive.body.vehicles, []);

    // =========================================================================
    // TKT-015: Gateway -> Vehicle -> Device end-to-end real integration suite
    // =========================================================================
    const deviceDb = rootClient.db('device_db');
    const grantReaderId = String(new Types.ObjectId());
    const grantReaderSessionId = String(new Types.ObjectId());
    await identityDb.collection('users').insertOne({
      _id: new Types.ObjectId(grantReaderId),
      name: 'Grant Reader Verified',
      username: 'grant_reader_verified',
      normalizedUsername: 'grant_reader_verified',
      email: 'grantreader@example.com',
      normalizedEmail: 'grantreader@example.com',
      passwordHash: 'unused',
      emailVerifiedAt: new Date(),
      passwordRecoverySequence: 0,
      passwordRecoveryGeneration: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    await identityDb.collection('sessions').insertOne({
      _id: new Types.ObjectId(grantReaderSessionId),
      userId: new Types.ObjectId(grantReaderId),
      familyId: randomUUID(),
      createdAt: new Date(),
      lastActivityAt: new Date(),
      expiresAt: new Date(Date.now() + 600_000),
      revokedAt: null,
      revokeReason: null,
      userAgent: 'tkt015-e2e',
    });
    const grantReaderJwt = signUserJwt(grantReaderId, grantReaderSessionId, jwtSecret);

    const tkt015VehicleCreate = await gw('POST', '/api/vehicles', ownerJwt, {
      name: 'TKT-015 Mazda 3 Sedan',
      make: 'Mazda',
      model: '3',
      year: 2011,
    });
    assert.equal(tkt015VehicleCreate.status, 201);
    const tkt015VehicleId = String(tkt015VehicleCreate.body.vehicleId);

    const assertNoDeviceSecretsOrAudit = (payload: unknown) => {
      const serialized = JSON.stringify(payload);
      for (const forbidden of [
        '"publicKey"',
        '"challengeHash"',
        '"requestedByUserId"',
        '"requestedByMembershipId"',
        '"revokedByUserId"',
      ]) {
        assert.equal(serialized.includes(forbidden), false, `Forbidden field leaked: ${forbidden}`);
      }
    };

    const registerAndEnrollDevice = async (
      jwt: string,
      label: string,
      metadata?: Record<string, unknown>,
    ) => {
      const keyPair = generateKeyPairSync('ed25519');
      const publicKey = keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
      const reg = await gw('POST', `/api/vehicles/${tkt015VehicleId}/devices`, jwt, {
        identifier: `tkt015-${label}-${randomUUID().slice(0, 8)}`,
        publicKey,
        ...(metadata ? { metadata } : {}),
      });
      assert.equal(reg.status, 201);
      assertNoDeviceSecretsOrAudit(reg.body);
      const devId = String(reg.body.deviceId);
      const chal = await gw(
        'POST',
        `/api/vehicles/${tkt015VehicleId}/devices/${devId}/challenge`,
        jwt,
        {},
      );
      assert.equal(chal.status, 201);
      const c = chal.body.data as Record<string, string>;
      const message = [
        c.protocol,
        c.deviceId,
        c.vehicleId,
        c.credentialId,
        c.requestedByUserId,
        c.challengeId,
        c.challenge,
      ].join('\n');
      const signature = signDetached(
        null,
        Buffer.from(message, 'utf8'),
        keyPair.privateKey,
      ).toString('base64url');
      const linked = await gw(
        'POST',
        `/api/vehicles/${tkt015VehicleId}/devices/${devId}/link`,
        jwt,
        {
          challengeId: c.challengeId,
          challenge: c.challenge,
          signature,
        },
      );
      assert.equal(linked.status, 200);
      assertNoDeviceSecretsOrAudit(linked.body);
      return { deviceId: devId, keyPair, linked: linked.body };
    };

    // 1. Metadata validation: control chars before trim, unknown fields and empty PATCH rejected
    const badMetaKeyPair = generateKeyPairSync('ed25519');
    const badMetaPem = badMetaKeyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    for (const invalidMetadata of [
      { name: '\u0007Sunroof' },
      { name: 'Sunroof\nModule' },
      { unknownField: 'x' },
    ]) {
      const invalidReg = await gw('POST', `/api/vehicles/${tkt015VehicleId}/devices`, ownerJwt, {
        identifier: `tkt015-badmeta-${randomUUID().slice(0, 8)}`,
        publicKey: badMetaPem,
        metadata: invalidMetadata,
      });
      assert.equal(invalidReg.status, 400);
    }

    // 2. Concurrent challenge emissions + domain separation + wrong context + real enrollment
    const primaryPair = generateKeyPairSync('ed25519');
    const primaryReg = await gw('POST', `/api/vehicles/${tkt015VehicleId}/devices`, ownerJwt, {
      identifier: `tkt015-primary-${randomUUID().slice(0, 8)}`,
      publicKey: primaryPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      metadata: {
        name: '  Cabin ESP32  ',
        manufacturer: 'Espressif',
        serialNumber: 'SN-001',
      },
    });
    assert.equal(primaryReg.status, 201);
    const primaryDeviceId = String(primaryReg.body.deviceId);
    assert.equal(
      ((primaryReg.body.data as Record<string, unknown>).metadata as Record<string, unknown>).name,
      'Cabin ESP32',
    );

    // Direct GET /devices/:deviceId on Device is retired (404)
    const retiredDeviceDirectGet = await httpsJsonRequest({
      url: `https://localhost:${ports.device}/devices/${primaryDeviceId}`,
      method: 'GET',
      timeoutMs: 5_000,
      tls: { caPath: caCert, servername: 'localhost' },
    });
    assert.equal(retiredDeviceDirectGet.status, 404);

    // Two concurrent challenge emissions leave strictly one unused challenge
    const [chalA, chalB] = await Promise.all([
      gw(
        'POST',
        `/api/vehicles/${tkt015VehicleId}/devices/${primaryDeviceId}/challenge`,
        ownerJwt,
        {},
      ),
      gw(
        'POST',
        `/api/vehicles/${tkt015VehicleId}/devices/${primaryDeviceId}/challenge`,
        ownerJwt,
        {},
      ),
    ]);
    assert.equal(chalA.status, 201);
    assert.equal(chalB.status, 201);
    const activeChallengesInDb = await deviceDb
      .collection('devicelinkchallenges')
      .find({
        deviceId: new Types.ObjectId(primaryDeviceId),
        usedAt: null,
      })
      .toArray();
    assert.equal(activeChallengesInDb.length, 1);
    const winnerChallengeId = String(activeChallengesInDb[0]!._id);
    const winnerPayload = (
      (chalA.body.data as Record<string, string>).challengeId === winnerChallengeId
        ? chalA.body.data
        : chalB.body.data
    ) as Record<string, string>;
    const supersededPayload = (
      (chalA.body.data as Record<string, string>).challengeId === winnerChallengeId
        ? chalB.body.data
        : chalA.body.data
    ) as Record<string, string>;

    // Superseded challenge cannot be used (409)
    const supersededMsg = [
      supersededPayload.protocol,
      supersededPayload.deviceId,
      supersededPayload.vehicleId,
      supersededPayload.credentialId,
      supersededPayload.requestedByUserId,
      supersededPayload.challengeId,
      supersededPayload.challenge,
    ].join('\n');
    const supersededAttempt = await gw(
      'POST',
      `/api/vehicles/${tkt015VehicleId}/devices/${primaryDeviceId}/link`,
      ownerJwt,
      {
        challengeId: supersededPayload.challengeId,
        challenge: supersededPayload.challenge,
        signature: signDetached(
          null,
          Buffer.from(supersededMsg, 'utf8'),
          primaryPair.privateKey,
        ).toString('base64url'),
      },
    );
    assert.equal(supersededAttempt.status, 409);

    // Bare nonce signature (legacy protocol) is rejected (400)
    const bareNonceSig = signDetached(
      null,
      Buffer.from(winnerPayload.challenge!, 'utf8'),
      primaryPair.privateKey,
    ).toString('base64url');
    const bareNonceAttempt = await gw(
      'POST',
      `/api/vehicles/${tkt015VehicleId}/devices/${primaryDeviceId}/link`,
      ownerJwt,
      {
        challengeId: winnerPayload.challengeId,
        challenge: winnerPayload.challenge,
        signature: bareNonceSig,
      },
    );
    assert.equal(bareNonceAttempt.status, 400);

    // Signature over wrong context (mismatched vehicleId) is rejected (400)
    const wrongContextMsg = [
      winnerPayload.protocol,
      winnerPayload.deviceId,
      String(new Types.ObjectId()),
      winnerPayload.credentialId,
      winnerPayload.requestedByUserId,
      winnerPayload.challengeId,
      winnerPayload.challenge,
    ].join('\n');
    const wrongContextAttempt = await gw(
      'POST',
      `/api/vehicles/${tkt015VehicleId}/devices/${primaryDeviceId}/link`,
      ownerJwt,
      {
        challengeId: winnerPayload.challengeId,
        challenge: winnerPayload.challenge,
        signature: signDetached(
          null,
          Buffer.from(wrongContextMsg, 'utf8'),
          primaryPair.privateKey,
        ).toString('base64url'),
      },
    );
    assert.equal(wrongContextAttempt.status, 400);

    // Valid canonical signature completes enrollment -> ACTIVE & operational
    const validWinnerMsg = [
      winnerPayload.protocol,
      winnerPayload.deviceId,
      winnerPayload.vehicleId,
      winnerPayload.credentialId,
      winnerPayload.requestedByUserId,
      winnerPayload.challengeId,
      winnerPayload.challenge,
    ].join('\n');
    const validWinnerLink = await gw(
      'POST',
      `/api/vehicles/${tkt015VehicleId}/devices/${primaryDeviceId}/link`,
      ownerJwt,
      {
        challengeId: winnerPayload.challengeId,
        challenge: winnerPayload.challenge,
        signature: signDetached(
          null,
          Buffer.from(validWinnerMsg, 'utf8'),
          primaryPair.privateKey,
        ).toString('base64url'),
      },
    );
    assert.equal(validWinnerLink.status, 200);
    assert.equal(validWinnerLink.body.status, 'ACTIVE');
    assert.equal((validWinnerLink.body.data as Record<string, unknown>).operational, true);
    assertNoDeviceSecretsOrAudit(validWinnerLink.body);

    // Owner revokes primaryDeviceId so it sits first as REVOKED in chronological pagination
    assert.equal(
      (
        await gw(
          'POST',
          `/api/vehicles/${tkt015VehicleId}/devices/${primaryDeviceId}/revoke`,
          ownerJwt,
          { reason: 'REPLACED' },
        )
      ).status,
      200,
    );
    // Revoked device rejects metadata PATCH (409)
    assert.equal(
      (
        await gw('PATCH', `/api/vehicles/${tkt015VehicleId}/devices/${primaryDeviceId}`, ownerJwt, {
          name: 'Cannot mutate revoked',
        })
      ).status,
      409,
    );

    // 3. Loss of permission before completing enrollment + Re-entry with new membership
    const invM1 = await gw('POST', `/api/vehicles/${tkt015VehicleId}/invitations`, ownerJwt, {
      inviteeUserId: inviteeId,
      permissions: ['vehicle:read', 'device:link'],
    });
    assert.equal(invM1.status, 201);
    const accM1 = await gw(
      'POST',
      `/api/invitations/${String(invM1.body.invitationId)}/accept`,
      inviteeJwt,
      {},
    );
    assert.equal(accM1.status, 200);
    const m1Id = String((accM1.body.data as Record<string, unknown>).membershipId);

    const lostPermPair = generateKeyPairSync('ed25519');
    const lostPermReg = await gw('POST', `/api/vehicles/${tkt015VehicleId}/devices`, inviteeJwt, {
      identifier: `tkt015-lostperm-${randomUUID().slice(0, 8)}`,
      publicKey: lostPermPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    });
    assert.equal(lostPermReg.status, 201);
    const lostPermDeviceId = String(lostPermReg.body.deviceId);
    const lostPermChal = await gw(
      'POST',
      `/api/vehicles/${tkt015VehicleId}/devices/${lostPermDeviceId}/challenge`,
      inviteeJwt,
      {},
    );
    assert.equal(lostPermChal.status, 201);
    const lostPermChalData = lostPermChal.body.data as Record<string, string>;

    // Owner removes device:link before invitee completes link
    assert.equal(
      (
        await gw('PATCH', `/api/vehicles/${tkt015VehicleId}/members/${m1Id}`, ownerJwt, {
          permissions: ['vehicle:read', 'device:read'],
        })
      ).status,
      200,
    );
    const lostPermMsg = [
      lostPermChalData.protocol,
      lostPermChalData.deviceId,
      lostPermChalData.vehicleId,
      lostPermChalData.credentialId,
      lostPermChalData.requestedByUserId,
      lostPermChalData.challengeId,
      lostPermChalData.challenge,
    ].join('\n');
    const lostPermLink = await gw(
      'POST',
      `/api/vehicles/${tkt015VehicleId}/devices/${lostPermDeviceId}/link`,
      inviteeJwt,
      {
        challengeId: lostPermChalData.challengeId,
        challenge: lostPermChalData.challenge,
        signature: signDetached(
          null,
          Buffer.from(lostPermMsg, 'utf8'),
          lostPermPair.privateKey,
        ).toString('base64url'),
      },
    );
    assert.equal(lostPermLink.status, 404);
    assert.equal(
      (await deviceDb.collection('devices').findOne({ _id: new Types.ObjectId(lostPermDeviceId) }))
        ?.status,
      'PENDING',
    );

    // Owner revokes M1 and re-invites the SAME user (inviteeId) with vehicle:manage (new membership M2)
    assert.equal(
      (await gw('DELETE', `/api/vehicles/${tkt015VehicleId}/members/${m1Id}`, ownerJwt, {})).status,
      200,
    );
    const invM2 = await gw('POST', `/api/vehicles/${tkt015VehicleId}/invitations`, ownerJwt, {
      inviteeUserId: inviteeId,
      permissions: ['vehicle:manage'],
    });
    assert.equal(invM2.status, 201);
    const accM2 = await gw(
      'POST',
      `/api/invitations/${String(invM2.body.invitationId)}/accept`,
      inviteeJwt,
      {},
    );
    assert.equal(accM2.status, 200);
    const m2Id = String((accM2.body.data as Record<string, unknown>).membershipId);
    assert.notEqual(m2Id, m1Id);

    // Even with vehicle:manage under M2, invitee CANNOT challenge, link or self-cancel M1's PENDING device (403)
    assert.equal(
      (
        await gw(
          'POST',
          `/api/vehicles/${tkt015VehicleId}/devices/${lostPermDeviceId}/challenge`,
          inviteeJwt,
          {},
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await gw(
          'POST',
          `/api/vehicles/${tkt015VehicleId}/devices/${lostPermDeviceId}/link`,
          inviteeJwt,
          {
            challengeId: lostPermChalData.challengeId,
            challenge: lostPermChalData.challenge,
            signature: signDetached(
              null,
              Buffer.from(lostPermMsg, 'utf8'),
              lostPermPair.privateKey,
            ).toString('base64url'),
          },
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await gw(
          'POST',
          `/api/vehicles/${tkt015VehicleId}/devices/${lostPermDeviceId}/revoke`,
          inviteeJwt,
          { reason: 'REGISTRATION_CANCELLED' },
        )
      ).status,
      403,
    );

    // Owner administratively revokes lostPermDeviceId (PENDING -> REVOKED)
    assert.equal(
      (
        await gw(
          'POST',
          `/api/vehicles/${tkt015VehicleId}/devices/${lostPermDeviceId}/revoke`,
          ownerJwt,
          { reason: 'ADMINISTRATIVE' },
        )
      ).status,
      200,
    );

    // 4. MEMBER with vehicle:manage: allowed metadata PATCH & own PENDING cancellation (idempotent),
    //    denied administrative revocation on ACTIVE and foreign PENDING
    const activeGrantA = (
      await registerAndEnrollDevice(inviteeJwt, 'grant-a', {
        name: 'Module A',
        manufacturer: 'Bosch',
        serialNumber: 'BOSCH-A',
      })
    ).deviceId;

    assert.equal(
      (
        await gw(
          'PATCH',
          `/api/vehicles/${tkt015VehicleId}/devices/${activeGrantA}`,
          inviteeJwt,
          {},
        )
      ).status,
      400,
    );
    const managerPatch = await gw(
      'PATCH',
      `/api/vehicles/${tkt015VehicleId}/devices/${activeGrantA}`,
      inviteeJwt,
      { name: 'Module A Updated', serialNumber: null },
    );
    assert.equal(managerPatch.status, 200);
    assert.deepEqual(
      (managerPatch.body.data as Record<string, unknown>).metadata as Record<string, unknown>,
      {
        name: 'Module A Updated',
        manufacturer: 'Bosch',
        hardwareModel: null,
        hardwareRevision: null,
        firmwareVersion: null,
        serialNumber: null,
      },
    );

    // MEMBER with vehicle:manage CANNOT revoke an ACTIVE device (even one they linked themselves) -> 403
    assert.equal(
      (
        await gw(
          'POST',
          `/api/vehicles/${tkt015VehicleId}/devices/${activeGrantA}/revoke`,
          inviteeJwt,
          { reason: 'SECURITY_COMPROMISE' },
        )
      ).status,
      403,
    );
    // REGISTRATION_CANCELLED on ACTIVE is rejected (409 for OWNER)
    assert.equal(
      (
        await gw(
          'POST',
          `/api/vehicles/${tkt015VehicleId}/devices/${activeGrantA}/revoke`,
          ownerJwt,
          { reason: 'REGISTRATION_CANCELLED' },
        )
      ).status,
      409,
    );

    // Own PENDING cancellation with REGISTRATION_CANCELLED + idempotent replay
    const ownPendingReg = await gw('POST', `/api/vehicles/${tkt015VehicleId}/devices`, inviteeJwt, {
      identifier: `tkt015-owncancel-${randomUUID().slice(0, 8)}`,
      publicKey: generateKeyPairSync('ed25519')
        .publicKey.export({ type: 'spki', format: 'pem' })
        .toString(),
    });
    assert.equal(ownPendingReg.status, 201);
    const ownPendingId = String(ownPendingReg.body.deviceId);
    // Administrative reason on own PENDING by MEMBER is rejected (403)
    assert.equal(
      (
        await gw(
          'POST',
          `/api/vehicles/${tkt015VehicleId}/devices/${ownPendingId}/revoke`,
          inviteeJwt,
          { reason: 'LOST' },
        )
      ).status,
      403,
    );
    const cancelFirst = await gw(
      'POST',
      `/api/vehicles/${tkt015VehicleId}/devices/${ownPendingId}/revoke`,
      inviteeJwt,
      { reason: 'REGISTRATION_CANCELLED' },
    );
    assert.equal(cancelFirst.status, 200);
    const cancelFirstAt = (cancelFirst.body.data as Record<string, unknown>).revokedAt;
    const cancelReplay = await gw(
      'POST',
      `/api/vehicles/${tkt015VehicleId}/devices/${ownPendingId}/revoke`,
      inviteeJwt,
      { reason: 'REGISTRATION_CANCELLED' },
    );
    assert.equal(cancelReplay.status, 200);
    assert.equal((cancelReplay.body.data as Record<string, unknown>).revokedAt, cancelFirstAt);
    assert.equal(
      (cancelReplay.body.data as Record<string, unknown>).revocationReason,
      'REGISTRATION_CANCELLED',
    );

    // Foreign PENDING cancellation denied
    const ownerPendingReg = await gw('POST', `/api/vehicles/${tkt015VehicleId}/devices`, ownerJwt, {
      identifier: `tkt015-ownerpending-${randomUUID().slice(0, 8)}`,
      publicKey: generateKeyPairSync('ed25519')
        .publicKey.export({ type: 'spki', format: 'pem' })
        .toString(),
    });
    assert.equal(ownerPendingReg.status, 201);
    const ownerPendingId = String(ownerPendingReg.body.deviceId);
    assert.equal(
      (
        await gw(
          'POST',
          `/api/vehicles/${tkt015VehicleId}/devices/${ownerPendingId}/revoke`,
          inviteeJwt,
          { reason: 'REGISTRATION_CANCELLED' },
        )
      ).status,
      403,
    );

    // 5. Interleaved devices for cursor pagination + specific DEVICE grants + degraded ACTIVE
    const activeNoGrantB = (await registerAndEnrollDevice(ownerJwt, 'nogrant-b')).deviceId;
    const activeGrantC = (await registerAndEnrollDevice(ownerJwt, 'grant-c')).deviceId;
    const activeDegradedD = (await registerAndEnrollDevice(ownerJwt, 'degraded-d')).deviceId;
    const activeGrantE = (await registerAndEnrollDevice(ownerJwt, 'grant-e')).deviceId;

    // Degrade activeDegradedD credential in device_db (EXPIRED -> operational: false)
    await deviceDb
      .collection('device_credentials')
      .updateOne(
        { deviceId: new Types.ObjectId(activeDegradedD), status: 'ACTIVE' },
        { $set: { expiresAt: new Date(Date.now() - 60_000) } },
      );

    // Invite grantReader and narrow base permissions to [] (zero base permissions, no vehicle:read!)
    const invGrantReader = await gw(
      'POST',
      `/api/vehicles/${tkt015VehicleId}/invitations`,
      ownerJwt,
      {
        inviteeUserId: grantReaderId,
        permissions: ['vehicle:read'],
      },
    );
    assert.equal(invGrantReader.status, 201);
    const accGrantReader = await gw(
      'POST',
      `/api/invitations/${String(invGrantReader.body.invitationId)}/accept`,
      grantReaderJwt,
      {},
    );
    assert.equal(accGrantReader.status, 200);
    const grantReaderMembershipId = String(
      (accGrantReader.body.data as Record<string, unknown>).membershipId,
    );
    assert.equal(
      (
        await gw(
          'PATCH',
          `/api/vehicles/${tkt015VehicleId}/members/${grantReaderMembershipId}`,
          ownerJwt,
          { permissions: [] },
        )
      ).status,
      200,
    );

    // Issue specific DEVICE ONLINE device:read grants for A, C, D (before degrading D), E, and BLE_OFFLINE for B
    const vehicleObjectId = new Types.ObjectId(tkt015VehicleId);
    for (const targetDeviceId of [activeGrantA, activeGrantC, activeDegradedD, activeGrantE]) {
      const devObjId = new Types.ObjectId(targetDeviceId);
      await createAccessGrant({
        vehicleId: vehicleObjectId,
        membershipId: new Types.ObjectId(grantReaderMembershipId),
        subjectUserId: new Types.ObjectId(grantReaderId),
        actorUserId: new Types.ObjectId(ownerId),
        scopeType: 'DEVICE',
        scopeResourceId: devObjId,
        verifiedResourceBinding: createVerifiedExternalResourceBinding({
          scopeType: 'DEVICE',
          resourceId: devObjId,
          vehicleId: vehicleObjectId,
          isActive: true,
        }),
        channel: 'ONLINE',
        permissions: ['device:read'],
        expiresAt: new Date(Date.now() + 600_000),
      });
    }
    const noGrantBObjId = new Types.ObjectId(activeNoGrantB);
    await createAccessGrant({
      vehicleId: vehicleObjectId,
      membershipId: new Types.ObjectId(grantReaderMembershipId),
      subjectUserId: new Types.ObjectId(grantReaderId),
      actorUserId: new Types.ObjectId(ownerId),
      scopeType: 'DEVICE',
      scopeResourceId: noGrantBObjId,
      verifiedResourceBinding: createVerifiedExternalResourceBinding({
        scopeType: 'DEVICE',
        resourceId: noGrantBObjId,
        vehicleId: vehicleObjectId,
        isActive: true,
      }),
      channel: 'BLE_OFFLINE',
      permissions: ['device:read'],
      expiresAt: new Date(Date.now() + 600_000),
    });

    // grantReader has NO vehicle:read (404 on vehicle detail), CAN read A via both GET endpoints,
    // CANNOT PATCH A (403 because visible via grant), CANNOT read B (BLE_OFFLINE -> 404),
    // CANNOT read ownerPendingId (404), CANNOT read revoked primaryDeviceId (404),
    // and CANNOT read degraded D via DEVICE grant because DeviceClient refuses active binding (404)!
    assert.equal((await gw('GET', `/api/vehicles/${tkt015VehicleId}`, grantReaderJwt)).status, 404);
    assert.equal((await gw('GET', `/api/devices/${activeGrantA}`, grantReaderJwt)).status, 200);
    assert.equal(
      (await gw('GET', `/api/vehicles/${tkt015VehicleId}/devices/${activeGrantA}`, grantReaderJwt))
        .status,
      200,
    );
    assert.equal(
      (
        await gw(
          'PATCH',
          `/api/vehicles/${tkt015VehicleId}/devices/${activeGrantA}`,
          grantReaderJwt,
          { name: 'Grant cannot patch' },
        )
      ).status,
      403,
    );
    for (const invisibleId of [activeNoGrantB, ownerPendingId, primaryDeviceId, activeDegradedD]) {
      assert.equal((await gw('GET', `/api/devices/${invisibleId}`, grantReaderJwt)).status, 404);
      assert.equal(
        (await gw('GET', `/api/vehicles/${tkt015VehicleId}/devices/${invisibleId}`, grantReaderJwt))
          .status,
        404,
      );
    }

    // Base diagnostic reader (OWNER or MEMBER with base device:read/vehicle:manage) CAN inspect degraded D
    const ownerDiag = await gw('GET', `/api/devices/${activeDegradedD}`, ownerJwt);
    assert.equal(ownerDiag.status, 200);
    assert.equal(ownerDiag.body.status, 'ACTIVE');
    assert.equal(ownerDiag.body.operational, false);
    const ownerDiagCred = ownerDiag.body.credential as Record<string, unknown>;
    assert.equal(ownerDiagCred.status, 'EXPIRED');
    assert.equal(ownerDiagCred.usable, false);

    // Interleaved cursor pagination for grantReader with limit=2:
    // Stored order: [primaryDeviceId(REVOKED), lostPermDeviceId(REVOKED), activeGrantA(VISIBLE),
    // ownPendingId(REVOKED), ownerPendingId(PENDING), activeNoGrantB(BLE_OFFLINE),
    // activeGrantC(VISIBLE), activeDegradedD(DEGRADED), activeGrantE(VISIBLE)]
    const grantPage1 = await gw(
      'GET',
      `/api/vehicles/${tkt015VehicleId}/devices?limit=2`,
      grantReaderJwt,
    );
    assert.equal(grantPage1.status, 200);
    assertNoDeviceSecretsOrAudit(grantPage1.body);
    assert.deepEqual(
      (grantPage1.body.devices as Array<Record<string, unknown>>).map((d) => d.deviceId),
      [activeGrantA, activeGrantC],
    );
    const grantCursor = (grantPage1.body.page as { nextCursor: string | null }).nextCursor;
    assert.ok(grantCursor);

    // Cursor bound to actor, vehicle and status filter
    assert.equal(
      (
        await gw(
          'GET',
          `/api/vehicles/${tkt015VehicleId}/devices?limit=2&cursor=${encodeURIComponent(grantCursor)}`,
          ownerJwt,
        )
      ).status,
      400,
    );
    assert.equal(
      (
        await gw(
          'GET',
          `/api/vehicles/${tkt015VehicleId}/devices?limit=2&status=ACTIVE&cursor=${encodeURIComponent(grantCursor)}`,
          grantReaderJwt,
        )
      ).status,
      400,
    );

    const grantPage2 = await gw(
      'GET',
      `/api/vehicles/${tkt015VehicleId}/devices?limit=2&cursor=${encodeURIComponent(grantCursor)}`,
      grantReaderJwt,
    );
    assert.equal(grantPage2.status, 200);
    assert.deepEqual(
      (grantPage2.body.devices as Array<Record<string, unknown>>).map((d) => d.deviceId),
      [activeGrantE],
    );
    assert.equal((grantPage2.body.page as { nextCursor: string | null }).nextCursor, null);

    // Repeated self-cancel preserves original audit, and MUST fail once authority or original membership is lost
    assert.equal(
      (
        await gw('PATCH', `/api/vehicles/${tkt015VehicleId}/members/${m2Id}`, ownerJwt, {
          permissions: ['vehicle:read'],
        })
      ).status,
      200,
    );
    assert.equal(
      (
        await gw(
          'POST',
          `/api/vehicles/${tkt015VehicleId}/devices/${ownPendingId}/revoke`,
          inviteeJwt,
          { reason: 'REGISTRATION_CANCELLED' },
        )
      ).status,
      404,
    );
    const storedOwnCancelled = await deviceDb
      .collection('devices')
      .findOne({ _id: new Types.ObjectId(ownPendingId) });
    assert.equal(storedOwnCancelled?.status, 'REVOKED');
    assert.equal((storedOwnCancelled?.revokedAt as Date | undefined)?.toISOString(), cancelFirstAt);
    const storedOwnRevocation = await deviceDb
      .collection('device_revocations')
      .findOne({ _id: storedOwnCancelled?.revocationId });
    assert.equal(storedOwnRevocation?.reason, 'REGISTRATION_CANCELLED');
    assert.equal(
      (await gw('DELETE', `/api/vehicles/${tkt015VehicleId}/members/${m2Id}`, ownerJwt, {})).status,
      200,
    );
    const invM3 = await gw('POST', `/api/vehicles/${tkt015VehicleId}/invitations`, ownerJwt, {
      inviteeUserId: inviteeId,
      permissions: ['vehicle:manage'],
    });
    assert.equal(invM3.status, 201);
    assert.equal(
      (
        await gw(
          'POST',
          `/api/invitations/${String(invM3.body.invitationId)}/accept`,
          inviteeJwt,
          {},
        )
      ).status,
      200,
    );
    assert.equal(
      (
        await gw(
          'POST',
          `/api/vehicles/${tkt015VehicleId}/devices/${ownPendingId}/revoke`,
          inviteeJwt,
          { reason: 'REGISTRATION_CANCELLED' },
        )
      ).status,
      403,
    );

    // Dedicated vehicle verifying TKT-013 authorization matrix + >5-batch empty-page pagination
    const matrixVehicleCreate = await gw('POST', '/api/vehicles', ownerJwt, {
      name: 'TKT-015 Matrix & Pagination',
      make: 'Mazda',
      model: '3',
      year: 2011,
    });
    assert.equal(matrixVehicleCreate.status, 201);
    const matrixVehicleId = String(matrixVehicleCreate.body.vehicleId);
    const matrixVehicleObjId = new Types.ObjectId(matrixVehicleId);

    const invMatrix = await gw('POST', `/api/vehicles/${matrixVehicleId}/invitations`, ownerJwt, {
      inviteeUserId: grantReaderId,
      permissions: ['vehicle:read'],
    });
    assert.equal(invMatrix.status, 201);
    const accMatrix = await gw(
      'POST',
      `/api/invitations/${String(invMatrix.body.invitationId)}/accept`,
      grantReaderJwt,
      {},
    );
    assert.equal(accMatrix.status, 200);
    const matrixMembershipId = String(
      (accMatrix.body.data as Record<string, unknown>).membershipId,
    );

    // Seed 130 older hidden ACTIVE devices (with ACTIVE credentials, no DEVICE grant)
    // before the granted ACTIVE devices (>5 batches of 25)
    const hiddenBaseTime = new Date(Date.now() - 3_600_000);
    const hiddenSharedPem = generateKeyPairSync('ed25519')
      .publicKey.export({ type: 'spki', format: 'pem' })
      .toString()
      .trim();
    const hiddenDocs = Array.from({ length: 130 }, (_, index) => {
      const id = new Types.ObjectId();
      const ts = new Date(hiddenBaseTime.getTime() + index * 1_000);
      return {
        _id: id,
        vehicleId: matrixVehicleObjId,
        identifier: `tkt015-hidden-${String(index).padStart(3, '0')}-${randomUUID().slice(0, 6)}`,
        status: 'ACTIVE',
        requestedByUserId: new Types.ObjectId(ownerId),
        requestedByMembershipId: null,
        linkedByUserId: new Types.ObjectId(ownerId),
        linkedAt: ts,
        revokedAt: null,
        revocationId: null,
        lastSeenAt: null,
        metadata: null,
        createdAt: ts,
        updatedAt: ts,
      };
    });
    const hiddenCredentialDocs = hiddenDocs.map((doc, index) => ({
      _id: new Types.ObjectId(),
      deviceId: doc._id,
      vehicleId: matrixVehicleObjId,
      keyId: `dk_${randomUUID().replaceAll('-', '').slice(0, 22)}`,
      algorithm: 'Ed25519',
      publicKey: hiddenSharedPem,
      fingerprint: `sha256:${String(index).padStart(64, 'a')}`,
      status: 'ACTIVE',
      activatedAt: doc.createdAt,
      expiresAt: null,
      revokedAt: null,
      revocationId: null,
      createdAt: doc.createdAt,
      updatedAt: doc.createdAt,
    }));
    await deviceDb.collection('devices').insertMany(hiddenDocs);
    await deviceDb.collection('device_credentials').insertMany(hiddenCredentialDocs);

    const matrixPendingReg = await gw(
      'POST',
      `/api/vehicles/${matrixVehicleId}/devices`,
      ownerJwt,
      {
        identifier: `tkt015-matrix-pending-${randomUUID().slice(0, 8)}`,
        publicKey: generateKeyPairSync('ed25519')
          .publicKey.export({ type: 'spki', format: 'pem' })
          .toString(),
      },
    );
    assert.equal(matrixPendingReg.status, 201);
    const matrixPendingId = String(matrixPendingReg.body.deviceId);

    const registerAndEnrollInMatrixVehicle = async (label: string) => {
      const kp = generateKeyPairSync('ed25519');
      const reg = await gw('POST', `/api/vehicles/${matrixVehicleId}/devices`, ownerJwt, {
        identifier: `tkt015-${label}-${randomUUID().slice(0, 8)}`,
        publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      });
      assert.equal(reg.status, 201);
      const devId = String(reg.body.deviceId);
      const chal = await gw(
        'POST',
        `/api/vehicles/${matrixVehicleId}/devices/${devId}/challenge`,
        ownerJwt,
        {},
      );
      assert.equal(chal.status, 201);
      const c = chal.body.data as Record<string, string>;
      const msg = [
        c.protocol,
        c.deviceId,
        c.vehicleId,
        c.credentialId,
        c.requestedByUserId,
        c.challengeId,
        c.challenge,
      ].join('\n');
      const linked = await gw(
        'POST',
        `/api/vehicles/${matrixVehicleId}/devices/${devId}/link`,
        ownerJwt,
        {
          challengeId: c.challengeId,
          challenge: c.challenge,
          signature: signDetached(null, Buffer.from(msg, 'utf8'), kp.privateKey).toString(
            'base64url',
          ),
        },
      );
      assert.equal(linked.status, 200);
      return devId;
    };

    const deepAuthA = await registerAndEnrollInMatrixVehicle('deep-a');
    const deepAuthB = await registerAndEnrollInMatrixVehicle('deep-b');
    const deepDegradedC = await registerAndEnrollInMatrixVehicle('deep-degraded-c');
    await deviceDb
      .collection('device_credentials')
      .updateOne(
        { deviceId: new Types.ObjectId(deepDegradedC), status: 'ACTIVE' },
        { $set: { expiresAt: new Date(Date.now() - 60_000) } },
      );

    // Historical VEHICLE-scoped grant with `device:read` MUST NEVER grant device access
    const legacyGrantNow = new Date();
    const legacyVehicleGrantId = new Types.ObjectId();
    await AccessGrantModel.collection.insertOne({
      _id: legacyVehicleGrantId,
      vehicleId: matrixVehicleObjId,
      membershipId: new Types.ObjectId(matrixMembershipId),
      subjectUserId: new Types.ObjectId(grantReaderId),
      scopeType: 'VEHICLE',
      scopeResourceId: null,
      channel: 'ONLINE',
      permissions: ['device:read'],
      status: 'ACTIVE',
      startsAt: legacyGrantNow,
      expiresAt: null,
      grantedByUserId: new Types.ObjectId(ownerId),
      revokedAt: null,
      revokedByUserId: null,
      revokeReason: null,
      expiredAt: null,
      createdAt: legacyGrantNow,
      updatedAt: legacyGrantNow,
    });
    assert.equal((await gw('GET', `/api/devices/${deepAuthA}`, grantReaderJwt)).status, 404);
    assert.equal(
      (await gw('GET', `/api/vehicles/${matrixVehicleId}/devices/${deepAuthA}`, grantReaderJwt))
        .status,
      404,
    );
    assert.equal(
      (await gw('GET', `/api/vehicles/${matrixVehicleId}/devices`, grantReaderJwt)).status,
      403,
    );

    // Base `device:read` permission (without `vehicle:read`) retains approved behavior
    assert.equal(
      (
        await gw(
          'PATCH',
          `/api/vehicles/${matrixVehicleId}/members/${matrixMembershipId}`,
          ownerJwt,
          { permissions: ['device:read'] },
        )
      ).status,
      200,
    );
    assert.equal((await gw('GET', `/api/devices/${deepAuthA}`, grantReaderJwt)).status, 200);
    const baseDegradedRead = await gw(
      'GET',
      `/api/vehicles/${matrixVehicleId}/devices/${deepDegradedC}`,
      grantReaderJwt,
    );
    assert.equal(baseDegradedRead.status, 200);
    assert.equal(baseDegradedRead.body.operational, false);
    assert.equal(
      (
        await gw(
          'GET',
          `/api/vehicles/${matrixVehicleId}/devices/${matrixPendingId}`,
          grantReaderJwt,
        )
      ).status,
      404,
    );
    assert.equal(
      (
        await gw('PATCH', `/api/vehicles/${matrixVehicleId}/devices/${deepAuthA}`, grantReaderJwt, {
          name: 'Base read cannot patch',
        })
      ).status,
      403,
    );

    // Restore `vehicle:read` only, then grant DEVICE ONLINE `device:read` on deepAuthA & deepAuthB
    assert.equal(
      (
        await gw(
          'PATCH',
          `/api/vehicles/${matrixVehicleId}/members/${matrixMembershipId}`,
          ownerJwt,
          { permissions: ['vehicle:read'] },
        )
      ).status,
      200,
    );
    for (const targetId of [deepAuthA, deepAuthB]) {
      const targetObjId = new Types.ObjectId(targetId);
      await createAccessGrant({
        vehicleId: matrixVehicleObjId,
        membershipId: new Types.ObjectId(matrixMembershipId),
        subjectUserId: new Types.ObjectId(grantReaderId),
        actorUserId: new Types.ObjectId(ownerId),
        scopeType: 'DEVICE',
        scopeResourceId: targetObjId,
        verifiedResourceBinding: createVerifiedExternalResourceBinding({
          scopeType: 'DEVICE',
          resourceId: targetObjId,
          vehicleId: matrixVehicleObjId,
          isActive: true,
        }),
        channel: 'ONLINE',
        permissions: ['device:read'],
        expiresAt: new Date(Date.now() + 600_000),
      });
    }

    // Real E2E >5-batch pagination: page 1 returns empty `devices: []` + encrypted `nextCursor`, page 2 yields [deepAuthA, deepAuthB]
    const deepPage1 = await gw(
      'GET',
      `/api/vehicles/${matrixVehicleId}/devices?limit=2`,
      grantReaderJwt,
    );
    assert.equal(deepPage1.status, 200);
    assert.deepEqual(deepPage1.body.devices, []);
    const deepCursor = (deepPage1.body.page as { nextCursor: string | null }).nextCursor;
    assert.ok(deepCursor, 'empty page across 5 unauthorized batches must still expose nextCursor');
    const decodedDeepCursor = Buffer.from(deepCursor, 'base64url').toString('latin1');
    for (const hiddenDoc of hiddenDocs) {
      const hiddenHex = String(hiddenDoc._id);
      assert.equal(deepCursor.includes(hiddenHex), false);
      assert.equal(decodedDeepCursor.includes(hiddenHex), false);
    }

    const deepPage2 = await gw(
      'GET',
      `/api/vehicles/${matrixVehicleId}/devices?limit=2&cursor=${encodeURIComponent(deepCursor)}`,
      grantReaderJwt,
    );
    assert.equal(deepPage2.status, 200);
    assert.deepEqual(
      (deepPage2.body.devices as Array<Record<string, unknown>>).map((d) => d.deviceId),
      [deepAuthA, deepAuthB],
    );
    assert.equal((deepPage2.body.page as { nextCursor: string | null }).nextCursor, null);

    // Archived vehicle blocks device reads and administrative operations via API (404)
    assert.equal((await gw('DELETE', `/api/vehicles/${tkt015VehicleId}`, ownerJwt)).status, 200);
    assert.equal((await gw('GET', `/api/devices/${activeGrantA}`, ownerJwt)).status, 404);
    assert.equal(
      (await gw('GET', `/api/vehicles/${tkt015VehicleId}/devices`, ownerJwt)).status,
      404,
    );
    assert.equal(
      (
        await gw(
          'POST',
          `/api/vehicles/${tkt015VehicleId}/devices/${activeGrantA}/revoke`,
          ownerJwt,
          { reason: 'ADMINISTRATIVE' },
        )
      ).status,
      404,
    );

    // Also verify MongoNonceStore.assertReady() passes against the real vehicle_db
    const nonceStore = new MongoNonceStore(() => mongoose.connection.db as never);
    await assert.doesNotReject(() => nonceStore.assertReady());
  } finally {
    for (const child of children.reverse()) {
      await stopChild(child);
    }
    await rm(tlsDir, { recursive: true, force: true }).catch(() => undefined);
  }
});

async function insertBoundInvitation(input: {
  vehicleId: Types.ObjectId;
  inviterUserId: Types.ObjectId;
  inviteeUserId: Types.ObjectId;
  issuerMembershipId?: Types.ObjectId;
  permissions?: string[];
}): Promise<Types.ObjectId> {
  const _id = new Types.ObjectId();
  const now = new Date();
  await InvitationModel.collection.insertOne({
    _id,
    vehicleId: input.vehicleId,
    inviterUserId: input.inviterUserId,
    inviteeUserId: input.inviteeUserId,
    ...(input.issuerMembershipId ? { issuerMembershipId: input.issuerMembershipId } : {}),
    targetRole: 'MEMBER',
    permissions: input.permissions ?? ['vehicle:read'],
    status: 'PENDING',
    expiresAt: new Date(now.getTime() + 3_600_000),
    acceptedAt: null,
    acceptedByUserId: null,
    revokedAt: null,
    revokedByUserId: null,
    revokeReason: null,
    expiredAt: null,
    updatedByUserId: null,
    createdAt: now,
    updatedAt: now,
  });
  return _id;
}

/**
 * Holds an uncommitted transaction that writes the vehicle (the shared barrier) and applies
 * `update` to a membership, simulating an issuer change in flight.
 */
async function holdMembershipChange(
  vehicleId: Types.ObjectId,
  membershipId: Types.ObjectId,
  update: Record<string, unknown>,
): Promise<{ commit: () => Promise<void> }> {
  const session = await mongoose.startSession();
  session.startTransaction({ readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' } });
  await VehicleModel.updateOne(
    { _id: vehicleId },
    { $set: { updatedAt: new Date() } },
    { session },
  );
  await MembershipModel.updateOne({ _id: membershipId }, { $set: update }, { session });
  return {
    commit: async () => {
      await session.commitTransaction();
      await session.endSession();
    },
  };
}

test('20. TKT-012 issuance: delegation limits, no AccessGrant authority, no overwrite, OWNER-only re-invitation, and no oracle', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Delegation Coupe' });
  const otherVehicle = await createVehicle(new Types.ObjectId(), { name: 'Foreign Coupe' });
  const ownerMembership = await MembershipModel.findOne({ vehicleId: vehicle._id, role: 'OWNER' });
  assert.ok(ownerMembership);
  const delegate = await addAcceptedMember(vehicle._id, ownerId, [
    'vehicle:read',
    'device:read',
    'invitation:create',
  ]);
  const manager = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:manage', 'module:read']);
  const reader = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read']);
  await insertRawActiveGrant({
    vehicleId: vehicle._id,
    membershipId: reader.membershipId,
    subjectUserId: reader.memberId,
    grantedByUserId: ownerId,
    permissions: ['vehicle:read', 'invitation:create', 'vehicle:manage'],
    expiresAt: null,
  });

  let lookups = 0;
  const confirmInviteeExists = async () => {
    lookups += 1;
    return true;
  };
  const target = new Types.ObjectId();
  const snapshot = await vehiclePersistenceSnapshot(vehicle._id);
  const forbidden: Array<[Types.ObjectId, string[]]> = [
    [delegate.memberId, ['device:link']],
    [delegate.memberId, ['module:read']],
    [delegate.memberId, ['invitation:create']],
    [delegate.memberId, ['vehicle:manage']],
    [delegate.memberId, ['vehicle:read', 'device:link']],
    [manager.memberId, ['vehicle:read']],
    [reader.memberId, ['vehicle:read']],
  ];
  for (const [issuer, permissions] of forbidden) {
    await rejectsWithCode(
      () => inviteMember(vehicle._id, issuer, target, permissions, { confirmInviteeExists }),
      'FORBIDDEN',
    );
  }
  assert.equal(
    await inviteMember(vehicle._id, new Types.ObjectId(), target, ['vehicle:read'], {
      confirmInviteeExists,
    }),
    null,
  );
  assert.equal(
    await inviteMember(otherVehicle._id, delegate.memberId, target, ['vehicle:read'], {
      confirmInviteeExists,
    }),
    null,
  );
  assert.equal(lookups, 0, 'unauthorized issuers never reach Identity');
  assert.equal(await vehiclePersistenceSnapshot(vehicle._id), snapshot);

  await rejectsWithCode(
    () =>
      inviteMember(vehicle._id, ownerId, target, ['vehicle:read'], {
        confirmInviteeExists: async () => {
          lookups += 1;
          return false;
        },
      }),
    'NOT_FOUND',
  );
  assert.equal(lookups, 1);
  assert.equal(await vehiclePersistenceSnapshot(vehicle._id), snapshot);

  // Allowed delegations are bound to the issuing membership identity.
  const delegated = await inviteMember(
    vehicle._id,
    delegate.memberId,
    target,
    ['vehicle:read', 'device:read'],
    { confirmInviteeExists },
  );
  assert.ok(delegated);
  assert.equal(lookups, 2);
  assert.equal(delegated.issuerMembershipId?.equals(delegate.membershipId), true);
  const managerTarget = new Types.ObjectId();
  const managed = await inviteMember(vehicle._id, manager.memberId, managerTarget, ['module:read']);
  assert.equal(managed?.issuerMembershipId?.equals(manager.membershipId), true);
  const ownerTarget = new Types.ObjectId();
  const ownerIssued = await inviteMember(vehicle._id, ownerId, ownerTarget, [
    'vehicle:read',
    'device:link',
  ]);
  assert.ok(ownerIssued && managed);
  assert.equal(ownerIssued.issuerMembershipId?.equals(ownerMembership._id), true);

  // A valid pending invitation is never overwritten, whoever tries.
  const beforeDuplicate = await InvitationModel.findById(ownerIssued._id).lean();
  await rejectsWithCode(
    () => inviteMember(vehicle._id, ownerId, ownerTarget, ['vehicle:read']),
    'CONFLICT',
  );
  await rejectsWithCode(
    () => inviteMember(vehicle._id, delegate.memberId, ownerTarget, ['vehicle:read']),
    'CONFLICT',
  );
  assert.deepEqual(await InvitationModel.findById(ownerIssued._id).lean(), beforeDuplicate);
  assert.equal(
    await InvitationModel.countDocuments({ vehicleId: vehicle._id, inviteeUserId: ownerTarget }),
    1,
  );

  // Invalid recipients.
  await rejectsWithCode(
    () => inviteMember(vehicle._id, delegate.memberId, delegate.memberId, ['vehicle:read']),
    'VALIDATION_ERROR',
  );
  await rejectsWithCode(
    () => inviteMember(vehicle._id, delegate.memberId, ownerId, ['vehicle:read']),
    'CONFLICT',
  );
  await rejectsWithCode(
    () => inviteMember(vehicle._id, ownerId, reader.memberId, ['vehicle:read']),
    'CONFLICT',
  );
  await suspendMembership({
    vehicleId: vehicle._id,
    membershipId: reader.membershipId,
    actorUserId: ownerId,
  });
  await rejectsWithCode(
    () => inviteMember(vehicle._id, ownerId, reader.memberId, ['vehicle:read']),
    'CONFLICT',
  );

  // Terminal invitations cannot be reused.
  await revokeInvitation({
    vehicleId: vehicle._id,
    invitationId: managed._id,
    actorUserId: ownerId,
  });
  await rejectsWithCode(() => acceptInvitation(managed._id, managerTarget), 'CONFLICT');

  // Only the OWNER re-invites a revoked member; the new membership inherits no grants.
  await revokeMembership({
    vehicleId: vehicle._id,
    membershipId: reader.membershipId,
    actorUserId: ownerId,
  });
  await rejectsWithCode(
    () => inviteMember(vehicle._id, delegate.memberId, reader.memberId, ['vehicle:read']),
    'FORBIDDEN',
  );
  const reinvite = await inviteMember(vehicle._id, ownerId, reader.memberId, ['vehicle:read']);
  assert.ok(reinvite);
  const rejoined = await acceptInvitation(reinvite._id, reader.memberId);
  assert.ok(rejoined);
  assert.equal(rejoined._id.equals(reader.membershipId), false);
  assert.equal(await AccessGrantModel.countDocuments({ membershipId: rejoined._id }), 0);
  assert.equal(
    await AccessGrantModel.countDocuments({ membershipId: reader.membershipId, status: 'ACTIVE' }),
    0,
  );

  // Concurrent duplicate issuance: exactly one invitation, every loser gets CONFLICT.
  const raceTarget = new Types.ObjectId();
  const attempts = await Promise.allSettled(
    Array.from({ length: 6 }, (_, index) =>
      inviteMember(vehicle._id, index % 2 ? ownerId : delegate.memberId, raceTarget, [
        'vehicle:read',
      ]),
    ),
  );
  assert.equal(
    attempts.filter((attempt) => attempt.status === 'fulfilled' && attempt.value).length,
    1,
  );
  for (const attempt of attempts) {
    if (attempt.status === 'rejected') {
      assert.ok(attempt.reason instanceof VehicleServiceError);
      assert.equal(attempt.reason.code, 'CONFLICT');
    }
  }
  assert.equal(
    await InvitationModel.countDocuments({ vehicleId: vehicle._id, inviteeUserId: raceTarget }),
    1,
  );
});

test('21. TKT-012 acceptance revalidates the issuing membership and durably revokes invitations whose issuer lost authority', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Authority Sedan' });
  const delegate = await addAcceptedMember(vehicle._id, ownerId, [
    'vehicle:read',
    'device:read',
    'invitation:create',
  ]);
  const issue = async (issuer: Types.ObjectId, permissions: string[]) => {
    const invitee = new Types.ObjectId();
    const invitation = await inviteMember(vehicle._id, issuer, invitee, permissions);
    assert.ok(invitation);
    return { invitee, invitationId: invitation._id };
  };

  // Only the invitee can accept; everyone else sees nothing and changes nothing.
  const readInvite = await issue(delegate.memberId, ['vehicle:read']);
  const deviceInvite = await issue(delegate.memberId, ['device:read']);
  assert.equal(await acceptInvitation(readInvite.invitationId, new Types.ObjectId()), null);
  assert.equal(await acceptInvitation(readInvite.invitationId, ownerId), null);
  assert.equal(await acceptInvitation(readInvite.invitationId, delegate.memberId), null);
  assert.equal((await InvitationModel.findById(readInvite.invitationId).lean())?.status, 'PENDING');

  // Partial loss of delegated permissions revokes only the invitations it no longer covers.
  const partial = await updateMembershipPermissions({
    vehicleId: vehicle._id,
    membershipId: delegate.membershipId,
    actorUserId: ownerId,
    permissions: ['vehicle:read', 'invitation:create'],
  });
  assert.equal(partial.changed, true);
  assert.equal(partial.revokedInvitationsCount, 1);
  const deviceAfter = await InvitationModel.findById(deviceInvite.invitationId).lean();
  assert.equal(deviceAfter?.status, 'REVOKED');
  assert.equal(deviceAfter?.revokeReason, INVITATION_ISSUER_AUTHORITY_LOST_REASON);
  assert.equal(deviceAfter?.revokedByUserId?.equals(ownerId), true);
  assert.equal((await InvitationModel.findById(readInvite.invitationId).lean())?.status, 'PENDING');

  // Authority lost without a cascade (e.g. a pre-TKT-012 writer): acceptance is rejected and the
  // REVOKED transition survives the rejected acceptance.
  await MembershipModel.collection.updateOne(
    { _id: delegate.membershipId },
    { $set: { permissions: ['vehicle:read'] } },
  );
  await rejectsWithCode(
    () => acceptInvitation(readInvite.invitationId, readInvite.invitee),
    'CONFLICT',
  );
  const lost = await InvitationModel.findById(readInvite.invitationId).lean();
  assert.equal(lost?.status, 'REVOKED');
  assert.equal(lost?.revokeReason, INVITATION_ISSUER_AUTHORITY_LOST_REASON);
  assert.equal(lost?.revokedByUserId?.equals(readInvite.invitee), true);
  assert.equal(
    await MembershipModel.countDocuments({ vehicleId: vehicle._id, userId: readInvite.invitee }),
    0,
  );
  await rejectsWithCode(
    () => acceptInvitation(readInvite.invitationId, readInvite.invitee),
    'CONFLICT',
  );
  await MembershipModel.collection.updateOne(
    { _id: delegate.membershipId },
    { $set: { permissions: ['vehicle:read', 'invitation:create'] } },
  );

  // Revoked and rejoined issuer: the new membership never revalidates invitations of the old one.
  const cascaded = await issue(delegate.memberId, ['vehicle:read']);
  const revokedIssuer = await revokeMembership({
    vehicleId: vehicle._id,
    membershipId: delegate.membershipId,
    actorUserId: ownerId,
  });
  assert.equal(revokedIssuer.revokedInvitationsCount, 1);
  assert.equal((await InvitationModel.findById(cascaded.invitationId).lean())?.status, 'REVOKED');
  const orphanInvitee = new Types.ObjectId();
  const orphanId = await insertBoundInvitation({
    vehicleId: vehicle._id,
    inviterUserId: delegate.memberId,
    inviteeUserId: orphanInvitee,
    issuerMembershipId: delegate.membershipId,
  });
  const rejoinInvite = await inviteMember(vehicle._id, ownerId, delegate.memberId, [
    'vehicle:read',
    'invitation:create',
  ]);
  assert.ok(rejoinInvite);
  const rejoined = await acceptInvitation(rejoinInvite._id, delegate.memberId);
  assert.ok(rejoined);
  await rejectsWithCode(() => acceptInvitation(orphanId, orphanInvitee), 'CONFLICT');
  assert.equal(
    (await InvitationModel.findById(orphanId).lean())?.revokeReason,
    INVITATION_ISSUER_AUTHORITY_LOST_REASON,
  );
  const fresh = await issue(delegate.memberId, ['vehicle:read']);
  assert.ok(await acceptInvitation(fresh.invitationId, fresh.invitee));

  // Legacy invitations without issuer binding: delegate ones fail closed, owner ones stay valid.
  const legacyDelegateInvitee = new Types.ObjectId();
  const legacyDelegate = await insertBoundInvitation({
    vehicleId: vehicle._id,
    inviterUserId: delegate.memberId,
    inviteeUserId: legacyDelegateInvitee,
  });
  await rejectsWithCode(() => acceptInvitation(legacyDelegate, legacyDelegateInvitee), 'CONFLICT');
  assert.equal((await InvitationModel.findById(legacyDelegate).lean())?.status, 'REVOKED');
  const legacyOwnerInvitee = new Types.ObjectId();
  const legacyOwner = await insertBoundInvitation({
    vehicleId: vehicle._id,
    inviterUserId: ownerId,
    inviteeUserId: legacyOwnerInvitee,
  });
  assert.ok(await acceptInvitation(legacyOwner, legacyOwnerInvitee));

  // Exact expiry boundary: expiresAt itself is already expired; one millisecond earlier is valid.
  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + 1_000);
  const atBoundary = new Types.ObjectId();
  const boundaryInvite = await inviteMember(vehicle._id, ownerId, atBoundary, ['vehicle:read'], {
    now: issuedAt,
    ttlMs: 1_000,
  });
  const beforeBoundary = new Types.ObjectId();
  const earlyInvite = await inviteMember(vehicle._id, ownerId, beforeBoundary, ['vehicle:read'], {
    now: issuedAt,
    ttlMs: 1_000,
  });
  assert.ok(boundaryInvite && earlyInvite);
  await rejectsWithCode(
    () => acceptInvitation(boundaryInvite._id, atBoundary, { now: expiresAt }),
    'CONFLICT',
  );
  const expired = await InvitationModel.findById(boundaryInvite._id).lean();
  assert.equal(expired?.status, 'EXPIRED');
  assert.equal(expired?.expiredAt?.getTime(), expiresAt.getTime());
  assert.ok(
    await acceptInvitation(earlyInvite._id, beforeBoundary, {
      now: new Date(expiresAt.getTime() - 1),
    }),
  );
});

test('22. TKT-012 membership administration: OWNER-only transitions, cascades, idempotency, leave, and protected OWNER', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Lifecycle Wagon' });
  const otherVehicle = await createVehicle(ownerId, { name: 'Second Wagon' });
  const ownerMembership = await MembershipModel.findOne({ vehicleId: vehicle._id, role: 'OWNER' });
  assert.ok(ownerMembership);
  const member = await addAcceptedMember(vehicle._id, ownerId, [
    'vehicle:read',
    'device:read',
    'invitation:create',
  ]);
  const manager = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read', 'vehicle:manage']);
  const outsider = new Types.ObjectId();
  const grantId = await insertRawActiveGrant({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: member.memberId,
    grantedByUserId: ownerId,
    permissions: ['device:link'],
    expiresAt: null,
  });
  assert.ok(
    await inviteMember(vehicle._id, member.memberId, new Types.ObjectId(), ['vehicle:read']),
  );
  const target = { vehicleId: vehicle._id, membershipId: member.membershipId };

  // Non-owners: FORBIDDEN when they can read the vehicle, NOT_FOUND otherwise; nothing changes.
  const snapshot = await vehiclePersistenceSnapshot(vehicle._id);
  for (const [actor, code] of [
    [manager.memberId, 'FORBIDDEN'],
    [outsider, 'NOT_FOUND'],
  ] as const) {
    await rejectsWithCode(() => suspendMembership({ ...target, actorUserId: actor }), code);
    await rejectsWithCode(() => reactivateMembership({ ...target, actorUserId: actor }), code);
    await rejectsWithCode(() => revokeMembership({ ...target, actorUserId: actor }), code);
    await rejectsWithCode(
      () => updateMembershipPermissions({ ...target, actorUserId: actor, permissions: [] }),
      code,
    );
    await rejectsWithCode(() => listVehicleMembers(vehicle._id, actor), code);
  }
  await rejectsWithCode(
    () =>
      suspendMembership({
        vehicleId: otherVehicle._id,
        membershipId: member.membershipId,
        actorUserId: ownerId,
      }),
    'NOT_FOUND',
  );
  assert.equal(await vehiclePersistenceSnapshot(vehicle._id), snapshot);

  // The OWNER membership is never a valid target and the OWNER cannot leave.
  const ownerTarget = {
    vehicleId: vehicle._id,
    membershipId: ownerMembership._id,
    actorUserId: ownerId,
  };
  await rejectsWithCode(() => suspendMembership(ownerTarget), 'CONFLICT');
  await rejectsWithCode(() => reactivateMembership(ownerTarget), 'CONFLICT');
  await rejectsWithCode(() => revokeMembership(ownerTarget), 'CONFLICT');
  await rejectsWithCode(
    () => updateMembershipPermissions({ ...ownerTarget, permissions: ['vehicle:read'] }),
    'CONFLICT',
  );
  await rejectsWithCode(
    () =>
      leaveVehicle({
        vehicleId: vehicle._id,
        actorUserId: ownerId,
        membershipId: ownerMembership._id,
      }),
    'CONFLICT',
  );
  const ownerAfter = await MembershipModel.findById(ownerMembership._id).lean();
  assert.equal(ownerAfter?.status, 'ACTIVE');
  assert.equal(ownerAfter?.role, 'OWNER');
  assert.deepEqual(ownerAfter?.permissions, ownerMembership.permissions);

  // Permission replacement: validated, full replace, empty allowed, grants untouched.
  await rejectsWithCode(
    () =>
      updateMembershipPermissions({
        ...target,
        actorUserId: ownerId,
        permissions: ['vehicle:fly'],
      }),
    'VALIDATION_ERROR',
  );
  await rejectsWithCode(
    () =>
      updateMembershipPermissions({
        ...target,
        actorUserId: ownerId,
        permissions: ['vehicle:read', 'vehicle:read'],
      }),
    'VALIDATION_ERROR',
  );
  const unchanged = await updateMembershipPermissions({
    ...target,
    actorUserId: ownerId,
    permissions: ['vehicle:read', 'device:read', 'invitation:create'],
  });
  assert.equal(unchanged.changed, false);
  const emptied = await updateMembershipPermissions({
    ...target,
    actorUserId: ownerId,
    permissions: [],
  });
  assert.equal(emptied.changed, true);
  assert.deepEqual(emptied.membership.permissions, []);
  assert.equal(emptied.membership.role, 'MEMBER');
  assert.equal(emptied.membership.status, 'ACTIVE');
  assert.equal(emptied.membership.userId.equals(member.memberId), true);
  assert.equal(emptied.revokedInvitationsCount, 1);
  assert.equal((await AccessGrantModel.findById(grantId).lean())?.status, 'ACTIVE');
  await updateMembershipPermissions({
    ...target,
    actorUserId: ownerId,
    permissions: ['vehicle:read', 'invitation:create'],
  });

  // Suspension revokes grants and issued invitations, keeps base permissions.
  const issuedBeforeSuspend = await inviteMember(
    vehicle._id,
    member.memberId,
    new Types.ObjectId(),
    ['vehicle:read'],
  );
  assert.ok(issuedBeforeSuspend);
  const suspended = await suspendMembership({
    ...target,
    actorUserId: ownerId,
    reason: 'Lost keys',
  });
  assert.equal(suspended.membership.status, 'SUSPENDED');
  assert.equal(suspended.revokedGrantsCount, 1);
  assert.equal(suspended.revokedInvitationsCount, 1);
  assert.deepEqual(suspended.membership.permissions, ['vehicle:read', 'invitation:create']);
  assert.equal((await AccessGrantModel.findById(grantId).lean())?.status, 'REVOKED');
  const suspendedInvite = await InvitationModel.findById(issuedBeforeSuspend._id).lean();
  assert.equal(suspendedInvite?.revokeReason, INVITATION_ISSUER_AUTHORITY_LOST_REASON);
  await rejectsWithCode(() => suspendMembership({ ...target, actorUserId: ownerId }), 'CONFLICT');
  await assert.rejects(
    () =>
      createAccessGrant({
        vehicleId: vehicle._id,
        membershipId: member.membershipId,
        subjectUserId: member.memberId,
        actorUserId: ownerId,
        scopeType: 'VEHICLE',
        channel: 'ONLINE',
        permissions: ['vehicle:read'],
      }),
    (err: unknown) => err instanceof VehicleServiceError,
  );
  const whileSuspended = await updateMembershipPermissions({
    ...target,
    actorUserId: ownerId,
    permissions: ['vehicle:read', 'device:read', 'invitation:create'],
  });
  assert.equal(whileSuspended.membership.status, 'SUSPENDED');

  // Reactivation restores base permissions only.
  const reactivated = await reactivateMembership({ ...target, actorUserId: ownerId });
  assert.equal(reactivated.status, 'ACTIVE');
  assert.equal(reactivated.suspendedAt, null);
  assert.deepEqual(reactivated.permissions, ['vehicle:read', 'device:read', 'invitation:create']);
  assert.equal((await AccessGrantModel.findById(grantId).lean())?.status, 'REVOKED');
  assert.equal((await InvitationModel.findById(issuedBeforeSuspend._id).lean())?.status, 'REVOKED');
  await rejectsWithCode(
    () => reactivateMembership({ ...target, actorUserId: ownerId }),
    'CONFLICT',
  );

  // Revocation cascades once; a repeated revocation returns the original record.
  assert.ok(
    await inviteMember(vehicle._id, member.memberId, new Types.ObjectId(), ['device:read']),
  );
  await createAccessGrant({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: member.memberId,
    actorUserId: ownerId,
    scopeType: 'VEHICLE',
    channel: 'ONLINE',
    permissions: ['vehicle:read'],
  });
  const revoked = await revokeMembership({ ...target, actorUserId: ownerId, reason: 'Moved away' });
  assert.equal(revoked.alreadyRevoked, false);
  assert.equal(revoked.revokedGrantsCount, 1);
  assert.equal(revoked.revokedInvitationsCount, 1);
  const revokedAgain = await revokeMembership({ ...target, actorUserId: ownerId, reason: 'Other' });
  assert.equal(revokedAgain.alreadyRevoked, true);
  assert.equal(revokedAgain.revokedGrantsCount, 0);
  assert.equal(revokedAgain.revokedInvitationsCount, 0);
  assert.equal(
    revokedAgain.membership.revokedAt?.getTime(),
    revoked.membership.revokedAt?.getTime(),
  );
  assert.equal(
    (await MembershipModel.findById(member.membershipId).lean())?.revokeReason,
    'Moved away',
  );
  for (const terminal of [
    () => reactivateMembership({ ...target, actorUserId: ownerId }),
    () => suspendMembership({ ...target, actorUserId: ownerId }),
    () => updateMembershipPermissions({ ...target, actorUserId: ownerId, permissions: [] }),
  ]) {
    await rejectsWithCode(terminal, 'CONFLICT');
  }

  // Voluntary leave: cascades, idempotent per membership, never touches a later membership.
  const leaver = await addAcceptedMember(vehicle._id, ownerId, [
    'vehicle:read',
    'invitation:create',
  ]);
  assert.ok(
    await inviteMember(vehicle._id, leaver.memberId, new Types.ObjectId(), ['vehicle:read']),
  );
  await createAccessGrant({
    vehicleId: vehicle._id,
    membershipId: leaver.membershipId,
    subjectUserId: leaver.memberId,
    actorUserId: ownerId,
    scopeType: 'VEHICLE',
    channel: 'ONLINE',
    permissions: ['vehicle:read'],
  });
  const left = await leaveVehicle({
    vehicleId: vehicle._id,
    actorUserId: leaver.memberId,
    membershipId: leaver.membershipId,
  });
  assert.equal(left.alreadyRevoked, false);
  assert.equal(left.membership.status, 'REVOKED');
  assert.equal(left.membership.revokeReason, MEMBER_LEFT_REASON);
  assert.equal(left.membership.revokedByUserId?.equals(leaver.memberId), true);
  assert.equal(left.revokedGrantsCount, 1);
  assert.equal(left.revokedInvitationsCount, 1);
  const leftAgain = await leaveVehicle({
    vehicleId: vehicle._id,
    actorUserId: leaver.memberId,
    membershipId: leaver.membershipId,
  });
  assert.equal(leftAgain.alreadyRevoked, true);
  assert.equal(leftAgain.membership.revokedAt?.getTime(), left.membership.revokedAt?.getTime());
  const comeback = await inviteMember(vehicle._id, ownerId, leaver.memberId, ['vehicle:read']);
  assert.ok(comeback);
  const newMembership = await acceptInvitation(comeback._id, leaver.memberId);
  assert.ok(newMembership);
  const replayedLeave = await leaveVehicle({
    vehicleId: vehicle._id,
    actorUserId: leaver.memberId,
    membershipId: leaver.membershipId,
  });
  assert.equal(replayedLeave.alreadyRevoked, true);
  assert.equal(replayedLeave.membership._id.equals(leaver.membershipId), true);
  assert.equal((await MembershipModel.findById(newMembership._id).lean())?.status, 'ACTIVE');
  await rejectsWithCode(
    () =>
      leaveVehicle({
        vehicleId: vehicle._id,
        actorUserId: outsider,
        membershipId: newMembership._id,
      }),
    'NOT_FOUND',
  );
  await rejectsWithCode(
    () =>
      leaveVehicle({
        vehicleId: otherVehicle._id,
        actorUserId: leaver.memberId,
        membershipId: newMembership._id,
      }),
    'NOT_FOUND',
  );
  await suspendMembership({
    vehicleId: vehicle._id,
    membershipId: newMembership._id,
    actorUserId: ownerId,
  });
  const leftWhileSuspended = await leaveVehicle({
    vehicleId: vehicle._id,
    actorUserId: leaver.memberId,
    membershipId: newMembership._id,
  });
  assert.equal(leftWhileSuspended.membership._id.equals(newMembership._id), true);
  assert.equal(leftWhileSuspended.membership.status, 'REVOKED');

  // Invitation revocation scope: delegates revoke only their own; readers are FORBIDDEN.
  const delegate = await addAcceptedMember(vehicle._id, ownerId, [
    'vehicle:read',
    'invitation:create',
  ]);
  const reader = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read']);
  const delegateOwn = await inviteMember(vehicle._id, delegate.memberId, new Types.ObjectId(), [
    'vehicle:read',
  ]);
  const ownerOwn = await inviteMember(vehicle._id, ownerId, new Types.ObjectId(), ['vehicle:read']);
  assert.ok(delegateOwn && ownerOwn);
  await rejectsWithCode(
    () =>
      revokeInvitation({
        vehicleId: vehicle._id,
        invitationId: ownerOwn._id,
        actorUserId: delegate.memberId,
      }),
    'NOT_FOUND',
  );
  await rejectsWithCode(
    () =>
      revokeInvitation({
        vehicleId: vehicle._id,
        invitationId: delegateOwn._id,
        actorUserId: reader.memberId,
      }),
    'FORBIDDEN',
  );
  await rejectsWithCode(
    () =>
      revokeInvitation({
        vehicleId: otherVehicle._id,
        invitationId: delegateOwn._id,
        actorUserId: ownerId,
      }),
    'NOT_FOUND',
  );
  const firstRevoke = await revokeInvitation({
    vehicleId: vehicle._id,
    invitationId: delegateOwn._id,
    actorUserId: delegate.memberId,
    reason: 'Typo',
  });
  assert.equal(firstRevoke.alreadyRevoked, false);
  const secondRevoke = await revokeInvitation({
    vehicleId: vehicle._id,
    invitationId: delegateOwn._id,
    actorUserId: ownerId,
    reason: 'Other',
  });
  assert.equal(secondRevoke.alreadyRevoked, true);
  assert.equal(secondRevoke.invitation.revokeReason, 'Typo');
  assert.equal(
    secondRevoke.invitation.revokedAt?.getTime(),
    firstRevoke.invitation.revokedAt?.getTime(),
  );
});

test('23. TKT-012 keyset lists: bound cursors, effective EXPIRED without writes, defaults, limits, and per-page reauthorization', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Paging Van' });
  const otherVehicle = await createVehicle(ownerId, { name: 'Other Van' });
  const delegate = await addAcceptedMember(vehicle._id, ownerId, [
    'vehicle:read',
    'invitation:create',
  ]);
  const reader = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read']);
  const invitees = Array.from({ length: 5 }, () => new Types.ObjectId());
  for (const invitee of invitees.slice(0, 3)) {
    assert.ok(await inviteMember(vehicle._id, ownerId, invitee, ['vehicle:read']));
  }
  const delegateIssued = await inviteMember(vehicle._id, delegate.memberId, invitees[3]!, [
    'vehicle:read',
  ]);
  const delegateIssued2 = await inviteMember(vehicle._id, delegate.memberId, invitees[4]!, [
    'vehicle:read',
  ]);
  assert.ok(delegateIssued && delegateIssued2);
  await InvitationModel.collection.updateMany(
    { vehicleId: vehicle._id, status: 'PENDING' },
    { $set: { createdAt: new Date('2026-03-01T00:00:00.000Z') } },
  );
  const elapsedId = await insertRawPendingInvitation(
    vehicle._id,
    ownerId,
    new Date(Date.now() - 1_000),
  );

  const snapshot = await vehiclePersistenceSnapshot(vehicle._id);
  const seen: Array<{ id: string; createdAt: number; status: string }> = [];
  let cursor: string | undefined;
  do {
    const page = await listVehicleInvitations(vehicle._id, ownerId, { limit: 2, cursor });
    assert.ok(page.items.length <= 2);
    for (const item of page.items) {
      seen.push({
        id: String(item.invitation._id),
        createdAt: item.invitation.createdAt.getTime(),
        status: item.status,
      });
    }
    cursor = page.nextCursor ?? undefined;
  } while (cursor);
  assert.equal(seen.length, 8);
  assert.equal(new Set(seen.map((row) => row.id)).size, 8);
  const sorted = [...seen].sort((a, b) => a.createdAt - b.createdAt || a.id.localeCompare(b.id));
  assert.deepEqual(seen, sorted);
  assert.equal(seen.find((row) => row.id === String(elapsedId))?.status, 'EXPIRED');
  assert.equal(await vehiclePersistenceSnapshot(vehicle._id), snapshot, 'lists never write');

  const countWith = async (status: 'PENDING' | 'EXPIRED' | 'ACCEPTED') =>
    (await listVehicleInvitations(vehicle._id, ownerId, { status, limit: 100 })).items.length;
  assert.equal(await countWith('PENDING'), 5);
  assert.equal(await countWith('EXPIRED'), 1);
  assert.equal(await countWith('ACCEPTED'), 2);
  assert.deepEqual(
    (await listVehicleInvitations(vehicle._id, delegate.memberId)).items
      .map((item) => String(item.invitation._id))
      .sort(),
    [String(delegateIssued._id), String(delegateIssued2._id)].sort(),
  );
  await rejectsWithCode(() => listVehicleInvitations(vehicle._id, reader.memberId), 'FORBIDDEN');
  await rejectsWithCode(
    () => listVehicleInvitations(vehicle._id, new Types.ObjectId()),
    'NOT_FOUND',
  );
  assert.equal((await listVehicleInvitations(otherVehicle._id, ownerId)).items.length, 0);

  for (const limit of [0, 101, 1.5]) {
    await rejectsWithCode(
      () => listVehicleInvitations(vehicle._id, ownerId, { limit }),
      'VALIDATION_ERROR',
    );
  }
  assert.equal(
    (await listVehicleInvitations(vehicle._id, ownerId, { limit: 100 })).nextCursor,
    null,
  );

  // Cursors are bound to actor, resource, list type, and filters; tampering is rejected.
  const first = await listVehicleInvitations(vehicle._id, ownerId, { limit: 1 });
  const boundCursor = first.nextCursor;
  assert.ok(boundCursor);
  const payload = JSON.parse(Buffer.from(boundCursor, 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
  const reencode = (changes: Record<string, unknown>) =>
    Buffer.from(JSON.stringify({ ...payload, ...changes }), 'utf8').toString('base64url');
  const invalidCursors: Array<() => Promise<unknown>> = [
    () => listVehicleInvitations(vehicle._id, delegate.memberId, { cursor: boundCursor }),
    () => listVehicleInvitations(vehicle._id, ownerId, { cursor: boundCursor, status: 'PENDING' }),
    () => listVehicleInvitations(otherVehicle._id, ownerId, { cursor: boundCursor }),
    () => listVehicleMembers(vehicle._id, ownerId, { cursor: boundCursor }),
    () => listReceivedInvitations(ownerId, { cursor: boundCursor }),
    () => listVehicleInvitations(vehicle._id, ownerId, { cursor: reencode({ v: 2 }) }),
    () => listVehicleInvitations(vehicle._id, ownerId, { cursor: reencode({ b: 'x'.repeat(22) }) }),
    () => listVehicleInvitations(vehicle._id, ownerId, { cursor: reencode({ k: 'members' }) }),
    () => listVehicleInvitations(vehicle._id, ownerId, { cursor: reencode({ i: 'zz' }) }),
    () => listVehicleInvitations(vehicle._id, ownerId, { cursor: reencode({ c: 'yesterday' }) }),
    () => listVehicleInvitations(vehicle._id, ownerId, { cursor: 'not-a-cursor' }),
    () => listVehicleInvitations(vehicle._id, ownerId, { cursor: 'a'.repeat(2_000) }),
  ];
  for (const attempt of invalidCursors) {
    await rejectsWithCode(attempt, 'VALIDATION_ERROR');
  }

  // Each page re-authorizes: a delegate who loses invite authority cannot continue paging.
  const delegatePage = await listVehicleInvitations(vehicle._id, delegate.memberId, { limit: 1 });
  assert.ok(delegatePage.nextCursor);
  await updateMembershipPermissions({
    vehicleId: vehicle._id,
    membershipId: delegate.membershipId,
    actorUserId: ownerId,
    permissions: ['vehicle:read'],
  });
  await rejectsWithCode(
    () =>
      listVehicleInvitations(vehicle._id, delegate.memberId, {
        limit: 1,
        cursor: delegatePage.nextCursor ?? undefined,
      }),
    'FORBIDDEN',
  );

  // Received invitations: only the caller's, valid PENDING by default.
  const received = await listReceivedInvitations(invitees[0]!);
  assert.equal(received.items.length, 1);
  assert.equal(received.items[0]?.vehicleName, 'Paging Van');
  assert.equal(received.items[0]?.status, 'PENDING');
  assert.equal((await listReceivedInvitations(delegate.memberId)).items.length, 0);
  assert.equal(
    (await listReceivedInvitations(delegate.memberId, { status: 'ACCEPTED' })).items.length,
    1,
  );
  const revokedForInvitee = await listReceivedInvitations(invitees[3]!, { status: 'REVOKED' });
  assert.equal(revokedForInvitee.items.length, 1);

  // Members: owner-only, ACTIVE + SUSPENDED by default, REVOKED on request.
  await suspendMembership({
    vehicleId: vehicle._id,
    membershipId: reader.membershipId,
    actorUserId: ownerId,
  });
  const memberIds: string[] = [];
  let memberCursor: string | undefined;
  do {
    const page = await listVehicleMembers(vehicle._id, ownerId, { limit: 1, cursor: memberCursor });
    memberIds.push(...page.items.map((item) => `${String(item.userId)}:${item.status}`));
    memberCursor = page.nextCursor ?? undefined;
  } while (memberCursor);
  assert.deepEqual(memberIds, [
    `${String(ownerId)}:ACTIVE`,
    `${String(delegate.memberId)}:ACTIVE`,
    `${String(reader.memberId)}:SUSPENDED`,
  ]);
  await revokeMembership({
    vehicleId: vehicle._id,
    membershipId: reader.membershipId,
    actorUserId: ownerId,
  });
  assert.equal((await listVehicleMembers(vehicle._id, ownerId)).items.length, 2);
  assert.equal(
    (await listVehicleMembers(vehicle._id, ownerId, { status: 'REVOKED' })).items.length,
    1,
  );
  await rejectsWithCode(() => listVehicleMembers(vehicle._id, delegate.memberId), 'FORBIDDEN');
});

test('24. TKT-012 races: acceptance vs issuer changes, revocation and archive; grants vs suspension/revocation; leave vs admin', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Race Track Hatch' });

  // Acceptance blocked behind an in-flight issuer change re-validates and revokes durably.
  const issuerChanges: Array<[string, Record<string, unknown>]> = [
    ['suspension', { status: 'SUSPENDED', suspendedAt: new Date(), suspendedByUserId: ownerId }],
    [
      'revocation',
      {
        status: 'REVOKED',
        revokedAt: new Date(),
        revokedByUserId: ownerId,
        revokeReason: 'race',
      },
    ],
    ['permission reduction', { permissions: ['vehicle:read'] }],
  ];
  for (const [label, update] of issuerChanges) {
    const delegate = await addAcceptedMember(vehicle._id, ownerId, [
      'vehicle:read',
      'invitation:create',
    ]);
    const invitee = new Types.ObjectId();
    const invitation = await inviteMember(vehicle._id, delegate.memberId, invitee, [
      'vehicle:read',
    ]);
    assert.ok(invitation);
    const barrier = await holdMembershipChange(vehicle._id, delegate.membershipId, update);
    const accept = acceptInvitation(invitation._id, invitee);
    accept.catch(() => undefined);
    assert.equal(await stillPendingAfter(accept, 400), true, `${label}: accept waits`);
    await barrier.commit();
    await rejectsWithCode(() => accept, 'CONFLICT');
    const after = await InvitationModel.findById(invitation._id).lean();
    assert.equal(after?.status, 'REVOKED', label);
    assert.equal(after?.revokeReason, INVITATION_ISSUER_AUTHORITY_LOST_REASON, label);
    assert.equal(
      await MembershipModel.countDocuments({ vehicleId: vehicle._id, userId: invitee }),
      0,
      label,
    );
  }

  // Acceptance vs invitation revocation: exactly one wins, state is consistent.
  for (let round = 0; round < 3; round += 1) {
    const invitee = new Types.ObjectId();
    const invitation = await inviteMember(vehicle._id, ownerId, invitee, ['vehicle:read']);
    assert.ok(invitation);
    const [accepted, revoked] = await Promise.allSettled([
      acceptInvitation(invitation._id, invitee),
      revokeInvitation({
        vehicleId: vehicle._id,
        invitationId: invitation._id,
        actorUserId: ownerId,
      }),
    ]);
    const final = await InvitationModel.findById(invitation._id).lean();
    const memberships = await MembershipModel.countDocuments({
      vehicleId: vehicle._id,
      userId: invitee,
    });
    if (final?.status === 'ACCEPTED') {
      assert.ok(accepted.status === 'fulfilled' && accepted.value);
      assert.equal(revoked.status, 'rejected');
      assert.equal(memberships, 1);
    } else {
      assert.equal(final?.status, 'REVOKED');
      assert.equal(revoked.status, 'fulfilled');
      assert.equal(accepted.status, 'rejected');
      assert.equal(memberships, 0);
    }
  }

  // Acceptance vs archive: never a membership created on an archived vehicle after the archive.
  const archiveTarget = await createVehicle(ownerId, { name: 'Race Archive Sedan' });
  const archiveInvitee = new Types.ObjectId();
  const archiveInvitation = await inviteMember(archiveTarget._id, ownerId, archiveInvitee, [
    'vehicle:read',
  ]);
  assert.ok(archiveInvitation);
  const [acceptVsArchive, archived] = await Promise.allSettled([
    acceptInvitation(archiveInvitation._id, archiveInvitee),
    archiveVehicle({ vehicleId: archiveTarget._id, actorUserId: ownerId }),
  ]);
  assert.equal(archived.status, 'fulfilled');
  const archivedInvitation = await InvitationModel.findById(archiveInvitation._id).lean();
  const archivedMemberships = await MembershipModel.countDocuments({
    vehicleId: archiveTarget._id,
    userId: archiveInvitee,
  });
  if (archivedInvitation?.status === 'ACCEPTED') {
    assert.equal(archivedMemberships, 1);
  } else {
    assert.equal(archivedInvitation?.status, 'REVOKED');
    assert.equal(archivedMemberships, 0);
    assert.ok(
      acceptVsArchive.status === 'rejected' ||
        (acceptVsArchive.status === 'fulfilled' && acceptVsArchive.value === null),
    );
  }

  // Permission change vs membership revocation.
  const contested = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read']);
  const [permissionChange, revocation] = await Promise.allSettled([
    updateMembershipPermissions({
      vehicleId: vehicle._id,
      membershipId: contested.membershipId,
      actorUserId: ownerId,
      permissions: ['device:read'],
    }),
    revokeMembership({
      vehicleId: vehicle._id,
      membershipId: contested.membershipId,
      actorUserId: ownerId,
    }),
  ]);
  assert.equal(revocation.status, 'fulfilled');
  if (permissionChange.status === 'rejected') {
    assert.ok(permissionChange.reason instanceof VehicleServiceError);
    assert.equal(permissionChange.reason.code, 'CONFLICT');
  }
  assert.equal((await MembershipModel.findById(contested.membershipId).lean())?.status, 'REVOKED');

  // AccessGrant creation vs suspension / revocation: no ACTIVE grant survives on the membership.
  for (const operation of ['suspend', 'revoke'] as const) {
    const subject = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read']);
    const frame = {
      vehicleId: vehicle._id,
      membershipId: subject.membershipId,
      actorUserId: ownerId,
    };
    const [transition] = await Promise.allSettled([
      operation === 'suspend' ? suspendMembership(frame) : revokeMembership(frame),
      createAccessGrant({
        vehicleId: vehicle._id,
        membershipId: subject.membershipId,
        subjectUserId: subject.memberId,
        actorUserId: ownerId,
        scopeType: 'VEHICLE',
        channel: 'ONLINE',
        permissions: ['vehicle:read'],
      }),
    ]);
    assert.equal(transition.status, 'fulfilled', operation);
    assert.equal(
      await AccessGrantModel.countDocuments({
        membershipId: subject.membershipId,
        status: 'ACTIVE',
      }),
      0,
      operation,
    );
  }
  const barrierSubject = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read']);
  const suspensionInFlight = await holdMembershipChange(vehicle._id, barrierSubject.membershipId, {
    status: 'SUSPENDED',
    suspendedAt: new Date(),
    suspendedByUserId: ownerId,
  });
  const blockedGrant = createAccessGrant({
    vehicleId: vehicle._id,
    membershipId: barrierSubject.membershipId,
    subjectUserId: barrierSubject.memberId,
    actorUserId: ownerId,
    scopeType: 'VEHICLE',
    channel: 'ONLINE',
    permissions: ['vehicle:read'],
  });
  blockedGrant.catch(() => undefined);
  assert.equal(await stillPendingAfter(blockedGrant, 400), true, 'grant waits on the barrier');
  await suspensionInFlight.commit();
  await assert.rejects(
    () => blockedGrant,
    (err: unknown) => err instanceof VehicleServiceError,
  );
  assert.equal(
    await AccessGrantModel.countDocuments({ membershipId: barrierSubject.membershipId }),
    0,
  );

  // Leave vs administrative operations: the membership ends REVOKED exactly once.
  const leaving = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read']);
  const leaveFrame = {
    vehicleId: vehicle._id,
    membershipId: leaving.membershipId,
    actorUserId: ownerId,
  };
  const [leaveResult, suspendResult, updateResult] = await Promise.allSettled([
    leaveVehicle({
      vehicleId: vehicle._id,
      actorUserId: leaving.memberId,
      membershipId: leaving.membershipId,
    }),
    suspendMembership(leaveFrame),
    updateMembershipPermissions({ ...leaveFrame, permissions: ['device:read'] }),
  ]);
  assert.equal(leaveResult.status, 'fulfilled');
  for (const result of [suspendResult, updateResult]) {
    if (result.status === 'rejected') {
      assert.ok(result.reason instanceof VehicleServiceError);
      assert.equal(result.reason.code, 'CONFLICT');
    }
  }
  const leftRecord = await MembershipModel.findById(leaving.membershipId).lean();
  assert.equal(leftRecord?.status, 'REVOKED');
  assert.equal(leftRecord?.revokeReason, MEMBER_LEFT_REASON);

  const doubleExit = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read']);
  const [selfExit, ownerExit] = await Promise.allSettled([
    leaveVehicle({
      vehicleId: vehicle._id,
      actorUserId: doubleExit.memberId,
      membershipId: doubleExit.membershipId,
    }),
    revokeMembership({
      vehicleId: vehicle._id,
      membershipId: doubleExit.membershipId,
      actorUserId: ownerId,
      reason: 'Owner removal',
    }),
  ]);
  assert.ok(selfExit.status === 'fulfilled' && ownerExit.status === 'fulfilled');
  assert.equal(
    [selfExit.value.alreadyRevoked, ownerExit.value.alreadyRevoked].filter(Boolean).length,
    1,
  );
  const exitRecord = await MembershipModel.findById(doubleExit.membershipId).lean();
  assert.equal(
    exitRecord?.revokeReason,
    selfExit.value.alreadyRevoked ? 'Owner removal' : MEMBER_LEFT_REASON,
  );
});

test('25. TKT-012 unauthorized membership and invitation operations leave no persistent trace', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Untouched Roadster' });
  const reader = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read']);
  const member = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read', 'device:read']);
  const pending = await inviteMember(vehicle._id, ownerId, new Types.ObjectId(), ['vehicle:read']);
  assert.ok(pending);
  await insertRawPendingInvitation(vehicle._id, ownerId, new Date(Date.now() - 1_000));
  const outsider = new Types.ObjectId();
  const snapshot = await vehiclePersistenceSnapshot(vehicle._id);
  const frame = { vehicleId: vehicle._id, membershipId: member.membershipId };
  for (const actor of [reader.memberId, outsider]) {
    const attempts: Array<() => Promise<unknown>> = [
      () => suspendMembership({ ...frame, actorUserId: actor }),
      () => reactivateMembership({ ...frame, actorUserId: actor }),
      () => revokeMembership({ ...frame, actorUserId: actor }),
      () => updateMembershipPermissions({ ...frame, actorUserId: actor, permissions: [] }),
      () =>
        revokeInvitation({ vehicleId: vehicle._id, invitationId: pending._id, actorUserId: actor }),
      () => listVehicleMembers(vehicle._id, actor),
      () => listVehicleInvitations(vehicle._id, actor),
      () => inviteMember(vehicle._id, actor, new Types.ObjectId(), ['vehicle:read']),
    ];
    for (const attempt of attempts) {
      await attempt().catch((error: unknown) => {
        assert.ok(error instanceof VehicleServiceError);
        assert.ok(['FORBIDDEN', 'NOT_FOUND'].includes(error.code), error.code);
      });
    }
  }
  assert.equal(await acceptInvitation(pending._id, outsider), null);
  await rejectsWithCode(
    () =>
      leaveVehicle({
        vehicleId: vehicle._id,
        actorUserId: outsider,
        membershipId: member.membershipId,
      }),
    'NOT_FOUND',
  );
  assert.equal(await vehiclePersistenceSnapshot(vehicle._id), snapshot);
});

test('26. TKT-012 voluntary leave binds to the explicit membership and a replay never reaches a later one', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Explicit Leave Hatch' });
  const otherVehicle = await createVehicle(ownerId, { name: 'Explicit Leave Wagon' });
  const leaver = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read']);
  const bystander = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read']);
  const elsewhereInvite = await inviteMember(otherVehicle._id, ownerId, leaver.memberId, [
    'vehicle:read',
  ]);
  assert.ok(elsewhereInvite);
  const leaverElsewhere = await acceptInvitation(elsewhereInvite._id, leaver.memberId);
  assert.ok(leaverElsewhere);

  // Foreign, cross-vehicle and unknown memberships: NOT_FOUND without any write.
  const before = await vehiclePersistenceSnapshot(vehicle._id);
  const beforeOther = await vehiclePersistenceSnapshot(otherVehicle._id);
  for (const attempt of [
    { vehicleId: vehicle._id, membershipId: bystander.membershipId },
    { vehicleId: vehicle._id, membershipId: leaverElsewhere._id },
    { vehicleId: otherVehicle._id, membershipId: leaver.membershipId },
    { vehicleId: vehicle._id, membershipId: new Types.ObjectId() },
  ]) {
    await rejectsWithCode(
      () => leaveVehicle({ ...attempt, actorUserId: leaver.memberId }),
      'NOT_FOUND',
    );
  }
  assert.equal(await vehiclePersistenceSnapshot(vehicle._id), before);
  assert.equal(await vehiclePersistenceSnapshot(otherVehicle._id), beforeOther);

  // 1. Leave.
  const events: VehicleAuditEvent[] = [];
  const leaveRequest = {
    vehicleId: vehicle._id,
    actorUserId: leaver.memberId,
    membershipId: leaver.membershipId,
    audit: (event: VehicleAuditEvent) => events.push(event),
  };
  const left = await leaveVehicle(leaveRequest);
  assert.equal(left.alreadyRevoked, false);
  const revokedRecord = await MembershipModel.findById(leaver.membershipId).lean();
  assert.equal(revokedRecord?.status, 'REVOKED');
  assert.equal(revokedRecord?.revokeReason, MEMBER_LEFT_REASON);
  assert.equal(revokedRecord?.revokedByUserId?.equals(leaver.memberId), true);
  assert.equal(revokedRecord?.updatedByUserId?.equals(leaver.memberId), true);
  assert.deepEqual(
    events.map((event) => `${event.action}:${event.outcome}`),
    ['membership.leave:success'],
  );

  // 2. Idempotent repeat: same record, no cascades, no new audit event.
  const repeated = await leaveVehicle(leaveRequest);
  assert.equal(repeated.alreadyRevoked, true);
  assert.equal(repeated.revokedGrantsCount, 0);
  assert.equal(repeated.revokedInvitationsCount, 0);
  assert.deepEqual(await MembershipModel.findById(leaver.membershipId).lean(), revokedRecord);
  assert.equal(events.length, 1);

  // 3. New OWNER invitation; 4. its acceptance creates another membership.
  const rejoinInvite = await inviteMember(vehicle._id, ownerId, leaver.memberId, [
    'vehicle:read',
    'device:read',
  ]);
  assert.ok(rejoinInvite);
  const rejoined = await acceptInvitation(rejoinInvite._id, leaver.memberId);
  assert.ok(rejoined);
  assert.equal(rejoined._id.equals(leaver.membershipId), false);
  await createAccessGrant({
    vehicleId: vehicle._id,
    membershipId: rejoined._id,
    subjectUserId: leaver.memberId,
    actorUserId: ownerId,
    scopeType: 'VEHICLE',
    channel: 'ONLINE',
    permissions: ['vehicle:read'],
  });
  const rejoinedBefore = await MembershipModel.findById(rejoined._id).lean();
  const grantsBefore = await AccessGrantModel.find({ membershipId: rejoined._id }).lean();

  // 5. Replay of the original leave request.
  const replayed = await leaveVehicle(leaveRequest);
  assert.equal(replayed.alreadyRevoked, true);
  assert.equal(replayed.membership._id.equals(leaver.membershipId), true);
  assert.equal(replayed.revokedGrantsCount, 0);
  assert.equal(replayed.revokedInvitationsCount, 0);

  // 6. The new membership stays ACTIVE with its permissions, grants and audit untouched.
  const rejoinedAfter = await MembershipModel.findById(rejoined._id).lean();
  assert.deepEqual(rejoinedAfter, rejoinedBefore);
  assert.equal(rejoinedAfter?.status, 'ACTIVE');
  assert.deepEqual(rejoinedAfter?.permissions, ['vehicle:read', 'device:read']);
  assert.deepEqual(
    await AccessGrantModel.find({ membershipId: rejoined._id }).lean(),
    grantsBefore,
  );
  assert.deepEqual(await MembershipModel.findById(leaver.membershipId).lean(), revokedRecord);
  assert.ok(await getVehicleForUser(vehicle._id, leaver.memberId));
  assert.equal(events.length, 1);
});

test('27. TKT-012 historical invitations fail closed on ambiguous or foreign issuer bindings and stay revocable', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Legacy Coupe' });
  const otherVehicle = await createVehicle(ownerId, { name: 'Legacy Van' });
  const delegatePermissions = ['vehicle:read', 'invitation:create'];
  const delegate = await addAcceptedMember(vehicle._id, ownerId, delegatePermissions);
  const peer = await addAcceptedMember(vehicle._id, ownerId, delegatePermissions);
  const elsewhereInvite = await inviteMember(
    otherVehicle._id,
    ownerId,
    delegate.memberId,
    delegatePermissions,
  );
  assert.ok(elsewhereInvite);
  const delegateElsewhere = await acceptInvitation(elsewhereInvite._id, delegate.memberId);
  assert.ok(delegateElsewhere);
  const ownerMembership = await MembershipModel.findOne({
    vehicleId: vehicle._id,
    role: 'OWNER',
  }).lean();
  assert.ok(ownerMembership);

  const expectDurablyRevoked = async (invitationId: Types.ObjectId, invitee: Types.ObjectId) => {
    await rejectsWithCode(() => acceptInvitation(invitationId, invitee), 'CONFLICT');
    const record = await InvitationModel.findById(invitationId).lean();
    assert.equal(record?.status, 'REVOKED');
    assert.equal(record?.revokeReason, INVITATION_ISSUER_AUTHORITY_LOST_REASON);
    await rejectsWithCode(() => acceptInvitation(invitationId, invitee), 'CONFLICT');
    assert.deepEqual(await InvitationModel.findById(invitationId).lean(), record);
    assert.equal(
      await MembershipModel.countDocuments({ vehicleId: vehicle._id, userId: invitee }),
      0,
    );
  };

  // Bindings that do not belong to the inviter, the vehicle, or the canonical OWNER.
  const foreignBindings = [
    { inviterUserId: delegate.memberId, issuerMembershipId: peer.membershipId },
    { inviterUserId: delegate.memberId, issuerMembershipId: delegateElsewhere._id },
    { inviterUserId: delegate.memberId, issuerMembershipId: new Types.ObjectId() },
    { inviterUserId: ownerId, issuerMembershipId: delegate.membershipId },
    { inviterUserId: delegate.memberId },
  ];
  for (const binding of foreignBindings) {
    const invitee = new Types.ObjectId();
    const invitationId = await insertBoundInvitation({
      vehicleId: vehicle._id,
      inviteeUserId: invitee,
      ...binding,
    });
    await expectDurablyRevoked(invitationId, invitee);
  }

  // Legitimate OWNER invitations, unbound legacy or bound to the OWNER membership, stay valid.
  for (const issuerMembershipId of [undefined, ownerMembership._id]) {
    const invitee = new Types.ObjectId();
    const invitationId = await insertBoundInvitation({
      vehicleId: vehicle._id,
      inviterUserId: ownerId,
      inviteeUserId: invitee,
      ...(issuerMembershipId ? { issuerMembershipId } : {}),
    });
    assert.ok(await acceptInvitation(invitationId, invitee));
  }

  // An invalid legacy invitation lists as PENDING until processed, the OWNER revokes it without
  // granting access, and a new valid invitation for the same invitee can then be issued.
  const legacyInvitee = new Types.ObjectId();
  const legacyId = await insertBoundInvitation({
    vehicleId: vehicle._id,
    inviterUserId: delegate.memberId,
    inviteeUserId: legacyInvitee,
  });
  const pendingIds = (
    await listVehicleInvitations(vehicle._id, ownerId, { status: 'PENDING', limit: 100 })
  ).items.map((item) => String(item.invitation._id));
  assert.ok(pendingIds.includes(String(legacyId)));
  await rejectsWithCode(
    () => inviteMember(vehicle._id, ownerId, legacyInvitee, ['vehicle:read']),
    'CONFLICT',
  );
  const revoked = await revokeInvitation({
    vehicleId: vehicle._id,
    invitationId: legacyId,
    actorUserId: ownerId,
  });
  assert.equal(revoked.alreadyRevoked, false);
  assert.equal(revoked.invitation.status, 'REVOKED');
  assert.equal(revoked.invitation.revokedByUserId?.equals(ownerId), true);
  const afterRevoke = await acceptInvitation(legacyId, legacyInvitee).catch(
    (error: unknown) => error,
  );
  assert.ok(
    afterRevoke === null ||
      (afterRevoke instanceof VehicleServiceError && afterRevoke.code === 'CONFLICT'),
  );
  assert.equal(
    await MembershipModel.countDocuments({ vehicleId: vehicle._id, userId: legacyInvitee }),
    0,
  );
  const reissued = await inviteMember(vehicle._id, ownerId, legacyInvitee, ['vehicle:read']);
  assert.ok(reissued);
  assert.equal(reissued.issuerMembershipId?.equals(ownerMembership._id), true);
  assert.ok(await acceptInvitation(reissued._id, legacyInvitee));
});

test('28. TKT-012 permission updates audit actor and date without touching identity, history, or AccessGrants', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Audit Saloon' });
  const member = await addAcceptedMember(vehicle._id, ownerId, [
    'vehicle:read',
    'device:read',
    'invitation:create',
  ]);
  const reader = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read']);
  const grantFrame = {
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: member.memberId,
    actorUserId: ownerId,
    scopeType: 'VEHICLE' as const,
    channel: 'ONLINE' as const,
  };
  await createAccessGrant({ ...grantFrame, permissions: ['vehicle:read'] });
  const revokedGrant = await createAccessGrant({ ...grantFrame, permissions: ['device:link'] });
  await revokeAccessGrant({
    vehicleId: vehicle._id,
    grantId: revokedGrant._id,
    actorUserId: ownerId,
    reason: 'Temporary access ended',
  });
  const delegated = await inviteMember(vehicle._id, member.memberId, new Types.ObjectId(), [
    'device:read',
  ]);
  assert.ok(delegated);
  const grantsOf = () =>
    AccessGrantModel.find({ membershipId: member.membershipId }).sort({ _id: 1 }).lean();
  const grantsBefore = await grantsOf();
  const original = await MembershipModel.findById(member.membershipId).lean();
  assert.ok(original);
  const events: VehicleAuditEvent[] = [];
  const audit = (event: VehicleAuditEvent) => events.push(event);
  const frame = { vehicleId: vehicle._id, membershipId: member.membershipId, audit };

  // Unauthorized callers change nothing and leave no success audit.
  const snapshot = await vehiclePersistenceSnapshot(vehicle._id);
  for (const actor of [reader.memberId, member.memberId, new Types.ObjectId()]) {
    await updateMembershipPermissions({
      ...frame,
      actorUserId: actor,
      permissions: ['vehicle:read'],
    }).catch((error: unknown) => {
      assert.ok(error instanceof VehicleServiceError);
      assert.ok(['FORBIDDEN', 'NOT_FOUND'].includes(error.code), error.code);
    });
  }
  assert.equal(await vehiclePersistenceSnapshot(vehicle._id), snapshot);
  assert.equal(
    events.some((event) => event.outcome === 'success'),
    false,
  );

  // Effective change: actor and date recorded, creation audit and identity preserved.
  await new Promise((resolve) => setTimeout(resolve, 5));
  const changed = await updateMembershipPermissions({
    ...frame,
    actorUserId: ownerId,
    permissions: ['vehicle:read', 'invitation:create'],
  });
  assert.equal(changed.changed, true);
  assert.equal(changed.revokedInvitationsCount, 1);
  const updated = await MembershipModel.findById(member.membershipId).lean();
  assert.ok(updated);
  assert.deepEqual(updated.permissions, ['vehicle:read', 'invitation:create']);
  assert.equal(updated.updatedByUserId?.equals(ownerId), true);
  assert.ok(updated.updatedAt.getTime() > original.updatedAt.getTime());
  assert.equal(updated.createdAt.getTime(), original.createdAt.getTime());
  assert.equal(updated.grantedByUserId.equals(original.grantedByUserId), true);
  assert.equal(String(updated.sourceInvitationId), String(original.sourceInvitationId));
  assert.equal(updated.role, original.role);
  assert.equal(updated.userId.equals(original.userId), true);
  assert.equal(updated.vehicleId.equals(original.vehicleId), true);
  assert.equal(updated.status, 'ACTIVE');
  assert.equal(updated.revokedAt, null);
  assert.equal(updated.suspendedAt, null);
  assert.deepEqual(await grantsOf(), grantsBefore);
  const cascaded = await InvitationModel.findById(delegated._id).lean();
  assert.equal(cascaded?.status, 'REVOKED');
  assert.equal(cascaded?.revokeReason, INVITATION_ISSUER_AUTHORITY_LOST_REASON);
  assert.equal(cascaded?.revokedByUserId?.equals(ownerId), true);
  const successEvents = () =>
    events.filter((event) => event.action === 'membership.update' && event.outcome === 'success');
  assert.equal(successEvents().length, 1);
  assert.equal(successEvents()[0]?.actorUserId, String(ownerId));

  // Idempotent repeat (same set, any order): membership audit and grants stay untouched.
  const repeated = await updateMembershipPermissions({
    ...frame,
    actorUserId: ownerId,
    permissions: ['invitation:create', 'vehicle:read'],
  });
  assert.equal(repeated.changed, false);
  assert.deepEqual(await MembershipModel.findById(member.membershipId).lean(), updated);
  assert.deepEqual(await grantsOf(), grantsBefore);
  assert.equal(successEvents().length, 1);

  // Revocation cascade records its reason and actor on the grants it revokes.
  await revokeMembership({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    actorUserId: ownerId,
    reason: 'Sold the car',
  });
  const grantsAfterRevoke = await grantsOf();
  const cascadedGrant = grantsAfterRevoke.find((grant) => !grant._id.equals(revokedGrant._id));
  assert.equal(cascadedGrant?.status, 'REVOKED');
  assert.equal(cascadedGrant?.revokeReason, 'Sold the car');
  assert.equal(cascadedGrant?.revokedByUserId?.equals(ownerId), true);
  assert.deepEqual(
    grantsAfterRevoke.find((grant) => grant._id.equals(revokedGrant._id)),
    grantsBefore.find((grant) => grant._id.equals(revokedGrant._id)),
  );
  await rejectsWithCode(
    () =>
      updateMembershipPermissions({
        ...frame,
        actorUserId: ownerId,
        permissions: ['vehicle:read'],
      }),
    'CONFLICT',
  );
});

function vehicleContext(
  vehicleId: Types.ObjectId,
  actorUserId: Types.ObjectId,
  permission: AuthorizationContext['permission'],
  channel: AuthorizationContext['channel'] = 'ONLINE',
): AuthorizationContext {
  return { actorUserId, vehicleId, resource: { type: 'VEHICLE' }, channel, permission };
}

function externalContext(
  vehicleId: Types.ObjectId,
  actorUserId: Types.ObjectId,
  resource: AuthorizationContext['resource'],
  permission: AuthorizationContext['permission'],
  channel: AuthorizationContext['channel'] = 'ONLINE',
): AuthorizationContext {
  return { actorUserId, vehicleId, resource, channel, permission };
}

const atTime = (instant: Date) => ({ clock: () => instant });

test('29. TKT-013 user and vehicle isolation: per-vehicle authority, exact roles, and read semantics', async () => {
  await resetVehicleCollections();
  const ownerA = new Types.ObjectId();
  const ownerB = new Types.ObjectId();
  const vehicleA = await createVehicle(ownerA, { name: 'Isolation A' });
  const vehicleB = await createVehicle(ownerB, { name: 'Isolation B' });
  const evaluate = (context: AuthorizationContext) => resourceAuthorization.evaluate(context);

  // The owner of A has no authority on B, even for reserved permissions.
  const ownerOnA = await evaluate(vehicleContext(vehicleA._id, ownerA, 'vehicle:archive'));
  assert.equal(ownerOnA.allowed, true);
  assert.equal(ownerOnA.allowed && ownerOnA.source, 'OWNER_ROLE');
  const ownerOnB = await evaluate(vehicleContext(vehicleB._id, ownerA, 'vehicle:read'));
  assert.equal(ownerOnB.allowed, false);
  assert.equal(ownerOnB.reason, 'MEMBERSHIP_INACTIVE_OR_MISSING');
  assert.equal(await resourceAuthorization.isOwner(vehicleB._id, ownerA), false);
  assert.equal(await resourceAuthorization.isMember(vehicleB._id, ownerA), false);
  assert.equal(await resourceAuthorization.isMember(vehicleA._id, ownerA), true);
  assert.equal(await resourceAuthorization.hasRole(vehicleA._id, ownerA, 'MEMBER'), false);
  await rejectsWithCode(
    () =>
      resourceAuthorization.assertPermission(vehicleContext(vehicleB._id, ownerA, 'vehicle:read')),
    'NOT_FOUND',
  );

  // The same user holds different permissions on two vehicles; nothing leaks across them.
  const sharedUser = new Types.ObjectId();
  const invitationA = await inviteMember(vehicleA._id, ownerA, sharedUser, [
    'vehicle:read',
    'device:link',
  ]);
  const invitationB = await inviteMember(vehicleB._id, ownerB, sharedUser, [
    'vehicle:read',
    'vehicle:update',
  ]);
  assert.ok(invitationA && invitationB);
  assert.ok(await acceptInvitation(invitationA._id, sharedUser));
  assert.ok(await acceptInvitation(invitationB._id, sharedUser));
  assert.equal(
    (await evaluate(vehicleContext(vehicleA._id, sharedUser, 'device:link'))).allowed,
    true,
  );
  assert.equal(
    (await evaluate(vehicleContext(vehicleB._id, sharedUser, 'device:link'))).allowed,
    false,
  );
  assert.equal(
    (await evaluate(vehicleContext(vehicleA._id, sharedUser, 'vehicle:update'))).allowed,
    false,
  );
  const updateOnB = await evaluate(vehicleContext(vehicleB._id, sharedUser, 'vehicle:update'));
  assert.equal(updateOnB.allowed && updateOnB.source, 'MEMBERSHIP_PERMISSION');
  assert.equal(await canLinkDeviceToVehicle(vehicleA._id, sharedUser), true);
  assert.equal(await canLinkDeviceToVehicle(vehicleB._id, sharedUser), false);
  assert.equal(await resourceAuthorization.hasRole(vehicleB._id, sharedUser, 'MEMBER'), true);
  assert.equal(await resourceAuthorization.isOwner(vehicleB._id, sharedUser), false);
  // A generic ALLOW never replaces the operation policy: vehicle updates stay OWNER-only.
  await rejectsWithCode(
    () =>
      updateVehicle({ vehicleId: vehicleB._id, actorUserId: sharedUser, changes: { trim: 'X' } }),
    'FORBIDDEN',
  );
  // Reserved permissions stay OWNER-only for members.
  const reserved = await evaluate(vehicleContext(vehicleB._id, sharedUser, 'vehicle:archive'));
  assert.equal(reserved.reason, 'OWNER_PERMISSION_FORBIDDEN');

  // A member without vehicle:read is a member but cannot read the vehicle.
  const blind = await addAcceptedMember(vehicleA._id, ownerA, ['device:read']);
  assert.equal(await resourceAuthorization.isMember(vehicleA._id, blind.memberId), true);
  assert.equal(
    await resourceAuthorization.hasVehicleReadAccess(vehicleA._id, blind.memberId),
    false,
  );
  assert.equal(await canAccessVehicle(vehicleA._id, blind.memberId), false);
  assert.equal(await canAccessVehicle(vehicleA._id, blind.memberId, 'device:read'), false);
  await rejectsWithCode(() => getAccessibleVehicle(vehicleA._id, blind.memberId), 'NOT_FOUND');
  await rejectsWithCode(
    () =>
      resourceAuthorization.assertPermission(
        vehicleContext(vehicleA._id, blind.memberId, 'vehicle:update'),
      ),
    'NOT_FOUND',
  );
  // vehicle:manage keeps implying read without an explicit vehicle:read.
  const manager = await addAcceptedMember(vehicleA._id, ownerA, ['vehicle:manage']);
  assert.equal(await canAccessVehicle(vehicleA._id, manager.memberId), true);
  await rejectsWithCode(
    () =>
      resourceAuthorization.assertPermission(
        vehicleContext(vehicleA._id, manager.memberId, 'vehicle:update'),
      ),
    'FORBIDDEN',
  );
});

test('30. TKT-013 DEVICE/MODULE isolation with verified test evidence and hardened grant issuance', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Resource Hatch' });
  const otherVehicle = await createVehicle(new Types.ObjectId(), { name: 'Foreign Hatch' });
  const member = await addAcceptedMember(vehicle._id, ownerId, ['device:read', 'module:read']);
  const bare = await addAcceptedMember(vehicle._id, ownerId, []);
  const device1 = new Types.ObjectId();
  const device2 = new Types.ObjectId();
  const module1 = new Types.ObjectId();
  const device = (resourceId: Types.ObjectId, evidenceVehicle = vehicle._id) => ({
    type: 'DEVICE' as const,
    resourceId,
    binding: testOwnershipEvidence('DEVICE', resourceId, evidenceVehicle),
  });
  const moduleResource = (resourceId: Types.ObjectId) => ({
    type: 'MODULE' as const,
    resourceId,
    binding: testOwnershipEvidence('MODULE', resourceId, vehicle._id),
  });
  const evaluate = (context: AuthorizationContext) => resourceAuthorization.evaluate(context);

  // Base permissions apply ONLINE to compatible resources with verified evidence only.
  const baseDevice = await evaluate(
    externalContext(vehicle._id, member.memberId, device(device1), 'device:read'),
  );
  assert.equal(baseDevice.allowed && baseDevice.source, 'MEMBERSHIP_PERMISSION');
  const baseModule = await evaluate(
    externalContext(vehicle._id, member.memberId, moduleResource(module1), 'module:read'),
  );
  assert.equal(baseModule.allowed && baseModule.source, 'MEMBERSHIP_PERMISSION');
  const offline = await evaluate(
    externalContext(vehicle._id, member.memberId, device(device1), 'device:read', 'BLE_OFFLINE'),
  );
  assert.equal(offline.allowed, false);
  assert.equal(offline.reason, 'PERMISSION_NOT_GRANTED');
  // Base device:read no longer authorizes the VEHICLE resource (documented incompatibility).
  const onVehicle = await evaluate(vehicleContext(vehicle._id, member.memberId, 'device:read'));
  assert.equal(onVehicle.reason, 'PERMISSION_RESOURCE_MISMATCH');

  // Missing, wrong-type, wrong-resource, and foreign-vehicle evidence all fail closed.
  const unverified = [
    { type: 'DEVICE' as const, resourceId: device1 },
    { type: 'DEVICE' as const, resourceId: device1, binding: moduleResource(device1).binding },
    { type: 'DEVICE' as const, resourceId: device2, binding: device(device1).binding },
    device(device1, otherVehicle._id),
  ];
  for (const resource of unverified) {
    const decision = await evaluate(
      externalContext(vehicle._id, member.memberId, resource, 'device:read'),
    );
    assert.equal(decision.allowed, false);
    assert.equal(decision.reason, 'UNVERIFIED_EXTERNAL_RESOURCE');
  }
  const crossType = await evaluate(
    externalContext(vehicle._id, member.memberId, moduleResource(module1), 'device:read'),
  );
  assert.equal(crossType.reason, 'PERMISSION_RESOURCE_MISMATCH');

  // A DEVICE grant authorizes that device only, never a sibling device or a module.
  const grantFrame = {
    vehicleId: vehicle._id,
    membershipId: bare.membershipId,
    subjectUserId: bare.memberId,
    actorUserId: ownerId,
    channel: 'ONLINE' as const,
  };
  const deviceGrant = await createAccessGrant({
    ...grantFrame,
    scopeType: 'DEVICE',
    scopeResourceId: device1,
    verifiedResourceBinding: testOwnershipEvidence('DEVICE', device1, vehicle._id),
    permissions: ['device:read', 'device:command'],
  });
  const granted = await evaluate(
    externalContext(vehicle._id, bare.memberId, device(device1), 'device:command'),
  );
  assert.equal(granted.allowed && granted.source, 'ACCESS_GRANT');
  assert.equal(granted.allowed && granted.grantId?.equals(deviceGrant._id), true);
  const sibling = await evaluate(
    externalContext(vehicle._id, bare.memberId, device(device2), 'device:command'),
  );
  assert.equal(sibling.reason, 'PERMISSION_NOT_GRANTED');
  const moduleDenied = await evaluate(
    externalContext(vehicle._id, bare.memberId, moduleResource(module1), 'module:read'),
  );
  assert.equal(moduleDenied.reason, 'PERMISSION_NOT_GRANTED');
  // A DEVICE grant does not let the member read the vehicle.
  assert.equal(await canAccessVehicle(vehicle._id, bare.memberId), false);

  // Issuing DEVICE/MODULE grants without verified evidence persists nothing.
  const before = await vehiclePersistenceSnapshot(vehicle._id);
  const forged = JSON.parse(
    JSON.stringify(testOwnershipEvidence('DEVICE', device2, vehicle._id)),
  ) as ReturnType<typeof testOwnershipEvidence>;
  const rejectedEvidence = [
    { scopeType: 'DEVICE' as const, scopeResourceId: device2, verifiedResourceBinding: undefined },
    { scopeType: 'DEVICE' as const, scopeResourceId: device2, verifiedResourceBinding: forged },
    {
      scopeType: 'DEVICE' as const,
      scopeResourceId: device2,
      verifiedResourceBinding: testOwnershipEvidence('DEVICE', device2, otherVehicle._id),
    },
    {
      scopeType: 'DEVICE' as const,
      scopeResourceId: device2,
      verifiedResourceBinding: testOwnershipEvidence('DEVICE', device1, vehicle._id),
    },
    {
      scopeType: 'MODULE' as const,
      scopeResourceId: module1,
      verifiedResourceBinding: testOwnershipEvidence('DEVICE', module1, vehicle._id),
    },
  ];
  for (const evidence of rejectedEvidence) {
    await rejectsWithCode(
      () =>
        createAccessGrant({
          ...grantFrame,
          ...evidence,
          permissions: evidence.scopeType === 'DEVICE' ? ['device:read'] : ['module:read'],
        }),
      'VALIDATION_ERROR',
    );
  }
  assert.equal(await vehiclePersistenceSnapshot(vehicle._id), before);
});

test('31. TKT-013 AccessGrant matching: subject, membership, inclusive start, exclusive expiry, status, and channel', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Grant Window Wagon' });
  const member = await addAcceptedMember(vehicle._id, ownerId, []);
  const bystander = await addAcceptedMember(vehicle._id, ownerId, []);
  const evaluate = (context: AuthorizationContext, instant?: Date) =>
    resourceAuthorization.evaluate(context, instant ? atTime(instant) : {});
  const readCtx = vehicleContext(vehicle._id, member.memberId, 'vehicle:read');
  const grantFrame = {
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: member.memberId,
    actorUserId: ownerId,
    scopeType: 'VEHICLE' as const,
  };

  // Window boundaries: startsAt == now allows, expiresAt == now denies, future/past deny.
  const start = new Date(Date.now() + 60_000);
  const end = new Date(start.getTime() + 60_000);
  const windowed = await createAccessGrant({
    ...grantFrame,
    channel: 'ONLINE',
    permissions: ['vehicle:read'],
    startsAt: start,
    expiresAt: end,
  });
  assert.equal((await evaluate(readCtx, new Date(start.getTime() - 1))).allowed, false);
  const atStart = await evaluate(readCtx, start);
  assert.equal(atStart.allowed && atStart.grantId?.equals(windowed._id), true);
  assert.equal((await evaluate(readCtx, new Date(end.getTime() - 1))).allowed, true);
  assert.equal((await evaluate(readCtx, end)).allowed, false);
  assert.equal((await evaluate(readCtx, new Date(end.getTime() + 1))).allowed, false);
  assert.equal((await evaluate(readCtx)).allowed, false, 'future grant is not yet effective');

  // The grant belongs to its subject only.
  assert.equal(
    (await evaluate(vehicleContext(vehicle._id, bystander.memberId, 'vehicle:read'), start))
      .allowed,
    false,
  );
  // A grant whose subject does not match the membership never applies to either party.
  await insertRawActiveGrant({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: bystander.memberId,
    grantedByUserId: ownerId,
    permissions: ['vehicle:update'],
    expiresAt: null,
  });
  assert.equal(
    (await evaluate(vehicleContext(vehicle._id, member.memberId, 'vehicle:update'))).allowed,
    false,
  );
  assert.equal(
    (await evaluate(vehicleContext(vehicle._id, bystander.memberId, 'vehicle:update'))).allowed,
    false,
  );

  // Revoked and expired grants never apply.
  const revoked = await createAccessGrant({
    ...grantFrame,
    channel: 'ONLINE',
    permissions: ['vehicle:update'],
  });
  assert.equal(
    (await evaluate(vehicleContext(vehicle._id, member.memberId, 'vehicle:update'))).allowed,
    true,
  );
  await revokeAccessGrant({ vehicleId: vehicle._id, grantId: revoked._id, actorUserId: ownerId });
  assert.equal(
    (await evaluate(vehicleContext(vehicle._id, member.memberId, 'vehicle:update'))).allowed,
    false,
  );
  await expireElapsedAccessGrants(vehicle._id, new Date(end.getTime() + 1));
  assert.equal((await AccessGrantModel.findById(windowed._id).lean())?.status, 'EXPIRED');
  assert.equal((await evaluate(readCtx, start)).allowed, false);

  // Channel semantics: ONLINE without expiry allowed; BLE_OFFLINE/ANY without expiry never count.
  const online = await createAccessGrant({
    ...grantFrame,
    channel: 'ONLINE',
    permissions: ['device:link'],
  });
  assert.equal(online.expiresAt, null);
  const linkCtx = vehicleContext(vehicle._id, member.memberId, 'device:link');
  assert.equal((await evaluate(linkCtx)).allowed, true);
  assert.equal((await evaluate({ ...linkCtx, channel: 'BLE_OFFLINE' })).allowed, false);
  await rejectsWithCode(
    () =>
      createAccessGrant({ ...grantFrame, channel: 'BLE_OFFLINE', permissions: ['vehicle:read'] }),
    'VALIDATION_ERROR',
  );
  await rejectsWithCode(
    () => createAccessGrant({ ...grantFrame, channel: 'ANY', permissions: ['vehicle:read'] }),
    'VALIDATION_ERROR',
  );
  await insertRawActiveGrant({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: member.memberId,
    grantedByUserId: ownerId,
    permissions: ['vehicle:read'],
    expiresAt: null,
    channel: 'ANY',
  });
  const anyCtx = vehicleContext(vehicle._id, member.memberId, 'vehicle:read');
  assert.equal((await evaluate(anyCtx)).allowed, false);
  assert.equal((await evaluate({ ...anyCtx, channel: 'BLE_OFFLINE' })).allowed, false);
  // ANY with expiry covers both channels; a grant gives no invitation issuance authority.
  await createAccessGrant({
    ...grantFrame,
    channel: 'ANY',
    permissions: ['vehicle:read'],
    expiresAt: new Date(Date.now() + 3_600_000),
  });
  assert.equal((await evaluate(anyCtx)).allowed, true);
  const offlineGrant = await evaluate({ ...anyCtx, channel: 'BLE_OFFLINE' });
  assert.equal(offlineGrant.allowed && offlineGrant.source, 'ACCESS_GRANT');
  await rejectsWithCode(
    () =>
      createAccessGrant({ ...grantFrame, channel: 'ONLINE', permissions: ['invitation:create'] }),
    'VALIDATION_ERROR',
  );
  await rejectsWithCode(
    () => inviteMember(vehicle._id, member.memberId, new Types.ObjectId(), ['vehicle:read']),
    'FORBIDDEN',
  );

  // Grants of a previous membership never apply to a later membership of the same user.
  const formerGrant = await createAccessGrant({
    ...grantFrame,
    channel: 'ONLINE',
    permissions: ['vehicle:update'],
  });
  await revokeMembership({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    actorUserId: ownerId,
  });
  await AccessGrantModel.collection.updateOne(
    { _id: formerGrant._id },
    { $set: { status: 'ACTIVE', revokedAt: null, revokedByUserId: null, revokeReason: null } },
  );
  const reinvited = await inviteMember(vehicle._id, ownerId, member.memberId, []);
  assert.ok(reinvited);
  assert.ok(await acceptInvitation(reinvited._id, member.memberId));
  const stale = await evaluate(vehicleContext(vehicle._id, member.memberId, 'vehicle:update'));
  assert.equal(stale.allowed, false);
  assert.equal(stale.reason, 'PERMISSION_NOT_GRANTED');
});

test('32. TKT-013 evaluation with a session sees the transaction snapshot but is not a write barrier', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Snapshot Sedan' });
  const member = await addAcceptedMember(vehicle._id, ownerId, ['vehicle:read']);
  const readCtx = vehicleContext(vehicle._id, member.memberId, 'vehicle:read');
  const updateCtx = vehicleContext(vehicle._id, member.memberId, 'vehicle:update');

  // Uncommitted changes are visible only to evaluations bound to the same session.
  const session = await mongoose.startSession();
  try {
    session.startTransaction({
      readConcern: { level: 'snapshot' },
      writeConcern: { w: 'majority' },
    });
    await MembershipModel.updateOne(
      { _id: member.membershipId },
      { $set: { permissions: [] } },
      { session },
    );
    await AccessGrantModel.create(
      [
        {
          vehicleId: vehicle._id,
          membershipId: member.membershipId,
          subjectUserId: member.memberId,
          scopeType: 'VEHICLE',
          scopeResourceId: null,
          channel: 'ONLINE',
          permissions: ['vehicle:update'],
          status: 'ACTIVE',
          startsAt: new Date(Date.now() - 1_000),
          expiresAt: null,
          grantedByUserId: ownerId,
        },
      ],
      { session },
    );
    const inTxRead = await resourceAuthorization.evaluate(readCtx, { session });
    assert.equal(inTxRead.reason, 'PERMISSION_NOT_GRANTED');
    const inTxUpdate = await resourceAuthorization.evaluate(updateCtx, { session });
    assert.equal(inTxUpdate.allowed && inTxUpdate.source, 'ACCESS_GRANT');
    assert.equal((await resourceAuthorization.evaluate(readCtx)).allowed, true);
    assert.equal((await resourceAuthorization.evaluate(updateCtx)).allowed, false);
    await VehicleModel.updateOne(
      { _id: vehicle._id },
      { $set: { status: 'ARCHIVED', archivedAt: new Date(), archivedByUserId: ownerId } },
      { session },
    );
    const archivedInTx = await resourceAuthorization.evaluate(updateCtx, { session });
    assert.equal(archivedInTx.reason, 'VEHICLE_UNAVAILABLE_OR_INCONSISTENT');
    await session.abortTransaction();
  } finally {
    await session.endSession();
  }
  assert.equal((await resourceAuthorization.evaluate(readCtx)).allowed, true);
  assert.equal(await AccessGrantModel.countDocuments({ vehicleId: vehicle._id }), 0);

  // A snapshot read keeps answering ALLOW after a concurrent suspension commits: only the
  // conditional write on the authority document detects the conflict.
  const stale = await mongoose.startSession();
  try {
    stale.startTransaction({ readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' } });
    assert.equal((await resourceAuthorization.evaluate(readCtx, { session: stale })).allowed, true);
    await suspendMembership({
      vehicleId: vehicle._id,
      membershipId: member.membershipId,
      actorUserId: ownerId,
    });
    assert.equal((await resourceAuthorization.evaluate(readCtx)).allowed, false);
    assert.equal((await resourceAuthorization.evaluate(readCtx, { session: stale })).allowed, true);
    await assert.rejects(
      MembershipModel.updateOne(
        { _id: member.membershipId, status: 'ACTIVE' },
        { $set: { updatedAt: new Date() } },
        { session: stale },
      ),
      (error: unknown) =>
        error instanceof mongoose.mongo.MongoServerError &&
        error.hasErrorLabel('TransientTransactionError'),
    );
    await stale.abortTransaction().catch(() => undefined);
  } finally {
    await stale.endSession();
  }
  const persisted = await MembershipModel.findById(member.membershipId).lean();
  assert.equal(persisted?.status, 'SUSPENDED');
});

test('33. TKT-013 authorized mutations re-validate authority inside the transaction against concurrent changes', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Concurrency Coupe' });
  const pendingFrom = (membershipId: Types.ObjectId) =>
    InvitationModel.countDocuments({ issuerMembershipId: membershipId, status: 'PENDING' });

  // Deterministic: the pre-check passes against committed state, the held permission change
  // commits, and the in-transaction re-check denies without persisting anything.
  const changes: Array<{ label: string; update: Record<string, unknown> }> = [
    { label: 'permission change', update: { permissions: ['vehicle:read'] } },
    {
      label: 'suspension',
      update: { status: 'SUSPENDED', suspendedAt: new Date(), suspendedByUserId: ownerId },
    },
    {
      label: 'revocation',
      update: { status: 'REVOKED', revokedAt: new Date(), revokedByUserId: ownerId },
    },
  ];
  for (const { label, update } of changes) {
    const delegate = await addAcceptedMember(vehicle._id, ownerId, [
      'vehicle:read',
      'invitation:create',
    ]);
    assert.equal(
      (
        await resourceAuthorization.evaluate(
          vehicleContext(vehicle._id, delegate.memberId, 'invitation:create'),
        )
      ).allowed,
      true,
    );
    const held = await holdMembershipChange(vehicle._id, delegate.membershipId, update);
    const blocked = inviteMember(vehicle._id, delegate.memberId, new Types.ObjectId(), [
      'vehicle:read',
    ]);
    blocked.catch(() => undefined);
    assert.equal(await stillPendingAfter(blocked, 300), true, `${label}: invite must wait`);
    await held.commit();
    await assert.rejects(
      blocked,
      (error: unknown) =>
        error instanceof VehicleServiceError && ['FORBIDDEN', 'NOT_FOUND'].includes(error.code),
      label,
    );
    assert.equal(await pendingFrom(delegate.membershipId), 0, label);
  }

  // Racing: whichever order commits, no PENDING invitation survives the loss of authority.
  for (let round = 0; round < 5; round += 1) {
    const delegate = await addAcceptedMember(vehicle._id, ownerId, [
      'vehicle:read',
      'invitation:create',
    ]);
    const [, demoted] = await Promise.allSettled([
      inviteMember(vehicle._id, delegate.memberId, new Types.ObjectId(), ['vehicle:read']),
      round % 2 === 0
        ? updateMembershipPermissions({
            vehicleId: vehicle._id,
            membershipId: delegate.membershipId,
            actorUserId: ownerId,
            permissions: ['vehicle:read'],
          })
        : suspendMembership({
            vehicleId: vehicle._id,
            membershipId: delegate.membershipId,
            actorUserId: ownerId,
          }),
    ]);
    assert.equal(demoted.status, 'fulfilled', `round ${round}`);
    assert.equal(await pendingFrom(delegate.membershipId), 0, `round ${round}`);
    assert.equal(
      (
        await resourceAuthorization.evaluate(
          vehicleContext(vehicle._id, delegate.memberId, 'invitation:create'),
        )
      ).allowed,
      false,
    );
  }
});

test('34. TKT-013 incompatible and inconsistent AccessGrants: creation rejected without writes, stored records never grant and stay manageable', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'Historical Grant Hatch' });
  const member = await addAcceptedMember(vehicle._id, ownerId, []);
  const deviceId = new Types.ObjectId();
  const grantFrame = {
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: member.memberId,
    actorUserId: ownerId,
    scopeType: 'VEHICLE' as const,
    channel: 'ONLINE' as const,
  };

  // Creation: VEHICLE-scoped device:read is grantable in storage but never issuable.
  const before = await vehiclePersistenceSnapshot(vehicle._id);
  for (const permissions of [['device:read'], ['vehicle:read', 'device:read']]) {
    await rejectsWithCode(
      () => createAccessGrant({ ...grantFrame, permissions }),
      'VALIDATION_ERROR',
    );
  }
  assert.equal(await vehiclePersistenceSnapshot(vehicle._id), before);

  const rawGrant = async (fields: Record<string, unknown>): Promise<Types.ObjectId> => {
    const _id = new Types.ObjectId();
    const created = new Date(Date.now() - 120_000);
    await AccessGrantModel.collection.insertOne({
      _id,
      vehicleId: vehicle._id,
      membershipId: member.membershipId,
      subjectUserId: member.memberId,
      scopeType: 'VEHICLE',
      scopeResourceId: null,
      channel: 'ONLINE',
      permissions: ['device:read'],
      status: 'ACTIVE',
      startsAt: created,
      expiresAt: null,
      grantedByUserId: ownerId,
      updatedByUserId: null,
      revokedAt: null,
      revokedByUserId: null,
      revokeReason: null,
      expiredAt: null,
      createdAt: created,
      updatedAt: created,
      ...fields,
    });
    return _id;
  };

  // A historical incompatible record stays valid for the model but never grants anything.
  const historicalId = await rawGrant({});
  const historical = await AccessGrantModel.findById(historicalId);
  assert.ok(historical);
  await assert.doesNotReject(() => historical.validate());
  const onVehicle = await resourceAuthorization.evaluate(
    vehicleContext(vehicle._id, member.memberId, 'device:read'),
  );
  assert.equal(onVehicle.reason, 'PERMISSION_RESOURCE_MISMATCH');
  const onDevice = await resourceAuthorization.evaluate(
    externalContext(
      vehicle._id,
      member.memberId,
      {
        type: 'DEVICE',
        resourceId: deviceId,
        binding: testOwnershipEvidence('DEVICE', deviceId, vehicle._id),
      },
      'device:read',
    ),
  );
  assert.equal(onDevice.reason, 'PERMISSION_NOT_GRANTED');
  assert.equal(await canAccessVehicle(vehicle._id, member.memberId), false);
  assert.equal(await canAccessVehicle(vehicle._id, member.memberId, 'device:read'), false);

  // Revocation of the historical record keeps working and is audited on the record.
  const revoked = await revokeAccessGrant({
    vehicleId: vehicle._id,
    grantId: historicalId,
    actorUserId: ownerId,
    reason: 'Historical incompatible grant',
  });
  assert.equal(revoked?.status, 'REVOKED');
  assert.equal(revoked?.revokeReason, 'Historical incompatible grant');
  assert.deepEqual(revoked?.permissions, ['device:read']);

  // BLE_OFFLINE / ANY records without a valid expiry never grant, whatever their inconsistency.
  const inconsistent = [
    { channel: 'BLE_OFFLINE', expiresAt: null },
    { channel: 'ANY', expiresAt: null },
    { channel: 'BLE_OFFLINE', expiresAt: undefined },
    { channel: 'ANY', expiresAt: undefined },
    { channel: 'ANY', expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
  ];
  const inconsistentIds: Types.ObjectId[] = [];
  for (const { channel, expiresAt } of inconsistent) {
    const fields: Record<string, unknown> = { channel, permissions: ['vehicle:read'] };
    if (expiresAt !== undefined) {
      fields.expiresAt = expiresAt;
    }
    const id = await rawGrant(fields);
    if (expiresAt === undefined) {
      await AccessGrantModel.collection.updateOne({ _id: id }, { $unset: { expiresAt: '' } });
    }
    inconsistentIds.push(id);
  }
  const readCtx = vehicleContext(vehicle._id, member.memberId, 'vehicle:read');
  assert.equal((await resourceAuthorization.evaluate(readCtx)).allowed, false);
  assert.equal(
    (await resourceAuthorization.evaluate({ ...readCtx, channel: 'BLE_OFFLINE' })).allowed,
    false,
  );
  assert.equal(await canAccessVehicle(vehicle._id, member.memberId), false);
  const [vehicleRecord] = await VehicleModel.find({ _id: vehicle._id }).lean();
  const membershipRecord = await MembershipModel.findById(member.membershipId).lean();
  assert.ok(vehicleRecord && membershipRecord);
  assert.deepEqual(
    await resourceAuthorization.filterReadableCandidates(
      member.memberId,
      [{ vehicle: vehicleRecord, membership: membershipRecord }],
      { now: new Date() },
    ),
    [],
  );

  // Cascades still manage stored incompatible and inconsistent records.
  const historicalActive = await rawGrant({});
  await suspendMembership({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    actorUserId: ownerId,
  });
  for (const id of [historicalActive, ...inconsistentIds]) {
    const stored = await AccessGrantModel.findById(id).lean();
    assert.notEqual(stored?.status, 'ACTIVE', String(id));
  }
});

test('35. TKT-013 single and batch read authorization agree for every actor kind without N+1', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const vehicles = await Promise.all(
    ['Batch One', 'Batch Two', 'Batch Three'].map((name) => createVehicle(ownerId, { name })),
  );
  const actorId = new Types.ObjectId();
  const actorKinds: Array<{ vehicle: (typeof vehicles)[number]; permissions: string[] }> = [
    { vehicle: vehicles[0]!, permissions: ['vehicle:read'] },
    { vehicle: vehicles[1]!, permissions: ['vehicle:manage'] },
    { vehicle: vehicles[2]!, permissions: ['device:read'] },
  ];
  const memberships: Types.ObjectId[] = [];
  for (const { vehicle, permissions } of actorKinds) {
    const invitation = await inviteMember(vehicle._id, ownerId, actorId, permissions);
    assert.ok(invitation);
    const membership = await acceptInvitation(invitation._id, actorId);
    assert.ok(membership);
    memberships.push(membership._id);
  }
  // A current VEHICLE vehicle:read grant makes the third vehicle readable as well.
  await createAccessGrant({
    vehicleId: vehicles[2]!._id,
    membershipId: memberships[2]!,
    subjectUserId: actorId,
    actorUserId: ownerId,
    scopeType: 'VEHICLE',
    channel: 'ONLINE',
    permissions: ['vehicle:read'],
    expiresAt: new Date(Date.now() + 60_000),
  });

  const loadCandidates = async () => {
    const records = await MembershipModel.find({ userId: actorId, status: 'ACTIVE' }).lean();
    const vehicleRecords = await VehicleModel.find({
      _id: { $in: records.map((record) => record.vehicleId) },
    }).lean();
    return records.map((membership) => ({
      membership,
      vehicle: vehicleRecords.find((record) => record._id.equals(membership.vehicleId))!,
    }));
  };
  const compare = async (label: string) => {
    const candidates = await loadCandidates();
    const originalFind = AccessGrantModel.find.bind(AccessGrantModel);
    let grantQueries = 0;
    AccessGrantModel.find = ((...args: Parameters<typeof AccessGrantModel.find>) => {
      grantQueries += 1;
      return originalFind(...args);
    }) as typeof AccessGrantModel.find;
    let batch: VehicleAccessCandidate[];
    try {
      batch = await resourceAuthorization.filterReadableCandidates(actorId, candidates, {
        now: new Date(),
      });
    } finally {
      AccessGrantModel.find = originalFind;
    }
    assert.ok(grantQueries <= 1, `${label}: ${grantQueries} grant queries`);
    for (const vehicle of vehicles) {
      const single = await resourceAuthorization.hasVehicleReadAccess(vehicle._id, actorId);
      const inBatch = batch.some((candidate) => candidate.vehicle._id.equals(vehicle._id));
      assert.equal(inBatch, single, `${label}: ${vehicle.name}`);
      assert.equal(await canAccessVehicle(vehicle._id, actorId), single, label);
    }
    return batch.length;
  };

  assert.equal(await compare('initial'), 3);
  await suspendMembership({
    vehicleId: vehicles[1]!._id,
    membershipId: memberships[1]!,
    actorUserId: ownerId,
  });
  assert.equal(await compare('after suspension'), 2);
  await updateMembershipPermissions({
    vehicleId: vehicles[0]!._id,
    membershipId: memberships[0]!,
    actorUserId: ownerId,
    permissions: ['device:read'],
  });
  assert.equal(await compare('after permission change'), 1);
});

test('36. TKT-015 controlled cross-service TOCTOU race and concurrent PATCH vs revoke', async () => {
  await resetVehicleCollections();
  const ownerId = new Types.ObjectId();
  const memberId = new Types.ObjectId();
  const vehicle = await createVehicle(ownerId, { name: 'TKT-015 Race Mazda 3' });
  const invitation = await inviteMember(vehicle._id, ownerId, memberId, [
    'vehicle:read',
    'vehicle:manage',
  ]);
  assert.ok(invitation);
  const membership = await acceptInvitation(invitation._id, memberId);
  assert.ok(membership);

  const remoteDeviceObjectId = new Types.ObjectId();
  const remoteDeviceId = String(remoteDeviceObjectId);
  const remoteCredentialId = String(new Types.ObjectId());
  const baseRecord: InternalDeviceRecord = {
    deviceId: remoteDeviceId,
    vehicleId: String(vehicle._id),
    identifier: 'esp32-race-01',
    status: 'ACTIVE',
    operational: true,
    credential: {
      credentialId: remoteCredentialId,
      keyId: 'dk_0123456789abcdefghijkl',
      algorithm: 'Ed25519',
      fingerprint: `sha256:${'a'.repeat(64)}`,
      status: 'ACTIVE',
      usable: true,
      activatedAt: '2026-04-20T00:00:00.000Z',
      expiresAt: null,
      revokedAt: null,
    },
    connectivity: { lastSeenAt: null },
    metadata: {
      name: 'Initial Name',
      manufacturer: null,
      hardwareModel: null,
      hardwareRevision: null,
      firmwareVersion: null,
      serialNumber: null,
    },
    requestedByUserId: String(memberId),
    requestedByMembershipId: String(membership._id),
    linkedAt: '2026-04-20T00:00:00.000Z',
    revokedAt: null,
    revokedByUserId: null,
    revocationReason: null,
    createdAt: '2026-04-20T00:00:00.000Z',
    updatedAt: '2026-04-20T00:00:00.000Z',
  };

  let storedState: InternalDeviceRecord = structuredClone(baseRecord);
  const toSnapshot = (record: InternalDeviceRecord): VerifiedDeviceSnapshot => ({
    record: structuredClone(record),
    publicDetail: toPublicDeviceDetail(record),
    activeBinding:
      record.status === 'ACTIVE' && record.operational
        ? createVerifiedExternalResourceBinding({
            scopeType: 'DEVICE',
            resourceId: remoteDeviceObjectId,
            vehicleId: vehicle._id,
            isActive: true,
          })
        : null,
  });

  let releaseRemoteMutation!: () => void;
  let notifyAuthorizedAndEnteredRemote!: () => void;
  const authorizedAndEnteredRemote = new Promise<void>((resolve) => {
    notifyAuthorizedAndEnteredRemote = resolve;
  });
  const remoteBarrier = new Promise<void>((resolve) => {
    releaseRemoteMutation = resolve;
  });
  let holdNextPatch = true;

  const stubClient: DeviceServiceClient = {
    async registerDevice() {
      throw new Error('unexpected call');
    },
    async getDeviceById(deviceId) {
      if (deviceId !== storedState.deviceId) return null;
      return toSnapshot(storedState);
    },
    async listVehicleDevicesBatch() {
      return { items: [toSnapshot(storedState)], hasMore: false };
    },
    async updateDeviceMetadata(input) {
      if (holdNextPatch) {
        holdNextPatch = false;
        notifyAuthorizedAndEnteredRemote();
        await remoteBarrier;
      }
      if (storedState.status === 'REVOKED') {
        throw new DeviceUpstreamDomainError(409, 'DEVICE_REVOKED');
      }
      storedState = {
        ...storedState,
        metadata: {
          ...storedState.metadata,
          ...(input.metadata.name !== undefined ? { name: input.metadata.name } : {}),
        },
      };
      return toSnapshot(storedState);
    },
    async createChallenge() {
      throw new Error('unexpected call');
    },
    async completeLink() {
      throw new Error('unexpected call');
    },
    async revokeDevice(input) {
      if (storedState.status !== 'REVOKED') {
        storedState = {
          ...storedState,
          status: 'REVOKED',
          operational: false,
          credential: {
            ...storedState.credential,
            status: 'REVOKED',
            usable: false,
            revokedAt: '2026-04-20T00:05:00.000Z',
          },
          revokedAt: '2026-04-20T00:05:00.000Z',
          revokedByUserId: input.userId,
          revocationReason: input.reason,
        };
      }
      return toSnapshot(storedState);
    },
  };

  const ctx = {
    deviceClient: stubClient,
    confirmActorVerified: async () => undefined,
  };

  // 1. Controlled TOCTOU race: member passes Vehicle authorization and enters remote HTTP call;
  //    no MongoDB transaction is held open in Vehicle, so owner revokes membership cleanly in parallel.
  const inFlightPatch = updateVehicleDeviceMetadata(
    vehicle._id,
    remoteDeviceObjectId,
    memberId,
    { name: 'Completed After Permission Loss' },
    ctx,
  );

  await authorizedAndEnteredRemote;

  // Membership revocation commits immediately in MongoDB without lock/WriteConflict contention
  const revokeResult = await revokeMembership({
    vehicleId: vehicle._id,
    membershipId: membership._id,
    actorUserId: ownerId,
    reason: 'Revoked during in-flight remote call',
  });
  assert.equal(revokeResult.membership.status, 'REVOKED');

  // Release remote mutation: demonstrates documented residual cross-service window
  releaseRemoteMutation();
  const completedInFlight = await inFlightPatch;
  assert.equal(completedInFlight.metadata.name, 'Completed After Permission Loss');

  // Immediately afterwards, the revoked member has ZERO subsequent access (uniform 404 NOT_FOUND)
  const expectNotFound = (err: unknown) =>
    err instanceof VehicleServiceError && err.code === 'NOT_FOUND';
  await assert.rejects(
    () => getVehicleScopedDeviceDetail(vehicle._id, remoteDeviceObjectId, memberId, ctx),
    expectNotFound,
  );
  await assert.rejects(
    () => getDirectDeviceDetail(remoteDeviceObjectId, memberId, ctx),
    expectNotFound,
  );
  await assert.rejects(() => listVehicleDevices(vehicle._id, memberId, {}, ctx), expectNotFound);
  await assert.rejects(
    () =>
      updateVehicleDeviceMetadata(
        vehicle._id,
        remoteDeviceObjectId,
        memberId,
        { name: 'Blocked' },
        ctx,
      ),
    expectNotFound,
  );

  // 2. Concurrent PATCH vs OWNER revoke: once revoked, terminal REVOKED state is preserved
  const [revokeSettled, latePatchSettled] = await Promise.allSettled([
    revokeVehicleDevice(vehicle._id, remoteDeviceObjectId, ownerId, 'SECURITY_COMPROMISE', ctx),
    (async () => {
      await Promise.resolve();
      return updateVehicleDeviceMetadata(
        vehicle._id,
        remoteDeviceObjectId,
        ownerId,
        { name: 'After Revoke' },
        ctx,
      );
    })(),
  ]);
  assert.equal(revokeSettled.status, 'fulfilled');
  if (latePatchSettled.status === 'rejected') {
    assert.equal(
      latePatchSettled.reason instanceof VehicleServiceError &&
        latePatchSettled.reason.code === 'CONFLICT',
      true,
    );
  }
  assert.equal(storedState.status, 'REVOKED');
});
