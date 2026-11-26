import assert from 'node:assert/strict';
import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { createHmac, generateKeyPairSync, randomUUID } from 'node:crypto';
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
  getVehicleForUser,
  inviteMember,
  listAccessibleVehicles,
  listOwnedVehicles,
  reactivateMembership,
  revokeAccessGrant,
  revokeInvitation,
  revokeMembership,
  suspendMembership,
  VehicleServiceError,
} from '../../src/services/vehicle.service.js';
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
  assert.equal(accessibleToShared.length, 2);

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

  // Attempting to accept after expiry returns null AND durably persists EXPIRED (not rolled back!)
  const acceptResult = await acceptInvitation(expiredInvite._id, inviteeA);
  assert.equal(acceptResult, null);

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
  assert.equal(revoked?.status, 'REVOKED');

  // Cannot reopen terminal REVOKED or EXPIRED invitations
  assert.equal(await acceptInvitation(reissued._id, inviteeB), null);
  assert.equal(
    await revokeInvitation({
      vehicleId: vehicle._id,
      invitationId: expiredInvite._id,
      actorUserId: ownerId,
    }),
    null,
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

  // 8f. Suspending Membership blocks active AccessGrants without revoking them; reactivation restores them
  await suspendMembership({
    vehicleId: vehicle1._id,
    membershipId: memA._id,
    actorUserId: ownerId,
    reason: 'Temporary travel pause',
    now,
  });
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
  assert.equal(afterReactivate.allowed, true);

  // 8g. Revoking Membership cascades to all remaining ACTIVE grants AND new Membership does NOT inherit old grants
  const revokeOutcome = await revokeMembership({
    vehicleId: vehicle1._id,
    membershipId: memA._id,
    actorUserId: ownerId,
    reason: 'End membership',
    now,
  });
  assert.equal(revokeOutcome?.revokedGrantsCount, 2); // grantDev2Online + grantModuleFuture

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
  assert.equal(archived?.status, 'ARCHIVED');
  assert.equal((await InvitationModel.findById(invPending._id))?.status, 'REVOKED');
  assert.equal((await AccessGrantModel.findById(activeGrant._id))?.status, 'REVOKED');

  // Denials across read, list, device linking, invitation creation, invitation acceptance, and new grants
  assert.equal(await canAccessVehicle(vehicle._id, ownerId), false);
  assert.equal(await canLinkDeviceToVehicle(vehicle._id, ownerId), false);
  assert.equal(await canLinkDeviceToVehicle(vehicle._id, memberId), false);
  assert.equal(await getVehicleForUser(vehicle._id, ownerId), null);
  assert.equal((await listOwnedVehicles(ownerId)).length, 0);
  assert.equal((await listAccessibleVehicles(memberId)).length, 0);
  assert.equal(
    await inviteMember(vehicle._id, ownerId, new Types.ObjectId(), ['vehicle:read']),
    null,
  );
  assert.equal(await acceptInvitation(invPending._id, pendingInviteeId), null);

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

    for (const espSuffix of ['cabin-esp32', 'trunk-esp32']) {
      const linkRes = await fetch(`${gatewayUrl}/api/vehicles/${vehicleId}/devices/link`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${inviteeJwt}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          deviceIdentifier: `esp32-${espSuffix}-${randomUUID().slice(0, 8)}`,
          publicKey: generateKeyPairSync('ed25519')
            .publicKey.export({ type: 'spki', format: 'pem' })
            .toString(),
        }),
      });
      assert.equal(linkRes.status, 201);
    }

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
