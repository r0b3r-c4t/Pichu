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
  getAccessibleVehicle,
  getVehicleForUser,
  inviteMember,
  listAccessibleVehicles,
  listOwnedVehicles,
  reactivateMembership,
  revokeAccessGrant,
  revokeInvitation,
  revokeMembership,
  suspendMembership,
  updateVehicle,
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
  await createAccessGrant({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: member.memberId,
    actorUserId: ownerId,
    scopeType: 'DEVICE',
    scopeResourceId: deviceId,
    channel: 'ONLINE',
    permissions: ['device:read'],
  });
  await createAccessGrant({
    vehicleId: vehicle._id,
    membershipId: member.membershipId,
    subjectUserId: member.memberId,
    actorUserId: ownerId,
    scopeType: 'MODULE',
    scopeResourceId: new Types.ObjectId(),
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
  const delegate = await addAcceptedMember(vehicle._id, ownerId, ['invitation:create']);
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
  for (const unauthorized of [outsider, reader.memberId]) {
    assert.equal(
      await inviteMember(vehicle._id, unauthorized, elapsedInvitee, ['vehicle:read']),
      null,
    );
  }
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
