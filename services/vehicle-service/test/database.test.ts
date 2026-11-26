import assert from 'node:assert/strict';
import test from 'node:test';
import type mongoose from 'mongoose';
import {
  assertCriticalVehicleIndexes,
  findCriticalVehicleIndexIssues,
  VehicleSchemaNotReadyError,
} from '../src/database/bootstrap.js';
import { createDatabaseService } from '../src/database/connection.js';

type MongoDb = NonNullable<typeof mongoose.connection.db>;

function mockDbWithIndexes(byCollection: Record<string, unknown[]>): MongoDb {
  return {
    collection(name: string) {
      return {
        listIndexes() {
          return {
            async toArray() {
              return byCollection[name] ?? [];
            },
          };
        },
      };
    },
  } as unknown as MongoDb;
}

const completeValidIndexes = {
  vehicles: [
    { name: '_id_', key: { _id: 1 } },
    {
      name: 'vehicle_owner_status_created_idx',
      key: { ownerUserId: 1, status: 1, createdAt: 1, _id: 1 },
    },
    {
      name: 'vehicle_status_id_idx',
      key: { status: 1, _id: 1 },
    },
  ],
  memberships: [
    { name: '_id_', key: { _id: 1 } },
    {
      name: 'membership_single_active_owner_unique',
      key: { vehicleId: 1 },
      unique: true,
      partialFilterExpression: { role: 'OWNER', status: 'ACTIVE' },
    },
    {
      name: 'membership_active_vehicle_user_unique',
      key: { vehicleId: 1, userId: 1 },
      unique: true,
      partialFilterExpression: { revokedAt: null },
    },
    {
      name: 'membership_user_status_vehicle_idx',
      key: { userId: 1, status: 1, vehicleId: 1 },
    },
    {
      name: 'membership_vehicle_status_role_idx',
      key: { vehicleId: 1, status: 1, role: 1 },
    },
  ],
  invitations: [
    { name: '_id_', key: { _id: 1 } },
    {
      name: 'invitation_pending_vehicle_invitee_unique',
      key: { vehicleId: 1, inviteeUserId: 1 },
      unique: true,
      partialFilterExpression: { status: 'PENDING' },
    },
    {
      name: 'invitation_vehicle_status_created_idx',
      key: { vehicleId: 1, status: 1, createdAt: -1 },
    },
    {
      name: 'invitation_invitee_status_expires_idx',
      key: { inviteeUserId: 1, status: 1, expiresAt: 1 },
    },
    {
      name: 'invitation_status_expires_idx',
      key: { status: 1, expiresAt: 1 },
    },
  ],
  access_grants: [
    { name: '_id_', key: { _id: 1 } },
    {
      name: 'access_grant_lookup_idx',
      key: {
        vehicleId: 1,
        subjectUserId: 1,
        status: 1,
        scopeType: 1,
        scopeResourceId: 1,
        expiresAt: 1,
      },
    },
    { name: 'access_grant_membership_status_idx', key: { membershipId: 1, status: 1 } },
    {
      name: 'access_grant_resource_status_idx',
      key: { vehicleId: 1, scopeType: 1, scopeResourceId: 1, status: 1 },
    },
    { name: 'access_grant_status_expires_idx', key: { status: 1, expiresAt: 1 } },
  ],
};

test('critical index validator passes when all integrity indexes match exact names, patterns, and options', async () => {
  const db = mockDbWithIndexes(completeValidIndexes);
  assert.deepEqual(await findCriticalVehicleIndexIssues(db), []);
  await assert.doesNotReject(() => assertCriticalVehicleIndexes(db));
});

test('critical index validator blocks readiness on destructive TTL, legacy unique, missing, or weakened index options', async () => {
  // Destructive TTL still present on invitations
  const withTtl = mockDbWithIndexes({
    ...completeValidIndexes,
    invitations: [
      ...completeValidIndexes.invitations,
      { name: 'expiresAt_1', key: { expiresAt: 1 }, expireAfterSeconds: 0 },
    ],
  });
  await assert.rejects(
    () => assertCriticalVehicleIndexes(withTtl),
    (err: unknown) =>
      err instanceof VehicleSchemaNotReadyError &&
      err.reasons.some((r) => r.includes('Destructive legacy TTL index')),
  );

  // Legacy unfiltered unique index on memberships (vehicleId, userId)
  const withLegacyMembershipUnique = mockDbWithIndexes({
    ...completeValidIndexes,
    memberships: [
      ...completeValidIndexes.memberships,
      { name: 'vehicleId_1_userId_1', key: { vehicleId: 1, userId: 1 }, unique: true },
    ],
  });
  await assert.rejects(() => assertCriticalVehicleIndexes(withLegacyMembershipUnique));

  // Wrong index name, sparse option, or non-simple collation weakens index coverage and fails readiness
  const withSparseOwnerUnique = mockDbWithIndexes({
    ...completeValidIndexes,
    memberships: completeValidIndexes.memberships.map((idx) =>
      idx.name === 'membership_single_active_owner_unique' ? { ...idx, sparse: true } : idx,
    ),
  });
  await assert.rejects(() => assertCriticalVehicleIndexes(withSparseOwnerUnique));

  const withRenamedCriticalIndex = mockDbWithIndexes({
    ...completeValidIndexes,
    invitations: completeValidIndexes.invitations.map((idx) =>
      idx.name === 'invitation_pending_vehicle_invitee_unique'
        ? { ...idx, name: 'wrong_name_unique' }
        : idx,
    ),
  });
  await assert.rejects(() => assertCriticalVehicleIndexes(withRenamedCriticalIndex));

  const withWeakCollation = mockDbWithIndexes({
    ...completeValidIndexes,
    vehicles: completeValidIndexes.vehicles.map((idx) =>
      idx.name === 'vehicle_owner_status_created_idx'
        ? { ...idx, collation: { locale: 'en' } }
        : idx,
    ),
  });
  await assert.rejects(() => assertCriticalVehicleIndexes(withWeakCollation));

  // Illegal restrictive unique index on access_grants
  const withRestrictiveGrantUnique = mockDbWithIndexes({
    ...completeValidIndexes,
    access_grants: [
      ...completeValidIndexes.access_grants,
      { name: 'scope_unique', key: { vehicleId: 1, scopeType: 1 }, unique: true },
    ],
  });
  await assert.rejects(() => assertCriticalVehicleIndexes(withRestrictiveGrantUnique));
});

test('createDatabaseService enforces autoIndex: false, checks ping, and deduplicates connection lifecycle', async () => {
  let connectCalls = 0;
  let disconnectCalls = 0;
  let pingResult: { ok: number } | Error = { ok: 1 };
  const fakeClient = {
    connection: {
      readyState: 0,
      db: undefined as unknown,
    },
    async connect(_url: string, options: { autoIndex?: boolean }) {
      assert.equal(options.autoIndex, false);
      connectCalls += 1;
      fakeClient.connection.readyState = 1;
      fakeClient.connection.db = {
        async command() {
          if (pingResult instanceof Error) throw pingResult;
          return pingResult;
        },
      };
      return fakeClient;
    },
    async disconnect() {
      disconnectCalls += 1;
      fakeClient.connection.readyState = 0;
      fakeClient.connection.db = undefined;
    },
  } as unknown as typeof mongoose;

  const service = createDatabaseService(fakeClient);
  assert.equal(await service.checkDatabaseConnection(), false);

  await Promise.all([
    service.connectDatabase('mongodb://127.0.0.1:27018/vehicle_db'),
    service.connectDatabase('mongodb://127.0.0.1:27018/vehicle_db'),
  ]);
  assert.equal(connectCalls, 1);
  assert.equal(await service.checkDatabaseConnection(), true);

  pingResult = new Error('network error');
  assert.equal(await service.checkDatabaseConnection(), false);

  await service.closeDatabase();
  assert.equal(disconnectCalls, 1);
  assert.equal(await service.checkDatabaseConnection(), false);
});
