import type mongoose from 'mongoose';
import {
  assertCriticalVehicleIndexes,
  findCriticalVehicleIndexIssues,
  VEHICLE_DOMAIN_MODELS,
} from './bootstrap.js';
import { InvitationModel } from '../models/invitation.model.js';
import { MembershipModel } from '../models/membership.model.js';
import { VehicleModel } from '../models/vehicle.model.js';

type MongoDb = NonNullable<typeof mongoose.connection.db>;

interface RawIndexInfo {
  name?: string;
  key?: Record<string, unknown>;
  unique?: boolean;
  expireAfterSeconds?: number;
  partialFilterExpression?: Record<string, unknown>;
}

export interface VehicleMigrationPreflightReport {
  destructiveInvitationTtlIndexNames: string[];
  legacyUnfilteredMembershipUniqueIndexNames: string[];
  expiredPendingInvitationsCount: number;
  vehiclesMissingStatusCount: number;
  membershipsMissingStatusCount: number;
  invitationsMissingTargetRoleCount: number;
  vehiclesMissingAuditActorCount: number;
  membershipsMissingAuditActorCount: number;
  ownerInconsistentVehicleIds: string[];
  duplicateActiveMembershipPairs: Array<{
    vehicleId: string;
    userId: string;
    count: number;
  }>;
  duplicateUnexpiredPendingInvitationPairs: Array<{
    vehicleId: string;
    inviteeUserId: string;
    count: number;
  }>;
  missingOrInvalidIndexIssues: string[];
  canAutoMigrateSafely: boolean;
  blockingReasons: string[];
}

export class VehicleMigrationBlockedError extends Error {
  constructor(
    message: string,
    public readonly report: VehicleMigrationPreflightReport,
  ) {
    super(message);
    this.name = 'VehicleMigrationBlockedError';
  }
}

const VEHICLE_STRUCTURAL_DEFAULTS: ReadonlyArray<readonly [string, unknown]> = [
  ['status', 'ACTIVE'],
  ['make', null],
  ['model', null],
  ['generation', null],
  ['trim', null],
  ['year', null],
  ['bodyStyle', null],
  ['engine', null],
  ['transmission', null],
  ['fuelType', null],
  ['updatedByUserId', null],
  ['archivedAt', null],
  ['archivedByUserId', null],
  ['archiveReason', null],
];

const MEMBERSHIP_STRUCTURAL_DEFAULTS: ReadonlyArray<readonly [string, unknown]> = [
  ['status', 'ACTIVE'],
  ['sourceInvitationId', null],
  ['updatedByUserId', null],
  ['suspendedAt', null],
  ['suspendedByUserId', null],
  ['suspensionReason', null],
  ['revokedAt', null],
  ['revokedByUserId', null],
  ['revokeReason', null],
];

const INVITATION_STRUCTURAL_DEFAULTS: ReadonlyArray<readonly [string, unknown]> = [
  ['targetRole', 'MEMBER'],
  ['acceptedAt', null],
  ['acceptedByUserId', null],
  ['revokedAt', null],
  ['revokedByUserId', null],
  ['revokeReason', null],
  ['expiredAt', null],
  ['updatedByUserId', null],
];

async function listIndexesSafe(db: MongoDb, collectionName: string): Promise<RawIndexInfo[]> {
  try {
    return (await db.collection(collectionName).listIndexes().toArray()) as RawIndexInfo[];
  } catch (error) {
    if (error instanceof Error && /NamespaceNotFound|ns does not exist/i.test(error.message)) {
      return [];
    }
    throw error;
  }
}

async function dropIndexIdempotent(
  db: MongoDb,
  collectionName: string,
  indexName: string,
): Promise<void> {
  try {
    await db.collection(collectionName).dropIndex(indexName);
  } catch (error) {
    if (
      error instanceof Error &&
      /IndexNotFound|index not found|NamespaceNotFound|ns does not exist/i.test(error.message)
    ) {
      return;
    }
    throw error;
  }
}

function sameOrderedKeys(
  actual: Record<string, unknown> | undefined,
  expected: Record<string, number>,
): boolean {
  if (!actual) {
    return false;
  }
  return JSON.stringify(Object.entries(actual)) === JSON.stringify(Object.entries(expected));
}

function missingAnyStructuralFieldFilter(
  defaults: ReadonlyArray<readonly [string, unknown]>,
): Record<string, unknown> {
  return {
    $or: defaults.map(([field]) => ({ [field]: { $exists: false } })),
  };
}

/**
 * Read-only preflight inspection of a legacy or partially migrated vehicle_db deployment.
 * Never mutates documents or indexes, and never fabricates historical audit actors.
 */
export async function inspectVehicleMigrationPreflight(
  db: MongoDb,
  now: Date = new Date(),
): Promise<VehicleMigrationPreflightReport> {
  const [membershipIndexes, invitationIndexes] = await Promise.all([
    listIndexesSafe(db, MembershipModel.collection.name),
    listIndexesSafe(db, InvitationModel.collection.name),
  ]);

  const destructiveInvitationTtlIndexNames = invitationIndexes
    .filter(
      (index) =>
        typeof index.name === 'string' &&
        index.name !== '_id_' &&
        index.expireAfterSeconds !== undefined,
    )
    .map((index) => index.name as string);

  const legacyUnfilteredMembershipUniqueIndexNames = membershipIndexes
    .filter(
      (index) =>
        typeof index.name === 'string' &&
        sameOrderedKeys(index.key, { vehicleId: 1, userId: 1 }) &&
        index.unique === true &&
        !index.partialFilterExpression,
    )
    .map((index) => index.name as string);

  const vehiclesCollection = db.collection(VehicleModel.collection.name);
  const membershipsCollection = db.collection(MembershipModel.collection.name);
  const invitationsCollection = db.collection(InvitationModel.collection.name);

  const [
    expiredPendingInvitationsCount,
    vehiclesMissingStatusCount,
    membershipsMissingStatusCount,
    invitationsMissingTargetRoleCount,
    vehiclesMissingAuditActorCount,
    membershipsMissingAuditActorCount,
    vehicles,
    ownerMemberships,
    duplicateActiveMembershipsRaw,
    duplicateUnexpiredPendingRaw,
    missingOrInvalidIndexIssues,
  ] = await Promise.all([
    invitationsCollection.countDocuments({
      status: 'PENDING',
      expiresAt: { $lte: now },
    }),
    vehiclesCollection.countDocuments(missingAnyStructuralFieldFilter(VEHICLE_STRUCTURAL_DEFAULTS)),
    membershipsCollection.countDocuments(
      missingAnyStructuralFieldFilter(MEMBERSHIP_STRUCTURAL_DEFAULTS),
    ),
    invitationsCollection.countDocuments(
      missingAnyStructuralFieldFilter(INVITATION_STRUCTURAL_DEFAULTS),
    ),
    vehiclesCollection.countDocuments({
      $or: [{ createdByUserId: { $exists: false } }, { createdByUserId: null }],
    }),
    membershipsCollection.countDocuments({
      $or: [{ grantedByUserId: { $exists: false } }, { grantedByUserId: null }],
    }),
    vehiclesCollection.find({}, { projection: { _id: 1, ownerUserId: 1, status: 1 } }).toArray(),
    membershipsCollection
      .find(
        { role: 'OWNER', revokedAt: { $in: [null, undefined] } },
        { projection: { _id: 1, vehicleId: 1, userId: 1, status: 1 } },
      )
      .toArray(),
    membershipsCollection
      .aggregate<{ _id: { vehicleId: unknown; userId: unknown }; count: number }>([
        { $match: { revokedAt: { $in: [null, undefined] } } },
        {
          $group: {
            _id: { vehicleId: '$vehicleId', userId: '$userId' },
            count: { $sum: 1 },
          },
        },
        { $match: { count: { $gt: 1 } } },
      ])
      .toArray(),
    invitationsCollection
      .aggregate<{ _id: { vehicleId: unknown; inviteeUserId: unknown }; count: number }>([
        { $match: { status: 'PENDING', expiresAt: { $gt: now } } },
        {
          $group: {
            _id: { vehicleId: '$vehicleId', inviteeUserId: '$inviteeUserId' },
            count: { $sum: 1 },
          },
        },
        { $match: { count: { $gt: 1 } } },
      ])
      .toArray(),
    findCriticalVehicleIndexIssues(db),
  ]);

  const ownersByVehicle = new Map<string, Array<{ userId: string; status: unknown }>>();
  for (const membership of ownerMemberships) {
    const vehicleKey = String(membership.vehicleId);
    const list = ownersByVehicle.get(vehicleKey) ?? [];
    list.push({ userId: String(membership.userId), status: membership.status });
    ownersByVehicle.set(vehicleKey, list);
  }

  const ownerInconsistentVehicleIds: string[] = [];
  for (const vehicle of vehicles) {
    if (vehicle.status === 'ARCHIVED') {
      continue;
    }
    const vehicleKey = String(vehicle._id);
    const expectedOwner = String(vehicle.ownerUserId);
    const owners = ownersByVehicle.get(vehicleKey) ?? [];
    const activeOwners = owners.filter(
      (entry) => entry.status === undefined || entry.status === 'ACTIVE',
    );
    if (activeOwners.length !== 1 || activeOwners[0]?.userId !== expectedOwner) {
      ownerInconsistentVehicleIds.push(vehicleKey);
    }
  }

  const duplicateActiveMembershipPairs = duplicateActiveMembershipsRaw.map((entry) => ({
    vehicleId: String(entry._id.vehicleId),
    userId: String(entry._id.userId),
    count: entry.count,
  }));

  const duplicateUnexpiredPendingInvitationPairs = duplicateUnexpiredPendingRaw.map((entry) => ({
    vehicleId: String(entry._id.vehicleId),
    inviteeUserId: String(entry._id.inviteeUserId),
    count: entry.count,
  }));

  const blockingReasons: string[] = [];
  if (ownerInconsistentVehicleIds.length > 0) {
    blockingReasons.push(
      `Found ${ownerInconsistentVehicleIds.length} vehicle(s) with inconsistent canonical ownership`,
    );
  }
  if (duplicateActiveMembershipPairs.length > 0) {
    blockingReasons.push(
      `Found ${duplicateActiveMembershipPairs.length} duplicate non-revoked membership pair(s)`,
    );
  }
  if (duplicateUnexpiredPendingInvitationPairs.length > 0) {
    blockingReasons.push(
      `Found ${duplicateUnexpiredPendingInvitationPairs.length} duplicate unexpired PENDING invitation pair(s)`,
    );
  }
  if (vehiclesMissingAuditActorCount > 0) {
    blockingReasons.push(
      `Found ${vehiclesMissingAuditActorCount} legacy vehicle(s) without verified createdByUserId; audit actors cannot be fabricated automatically`,
    );
  }
  if (membershipsMissingAuditActorCount > 0) {
    blockingReasons.push(
      `Found ${membershipsMissingAuditActorCount} legacy membership(s) without verified grantedByUserId; audit actors cannot be fabricated automatically`,
    );
  }

  return {
    destructiveInvitationTtlIndexNames,
    legacyUnfilteredMembershipUniqueIndexNames,
    expiredPendingInvitationsCount,
    vehiclesMissingStatusCount,
    membershipsMissingStatusCount,
    invitationsMissingTargetRoleCount,
    vehiclesMissingAuditActorCount,
    membershipsMissingAuditActorCount,
    ownerInconsistentVehicleIds,
    duplicateActiveMembershipPairs,
    duplicateUnexpiredPendingInvitationPairs,
    missingOrInvalidIndexIssues,
    canAutoMigrateSafely: blockingReasons.length === 0,
    blockingReasons,
  };
}

async function backfillMissingStructuralFields(
  db: MongoDb,
  collectionName: string,
  defaults: ReadonlyArray<readonly [string, unknown]>,
): Promise<void> {
  const collection = db.collection(collectionName);
  for (const [field, defaultValue] of defaults) {
    await collection.updateMany(
      { [field]: { $exists: false } },
      { $set: { [field]: defaultValue } },
    );
  }
}

export async function ensureDeclaredVehicleIndexesOnDb(
  db: MongoDb,
  options: { onAfterEachIndex?: (collectionName: string, indexName: string) => Promise<void> } = {},
): Promise<void> {
  for (const model of VEHICLE_DOMAIN_MODELS) {
    const collectionName = model.collection.name;
    try {
      await db.createCollection(collectionName);
    } catch (error) {
      if (!(error instanceof Error) || !/already exists|NamespaceExists/i.test(error.message)) {
        throw error;
      }
    }

    for (const [fields, indexOptions] of model.schema.indexes()) {
      const createdName = await db
        .collection(collectionName)
        .createIndex(fields as Record<string, 1 | -1>, {
          ...(typeof indexOptions.name === 'string' ? { name: indexOptions.name } : {}),
          ...(indexOptions.unique === true ? { unique: true } : {}),
          ...(indexOptions.partialFilterExpression
            ? { partialFilterExpression: indexOptions.partialFilterExpression }
            : {}),
        });
      if (options.onAfterEachIndex) {
        await options.onAfterEachIndex(collectionName, createdName);
      }
    }
  }
}

/**
 * Controlled, idempotent, and crash-resilient schema migration for legacy indexes
 * and non-actor structural defaults:
 *
 * 1. Aborts fail-closed without mutations if any blocking inconsistency exists.
 * 2. Drops destructive TTL indexes on invitations FIRST so background purges stop immediately.
 * 3. Transitions elapsed PENDING invitations to EXPIRED and backfills missing structural fields
 *    one field at a time without overwriting existing values or inventing historical actors.
 * 4. Builds ALL replacement partial unique and lookup indexes BEFORE dropping the legacy
 *    unfiltered unique index on memberships, eliminating any window without active uniqueness.
 * 5. Drops the legacy unfiltered membership unique index idempotently, then verifies readiness.
 */
export async function applyControlledVehicleMigration(
  db: MongoDb,
  options: {
    now?: Date;
    log?: (message: string) => void;
    onStep?: (step: string) => Promise<void> | void;
  } = {},
): Promise<VehicleMigrationPreflightReport> {
  const now = options.now ?? new Date();
  const log = options.log ?? (() => undefined);

  const preflight = await inspectVehicleMigrationPreflight(db, now);
  if (!preflight.canAutoMigrateSafely) {
    throw new VehicleMigrationBlockedError(
      `Vehicle migration aborted due to blocking data inconsistencies: ${preflight.blockingReasons.join('; ')}`,
      preflight,
    );
  }

  for (const indexName of preflight.destructiveInvitationTtlIndexNames) {
    log(`Dropping destructive legacy TTL index on invitations: ${indexName}`);
    await dropIndexIdempotent(db, InvitationModel.collection.name, indexName);
  }
  await options.onStep?.('after_drop_destructive_ttl');

  if (preflight.expiredPendingInvitationsCount > 0) {
    log(`Resolving ${preflight.expiredPendingInvitationsCount} expired PENDING invitation(s)`);
    await db
      .collection(InvitationModel.collection.name)
      .updateMany(
        { status: 'PENDING', expiresAt: { $lte: now } },
        { $set: { status: 'EXPIRED', expiredAt: now } },
      );
  }

  if (preflight.vehiclesMissingStatusCount > 0) {
    log(
      `Backfilling missing structural fields on ${preflight.vehiclesMissingStatusCount} vehicle(s)`,
    );
    await backfillMissingStructuralFields(
      db,
      VehicleModel.collection.name,
      VEHICLE_STRUCTURAL_DEFAULTS,
    );
  }

  if (preflight.membershipsMissingStatusCount > 0) {
    log(
      `Backfilling missing structural fields on ${preflight.membershipsMissingStatusCount} membership(s)`,
    );
    await backfillMissingStructuralFields(
      db,
      MembershipModel.collection.name,
      MEMBERSHIP_STRUCTURAL_DEFAULTS,
    );
  }

  if (preflight.invitationsMissingTargetRoleCount > 0) {
    log(
      `Backfilling missing structural fields on ${preflight.invitationsMissingTargetRoleCount} invitation(s)`,
    );
    await backfillMissingStructuralFields(
      db,
      InvitationModel.collection.name,
      INVITATION_STRUCTURAL_DEFAULTS,
    );
  }
  await options.onStep?.('after_backfill_documents');

  // Create replacement partial unique & query indexes BEFORE dropping legacy membership unique index
  // so there is zero operational window where duplicate active memberships could be inserted.
  await ensureDeclaredVehicleIndexesOnDb(db);
  await options.onStep?.('after_create_replacement_indexes');

  for (const indexName of preflight.legacyUnfilteredMembershipUniqueIndexNames) {
    log(`Dropping legacy unfiltered unique index on memberships: ${indexName}`);
    await dropIndexIdempotent(db, MembershipModel.collection.name, indexName);
  }

  await assertCriticalVehicleIndexes(db);

  return inspectVehicleMigrationPreflight(db, now);
}
