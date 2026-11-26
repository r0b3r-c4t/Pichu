import type mongoose from 'mongoose';
import { AccessGrantModel } from '../models/access-grant.model.js';
import { InvitationModel } from '../models/invitation.model.js';
import { MembershipModel } from '../models/membership.model.js';
import { VehicleModel } from '../models/vehicle.model.js';

type MongoDb = NonNullable<typeof mongoose.connection.db>;

export class VehicleSchemaNotReadyError extends Error {
  constructor(
    message: string,
    public readonly reasons: readonly string[] = [message],
  ) {
    super(message);
    this.name = 'VehicleSchemaNotReadyError';
  }
}

export const VEHICLE_DOMAIN_MODELS = [
  VehicleModel,
  MembershipModel,
  InvitationModel,
  AccessGrantModel,
] as const;

interface RawIndexInfo {
  name?: string;
  key?: Record<string, unknown>;
  unique?: boolean;
  sparse?: boolean;
  expireAfterSeconds?: number;
  partialFilterExpression?: Record<string, unknown>;
  collation?: { locale?: string };
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

function sameDocumentShape(actual: unknown, expected: Record<string, unknown>): boolean {
  if (typeof actual !== 'object' || actual === null) {
    return false;
  }
  const actualRecord = actual as Record<string, unknown>;
  const expectedKeys = Object.keys(expected);
  if (Object.keys(actualRecord).length !== expectedKeys.length) {
    return false;
  }
  return expectedKeys.every(
    (key) => JSON.stringify(actualRecord[key]) === JSON.stringify(expected[key]),
  );
}

function hasSafeDefaultOptions(index: RawIndexInfo): boolean {
  return (
    !index.sparse &&
    index.expireAfterSeconds === undefined &&
    (!index.collation || index.collation.locale === 'simple')
  );
}

function hasExactNonUniqueIndex(
  indexes: readonly RawIndexInfo[],
  name: string,
  key: Record<string, number>,
): boolean {
  return indexes.some(
    (index) =>
      index.name === name &&
      sameOrderedKeys(index.key, key) &&
      !index.unique &&
      !index.partialFilterExpression &&
      hasSafeDefaultOptions(index),
  );
}

function hasExactPartialUniqueIndex(
  indexes: readonly RawIndexInfo[],
  name: string,
  key: Record<string, number>,
  partialFilterExpression: Record<string, unknown>,
): boolean {
  return indexes.some(
    (index) =>
      index.name === name &&
      sameOrderedKeys(index.key, key) &&
      index.unique === true &&
      sameDocumentShape(index.partialFilterExpression, partialFilterExpression) &&
      hasSafeDefaultOptions(index),
  );
}

async function listCollectionIndexes(db: MongoDb, collectionName: string): Promise<RawIndexInfo[]> {
  try {
    return (await db
      .collection(collectionName)
      .listIndexes({ maxTimeMS: 500 })
      .toArray()) as RawIndexInfo[];
  } catch (error) {
    if (error instanceof Error && /NamespaceNotFound|ns does not exist/i.test(error.message)) {
      return [];
    }
    throw error;
  }
}

/**
 * Inspects effective MongoDB indexes without mutating schema state.
 * Validates exact index names, ordered key patterns, partial filter expressions,
 * and safety options (non-sparse, no TTL, simple collation).
 */
export async function findCriticalVehicleIndexIssues(db: MongoDb): Promise<string[]> {
  const [vehicleIndexes, membershipIndexes, invitationIndexes, grantIndexes] = await Promise.all([
    listCollectionIndexes(db, VehicleModel.collection.name),
    listCollectionIndexes(db, MembershipModel.collection.name),
    listCollectionIndexes(db, InvitationModel.collection.name),
    listCollectionIndexes(db, AccessGrantModel.collection.name),
  ]);

  const issues: string[] = [];

  if (
    !hasExactNonUniqueIndex(vehicleIndexes, 'vehicle_owner_status_created_idx', {
      ownerUserId: 1,
      status: 1,
      createdAt: 1,
      _id: 1,
    })
  ) {
    issues.push('Missing or invalid index vehicles.vehicle_owner_status_created_idx');
  }

  if (!hasExactNonUniqueIndex(vehicleIndexes, 'vehicle_status_id_idx', { status: 1, _id: 1 })) {
    issues.push('Missing or invalid index vehicles.vehicle_status_id_idx');
  }

  const hasIllegalUniqueOwnerIndex = vehicleIndexes.some(
    (index) => sameOrderedKeys(index.key, { ownerUserId: 1 }) && index.unique === true,
  );
  if (hasIllegalUniqueOwnerIndex) {
    issues.push('Illegal unique index on vehicles.ownerUserId blocks multi-vehicle ownership');
  }

  if (
    !hasExactPartialUniqueIndex(
      membershipIndexes,
      'membership_single_active_owner_unique',
      { vehicleId: 1 },
      { role: 'OWNER', status: 'ACTIVE' },
    )
  ) {
    issues.push(
      'Missing or invalid partial unique index memberships.membership_single_active_owner_unique',
    );
  }

  if (
    !hasExactPartialUniqueIndex(
      membershipIndexes,
      'membership_active_vehicle_user_unique',
      { vehicleId: 1, userId: 1 },
      { revokedAt: null },
    )
  ) {
    issues.push(
      'Missing or invalid partial unique index memberships.membership_active_vehicle_user_unique',
    );
  }

  if (
    !hasExactNonUniqueIndex(membershipIndexes, 'membership_user_status_vehicle_idx', {
      userId: 1,
      status: 1,
      vehicleId: 1,
    })
  ) {
    issues.push('Missing or invalid index memberships.membership_user_status_vehicle_idx');
  }

  if (
    !hasExactNonUniqueIndex(membershipIndexes, 'membership_vehicle_status_role_idx', {
      vehicleId: 1,
      status: 1,
      role: 1,
    })
  ) {
    issues.push('Missing or invalid index memberships.membership_vehicle_status_role_idx');
  }

  const hasLegacyUnfilteredMembershipUnique = membershipIndexes.some(
    (index) =>
      sameOrderedKeys(index.key, { vehicleId: 1, userId: 1 }) &&
      index.unique === true &&
      !index.partialFilterExpression,
  );
  if (hasLegacyUnfilteredMembershipUnique) {
    issues.push(
      'Legacy unfiltered unique index on memberships (vehicleId, userId) blocks re-membership after revocation',
    );
  }

  const hasIllegalUniqueUserIndex = membershipIndexes.some(
    (index) => sameOrderedKeys(index.key, { userId: 1 }) && index.unique === true,
  );
  if (hasIllegalUniqueUserIndex) {
    issues.push('Illegal unique index on memberships.userId blocks multi-vehicle membership');
  }

  if (
    !hasExactPartialUniqueIndex(
      invitationIndexes,
      'invitation_pending_vehicle_invitee_unique',
      { vehicleId: 1, inviteeUserId: 1 },
      { status: 'PENDING' },
    )
  ) {
    issues.push(
      'Missing or invalid partial unique index invitations.invitation_pending_vehicle_invitee_unique',
    );
  }

  if (
    !hasExactNonUniqueIndex(invitationIndexes, 'invitation_vehicle_status_created_idx', {
      vehicleId: 1,
      status: 1,
      createdAt: -1,
    })
  ) {
    issues.push('Missing or invalid index invitations.invitation_vehicle_status_created_idx');
  }

  if (
    !hasExactNonUniqueIndex(invitationIndexes, 'invitation_invitee_status_expires_idx', {
      inviteeUserId: 1,
      status: 1,
      expiresAt: 1,
    })
  ) {
    issues.push('Missing or invalid index invitations.invitation_invitee_status_expires_idx');
  }

  if (
    !hasExactNonUniqueIndex(invitationIndexes, 'invitation_status_expires_idx', {
      status: 1,
      expiresAt: 1,
    })
  ) {
    issues.push('Missing or invalid index invitations.invitation_status_expires_idx');
  }

  const hasDestructiveInvitationTtl = invitationIndexes.some(
    (index) => index.name !== '_id_' && index.expireAfterSeconds !== undefined,
  );
  if (hasDestructiveInvitationTtl) {
    issues.push(
      'Destructive legacy TTL index on invitations is still present; run explicit migration',
    );
  }

  if (
    !hasExactNonUniqueIndex(grantIndexes, 'access_grant_lookup_idx', {
      vehicleId: 1,
      subjectUserId: 1,
      status: 1,
      scopeType: 1,
      scopeResourceId: 1,
      expiresAt: 1,
    })
  ) {
    issues.push('Missing or invalid index access_grants.access_grant_lookup_idx');
  }

  if (
    !hasExactNonUniqueIndex(grantIndexes, 'access_grant_membership_status_idx', {
      membershipId: 1,
      status: 1,
    })
  ) {
    issues.push('Missing or invalid index access_grants.access_grant_membership_status_idx');
  }

  if (
    !hasExactNonUniqueIndex(grantIndexes, 'access_grant_resource_status_idx', {
      vehicleId: 1,
      scopeType: 1,
      scopeResourceId: 1,
      status: 1,
    })
  ) {
    issues.push('Missing or invalid index access_grants.access_grant_resource_status_idx');
  }

  if (
    !hasExactNonUniqueIndex(grantIndexes, 'access_grant_status_expires_idx', {
      status: 1,
      expiresAt: 1,
    })
  ) {
    issues.push('Missing or invalid index access_grants.access_grant_status_expires_idx');
  }

  const hasRestrictiveUniqueGrantIndex = grantIndexes.some(
    (index) => index.name !== '_id_' && index.unique === true,
  );
  if (hasRestrictiveUniqueGrantIndex) {
    issues.push(
      'Illegal unique index on access_grants restricts multiple grants per scope/channel',
    );
  }

  return issues;
}

export async function assertCriticalVehicleIndexes(db: MongoDb): Promise<void> {
  let issues: string[];
  try {
    issues = await findCriticalVehicleIndexIssues(db);
  } catch {
    throw new VehicleSchemaNotReadyError('Unable to verify critical Vehicle database indexes');
  }

  if (issues.length > 0) {
    throw new VehicleSchemaNotReadyError(
      `Critical Vehicle database indexes are not ready: ${issues.join('; ')}`,
      issues,
    );
  }
}

/**
 * Creates missing collections and declared indexes in non-production environments.
 * Never runs destructive syncIndexes() or drops existing indexes automatically.
 */
export async function ensureDevelopmentDatabaseSchema(
  log: (message: string) => void = console.info,
): Promise<void> {
  for (const model of VEHICLE_DOMAIN_MODELS) {
    log(`Verifying collection: ${model.collection.name}`);

    try {
      await model.createCollection();
    } catch (error) {
      if (!(error instanceof Error) || !/already exists|NamespaceExists/i.test(error.message)) {
        throw error;
      }
    }

    log(`Verifying indexes: ${model.collection.name}`);

    await model.createIndexes();

    log(`Database schema ready: ${model.collection.name}`);
  }
}
