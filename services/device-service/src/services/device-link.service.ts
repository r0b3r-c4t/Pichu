import { createHash, randomBytes } from 'node:crypto';
import { Types } from 'mongoose';
import {
  DEVICE_LINK_PROTOCOL_VERSION,
  type DeviceLinkChallenge as PublicDeviceLinkChallenge,
  type InternalDeviceRecord,
} from '@pichu/contracts';
import { runInDeviceTransaction } from '../database/transaction.js';
import { DeviceCredentialModel, isCredentialUsable } from '../models/device-credential.model.js';
import { DeviceLinkChallengeModel } from '../models/device-link-challenge.model.js';
import { DeviceModel } from '../models/device.model.js';
import {
  buildDeviceLinkProofMessage,
  CANONICAL_CHALLENGE_NONCE_PATTERN,
  verifyDeviceSignature,
} from '../security/device-public-key.js';
import { loadInternalDeviceInSession } from './device-query.service.js';

export const DEVICE_LINK_CHALLENGE_TTL_MS = 5 * 60_000;
const OBJECT_ID_PATTERN = /^[a-f0-9]{24}$/;
const CANONICAL_SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{85}[AQgw]$/;

function hashChallenge(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function toObjectId(value: string | Types.ObjectId): Types.ObjectId | null {
  if (value instanceof Types.ObjectId) return value;
  return OBJECT_ID_PATTERN.test(value) ? new Types.ObjectId(value) : null;
}

export type DeviceChallengeFailureReason =
  | 'DEVICE_NOT_FOUND'
  | 'DEVICE_NOT_LINKABLE'
  | 'UNVERIFIABLE_ENROLLMENT_CONTEXT'
  | 'ACTOR_MISMATCH'
  | 'CREDENTIAL_UNAVAILABLE';

export type DeviceChallengeOutcome =
  | {
      ok: true;
      challengeId: string;
      challenge: string;
      expiresAt: Date;
      data: PublicDeviceLinkChallenge;
    }
  | { ok: false; reason: DeviceChallengeFailureReason };

class DeviceChallengeAbort extends Error {
  constructor(readonly reason: DeviceChallengeFailureReason) {
    super('Device challenge aborted');
  }
}

/**
 * Issues a single-use challenge bound to the device, its expected vehicle, its usable credential,
 * the original requester, and the original Vehicle membership ID.
 *
 * Concurrency guarantee: touches the parent `Device` document inside the `snapshot` transaction
 * before invalidating prior unused challenges and inserting the new one, forcing WiredTiger to
 * serialize concurrent challenge issuances (as well as concurrent link/revocation mutations) so at
 * most one unused challenge can remain active per device.
 */
export async function createDeviceChallenge(
  input: {
    deviceId: string | Types.ObjectId;
    vehicleId: string | Types.ObjectId;
    requestedByUserId: string | Types.ObjectId;
    requestedByMembershipId: string | Types.ObjectId;
  },
  options: { now?: Date } = {},
): Promise<DeviceChallengeOutcome> {
  const deviceId = toObjectId(input.deviceId);
  const vehicleId = toObjectId(input.vehicleId);
  const actor = toObjectId(input.requestedByUserId);
  const actorMembership = toObjectId(input.requestedByMembershipId);
  if (!deviceId || !vehicleId || !actor || !actorMembership) {
    return { ok: false, reason: 'DEVICE_NOT_FOUND' };
  }
  const now = options.now ?? new Date();

  try {
    return await runInDeviceTransaction<DeviceChallengeOutcome>(async (session) => {
      const device = await DeviceModel.findById(deviceId).session(session);
      if (!device || !device.vehicleId?.equals(vehicleId)) {
        return { ok: false, reason: 'DEVICE_NOT_FOUND' };
      }
      if (
        device.status !== 'PENDING' ||
        device.revokedAt !== null ||
        device.revocationId !== null
      ) {
        return { ok: false, reason: 'DEVICE_NOT_LINKABLE' };
      }
      if (!device.requestedByUserId || !device.requestedByMembershipId) {
        return { ok: false, reason: 'UNVERIFIABLE_ENROLLMENT_CONTEXT' };
      }
      if (
        !device.requestedByUserId.equals(actor) ||
        !device.requestedByMembershipId.equals(actorMembership)
      ) {
        return { ok: false, reason: 'ACTOR_MISMATCH' };
      }

      const credential = await DeviceCredentialModel.findOne({
        deviceId,
        status: 'ACTIVE',
      }).session(session);
      if (!credential || !isCredentialUsable(credential, now)) {
        return { ok: false, reason: 'CREDENTIAL_UNAVAILABLE' };
      }

      // Write barrier on parent Device document so concurrent challenge issuances conflict & retry.
      const barrier = await DeviceModel.updateOne(
        {
          _id: deviceId,
          vehicleId,
          status: 'PENDING',
          revokedAt: null,
          revocationId: null,
          requestedByUserId: actor,
          requestedByMembershipId: actorMembership,
        },
        { $currentDate: { updatedAt: true } },
        { session, timestamps: false },
      );
      if (barrier.matchedCount !== 1) {
        throw new DeviceChallengeAbort('DEVICE_NOT_LINKABLE');
      }

      // Invalidate every prior pending challenge on this device before inserting the new one.
      await DeviceLinkChallengeModel.updateMany(
        { deviceId, usedAt: null },
        { $set: { usedAt: now } },
        { session },
      );

      const challenge = randomBytes(32).toString('base64url');
      const expiresAt = new Date(now.getTime() + DEVICE_LINK_CHALLENGE_TTL_MS);
      const [created] = await DeviceLinkChallengeModel.create(
        [
          {
            challengeHash: hashChallenge(challenge),
            deviceId,
            credentialId: credential._id,
            vehicleId,
            requestedByUserId: actor,
            requestedByMembershipId: actorMembership,
            expiresAt,
          },
        ],
        { session },
      );
      const challengeId = String(created!._id);
      return {
        ok: true,
        challengeId,
        challenge,
        expiresAt,
        data: {
          protocol: DEVICE_LINK_PROTOCOL_VERSION,
          challengeId,
          deviceId: String(deviceId),
          vehicleId: String(vehicleId),
          credentialId: String(credential._id),
          requestedByUserId: String(actor),
          challenge,
          expiresAt: expiresAt.toISOString(),
        },
      };
    });
  } catch (error) {
    if (error instanceof DeviceChallengeAbort) {
      return { ok: false, reason: error.reason };
    }
    throw error;
  }
}

export type DeviceLinkFailureReason =
  | 'DEVICE_NOT_FOUND'
  | 'INVALID_CHALLENGE'
  | 'ACTOR_MISMATCH'
  | 'CREDENTIAL_UNAVAILABLE'
  | 'INVALID_PROOF'
  | 'UNVERIFIABLE_ENROLLMENT_CONTEXT'
  | 'DEVICE_NOT_LINKABLE';

export type DeviceLinkResult =
  | {
      linked: true;
      deviceId: string;
      vehicleId: string;
      linkedAt: Date;
      record: InternalDeviceRecord;
    }
  | { linked: false; reason: DeviceLinkFailureReason };

class DeviceLinkAbort extends Error {
  constructor(readonly reason: DeviceLinkFailureReason) {
    super('Device link aborted');
  }
}

/**
 * Verifies the device's Ed25519 signature over the canonical `pichu-device-link-v1` message
 * reconstructed exclusively from authoritative challenge state, then consumes the challenge and
 * activates the link in one transaction with conditional writes.
 */
export async function completeDeviceLink(
  input: {
    deviceId: string;
    vehicleId: string;
    challengeId: string;
    challenge: string;
    signature: string;
    actorUserId: string;
    actorMembershipId: string;
  },
  options: { now?: Date } = {},
): Promise<DeviceLinkResult> {
  const expectedDeviceId = toObjectId(input.deviceId);
  const expectedVehicleId = toObjectId(input.vehicleId);
  const challengeId = toObjectId(input.challengeId);
  const actor = toObjectId(input.actorUserId);
  const actorMembership = toObjectId(input.actorMembershipId);

  if (!expectedDeviceId || !expectedVehicleId) {
    return { linked: false, reason: 'DEVICE_NOT_FOUND' };
  }
  if (!actor || !actorMembership) {
    return { linked: false, reason: 'ACTOR_MISMATCH' };
  }
  if (!challengeId || !CANONICAL_CHALLENGE_NONCE_PATTERN.test(input.challenge)) {
    return { linked: false, reason: 'INVALID_CHALLENGE' };
  }
  if (!CANONICAL_SIGNATURE_PATTERN.test(input.signature)) {
    return { linked: false, reason: 'INVALID_PROOF' };
  }
  const now = options.now ?? new Date();

  try {
    return await runInDeviceTransaction<DeviceLinkResult>(async (session) => {
      const device = await DeviceModel.findById(expectedDeviceId).session(session);
      if (!device || !device.vehicleId?.equals(expectedVehicleId)) {
        return { linked: false, reason: 'DEVICE_NOT_FOUND' };
      }
      if (
        device.status !== 'PENDING' ||
        device.revokedAt !== null ||
        device.revocationId !== null
      ) {
        return { linked: false, reason: 'DEVICE_NOT_LINKABLE' };
      }
      if (!device.requestedByUserId || !device.requestedByMembershipId) {
        return { linked: false, reason: 'UNVERIFIABLE_ENROLLMENT_CONTEXT' };
      }
      if (
        !device.requestedByUserId.equals(actor) ||
        !device.requestedByMembershipId.equals(actorMembership)
      ) {
        return { linked: false, reason: 'ACTOR_MISMATCH' };
      }

      const challenge = await DeviceLinkChallengeModel.findOne({
        _id: challengeId,
        deviceId: expectedDeviceId,
        vehicleId: expectedVehicleId,
        challengeHash: hashChallenge(input.challenge),
        usedAt: null,
        expiresAt: { $gt: now },
      }).session(session);
      if (!challenge) return { linked: false, reason: 'INVALID_CHALLENGE' };
      if (
        !challenge.requestedByUserId.equals(actor) ||
        !challenge.requestedByMembershipId?.equals(actorMembership)
      ) {
        return { linked: false, reason: 'ACTOR_MISMATCH' };
      }

      const credential = await DeviceCredentialModel.findOne({
        _id: challenge.credentialId,
        deviceId: challenge.deviceId,
      })
        .select('+publicKey')
        .session(session);
      if (!credential || !isCredentialUsable(credential, now)) {
        return { linked: false, reason: 'CREDENTIAL_UNAVAILABLE' };
      }

      const canonicalMessage = buildDeviceLinkProofMessage({
        deviceId: String(challenge.deviceId),
        vehicleId: String(challenge.vehicleId),
        credentialId: String(challenge.credentialId),
        requestedByUserId: String(challenge.requestedByUserId),
        challengeId: String(challenge._id),
        challenge: input.challenge,
      });
      if (!verifyDeviceSignature(credential.publicKey, canonicalMessage, input.signature)) {
        return { linked: false, reason: 'INVALID_PROOF' };
      }

      const consumed = await DeviceLinkChallengeModel.updateOne(
        { _id: challenge._id, usedAt: null, expiresAt: { $gt: now } },
        { $set: { usedAt: now } },
        { session },
      );
      if (consumed.modifiedCount !== 1) return { linked: false, reason: 'INVALID_CHALLENGE' };

      await DeviceLinkChallengeModel.updateMany(
        { deviceId: challenge.deviceId, usedAt: null },
        { $set: { usedAt: now } },
        { session },
      );

      const credentialGuard = await DeviceCredentialModel.updateOne(
        { _id: credential._id, deviceId: challenge.deviceId, status: 'ACTIVE' },
        { $currentDate: { updatedAt: true } },
        { session, timestamps: false },
      );
      if (credentialGuard.matchedCount !== 1) throw new DeviceLinkAbort('CREDENTIAL_UNAVAILABLE');

      const linked = await DeviceModel.updateOne(
        {
          _id: challenge.deviceId,
          status: 'PENDING',
          revokedAt: null,
          revocationId: null,
          vehicleId: challenge.vehicleId,
          requestedByUserId: challenge.requestedByUserId,
          requestedByMembershipId: challenge.requestedByMembershipId,
        },
        { $set: { status: 'ACTIVE', linkedByUserId: actor, linkedAt: now } },
        { session },
      );
      if (linked.modifiedCount !== 1) throw new DeviceLinkAbort('DEVICE_NOT_LINKABLE');

      const record = await loadInternalDeviceInSession(challenge.deviceId, session, now);
      if (!record) throw new DeviceLinkAbort('DEVICE_NOT_LINKABLE');

      return {
        linked: true,
        deviceId: String(challenge.deviceId),
        vehicleId: String(challenge.vehicleId),
        linkedAt: now,
        record,
      };
    });
  } catch (error) {
    if (error instanceof DeviceLinkAbort) return { linked: false, reason: error.reason };
    throw error;
  }
}
