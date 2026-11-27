import { createHash, randomBytes } from 'node:crypto';
import { Types } from 'mongoose';
import { runInDeviceTransaction } from '../database/transaction.js';
import { DeviceCredentialModel, isCredentialUsable } from '../models/device-credential.model.js';
import { DeviceLinkChallengeModel } from '../models/device-link-challenge.model.js';
import { DeviceModel } from '../models/device.model.js';
import { verifyDeviceSignature } from '../security/device-public-key.js';

export const DEVICE_LINK_CHALLENGE_TTL_MS = 5 * 60_000;
const OBJECT_ID_PATTERN = /^[a-f0-9]{24}$/;

function hashChallenge(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function toObjectId(value: string | Types.ObjectId): Types.ObjectId | null {
  if (value instanceof Types.ObjectId) return value;
  return OBJECT_ID_PATTERN.test(value) ? new Types.ObjectId(value) : null;
}

export interface DeviceLinkChallengeResult {
  challengeId: string;
  /** Returned once to the caller; only its SHA-256 is persisted. */
  challenge: string;
  expiresAt: Date;
}

/**
 * Issues a challenge bound to the device, its requested vehicle, its usable credential and the
 * requesting actor. Returns null when the device is not linkable by that actor. This does not
 * re-authorize the actor against Vehicle; callers must do so before invoking it.
 */
export async function createDeviceChallenge(
  input: { deviceId: string | Types.ObjectId; requestedByUserId: string | Types.ObjectId },
  options: { now?: Date } = {},
): Promise<DeviceLinkChallengeResult | null> {
  const deviceId = toObjectId(input.deviceId);
  const actor = toObjectId(input.requestedByUserId);
  if (!deviceId || !actor) return null;
  const now = options.now ?? new Date();

  return runInDeviceTransaction(async (session) => {
    const device = await DeviceModel.findOne({
      _id: deviceId,
      status: 'PENDING',
      revokedAt: null,
      revocationId: null,
    }).session(session);
    if (!device?.vehicleId || !device.requestedByUserId?.equals(actor)) return null;
    const credential = await DeviceCredentialModel.findOne({
      deviceId,
      status: 'ACTIVE',
    }).session(session);
    if (!credential || !isCredentialUsable(credential, now)) return null;

    const challenge = randomBytes(32).toString('base64url');
    const expiresAt = new Date(now.getTime() + DEVICE_LINK_CHALLENGE_TTL_MS);
    const [created] = await DeviceLinkChallengeModel.create(
      [
        {
          challengeHash: hashChallenge(challenge),
          deviceId,
          credentialId: credential._id,
          vehicleId: device.vehicleId,
          requestedByUserId: actor,
          expiresAt,
        },
      ],
      { session },
    );
    return { challengeId: String(created!._id), challenge, expiresAt };
  });
}

export type DeviceLinkFailureReason =
  | 'INVALID_CHALLENGE'
  | 'ACTOR_MISMATCH'
  | 'CREDENTIAL_UNAVAILABLE'
  | 'INVALID_PROOF'
  | 'DEVICE_NOT_LINKABLE';

export type DeviceLinkResult =
  | { linked: true; deviceId: string; vehicleId: string; linkedAt: Date }
  | { linked: false; reason: DeviceLinkFailureReason };

class DeviceLinkAbort extends Error {
  constructor(readonly reason: DeviceLinkFailureReason) {
    super('Device link aborted');
  }
}

/**
 * Verifies the device's Ed25519 proof with its DeviceCredential only, then consumes the challenge
 * and activates the link in one transaction with conditional writes. The credential is touched
 * inside the transaction so a concurrent credential revocation conflicts instead of interleaving.
 */
export async function completeDeviceLink(
  input: { challengeId: string; challenge: string; signature: string; actorUserId: string },
  options: { now?: Date } = {},
): Promise<DeviceLinkResult> {
  const challengeId = toObjectId(input.challengeId);
  const actor = toObjectId(input.actorUserId);
  if (!challengeId || !actor || input.challenge.length < 32 || input.challenge.length > 512) {
    return { linked: false, reason: 'INVALID_CHALLENGE' };
  }
  const now = options.now ?? new Date();

  try {
    return await runInDeviceTransaction<DeviceLinkResult>(async (session) => {
      const challenge = await DeviceLinkChallengeModel.findOne({
        _id: challengeId,
        challengeHash: hashChallenge(input.challenge),
        usedAt: null,
        expiresAt: { $gt: now },
      }).session(session);
      if (!challenge) return { linked: false, reason: 'INVALID_CHALLENGE' };
      if (!challenge.requestedByUserId.equals(actor)) {
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
      if (
        !verifyDeviceSignature(credential.publicKey, Buffer.from(input.challenge), input.signature)
      ) {
        return { linked: false, reason: 'INVALID_PROOF' };
      }

      const consumed = await DeviceLinkChallengeModel.updateOne(
        { _id: challenge._id, usedAt: null, expiresAt: { $gt: now } },
        { $set: { usedAt: now } },
        { session },
      );
      if (consumed.modifiedCount !== 1) return { linked: false, reason: 'INVALID_CHALLENGE' };

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
        },
        { $set: { status: 'ACTIVE', linkedByUserId: actor, linkedAt: now } },
        { session },
      );
      if (linked.modifiedCount !== 1) throw new DeviceLinkAbort('DEVICE_NOT_LINKABLE');

      return {
        linked: true,
        deviceId: String(challenge.deviceId),
        vehicleId: String(challenge.vehicleId),
        linkedAt: now,
      };
    });
  } catch (error) {
    if (error instanceof DeviceLinkAbort) return { linked: false, reason: error.reason };
    throw error;
  }
}
