import { createHash, randomBytes, verify } from 'node:crypto';
import { DeviceLinkChallengeModel } from '../models/device-link-challenge.model.js';
import { DeviceModel } from '../models/device.model.js';
import { Types } from 'mongoose';

export class DeviceLinkServiceError extends Error {}
function hash(value: string) {
  return createHash('sha256').update(value).digest('hex');
}

export async function createDeviceChallenge(input: {
  deviceId: Types.ObjectId;
  vehicleId: Types.ObjectId;
  userId: Types.ObjectId;
}) {
  const raw = randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + 5 * 60_000);
  await DeviceLinkChallengeModel.create({ challengeHash: hash(raw), ...input, expiresAt });
  return { challenge: raw, expiresAt };
}

export async function completeDeviceLink(input: { challenge: string; signature: string }) {
  const challenge = await DeviceLinkChallengeModel.findOne({
    challengeHash: hash(input.challenge),
    usedAt: null,
    expiresAt: { $gt: new Date() },
  }).select('+challengeHash');
  if (!challenge) return false;
  const device = await DeviceModel.findById(challenge.deviceId).select('+publicKey');
  if (!device || device.status === 'REVOKED') return false;
  const valid = verify(
    null,
    Buffer.from(input.challenge),
    device.publicKey,
    Buffer.from(input.signature, 'base64url'),
  );
  if (!valid) return false;
  const consumed = await DeviceLinkChallengeModel.updateOne(
    { _id: challenge._id, usedAt: null, expiresAt: { $gt: new Date() } },
    { $set: { usedAt: new Date() } },
  );
  if (consumed.modifiedCount !== 1) return false;
  const updated = await DeviceModel.updateOne(
    { _id: challenge.deviceId, status: 'PENDING' },
    {
      $set: { vehicleId: challenge.vehicleId, linkedByUserId: challenge.userId, status: 'ACTIVE' },
    },
  );
  return updated.modifiedCount === 1;
}
