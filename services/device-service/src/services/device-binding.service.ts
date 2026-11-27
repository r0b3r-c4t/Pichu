import { Types } from 'mongoose';
import { runInDeviceTransaction } from '../database/transaction.js';
import {
  DeviceCredentialModel,
  isCredentialUsable,
  type DeviceCredential,
} from '../models/device-credential.model.js';
import { DeviceModel, type Device } from '../models/device.model.js';

const OBJECT_ID_PATTERN = /^[a-f0-9]{24}$/;

/**
 * Evidence that a device is effectively bound to a vehicle right now. It states facts owned by
 * Device only; it carries no user identity and is not an authorization decision.
 */
export interface EffectiveDeviceBinding {
  readonly deviceId: string;
  readonly vehicleId: string;
  readonly credentialId: string;
  readonly keyId: string;
  readonly fingerprint: string;
  readonly linkedAt: Date | null;
  readonly evaluatedAt: Date;
}

/**
 * Internal lookup (no HTTP endpoint yet). Returns evidence only for an ACTIVE device without
 * revocation fields, with a vehicle and link actor, and exactly one usable credential, read from
 * one snapshot. Anything else, including inconsistent states, yields null.
 *
 * Consistency limit: the result is a point-in-time read. It holds no lock and may be stale as soon
 * as it is returned; it is not a guarantee against cross-service TOCTOU. Device-local mutations
 * must re-check their own conditions inside their write transaction.
 */
export async function findEffectiveDeviceBinding(
  deviceId: string,
  options: { now?: Date } = {},
): Promise<EffectiveDeviceBinding | null> {
  if (!OBJECT_ID_PATTERN.test(deviceId)) return null;
  const id = new Types.ObjectId(deviceId);
  const now = options.now ?? new Date();
  return runInDeviceTransaction(async (session) => {
    const device = await DeviceModel.findOne({
      _id: id,
      status: 'ACTIVE',
      revokedAt: null,
      revocationId: null,
      vehicleId: { $ne: null },
      linkedByUserId: { $ne: null },
    })
      .session(session)
      .lean<Device & { _id: Types.ObjectId }>();
    if (!device?.vehicleId) return null;
    const credentials = await DeviceCredentialModel.find({ deviceId: id, status: 'ACTIVE' })
      .limit(2)
      .session(session)
      .lean<Array<DeviceCredential & { _id: Types.ObjectId }>>();
    const [credential] = credentials;
    if (
      credentials.length !== 1 ||
      !credential ||
      !credential.deviceId.equals(id) ||
      credential.algorithm !== 'Ed25519' ||
      !isCredentialUsable(credential, now)
    ) {
      return null;
    }
    return Object.freeze({
      deviceId: String(device._id),
      vehicleId: String(device.vehicleId),
      credentialId: String(credential._id),
      keyId: credential.keyId,
      fingerprint: credential.fingerprint,
      linkedAt: device.linkedAt ?? null,
      evaluatedAt: now,
    });
  });
}
