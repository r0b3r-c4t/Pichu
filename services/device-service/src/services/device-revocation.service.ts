import { Types, type ClientSession } from 'mongoose';
import type { InternalPrincipal } from '@pichu/internal-auth-adapters/types';
import { runInDeviceTransaction } from '../database/transaction.js';
import { DeviceCredentialModel } from '../models/device-credential.model.js';
import {
  DEVICE_REVOCATION_REASONS,
  DEVICE_REVOCATION_REQUEST_ID_PATTERN,
  DeviceRevocationModel,
  TRUSTED_REVOCATION_SERVICES,
  type DeviceRevocation,
  type DeviceRevocationReason,
  type TrustedRevocationService,
} from '../models/device-revocation.model.js';
import { DeviceModel } from '../models/device.model.js';
import { DeviceServiceError, duplicateKeyIndexName, isDuplicateKeyError } from './device-errors.js';

const OBJECT_ID_PATTERN = /^[a-f0-9]{24}$/;

export type RevocationActor = Readonly<
  | { type: 'USER'; userId: Types.ObjectId; service: TrustedRevocationService }
  | { type: 'SERVICE'; userId: null; service: TrustedRevocationService }
  | { type: 'SYSTEM'; userId: null; service: null }
>;

/** Actors can only be minted by the constructors below; client-declared objects are rejected. */
const trustedActors = new WeakSet<object>();

function mint(actor: RevocationActor): RevocationActor {
  const frozen = Object.freeze({ ...actor });
  trustedActors.add(frozen);
  return frozen;
}

function isTrustedService(sender: string): sender is TrustedRevocationService {
  return (TRUSTED_REVOCATION_SERVICES as readonly string[]).includes(sender);
}

/**
 * Builds an actor from an HMAC-verified internal principal. The service is authenticated; the
 * optional user is an assertion made by that service after its own authorization decision.
 */
export function revocationActorFromInternalPrincipal(
  principal: InternalPrincipal,
  assertedUserId?: string,
): RevocationActor {
  if (!isTrustedService(principal.sender)) {
    throw new DeviceServiceError('UNTRUSTED_REVOCATION_ACTOR', 'Untrusted revocation actor');
  }
  if (assertedUserId === undefined) {
    return mint({ type: 'SERVICE', userId: null, service: principal.sender });
  }
  if (!OBJECT_ID_PATTERN.test(assertedUserId)) {
    throw new DeviceServiceError('UNTRUSTED_REVOCATION_ACTOR', 'Untrusted revocation actor');
  }
  return mint({
    type: 'USER',
    userId: new Types.ObjectId(assertedUserId),
    service: principal.sender,
  });
}

/** For in-process maintenance (e.g. operator-run scripts), never for request handling. */
export function systemRevocationActor(): RevocationActor {
  return mint({ type: 'SYSTEM', userId: null, service: null });
}

export interface DeviceRevocationOutcome {
  revocation: DeviceRevocation & { _id: Types.ObjectId };
  /** false when an earlier revocation already covered the target; its audit is preserved. */
  created: boolean;
}

interface RevocationCommon {
  reason: DeviceRevocationReason;
  actor: RevocationActor;
  requestId: string;
}

function parseObjectId(value: string, code: 'DEVICE_NOT_FOUND' | 'CREDENTIAL_NOT_FOUND') {
  if (!OBJECT_ID_PATTERN.test(value)) {
    throw new DeviceServiceError(
      code,
      code === 'DEVICE_NOT_FOUND' ? 'Device not found' : 'Credential not found',
    );
  }
  return new Types.ObjectId(value);
}

function validateCommon(input: RevocationCommon): void {
  if (!trustedActors.has(input.actor)) {
    throw new DeviceServiceError('UNTRUSTED_REVOCATION_ACTOR', 'Untrusted revocation actor');
  }
  if (
    !(DEVICE_REVOCATION_REASONS as readonly string[]).includes(input.reason) ||
    !DEVICE_REVOCATION_REQUEST_ID_PATTERN.test(input.requestId)
  ) {
    throw new DeviceServiceError('INVALID_REVOCATION_REQUEST', 'Invalid revocation request');
  }
}

function actorRecord(actor: RevocationActor) {
  return { type: actor.type, userId: actor.userId, service: actor.service };
}

function inconsistent(): DeviceServiceError {
  return new DeviceServiceError('INCONSISTENT_DEVICE_STATE', 'Inconsistent device state');
}

async function findRevocation(filter: Record<string, unknown>, session?: ClientSession) {
  return DeviceRevocationModel.findOne(filter, null, session ? { session } : {}).lean<
    DeviceRevocation & { _id: Types.ObjectId }
  >();
}

/**
 * Revokes the device and every ACTIVE credential atomically. REVOKED is terminal; repeating the
 * call returns the original record unchanged. There is no reactivation path.
 */
export async function revokeDevice(
  input: RevocationCommon & { deviceId: string },
  options: { now?: Date } = {},
): Promise<DeviceRevocationOutcome> {
  validateCommon(input);
  const deviceId = parseObjectId(input.deviceId, 'DEVICE_NOT_FOUND');
  const now = options.now ?? new Date();
  try {
    return await runInDeviceTransaction(async (session) => {
      const existing = await findRevocation({ targetType: 'DEVICE', deviceId }, session);
      if (existing) return { revocation: existing, created: false };

      const device = await DeviceModel.findById(deviceId).session(session);
      if (!device) throw new DeviceServiceError('DEVICE_NOT_FOUND', 'Device not found');
      if (device.status === 'REVOKED') throw inconsistent();
      const active = await DeviceCredentialModel.findOne({ deviceId, status: 'ACTIVE' }).session(
        session,
      );

      const revocationId = new Types.ObjectId();
      const [record] = await DeviceRevocationModel.create(
        [
          {
            _id: revocationId,
            targetType: 'DEVICE',
            deviceId,
            credentialId: null,
            fingerprint: active?.fingerprint ?? null,
            vehicleId: device.vehicleId,
            reason: input.reason,
            actor: actorRecord(input.actor),
            requestId: input.requestId,
            revokedAt: now,
          },
        ],
        { session },
      );
      const updated = await DeviceModel.updateOne(
        { _id: deviceId, status: { $in: ['PENDING', 'ACTIVE'] }, revocationId: null },
        { $set: { status: 'REVOKED', revokedAt: now, revocationId } },
        { session },
      );
      if (updated.modifiedCount !== 1) throw inconsistent();
      await DeviceCredentialModel.updateMany(
        { deviceId, status: 'ACTIVE' },
        { $set: { status: 'REVOKED', revokedAt: now, revocationId } },
        { session },
      );
      return { revocation: record!.toObject(), created: true };
    });
  } catch (error) {
    if (
      isDuplicateKeyError(error) &&
      duplicateKeyIndexName(error) === 'device_revocation_device_target_unique'
    ) {
      const existing = await findRevocation({ targetType: 'DEVICE', deviceId });
      if (existing) return { revocation: existing, created: false };
    }
    throw error;
  }
}

/**
 * Revokes one credential that must belong exactly to `deviceId`. The device link state is not
 * changed, but without a usable credential the device is no longer operational.
 */
export async function revokeDeviceCredential(
  input: RevocationCommon & { deviceId: string; credentialId: string },
  options: { now?: Date } = {},
): Promise<DeviceRevocationOutcome> {
  validateCommon(input);
  const deviceId = parseObjectId(input.deviceId, 'DEVICE_NOT_FOUND');
  const credentialId = parseObjectId(input.credentialId, 'CREDENTIAL_NOT_FOUND');
  const now = options.now ?? new Date();
  const notFound = () => new DeviceServiceError('CREDENTIAL_NOT_FOUND', 'Credential not found');
  try {
    return await runInDeviceTransaction(async (session) => {
      const existing = await findRevocation({ targetType: 'CREDENTIAL', credentialId }, session);
      if (existing) {
        if (!existing.deviceId.equals(deviceId)) throw notFound();
        return { revocation: existing, created: false };
      }

      const credential = await DeviceCredentialModel.findOne({
        _id: credentialId,
        deviceId,
      }).session(session);
      if (!credential) throw notFound();
      if (credential.status === 'REVOKED') {
        const prior = credential.revocationId
          ? await findRevocation({ _id: credential.revocationId, deviceId }, session)
          : null;
        if (!prior) throw inconsistent();
        return { revocation: prior, created: false };
      }
      const device = await DeviceModel.findById(deviceId).session(session);
      if (!device) throw inconsistent();

      const revocationId = new Types.ObjectId();
      const [record] = await DeviceRevocationModel.create(
        [
          {
            _id: revocationId,
            targetType: 'CREDENTIAL',
            deviceId,
            credentialId,
            fingerprint: credential.fingerprint,
            vehicleId: device.vehicleId,
            reason: input.reason,
            actor: actorRecord(input.actor),
            requestId: input.requestId,
            revokedAt: now,
          },
        ],
        { session },
      );
      const updated = await DeviceCredentialModel.updateOne(
        { _id: credentialId, deviceId, status: 'ACTIVE' },
        { $set: { status: 'REVOKED', revokedAt: now, revocationId } },
        { session },
      );
      if (updated.modifiedCount !== 1) throw inconsistent();
      return { revocation: record!.toObject(), created: true };
    });
  } catch (error) {
    if (
      isDuplicateKeyError(error) &&
      duplicateKeyIndexName(error) === 'device_revocation_credential_target_unique'
    ) {
      const existing = await findRevocation({ targetType: 'CREDENTIAL', credentialId });
      if (existing?.deviceId.equals(deviceId)) return { revocation: existing, created: false };
    }
    throw error;
  }
}
