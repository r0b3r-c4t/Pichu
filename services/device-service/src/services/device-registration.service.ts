import { randomBytes } from 'node:crypto';
import { Types } from 'mongoose';
import {
  deviceMetadataInputSchema,
  type DeviceMetadataInput,
  type InternalDeviceRecord,
} from '@pichu/contracts';
import { runInDeviceTransaction } from '../database/transaction.js';
import { DeviceCredentialModel } from '../models/device-credential.model.js';
import { DeviceModel, emptyDeviceMetadata } from '../models/device.model.js';
import {
  parseDevicePublicKey,
  type CanonicalDevicePublicKey,
} from '../security/device-public-key.js';
import { DeviceServiceError, duplicateKeyIndexName, isDuplicateKeyError } from './device-errors.js';
import { loadInternalDeviceInSession } from './device-query.service.js';

const KEY_ID_INDEX = 'device_credential_key_id_unique';
const CONFLICT_INDEXES = new Set(['identifier_1', 'device_credential_fingerprint_unique']);
const KEY_ID_ATTEMPTS = 3;

export interface DeviceRegistrationInput {
  identifier: string;
  publicKey: string;
  vehicleId: string;
  /** Taken from the authenticated internal request, never from an end-user client. */
  requestedByUserId: string;
  /** Vehicle membership ID under which enrollment was authorized (null only for legacy tests). */
  requestedByMembershipId?: string | null;
  metadata?: DeviceMetadataInput;
}

export interface DeviceRegistrationResult {
  deviceId: Types.ObjectId;
  credentialId: Types.ObjectId;
  keyId: string;
  fingerprint: string;
  status: 'PENDING';
  record: InternalDeviceRecord;
}

export function generateDeviceKeyId(): string {
  return `dk_${randomBytes(16).toString('base64url')}`;
}

/**
 * Creates the PENDING device and its ACTIVE credential in one transaction, so neither can exist
 * without the other. Duplicate identifiers or keys (including revoked ones) are conflicts.
 */
export async function registerDevice(
  input: DeviceRegistrationInput,
  options: { now?: Date; generateKeyId?: () => string } = {},
): Promise<DeviceRegistrationResult> {
  let key: CanonicalDevicePublicKey;
  try {
    key = parseDevicePublicKey(input.publicKey);
  } catch {
    throw new DeviceServiceError('INVALID_DEVICE_KEY', 'Invalid device key');
  }
  const normalizedMetadata =
    input.metadata === undefined
      ? emptyDeviceMetadata()
      : { ...emptyDeviceMetadata(), ...deviceMetadataInputSchema.parse(input.metadata) };

  const now = options.now ?? new Date();
  const generateKeyId = options.generateKeyId ?? generateDeviceKeyId;
  const vehicleId = new Types.ObjectId(input.vehicleId);
  const requestedByUserId = new Types.ObjectId(input.requestedByUserId);
  const requestedByMembershipId = input.requestedByMembershipId
    ? new Types.ObjectId(input.requestedByMembershipId)
    : null;

  for (let attempt = 1; ; attempt += 1) {
    try {
      return await runInDeviceTransaction(async (session) => {
        const deviceId = new Types.ObjectId();
        const credentialId = new Types.ObjectId();
        const keyId = generateKeyId();
        await DeviceModel.create(
          [
            {
              _id: deviceId,
              identifier: input.identifier.trim(),
              vehicleId,
              requestedByUserId,
              requestedByMembershipId,
              status: 'PENDING',
              metadata: normalizedMetadata,
            },
          ],
          { session },
        );
        await DeviceCredentialModel.create(
          [
            {
              _id: credentialId,
              deviceId,
              keyId,
              algorithm: key.algorithm,
              publicKey: key.publicKeyPem,
              fingerprint: key.fingerprint,
              status: 'ACTIVE',
              activatedAt: now,
              expiresAt: null,
            },
          ],
          { session },
        );
        const record = await loadInternalDeviceInSession(deviceId, session, now);
        if (!record) {
          throw new DeviceServiceError('INCONSISTENT_DEVICE_STATE', 'Created device missing');
        }
        return {
          deviceId,
          credentialId,
          keyId,
          fingerprint: key.fingerprint,
          status: 'PENDING' as const,
          record,
        };
      });
    } catch (error) {
      if (isDuplicateKeyError(error)) {
        const index = duplicateKeyIndexName(error);
        if (index === KEY_ID_INDEX && attempt < KEY_ID_ATTEMPTS) continue;
        if (index !== undefined && CONFLICT_INDEXES.has(index)) {
          throw new DeviceServiceError('DEVICE_ALREADY_REGISTERED', 'Device already registered', {
            cause: error,
          });
        }
      }
      throw error;
    }
  }
}
