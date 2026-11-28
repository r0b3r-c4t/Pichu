import { Types } from 'mongoose';
import {
  DEVICE_METADATA_FIELDS,
  deviceMetadataUpdateRequestSchema,
  type DeviceMetadataUpdateRequest,
  type InternalDeviceRecord,
} from '@pichu/contracts';
import { runInDeviceTransaction } from '../database/transaction.js';
import { DeviceModel } from '../models/device.model.js';
import { DeviceServiceError } from './device-errors.js';
import { loadInternalDeviceInSession } from './device-query.service.js';

const OBJECT_ID_PATTERN = /^[a-f0-9]{24}$/;

export interface UpdateDeviceMetadataInput {
  deviceId: string;
  vehicleId: string;
  metadata: DeviceMetadataUpdateRequest;
}

/**
 * Partially updates descriptive metadata on a PENDING or ACTIVE device belonging to `vehicleId`.
 * REVOKED devices are terminal and reject metadata updates (`DEVICE_REVOKED`).
 */
export async function updateDeviceMetadata(
  input: UpdateDeviceMetadataInput,
  options: { now?: Date } = {},
): Promise<InternalDeviceRecord> {
  if (!OBJECT_ID_PATTERN.test(input.deviceId) || !OBJECT_ID_PATTERN.test(input.vehicleId)) {
    throw new DeviceServiceError('DEVICE_NOT_FOUND', 'Device not found');
  }
  const parsedMetadata = deviceMetadataUpdateRequestSchema.parse(input.metadata);
  const deviceId = new Types.ObjectId(input.deviceId);
  const vehicleId = new Types.ObjectId(input.vehicleId);
  const now = options.now ?? new Date();

  const setPaths: Record<string, string | null> = {};
  for (const field of DEVICE_METADATA_FIELDS) {
    const value = parsedMetadata[field];
    if (value !== undefined) {
      setPaths[`metadata.${field}`] = value;
    }
  }

  return runInDeviceTransaction(async (session) => {
    const existing = await DeviceModel.findById(deviceId).session(session);
    if (!existing || !existing.vehicleId?.equals(vehicleId)) {
      throw new DeviceServiceError('DEVICE_NOT_FOUND', 'Device not found');
    }
    if (
      existing.status === 'REVOKED' ||
      existing.revokedAt !== null ||
      existing.revocationId !== null
    ) {
      throw new DeviceServiceError('DEVICE_REVOKED', 'Revoked devices cannot be modified');
    }

    const updated = await DeviceModel.updateOne(
      {
        _id: deviceId,
        vehicleId,
        status: { $in: ['PENDING', 'ACTIVE'] },
        revokedAt: null,
        revocationId: null,
      },
      { $set: setPaths },
      { session },
    );
    if (updated.matchedCount !== 1) {
      throw new DeviceServiceError('DEVICE_REVOKED', 'Revoked devices cannot be modified');
    }

    const record = await loadInternalDeviceInSession(deviceId, session, now);
    if (!record) {
      throw new DeviceServiceError('INCONSISTENT_DEVICE_STATE', 'Updated device missing');
    }
    return record;
  });
}
