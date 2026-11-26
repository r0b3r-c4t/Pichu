import { DeviceLinkChallengeModel } from '../models/device-link-challenge.model.js';
import { DeviceModel } from '../models/device.model.js';

export async function ensureDevelopmentDatabaseSchema(
  log: (message: string) => void = console.info,
): Promise<void> {
  for (const model of [DeviceModel, DeviceLinkChallengeModel]) {
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
