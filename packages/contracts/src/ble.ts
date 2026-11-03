import { z } from 'zod';
import { objectIdSchema } from './common.js';

/** Contrato neutral para un bridge BLE nativo (Capacitor en iOS/Android). */
export const bleDeviceReferenceSchema = z.object({
  deviceId: objectIdSchema,
  bluetoothIdentifier: z.string().trim().min(1).max(128),
});
export type BleDeviceReference = z.infer<typeof bleDeviceReferenceSchema>;

export const bleCommandSchema = z.object({
  deviceId: objectIdSchema,
  command: z.string().trim().min(1).max(64),
  payload: z.record(z.string(), z.unknown()),
  nonce: z.string().trim().min(16).max(256),
  expiresAt: z.string().datetime({ offset: true }),
});
export type BleCommand = z.infer<typeof bleCommandSchema>;
