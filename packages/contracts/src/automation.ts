import { z } from 'zod';
import { objectIdSchema } from './common.js';

export const moduleTypeSchema = z.string().trim().min(1).max(64);
export const moduleStatusSchema = z.enum(['ACTIVE', 'DISABLED']);

export const vehicleModuleSchema = z.object({
  id: objectIdSchema,
  vehicleId: objectIdSchema,
  type: moduleTypeSchema,
  status: moduleStatusSchema,
});
export type VehicleModule = z.infer<typeof vehicleModuleSchema>;

export const moduleConfigurationSchema = z.object({
  moduleId: objectIdSchema,
  configuration: z.record(z.string(), z.unknown()),
  updatedAt: z.string().datetime({ offset: true }),
});
export type ModuleConfiguration = z.infer<typeof moduleConfigurationSchema>;

export const automationRuleSchema = z.object({
  id: objectIdSchema,
  vehicleId: objectIdSchema,
  enabled: z.boolean(),
  definition: z.record(z.string(), z.unknown()),
});
export type AutomationRule = z.infer<typeof automationRuleSchema>;

export const reportedStateSchema = z.object({
  moduleId: objectIdSchema,
  state: z.record(z.string(), z.unknown()),
  reportedAt: z.string().datetime({ offset: true }),
  sourceDeviceId: objectIdSchema.nullable(),
});
export type ReportedState = z.infer<typeof reportedStateSchema>;
