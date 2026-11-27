export type VehicleDomainErrorCode =
  'VALIDATION_ERROR' | 'FORBIDDEN' | 'NOT_FOUND' | 'CONFLICT' | 'DATABASE_UNAVAILABLE';

export class VehicleServiceError extends Error {
  constructor(
    public readonly code: VehicleDomainErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = 'VehicleServiceError';
  }
}

export interface VehicleAuditEvent {
  action: string;
  actorUserId: string;
  vehicleId?: string;
  targetId?: string;
  outcome: 'success' | 'denied' | 'conflict' | 'error';
  reason?: string;
}

export type VehicleAuditLogger = (event: VehicleAuditEvent) => void;

export const defaultAuditLogger: VehicleAuditLogger = () => undefined;
