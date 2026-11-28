import mongoose from 'mongoose';

export type DeviceServiceErrorCode =
  | 'INVALID_DEVICE_KEY'
  | 'DEVICE_ALREADY_REGISTERED'
  | 'DEVICE_NOT_FOUND'
  | 'DEVICE_REVOKED'
  | 'DEVICE_NOT_LINKABLE'
  | 'UNVERIFIABLE_ENROLLMENT_CONTEXT'
  | 'ACTOR_MISMATCH'
  | 'INVALID_CHALLENGE'
  | 'CREDENTIAL_UNAVAILABLE'
  | 'INVALID_PROOF'
  | 'INVALID_REVOCATION_STATE'
  | 'CREDENTIAL_NOT_FOUND'
  | 'INCONSISTENT_DEVICE_STATE'
  | 'INVALID_REVOCATION_REQUEST'
  | 'UNTRUSTED_REVOCATION_ACTOR'
  | 'DATABASE_UNAVAILABLE';

export class DeviceServiceError extends Error {
  constructor(
    readonly code: DeviceServiceErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = 'DeviceServiceError';
  }
}

/**
 * Only confirmed connectivity failures are availability errors. Validation, duplicate-key,
 * write-conflict and programming errors (including other MongooseError subclasses) are not.
 */
export function isDatabaseUnavailableError(error: unknown): boolean {
  return (
    error instanceof mongoose.mongo.MongoNetworkError ||
    error instanceof mongoose.mongo.MongoServerSelectionError ||
    error instanceof mongoose.mongo.MongoNotConnectedError ||
    error instanceof mongoose.mongo.MongoTopologyClosedError ||
    error instanceof mongoose.mongo.MongoServerClosedError ||
    error instanceof mongoose.Error.MongooseServerSelectionError
  );
}

export function databaseUnavailableError(cause?: unknown): DeviceServiceError {
  return new DeviceServiceError(
    'DATABASE_UNAVAILABLE',
    'Device database unavailable',
    cause === undefined ? undefined : { cause },
  );
}

export function isDuplicateKeyError(error: unknown): error is { code: 11000; message?: string } {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === 11000
  );
}

/** Index name reported by a duplicate-key error, when the server includes it. */
export function duplicateKeyIndexName(error: unknown): string | undefined {
  if (!isDuplicateKeyError(error) || typeof error.message !== 'string') return undefined;
  return /index: ([A-Za-z0-9_.$-]+) dup key/.exec(error.message)?.[1];
}
