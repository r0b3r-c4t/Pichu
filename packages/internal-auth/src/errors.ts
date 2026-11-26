export type InternalAuthErrorCode =
  'INVALID_FORMAT' | 'INVALID_AUTH' | 'DEADLINE_EXCEEDED' | 'INVALID_CONFIG';

/** Never attaches input, key material, Zod issues or an underlying cause. */
export class InternalAuthError extends Error {
  constructor(public readonly code: InternalAuthErrorCode) {
    super('Internal authentication failed');
    this.name = 'InternalAuthError';
  }
}

export function fail(code: InternalAuthErrorCode): never {
  throw new InternalAuthError(code);
}
