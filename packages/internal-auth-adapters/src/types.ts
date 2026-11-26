import type { InternalCallerName, InternalEnvironment } from '@pichu/contracts';

export interface NonceReservation {
  readonly environment: InternalEnvironment;
  readonly sender: InternalCallerName;
  readonly audience: InternalCallerName;
  readonly nonce: string;
  readonly timestamp: number;
  readonly acceptedAt: number;
}

/** An unconfirmed reservation MUST reject, never return reserved. No business callbacks. */
export interface NonceStore {
  assertReady(): Promise<void>;
  reserve(input: NonceReservation, signal: AbortSignal): Promise<'reserved' | 'replay'>;
}

export class NonceStoreUnavailable extends Error {
  constructor() {
    super('Internal security unavailable');
    this.name = 'NonceStoreUnavailable';
  }
}

export interface InternalPrincipal {
  readonly environment: InternalEnvironment;
  readonly sender: InternalCallerName;
  readonly audience: InternalCallerName;
  readonly keyId: string;
  readonly operationId: string;
  readonly requestId: string;
  readonly nonce: string;
  readonly timestamp: number;
  readonly deadline: number;
}

export interface OperationPolicy {
  readonly method: string;
  /** Exact Fastify route template, including any registration prefix. */
  readonly route: string;
  readonly senders: readonly InternalCallerName[];
}
