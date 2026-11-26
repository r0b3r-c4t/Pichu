import { generateNonce, signRequest, type KeyEntry } from '@pichu/internal-auth';
import type { InternalUnsignedHeadersV2 } from '@pichu/contracts';
import type { NonceReservation, NonceStore } from '@pichu/internal-auth-adapters/types';
import { createApp, type VehicleAppDependencies } from '../src/app.js';

export const vehicleKey: KeyEntry = {
  environment: 'test',
  sender: 'api-gateway',
  audience: 'vehicle-service',
  keyId: 'test-key',
  secret: Buffer.alloc(32, 7),
  state: 'active',
  notBefore: 1,
  notAfter: 8000000000000000,
};
export class TestNonceStore implements NonceStore {
  private readonly seen = new Set<string>();
  async assertReady(): Promise<void> {}
  async reserve(input: NonceReservation, _signal: AbortSignal): Promise<'reserved' | 'replay'> {
    if (this.seen.has(input.nonce)) return 'replay';
    this.seen.add(input.nonce);
    return 'reserved';
  }
}
export function setupVehicleTestAuth(): VehicleAppDependencies {
  const entries = [
    {
      environment: 'test',
      sender: 'vehicle-service',
      audience: 'identity-service',
      keyId: 'i',
      secretBase64Url: Buffer.alloc(32, 8).toString('base64url'),
      notBefore: 1,
      notAfter: 8000000000000000,
      state: 'active',
    },
    {
      environment: 'test',
      sender: 'vehicle-service',
      audience: 'device-service',
      keyId: 'd',
      secretBase64Url: Buffer.alloc(32, 9).toString('base64url'),
      notBefore: 1,
      notAfter: 8000000000000000,
      state: 'active',
    },
  ];
  process.env.INTERNAL_AUTH_ENVIRONMENT = 'test';
  process.env.INTERNAL_AUTH_KEYRING_JSON = JSON.stringify(entries);
  process.env.DATABASE_URL ??= 'mongodb://127.0.0.1:27017/test';
  return {
    internalAuth: { environment: 'test', keyring: [vehicleKey], nonces: new TestNonceStore() },
  };
}
export function v2Headers(body: Buffer, method: string, target: string): Record<string, string> {
  const now = Date.now();
  const unsigned: InternalUnsignedHeadersV2 = {
    'x-internal-auth-version': '2',
    'x-service-name': 'api-gateway',
    'x-service-audience': 'vehicle-service',
    'x-service-key-id': vehicleKey.keyId,
    'x-contract-version': 'v1',
    'x-timestamp': String(now),
    'x-nonce': generateNonce(),
    'x-request-id': `req-${generateNonce()}`,
    'x-internal-deadline': String(now + 5000),
    ...(body.length ? { 'content-type': 'application/json' as const } : {}),
  };
  return {
    ...unsigned,
    'x-signature': signRequest({ ...vehicleKey, keyring: [vehicleKey], now }, unsigned, {
      method,
      target,
      body,
    }),
  };
}
export function createVehicleTestApp() {
  return createApp(setupVehicleTestAuth());
}
