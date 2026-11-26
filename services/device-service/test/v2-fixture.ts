import { generateNonce, signRequest, type KeyEntry } from '@pichu/internal-auth';
import type { InternalUnsignedHeadersV2 } from '@pichu/contracts';
import type { NonceReservation, NonceStore } from '@pichu/internal-auth-adapters/types';
import { createApp, type DeviceAppDependencies } from '../src/app.js';

export const deviceKey: KeyEntry = {
  environment: 'test',
  sender: 'api-gateway',
  audience: 'device-service',
  keyId: 'test-key',
  secret: Buffer.alloc(32, 7),
  state: 'active',
  notBefore: 1,
  notAfter: 8000000000000000,
};
export const vehicleKey: KeyEntry = { ...deviceKey, sender: 'vehicle-service' };
export class TestNonceStore implements NonceStore {
  private readonly seen = new Set<string>();
  async assertReady(): Promise<void> {}
  async reserve(input: NonceReservation, _signal: AbortSignal): Promise<'reserved' | 'replay'> {
    if (this.seen.has(input.nonce)) return 'replay';
    this.seen.add(input.nonce);
    return 'reserved';
  }
}
export function setupDeviceTestAuth(): DeviceAppDependencies {
  const entries = [
    {
      environment: 'test',
      sender: 'device-service',
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
      audience: 'identity-service',
      keyId: 'v',
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
    internalAuth: {
      environment: 'test',
      keyring: [deviceKey, vehicleKey],
      nonces: new TestNonceStore(),
    },
  };
}
export function v2Headers(
  body: Buffer,
  method: string,
  target: string,
  sender = 'api-gateway',
): Record<string, string> {
  const now = Date.now();
  const signingKey = sender === 'vehicle-service' ? vehicleKey : deviceKey;
  const unsigned: InternalUnsignedHeadersV2 = {
    'x-internal-auth-version': '2',
    'x-service-name': sender,
    'x-service-audience': 'device-service',
    'x-service-key-id': signingKey.keyId,
    'x-contract-version': 'v1',
    'x-timestamp': String(now),
    'x-nonce': generateNonce(),
    'x-request-id': `req-${generateNonce()}`,
    'x-internal-deadline': String(now + 5000),
    ...(body.length ? { 'content-type': 'application/json' as const } : {}),
  };
  return {
    ...unsigned,
    'x-signature': signRequest({ ...signingKey, keyring: [signingKey], now }, unsigned, {
      method,
      target,
      body,
    }),
  };
}
export function createDeviceTestApp() {
  return createApp(setupDeviceTestAuth());
}
