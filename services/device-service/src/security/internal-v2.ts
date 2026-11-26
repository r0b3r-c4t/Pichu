import { randomUUID } from 'node:crypto';
import type { InternalUnsignedHeadersV2 } from '@pichu/contracts';
import { generateNonce, signRequest, type Keyring } from '@pichu/internal-auth';

export interface InternalClientConfig {
  readonly environment: 'development' | 'test' | 'staging' | 'production';
  readonly keyring: Keyring;
  readonly sender: 'device-service';
}

export function signedHeaders(
  config: InternalClientConfig,
  audience: 'identity-service',
  method: string,
  target: string,
  body: Buffer,
  authorization?: string,
): Record<string, string> {
  const now = Date.now();
  const key = config.keyring.find(
    (entry) =>
      entry.environment === config.environment &&
      entry.sender === config.sender &&
      entry.audience === audience &&
      entry.state === 'active' &&
      entry.notBefore <= now &&
      now < entry.notAfter,
  );
  if (!key) throw new Error('Internal authentication unavailable');
  const headers: InternalUnsignedHeadersV2 = {
    'x-internal-auth-version': '2',
    'x-service-name': config.sender,
    'x-service-audience': audience,
    'x-service-key-id': key.keyId,
    'x-contract-version': 'v1',
    'x-timestamp': String(now),
    'x-nonce': generateNonce(),
    'x-request-id': randomUUID(),
    'x-internal-deadline': String(now + 4_000),
    ...(authorization ? { authorization } : {}),
    ...(body.byteLength ? { 'content-type': 'application/json' as const } : {}),
  };
  return {
    ...headers,
    'x-signature': signRequest(
      {
        environment: config.environment,
        sender: config.sender,
        audience,
        keyring: config.keyring,
        now,
      },
      headers,
      { method, target, body },
    ),
  };
}
