import {
  decodeBytes32,
  generateNonce,
  signRequest,
  validateKeyring,
  type Keyring,
} from '@pichu/internal-auth';
import type { InternalCallerName } from '@pichu/contracts';
import type { GatewayEnv } from '../config/env.js';
import { z } from 'zod';

const entrySchema = z.strictObject({
  environment: z.enum(['development', 'test', 'staging', 'production']),
  sender: z.string(),
  audience: z.string(),
  keyId: z.string(),
  secretBase64Url: z.string(),
  notBefore: z.number().int().nonnegative(),
  notAfter: z.number().int().nonnegative(),
  state: z.enum(['active', 'previous', 'revoked']),
});

export function parseGatewayKeyring(env: GatewayEnv): Keyring {
  try {
    const entries = z.array(entrySchema).parse(JSON.parse(env.INTERNAL_AUTH_KEYRING_JSON));
    const keyring = entries.map((entry) => ({
      ...entry,
      secret: decodeBytes32(entry.secretBase64Url),
    })) as Keyring;
    validateKeyring(keyring);
    return keyring;
  } catch {
    throw new Error('Invalid internal authentication configuration');
  }
}

export function createInternalHeaders(options: {
  env: GatewayEnv;
  keyring: Keyring;
  audience: Extract<InternalCallerName, 'vehicle-service' | 'device-service'>;
  method: string;
  target: string;
  body: Uint8Array;
  requestId: string;
  deadline?: number;
  authorization?: string;
  idempotencyKey?: string;
}): Record<string, string> {
  const now = Date.now();
  const deadline = options.deadline ?? now + 5000;
  if (!Number.isSafeInteger(deadline) || deadline <= now || deadline > now + 5000) {
    throw new Error('Invalid internal authentication deadline');
  }
  const key = options.keyring.find(
    (entry) =>
      entry.environment === options.env.INTERNAL_AUTH_ENVIRONMENT &&
      entry.sender === 'api-gateway' &&
      entry.audience === options.audience &&
      entry.state === 'active',
  );
  if (!key) throw new Error('Invalid internal authentication configuration');
  const headers = {
    'x-internal-auth-version': '2' as const,
    'x-service-name': 'api-gateway' as const,
    'x-service-audience': options.audience,
    'x-service-key-id': key.keyId,
    'x-contract-version': 'v1' as const,
    'x-timestamp': String(now),
    'x-nonce': generateNonce(),
    'x-request-id': options.requestId,
    'x-internal-deadline': String(deadline),
    ...(options.body.length ? { 'content-type': 'application/json' as const } : {}),
    ...(options.authorization ? { authorization: options.authorization } : {}),
    ...(options.idempotencyKey ? { 'idempotency-key': options.idempotencyKey } : {}),
  };
  const signature = signRequest(
    {
      environment: options.env.INTERNAL_AUTH_ENVIRONMENT,
      sender: 'api-gateway',
      audience: options.audience,
      keyring: options.keyring,
      now,
    },
    headers,
    { method: options.method, target: options.target, body: options.body },
  );
  return { ...headers, 'x-signature': signature };
}
