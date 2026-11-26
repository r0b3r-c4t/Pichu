import {
  internalCallerNameSchema,
  internalEnvironmentSchema,
  internalKeyIdSchema,
  type InternalCallerName,
  type InternalEnvironment,
} from '@pichu/contracts';
import { fail } from './errors.js';

export interface KeyIdentity {
  readonly environment: InternalEnvironment;
  readonly sender: InternalCallerName;
  readonly audience: InternalCallerName;
  readonly keyId: string;
}
export interface KeyEntry extends KeyIdentity {
  readonly secret: Uint8Array;
  readonly notBefore: number;
  readonly notAfter: number;
  readonly state: 'active' | 'previous' | 'revoked';
}
export type Keyring = readonly KeyEntry[];

export function validateKeyring(keyring: Keyring): void {
  if (!Array.isArray(keyring)) fail('INVALID_CONFIG');
  const ids = new Set<string>();
  const states = new Set<string>();
  for (const key of keyring) {
    if (
      !key ||
      !internalEnvironmentSchema.safeParse(key.environment).success ||
      !internalCallerNameSchema.safeParse(key.sender).success ||
      !internalCallerNameSchema.safeParse(key.audience).success ||
      !internalKeyIdSchema.safeParse(key.keyId).success ||
      !(key.secret instanceof Uint8Array) ||
      key.secret.byteLength !== 32 ||
      !Number.isSafeInteger(key.notBefore) ||
      !Number.isSafeInteger(key.notAfter) ||
      key.notBefore < 0 ||
      key.notBefore >= key.notAfter ||
      !['active', 'previous', 'revoked'].includes(key.state)
    )
      fail('INVALID_CONFIG');
    const pair = JSON.stringify([key.environment, key.sender, key.audience]);
    const id = JSON.stringify([pair, key.keyId]);
    const state = JSON.stringify([pair, key.state]);
    if (ids.has(id) || (key.state !== 'revoked' && states.has(state))) fail('INVALID_CONFIG');
    ids.add(id);
    states.add(state);
  }
}

/** Exact tuple lookup only; no key fallback. Returns a copy of the secret bytes. */
export function resolveKey(
  keyring: Keyring,
  identity: KeyIdentity,
  timestamp: number,
  now: number,
  purpose: 'sign' | 'verify',
): Uint8Array {
  validateKeyring(keyring);
  if (
    !Number.isSafeInteger(now) ||
    now < 0 ||
    !Number.isSafeInteger(timestamp) ||
    timestamp < 0 ||
    !['sign', 'verify'].includes(purpose)
  )
    fail('INVALID_CONFIG');
  const key = keyring.find(
    (entry) =>
      entry.environment === identity.environment &&
      entry.sender === identity.sender &&
      entry.audience === identity.audience &&
      entry.keyId === identity.keyId,
  );
  if (
    !key ||
    key.state === 'revoked' ||
    (purpose === 'sign' && key.state !== 'active') ||
    timestamp < key.notBefore ||
    timestamp >= key.notAfter ||
    now < key.notBefore ||
    now >= key.notAfter
  )
    fail('INVALID_AUTH');
  return Uint8Array.from(key.secret);
}
