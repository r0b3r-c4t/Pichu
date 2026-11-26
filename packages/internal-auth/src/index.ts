import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  INTERNAL_AUTH_PROTOCOL,
  internalCallerNameSchema,
  internalEnvironmentSchema,
  type InternalCallerName,
  type InternalEnvironment,
  type InternalUnsignedHeadersV2,
} from '@pichu/contracts';
import { fail } from './errors.js';
import { resolveKey, type Keyring } from './keyring.js';
import {
  decodeBytes32,
  parseRequestHeaders,
  validateBody,
  validateRequestTarget,
  validateTimestampAndDeadline,
  validateUnsignedHeaders,
} from './validation.js';

export { InternalAuthError, type InternalAuthErrorCode } from './errors.js';
export {
  resolveKey,
  validateKeyring,
  type KeyIdentity,
  type KeyEntry,
  type Keyring,
} from './keyring.js';
export {
  decodeBytes32,
  parseRequestHeaders,
  validateRequestTarget,
  validateTimestampAndDeadline,
  validateUnsignedHeaders,
} from './validation.js';

export type CanonicalFields = readonly [
  string,
  string,
  string,
  string,
  string,
  string,
  string,
  string,
  string,
  string,
  string,
  string,
  string,
  string,
  string,
  string,
];
export interface RequestBytes {
  readonly method: string;
  readonly target: string;
  readonly body: Uint8Array;
}
export interface AuthContext {
  readonly environment: InternalEnvironment;
  readonly sender: InternalCallerName;
  readonly audience: InternalCallerName;
  readonly keyring: Keyring;
  readonly now: number;
}

export function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export function generateNonce(): string {
  return randomBytes(32).toString('base64url');
}

export function buildCanonicalFields(
  environment: InternalEnvironment,
  headers: InternalUnsignedHeadersV2,
  request: RequestBytes,
): CanonicalFields {
  if (!internalEnvironmentSchema.safeParse(environment).success) fail('INVALID_CONFIG');
  const h = validateUnsignedHeaders(headers);
  validateBody(request.method, request.body, h['content-type']);
  validateRequestTarget(request.target);
  return [
    INTERNAL_AUTH_PROTOCOL,
    environment,
    h['x-service-name'],
    h['x-service-audience'],
    h['x-service-key-id'],
    h['x-contract-version'],
    h['x-timestamp'],
    h['x-nonce'],
    h['x-request-id'],
    h['x-internal-deadline'],
    request.method,
    request.target,
    h['content-type'] ?? '',
    sha256(request.body),
    sha256(Buffer.from(h.authorization ?? '', 'utf8')),
    h['idempotency-key'] ?? '',
  ];
}

/** Low-level serialization: validates shape, not protocol semantics. Use signRequest/verifyRequest at boundaries. */
export function serializeCanonicalFields(fields: CanonicalFields): Buffer {
  if (
    !Array.isArray(fields) ||
    fields.length !== 16 ||
    Array.from(fields).some((value) => typeof value !== 'string' || /[^\x20-\x7e]/.test(value))
  )
    fail('INVALID_FORMAT');
  return Buffer.from(JSON.stringify(fields), 'utf8');
}

/** Low-level HMAC; does not establish key validity, freshness or replay protection. */
export function signCanonicalFields(fields: CanonicalFields, key: Uint8Array): string {
  if (!(key instanceof Uint8Array) || key.byteLength !== 32) fail('INVALID_CONFIG');
  return createHmac('sha256', key).update(serializeCanonicalFields(fields)).digest('base64url');
}

export function verifyCanonicalSignature(
  fields: CanonicalFields,
  signature: string,
  key: Uint8Array,
): boolean {
  const supplied = decodeBytes32(signature);
  const expected = Buffer.from(signCanonicalFields(fields, key), 'base64url');
  return timingSafeEqual(supplied, expected);
}

function validateContext(context: AuthContext, headers: InternalUnsignedHeadersV2): void {
  if (
    !internalEnvironmentSchema.safeParse(context.environment).success ||
    !internalCallerNameSchema.safeParse(context.sender).success ||
    !internalCallerNameSchema.safeParse(context.audience).success
  )
    fail('INVALID_CONFIG');
  if (
    context.sender !== headers['x-service-name'] ||
    context.audience !== headers['x-service-audience']
  )
    fail('INVALID_AUTH');
  validateTimestampAndDeadline(headers['x-timestamp'], headers['x-internal-deadline'], context.now);
}

export function signRequest(
  context: AuthContext,
  headers: InternalUnsignedHeadersV2,
  request: RequestBytes,
): string {
  const h = validateUnsignedHeaders(headers);
  validateContext(context, h);
  const key = resolveKey(
    context.keyring,
    { ...context, keyId: h['x-service-key-id'] },
    Number(h['x-timestamp']),
    context.now,
    'sign',
  );
  return signCanonicalFields(buildCanonicalFields(context.environment, h, request), key);
}

/** Crypto verification ONLY. The receiver must still authorize, reserve the nonce and verify the user JWT. */
export function verifyRequest(
  context: AuthContext,
  rawHeaders: readonly string[],
  request: RequestBytes,
): void {
  const { 'x-signature': signature, ...headers } = parseRequestHeaders(rawHeaders);
  validateContext(context, headers);
  const key = resolveKey(
    context.keyring,
    { ...context, keyId: headers['x-service-key-id'] },
    Number(headers['x-timestamp']),
    context.now,
    'verify',
  );
  if (
    !verifyCanonicalSignature(
      buildCanonicalFields(context.environment, headers, request),
      signature,
      key,
    )
  )
    fail('INVALID_AUTH');
}
