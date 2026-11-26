import {
  INTERNAL_AUTH_VERSION,
  CONTRACTS_VERSION,
  internalBytes32Schema,
  internalRequestHeadersV2Schema,
  internalUnsignedHeadersV2Schema,
  internalTimestampV2Schema,
  type InternalRequestHeadersV2,
  type InternalUnsignedHeadersV2,
} from '@pichu/contracts';
import { fail } from './errors.js';

export function decodeBytes32(value: string): Buffer {
  if (!internalBytes32Schema.safeParse(value).success) fail('INVALID_FORMAT');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== 32 || bytes.toString('base64url') !== value) fail('INVALID_FORMAT');
  return bytes;
}

export function validateUnsignedHeaders(value: unknown): InternalUnsignedHeadersV2 {
  const result = internalUnsignedHeadersV2Schema.safeParse(value);
  if (!result.success) fail('INVALID_FORMAT');
  decodeBytes32(result.data['x-nonce']);
  return result.data;
}

/** Pass Node's rawHeaders, not the merged headers map. Ordinary transport headers are ignored. */
export function parseRequestHeaders(rawHeaders: readonly string[]): InternalRequestHeadersV2 {
  if (rawHeaders.length % 2 !== 0) fail('INVALID_FORMAT');
  const selected: Record<string, string> = Object.create(null) as Record<string, string>;
  const seen = new Set<string>();
  const protectedNames = new Set(Object.keys(internalRequestHeadersV2Schema.shape));
  let size = 2;
  for (let i = 0; i < rawHeaders.length; i += 2) {
    const name = rawHeaders[i];
    const value = rawHeaders[i + 1];
    if (typeof name !== 'string' || typeof value !== 'string') fail('INVALID_FORMAT');
    size += Buffer.byteLength(name) + Buffer.byteLength(value) + 4;
    if (size > 16384 || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || /[\r\n]/.test(name))
      fail('INVALID_FORMAT');
    const lower = name.toLowerCase();
    if (lower === 'content-encoding' || lower === 'trailer') fail('INVALID_FORMAT');
    if ([...value].some((char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127)) {
      fail('INVALID_FORMAT');
    }
    if (seen.has(lower)) fail('INVALID_FORMAT');
    seen.add(lower);
    if (!protectedNames.has(lower)) {
      if (lower.startsWith('x-service-') || lower.startsWith('x-internal-')) fail('INVALID_FORMAT');
      continue;
    }
    if (value.trim() !== value || value.includes(',')) fail('INVALID_FORMAT');
    selected[lower] = value;
  }
  if (
    selected['x-internal-auth-version'] !== INTERNAL_AUTH_VERSION ||
    selected['x-contract-version'] !== CONTRACTS_VERSION
  )
    fail('INVALID_AUTH');
  const result = internalRequestHeadersV2Schema.safeParse(selected);
  if (!result.success) fail('INVALID_FORMAT');
  decodeBytes32(result.data['x-nonce']);
  decodeBytes32(result.data['x-signature']);
  return result.data;
}

export function validateTimestampAndDeadline(
  timestamp: string,
  deadline: string,
  now: number,
): void {
  if (!Number.isSafeInteger(now) || now < 0) fail('INVALID_CONFIG');
  if (
    !internalTimestampV2Schema.safeParse(timestamp).success ||
    !internalTimestampV2Schema.safeParse(deadline).success
  )
    fail('INVALID_FORMAT');
  const t = Number(timestamp);
  const d = Number(deadline);
  if (t < now - 60000 || t > now + 5000) fail('INVALID_AUTH');
  if (d <= t || d - t > 5000) fail('INVALID_FORMAT');
  if (now >= d) fail('DEADLINE_EXCEEDED');
}

/** Validates without rewriting: the returned target is byte-for-byte the supplied target. */
export function validateRequestTarget(target: string): string {
  if (
    typeof target !== 'string' ||
    !target.startsWith('/') ||
    target.length > 4096 ||
    /[^\x21-\x7e]|[#\\]/.test(target) ||
    target.includes('//')
  )
    fail('INVALID_FORMAT');
  for (let i = 0; i < target.length; i++) {
    if (target[i] !== '%') continue;
    const escape = target.slice(i + 1, i + 3);
    if (
      !/^[0-9A-F]{2}$/.test(escape) ||
      /^[A-Za-z0-9._~-]$/.test(String.fromCharCode(Number.parseInt(escape, 16)))
    )
      fail('INVALID_FORMAT');
    i += 2;
  }
  const question = target.indexOf('?');
  const path = question < 0 ? target : target.slice(0, question);
  // RFC origin-form: path uses pchar plus '/', query additionally permits '?'.
  if (/[^A-Za-z0-9._~!$&'()*+,;=:@%/-]/.test(path)) fail('INVALID_FORMAT');
  if (question >= 0 && /[^A-Za-z0-9._~!$&'()*+,;=:@%/?-]/.test(target.slice(question + 1))) {
    fail('INVALID_FORMAT');
  }
  if (/%(?:2F|5C)/.test(path) || path.split('/').some((part) => part === '.' || part === '..'))
    fail('INVALID_FORMAT');
  try {
    decodeURIComponent(path);
    if (question >= 0) {
      const query = target.slice(question + 1);
      if (!query || query.includes('+')) fail('INVALID_FORMAT');
      const names = new Set<string>();
      for (const pair of query.split('&')) {
        const equals = pair.indexOf('=');
        if (equals <= 0) fail('INVALID_FORMAT');
        const name = decodeURIComponent(pair.slice(0, equals));
        decodeURIComponent(pair.slice(equals + 1));
        if (names.has(name)) fail('INVALID_FORMAT');
        names.add(name);
      }
    }
  } catch {
    fail('INVALID_FORMAT');
  }
  return target;
}

export function validateBody(method: string, body: Uint8Array, contentType?: string): void {
  if (
    !/^[A-Z]+$/.test(method) ||
    /[\r\n]/.test(method) ||
    !(body instanceof Uint8Array) ||
    body.byteLength > 1048576
  )
    fail('INVALID_FORMAT');
  if (body.byteLength === 0) {
    if (contentType !== undefined) fail('INVALID_FORMAT');
    return;
  }
  if (method === 'GET' || method === 'HEAD' || contentType !== 'application/json')
    fail('INVALID_FORMAT');
  if (body[0] === 0xef && body[1] === 0xbb && body[2] === 0xbf) fail('INVALID_FORMAT');
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(body);
  } catch {
    fail('INVALID_FORMAT');
  }
  // JSON and DTO parsing belong to the receiver, after cryptographic verification.
}
