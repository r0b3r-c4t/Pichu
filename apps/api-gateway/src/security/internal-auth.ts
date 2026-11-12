import { createHash, createHmac } from 'node:crypto';

export function signInternalRequest(
  secret: string,
  method: string,
  url: string,
  body: unknown,
  timestamp: string,
  requestId: string,
): string {
  const bodyHash = createHash('sha256')
    .update(JSON.stringify(body ?? {}))
    .digest('hex');
  return createHmac('sha256', secret)
    .update(`${timestamp}.${requestId}.${method}.${url}.${bodyHash}`)
    .digest('base64url');
}
