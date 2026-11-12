import assert from 'node:assert/strict';
import { apiErrorResponseSchema, type ApiErrorResponse } from '../src/schemas/error.schema.js';

export function assertApiError(
  response: { json(): unknown; headers: Record<string, unknown> },
  code: ApiErrorResponse['error'],
  message: string,
): ApiErrorResponse {
  const body = apiErrorResponseSchema.parse(response.json());
  assert.equal(body.error, code);
  assert.equal(body.message, message);
  assert.equal(body.requestId, response.headers['x-request-id']);
  return body;
}
