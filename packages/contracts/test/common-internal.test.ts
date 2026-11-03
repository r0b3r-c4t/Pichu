import assert from 'node:assert/strict';
import test from 'node:test';
import {
  CONTRACTS_VERSION,
  domainServiceNameSchema,
  errorCodeSchema,
  errorResponseSchema,
  healthResponseSchema,
  internalCallerNameSchema,
  internalRequestHeadersSchema,
  internalResponseMetadataSchema,
  internalSignatureSchema,
  internalTimestampSchema,
  objectIdSchema,
  paginationQuerySchema,
  pageInfoSchema,
  requestIdSchema,
} from '../src/index.js';

test('object and request identifiers enforce canonical formats and limits', () => {
  assert.equal(objectIdSchema.safeParse('507f1f77bcf86cd799439011').success, true);
  assert.equal(objectIdSchema.safeParse('507F1F77BCF86CD799439011').success, false);
  assert.equal(objectIdSchema.safeParse('507f1f77bcf86cd79943901').success, false);
  assert.equal(objectIdSchema.safeParse('507f1f77bcf86cd7994390111').success, false);

  assert.equal(requestIdSchema.parse('  request-1  '), 'request-1');
  assert.equal(requestIdSchema.safeParse('').success, false);
  assert.equal(requestIdSchema.safeParse('x'.repeat(129)).success, false);
  assert.equal(requestIdSchema.safeParse('request\nforged').success, false);
  assert.equal(requestIdSchema.safeParse('\u0000').success, false);
});

test('common error, health and pagination contracts are strict', () => {
  assert.equal(
    errorResponseSchema.safeParse({
      error: { code: 'OPERATION_FAILED', message: 'Request failed' },
      requestId: 'request-1',
    }).success,
    true,
  );
  assert.equal(errorCodeSchema.safeParse('SERVICE_UNAVAILABLE').success, false);
  assert.equal(
    errorResponseSchema.safeParse({
      error: { code: 'NOT_FOUND', message: 'Not found', details: true },
    }).success,
    false,
  );
  assert.equal(
    healthResponseSchema.safeParse({ status: 'error', service: 'identity-service' }).success,
    true,
  );
  assert.equal(
    healthResponseSchema.safeParse({ status: 'unknown', service: 'identity' }).success,
    false,
  );
  assert.deepEqual(paginationQuerySchema.parse({}), { limit: 20 });
  assert.deepEqual(paginationQuerySchema.parse({ limit: '100', cursor: 'next' }), {
    limit: 100,
    cursor: 'next',
  });
  assert.equal(paginationQuerySchema.safeParse({ limit: 0 }).success, false);
  assert.equal(paginationQuerySchema.safeParse({ limit: 101 }).success, false);
  assert.equal(paginationQuerySchema.safeParse({ unknown: true }).success, false);
  assert.equal(pageInfoSchema.safeParse({ nextCursor: null }).success, true);
  assert.equal(pageInfoSchema.safeParse({ nextCursor: '' }).success, false);
});

test('internal caller contracts include Gateway and distinguish domain services', () => {
  assert.equal(domainServiceNameSchema.safeParse('vehicle-service').success, true);
  assert.equal(domainServiceNameSchema.safeParse('api-gateway').success, false);
  assert.equal(internalCallerNameSchema.safeParse('api-gateway').success, true);
  assert.equal(internalCallerNameSchema.safeParse('unknown-service').success, false);
});

test('internal request headers require metadata and cryptographic formats only', () => {
  const valid = {
    'x-request-id': 'request-1',
    'x-service-name': 'api-gateway',
    'x-contract-version': CONTRACTS_VERSION,
    'x-timestamp': '1730635200000',
    'x-signature': 'signature_123',
  };
  assert.equal(internalRequestHeadersSchema.safeParse(valid).success, true);
  assert.equal(
    internalRequestHeadersSchema.safeParse({ ...valid, 'x-contract-version': 'v2' }).success,
    false,
  );
  assert.equal(
    internalRequestHeadersSchema.safeParse({ ...valid, 'x-request-id': undefined }).success,
    false,
  );
  assert.equal(
    internalRequestHeadersSchema.safeParse({ ...valid, 'x-signature': 'not valid!' }).success,
    false,
  );
  assert.equal(internalRequestHeadersSchema.safeParse({ ...valid, extra: true }).success, false);
});

test('internal timestamp and signature schemas validate syntax without authenticating', () => {
  assert.equal(internalTimestampSchema.safeParse('1730635200000').success, true);
  assert.equal(internalTimestampSchema.safeParse('not-a-timestamp').success, false);
  assert.equal(internalTimestampSchema.safeParse('-1730635200000').success, false);
  assert.equal(internalTimestampSchema.safeParse('1730635200000.5').success, false);
  assert.equal(internalTimestampSchema.safeParse('9'.repeat(30)).success, false);
  assert.equal(internalTimestampSchema.safeParse('9007199254740992').success, false);
  assert.equal(internalSignatureSchema.safeParse('abc_X-123').success, true);
  assert.equal(internalSignatureSchema.safeParse('signature with spaces').success, false);
  assert.equal(
    internalResponseMetadataSchema.safeParse({
      requestId: 'request-1',
      contractVersion: CONTRACTS_VERSION,
    }).success,
    true,
  );
  assert.equal(
    internalResponseMetadataSchema.safeParse({ requestId: 'request-1', contractVersion: 'v2' })
      .success,
    false,
  );
});
