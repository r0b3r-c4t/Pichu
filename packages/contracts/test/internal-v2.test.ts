import assert from 'node:assert/strict';
import test from 'node:test';
import {
  CONTRACTS_VERSION,
  internalRequestHeadersSchema,
  internalRequestHeadersV2Schema,
  internalUnsignedHeadersV2Schema,
  internalEnvironmentSchema,
} from '../src/index.js';

const headers = {
  'x-internal-auth-version': '2',
  'x-service-name': 'api-gateway',
  'x-service-audience': 'vehicle-service',
  'x-service-key-id': 'key-1',
  'x-contract-version': 'v1',
  'x-timestamp': '1800000000000',
  'x-nonce': 'A'.repeat(43),
  'x-request-id': 'request-1',
  'x-internal-deadline': '1800000005000',
  'x-signature': 'A'.repeat(43),
};

test('v2 is a separate strict contract; legacy exports and version remain compatible', () => {
  assert.equal(CONTRACTS_VERSION, 'v1');
  assert.deepEqual(internalRequestHeadersV2Schema.parse(headers), headers);
  assert.equal(
    internalRequestHeadersV2Schema.safeParse({ ...headers, extra: true }).success,
    false,
  );
  assert.equal(
    internalRequestHeadersSchema.safeParse({
      'x-service-name': 'api-gateway',
      'x-request-id': 'request-1',
      'x-contract-version': 'v1',
      'x-timestamp': '1800000000000',
      'x-signature': 'legacy',
    }).success,
    true,
  );
  assert.equal(
    internalRequestHeadersV2Schema.safeParse({ ...headers, 'x-internal-auth-version': '1' })
      .success,
    false,
  );
  assert.equal(
    internalRequestHeadersV2Schema.safeParse({ ...headers, 'x-contract-version': 'v2' }).success,
    false,
  );
});

test('every required v2 header is mandatory and rejects trailing line breaks', () => {
  for (const name of Object.keys(headers)) {
    assert.equal(
      internalRequestHeadersV2Schema.safeParse({ ...headers, [name]: undefined }).success,
      false,
      name,
    );
    assert.equal(
      internalRequestHeadersV2Schema.safeParse({
        ...headers,
        [name]: headers[name as keyof typeof headers] + '\n',
      }).success,
      false,
      name,
    );
  }
});

test('optional v2 fields and canonical formats have strict limits without transformations', () => {
  assert.equal(
    internalRequestHeadersV2Schema.safeParse({
      ...headers,
      authorization: 'Bearer e30.e30.c2ln',
      'idempotency-key': 'op-1',
      'content-type': 'application/json',
    }).success,
    true,
  );
  for (const [name, value] of [
    ['x-nonce', 'A'.repeat(42) + 'B'],
    ['x-signature', 'A'.repeat(43) + '='],
    ['x-timestamp', '01'],
    ['x-internal-deadline', '9007199254740992'],
    ['x-service-key-id', 'k'.repeat(65)],
    ['x-request-id', 'r'.repeat(129)],
    ['x-request-id', ' request-1 '],
    ['authorization', 'Bearer a.b.c\n'],
    ['authorization', 'Bearer ' + 'a'.repeat(8192) + '.b.c'],
    ['idempotency-key', 'a\n'],
    ['x-service-name', 'unrecognized'],
    ['x-service-audience', 'unrecognized'],
  ])
    assert.equal(
      internalRequestHeadersV2Schema.safeParse({ ...headers, [name]: value }).success,
      false,
      name,
    );
  assert.equal(internalEnvironmentSchema.safeParse('production').success, true);
  assert.equal(internalEnvironmentSchema.safeParse('prod').success, false);
  const unsigned = { ...headers, 'x-signature': undefined };
  assert.equal(internalUnsignedHeadersV2Schema.safeParse(unsigned).success, false);
});
