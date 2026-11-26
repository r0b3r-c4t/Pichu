import assert from 'node:assert/strict';
import test from 'node:test';
import { type InternalUnsignedHeadersV2 } from '@pichu/contracts';
import {
  InternalAuthError,
  buildCanonicalFields,
  serializeCanonicalFields,
  signCanonicalFields,
  verifyCanonicalSignature,
  generateNonce,
  sha256,
  decodeBytes32,
  parseRequestHeaders,
  signRequest,
  verifyRequest,
  validateRequestTarget,
  validateTimestampAndDeadline,
  validateKeyring,
  resolveKey,
  type AuthContext,
  type CanonicalFields,
  type KeyEntry,
} from '../src/index.js';

const now = 1800000000000;
const secret = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const key: KeyEntry = {
  environment: 'test',
  sender: 'api-gateway',
  audience: 'vehicle-service',
  keyId: 'test-key-01',
  secret,
  notBefore: now - 100000,
  notAfter: now + 100000,
  state: 'active',
};
const context: AuthContext = {
  environment: 'test',
  sender: 'api-gateway',
  audience: 'vehicle-service',
  keyring: [key],
  now,
};
const headers: InternalUnsignedHeadersV2 = {
  'x-internal-auth-version': '2',
  'x-service-name': 'api-gateway',
  'x-service-audience': 'vehicle-service',
  'x-service-key-id': 'test-key-01',
  'x-contract-version': 'v1',
  'x-timestamp': String(now),
  'x-nonce': secret.toString('base64url'),
  'x-request-id': 'vector-001',
  'x-internal-deadline': String(now + 5000),
};
const request = { method: 'POST', target: '/vehicles', body: Buffer.alloc(0) };
function raw(
  h: InternalUnsignedHeadersV2 = headers,
  signature = signRequest(context, h, request),
): string[] {
  return Object.entries({ ...h, 'x-signature': signature }).flatMap(([name, value]) => [
    name,
    value,
  ]);
}
function rejects(fn: () => unknown, code?: InternalAuthError['code']): void {
  assert.throws(
    fn,
    (error: unknown) => error instanceof InternalAuthError && (!code || error.code === code),
  );
}

const vectors = [
  [
    '',
    '9rTt3dTH_BQ6BDIHrZtVi7v9HRveThWegr1iz92yNM0',
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  ],
  [
    '{}',
    'XDN4R6XxeyY-FfF3-xmMa2sgx60Jd8VPfR6F1NTWFSI',
    '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
  ],
  [
    '{"name":"Mazda 3"}',
    'JEjn5CL-9-A2hG-ajE8t7RfkW_2WT17Sc8WOifL_aK0',
    'eca9317fc9124a1191ae5c4b31171ce3ab3425db06bb2bf90a34e41d1fc99dd0',
  ],
] as const;
for (const [vector, [body, signature, hash]] of vectors.entries()) {
  const h: InternalUnsignedHeadersV2 = body
    ? { ...headers, 'content-type': 'application/json' }
    : headers;
  const r = { ...request, body: Buffer.from(body) };
  const fields = buildCanonicalFields('test', h, r);
  test(`normative V${vector}: raw hash, canonical UTF8, signature and request verification`, () => {
    assert.equal(sha256(r.body), hash);
    const expected = [
      'pichu-s2s-v2',
      'test',
      'api-gateway',
      'vehicle-service',
      'test-key-01',
      'v1',
      '1800000000000',
      'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
      'vector-001',
      '1800000005000',
      'POST',
      '/vehicles',
      body ? 'application/json' : '',
      hash,
      vectors[0][2],
      '',
    ];
    assert.deepEqual(fields, expected);
    assert.deepEqual(serializeCanonicalFields(fields), Buffer.from(JSON.stringify(expected)));
    assert.equal(signRequest(context, h, r), signature);
    assert.equal(verifyCanonicalSignature(fields, signature, secret), true);
    verifyRequest(context, raw(h, signature), r);
  });
  for (let position = 1; position <= 15; position++) {
    test(`normative V${vector}: mutation field ${position} rejects original signature`, () => {
      const changed = [...fields] as unknown as [...CanonicalFields];
      changed[position] += 'x';
      assert.notEqual(signCanonicalFields(changed, secret), signature);
      assert.equal(verifyCanonicalSignature(changed, signature, secret), false);
    });
  }
}

test('empty body and JSON object cannot substitute each other', () => {
  rejects(() => verifyRequest(context, raw(), { ...request, body: Buffer.from('{}') }));
  rejects(() => signRequest(context, { ...headers, 'content-type': 'application/json' }, request));
});

test('original Unicode bytes, property order and whitespace are bound without normalization', () => {
  const h = { ...headers, 'content-type': 'application/json' } as const;
  const r = { ...request, body: Buffer.from('{"name":"車é","n":1}') };
  const sig = signRequest(context, h, r);
  verifyRequest(context, raw(h, sig), r);
  for (const changed of [
    '{"name":"車e\u0301","n":1}',
    '{"n":1,"name":"車é"}',
    '{ "name":"車é","n":1}',
  ]) {
    rejects(
      () => verifyRequest(context, raw(h, sig), { ...r, body: Buffer.from(changed) }),
      'INVALID_AUTH',
    );
  }
  const changed = Buffer.from(r.body);
  changed[changed.length - 2] = 50;
  rejects(() => verifyRequest(context, raw(h, sig), { ...r, body: changed }), 'INVALID_AUTH');
});

test('query ordering and JWT/idempotency/correlation changes invalidate signatures', () => {
  const h = { ...headers, authorization: 'Bearer e30.e30.c2ln', 'idempotency-key': 'operation-1' };
  const r = { ...request, target: '/vehicles?a=1&b=2' };
  const sig = signRequest(context, h, r);
  verifyRequest(context, raw(h, sig), r);
  for (const target of ['/vehicles?b=2&a=1', '/vehicles?a=2&b=2'])
    rejects(() => verifyRequest(context, raw(h, sig), { ...r, target }), 'INVALID_AUTH');
  for (const mutation of [
    { authorization: 'Bearer e30.e30.c2lo' },
    { 'idempotency-key': 'operation-2' },
    { 'x-request-id': 'another-id' },
    { 'x-nonce': generateNonce() },
  ])
    rejects(() => verifyRequest(context, raw({ ...h, ...mutation }, sig), r), 'INVALID_AUTH');
});

test('nonces are independent canonical 32-byte values', () => {
  const values = Array.from({ length: 100 }, () => generateNonce());
  assert.equal(new Set(values).size, 100);
  for (const value of values) assert.equal(decodeBytes32(value).length, 32);
});

test('case insensitive names; duplicates rejected before merging', () => {
  const all = raw();
  verifyRequest(
    context,
    all.map((v, i) => (i % 2 === 0 ? v.toUpperCase() : v)),
    request,
  );
  for (let i = 0; i < all.length; i += 2)
    rejects(
      () => parseRequestHeaders([...all, all[i].toUpperCase(), all[i + 1]]),
      'INVALID_FORMAT',
    );
  rejects(() => parseRequestHeaders([...all, 'Host', 'one', 'host', 'two']));
  rejects(() => parseRequestHeaders([...all, 'dangling']));
});

for (const field of ['x-nonce', 'x-signature'] as const) {
  for (const value of [
    '',
    'A'.repeat(42),
    'A'.repeat(44),
    'A'.repeat(42) + 'B',
    secret.toString('base64'),
    ' ' + secret.toString('base64url'),
    secret.toString('base64url') + '\n',
  ]) {
    test(`${field} rejects malformed/noncanonical ${JSON.stringify(value)}`, () => {
      const all = raw();
      all[all.indexOf(field) + 1] = value;
      rejects(() => parseRequestHeaders(all), 'INVALID_FORMAT');
    });
  }
}

test('protected header syntax, incompatible versions and HTTP envelope limits', () => {
  for (const [name, value] of [
    ['x-request-id', ' padded'],
    ['x-request-id', 'a,b'],
    ['x-timestamp', '01800000000000'],
    ['x-timestamp', '9007199254740992'],
    ['authorization', 'Bearer a.b.c extra'],
    ['authorization', 'Bearer ' + 'a'.repeat(8192) + '.b.c'],
    ['content-type', 'application/json; charset=utf-8'],
  ]) {
    const h = { ...headers, [name]: value };
    rejects(() => parseRequestHeaders(raw(h, vectors[0][1])), 'INVALID_FORMAT');
  }
  for (const [name, value] of [
    ['x-internal-auth-version', '1'],
    ['x-contract-version', 'v2'],
  ])
    rejects(
      () => parseRequestHeaders(raw({ ...headers, [name]: value }, vectors[0][1])),
      'INVALID_AUTH',
    );
  for (const name of ['content-encoding', 'trailer', 'x-service-extra', 'x-internal-extra'])
    rejects(() => parseRequestHeaders([...raw(), name, 'value']));
  rejects(() => parseRequestHeaders([...raw(), 'x-extra', 'a'.repeat(16384)]));
  const missing = raw();
  missing.splice(0, 2);
  rejects(() => parseRequestHeaders(missing), 'INVALID_AUTH');
});

for (const target of [
  'https://host/path',
  '//host',
  '/a//b',
  '/a/../b',
  '/./x',
  '/a%2Fb',
  '/a%5Cb',
  '/%2e',
  '/%41',
  '/%GG',
  '/%C3%28',
  '/x#f',
  '/x\\a',
  '/x a',
  '/車',
  '/x?',
  '/x?a=1&',
  '/x?=1',
  '/x?a',
  '/x?a=1&a=2',
  '/x?a=hello+world',
  '/' + 'a'.repeat(4096),
  '/x\n',
]) {
  test(`invalid request target ${JSON.stringify(target.slice(0, 60))}`, () =>
    rejects(() => validateRequestTarget(target), 'INVALID_FORMAT'));
}
test('targets preserve allowed encoding, separators and parameter order', () => {
  for (const target of [
    '/',
    '/a?b=&a=%E8%BB%8A%20x',
    '/x?q=a=b',
    '/x?q=a;b',
    '/x?path=%2F',
    '/%252F',
    '/' + 'a'.repeat(4095),
  ])
    assert.equal(validateRequestTarget(target), target);
});

test('body validation rejects invalid UTF8, BOM, GET/HEAD body, oversized payload and lowercase method', () => {
  const h = { ...headers, 'content-type': 'application/json' } as const;
  for (const body of [
    Buffer.from([0xff]),
    Buffer.from([0xef, 0xbb, 0xbf, 123, 125]),
    Buffer.alloc(1048577),
  ])
    rejects(() => signRequest(context, h, { ...request, body }));
  for (const method of ['GET', 'HEAD', 'post', 'POST\n'])
    rejects(() => signRequest(context, h, { ...request, method, body: Buffer.from('{}') }));
  assert.equal(
    typeof signRequest(context, h, { ...request, body: Buffer.alloc(1048576, 32) }),
    'string',
  );
});

test('exact timestamp/deadline boundaries and independent freshness rejection', () => {
  const check = (t: number, d: number, n: number) =>
    validateTimestampAndDeadline(String(t), String(d), n);
  check(now, now + 5000, now - 5000);
  rejects(() => check(now, now + 5000, now - 5001), 'INVALID_AUTH');
  check(now, now + 1, now);
  check(now, now + 5000, now + 4999);
  rejects(() => check(now, now + 5000, now + 5000), 'DEADLINE_EXCEEDED');
  rejects(() => check(now, now + 5000, now + 60000), 'DEADLINE_EXCEEDED');
  rejects(() => check(now, now + 5000, now + 60001), 'INVALID_AUTH');
  rejects(() => check(now, now, now), 'INVALID_FORMAT');
  rejects(() => check(now, now + 5001, now), 'INVALID_FORMAT');
  rejects(() => check(now, now - 1, now), 'INVALID_FORMAT');
  rejects(() => check(now, now + 5000, NaN), 'INVALID_CONFIG');
});

test('key tuple isolation, identity and valid-length wrong secret fail closed', () => {
  for (const mutation of [
    { sender: 'device-service' },
    { audience: 'identity-service' },
    { environment: 'production' },
    { keyId: 'another-key' },
    { secret: Buffer.alloc(32, 1) },
  ] as const) {
    const c = { ...context, keyring: [{ ...key, ...mutation }] };
    rejects(() => verifyRequest(c, raw(), request), 'INVALID_AUTH');
  }
  for (const mutation of [
    { sender: 'device-service' },
    { audience: 'identity-service' },
    { environment: 'production' },
  ] as const)
    rejects(() => verifyRequest({ ...context, ...mutation }, raw(), request), 'INVALID_AUTH');
});

test('key validity is checked at BOTH timestamp and now with exclusive expiry', () => {
  resolveKey([{ ...key, notBefore: now, notAfter: now + 1 }], key, now, now, 'verify');
  for (const [t, n, before, after] of [
    [now, now, now + 1, now + 100],
    [now, now, now - 100, now],
    [now + 1, now, now - 1, now + 1],
    [now - 1, now, now, now + 1],
    [now, now - 1, now, now + 1],
    [now, now + 1, now, now + 1],
  ])
    rejects(
      () => resolveKey([{ ...key, notBefore: before, notAfter: after }], key, t, n, 'verify'),
      'INVALID_AUTH',
    );
});

test('previous keys verify but cannot sign; revoked keys cannot do either; rotation uses explicit keyId', () => {
  const previous = { ...key, state: 'previous' } as const;
  const active = { ...key, keyId: 'test-key-02', secret: Buffer.alloc(32, 2) };
  const c = { ...context, keyring: [previous, active] };
  verifyRequest(c, raw(), request);
  rejects(() => signRequest(c, headers, request), 'INVALID_AUTH');
  const h = { ...headers, 'x-service-key-id': active.keyId };
  verifyRequest(c, raw(h, signRequest(c, h, request)), request);
  for (const purpose of ['sign', 'verify'] as const)
    rejects(
      () => resolveKey([{ ...key, state: 'revoked' }], key, now, now, purpose),
      'INVALID_AUTH',
    );
  rejects(() => verifyRequest({ ...context, keyring: [active] }, raw(), request), 'INVALID_AUTH');
});

test('invalid configuration errors expose no material or Zod issues', () => {
  for (const keyring of [
    [{ ...key, secret: Buffer.from('SECRET_MARKER') }],
    [key, key],
    [key, { ...key, keyId: 'other-active' }],
    [{ ...key, notBefore: NaN }],
    [{ ...key, notAfter: key.notBefore }],
    [
      { ...key, state: 'previous' as const },
      { ...key, keyId: 'other', state: 'previous' as const },
    ],
  ]) {
    assert.throws(
      () => validateKeyring(keyring),
      (error: unknown) => {
        assert.ok(error instanceof InternalAuthError);
        assert.equal(error.code, 'INVALID_CONFIG');
        assert.equal(error.message, 'Internal authentication failed');
        assert.equal('cause' in error, false);
        assert.equal(JSON.stringify(error).includes('SECRET_MARKER'), false);
        return true;
      },
    );
  }
  const copy = resolveKey([key], key, now, now, 'sign');
  copy[0] = 255;
  assert.equal(secret[0], 0);
});

test('canonical serialization rejects incorrect shape and non-ASCII fields', () => {
  rejects(() => serializeCanonicalFields([] as unknown as CanonicalFields));
  rejects(() => serializeCanonicalFields(new Array(16) as unknown as CanonicalFields));
  const fields = [...buildCanonicalFields('test', headers, request)] as [...CanonicalFields];
  fields[8] = 'é';
  rejects(() => serializeCanonicalFields(fields));
});

test('origin-form disallows raw characters outside path/query grammar', () => {
  for (const char of ['"', '<', '>', '`', '[', ']', '^', '|', '{', '}']) {
    rejects(() => validateRequestTarget('/' + char), 'INVALID_FORMAT');
    rejects(() => validateRequestTarget('/x?q=' + char), 'INVALID_FORMAT');
  }
  assert.equal(validateRequestTarget('/vehicle-id?q=some-value'), '/vehicle-id?q=some-value');
});

test('16 KiB header limit is inclusive and counts UTF8 bytes', () => {
  const original = raw();
  let size = 2;
  for (let i = 0; i < original.length; i += 2) {
    size += Buffer.byteLength(original[i]) + Buffer.byteLength(original[i + 1]) + 4;
  }
  const allowance = 16384 - size - Buffer.byteLength('x-padding') - 4;
  parseRequestHeaders([...original, 'x-padding', 'a'.repeat(allowance)]);
  rejects(() => parseRequestHeaders([...original, 'x-padding', 'a'.repeat(allowance + 1)]));
  rejects(() => parseRequestHeaders([...original, 'x-padding', 'é'.repeat(allowance)]));
});

test('explicit configuration rejects invalid identity, environment and key IDs without leaking input', () => {
  for (const field of ['sender', 'audience', 'environment', 'keyId'] as const) {
    const invalid = { ...key, [field]: '/SECRET_MARKER' } as KeyEntry;
    rejects(() => validateKeyring([invalid]), 'INVALID_CONFIG');
  }
  rejects(
    () =>
      signRequest({ ...context, environment: 'prod' } as unknown as AuthContext, headers, request),
    'INVALID_CONFIG',
  );
  rejects(
    () => signRequest(context, { ...headers, 'x-service-key-id': '../key' }, request),
    'INVALID_FORMAT',
  );
  rejects(
    () =>
      verifyCanonicalSignature(
        buildCanonicalFields('test', headers, request),
        'SECRET_MARKER',
        secret,
      ),
    'INVALID_FORMAT',
  );
});
