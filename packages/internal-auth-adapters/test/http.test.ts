import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import Fastify from 'fastify';
import { Transform } from 'node:stream';
import { httpFixture, RecordingStore, signedHeaders, wire, key } from './fixture.js';
import { internalAuthPlugin } from '../src/fastify.js';
import type { NonceStore } from '../src/types.js';

test('real HTTP: raw Unicode JSON, immutable service principal and public parser isolation', async (t) => {
  const store = new RecordingStore();
  const f = await httpFixture(store);
  t.after(() => f.app.close());
  const body = Buffer.from('{ "name": "車é", "userId":"untrusted" }');
  const response = await wire(f.port, signedHeaders(body), body);
  assert.equal(response.status, 200);
  const parsed = JSON.parse(response.body);
  assert.equal(parsed.body.name, '車é');
  assert.equal(parsed.frozen, true);
  assert.equal(parsed.principal.sender, 'api-gateway');
  assert.equal(parsed.principal.userId, undefined);
  assert.equal(store.inputs.length, 1);
  assert.equal(f.business(), 1);
  const publicResponse = await wire(f.port, ['Content-Type', 'application/json'], body, {
    target: '/public',
  });
  assert.equal(publicResponse.status, 200);
});

test('real HTTP: zero bytes vs {} and bodyless GET', async (t) => {
  const f = await httpFixture();
  t.after(() => f.app.close());
  for (const body of [Buffer.alloc(0), Buffer.from('{}')]) {
    const result = await wire(f.port, signedHeaders(body), body);
    assert.equal(result.status, 200);
    assert.deepEqual(JSON.parse(result.body).body, body.length ? {} : null);
  }
  const empty = Buffer.alloc(0);
  assert.equal(
    (await wire(f.port, signedHeaders(empty, 'GET'), empty, { method: 'GET' })).status,
    200,
  );
  assert.equal(
    (await wire(f.port, signedHeaders(empty, 'GET'), Buffer.from('{}'), { method: 'GET' })).status,
    400,
  );
  assert.equal((await wire(f.port, signedHeaders(empty), Buffer.from('{}'))).status, 400);
});

test('real HTTP: chunk framing is excluded from HMAC; undeclared trailers rejected', async (t) => {
  const f = await httpFixture();
  t.after(() => f.app.close());
  const body = Buffer.from('{"name":"é"}');
  assert.equal((await wire(f.port, signedHeaders(body), body, { chunked: true })).status, 200);
  assert.equal(
    (await wire(f.port, signedHeaders(body), body, { chunked: true, trailers: true })).status,
    400,
  );
});

for (const tampering of [
  'signature',
  'body',
  'target',
  'jwt',
  'audience',
  'key',
  'version',
  'duplicate',
] as const) {
  test(`real HTTP: rejects ${tampering} before reservation/business`, async (t) => {
    const store = new RecordingStore();
    const f = await httpFixture(store);
    t.after(() => f.app.close());
    let body = Buffer.from('{"a":1}');
    const headers = signedHeaders(body, 'POST', '/probe?a=1&b=2', {
      authorization: 'Bearer e30.e30.c2ln',
    });
    let target = '/probe?a=1&b=2';
    const change = (name: string, value: string) => {
      headers[headers.indexOf(name) + 1] = value;
    };
    if (tampering === 'signature') change('x-signature', 'A'.repeat(43));
    if (tampering === 'body') body = Buffer.from('{"a":2}');
    if (tampering === 'target') target = '/probe?b=2&a=1';
    if (tampering === 'jwt') change('authorization', 'Bearer e30.e30.c2lo');
    if (tampering === 'audience') change('x-service-audience', 'device-service');
    if (tampering === 'key') change('x-service-key-id', 'other');
    if (tampering === 'version') change('x-internal-auth-version', '1');
    if (tampering === 'duplicate') headers.push('X-Nonce', headers[headers.indexOf('x-nonce') + 1]);
    const response = await wire(f.port, headers, body, { target });
    assert.equal(response.status, tampering === 'duplicate' ? 400 : 401);
    assert.equal(f.business(), 0);
    assert.equal(store.inputs.length, 0);
    assert.equal(response.body.includes('c2ln'), false);
  });
}

test('real HTTP: JWT is bound but not interpreted as user authorization', async (t) => {
  const f = await httpFixture();
  t.after(() => f.app.close());
  const body = Buffer.from('{}');
  assert.equal(
    (
      await wire(
        f.port,
        signedHeaders(body, 'POST', '/probe', { authorization: 'Bearer e30.e30.c2ln' }),
        body,
      )
    ).status,
    200,
  );
});

test('real HTTP: missing, unknown, mismatched and unauthorized operation policies deny', async (t) => {
  const store = new RecordingStore();
  const f = await httpFixture(store);
  t.after(() => f.app.close());
  for (const target of ['/missing', '/unknown', '/denied', '/mismatch']) {
    const body = Buffer.from('{}');
    const response = await wire(f.port, signedHeaders(body, 'POST', target), body, { target });
    assert.equal(response.status, 403, target);
  }
  assert.equal(f.business(), 0);
  assert.equal(store.inputs.length, 0);
});

test('real HTTP: safe JSON parser rejects poisoning and invalid JSON only after HMAC', async (t) => {
  const store = new RecordingStore();
  const f = await httpFixture(store);
  t.after(() => f.app.close());
  for (const text of [
    '{"__proto__":{"polluted":true}}',
    '{"constructor":{"prototype":{"polluted":true}}}',
    '{broken',
  ]) {
    const body = Buffer.from(text);
    const headers = signedHeaders(body);
    const bad = [...headers];
    bad[bad.indexOf('x-signature') + 1] = 'A'.repeat(43);
    assert.equal((await wire(f.port, bad, body)).status, 401);
    assert.equal((await wire(f.port, headers, body)).status, 400);
  }
  assert.equal(store.inputs.length, 3);
  assert.equal(f.business(), 0);
});

test('real HTTP: Fastify schema coercion follows verification and JSON parsing', async (t) => {
  const f = await httpFixture();
  t.after(() => f.app.close());
  const body = Buffer.from('{"value":"12"}');
  const result = await wire(f.port, signedHeaders(body, 'POST', '/typed'), body, {
    target: '/typed',
  });
  assert.equal(result.status, 200);
  assert.equal(JSON.parse(result.body).body.value, 12);
});

test('real HTTP: route and chunked payload limits precede business', async (t) => {
  const f = await httpFixture();
  t.after(() => f.app.close());
  const body = Buffer.from('{"value":12}');
  for (const chunked of [false, true])
    assert.equal(
      (
        await wire(f.port, signedHeaders(body, 'POST', '/small'), body, {
          target: '/small',
          chunked,
        })
      ).status,
      413,
    );
  assert.equal(f.business(), 0);
});

test('real HTTP: storage rejection, replay and ambiguous timeout never execute business', async (t) => {
  for (const mode of ['error', 'replay', 'timeout'] as const) {
    const store: NonceStore = {
      assertReady: async () => {},
      reserve: async () => {
        if (mode === 'error') throw new Error('SECRET_STORAGE_DETAILS');
        if (mode === 'replay') return 'replay';
        await delay(650);
        return 'reserved';
      },
    };
    const f = await httpFixture(store);
    t.after(() => f.app.close());
    const body = Buffer.from('{}');
    const result = await wire(f.port, signedHeaders(body), body);
    assert.equal(result.status, mode === 'replay' ? 401 : 503);
    assert.equal(result.body.includes('SECRET_STORAGE_DETAILS'), false);
    await delay(200);
    assert.equal(f.business(), 0);
  }
});

test('real HTTP: deadline expires during body reception and during reservation', async (t) => {
  for (const slowBody of [true, false]) {
    const store: NonceStore = {
      assertReady: async () => {},
      reserve: async () => {
        await delay(250);
        return 'reserved';
      },
    };
    const f = await httpFixture(store);
    t.after(() => f.app.close());
    const body = Buffer.from('{}');
    const headers = signedHeaders(body, 'POST', '/probe', {
      'x-internal-deadline': String(Date.now() + 100),
    });
    const result = await wire(
      f.port,
      headers,
      body,
      slowBody ? { chunked: true, delayMs: 250 } : {},
    );
    assert.equal(result.status, 504);
    await delay(300);
    assert.equal(f.business(), 0);
  }
});

test('readiness fails closed without available security storage', async () => {
  const app = Fastify();
  const store = new RecordingStore();
  store.ready = false;
  app.register(internalAuthPlugin, {
    environment: 'test',
    audience: 'vehicle-service',
    keyring: () => [key],
    nonces: store,
    policies: {},
    routes: async () => {},
  });
  await assert.rejects(async () => {
    await app.ready();
  });
  await app.close();
});

test('real HTTP: storage budget is checked even when event-loop blocking delays the timer', async (t) => {
  const store: NonceStore = {
    assertReady: async () => {},
    reserve: async () => {
      const end = performance.now() + 520;
      while (performance.now() < end) {
        /* test only */
      }
      return 'reserved';
    },
  };
  const f = await httpFixture(store);
  t.after(() => f.app.close());
  const body = Buffer.from('{}');
  assert.equal((await wire(f.port, signedHeaders(body), body)).status, 503);
  assert.equal(f.business(), 0);
});

test('real HTTP: scope preParsing transformations are rejected before consuming transformed bytes', async (t) => {
  const store = new RecordingStore();
  const f = await httpFixture(store, async (scope) => {
    scope.addHook('preParsing', async (_request, _reply, payload) => {
      const transform = new Transform({
        transform(chunk, _encoding, done) {
          done(null, chunk);
        },
      });
      return payload.pipe(transform);
    });
  });
  t.after(() => f.app.close());
  const body = Buffer.from('{}');
  assert.equal((await wire(f.port, signedHeaders(body), body)).status, 400);
  assert.equal(store.inputs.length, 0);
  assert.equal(f.business(), 0);
});

test('real HTTP: final handler guard enforces monotonic budget after a blocking preHandler', async (t) => {
  const f = await httpFixture(new RecordingStore(), async (scope) => {
    scope.addHook('preHandler', async () => {
      const end = performance.now() + 150;
      // Intentionally blocks the event loop so timer delivery cannot be the only guard.
      while (performance.now() < end) {
        /* test only */
      }
    });
  });
  t.after(() => f.app.close());
  const body = Buffer.from('{}');
  const headers = signedHeaders(body, 'POST', '/probe', {
    'x-internal-deadline': String(Date.now() + 80),
  });
  assert.equal((await wire(f.port, headers, body)).status, 504);
  assert.equal(f.business(), 0);
});

test('real HTTP: header controls, malformed target and expired deadline fail before storage', async (t) => {
  const store = new RecordingStore();
  const f = await httpFixture(store);
  t.after(() => f.app.close());
  const body = Buffer.from('{}');
  const headers = signedHeaders(body);
  assert.equal((await wire(f.port, headers, body, { target: '/probe?a=1&a=2' })).status, 400);
  assert.equal((await wire(f.port, [...headers, 'Content-Encoding', 'gzip'], body)).status, 400);
  const old = signedHeaders(body, 'POST', '/probe', {
    'x-internal-deadline': String(Date.now() + 50),
  });
  await delay(80);
  assert.equal((await wire(f.port, old, body)).status, 504);
  assert.equal(store.inputs.length, 0);
  assert.equal(f.business(), 0);
});
