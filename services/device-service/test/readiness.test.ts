import assert from 'node:assert/strict';
import test from 'node:test';
import { createApp } from '../src/app.js';
import { setupDeviceTestAuth, TestNonceStore } from './v2-fixture.js';

test('liveness never depends on MongoDB while readiness requires nonce store and database', async () => {
  const ready = createApp({ ...setupDeviceTestAuth(), readinessCheck: async () => undefined });
  assert.equal((await ready.inject('/health')).statusCode, 200);
  assert.equal((await ready.inject('/health/ready')).statusCode, 200);
  await ready.close();

  let databaseChecks = 0;
  const databaseDown = createApp({
    ...setupDeviceTestAuth(),
    readinessCheck: async () => {
      databaseChecks += 1;
      throw new Error('indexes or migration not ready');
    },
  });
  assert.equal((await databaseDown.inject('/health')).statusCode, 200);
  const unready = await databaseDown.inject('/health/ready');
  assert.equal(unready.statusCode, 503);
  assert.deepEqual(unready.json(), { status: 'unready', service: 'device-service' });
  assert.equal(databaseChecks, 1);
  await databaseDown.close();

  const unauthenticated = createApp({ readinessCheck: async () => undefined });
  assert.equal((await unauthenticated.inject('/health/ready')).statusCode, 503);
  await unauthenticated.close();
});

test('nonce store unavailability blocks startup and readiness', async () => {
  const unavailable = new TestNonceStore();
  unavailable.assertReady = async () => {
    throw new Error('database unavailable');
  };
  const blocked = createApp({
    internalAuth: { ...setupDeviceTestAuth().internalAuth!, nonces: unavailable },
    readinessCheck: async () => undefined,
  });
  await assert.rejects(async () => {
    await blocked.ready();
  });
  await blocked.close();
});
