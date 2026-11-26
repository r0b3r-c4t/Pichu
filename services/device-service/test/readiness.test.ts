import assert from 'node:assert/strict';
import test from 'node:test';
import { createApp } from '../src/app.js';
import { setupDeviceTestAuth, TestNonceStore } from './v2-fixture.js';

test('device liveness is separate from readiness and readiness checks nonce storage', async () => {
  const ready = createApp(setupDeviceTestAuth());
  assert.equal((await ready.inject('/health')).statusCode, 200);
  assert.equal((await ready.inject('/health/ready')).statusCode, 200);
  await ready.close();

  const unavailable = new TestNonceStore();
  unavailable.assertReady = async () => {
    throw new Error('database unavailable');
  };
  const blocked = createApp({
    internalAuth: { ...setupDeviceTestAuth().internalAuth, nonces: unavailable },
  });
  await assert.rejects(() => blocked.ready());
  await blocked.close();
});
