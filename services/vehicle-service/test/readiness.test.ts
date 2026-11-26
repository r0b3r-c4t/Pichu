import assert from 'node:assert/strict';
import test from 'node:test';
import { createApp } from '../src/app.js';
import { setupVehicleTestAuth, TestNonceStore } from './v2-fixture.js';

test('vehicle liveness is separate from readiness and readiness checks nonce storage', async () => {
  const ready = createApp(setupVehicleTestAuth());
  assert.equal((await ready.inject('/health')).statusCode, 200);
  assert.equal((await ready.inject('/health/ready')).statusCode, 200);
  await ready.close();

  const unavailable = new TestNonceStore();
  unavailable.assertReady = async () => {
    throw new Error('database unavailable');
  };
  const blocked = createApp({
    internalAuth: { ...setupVehicleTestAuth().internalAuth, nonces: unavailable },
  });
  await assert.rejects(() => blocked.ready());
  await blocked.close();
});
