import assert from 'node:assert/strict';
import test from 'node:test';
import { assertVehicleDatabaseReady, createApp } from '../src/app.js';
import { setupVehicleTestAuth, TestNonceStore } from './v2-fixture.js';

test('vehicle liveness is separate from readiness and readiness checks nonce storage plus database schema', async () => {
  const ready = createApp(setupVehicleTestAuth());
  assert.equal((await ready.inject('/health')).statusCode, 200);
  assert.equal((await ready.inject('/health/live')).statusCode, 200);
  assert.equal((await ready.inject('/health/ready')).statusCode, 200);
  await ready.close();

  // Default readinessCheck fails closed with 503 when MongoDB is disconnected, while liveness stays 200.
  const disconnectedDbApp = createApp({
    internalAuth: setupVehicleTestAuth().internalAuth,
  });
  assert.equal((await disconnectedDbApp.inject('/health')).statusCode, 200);
  assert.equal((await disconnectedDbApp.inject('/health/ready')).statusCode, 503);
  await assert.rejects(() => assertVehicleDatabaseReady());
  await disconnectedDbApp.close();

  // Missing critical integrity indexes fail readiness with 503.
  const missingCriticalIndexesApp = createApp({
    ...setupVehicleTestAuth(),
    readinessCheck: async () => {
      throw new Error('Critical Vehicle database indexes are not ready');
    },
  });
  assert.equal((await missingCriticalIndexesApp.inject('/health')).statusCode, 200);
  assert.equal((await missingCriticalIndexesApp.inject('/health/ready')).statusCode, 503);
  await missingCriticalIndexesApp.close();

  const unavailable = new TestNonceStore();
  unavailable.assertReady = async () => {
    throw new Error('database unavailable');
  };
  const blocked = createApp({
    internalAuth: { ...setupVehicleTestAuth().internalAuth, nonces: unavailable },
    readinessCheck: async () => {},
  });
  await assert.rejects(() => blocked.ready());
  await blocked.close();
});
