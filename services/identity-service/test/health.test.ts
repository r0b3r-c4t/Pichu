import assert from 'node:assert/strict';
import test from 'node:test';
import { createApp } from '../src/app.js';

test('health reports service status and database disconnection', async (context) => {
  const app = createApp();
  context.after(async () => app.close());
  await app.ready();

  const healthResponse = await app.inject({ method: 'GET', url: '/health' });
  assert.equal(healthResponse.statusCode, 200);
  assert.deepEqual(healthResponse.json(), { status: 'ok' });

  const databaseResponse = await app.inject({ method: 'GET', url: '/health/db' });
  assert.equal(databaseResponse.statusCode, 503);
  assert.deepEqual(databaseResponse.json(), { status: 'error', database: 'disconnected' });
});
