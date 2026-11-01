import assert from 'node:assert/strict';
import test from 'node:test';
import { parseEnvironment } from '../src/config/env.js';

const validEnvironment = {
  HOST: '0.0.0.0',
  PORT: '3001',
  DOCUMENTATION_URL: 'http://localhost:3001/docs',
  NODE_ENV: 'test',
  DATABASE_URL: 'mongodb://identity_user:local-password@localhost:27018/identity_db?authSource=identity_db',
};

test('parses valid service environment variables', () => {
  assert.deepEqual(parseEnvironment(validEnvironment), {
    ...validEnvironment,
    PORT: 3001,
  });
});

test('rejects invalid or missing environment variables', () => {
  assert.throws(() => parseEnvironment({ ...validEnvironment, PORT: '70000' }));
  assert.throws(() => parseEnvironment({ ...validEnvironment, NODE_ENV: 'local' }));
  assert.throws(() => parseEnvironment({ ...validEnvironment, DATABASE_URL: undefined }));
});

test('rejects database URLs for a different account or database', () => {
  assert.throws(() =>
    parseEnvironment({
      ...validEnvironment,
      DATABASE_URL: 'mongodb://admin:secret@localhost:27018/admin?authSource=admin',
    }),
  );
});
