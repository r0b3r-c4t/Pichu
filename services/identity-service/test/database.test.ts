import assert from 'node:assert/strict';
import test from 'node:test';
import type { Mongoose } from 'mongoose';
import { createDatabaseService } from '../src/database/connection.js';

function createClient(overrides: Record<string, unknown> = {}) {
  const db = { command: async (_command: { ping: number }) => ({ ok: 1 }) };
  const connection = (overrides.connection as { readyState: number; db?: typeof db }) ?? {
    readyState: 1,
    db,
  };
  const connectOverride = overrides.connect as
    | ((url: string, options: { autoIndex: boolean }) => Promise<Mongoose>)
    | undefined;
  let connectCalls = 0;
  let disconnectCalls = 0;
  let client: Mongoose;
  client = {
    connection,
    connect: async (url: string, options: { autoIndex: boolean }) => {
      connectCalls += 1;
      if (connectOverride) {
        return connectOverride(url, options);
      }
      return client;
    },
    disconnect: async () => {
      disconnectCalls += 1;
      connection.readyState = 0;
    },
  } as unknown as Mongoose;

  return {
    client,
    connection,
    db,
    get disconnectCalls() {
      return disconnectCalls;
    },
  };
}

test('database health succeeds when a ping command succeeds', async () => {
  const fake = createClient();
  const database = createDatabaseService(fake.client);

  assert.equal(await database.checkDatabaseConnection(), true);
});

test('database health fails when a ping command fails', async () => {
  const fake = createClient();
  fake.db.command = async () => {
    throw new Error('unavailable');
  };
  const database = createDatabaseService(fake.client);

  assert.equal(await database.checkDatabaseConnection(), false);
});

test('concurrent calls reuse the connection attempt in progress', async () => {
  let resolveConnect: ((client: Mongoose) => void) | undefined;
  let connectCalls = 0;
  const fake = createClient({
    connection: { readyState: 2, db: undefined },
    connect: () => {
      connectCalls += 1;
      return new Promise<Mongoose>((resolve) => {
        resolveConnect = resolve;
      });
    },
  });
  const database = createDatabaseService(fake.client);

  const firstConnection = database.connectDatabase('mongodb://identity-user:secret@localhost/identity_db');
  const secondConnection = database.connectDatabase('mongodb://identity-user:secret@localhost/identity_db');
  resolveConnect?.(fake.client);

  const [first, second] = await Promise.all([firstConnection, secondConnection]);
  assert.equal(first, fake.client);
  assert.equal(second, fake.client);
  assert.equal(connectCalls, 1);
});

test('closing waits for an in-flight connection and disconnects once', async () => {
  let resolveConnect: ((client: Mongoose) => void) | undefined;
  const fake = createClient({
    connection: { readyState: 2, db: undefined },
    connect: () =>
      new Promise<Mongoose>((resolve) => {
        resolveConnect = resolve;
      }),
  });
  const database = createDatabaseService(fake.client);
  const connection = database.connectDatabase('mongodb://identity-user:secret@localhost/identity_db');
  const firstClose = database.closeDatabase();
  const secondClose = database.closeDatabase();

  resolveConnect?.(fake.client);
  await Promise.all([connection, firstClose, secondClose]);

  assert.equal(fake.disconnectCalls, 1);
  assert.equal(fake.connection.readyState, 0);
});
