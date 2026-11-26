import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { MongoClient, type CommandStartedEvent } from 'mongodb';
import { generateNonce } from '@pichu/internal-auth';
import { MongoNonceStore, NONCE_COLLECTION, createNonceIndexes } from '../src/mongodb.js';
import { NonceStoreUnavailable, type NonceReservation } from '../src/types.js';
import { httpFixture, signedHeaders, wire } from './fixture.js';

const run = promisify(execFile);
const image = 'mongo:8.0.17';
const label = 'pichu.tkt009.isolated';
const docker = async (...args: string[]) =>
  (await run('docker', args, { timeout: 30000, maxBuffer: 1048576 })).stdout.trim();

test(
  'MongoDB real: disposable replica set owned exclusively by this test',
  { timeout: 120000 },
  async (t) => {
    try {
      await docker('info', '--format', '{{.ServerVersion}}');
      await docker('image', 'inspect', image, '--format', '{{.Id}}');
    } catch {
      t.skip('Docker or local mongo:8.0.17 image unavailable; MongoDB integration NOT validated');
      return;
    }
    const id = randomUUID();
    const name = `pichu-tkt009-${id}`;
    let created = false;
    let client: MongoClient | undefined;
    try {
      await docker(
        'run',
        '--detach',
        '--rm',
        '--name',
        name,
        '--label',
        `${label}=${id}`,
        '--publish',
        '127.0.0.1::27017',
        '--tmpfs',
        '/data/db',
        '--tmpfs',
        '/data/configdb',
        image,
        '--replSet',
        'pichu_test',
        '--bind_ip_all',
        '--setParameter',
        'enableTestCommands=1',
      );
      created = true;
      for (let attempt = 0; ; attempt++) {
        try {
          await docker(
            'exec',
            name,
            'mongosh',
            '--quiet',
            '--eval',
            'rs.initiate({_id:"pichu_test",members:[{_id:0,host:"localhost:27017"}]})',
          );
          break;
        } catch {
          if (attempt >= 20) throw new Error('Disposable replica set failed to initialize');
          await delay(250);
        }
      }
      const binding = await docker('port', name, '27017/tcp');
      assert.match(binding, /^127\.0\.0\.1:[0-9]+$/);
      // URI is derived ONLY from the container this runner created. No external URI/env is accepted.
      const uri = `mongodb://${binding}/?replicaSet=pichu_test&directConnection=true`;
      client = new MongoClient(uri, {
        serverSelectionTimeoutMS: 2000,
        retryWrites: false,
        monitorCommands: true,
      });
      await client.connect();
      const db = client.db(`pichu_tkt009_test_${id.replaceAll('-', '')}`);
      for (let attempt = 0; ; attempt++) {
        if ((await db.admin().command({ hello: 1 })).isWritablePrimary === true) break;
        if (attempt >= 40) throw new Error('Disposable primary unavailable');
        await delay(100);
      }
      const store = new MongoNonceStore(db);
      const reservation = (): NonceReservation => ({
        environment: 'test',
        sender: 'api-gateway',
        audience: 'vehicle-service',
        nonce: generateNonce(),
        timestamp: Date.now(),
        acceptedAt: Date.now(),
      });
      const signal = () => new AbortController().signal;
      await t.test(
        'readiness rejects absent collection/indexes and passes after explicit provisioning',
        async () => {
          await assert.rejects(store.assertReady(), NonceStoreUnavailable);
          await createNonceIndexes(db);
          await store.assertReady();
          const indexes = await db.collection(NONCE_COLLECTION).listIndexes().toArray();
          assert.equal(
            indexes.find((index) => index.name === 'internal_nonce_unique')?.unique,
            true,
          );
          assert.equal(
            indexes.find((index) => index.name === 'internal_nonce_expiry')?.expireAfterSeconds,
            0,
          );
        },
      );
      await t.test(
        'sequential replay, document expiry and actual majority+journal write concern',
        async () => {
          const commands: CommandStartedEvent[] = [];
          const listener = (event: CommandStartedEvent) => {
            if (event.commandName === 'insert') commands.push(event);
          };
          client!.on('commandStarted', listener);
          try {
            const input = reservation();
            assert.equal(await store.reserve(input, signal()), 'reserved');
            assert.equal(await store.reserve(input, signal()), 'replay');
            const document = await db.collection(NONCE_COLLECTION).findOne({ nonce: input.nonce });
            assert.equal(document?.expiresAt.getTime(), input.timestamp + 120000);
            assert.equal(document?.acceptedAt.getTime(), input.acceptedAt);
            assert.equal(document?.keyId, undefined);
            assert.deepEqual(commands[0].command.writeConcern, {
              w: 'majority',
              wtimeout: 500,
              j: true,
            });
          } finally {
            client!.off('commandStarted', listener);
          }
        },
      );
      await t.test(
        'concurrent replay across independent connections admits exactly one insert',
        async () => {
          const second = new MongoClient(uri, {
            serverSelectionTimeoutMS: 2000,
            retryWrites: false,
          });
          try {
            await second.connect();
            const other = new MongoNonceStore(second.db(db.databaseName));
            const input = reservation();
            const results = await Promise.all(
              Array.from({ length: 12 }, (_, i) =>
                (i % 2 ? other : store).reserve(input, signal()),
              ),
            );
            assert.equal(results.filter((value) => value === 'reserved').length, 1);
            assert.equal(results.filter((value) => value === 'replay').length, 11);
          } finally {
            await second.close();
          }
        },
      );
      await t.test(
        'real HTTP + real MongoDB: sequential and concurrent replay allow one business invocation',
        async () => {
          const f = await httpFixture(store);
          try {
            const body = Buffer.from('{}');
            const headers = signedHeaders(body);
            const results = await Promise.all(
              Array.from({ length: 6 }, () => wire(f.port, headers, body)),
            );
            assert.equal(results.filter((result) => result.status === 200).length, 1);
            assert.equal(results.filter((result) => result.status === 401).length, 5);
            assert.equal((await wire(f.port, headers, body)).status, 401);
            assert.equal(f.business(), 1);
          } finally {
            await f.app.close();
          }
        },
      );
      await t.test('fresh adapter after reconnect still sees a consumed nonce', async () => {
        const input = reservation();
        await store.reserve(input, signal());
        const reconnected = new MongoClient(uri, { serverSelectionTimeoutMS: 2000 });
        try {
          await reconnected.connect();
          assert.equal(
            await new MongoNonceStore(reconnected.db(db.databaseName)).reserve(input, signal()),
            'replay',
          );
        } finally {
          await reconnected.close();
        }
      });
      await t.test(
        'TTL does not decide validity or permit reuse while document remains',
        async () => {
          const input = reservation();
          // Future expiry keeps the test deterministic; no dependence on the TTL monitor schedule.
          await store.reserve(input, signal());
          assert.equal(
            await store.reserve({ ...input, timestamp: input.timestamp + 1 }, signal()),
            'replay',
          );
        },
      );
      await t.test('indexes removed after readiness cause 503 and no business', async () => {
        const f = await httpFixture(store);
        try {
          for (const index of ['internal_nonce_unique', 'internal_nonce_expiry']) {
            await db.collection(NONCE_COLLECTION).dropIndex(index);
            await assert.rejects(store.assertReady(), NonceStoreUnavailable);
            const body = Buffer.from('{}');
            assert.equal((await wire(f.port, signedHeaders(body), body)).status, 503);
            assert.equal(f.business(), 0);
            await createNonceIndexes(db);
          }
        } finally {
          await createNonceIndexes(db);
          await f.app.close();
        }
      });
      await t.test(
        'server write concern error is unavailable, never confirmed or replay',
        async () => {
          const f = await httpFixture(store);
          try {
            await db.admin().command({
              configureFailPoint: 'failCommand',
              mode: { times: 1 },
              data: {
                failCommands: ['insert'],
                writeConcernError: {
                  code: 64,
                  errmsg: 'synthetic write concern timeout',
                  errInfo: { wtimeout: true },
                },
              },
            });
            const body = Buffer.from('{}');
            assert.equal((await wire(f.port, signedHeaders(body), body)).status, 503);
            assert.equal(f.business(), 0);
          } finally {
            await db.admin().command({ configureFailPoint: 'failCommand', mode: 'off' });
            await f.app.close();
          }
        },
      );
      await t.test(
        'blocked server insert times out and cannot enter business on late completion',
        async () => {
          const f = await httpFixture(store);
          try {
            await db.admin().command({
              configureFailPoint: 'failCommand',
              mode: { times: 1 },
              data: { failCommands: ['insert'], blockConnection: true, blockTimeMS: 1000 },
            });
            const body = Buffer.from('{}');
            const start = performance.now();
            assert.equal((await wire(f.port, signedHeaders(body), body)).status, 503);
            assert.ok(performance.now() - start < 900);
            await delay(1100);
            assert.equal(f.business(), 0);
          } finally {
            await db.admin().command({ configureFailPoint: 'failCommand', mode: 'off' });
            await f.app.close();
          }
        },
      );
      await t.test('aborted admission and closed connection reject safely', async () => {
        const controller = new AbortController();
        controller.abort();
        await assert.rejects(
          store.reserve(reservation(), controller.signal),
          NonceStoreUnavailable,
        );
        const closed = new MongoClient(uri, { serverSelectionTimeoutMS: 100, retryWrites: false });
        await closed.connect();
        const unavailable = new MongoNonceStore(closed.db(db.databaseName));
        await closed.close();
        await assert.rejects(unavailable.reserve(reservation(), signal()), NonceStoreUnavailable);
      });
    } finally {
      await client?.close();
      if (created) {
        // Cleanup only our own container; no shared volumes, compose project or database are touched.
        const owner = await docker(
          'inspect',
          '--format',
          `{{ index .Config.Labels "${label}" }}`,
          name,
        );
        assert.equal(owner, id);
        assert.match(name, /^pichu-tkt009-[a-f0-9-]+$/);
        await docker('rm', '--force', '--volumes', name);
      }
    }
  },
);
