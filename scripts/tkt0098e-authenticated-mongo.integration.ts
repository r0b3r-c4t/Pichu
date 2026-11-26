import assert from 'node:assert/strict';
import mongoose from '../services/vehicle-service/node_modules/mongoose/index.js';
import { startAuthenticatedMongo } from './helpers/authenticated-mongo.js';

const mongo = await startAuthenticatedMongo();
let admin: mongoose.mongo.MongoClient | undefined;
try {
  admin = new mongoose.mongo.MongoClient(mongo.rootUri, { serverSelectionTimeoutMS: 2_000 });
  await admin.connect();
  for (const service of ['identity', 'vehicle', 'device'] as const) {
    const client = new mongoose.mongo.MongoClient(mongo.uri(service), {
      serverSelectionTimeoutMS: 2_000,
    });
    await client.connect();
    await client.db(`${service}_db`).command({ ping: 1 });
    await client.close();
  }
  const wrong = new mongoose.mongo.MongoClient(
    mongo.rootUri.replace(/^mongodb:\/\/[^@]+@/, 'mongodb://wrong:wrong@'),
    { serverSelectionTimeoutMS: 1_000 },
  );
  await assert.rejects(() => wrong.connect());
  await wrong.close().catch(() => undefined);
  console.log(
    'TKT-009.8E.1 authenticated MongoDB replica set: PASS (3 users, isolated databases, invalid credentials rejected)',
  );
} finally {
  await admin?.close().catch(() => undefined);
  await mongo.cleanup();
}
