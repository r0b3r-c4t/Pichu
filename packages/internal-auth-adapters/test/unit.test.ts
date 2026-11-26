import assert from 'node:assert/strict';
import test from 'node:test';
import type { IndexDescriptionInfo } from 'mongodb';
import { NONCE_INDEXES, validateNonceIndexes } from '../src/mongodb.js';
import { NonceStoreUnavailable } from '../src/types.js';

const indexes = (): IndexDescriptionInfo[] =>
  NONCE_INDEXES.map((index) => ({ ...index, key: { ...index.key } }));
test('index metadata: compound unique and TTL must both exist with exact key order', () => {
  validateNonceIndexes(indexes());
  for (const input of [[], indexes().slice(0, 1), indexes().slice(1)])
    assert.throws(() => validateNonceIndexes(input), NonceStoreUnavailable);
  const reordered = indexes();
  reordered[0].key = { nonce: 1, sender: 1, audience: 1, environment: 1 };
  assert.throws(() => validateNonceIndexes(reordered), NonceStoreUnavailable);
});
test('index metadata: partial, sparse, wrong TTL, missing uniqueness and keyId are rejected', () => {
  for (const mutation of [
    { sparse: true },
    { partialFilterExpression: { sender: 'api-gateway' } },
    { unique: false },
    { key: { environment: 1, sender: 1, audience: 1, nonce: 1, keyId: 1 } },
    { collation: { locale: 'en' } },
  ]) {
    const changed = indexes();
    changed[0] = { ...changed[0], ...mutation };
    assert.throws(() => validateNonceIndexes(changed), NonceStoreUnavailable);
  }
  for (const mutation of [
    { expireAfterSeconds: 60 },
    { unique: true },
    { sparse: true },
    { partialFilterExpression: { sender: 'api-gateway' } },
  ]) {
    const changed = indexes();
    changed[1] = { ...changed[1], ...mutation };
    assert.throws(() => validateNonceIndexes(changed), NonceStoreUnavailable);
  }
});
