import assert from 'node:assert/strict';
import test from 'node:test';
import { generateOpaqueToken, hashToken } from '../src/security/crypto.js';
import { hashPassword, verifyPassword } from '../src/security/password.js';

test('generates unique 32-byte opaque tokens as 64-character hexadecimal strings', () => {
  const firstToken = generateOpaqueToken();
  const secondToken = generateOpaqueToken();

  assert.match(firstToken, /^[a-f0-9]{64}$/);
  assert.match(secondToken, /^[a-f0-9]{64}$/);
  assert.notEqual(firstToken, secondToken);
});

test('hashes tokens deterministically with a 64-character hexadecimal digest', () => {
  const token = generateOpaqueToken();
  const firstHash = hashToken(token);

  assert.equal(hashToken(token), firstHash);
  assert.match(firstHash, /^[a-f0-9]{64}$/);
  assert.notEqual(firstHash, token);
});

test('hashes and verifies passwords using Argon2id', async () => {
  const password = 'correct horse battery staple';
  const passwordHash = await hashPassword(password);

  assert.match(passwordHash, /^\$argon2id\$/);
  assert.equal(await verifyPassword(passwordHash, password), true);
  assert.equal(await verifyPassword(passwordHash, 'incorrect password'), false);
});
