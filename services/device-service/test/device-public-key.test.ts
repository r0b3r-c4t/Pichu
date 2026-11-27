import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import {
  DevicePublicKeyError,
  parseDevicePublicKey,
  verifyDeviceSignature,
} from '../src/security/device-public-key.js';

function ed25519() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKey,
    privateKey,
    pem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    der: publicKey.export({ type: 'spki', format: 'der' }),
  };
}

function armor(label: string, body: string): string {
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

test('reproduces the inspection defect: createPublicKey alone accepts a private key', () => {
  const { privateKey } = ed25519();
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  // The pre-TKT-014 validator only checked this, so a private key was accepted and stored.
  assert.equal(createPublicKey(privatePem).asymmetricKeyType, 'ed25519');
  assert.throws(() => parseDevicePublicKey(privatePem), DevicePublicKeyError);
  assert.throws(() => parseDevicePublicKey(privatePem.trim()), DevicePublicKeyError);
});

test('accepts only Ed25519 SPKI PEM and regenerates the canonical PEM and fingerprint', () => {
  const key = ed25519();
  const parsed = parseDevicePublicKey(key.pem);
  assert.equal(parsed.algorithm, 'Ed25519');
  assert.equal(parsed.publicKeyPem, key.pem);
  assert.equal(parsed.fingerprint, `sha256:${createHash('sha256').update(key.der).digest('hex')}`);
  assert.match(parsed.fingerprint, /^sha256:[0-9a-f]{64}$/);
  const trimmed = parseDevicePublicKey(key.pem.trim());
  assert.deepEqual(trimmed, parsed);
  assert.equal(Object.isFrozen(parsed), true);
  assert.notEqual(parseDevicePublicKey(ed25519().pem).fingerprint, parsed.fingerprint);
});

test('rejects private keys, certificates, other algorithms and ambiguous encodings', () => {
  const key = ed25519();
  const body = key.der.toString('base64');
  const privateDer = key.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
  const x25519 = generateKeyPairSync('x25519')
    .publicKey.export({ type: 'spki', format: 'pem' })
    .toString();
  const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 })
    .publicKey.export({ type: 'spki', format: 'pem' })
    .toString();
  const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    .publicKey.export({ type: 'spki', format: 'pem' })
    .toString();
  const lastChar = body.at(-2)!;
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const sibling = alphabet[alphabet.indexOf(lastChar) ^ 1]!;
  const nonCanonical = `${body.slice(0, -2)}${sibling}=`;
  const corruptedPrefix = Buffer.from(key.der);
  corruptedPrefix[1] = 0x2b;

  const invalid: unknown[] = [
    undefined,
    null,
    42,
    '',
    body,
    armor('PRIVATE KEY', privateDer),
    armor('PUBLIC KEY', privateDer),
    armor('CERTIFICATE', body),
    armor('RSA PUBLIC KEY', body),
    x25519,
    rsa,
    ec,
    `${key.pem}trailing`,
    `${key.pem}${key.pem}`,
    ` ${key.pem}`,
    key.pem.replaceAll('\n', '\r\n'),
    key.pem.replace('\n', ''),
    key.pem.replace('-----\n', '-----\n\n'),
    armor('PUBLIC KEY', `${body.slice(0, 30)}\n${body.slice(30)}`),
    armor('PUBLIC KEY', body.replace('=', '')),
    armor('PUBLIC KEY', nonCanonical),
    armor('PUBLIC KEY', corruptedPrefix.toString('base64')),
    'x'.repeat(5000),
  ];
  for (const value of invalid) {
    assert.throws(
      () => parseDevicePublicKey(value),
      (error: unknown) =>
        error instanceof DevicePublicKeyError && error.message === 'Invalid device public key',
    );
  }
  assert.notEqual(nonCanonical, body);
  assert.deepEqual(Buffer.from(nonCanonical, 'base64'), key.der);
});

test('verifies only canonical 64-byte base64url Ed25519 signatures', () => {
  const key = ed25519();
  const other = ed25519();
  const message = Buffer.from('challenge-value-0123456789abcdefghijklmnop');
  const signature = sign(null, message, key.privateKey).toString('base64url');
  assert.equal(verifyDeviceSignature(key.pem, message, signature), true);
  assert.equal(verifyDeviceSignature(other.pem, message, signature), false);
  assert.equal(verifyDeviceSignature(key.pem, Buffer.from('tampered'), signature), false);
  assert.equal(verifyDeviceSignature(key.pem, message, `${signature}=`), false);
  assert.equal(verifyDeviceSignature(key.pem, message, signature.slice(0, -2)), false);
  assert.equal(verifyDeviceSignature(key.pem, message, Buffer.alloc(64).toString('base64')), false);
  const privatePem = key.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  assert.equal(verifyDeviceSignature(privatePem, message, signature), false);
});
