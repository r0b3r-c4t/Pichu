import assert from 'node:assert/strict';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
} from 'node:crypto';
import test from 'node:test';
import {
  buildDeviceLinkProofMessage,
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

test('reproducible pichu-device-link-v1 ESP32 cryptographic vector and domain separation', () => {
  // Deterministic 32-byte RFC 8032 seed 000102...1f wrapped in PKCS#8 DER.
  // Public test fixture ONLY — never use this private seed on real hardware.
  const seed = Buffer.from(
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    'hex',
  );
  const pkcs8Der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const privateKey = createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
  const derivedPublicKey = createPublicKey(privateKey);
  const derivedSpkiDer = derivedPublicKey.export({ format: 'der', type: 'spki' });

  const expectedRawPublicKeyHex =
    '03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8';
  const expectedSpkiPem =
    '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=\n-----END PUBLIC KEY-----\n';
  const expectedFingerprint =
    'sha256:a050837d85070582ccf7394b0988847cc312cb88259b894899f6f239cf1791a5';

  assert.equal(derivedSpkiDer.subarray(12).toString('hex'), expectedRawPublicKeyHex);
  assert.equal(
    derivedPublicKey.export({ format: 'pem', type: 'spki' }).toString(),
    expectedSpkiPem,
  );
  const parsedKey = parseDevicePublicKey(expectedSpkiPem);
  assert.equal(parsedKey.publicKeyPem, expectedSpkiPem);
  assert.equal(parsedKey.fingerprint, expectedFingerprint);

  const fields = {
    deviceId: '665000000000000000000011',
    vehicleId: '665000000000000000000022',
    credentialId: '665000000000000000000033',
    requestedByUserId: '665000000000000000000044',
    challengeId: '665000000000000000000055',
    challenge: 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8',
  } as const;

  const message = buildDeviceLinkProofMessage(fields);
  const expectedUtf8 =
    'pichu-device-link-v1\n' +
    '665000000000000000000011\n' +
    '665000000000000000000022\n' +
    '665000000000000000000033\n' +
    '665000000000000000000044\n' +
    '665000000000000000000055\n' +
    'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8';
  const expectedHex =
    '70696368752d6465766963652d6c696e6b2d76310a' +
    '3636353030303030303030303030303030303030303031310a' +
    '3636353030303030303030303030303030303030303032320a' +
    '3636353030303030303030303030303030303030303033330a' +
    '3636353030303030303030303030303030303030303034340a' +
    '3636353030303030303030303030303030303030303035350a' +
    '494345694979516c4a69636f4b536f724c4330754c7a41784d6a4d304e5459334f446b364f7a7739506a38';
  const expectedSignature =
    'hGtacDafpIhNO2-hdrPzNaI-f-MzCaIFpR7CBS2xQXYxoo6D8OLZ_xsOyuC3eBM7n8bJCexa1DFzUoRhMNqaAw';

  assert.equal(message.length, 189);
  assert.equal(message.toString('utf8'), expectedUtf8);
  assert.equal(message.toString('hex'), expectedHex);
  assert.equal(message.toString('utf8').endsWith('\n'), false);
  assert.equal(message.toString('utf8').includes('\r'), false);

  // Compare against independent fixed expected signature AND verify the fixed signature directly
  const computedSignature = sign(null, message, privateKey).toString('base64url');
  assert.equal(computedSignature, expectedSignature);
  assert.equal(
    verifyDeviceSignature(expectedSpkiPem, Buffer.from(expectedHex, 'hex'), expectedSignature),
    true,
  );

  // Legacy bare-nonce signature MUST NOT verify against the canonical message
  const bareNonceSignature = sign(null, Buffer.from(fields.challenge, 'utf8'), privateKey).toString(
    'base64url',
  );
  assert.equal(verifyDeviceSignature(expectedSpkiPem, message, bareNonceSignature), false);

  // CRLF or trailing LF signatures MUST NOT verify against the canonical message
  const crlfSignature = sign(
    null,
    Buffer.from(expectedUtf8.replaceAll('\n', '\r\n'), 'utf8'),
    privateKey,
  ).toString('base64url');
  const trailingLfSignature = sign(
    null,
    Buffer.from(`${expectedUtf8}\n`, 'utf8'),
    privateKey,
  ).toString('base64url');
  assert.equal(verifyDeviceSignature(expectedSpkiPem, message, crlfSignature), false);
  assert.equal(verifyDeviceSignature(expectedSpkiPem, message, trailingLfSignature), false);

  // Context substitution in any bound field invalidates the proof
  for (const mutated of [
    { ...fields, deviceId: '665000000000000000000099' },
    { ...fields, vehicleId: '665000000000000000000099' },
    { ...fields, credentialId: '665000000000000000000099' },
    { ...fields, requestedByUserId: '665000000000000000000099' },
    { ...fields, challengeId: '665000000000000000000099' },
    { ...fields, challenge: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
  ]) {
    const mutatedMsg = buildDeviceLinkProofMessage(mutated);
    assert.equal(verifyDeviceSignature(expectedSpkiPem, mutatedMsg, expectedSignature), false);
  }

  // Non-canonical identifiers or nonces throw instead of concatenating injected newlines
  assert.throws(() =>
    buildDeviceLinkProofMessage({ ...fields, deviceId: '66500000000000000000001A' }),
  );
  assert.throws(() => buildDeviceLinkProofMessage({ ...fields, vehicleId: 'bad\ninjection' }));
  assert.throws(() => buildDeviceLinkProofMessage({ ...fields, challenge: 'short-nonce' }));
});
