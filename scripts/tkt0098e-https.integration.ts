import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, randomUUID, sign as signDetached } from 'node:crypto';
import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import mongoose from '../services/vehicle-service/node_modules/mongoose/index.js';
import { httpsJsonRequest } from '../packages/internal-auth-adapters/src/tls.js';
import { NONCE_COLLECTION } from '../packages/internal-auth-adapters/src/mongodb.js';
import { generateNonce, signRequest, type KeyEntry } from '../packages/internal-auth/src/index.js';
import { startAuthenticatedMongo } from './helpers/authenticated-mongo.js';

const run = promisify(execFile);
const openssl = 'C:/Program Files/Git/usr/bin/openssl.exe';
const tsx = 'tsx';
const id = randomUUID().replaceAll('-', '');
const userId = '507f1f77bcf86cd799439011';
const jwtSecret = 'j'.repeat(32);
const userJwt = (() => {
  const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const p = Buffer.from(
    JSON.stringify({
      sub: userId,
      sid: '507f1f77bcf86cd799439014',
      iss: 'issuer',
      aud: 'audience',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
    }),
  ).toString('base64url');
  return `${h}.${p}.${createHmac('sha256', jwtSecret).update(`${h}.${p}`).digest('base64url')}`;
})();
function key(sender: KeyEntry['sender'], audience: KeyEntry['audience'], fill: number): KeyEntry {
  return {
    environment: 'test',
    sender,
    audience,
    keyId: `${sender}-${audience}`,
    secret: Buffer.alloc(32, fill),
    state: 'active',
    notBefore: 1,
    notAfter: 8_000_000_000_000_000,
  };
}
const keys = [
  key('api-gateway', 'vehicle-service', 31),
  key('api-gateway', 'device-service', 32),
  key('vehicle-service', 'identity-service', 33),
  key('vehicle-service', 'device-service', 34),
  key('device-service', 'identity-service', 35),
];
const keyring = JSON.stringify(
  keys.map(({ secret, ...rest }) => ({
    ...rest,
    secretBase64Url: Buffer.from(secret).toString('base64url'),
  })),
);
const gatewayKeyring = JSON.stringify(
  keys
    .filter(({ sender }) => sender === 'api-gateway')
    .map(({ secret, ...rest }) => ({
      ...rest,
      secretBase64Url: Buffer.from(secret).toString('base64url'),
    })),
);
const findKey = (s: KeyEntry['sender'], a: KeyEntry['audience']) =>
  keys.find((k) => k.sender === s && k.audience === a)!;
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));
const processOutput = new WeakMap<
  ChildProcess,
  { service: string; stdout: string; stderr: string }
>();
const MAX_PROCESS_OUTPUT = 16_384;
function redactOutput(value: string): string {
  return value
    .replace(/(mongodb(?:\+srv)?:\/\/)[^@\s]+@/gi, '$1***@')
    .replace(/(authorization|password|secret|token|key)(["'=:\s]+)[^\s,"'}]+/gi, '$1$2***')
    .replace(/Bearer\s+[^\s,"'}]+/gi, 'Bearer ***');
}
function appendOutput(current: string, chunk: Buffer | string): string {
  return (current + chunk.toString()).slice(-MAX_PROCESS_OUTPUT);
}
function reportProcessFailure(child: ChildProcess, reason: 'exit' | 'readiness-timeout'): void {
  const output = processOutput.get(child);
  if (!output) return;
  console.error(
    `[${output.service}] ${reason}; exitCode=${String(child.exitCode)} signal=${String(child.signalCode)}\nstdout:\n${redactOutput(output.stdout)}\nstderr:\n${redactOutput(output.stderr)}`,
  );
}
async function freePort() {
  const s = await import('node:net').then((m) => m.createServer());
  await new Promise<void>((r) => s.listen({ host: '127.0.0.1', port: 0 }, () => r()));
  const p = (s.address() as { port: number }).port;
  await new Promise<void>((r, j) => s.close((e) => (e ? j(e) : r())));
  return p;
}
function start(service: string, env: NodeJS.ProcessEnv): ChildProcess {
  const c = spawn(process.execPath, ['--import', tsx, 'src/server.ts'], {
    cwd: `${process.cwd()}\\services\\${service}`,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  const output = { service, stdout: '', stderr: '' };
  processOutput.set(c, output);
  c.stdout?.on('data', (chunk: Buffer | string) => {
    output.stdout = appendOutput(output.stdout, chunk);
  });
  c.stderr?.on('data', (chunk: Buffer | string) => {
    output.stderr = appendOutput(output.stderr, chunk);
  });
  return c;
}
function startGateway(env: NodeJS.ProcessEnv): ChildProcess {
  const c = spawn(process.execPath, ['--import', tsx, 'src/server.ts'], {
    cwd: `${process.cwd()}\\apps\\api-gateway`,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  const output = { service: 'api-gateway', stdout: '', stderr: '' };
  processOutput.set(c, output);
  c.stdout?.on('data', (chunk: Buffer | string) => {
    output.stdout = appendOutput(output.stdout, chunk);
  });
  c.stderr?.on('data', (chunk: Buffer | string) => {
    output.stderr = appendOutput(output.stderr, chunk);
  });
  return c;
}
async function wait(url: string, child: ChildProcess, ca: string) {
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) {
      reportProcessFailure(child, 'exit');
      throw new Error(`process exited before readiness for ${url}`);
    }
    try {
      const r = await httpsJsonRequest({
        url,
        timeoutMs: 500,
        tls: { caPath: ca, servername: 'localhost' },
      });
      if (r.status === 200) return;
    } catch {
      /* retry until ready */
    }
    await delay(200);
  }
  reportProcessFailure(child, 'readiness-timeout');
  throw new Error(`readiness timeout for ${url}`);
}
async function waitHttp(url: string, child: ChildProcess) {
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) {
      reportProcessFailure(child, 'exit');
      throw new Error(`process exited before readiness for ${url}`);
    }
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      /* retry until ready */
    }
    await delay(200);
  }
  reportProcessFailure(child, 'readiness-timeout');
  throw new Error(`readiness timeout for ${url}`);
}
async function stop(c?: ChildProcess) {
  if (!c || c.exitCode !== null) return;
  c.kill('SIGTERM');
  await Promise.race([new Promise<void>((r) => c.once('exit', () => r())), delay(3000)]);
  if (c.exitCode === null) c.kill('SIGKILL');
}
function authHeaders(
  entry: KeyEntry,
  audience: KeyEntry['audience'],
  method: string,
  target: string,
  body: Buffer,
  deadline?: number,
  signingNow?: number,
) {
  const now = signingNow ?? Date.now();
  const h = {
    'x-internal-auth-version': '2' as const,
    'x-service-name': entry.sender,
    'x-service-audience': audience,
    'x-service-key-id': entry.keyId,
    'x-contract-version': 'v1' as const,
    'x-timestamp': String(now),
    'x-nonce': generateNonce(),
    'x-request-id': randomUUID(),
    'x-internal-deadline': String(deadline ?? now + 5000),
    authorization: `Bearer ${userJwt}`,
    ...(body.length ? { 'content-type': 'application/json' as const } : {}),
  };
  return {
    ...h,
    'x-signature': signRequest(
      { environment: 'test', sender: entry.sender, audience, keyring: [entry], now },
      h,
      { method, target, body },
    ),
  };
}

async function main() {
  const dir = await mkdtemp(`${tmpdir()}\\pichu-0098e-`);
  const caKey = `${dir}\\ca.key`;
  const caCert = `${dir}\\ca.crt`;
  const certKey = `${dir}\\server.key`;
  const csr = `${dir}\\server.csr`;
  const cert = `${dir}\\server.crt`;
  const ext = `${dir}\\server.ext`;
  let mongoClient: mongoose.mongo.MongoClient | undefined;
  let authenticatedMongo: Awaited<ReturnType<typeof startAuthenticatedMongo>> | undefined;
  const children: ChildProcess[] = [];
  try {
    await run(openssl, [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      caKey,
      '-out',
      caCert,
      '-subj',
      '/CN=PICHU Test CA',
      '-days',
      '1',
    ]);
    await run(openssl, [
      'req',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      certKey,
      '-out',
      csr,
      '-subj',
      '/CN=localhost',
    ]);
    const { writeFile } = await import('node:fs/promises');
    await writeFile(ext, 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
    await run(openssl, [
      'x509',
      '-req',
      '-in',
      csr,
      '-CA',
      caCert,
      '-CAkey',
      caKey,
      '-CAcreateserial',
      '-out',
      cert,
      '-days',
      '1',
      '-extfile',
      ext,
    ]);
    authenticatedMongo = await startAuthenticatedMongo();
    const activeMongo = authenticatedMongo;
    mongoClient = new mongoose.mongo.MongoClient(activeMongo.rootUri, {
      serverSelectionTimeoutMS: 3000,
    });
    await mongoClient.connect();
    const identityDb = mongoClient.db('identity_db');
    const vehicleDb = mongoClient.db('vehicle_db');
    const deviceDb = mongoClient.db('device_db');
    await identityDb.collection('users').insertOne({
      _id: new mongoose.Types.ObjectId(userId),
      name: 'Test User',
      username: 'test_user',
      normalizedUsername: 'test_user',
      email: 'test@example.com',
      normalizedEmail: 'test@example.com',
      passwordHash: 'unused',
      emailVerifiedAt: new Date(),
      passwordRecoverySequence: 0,
      passwordRecoveryGeneration: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    await identityDb.collection('sessions').insertOne({
      _id: new mongoose.Types.ObjectId('507f1f77bcf86cd799439014'),
      userId: new mongoose.Types.ObjectId(userId),
      familyId: randomUUID(),
      createdAt: new Date(),
      lastActivityAt: new Date(),
      expiresAt: new Date(Date.now() + 300_000),
      revokedAt: null,
      revokeReason: null,
      userAgent: 'tkt0098e-integration',
    });
    const ports = {
      identity: await freePort(),
      vehicle: await freePort(),
      device: await freePort(),
      gateway: await freePort(),
    };
    const dbUrl = (service: 'identity' | 'vehicle' | 'device') => activeMongo.uri(service);
    const common = {
      NODE_ENV: 'test',
      HOST: '127.0.0.1',
      JWT_SECRET: jwtSecret,
      JWT_ISSUER: 'issuer',
      JWT_AUDIENCE: 'audience',
      INTERNAL_AUTH_ENVIRONMENT: 'test',
      INTERNAL_AUTH_KEYRING_JSON: keyring,
      INTERNAL_AUTH_BODY_LIMIT: '1048576',
      TLS_CERT_PATH: cert,
      TLS_KEY_PATH: certKey,
      TLS_CA_PATH: caCert,
    };
    children.push(
      start('identity-service', {
        ...process.env,
        ...common,
        PORT: String(ports.identity),
        DOCUMENTATION_URL: 'https://localhost/docs',
        RESEND_API_KEY: 'test',
        RESEND_FROM_EMAIL: 'test@example.com',
        RESEND_FROM_NAME: 'PICHU',
        EMAIL_VERIFICATION_URL: 'https://localhost/verify',
        EMAIL_VERIFICATION_TOKEN_TTL_SECONDS: '3600',
        PASSWORD_RESET_URL: 'https://localhost/reset',
        PASSWORD_RESET_TOKEN_TTL_SECONDS: '3600',
        ACCESS_TOKEN_TTL_SECONDS: '300',
        REFRESH_TOKEN_TTL_SECONDS: '3600',
        AUTH_COOKIE_ORIGIN: 'https://localhost',
        DATABASE_URL: dbUrl('identity'),
      }),
    );
    // Identity's strict SCRAM schema is exercised by the dedicated runner; these services use the same isolated replica set and direct databases.
    children.push(
      start('vehicle-service', {
        ...process.env,
        ...common,
        PORT: String(ports.vehicle),
        DATABASE_URL: dbUrl('vehicle'),
        IDENTITY_SERVICE_URL: `https://localhost:${ports.identity}`,
        DEVICE_SERVICE_URL: `https://localhost:${ports.device}`,
      }),
    );
    children.push(
      start('device-service', {
        ...process.env,
        ...common,
        PORT: String(ports.device),
        DATABASE_URL: dbUrl('device'),
        IDENTITY_SERVICE_URL: `https://localhost:${ports.identity}`,
      }),
    );
    await wait(`https://localhost:${ports.identity}/health`, children[0], caCert);
    await wait(`https://localhost:${ports.vehicle}/health`, children[1], caCert);
    await wait(`https://localhost:${ports.device}/health`, children[2], caCert);
    await wait(`https://localhost:${ports.device}/health/ready`, children[2], caCert);
    children.push(
      startGateway({
        ...process.env,
        NODE_ENV: 'test',
        HOST: '127.0.0.1',
        PORT: String(ports.gateway),
        JWT_SECRET: jwtSecret,
        JWT_ISSUER: 'issuer',
        JWT_AUDIENCE: 'audience',
        INTERNAL_AUTH_ENVIRONMENT: 'test',
        INTERNAL_AUTH_KEYRING_JSON: gatewayKeyring,
        IDENTITY_SERVICE_URL: `https://localhost:${ports.identity}`,
        VEHICLE_SERVICE_URL: `https://localhost:${ports.vehicle}`,
        DEVICE_SERVICE_URL: `https://localhost:${ports.device}`,
        TLS_CA_PATH: caCert,
        PROXY_TIMEOUT_MS: '5000',
      }),
    );
    await waitHttp(`http://127.0.0.1:${ports.gateway}/health`, children[3]);
    const gateway = `http://127.0.0.1:${ports.gateway}`;
    const vehicle = await fetch(`${gateway}/api/vehicles`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${userJwt}`,
        'content-type': 'application/json',
        'x-request-id': 'gateway-https-create',
      },
      body: JSON.stringify({ name: 'Gateway TLS Vehicle' }),
    });
    assert.equal(vehicle.status, 201);
    const vehicleId = ((await vehicle.json()) as { vehicleId: string }).vehicleId;
    const list = await fetch(`${gateway}/api/vehicles`, {
      headers: {
        authorization: `Bearer ${userJwt}`,
        'x-request-id': 'gateway-https-list',
      },
    });
    assert.equal(list.status, 200);
    const detail = await fetch(`${gateway}/api/vehicles/${vehicleId}`, {
      headers: {
        authorization: `Bearer ${userJwt}`,
        'x-request-id': 'gateway-https-detail',
      },
    });
    assert.equal(detail.status, 200);
    const deviceKeyPair = generateKeyPairSync('ed25519');
    const devicePublicKeyPem = deviceKeyPair.publicKey
      .export({ type: 'spki', format: 'pem' })
      .toString();

    // Alias retirado en TKT-015: POST /api/vehicles/:vehicleId/devices/link -> 404
    const retiredAlias = await fetch(`${gateway}/api/vehicles/${vehicleId}/devices/link`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${userJwt}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        identifier: `tls-device-retired-${id}`,
        publicKey: devicePublicKeyPem,
      }),
    });
    assert.equal(retiredAlias.status, 404);

    // 1. Registro transaccional real: Gateway -> Vehicle -> Device (PENDING + credencial ACTIVE)
    const registerRes = await fetch(`${gateway}/api/vehicles/${vehicleId}/devices`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${userJwt}`,
        'content-type': 'application/json',
        'x-request-id': 'gateway-https-device-register',
      },
      body: JSON.stringify({
        identifier: `tls-device-${id}`,
        publicKey: devicePublicKeyPem,
        metadata: {
          name: '  Sunroof Controller  ',
          manufacturer: 'Espressif',
          hardwareModel: 'ESP32-S3',
          firmwareVersion: '1.0.0',
        },
      }),
    });
    assert.equal(registerRes.status, 201);
    const registerPayload = (await registerRes.json()) as {
      deviceId: string;
      status: string;
      data: {
        status: string;
        operational: boolean;
        credential: { credentialId: string; status: string; usable: boolean };
        metadata: { name: string | null; serialNumber: string | null };
      };
    };
    const deviceId = registerPayload.deviceId;
    assert.equal(registerPayload.status, 'PENDING');
    assert.equal(registerPayload.data.operational, false);
    assert.equal(registerPayload.data.credential.status, 'ACTIVE');
    assert.equal(registerPayload.data.credential.usable, true);
    assert.equal(registerPayload.data.metadata.name, 'Sunroof Controller');
    assert.equal(JSON.stringify(registerPayload).includes('publicKey'), false);

    const deviceObjectId = new mongoose.Types.ObjectId(deviceId);
    const registered = await deviceDb.collection('devices').findOne({ _id: deviceObjectId });
    assert.equal(registered?.status, 'PENDING');
    assert.equal(String(registered?.requestedByUserId), userId);
    assert.ok(registered?.requestedByMembershipId);
    assert.equal(registered?.linkedByUserId, null);
    assert.equal(registered && 'publicKey' in registered, false);
    assert.equal(
      await deviceDb
        .collection('device_credentials')
        .countDocuments({ deviceId: deviceObjectId, status: 'ACTIVE' }),
      1,
    );

    // Ninguna ruta directa de usuario existe en Device (incluido GET /devices/:deviceId retirado)
    const directRead = await httpsJsonRequest({
      url: `https://localhost:${ports.device}/devices/${deviceId}`,
      method: 'GET',
      timeoutMs: 5000,
      tls: { caPath: caCert, servername: 'localhost' },
    });
    assert.equal(directRead.status, 404);
    for (const disabledPath of ['challenge', 'link', 'revoke']) {
      const disabled = await httpsJsonRequest({
        url: `https://localhost:${ports.device}/devices/${deviceId}/${disabledPath}`,
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: Buffer.from('{}'),
        timeoutMs: 5000,
        tls: { caPath: caCert, servername: 'localhost' },
      });
      assert.equal(disabled.status, 404);
    }

    // 2. Desafío CSPRNG de un solo uso (solo hash almacenado en MongoDB)
    const challengeRes = await fetch(
      `${gateway}/api/vehicles/${vehicleId}/devices/${deviceId}/challenge`,
      {
        method: 'POST',
        headers: {
          authorization: `Bearer ${userJwt}`,
          'content-type': 'application/json',
          'x-request-id': 'gateway-https-device-challenge',
        },
        body: JSON.stringify({}),
      },
    );
    assert.equal(challengeRes.status, 201);
    const challengePayload = (await challengeRes.json()) as {
      data: {
        protocol: string;
        challengeId: string;
        deviceId: string;
        vehicleId: string;
        credentialId: string;
        requestedByUserId: string;
        challenge: string;
        expiresAt: string;
      };
    };
    assert.equal(challengePayload.data.protocol, 'pichu-device-link-v1');
    assert.equal(challengePayload.data.deviceId, deviceId);
    assert.equal(challengePayload.data.vehicleId, vehicleId);
    assert.equal(challengePayload.data.requestedByUserId, userId);

    const storedChallenge = await deviceDb
      .collection('devicelinkchallenges')
      .findOne({ _id: new mongoose.Types.ObjectId(challengePayload.data.challengeId) });
    assert.ok(storedChallenge?.challengeHash);
    assert.equal(storedChallenge && 'challenge' in storedChallenge, false);

    // 3. Firma Ed25519 sobre mensaje canónico pichu-device-link-v1 (sin fixture manual ACTIVE)
    const canonicalMessage = [
      challengePayload.data.protocol,
      challengePayload.data.deviceId,
      challengePayload.data.vehicleId,
      challengePayload.data.credentialId,
      challengePayload.data.requestedByUserId,
      challengePayload.data.challengeId,
      challengePayload.data.challenge,
    ].join('\n');
    const signature = signDetached(
      null,
      Buffer.from(canonicalMessage, 'utf8'),
      deviceKeyPair.privateKey,
    ).toString('base64url');

    const linkRes = await fetch(`${gateway}/api/vehicles/${vehicleId}/devices/${deviceId}/link`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${userJwt}`,
        'content-type': 'application/json',
        'x-request-id': 'gateway-https-device-link',
      },
      body: JSON.stringify({
        challengeId: challengePayload.data.challengeId,
        challenge: challengePayload.data.challenge,
        signature,
      }),
    });
    assert.equal(linkRes.status, 200);
    const linkPayload = (await linkRes.json()) as {
      status: string;
      data: { status: string; operational: boolean };
    };
    assert.equal(linkPayload.status, 'ACTIVE');
    assert.equal(linkPayload.data.operational, true);

    // 4. Consultas y actualización de metadatos siempre vía Gateway -> Vehicle -> Device
    const read = await fetch(`${gateway}/api/devices/${deviceId}`, {
      headers: {
        authorization: `Bearer ${userJwt}`,
        'x-request-id': 'gateway-https-device-read',
      },
    });
    assert.equal(read.status, 200);
    const readPayload = (await read.json()) as {
      status: string;
      operational: boolean;
      connectivity: { lastSeenAt: string | null };
    };
    assert.equal(readPayload.status, 'ACTIVE');
    assert.equal(readPayload.operational, true);
    assert.equal(readPayload.connectivity.lastSeenAt, null);
    assert.equal(JSON.stringify(readPayload).includes('publicKey'), false);

    const readScoped = await fetch(`${gateway}/api/vehicles/${vehicleId}/devices/${deviceId}`, {
      headers: {
        authorization: `Bearer ${userJwt}`,
        'x-request-id': 'gateway-https-device-read-scoped',
      },
    });
    assert.equal(readScoped.status, 200);
    const readScopedPayload = (await readScoped.json()) as {
      deviceId: string;
      status: string;
      operational: boolean;
    };
    assert.equal(readScopedPayload.deviceId, deviceId);
    assert.equal(readScopedPayload.status, 'ACTIVE');
    assert.equal(readScopedPayload.operational, true);

    const listDevices = await fetch(`${gateway}/api/vehicles/${vehicleId}/devices`, {
      headers: {
        authorization: `Bearer ${userJwt}`,
        'x-request-id': 'gateway-https-device-list',
      },
    });
    assert.equal(listDevices.status, 200);
    const listPayload = (await listDevices.json()) as {
      devices: Array<{ deviceId: string; status: string }>;
    };
    assert.deepEqual(
      listPayload.devices.map((item) => [item.deviceId, item.status]),
      [[deviceId, 'ACTIVE']],
    );

    const patchRes = await fetch(`${gateway}/api/vehicles/${vehicleId}/devices/${deviceId}`, {
      method: 'PATCH',
      headers: {
        authorization: `Bearer ${userJwt}`,
        'content-type': 'application/json',
        'x-request-id': 'gateway-https-device-patch',
      },
      body: JSON.stringify({
        name: 'Sunroof Primary Module',
        manufacturer: null,
      }),
    });
    assert.equal(patchRes.status, 200);
    const patchPayload = (await patchRes.json()) as {
      data: { metadata: { name: string | null; manufacturer: string | null } };
    };
    assert.equal(patchPayload.data.metadata.name, 'Sunroof Primary Module');
    assert.equal(patchPayload.data.metadata.manufacturer, null);

    // 5. Revocación administrativa por OWNER (estado terminal REVOKED)
    const revokeRes = await fetch(
      `${gateway}/api/vehicles/${vehicleId}/devices/${deviceId}/revoke`,
      {
        method: 'POST',
        headers: {
          authorization: `Bearer ${userJwt}`,
          'content-type': 'application/json',
          'x-request-id': 'gateway-https-device-revoke',
        },
        body: JSON.stringify({ reason: 'SECURITY_COMPROMISE' }),
      },
    );
    assert.equal(revokeRes.status, 200);
    const revokePayload = (await revokeRes.json()) as {
      status: string;
      data: {
        status: string;
        operational: boolean;
        credential: { status: string; usable: boolean };
        revocationReason: string | null;
      };
    };
    assert.equal(revokePayload.status, 'REVOKED');
    assert.equal(revokePayload.data.operational, false);
    assert.equal(revokePayload.data.credential.status, 'REVOKED');
    assert.equal(revokePayload.data.credential.usable, false);
    assert.equal(revokePayload.data.revocationReason, 'SECURITY_COMPROMISE');

    // Gateway nunca llama directamente a Device; todas las operaciones pasaron por Vehicle
    assert.equal(
      await vehicleDb
        .collection(NONCE_COLLECTION)
        .countDocuments({ sender: 'api-gateway', audience: 'vehicle-service' }),
      11,
    );
    assert.equal(
      await deviceDb
        .collection(NONCE_COLLECTION)
        .countDocuments({ sender: 'api-gateway', audience: 'device-service' }),
      0,
    );
    assert.equal(
      await deviceDb
        .collection(NONCE_COLLECTION)
        .countDocuments({ sender: 'vehicle-service', audience: 'device-service' }),
      12,
    );

    // Incluso con HMAC válido de api-gateway -> device-service, Device rechaza llamadores distintos de vehicle-service
    const forbiddenGatewayInternal = await httpsJsonRequest({
      url: `https://localhost:${ports.device}/internal/devices/${deviceId}`,
      method: 'GET',
      headers: authHeaders(
        findKey('api-gateway', 'device-service'),
        'device-service',
        'GET',
        `/internal/devices/${deviceId}`,
        Buffer.alloc(0),
      ),
      timeoutMs: 5000,
      tls: { caPath: caCert, servername: 'localhost' },
    });
    assert.equal(forbiddenGatewayInternal.status, 403);
    const invalidJwt = await fetch(`${gateway}/api/vehicles`, {
      headers: { authorization: 'Bearer invalid.token.value' },
    });
    assert.equal(invalidJwt.status, 401);
    const injected = await fetch(`${gateway}/api/vehicles`, {
      headers: {
        authorization: `Bearer ${userJwt}`,
        'x-service-name': 'device-service',
        'x-service-audience': 'identity-service',
        'x-internal-auth-version': '1',
        'x-signature': 'injected',
      },
    });
    assert.equal(injected.status, 200);
    const replayBody = Buffer.from(JSON.stringify({ userId, name: 'HTTPS replay' }));
    const replayHeaders = authHeaders(
      findKey('api-gateway', 'vehicle-service'),
      'vehicle-service',
      'POST',
      '/vehicles',
      replayBody,
    );
    const firstReplay = await httpsJsonRequest({
      url: `https://localhost:${ports.vehicle}/vehicles`,
      method: 'POST',
      headers: replayHeaders,
      body: replayBody,
      timeoutMs: 5000,
      tls: { caPath: caCert, servername: 'localhost' },
    });
    const secondReplay = await httpsJsonRequest({
      url: `https://localhost:${ports.vehicle}/vehicles`,
      method: 'POST',
      headers: replayHeaders,
      body: replayBody,
      timeoutMs: 5000,
      tls: { caPath: caCert, servername: 'localhost' },
    });
    assert.equal(firstReplay.status, 201);
    assert.equal(secondReplay.status, 401);
    const wrongAudience = await httpsJsonRequest({
      url: `https://localhost:${ports.vehicle}/vehicles`,
      method: 'POST',
      headers: authHeaders(
        findKey('api-gateway', 'device-service'),
        'device-service',
        'POST',
        '/vehicles',
        replayBody,
      ),
      body: replayBody,
      timeoutMs: 5000,
      tls: { caPath: caCert, servername: 'localhost' },
    });
    assert.equal(wrongAudience.status, 401);
    const expiredDeadline = Date.now() - 1;
    const expired = await httpsJsonRequest({
      url: `https://localhost:${ports.vehicle}/vehicles`,
      method: 'POST',
      headers: authHeaders(
        findKey('api-gateway', 'vehicle-service'),
        'vehicle-service',
        'POST',
        '/vehicles',
        replayBody,
        expiredDeadline,
        expiredDeadline - 1,
      ),
      body: replayBody,
      timeoutMs: 5000,
      tls: { caPath: caCert, servername: 'localhost' },
    });
    assert.ok(expired.status >= 400);
    const bad = {
      ...authHeaders(
        findKey('api-gateway', 'vehicle-service'),
        'vehicle-service',
        'GET',
        '/vehicles',
        Buffer.alloc(0),
      ),
      'x-signature': 'invalid',
    };
    const rejected = await httpsJsonRequest({
      url: `https://localhost:${ports.vehicle}/vehicles?userId=${userId}`,
      headers: bad,
      timeoutMs: 5000,
      tls: { caPath: caCert, servername: 'localhost' },
    });
    assert.ok(rejected.status >= 400);
    await stop(children[1]);
    const unavailable = await fetch(`${gateway}/api/vehicles`, {
      headers: { authorization: `Bearer ${userJwt}` },
    });
    assert.ok(unavailable.status === 502 || unavailable.status === 504);
    console.log(
      'TKT-009.8E.2 HTTPS integrations: PASS (Gateway→Vehicle→Device real Ed25519 enrollment, query, patch and revocation; Vehicle→Identity; security negatives rejected)',
    );
  } finally {
    await mongoClient?.close().catch(() => undefined);
    for (const c of children.reverse()) await stop(c);
    await authenticatedMongo?.cleanup();
    await rm(dir, { recursive: true, force: true });
  }
}
await main();
