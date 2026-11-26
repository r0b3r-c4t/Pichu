import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import Fastify from '../services/vehicle-service/node_modules/fastify/fastify.js';
import { httpsJsonRequest } from '../packages/internal-auth-adapters/src/tls.js';
import { proxyRequest } from '../apps/api-gateway/src/lib/proxy.js';
import { createApp as createVehicleApp } from '../services/vehicle-service/src/app.js';
import { createApp as createDeviceApp } from '../services/device-service/src/app.js';
import { createApp as createIdentityApp } from '../services/identity-service/src/app.js';
import type { NonceReservation, NonceStore } from '../packages/internal-auth-adapters/src/types.js';

const run = promisify(execFile);
const openssl = 'C:/Program Files/Git/usr/bin/openssl.exe';

class ReadyNonceStore implements NonceStore {
  async assertReady(): Promise<void> {}
  async reserve(_input: NonceReservation, _signal: AbortSignal): Promise<'reserved'> {
    return 'reserved';
  }
}

async function main() {
  const dir = await mkdtemp(`${tmpdir()}/pichu-tls-`);
  const caKey = `${dir}/ca.key`;
  const caCert = `${dir}/ca.crt`;
  const serverKey = `${dir}/server.key`;
  const serverCsr = `${dir}/server.csr`;
  const serverCert = `${dir}/server.crt`;
  const wrongCa = `${dir}/wrong-ca.crt`;
  const expiredCert = `${dir}/expired.crt`;
  let apps: Array<ReturnType<typeof createVehicleApp>> = [];
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
      serverKey,
      '-out',
      serverCsr,
      '-subj',
      '/CN=localhost',
    ]);
    const ext = `${dir}/server.ext`;
    await (
      await import('node:fs/promises')
    ).writeFile(ext, 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
    await run(openssl, [
      'x509',
      '-req',
      '-in',
      serverCsr,
      '-CA',
      caCert,
      '-CAkey',
      caKey,
      '-CAcreateserial',
      '-out',
      serverCert,
      '-days',
      '1',
      '-extfile',
      ext,
    ]);
    await run(openssl, [
      'x509',
      '-req',
      '-in',
      serverCsr,
      '-CA',
      caCert,
      '-CAkey',
      caKey,
      '-CAcreateserial',
      '-out',
      expiredCert,
      '-days',
      '0',
      '-extfile',
      ext,
    ]);
    await run(openssl, [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      `${dir}/wrong.key`,
      '-out',
      wrongCa,
      '-subj',
      '/CN=Wrong CA',
      '-days',
      '1',
    ]);
    const key = {
      environment: 'test' as const,
      sender: 'api-gateway' as const,
      audience: 'vehicle-service' as const,
      keyId: 'test',
      secret: Buffer.alloc(32, 1),
      state: 'active' as const,
      notBefore: 1,
      notAfter: 8_000_000_000_000_000,
    };
    const vehicle = createVehicleApp({
      internalAuth: { environment: 'test', keyring: [key], nonces: new ReadyNonceStore() },
      https: {
        key: await readFile(serverKey),
        cert: await readFile(serverCert),
        ca: await readFile(caCert),
      },
    });
    const device = createDeviceApp({
      internalAuth: {
        environment: 'test',
        keyring: [{ ...key, audience: 'device-service' }],
        nonces: new ReadyNonceStore(),
      },
      https: {
        key: await readFile(serverKey),
        cert: await readFile(serverCert),
        ca: await readFile(caCert),
      },
    });
    const identity = createIdentityApp({
      https: {
        key: await readFile(serverKey),
        cert: await readFile(serverCert),
        ca: await readFile(caCert),
      },
    });
    apps = [vehicle, device, identity];
    for (const app of apps) await app.listen({ host: '127.0.0.1', port: 0 });
    const addresses = apps.map(
      (app) => `https://localhost:${(app.server.address() as { port: number }).port}`,
    );
    for (const url of addresses) {
      const response = await httpsJsonRequest({
        url: `${url}/health`,
        timeoutMs: 1000,
        tls: { caPath: caCert, servername: 'localhost' },
      });
      assert.equal(response.status, 200);
    }
    for (const url of addresses.slice(0, 2)) {
      const response = await proxyRequest({
        url: `${url}/health`,
        method: 'GET',
        timeoutMs: 1000,
        tls: { caPath: caCert, servername: 'localhost' },
      });
      assert.equal(response.status, 200);
    }
    await assert.rejects(() =>
      httpsJsonRequest({
        url: `${addresses[0]}/health`,
        timeoutMs: 1000,
        tls: { caPath: wrongCa, servername: 'localhost' },
      }),
    );
    await assert.rejects(() =>
      httpsJsonRequest({
        url: addresses[0].replace('localhost', '127.0.0.1') + '/health',
        timeoutMs: 1000,
        tls: { caPath: caCert, servername: 'wrong.localhost' },
      }),
    );
    await assert.rejects(() => fetch(addresses[0].replace('https:', 'http:') + '/health'));
    const expired = Fastify({
      https: {
        key: await readFile(serverKey),
        cert: await readFile(expiredCert),
        ca: await readFile(caCert),
      },
    });
    expired.get('/health', async () => ({ status: 'ok' }));
    await expired.listen({ host: '127.0.0.1', port: 0 });
    const expiredUrl = `https://localhost:${(expired.server.address() as { port: number }).port}/health`;
    await assert.rejects(() =>
      httpsJsonRequest({
        url: expiredUrl,
        timeoutMs: 1000,
        tls: { caPath: caCert, servername: 'localhost' },
      }),
    );
    await expired.close();
    console.log('TKT-009.8D HTTPS native smoke: PASS (3 services, CA and hostname rejection)');
  } finally {
    for (const app of apps) await app.close().catch(() => undefined);
    await rm(dir, { recursive: true, force: true });
  }
}

await main();
