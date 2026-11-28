import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import test, { type TestContext } from 'node:test';
import mongoose, { Types } from 'mongoose';
import { AccessGrantModel } from '../src/models/access-grant.model.js';
import {
  ACCESS_GRANT_VEHICLE_PERMISSIONS,
  EVALUABLE_PERMISSIONS_BY_RESOURCE,
  isIssuableAccessGrantPermission,
} from '../src/models/vehicle-constants.js';
import {
  createDeviceServiceClient,
  DeviceUpstreamDomainError,
  DeviceUpstreamTimeoutError,
  DeviceUpstreamUnavailableError,
  toPublicDeviceDetail,
  type DeviceServiceClient,
  type VerifiedDeviceSnapshot,
} from '../src/services/device-client.service.js';
import {
  createVerifiedExternalResourceBinding,
  resourceAuthorization,
  verifyExternalResourceBinding,
} from '../src/services/resource-authorization.service.js';
import {
  getDirectDeviceDetail,
  getVehicleScopedDeviceDetail,
  listVehicleDevices,
  MAX_DEVICE_SCAN_BATCHES,
  revokeVehicleDevice,
} from '../src/services/vehicle-device.service.js';
import { VehicleServiceError } from '../src/services/vehicle-errors.js';
import { createVehicleTestApp, v2Headers } from './v2-fixture.js';

function makeInternalRecord(
  overrides: Partial<Parameters<typeof toPublicDeviceDetail>[0]> = {},
): Parameters<typeof toPublicDeviceDetail>[0] {
  const deviceId = String(new Types.ObjectId());
  const vehicleId = String(new Types.ObjectId());
  const credentialId = String(new Types.ObjectId());
  const requesterId = String(new Types.ObjectId());
  const membershipId = String(new Types.ObjectId());
  const nowIso = '2026-11-27T01:00:00.000Z';

  return {
    deviceId,
    vehicleId,
    identifier: 'esp32-sunroof',
    status: 'ACTIVE',
    operational: true,
    credential: {
      credentialId,
      keyId: `dk_${'A'.repeat(22)}`,
      algorithm: 'Ed25519',
      fingerprint: `sha256:${'a'.repeat(64)}`,
      status: 'ACTIVE',
      usable: true,
      activatedAt: nowIso,
      expiresAt: null,
      revokedAt: null,
    },
    connectivity: { lastSeenAt: null },
    metadata: {
      name: 'Sunroof',
      manufacturer: 'Espressif',
      hardwareModel: 'ESP32-S3',
      hardwareRevision: 'rev-1',
      firmwareVersion: '1.0.0',
      serialNumber: 'SN-1',
    },
    createdAt: nowIso,
    updatedAt: nowIso,
    linkedAt: nowIso,
    revokedAt: null,
    revocationReason: null,
    requestedByUserId: requesterId,
    requestedByMembershipId: membershipId,
    revokedByUserId: null,
    ...overrides,
  };
}

test('toPublicDeviceDetail strips internal audit/membership fields and rejects secret leakage', () => {
  const internal = makeInternalRecord();
  const projected = toPublicDeviceDetail(internal);

  assert.equal('requestedByUserId' in projected, false);
  assert.equal('requestedByMembershipId' in projected, false);
  assert.equal('revokedByUserId' in projected, false);
  assert.equal('publicKey' in projected.credential, false);
  assert.equal(projected.deviceId, internal.deviceId);
  assert.equal(projected.metadata.name, 'Sunroof');
});

test('DeviceServiceClient mints VerifiedExternalResourceBinding solely for operational ACTIVE devices and rejects upstream identity or contract mismatches', async (t) => {
  const vehicleId = new Types.ObjectId();
  const deviceId = new Types.ObjectId();
  const actorUserId = new Types.ObjectId();
  const membershipId = new Types.ObjectId();

  let upstreamStatus = 200;
  let upstreamBody: unknown = {};
  let patchCalls = 0;

  t.mock.method(globalThis, 'fetch', async (url: string | URL | Request, init?: RequestInit) => {
    const target = String(url instanceof Request ? url.url : url);
    if (target.endsWith('/verified')) {
      return new Response(JSON.stringify({ verified: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    if ((init?.method ?? 'GET') === 'PATCH') {
      patchCalls += 1;
    }
    return new Response(JSON.stringify(upstreamBody), {
      status: upstreamStatus,
      headers: { 'content-type': 'application/json' },
    });
  });

  // Use a tiny Fastify inject hook inside Vehicle test app to capture an authenticated internal request context
  const app = createVehicleTestApp();
  t.after(async () => app.close());

  let capturedError: unknown;
  const dummyClientConfig = {
    environment: 'test' as const,
    sender: 'vehicle-service' as const,
    keyring: [
      {
        environment: 'test' as const,
        sender: 'vehicle-service' as const,
        audience: 'device-service' as const,
        keyId: 'veh-dev',
        secret: Buffer.alloc(32, 9),
        state: 'active' as const,
        notBefore: 0,
        notAfter: 9_000_000_000_000_000,
      },
    ],
  };

  let probeRunner:
    ((client: ReturnType<typeof createDeviceServiceClient>) => Promise<void>) | undefined;
  app.addHook('preHandler', async (request, reply) => {
    if (request.headers['x-unit-device-client-probe'] === '1' && probeRunner) {
      const client = createDeviceServiceClient(
        request,
        dummyClientConfig,
        'http://device-unit.local',
      );
      try {
        await probeRunner(client);
        return reply.code(200).send({ ok: true });
      } catch (err) {
        capturedError = err;
        return reply.code(200).send({ ok: false });
      }
    }
  });

  // Verify retired alias POST /vehicles/:vehicleId/devices/link returns 404
  const retiredUrl = `/vehicles/${vehicleId}/devices/link`;
  const retiredPayload = Buffer.from(JSON.stringify({ userId: String(actorUserId) }));
  const retiredRes = await app.inject({
    method: 'POST',
    url: retiredUrl,
    headers: v2Headers(retiredPayload, 'POST', retiredUrl),
    payload: retiredPayload,
  });
  assert.equal(retiredRes.statusCode, 404);

  const runProbe = async (
    method: 'GET' | 'POST' | 'PATCH',
    fn: (client: ReturnType<typeof createDeviceServiceClient>) => Promise<void>,
  ): Promise<unknown> => {
    capturedError = undefined;
    probeRunner = fn;
    const url =
      method === 'GET'
        ? `/devices/${deviceId}?userId=${actorUserId}`
        : method === 'POST'
          ? `/vehicles/${vehicleId}/devices/${deviceId}/challenge`
          : `/vehicles/${vehicleId}/devices/${deviceId}`;
    const payload =
      method === 'GET'
        ? Buffer.alloc(0)
        : method === 'POST'
          ? Buffer.from(JSON.stringify({ userId: String(actorUserId) }))
          : Buffer.from(JSON.stringify({ userId: String(actorUserId), name: 'Probe' }));
    const headers = {
      ...v2Headers(payload, method, url),
      'x-unit-device-client-probe': '1',
    };
    const res = await app.inject({
      method,
      url,
      headers,
      ...(method === 'GET' ? {} : { payload }),
    });
    assert.equal(res.statusCode, 200);
    return capturedError;
  };

  // 1) Operational ACTIVE device produces a genuine VerifiedExternalResourceBinding
  const activeRecord = makeInternalRecord({
    deviceId: String(deviceId),
    vehicleId: String(vehicleId),
    status: 'ACTIVE',
    operational: true,
  });
  upstreamStatus = 200;
  upstreamBody = { data: activeRecord };
  await runProbe('GET', async (client) => {
    const snap = await client.getDeviceById(String(deviceId));
    assert.ok(snap);
    assert.ok(snap.activeBinding);
    assert.equal(
      verifyExternalResourceBinding(vehicleId, {
        type: 'DEVICE',
        resourceId: deviceId,
        binding: snap.activeBinding,
      }),
      true,
    );
    assert.equal(
      verifyExternalResourceBinding(new Types.ObjectId(), {
        type: 'DEVICE',
        resourceId: deviceId,
        binding: snap.activeBinding,
      }),
      false,
      'binding is locked to its authoritative vehicleId',
    );
  });
  assert.equal(capturedError, undefined);

  // 2) PENDING, REVOKED, and degraded ACTIVE (expired credential) NEVER mint activeBinding
  for (const nonOperational of [
    makeInternalRecord({
      deviceId: String(deviceId),
      vehicleId: String(vehicleId),
      status: 'PENDING',
      operational: false,
      linkedAt: null,
    }),
    makeInternalRecord({
      deviceId: String(deviceId),
      vehicleId: String(vehicleId),
      status: 'REVOKED',
      operational: false,
      revokedAt: '2026-11-27T01:05:00.000Z',
      revocationReason: 'LOST',
      credential: {
        ...activeRecord.credential,
        status: 'REVOKED',
        usable: false,
        revokedAt: '2026-11-27T01:05:00.000Z',
      },
    }),
    makeInternalRecord({
      deviceId: String(deviceId),
      vehicleId: String(vehicleId),
      status: 'ACTIVE',
      operational: false,
      credential: {
        ...activeRecord.credential,
        status: 'EXPIRED',
        usable: false,
        expiresAt: '2026-11-26T00:00:00.000Z',
      },
    }),
  ]) {
    upstreamStatus = 200;
    upstreamBody = { data: nonOperational };
    await runProbe('GET', async (client) => {
      const snap = await client.getDeviceById(String(deviceId));
      assert.ok(snap);
      assert.equal(snap.activeBinding, null);
    });
    assert.equal(capturedError, undefined);
  }

  // 3) Contradictory upstream response claiming operational=true on PENDING/REVOKED fails closed (PROTOCOL_ERROR)
  upstreamStatus = 200;
  upstreamBody = {
    data: makeInternalRecord({
      deviceId: String(deviceId),
      vehicleId: String(vehicleId),
      status: 'PENDING',
      operational: true,
    }),
  };
  const probeErr3 = await runProbe('GET', async (client) => {
    await client.getDeviceById(String(deviceId));
  });
  assert.ok(
    probeErr3 instanceof DeviceUpstreamUnavailableError && probeErr3.reason === 'PROTOCOL_ERROR',
  );

  // 4) Upstream deviceId or vehicleId mismatch fails closed (PROTOCOL_ERROR)
  upstreamStatus = 200;
  upstreamBody = {
    data: makeInternalRecord({
      deviceId: String(new Types.ObjectId()),
      vehicleId: String(vehicleId),
    }),
  };
  const probeErr4a = await runProbe('GET', async (client) => {
    await client.getDeviceById(String(deviceId));
  });
  assert.ok(
    probeErr4a instanceof DeviceUpstreamUnavailableError && probeErr4a.reason === 'PROTOCOL_ERROR',
  );

  upstreamStatus = 201;
  upstreamBody = {
    data: {
      protocol: 'pichu-device-link-v1',
      challengeId: String(new Types.ObjectId()),
      deviceId: String(deviceId),
      vehicleId: String(new Types.ObjectId()), // wrong vehicleId!
      credentialId: String(new Types.ObjectId()),
      requestedByUserId: String(actorUserId),
      challenge: 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8',
      expiresAt: '2026-11-27T01:05:00.000Z',
    },
  };
  const probeErr4b = await runProbe('POST', async (client) => {
    await client.createChallenge({
      deviceId: String(deviceId),
      vehicleId: String(vehicleId),
      userId: String(actorUserId),
      membershipId: String(membershipId),
    });
  });
  assert.ok(
    probeErr4b instanceof DeviceUpstreamUnavailableError && probeErr4b.reason === 'PROTOCOL_ERROR',
  );

  // 5) Closed domain error translation: 400 and 409 are NEVER blindly converted to 503;
  //    503 on PATCH is NEVER retried (patchCalls === 1); 504 maps to DeviceUpstreamTimeoutError.
  upstreamStatus = 409;
  upstreamBody = {
    error: 'DEVICE_ALREADY_REGISTERED',
    message: 'Sensitive internal detail that must not be forwarded verbatim',
    requestId: 'r1',
  };
  const probeErr5 = await runProbe('POST', async (client) => {
    await client.registerDevice({
      identifier: 'esp32-dup',
      publicKey: 'k'.repeat(44),
      vehicleId: String(vehicleId),
      userId: String(actorUserId),
      membershipId: String(membershipId),
    });
  });
  assert.ok(
    probeErr5 instanceof DeviceUpstreamDomainError &&
      probeErr5.status === 409 &&
      probeErr5.code === 'DEVICE_ALREADY_REGISTERED',
  );

  patchCalls = 0;
  upstreamStatus = 503;
  upstreamBody = { error: 'DEVICE_DATABASE_UNAVAILABLE', message: 'down', requestId: 'r2' };
  const probeErr503 = await runProbe('PATCH', async (client) => {
    await client.updateDeviceMetadata({
      deviceId: String(deviceId),
      vehicleId: String(vehicleId),
      userId: String(actorUserId),
      metadata: { name: 'Once' },
    });
  });
  assert.equal(patchCalls, 1, 'PATCH mutations must never be retried');
  assert.ok(probeErr503 instanceof DeviceUpstreamUnavailableError);

  upstreamStatus = 504;
  upstreamBody = { message: 'timed out' };
  const probeErr504 = await runProbe('PATCH', async (client) => {
    await client.updateDeviceMetadata({
      deviceId: String(deviceId),
      vehicleId: String(vehicleId),
      userId: String(actorUserId),
      metadata: { name: 'Timeout' },
    });
  });
  assert.ok(probeErr504 instanceof DeviceUpstreamTimeoutError);
});

test('listVehicleDevices handles >5 unauthorized batches without data loss, leaks, loops, duplicates, or N+1 queries', async (t) => {
  const vehicleId = new Types.ObjectId();
  const ownerUserId = new Types.ObjectId();
  const actorUserId = new Types.ObjectId();
  const otherUserId = new Types.ObjectId();
  const actorMembershipId = new Types.ObjectId();
  const otherMembershipId = new Types.ObjectId();
  const now = new Date('2026-11-27T02:00:00.000Z');
  const cursorSecrets = [randomBytes(32), randomBytes(32)];

  const makeSnapshot = (
    index: number,
    options: { status?: 'PENDING' | 'ACTIVE'; requesterUserId?: Types.ObjectId } = {},
  ): VerifiedDeviceSnapshot => {
    const deviceId = String(new Types.ObjectId());
    const status = options.status ?? 'PENDING';
    const createdAtIso = new Date(now.getTime() + index * 1_000).toISOString();
    const record = makeInternalRecord({
      deviceId,
      vehicleId: String(vehicleId),
      identifier: `dev-${String(index).padStart(4, '0')}`,
      status,
      operational: status === 'ACTIVE',
      credential: {
        credentialId: String(new Types.ObjectId()),
        keyId: `dk_${String(index).padStart(22, '0')}`,
        algorithm: 'Ed25519',
        fingerprint: `sha256:${'b'.repeat(64)}`,
        status: 'ACTIVE',
        usable: true,
        activatedAt: createdAtIso,
        expiresAt: null,
        revokedAt: null,
      },
      createdAt: createdAtIso,
      requestedByUserId: String(options.requesterUserId ?? otherUserId),
      requestedByMembershipId: String(otherMembershipId),
      linkedAt: status === 'ACTIVE' ? createdAtIso : null,
    });
    return {
      record,
      publicDetail: toPublicDeviceDetail(record),
      activeBinding:
        status === 'ACTIVE'
          ? createVerifiedExternalResourceBinding({
              scopeType: 'DEVICE',
              resourceId: Types.ObjectId.createFromHexString(deviceId),
              vehicleId,
              isActive: true,
            })
          : null,
    };
  };

  // 130 hidden items across first >5 batches (limit=2 => batchSize=25 => 5 batches = 125 items)
  // followed by 3 authorized ACTIVE devices after batch 5, plus 2 trailing hidden items.
  const catalog: VerifiedDeviceSnapshot[] = [];
  for (let i = 0; i < 130; i += 1) {
    catalog.push(makeSnapshot(i, { status: i % 2 === 0 ? 'PENDING' : 'ACTIVE' }));
  }
  const authD1 = makeSnapshot(130, { status: 'ACTIVE' });
  const authD2 = makeSnapshot(131, { status: 'ACTIVE' });
  const hiddenGap = makeSnapshot(132, { status: 'ACTIVE' });
  const authD3 = makeSnapshot(133, { status: 'ACTIVE' });
  const trailingHidden = makeSnapshot(134, { status: 'PENDING' });
  catalog.push(authD1, authD2, hiddenGap, authD3, trailingHidden);

  const authorizedIds = new Set([
    authD1.record.deviceId,
    authD2.record.deviceId,
    authD3.record.deviceId,
  ]);
  const hiddenIds = catalog
    .filter((entry) => !authorizedIds.has(entry.record.deviceId))
    .map((entry) => entry.record.deviceId);
  const hiddenCreatedAts = catalog
    .filter((entry) => !authorizedIds.has(entry.record.deviceId))
    .map((entry) => entry.record.createdAt);

  let currentSubjectActive = true;
  let grantQueryCount = 0;

  const originalReadyStateDescriptor = Object.getOwnPropertyDescriptor(
    mongoose.connection,
    'readyState',
  );
  Object.defineProperty(mongoose.connection, 'readyState', {
    configurable: true,
    get: () => 1,
  });
  t.after(() => {
    if (originalReadyStateDescriptor) {
      Object.defineProperty(mongoose.connection, 'readyState', originalReadyStateDescriptor);
    } else {
      delete (mongoose.connection as unknown as Record<string, unknown>).readyState;
    }
  });

  t.mock.method(resourceAuthorization, 'resolveSubject', async () => {
    if (!currentSubjectActive) {
      return { resolved: false, reason: 'NO_ACTIVE_MEMBERSHIP' } as never;
    }
    return {
      resolved: true,
      subject: {
        vehicle: {
          _id: vehicleId,
          name: 'Mazda 3',
          make: 'Mazda',
          model: '3',
          generation: null,
          trim: null,
          year: 2011,
          bodyStyle: 'SEDAN',
          ownerUserId,
          archivedAt: null,
        },
        membership: {
          _id: actorMembershipId,
          vehicleId,
          userId: actorUserId,
          role: 'MEMBER',
          permissions: ['vehicle:read'],
          status: 'ACTIVE',
          revokedAt: null,
        },
      },
    } as never;
  });

  t.mock.method(
    resourceAuthorization,
    'evaluate',
    async (req: Parameters<typeof resourceAuthorization.evaluate>[0]) => {
      if (req.permission === 'device:link') {
        return {
          allowed: false,
          reason: 'MISSING_BASE_PERMISSION',
          membershipId: actorMembershipId,
        } as never;
      }
      if (
        req.resource.type === 'DEVICE' &&
        req.permission === 'device:read' &&
        authorizedIds.has(String(req.resource.resourceId))
      ) {
        return {
          allowed: true,
          source: 'GRANT',
          membershipId: actorMembershipId,
        } as never;
      }
      return {
        allowed: false,
        reason: 'NO_MATCHING_GRANT',
        membershipId: actorMembershipId,
      } as never;
    },
  );

  t.mock.method(resourceAuthorization, 'hasVehicleReadAccess', async () => true);

  t.mock.method(AccessGrantModel, 'find', () => {
    grantQueryCount += 1;
    return {
      limit() {
        return this;
      },
      async lean() {
        return Array.from(authorizedIds).map((id) => ({
          scopeResourceId: Types.ObjectId.createFromHexString(id),
        }));
      },
    } as never;
  });

  let upstreamBatchesRequested = 0;
  const deviceClientStub: DeviceServiceClient = {
    async listVehicleDevicesBatch(input) {
      upstreamBatchesRequested += 1;
      const startIndex =
        input.afterCreatedAt && input.afterId
          ? catalog.findIndex(
              (entry) =>
                entry.record.createdAt > input.afterCreatedAt! ||
                (entry.record.createdAt === input.afterCreatedAt! &&
                  entry.record.deviceId > input.afterId!),
            )
          : 0;
      const slice = startIndex === -1 ? [] : catalog.slice(startIndex, startIndex + input.limit);
      const hasMore =
        startIndex !== -1 && startIndex + slice.length < catalog.length && slice.length > 0;
      return { items: slice, hasMore };
    },
    async getDeviceById() {
      throw new Error('unused');
    },
    async registerDevice() {
      throw new Error('unused');
    },
    async updateDeviceMetadata() {
      throw new Error('unused');
    },
    async createChallenge() {
      throw new Error('unused');
    },
    async completeLink() {
      throw new Error('unused');
    },
    async revokeDevice() {
      throw new Error('unused');
    },
  };

  // Page 1: scans MAX_DEVICE_SCAN_BATCHES (5 * 25 = 125 unauthorized items), returns empty page + opaque nextCursor
  const page1 = await listVehicleDevices(
    vehicleId,
    actorUserId,
    { limit: 2 },
    { deviceClient: deviceClientStub, now, cursorSecrets },
  );
  assert.equal(upstreamBatchesRequested, MAX_DEVICE_SCAN_BATCHES);
  assert.equal(grantQueryCount, 1, 'must execute at most 1 grant query per page (no N+1)');
  assert.deepEqual(page1.devices, []);
  assert.ok(page1.nextCursor, 'empty page after MAX_DEVICE_SCAN_BATCHES must still return cursor');
  assert.ok(page1.nextCursor.length <= 256);

  // Cursor must NOT reveal hidden deviceId or createdAt even in raw decoded base64url bytes
  const rawCursorDecoded = Buffer.from(page1.nextCursor, 'base64url').toString('latin1');
  for (const hiddenId of hiddenIds) {
    assert.equal(page1.nextCursor.includes(hiddenId), false);
    assert.equal(rawCursorDecoded.includes(hiddenId), false);
  }
  for (const hiddenCreatedAt of hiddenCreatedAts) {
    assert.equal(page1.nextCursor.includes(hiddenCreatedAt), false);
    assert.equal(rawCursorDecoded.includes(hiddenCreatedAt), false);
  }

  // Tampering or wrong scope/key must fail closed
  const tampered = `${page1.nextCursor.slice(0, -2)}${page1.nextCursor.endsWith('AA') ? 'BB' : 'AA'}`;
  await assert.rejects(
    () =>
      listVehicleDevices(
        vehicleId,
        actorUserId,
        { limit: 2, cursor: tampered },
        { deviceClient: deviceClientStub, now, cursorSecrets },
      ),
    (error: unknown) => error instanceof VehicleServiceError && error.code === 'VALIDATION_ERROR',
  );
  await assert.rejects(
    () =>
      listVehicleDevices(
        vehicleId,
        actorUserId,
        { limit: 2, cursor: page1.nextCursor!, status: 'ACTIVE' },
        { deviceClient: deviceClientStub, now, cursorSecrets },
      ),
    (error: unknown) => error instanceof VehicleServiceError && error.code === 'VALIDATION_ERROR',
  );

  // Page 2: advances past batch 5, discovers authD1 and authD2, and returns cursor (still supports key rotation)
  const rotatedSecrets = [randomBytes(32), cursorSecrets[0]!];
  const page2 = await listVehicleDevices(
    vehicleId,
    actorUserId,
    { limit: 2, cursor: page1.nextCursor },
    { deviceClient: deviceClientStub, now, cursorSecrets: rotatedSecrets },
  );
  assert.equal(grantQueryCount, 2);
  assert.deepEqual(
    page2.devices.map((d) => d.deviceId),
    [authD1.record.deviceId, authD2.record.deviceId],
  );
  assert.ok(page2.nextCursor);
  assert.notEqual(page2.nextCursor, page1.nextCursor);

  // Page 3: returns authD3 with null cursor (no duplicates, no omissions); old key-only keyring rejects cursor signed with new active key
  await assert.rejects(
    () =>
      listVehicleDevices(
        vehicleId,
        actorUserId,
        { limit: 2, cursor: page2.nextCursor! },
        { deviceClient: deviceClientStub, now, cursorSecrets },
      ),
    (error: unknown) => error instanceof VehicleServiceError && error.code === 'VALIDATION_ERROR',
  );
  const page3 = await listVehicleDevices(
    vehicleId,
    actorUserId,
    { limit: 2, cursor: page2.nextCursor },
    { deviceClient: deviceClientStub, now, cursorSecrets: rotatedSecrets },
  );
  assert.equal(grantQueryCount, 3);
  assert.deepEqual(
    page3.devices.map((d) => d.deviceId),
    [authD3.record.deviceId],
  );
  assert.equal(page3.nextCursor, null);

  // Re-evaluate permissions per page: revoking authD3's grant before re-fetching page 3 drops it
  authorizedIds.delete(authD3.record.deviceId);
  const page3AfterGrantRevoke = await listVehicleDevices(
    vehicleId,
    actorUserId,
    { limit: 2, cursor: page2.nextCursor },
    { deviceClient: deviceClientStub, now, cursorSecrets: rotatedSecrets },
  );
  assert.deepEqual(page3AfterGrantRevoke.devices, []);
  assert.equal(page3AfterGrantRevoke.nextCursor, null);

  // Re-evaluate membership per page: revoking membership blocks using a previously issued valid cursor
  currentSubjectActive = false;
  await assert.rejects(
    () =>
      listVehicleDevices(
        vehicleId,
        actorUserId,
        { limit: 2, cursor: page1.nextCursor! },
        { deviceClient: deviceClientStub, now, cursorSecrets },
      ),
    (error: unknown) => error instanceof VehicleServiceError && error.code === 'NOT_FOUND',
  );
  currentSubjectActive = true;
  authorizedIds.add(authD3.record.deviceId);

  // Mixed partial-page case (strictly sorted by createdAt ASC, _id ASC):
  // 1 visible item in batch 1, 0 in batches 2..5, and 1 visible item in batch 6
  const earlyVisible = makeSnapshot(0, { status: 'ACTIVE' });
  authorizedIds.add(earlyVisible.record.deviceId);
  const partialCatalog: VerifiedDeviceSnapshot[] = [earlyVisible, ...catalog.slice(1, 130), authD3];
  const partialClient: DeviceServiceClient = {
    ...deviceClientStub,
    async listVehicleDevicesBatch(input) {
      const startIndex =
        input.afterCreatedAt && input.afterId
          ? partialCatalog.findIndex(
              (entry) =>
                entry.record.createdAt > input.afterCreatedAt! ||
                (entry.record.createdAt === input.afterCreatedAt! &&
                  entry.record.deviceId > input.afterId!),
            )
          : 0;
      const slice =
        startIndex === -1 ? [] : partialCatalog.slice(startIndex, startIndex + input.limit);
      const hasMore =
        startIndex !== -1 && startIndex + slice.length < partialCatalog.length && slice.length > 0;
      return { items: slice, hasMore };
    },
  };
  const partialPage1 = await listVehicleDevices(
    vehicleId,
    actorUserId,
    { limit: 2 },
    { deviceClient: partialClient, now, cursorSecrets },
  );
  assert.deepEqual(
    partialPage1.devices.map((d) => d.deviceId),
    [earlyVisible.record.deviceId],
  );
  assert.ok(partialPage1.nextCursor);
  const partialPage2 = await listVehicleDevices(
    vehicleId,
    actorUserId,
    { limit: 2, cursor: partialPage1.nextCursor },
    { deviceClient: partialClient, now, cursorSecrets },
  );
  assert.deepEqual(
    partialPage2.devices.map((d) => d.deviceId),
    [authD3.record.deviceId],
  );
  assert.equal(partialPage2.nextCursor, null);
});

test('authorization matrix rules: VEHICLE grants cannot grant device:read and repeated self-cancel requires current membership + authority', async (t) => {
  // Confirm static permission matrix aligns with TKT-013 (device:read is DEVICE/base, never evaluable on VEHICLE)
  assert.equal(EVALUABLE_PERMISSIONS_BY_RESOURCE.VEHICLE.includes('device:read' as never), false);
  assert.equal(EVALUABLE_PERMISSIONS_BY_RESOURCE.DEVICE.includes('device:read'), true);
  assert.equal(ACCESS_GRANT_VEHICLE_PERMISSIONS.includes('device:read'), true);
  assert.equal(isIssuableAccessGrantPermission('VEHICLE', 'device:read'), false);
  assert.equal(isIssuableAccessGrantPermission('DEVICE', 'device:read'), true);

  const vehicleId = new Types.ObjectId();
  const ownerUserId = new Types.ObjectId();
  const memberUserId = new Types.ObjectId();
  const membershipId = new Types.ObjectId();
  const deviceId = new Types.ObjectId();
  const now = new Date('2026-11-27T02:00:00.000Z');

  let basePermissions: string[] = ['device:link'];
  let activeMembershipId = membershipId;
  let evaluateLinkAllowed = true;
  let deviceStatus: 'PENDING' | 'REVOKED' = 'PENDING';
  let revokedAt: string | null = null;

  const currentSnapshot = (): VerifiedDeviceSnapshot => {
    const rec = makeInternalRecord({
      deviceId: String(deviceId),
      vehicleId: String(vehicleId),
      status: deviceStatus,
      operational: false,
      credential: {
        credentialId: String(new Types.ObjectId()),
        keyId: `dk_${'C'.repeat(22)}`,
        algorithm: 'Ed25519',
        fingerprint: `sha256:${'c'.repeat(64)}`,
        status: deviceStatus === 'REVOKED' ? 'REVOKED' : 'ACTIVE',
        usable: deviceStatus !== 'REVOKED',
        activatedAt: now.toISOString(),
        expiresAt: null,
        revokedAt,
      },
      requestedByUserId: String(memberUserId),
      requestedByMembershipId: String(membershipId),
      linkedAt: null,
      revokedAt,
      revokedByUserId: deviceStatus === 'REVOKED' ? String(memberUserId) : null,
      revocationReason: deviceStatus === 'REVOKED' ? 'REGISTRATION_CANCELLED' : null,
    });
    return { record: rec, publicDetail: toPublicDeviceDetail(rec), activeBinding: null };
  };

  t.mock.method(
    resourceAuthorization,
    'resolveSubject',
    async () =>
      ({
        resolved: true,
        subject: {
          vehicle: {
            _id: vehicleId,
            name: 'Mazda 3',
            make: null,
            model: null,
            generation: null,
            trim: null,
            year: null,
            bodyStyle: null,
            ownerUserId,
            archivedAt: null,
          },
          membership: {
            _id: activeMembershipId,
            vehicleId,
            userId: memberUserId,
            role: 'MEMBER',
            permissions: basePermissions,
            status: 'ACTIVE',
            revokedAt: null,
          },
        },
      }) as never,
  );

  t.mock.method(
    resourceAuthorization,
    'evaluateAnyOf',
    async () =>
      ({
        allowed: evaluateLinkAllowed,
        membershipId: activeMembershipId,
      }) as never,
  );

  t.mock.method(
    resourceAuthorization,
    'evaluate',
    async (req: Parameters<typeof resourceAuthorization.evaluate>[0]) => {
      if (basePermissions.includes(req.permission)) {
        return {
          allowed: true,
          source: 'MEMBERSHIP',
          membershipId: activeMembershipId,
        } as never;
      }
      return {
        allowed: false,
        reason: 'NO_MATCHING_GRANT',
        membershipId: activeMembershipId,
      } as never;
    },
  );

  let revokeCalls = 0;
  const deviceClientStub: DeviceServiceClient = {
    async listVehicleDevicesBatch() {
      return { items: [], hasMore: false };
    },
    async getDeviceById() {
      return currentSnapshot();
    },
    async registerDevice() {
      throw new Error('unused');
    },
    async updateDeviceMetadata() {
      throw new Error('unused');
    },
    async createChallenge() {
      throw new Error('unused');
    },
    async completeLink() {
      throw new Error('unused');
    },
    async revokeDevice() {
      revokeCalls += 1;
      if (deviceStatus === 'PENDING') {
        deviceStatus = 'REVOKED';
        revokedAt = '2026-11-27T02:01:00.000Z';
      }
      return currentSnapshot();
    },
  };

  // First self-cancel succeeds
  const firstCancel = await revokeVehicleDevice(
    vehicleId,
    deviceId,
    memberUserId,
    'REGISTRATION_CANCELLED',
    { deviceClient: deviceClientStub, now },
  );
  assert.equal(firstCancel.status, 'REVOKED');
  assert.equal(revokeCalls, 1);

  // Repeated self-cancel with intact original membership + authority succeeds idempotently
  const repeatCancel = await revokeVehicleDevice(
    vehicleId,
    deviceId,
    memberUserId,
    'REGISTRATION_CANCELLED',
    { deviceClient: deviceClientStub, now },
  );
  assert.equal(repeatCancel.status, 'REVOKED');
  assert.equal(revokeCalls, 2);

  // Removing link authority blocks repeated self-cancel without touching upstream
  evaluateLinkAllowed = false;
  basePermissions = ['vehicle:read'];
  await assert.rejects(
    () =>
      revokeVehicleDevice(vehicleId, deviceId, memberUserId, 'REGISTRATION_CANCELLED', {
        deviceClient: deviceClientStub,
        now,
      }),
    (error: unknown) => error instanceof VehicleServiceError && error.code === 'NOT_FOUND',
  );
  assert.equal(revokeCalls, 2);

  // Even with device:link restored on a NEW membershipId (re-invited user), original membership check fails closed
  evaluateLinkAllowed = true;
  basePermissions = ['device:link'];
  activeMembershipId = new Types.ObjectId();
  await assert.rejects(
    () =>
      revokeVehicleDevice(vehicleId, deviceId, memberUserId, 'REGISTRATION_CANCELLED', {
        deviceClient: deviceClientStub,
        now,
      }),
    (error: unknown) => error instanceof VehicleServiceError && error.code === 'NOT_FOUND',
  );
  assert.equal(revokeCalls, 2);

  // Vehicle-level device:read detail check rejects base vehicle:read without base device:read or DEVICE grant
  basePermissions = ['vehicle:read'];
  deviceStatus = 'PENDING';
  await assert.rejects(
    () =>
      getVehicleScopedDeviceDetail(vehicleId, deviceId, memberUserId, {
        deviceClient: deviceClientStub,
        now,
      }),
    (error: unknown) => error instanceof VehicleServiceError && error.code === 'NOT_FOUND',
  );

  // Base device:read (without vehicle:read) allows reading ACTIVE devices while rejecting PENDING/REVOKED
  basePermissions = ['device:read'];
  const activeSnapshot = (): VerifiedDeviceSnapshot => {
    const rec = makeInternalRecord({
      deviceId: String(deviceId),
      vehicleId: String(vehicleId),
      status: 'ACTIVE',
      operational: true,
      credential: {
        credentialId: String(new Types.ObjectId()),
        keyId: `dk_${'D'.repeat(22)}`,
        algorithm: 'Ed25519',
        fingerprint: `sha256:${'d'.repeat(64)}`,
        status: 'ACTIVE',
        usable: true,
        activatedAt: now.toISOString(),
        expiresAt: null,
        revokedAt: null,
      },
      linkedAt: now.toISOString(),
    });
    return {
      record: rec,
      publicDetail: toPublicDeviceDetail(rec),
      activeBinding: createVerifiedExternalResourceBinding({
        scopeType: 'DEVICE',
        resourceId: deviceId,
        vehicleId,
        isActive: true,
      }),
    };
  };
  const activeClientStub: DeviceServiceClient = {
    ...deviceClientStub,
    async getDeviceById() {
      return activeSnapshot();
    },
  };
  const readViaDirect = await getDirectDeviceDetail(deviceId, memberUserId, {
    deviceClient: activeClientStub,
    now,
  });
  assert.equal(readViaDirect.deviceId, String(deviceId));
  const readViaVehicle = await getVehicleScopedDeviceDetail(vehicleId, deviceId, memberUserId, {
    deviceClient: activeClientStub,
    now,
  });
  assert.equal(readViaVehicle.deviceId, String(deviceId));
});

type ProbeClient = ReturnType<typeof createDeviceServiceClient>;

/**
 * Runs DeviceServiceClient calls inside an authenticated Vehicle request against a mocked Device
 * upstream. `responses` is consumed per Device call; the last entry is reused when exhausted.
 */
function createDeviceClientProbe(t: TestContext) {
  const ids = {
    vehicleId: String(new Types.ObjectId()),
    deviceId: String(new Types.ObjectId()),
    userId: String(new Types.ObjectId()),
    membershipId: String(new Types.ObjectId()),
  };
  let responses: Array<{ status: number; body: unknown }> = [];
  const calls: string[] = [];

  t.mock.method(globalThis, 'fetch', async (url: string | URL | Request, init?: RequestInit) => {
    const target = new URL(String(url instanceof Request ? url.url : url));
    if (target.pathname.endsWith('/verified')) {
      return new Response(JSON.stringify({ verified: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    calls.push(`${init?.method ?? 'GET'} ${target.pathname}`);
    const next = (responses.length > 1 ? responses.shift() : responses[0]) ?? {
      status: 500,
      body: {},
    };
    return new Response(JSON.stringify(next.body), {
      status: next.status,
      headers: { 'content-type': 'application/json' },
    });
  });

  const app = createVehicleTestApp();
  t.after(async () => app.close());
  let runner: ((client: ProbeClient) => Promise<void>) | undefined;
  let captured: unknown;
  app.addHook('preHandler', async (request, reply) => {
    if (request.headers['x-unit-device-client-probe'] !== '1' || !runner) return;
    const client = createDeviceServiceClient(
      request,
      {
        environment: 'test',
        sender: 'vehicle-service',
        keyring: [
          {
            environment: 'test',
            sender: 'vehicle-service',
            audience: 'device-service',
            keyId: 'veh-dev',
            secret: Buffer.alloc(32, 9),
            state: 'active',
            notBefore: 0,
            notAfter: 9_000_000_000_000_000,
          },
        ],
      },
      'http://device-unit.local',
    );
    try {
      await runner(client);
    } catch (error) {
      captured = error;
    }
    return reply.code(200).send({ ok: true });
  });

  async function run(
    upstream: Array<{ status: number; body: unknown }>,
    fn: (client: ProbeClient) => Promise<void>,
  ): Promise<unknown> {
    responses = [...upstream];
    calls.length = 0;
    captured = undefined;
    runner = fn;
    const url = `/devices/${ids.deviceId}?userId=${ids.userId}`;
    const res = await app.inject({
      method: 'GET',
      url,
      headers: { ...v2Headers(Buffer.alloc(0), 'GET', url), 'x-unit-device-client-probe': '1' },
    });
    assert.equal(res.statusCode, 200);
    return captured;
  }

  return { ids, calls, run };
}

function isProtocolError(error: unknown): boolean {
  return error instanceof DeviceUpstreamUnavailableError && error.reason === 'PROTOCOL_ERROR';
}

const REVOKED_AT = '2026-11-27T01:05:00.000Z';

function probeRecords(ids: ReturnType<typeof createDeviceClientProbe>['ids']) {
  const active = makeInternalRecord({
    deviceId: ids.deviceId,
    vehicleId: ids.vehicleId,
    requestedByUserId: ids.userId,
    requestedByMembershipId: ids.membershipId,
  });
  const pending = { ...active, status: 'PENDING' as const, operational: false, linkedAt: null };
  const revoked = {
    ...active,
    status: 'REVOKED' as const,
    operational: false,
    revokedAt: REVOKED_AT,
    revocationReason: 'LOST' as const,
    revokedByUserId: null,
    credential: {
      ...active.credential,
      status: 'REVOKED' as const,
      usable: false,
      revokedAt: REVOKED_AT,
    },
  };
  return { active, pending, revoked };
}

test('DeviceServiceClient validates every upstream record structurally before any evidence, without recomputing expiry', async (t) => {
  const probe = createDeviceClientProbe(t);
  const { active, pending, revoked } = probeRecords(probe.ids);

  const contradictory: Array<[string, Parameters<typeof toPublicDeviceDetail>[0]]> = [
    ['ACTIVE with usable credential but operational=false', { ...active, operational: false }],
    ['PENDING claiming operational', { ...pending, operational: true }],
    ['PENDING with link audit', { ...pending, linkedAt: REVOKED_AT }],
    ['PENDING with revocation reason', { ...pending, revocationReason: 'LOST' }],
    [
      'ACTIVE with device revocation marker',
      { ...active, operational: false, revokedAt: REVOKED_AT },
    ],
    ['ACTIVE with revoking user', { ...active, revokedByUserId: probe.ids.userId }],
    ['REVOKED without revocationReason', { ...revoked, revocationReason: null }],
    ['REVOKED without revokedAt', { ...revoked, revokedAt: null }],
    [
      'REVOKED with a non-revoked credential',
      { ...revoked, credential: { ...active.credential, usable: false } },
    ],
    [
      'REVOKED claiming operational',
      { ...revoked, operational: true, credential: { ...revoked.credential, usable: true } },
    ],
    [
      'REVOKED credential without revokedAt',
      { ...pending, credential: { ...revoked.credential, revokedAt: null } },
    ],
    [
      'ACTIVE credential carrying revokedAt',
      { ...pending, credential: { ...active.credential, revokedAt: REVOKED_AT } },
    ],
    [
      'EXPIRED credential without expiresAt',
      {
        ...active,
        operational: false,
        credential: { ...active.credential, status: 'EXPIRED', usable: false },
      },
    ],
    [
      'EXPIRED credential reported usable',
      {
        ...active,
        credential: {
          ...active.credential,
          status: 'EXPIRED',
          usable: true,
          expiresAt: '2026-11-27T02:00:00.000Z',
        },
      },
    ],
    ['membership without requester', { ...pending, requestedByUserId: null }],
    ['foreign deviceId', { ...active, deviceId: String(new Types.ObjectId()) }],
  ];
  for (const [label, record] of contradictory) {
    let snapshot: VerifiedDeviceSnapshot | null = null;
    const error = await probe.run([{ status: 200, body: { data: record } }], async (client) => {
      snapshot = await client.getDeviceById(probe.ids.deviceId);
    });
    assert.ok(isProtocolError(error), label);
    assert.equal(snapshot, null, `${label}: no snapshot or evidence escapes`);
  }

  const legitimate: Array<[string, Parameters<typeof toPublicDeviceDetail>[0], boolean]> = [
    ['historical ACTIVE without linkedAt', { ...active, linkedAt: null }, true],
    [
      'ACTIVE whose expiresAt already passed on Vehicle clock but Device observed usable',
      { ...active, credential: { ...active.credential, expiresAt: '2000-01-01T00:00:00.000Z' } },
      true,
    ],
    [
      'ACTIVE link with credential-only revocation',
      {
        ...active,
        operational: false,
        credential: {
          ...active.credential,
          status: 'REVOKED',
          usable: false,
          revokedAt: REVOKED_AT,
        },
      },
      false,
    ],
    [
      'ACTIVE with credential not yet activated on Device clock',
      { ...active, operational: false, credential: { ...active.credential, usable: false } },
      false,
    ],
    [
      'PENDING with credential-only revocation',
      {
        ...pending,
        credential: {
          ...active.credential,
          status: 'REVOKED',
          usable: false,
          revokedAt: REVOKED_AT,
        },
      },
      false,
    ],
    [
      'historical PENDING without enrollment context',
      { ...pending, requestedByUserId: null, requestedByMembershipId: null },
      false,
    ],
    ['REVOKED by SERVICE or SYSTEM (no revoking user)', revoked, false],
    ['REVOKED by USER', { ...revoked, revokedByUserId: probe.ids.userId }, false],
  ];
  for (const [label, record, expectsEvidence] of legitimate) {
    let snapshot: VerifiedDeviceSnapshot | null = null;
    const error = await probe.run([{ status: 200, body: { data: record } }], async (client) => {
      snapshot = await client.getDeviceById(probe.ids.deviceId);
    });
    assert.equal(error, undefined, label);
    assert.ok(snapshot, label);
    assert.equal(
      (snapshot as VerifiedDeviceSnapshot).activeBinding !== null,
      expectsEvidence,
      label,
    );
  }
});

test('DeviceServiceClient rejects contradictory register, link, list, PATCH and revoke responses per operation', async (t) => {
  const probe = createDeviceClientProbe(t);
  const { active, pending, revoked } = probeRecords(probe.ids);
  const { publicKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const fingerprint = `sha256:${createHash('sha256')
    .update(publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex')}`;
  const registered = {
    ...pending,
    identifier: 'esp32-registered',
    credential: { ...pending.credential, fingerprint },
  };
  const registerInput = {
    identifier: 'esp32-registered',
    publicKey: publicKeyPem,
    vehicleId: probe.ids.vehicleId,
    userId: probe.ids.userId,
    membershipId: probe.ids.membershipId,
  };
  const register = (data: unknown, deviceId = probe.ids.deviceId) =>
    probe.run([{ status: 201, body: { deviceId, status: 'PENDING', data } }], async (client) => {
      const snapshot = await client.registerDevice(registerInput);
      assert.equal(snapshot.activeBinding, null);
    });

  assert.equal(await register(registered), undefined, 'coherent registration is accepted');
  const otherId = () => String(new Types.ObjectId());
  for (const [label, data, deviceId] of [
    ['envelope/inner deviceId mismatch', registered, otherId()],
    ['ACTIVE inner status', { ...registered, status: 'ACTIVE', operational: true }],
    ['operational PENDING', { ...registered, operational: true }],
    ['foreign vehicle', { ...registered, vehicleId: otherId() }],
    ['foreign requester', { ...registered, requestedByUserId: otherId() }],
    ['foreign membership', { ...registered, requestedByMembershipId: otherId() }],
    ['missing membership', { ...registered, requestedByMembershipId: null }],
    ['other identifier', { ...registered, identifier: 'esp32-other' }],
    [
      'credential for another key',
      {
        ...registered,
        credential: { ...registered.credential, fingerprint: `sha256:${'e'.repeat(64)}` },
      },
    ],
    [
      'revoked credential',
      {
        ...registered,
        credential: {
          ...registered.credential,
          status: 'REVOKED',
          usable: false,
          revokedAt: REVOKED_AT,
        },
      },
    ],
    ['link audit on registration', { ...registered, linkedAt: REVOKED_AT }],
  ] as Array<[string, unknown, string?]>) {
    assert.ok(isProtocolError(await register(data, deviceId)), `register: ${label}`);
  }

  const linkInput = {
    deviceId: probe.ids.deviceId,
    vehicleId: probe.ids.vehicleId,
    userId: probe.ids.userId,
    membershipId: probe.ids.membershipId,
    challengeId: otherId(),
    challenge: 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8',
    signature: 'A'.repeat(86),
  };
  const link = (data: unknown) =>
    probe.run([{ status: 200, body: { data } }], async (client) => {
      const snapshot = await client.completeLink(linkInput);
      assert.ok(snapshot.activeBinding);
    });
  assert.equal(await link(active), undefined, 'coherent link completion mints evidence');
  for (const [label, data] of [
    ['still PENDING', pending],
    [
      'ACTIVE but not operational',
      { ...active, operational: false, credential: { ...active.credential, usable: false } },
    ],
    ['ACTIVE without linkedAt', { ...active, linkedAt: null }],
    ['other requester', { ...active, requestedByUserId: otherId() }],
    ['other membership', { ...active, requestedByMembershipId: otherId() }],
    ['foreign vehicle', { ...active, vehicleId: otherId() }],
    ['REVOKED', revoked],
  ] as Array<[string, unknown]>) {
    assert.ok(isProtocolError(await link(data)), `link: ${label}`);
  }

  const second = { ...pending, deviceId: otherId(), identifier: 'esp32-second' };
  const list = (devices: unknown[], status?: 'PENDING' | 'ACTIVE') =>
    probe.run([{ status: 200, body: { devices, hasMore: false } }], async (client) => {
      await client.listVehicleDevicesBatch({
        vehicleId: probe.ids.vehicleId,
        limit: 10,
        ...(status ? { status } : {}),
      });
    });
  assert.equal(await list([pending, second, { ...revoked, deviceId: otherId() }]), undefined);
  assert.ok(isProtocolError(await list([pending, pending])), 'list: duplicate deviceId');
  assert.ok(
    isProtocolError(await list([pending, { ...second, vehicleId: otherId() }])),
    'list: cross-vehicle record',
  );
  assert.ok(isProtocolError(await list([pending], 'ACTIVE')), 'list: status filter mismatch');
  assert.ok(
    isProtocolError(await list([second, { ...active, operational: false }])),
    'list: one incoherent record fails the whole batch',
  );

  const patch = (data: unknown) =>
    probe.run([{ status: 200, body: { data } }], async (client) => {
      await client.updateDeviceMetadata({
        deviceId: probe.ids.deviceId,
        vehicleId: probe.ids.vehicleId,
        userId: probe.ids.userId,
        metadata: { name: 'Renamed', serialNumber: null },
      });
    });
  const patched = {
    ...active,
    metadata: { ...active.metadata, name: 'Renamed', serialNumber: null },
  };
  assert.equal(await patch(patched), undefined);
  assert.ok(isProtocolError(await patch(active)), 'PATCH: requested metadata not applied');
  assert.ok(
    isProtocolError(await patch({ ...revoked, metadata: patched.metadata })),
    'PATCH: REVOKED result',
  );
  assert.ok(
    isProtocolError(await patch({ ...patched, operational: false })),
    'PATCH: incoherent result',
  );

  const revoke = (data: unknown) =>
    probe.run([{ status: 200, body: { data } }], async (client) => {
      const snapshot = await client.revokeDevice({
        deviceId: probe.ids.deviceId,
        vehicleId: probe.ids.vehicleId,
        userId: probe.ids.userId,
        reason: 'LOST',
      });
      assert.equal(snapshot.activeBinding, null);
    });
  assert.equal(await revoke(revoked), undefined, 'SERVICE/SYSTEM revocation without user');
  assert.ok(isProtocolError(await revoke(active)), 'revoke: success cannot represent ACTIVE');
  assert.ok(
    isProtocolError(await revoke({ ...revoked, revocationReason: null })),
    'revoke: missing audit',
  );
  assert.ok(
    isProtocolError(
      await revoke({ ...revoked, credential: { ...active.credential, usable: false } }),
    ),
    'revoke: credential still ACTIVE',
  );
});

test('DeviceServiceClient accepts only challenges bound to the expected device, vehicle and requester', async (t) => {
  const probe = createDeviceClientProbe(t);
  const challenge = {
    protocol: 'pichu-device-link-v1',
    challengeId: String(new Types.ObjectId()),
    deviceId: probe.ids.deviceId,
    vehicleId: probe.ids.vehicleId,
    credentialId: String(new Types.ObjectId()),
    requestedByUserId: probe.ids.userId,
    challenge: 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8',
    expiresAt: '2026-11-27T01:05:00.000Z',
  };
  const issue = (status: number, data: unknown) =>
    probe.run([{ status, body: { data } }], async (client) => {
      const issued = await client.createChallenge({
        deviceId: probe.ids.deviceId,
        vehicleId: probe.ids.vehicleId,
        userId: probe.ids.userId,
        membershipId: probe.ids.membershipId,
      });
      assert.deepEqual(issued, challenge);
    });

  assert.equal(await issue(201, challenge), undefined);
  assert.deepEqual(probe.calls, [`POST /internal/devices/${probe.ids.deviceId}/challenge`]);
  for (const [label, status, data] of [
    ['foreign device', 201, { ...challenge, deviceId: String(new Types.ObjectId()) }],
    ['foreign vehicle', 201, { ...challenge, vehicleId: String(new Types.ObjectId()) }],
    ['foreign requester', 201, { ...challenge, requestedByUserId: String(new Types.ObjectId()) }],
    ['other protocol', 201, { ...challenge, protocol: 'pichu-device-link-v0' }],
    ['missing credential', 201, { ...challenge, credentialId: undefined }],
    ['extra field', 201, { ...challenge, membershipId: probe.ids.membershipId }],
    ['non-201 success', 200, challenge],
  ] as Array<[string, number, unknown]>) {
    assert.ok(isProtocolError(await issue(status, data)), `challenge: ${label}`);
    assert.equal(probe.calls.length, 1, `challenge: ${label} is never retried`);
  }
});

test('a timed-out link is never retried and its outcome is recovered by an authorized query', async (t) => {
  const probe = createDeviceClientProbe(t);
  const { active } = probeRecords(probe.ids);
  let linkError: unknown;
  let recovered: VerifiedDeviceSnapshot | null = null;

  const error = await probe.run(
    [
      { status: 504, body: { message: 'timed out' } },
      { status: 200, body: { data: active } },
    ],
    async (client) => {
      try {
        await client.completeLink({
          deviceId: probe.ids.deviceId,
          vehicleId: probe.ids.vehicleId,
          userId: probe.ids.userId,
          membershipId: probe.ids.membershipId,
          challengeId: String(new Types.ObjectId()),
          challenge: 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8',
          signature: 'A'.repeat(86),
        });
      } catch (caught) {
        linkError = caught;
      }
      recovered = await client.getDeviceById(probe.ids.deviceId);
    },
  );

  assert.equal(error, undefined);
  assert.ok(linkError instanceof DeviceUpstreamTimeoutError);
  assert.deepEqual(probe.calls, [
    `POST /internal/devices/${probe.ids.deviceId}/link`,
    `GET /internal/devices/${probe.ids.deviceId}`,
  ]);
  assert.ok(recovered);
  assert.equal((recovered as VerifiedDeviceSnapshot).record.status, 'ACTIVE');
  assert.ok((recovered as VerifiedDeviceSnapshot).activeBinding);
});
