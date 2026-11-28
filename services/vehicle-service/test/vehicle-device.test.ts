import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
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
