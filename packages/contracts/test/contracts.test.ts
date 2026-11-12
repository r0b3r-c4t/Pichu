import assert from 'node:assert/strict';
import test from 'node:test';
import {
  CONTRACTS_VERSION,
  errorResponseSchema,
  internalRequestHeadersSchema,
  loginRequestSchema,
  passwordResetConfirmSchema,
  serviceNameSchema,
  vehicleCreateRequestSchema,
  deviceSummarySchema,
  reportedStateSchema,
  deviceLinkRequestSchema,
  deviceLinkCompletionSchema,
} from '../src/index.js';

test('common error responses accept the versioned public shape', () => {
  const result = errorResponseSchema.safeParse({
    error: { code: 'VALIDATION_ERROR', message: 'Invalid request' },
    requestId: 'req-123',
  });

  assert.equal(result.success, true);
});

test('identity login uses only credentials in its JSON contract', () => {
  const result = loginRequestSchema.parse({
    email: 'driver@example.com',
    password: 'a-secure-password',
  });
  assert.equal(result.email, 'driver@example.com');
});

test('password reset confirmation rejects malformed opaque tokens', () => {
  const result = passwordResetConfirmSchema.safeParse({
    token: 'not-a-token',
    password: 'a-secure-password',
  });

  assert.equal(result.success, false);
});

test('internal request headers require a known service and contract version', () => {
  const valid = internalRequestHeadersSchema.safeParse({
    'x-request-id': 'request-1',
    'x-service-name': 'vehicle-service',
    'x-contract-version': CONTRACTS_VERSION,
    'x-timestamp': '1730635200000',
    'x-signature': 'signature_123',
  });
  const invalid = internalRequestHeadersSchema.safeParse({
    'x-service-name': 'unknown-service',
    'x-contract-version': CONTRACTS_VERSION,
  });

  assert.equal(valid.success, true);
  assert.equal(invalid.success, false);
  assert.equal(serviceNameSchema.safeParse('identity-service').success, true);
});

test('vehicle, device and automation contracts validate their public DTOs', () => {
  const vehicle = vehicleCreateRequestSchema.safeParse({ name: 'Mazda 3' });
  const device = deviceSummarySchema.safeParse({
    deviceId: '507f1f77bcf86cd799439011',
    vehicleId: null,
    identifier: 'esp32-01',
    status: 'PENDING',
    lastSeenAt: null,
  });
  const state = reportedStateSchema.safeParse({
    moduleId: '507f1f77bcf86cd799439011',
    state: { position: 'closed' },
    reportedAt: '2026-11-02T12:00:00.000Z',
    sourceDeviceId: null,
  });

  assert.equal(vehicle.success, true);
  assert.equal(device.success, true);
  assert.equal(state.success, true);
});

test('device linking contracts require an account-scoped vehicle and a proof', () => {
  const request = deviceLinkRequestSchema.safeParse({
    vehicleId: '507f1f77bcf86cd799439011',
    deviceIdentifier: 'esp32-01',
  });
  const completion = deviceLinkCompletionSchema.safeParse({
    challengeId: '507f1f77bcf86cd799439011',
    proof: 'signed-device-proof',
  });

  assert.equal(request.success, true);
  assert.equal(completion.success, true);
});
