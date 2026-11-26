import type { FastifyPluginAsync } from 'fastify';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import type { OpenAPIV3 } from 'openapi-types';
import { z } from 'zod';
import {
  internalVehicleArchiveRequestSchema,
  internalVehicleCreateRequestSchema,
  internalVehicleUpdateRequestSchema,
} from '@pichu/contracts';
import {
  invitationPublicSchema,
  membershipPublicSchema,
  vehicleAccessPublicSchema,
  vehicleArchivePublicSchema,
  vehicleOwnerPublicSchema,
} from '../schemas/vehicle-response.schema.js';

const document = {
  openapi: '3.0.3',
  info: { title: 'PICHU Vehicle Service', version: '0.1.0' },
  paths: {
    '/health': { get: { summary: 'Liveness del servicio' } },
    '/health/ready': { get: { summary: 'Readiness del servicio e índices críticos' } },
    '/vehicles': {
      get: { summary: 'Listar vehículos propios y compartidos con paginación keyset' },
      post: { summary: 'Crear vehículo' },
    },
    '/vehicles/{vehicleId}': {
      get: { summary: 'Consultar vehículo con permiso efectivo de lectura' },
      patch: { summary: 'Actualizar parcialmente un vehículo (solo propietario canónico)' },
      delete: { summary: 'Archivar lógicamente un vehículo (solo propietario canónico)' },
    },
    '/vehicles/{vehicleId}/invitations': { post: { summary: 'Crear invitación' } },
    '/invitations/{invitationId}/accept': { post: { summary: 'Aceptar invitación' } },
    '/vehicles/{vehicleId}/devices/link': { post: { summary: 'Registrar dispositivo vinculado' } },
  },
};

const requestExamples: Record<string, unknown> = {
  '/vehicles': {
    userId: '507f1f77bcf86cd799439011',
    name: 'Daily Sedan',
    make: 'Toyota',
    model: 'Corolla',
    generation: 'E210',
    trim: 'LE',
    year: 2020,
    bodyStyle: 'sedan',
    engine: '1.8 Hybrid',
    transmission: 'e-CVT',
    fuelType: 'hybrid',
  },
  '/vehicles/{vehicleId}/invitations': {
    inviterUserId: '507f1f77bcf86cd799439011',
    inviteeUserId: '507f1f77bcf86cd799439012',
    permissions: ['vehicle:read'],
  },
  '/invitations/{invitationId}/accept': { userId: '507f1f77bcf86cd799439012' },
  '/vehicles/{vehicleId}/devices/link': {
    userId: '507f1f77bcf86cd799439011',
    deviceIdentifier: 'esp32-node-01',
    publicKey: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----',
  },
};

const paths = document.paths as unknown as Record<string, Record<string, Record<string, unknown>>>;
const vehicleTags = [
  { name: 'Health', description: 'Estado y disponibilidad del servicio' },
  { name: 'Vehicles', description: 'Vehículos y acceso aislado por recurso' },
  { name: 'Invitations', description: 'Invitaciones y membresías' },
  { name: 'Devices', description: 'Vinculación autorizada de dispositivos' },
];
(document as unknown as { tags: typeof vehicleTags }).tags = vehicleTags;
for (const [path, operations] of Object.entries(paths)) {
  const tag = path.startsWith('/health')
    ? 'Health'
    : path.includes('invitations')
      ? 'Invitations'
      : path.includes('/devices/')
        ? 'Devices'
        : 'Vehicles';
  for (const operation of Object.values(operations)) operation.tags = [tag];
}
for (const operations of Object.values(paths))
  for (const operation of Object.values(operations))
    operation.responses = { '200': { description: 'Respuesta del servicio' } };
for (const [path, operations] of Object.entries(paths)) {
  const names = [...path.matchAll(/\{([^}]+)\}/g)].map((match) => match[1]);
  for (const operation of Object.values(operations)) {
    operation.parameters = names.map((name) => ({
      name,
      in: 'path',
      required: true,
      schema: { type: 'string' },
    }));
  }
}
for (const [path, example] of Object.entries(requestExamples)) {
  const operation = paths[path]?.post;
  if (operation)
    operation.requestBody = {
      required: true,
      content: {
        'application/json': { schema: { type: 'object', additionalProperties: true }, example },
      },
    };
}

function jsonSchema(schema: z.ZodType): OpenAPIV3.SchemaObject {
  const result = z.toJSONSchema(schema, { target: 'draft-7' }) as Record<string, unknown>;
  delete result.$schema;
  return result as OpenAPIV3.SchemaObject;
}

function result(
  description: string,
  schema: z.ZodType,
  example: unknown,
): OpenAPIV3.ResponseObject {
  return {
    description,
    content: { 'application/json': { schema: jsonSchema(schema), example } },
  };
}

const requestId = z.string();
const message = z.string();
const error = result('Request failed', z.strictObject({ message }), { message: 'Invalid request' });
function domainError(description: string, code: string, text: string): OpenAPIV3.ResponseObject {
  return result(description, z.strictObject({ error: z.string(), message, requestId }), {
    error: code,
    message: text,
    requestId: 'request-1',
  });
}
const vehicleExample = {
  id: '507f1f77bcf86cd799439011',
  name: 'Daily Sedan',
  make: 'Toyota',
  model: 'Corolla',
  generation: 'E210',
  trim: 'LE',
  year: 2020,
  bodyStyle: 'sedan',
  engine: '1.8 Hybrid',
  transmission: 'e-CVT',
  fuelType: 'hybrid',
  ownerUserId: '507f1f77bcf86cd799439012',
};
const vehicleValidationError = domainError(
  'Invalid request, unsupported field, or invalid cursor',
  'VALIDATION_ERROR',
  'Invalid vehicle data',
);
const vehicleNotFound = domainError(
  'Vehicle not found or not visible to the caller',
  'NOT_FOUND',
  'Vehicle not found',
);
const vehicleOwnerOnly = domainError(
  'Caller can read the vehicle but is not its canonical owner',
  'FORBIDDEN',
  'Only the canonical vehicle owner may perform this operation',
);

function jsonRequestBody(schema: z.ZodType, example: unknown, required = true) {
  return {
    required,
    content: { 'application/json': { schema: jsonSchema(schema), example } },
  };
}

paths['/vehicles'].post.requestBody = jsonRequestBody(
  internalVehicleCreateRequestSchema,
  requestExamples['/vehicles'],
);
paths['/vehicles/{vehicleId}'].patch.requestBody = jsonRequestBody(
  internalVehicleUpdateRequestSchema,
  { userId: '507f1f77bcf86cd799439011', trim: 'XLE', engine: null },
);
paths['/vehicles/{vehicleId}'].delete.requestBody = jsonRequestBody(
  internalVehicleArchiveRequestSchema,
  { userId: '507f1f77bcf86cd799439011', reason: 'Vehicle sold' },
);
paths['/vehicles'].get.parameters = [
  {
    name: 'userId',
    in: 'query',
    required: true,
    description: 'Identidad derivada del JWT verificado por el Gateway y firmada con HMAC v2',
    schema: { type: 'string', pattern: '^[a-f0-9]{24}$' },
  },
  {
    name: 'limit',
    in: 'query',
    required: false,
    schema: { type: 'integer', minimum: 1, maximum: 100, default: 20 },
  },
  {
    name: 'cursor',
    in: 'query',
    required: false,
    description:
      'Cursor keyset opaco (base64url) ligado al usuario y al filtro. No está cifrado ni ' +
      'firmado y nunca concede acceso.',
    schema: { type: 'string', maxLength: 256, pattern: '^[A-Za-z0-9_-]+$' },
  },
  {
    name: 'role',
    in: 'query',
    required: false,
    schema: { type: 'string', enum: ['OWNER', 'MEMBER'] },
  },
];
paths['/vehicles/{vehicleId}'].get.parameters = [
  ...(paths['/vehicles/{vehicleId}'].get.parameters as unknown[]),
  {
    name: 'userId',
    in: 'query',
    required: true,
    schema: { type: 'string', pattern: '^[a-f0-9]{24}$' },
  },
];

paths['/health/ready'].get.responses = {
  200: result(
    'Service ready',
    z.strictObject({ status: z.literal('ready'), service: z.literal('vehicle-service') }),
    { status: 'ready', service: 'vehicle-service' },
  ),
  503: result(
    'Service unready',
    z.strictObject({ status: z.literal('unready'), service: z.literal('vehicle-service') }),
    { status: 'unready', service: 'vehicle-service' },
  ),
};

paths['/vehicles'].post.responses = {
  201: result(
    'Vehicle created',
    z.strictObject({ vehicleId: z.string(), message, data: vehicleOwnerPublicSchema, requestId }),
    {
      vehicleId: vehicleExample.id,
      message: 'Vehicle created',
      data: { ...vehicleExample, role: 'OWNER' },
      requestId: 'request-1',
    },
  ),
  400: vehicleValidationError,
  401: error,
  500: error,
};
paths['/vehicles'].get.responses = {
  200: result(
    'Owned and shared vehicles readable by the caller, ordered by createdAt ASC, _id ASC',
    z.strictObject({
      vehicles: z.array(vehicleAccessPublicSchema),
      page: z.strictObject({ nextCursor: z.string().nullable() }),
      requestId,
    }),
    {
      vehicles: [{ ...vehicleExample, role: 'OWNER' }],
      page: { nextCursor: null },
      requestId: 'request-1',
    },
  ),
  400: vehicleValidationError,
  401: error,
  500: error,
};
paths['/vehicles/{vehicleId}'].get.responses = {
  200: result('Readable vehicle', vehicleAccessPublicSchema.extend({ requestId }), {
    ...vehicleExample,
    role: 'MEMBER',
    requestId: 'request-1',
  }),
  400: vehicleValidationError,
  401: error,
  404: vehicleNotFound,
  500: error,
};
paths['/vehicles/{vehicleId}'].patch.responses = {
  200: result(
    'Vehicle updated',
    z.strictObject({ vehicleId: z.string(), message, data: vehicleOwnerPublicSchema, requestId }),
    {
      vehicleId: vehicleExample.id,
      message: 'Vehicle updated',
      data: { ...vehicleExample, trim: 'XLE', engine: null, role: 'OWNER' },
      requestId: 'request-1',
    },
  ),
  400: vehicleValidationError,
  401: error,
  403: vehicleOwnerOnly,
  404: vehicleNotFound,
  409: domainError(
    'Vehicle is archived or changed concurrently',
    'CONFLICT',
    'Archived vehicles cannot be modified',
  ),
  500: error,
};
paths['/vehicles/{vehicleId}'].delete.responses = {
  200: result(
    'Vehicle archived, or already archived (original archive record, unchanged)',
    vehicleArchivePublicSchema.extend({ message, requestId }),
    {
      vehicleId: vehicleExample.id,
      status: 'ARCHIVED',
      archivedAt: '2026-11-26T12:00:00.000Z',
      message: 'Vehicle archived',
      requestId: 'request-1',
    },
  ),
  400: vehicleValidationError,
  401: error,
  403: vehicleOwnerOnly,
  404: vehicleNotFound,
  409: domainError('Vehicle changed concurrently', 'CONFLICT', 'Concurrent state change'),
  500: error,
};
paths['/vehicles/{vehicleId}/invitations'].post.responses = {
  201: result(
    'Invitation created',
    z.strictObject({
      invitationId: z.string(),
      status: z.string(),
      message,
      data: invitationPublicSchema,
      requestId,
    }),
    {
      invitationId: '507f1f77bcf86cd799439013',
      status: 'PENDING',
      message: 'Invitation created',
      data: {
        id: '507f1f77bcf86cd799439013',
        vehicleId: vehicleExample.id,
        inviteeUserId: '507f1f77bcf86cd799439014',
        permissions: ['vehicle:read'],
        status: 'PENDING',
        expiresAt: '2026-11-10T12:00:00.000Z',
      },
      requestId: 'request-1',
    },
  ),
  400: error,
  401: error,
  404: error,
  409: error,
  503: error,
};
paths['/invitations/{invitationId}/accept'].post.responses = {
  200: result(
    'Invitation accepted',
    z.strictObject({
      accepted: z.literal(true),
      vehicleId: z.string(),
      message,
      data: membershipPublicSchema,
      requestId,
    }),
    {
      accepted: true,
      vehicleId: vehicleExample.id,
      message: 'Invitation accepted',
      data: {
        vehicleId: vehicleExample.id,
        userId: '507f1f77bcf86cd799439014',
        role: 'MEMBER',
        permissions: ['vehicle:read'],
      },
      requestId: 'request-1',
    },
  ),
  400: error,
  401: error,
  404: error,
  409: error,
  500: error,
};
paths['/vehicles/{vehicleId}/devices/link'].post.responses = {
  201: result(
    'Device registration accepted',
    z.strictObject({
      deviceId: z.string(),
      status: z.literal('PENDING'),
      message,
      data: z.strictObject({
        deviceId: z.string(),
        vehicleId: z.string(),
        status: z.literal('PENDING'),
      }),
      requestId,
    }),
    {
      deviceId: '507f1f77bcf86cd799439015',
      status: 'PENDING',
      message: 'Device registration accepted',
      data: {
        deviceId: '507f1f77bcf86cd799439015',
        vehicleId: vehicleExample.id,
        status: 'PENDING',
      },
      requestId: 'request-1',
    },
  ),
  400: error,
  401: error,
  404: error,
  503: error,
};
for (const [path, operations] of Object.entries(paths)) {
  if (path.startsWith('/health')) continue;
  for (const operation of Object.values(operations)) {
    const responses = operation.responses as Record<string, unknown>;
    responses['403'] = responses['403']
      ? result(
          'Email verification required, or caller is not the canonical vehicle owner',
          z.strictObject({
            error: z.enum(['EMAIL_NOT_VERIFIED', 'FORBIDDEN']),
            message,
            requestId,
          }),
          {
            error: 'FORBIDDEN',
            message: 'Only the canonical vehicle owner may perform this operation',
            requestId: 'request-1',
          },
        )
      : result(
          'Email verification required',
          z.strictObject({ error: z.literal('EMAIL_NOT_VERIFIED'), message, requestId }),
          {
            error: 'EMAIL_NOT_VERIFIED',
            message: 'Debes verificar tu correo electrónico para continuar.',
            requestId: 'request-1',
          },
        );
  }
}

export const docsRoutes: FastifyPluginAsync = async (fastify) => {
  await fastify.register(swagger, {
    mode: 'static',
    specification: { document: document as unknown as OpenAPIV3.Document },
  });
  await fastify.register(swaggerUi, {
    routePrefix: '/docs',
    uiConfig: { docExpansion: 'list', deepLinking: true, tryItOutEnabled: true },
  });
};
