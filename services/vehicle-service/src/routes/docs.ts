import type { FastifyPluginAsync } from 'fastify';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import type { OpenAPIV3 } from 'openapi-types';
import { z } from 'zod';
import {
  invitationPublicSchema,
  membershipPublicSchema,
  vehiclePublicSchema,
} from '../schemas/vehicle-response.schema.js';

const document = {
  openapi: '3.0.3',
  info: { title: 'PICHU Vehicle Service', version: '0.1.0' },
  paths: {
    '/health': { get: { summary: 'Liveness del servicio' } },
    '/health/ready': { get: { summary: 'Readiness del servicio e índices críticos' } },
    '/vehicles': { get: { summary: 'Listar vehículos' }, post: { summary: 'Crear vehículo' } },
    '/vehicles/{vehicleId}': { get: { summary: 'Consultar vehículo' } },
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
    year: 2020,
    engine: '1.8 Hybrid',
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
const vehicleExample = {
  id: '507f1f77bcf86cd799439011',
  name: 'Daily Sedan',
  make: 'Toyota',
  model: 'Corolla',
  year: 2020,
  engine: '1.8 Hybrid',
  ownerUserId: '507f1f77bcf86cd799439012',
};

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
    z.strictObject({ vehicleId: z.string(), message, data: vehiclePublicSchema, requestId }),
    {
      vehicleId: vehicleExample.id,
      message: 'Vehicle created',
      data: vehicleExample,
      requestId: 'request-1',
    },
  ),
  400: error,
  401: error,
  500: error,
};
paths['/vehicles'].get.responses = {
  200: result(
    'Owned vehicles',
    z.strictObject({ vehicles: z.array(vehiclePublicSchema), requestId }),
    { vehicles: [vehicleExample], requestId: 'request-1' },
  ),
  400: error,
  401: error,
  500: error,
};
paths['/vehicles/{vehicleId}'].get.responses = {
  200: result('Accessible vehicle', vehiclePublicSchema.extend({ requestId }), {
    ...vehicleExample,
    requestId: 'request-1',
  }),
  400: error,
  401: error,
  404: error,
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
    responses['403'] = result(
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
