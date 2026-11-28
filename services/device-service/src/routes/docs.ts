import type { FastifyPluginAsync } from 'fastify';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import type { OpenAPIV3 } from 'openapi-types';

const document = {
  openapi: '3.0.3',
  info: { title: 'PICHU Device Service', version: '0.2.0' },
  paths: {
    '/health': { get: { summary: 'Estado del servicio' } },
    '/health/ready': { get: { summary: 'Disponibilidad (MongoDB, índices, migración, nonces)' } },
    '/internal/devices/register': {
      post: {
        summary: 'Registrar dispositivo PENDING y credencial Ed25519 (vehicle-service HMAC)',
      },
    },
    '/internal/devices/{deviceId}': {
      get: { summary: 'Consultar estado interno de dispositivo (vehicle-service HMAC)' },
      patch: { summary: 'Actualizar metadatos descriptivos de dispositivo (vehicle-service HMAC)' },
    },
    '/internal/vehicles/{vehicleId}/devices': {
      get: { summary: 'Listar lote keyset de dispositivos por vehículo (vehicle-service HMAC)' },
    },
    '/internal/devices/{deviceId}/challenge': {
      post: { summary: 'Emitir desafío de enrolamiento de un solo uso (vehicle-service HMAC)' },
    },
    '/internal/devices/{deviceId}/link': {
      post: {
        summary: 'Completar vinculación mediante firma Ed25519 canónica (vehicle-service HMAC)',
      },
    },
    '/internal/devices/{deviceId}/revoke': {
      post: { summary: 'Revocar dispositivo y sus credenciales activas (vehicle-service HMAC)' },
    },
  },
};

const requestExamples: Array<{ path: string; method: 'post' | 'patch'; example: unknown }> = [
  {
    path: '/internal/devices/register',
    method: 'post',
    example: {
      identifier: 'esp32-mazda-3',
      publicKey:
        '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA45MvtrOX7j8UVh74F4GxZAyeEGjeMtA4e/FfWGi+z6Y=\n-----END PUBLIC KEY-----',
      metadata: {
        name: 'Sunroof Controller',
        manufacturer: 'Espressif',
        hardwareModel: 'ESP32-S3',
      },
      vehicleId: '507f1f77bcf86cd799439011',
      userId: '507f1f77bcf86cd799439012',
      membershipId: '507f1f77bcf86cd799439013',
    },
  },
  {
    path: '/internal/devices/{deviceId}',
    method: 'patch',
    example: {
      vehicleId: '507f1f77bcf86cd799439011',
      userId: '507f1f77bcf86cd799439012',
      metadata: { firmwareVersion: '1.2.0', serialNumber: null },
    },
  },
  {
    path: '/internal/devices/{deviceId}/challenge',
    method: 'post',
    example: {
      vehicleId: '507f1f77bcf86cd799439011',
      userId: '507f1f77bcf86cd799439012',
      membershipId: '507f1f77bcf86cd799439013',
    },
  },
  {
    path: '/internal/devices/{deviceId}/link',
    method: 'post',
    example: {
      vehicleId: '507f1f77bcf86cd799439011',
      userId: '507f1f77bcf86cd799439012',
      membershipId: '507f1f77bcf86cd799439013',
      challengeId: '507f1f77bcf86cd799439014',
      challenge: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      signature:
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    },
  },
  {
    path: '/internal/devices/{deviceId}/revoke',
    method: 'post',
    example: {
      vehicleId: '507f1f77bcf86cd799439011',
      userId: '507f1f77bcf86cd799439012',
      reason: 'ADMINISTRATIVE',
    },
  },
];

const paths = document.paths as unknown as Record<string, Record<string, Record<string, unknown>>>;
const deviceTags = [
  { name: 'Health', description: 'Estado del servicio' },
  {
    name: 'Internal device operations',
    description: 'Operaciones internas exclusivas para vehicle-service autenticado por HMAC v2',
  },
];
(document as unknown as { tags: typeof deviceTags }).tags = deviceTags;
for (const [path, operations] of Object.entries(paths)) {
  const tag = path.startsWith('/health') ? 'Health' : 'Internal device operations';
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
for (const { path, method, example } of requestExamples) {
  const operation = paths[path]?.[method];
  if (operation)
    operation.requestBody = {
      required: true,
      content: {
        'application/json': { schema: { type: 'object', additionalProperties: true }, example },
      },
    };
}

for (const [path, operations] of Object.entries(paths)) {
  if (!path.startsWith('/internal/')) continue;
  for (const operation of Object.values(operations)) {
    operation.responses = {
      ...(operation.responses as Record<string, unknown>),
      '400': { description: 'Solicitud o prueba criptográfica inválida' },
      '401': { description: 'Autenticación interna HMAC v2 requerida o llamador no autorizado' },
      '403': { description: 'Contexto de enrolamiento o llamador no autorizado' },
      '404': { description: 'Dispositivo no encontrado' },
      '409': { description: 'Conflicto de estado, desafío, credencial o unicidad' },
      '503': { description: 'Base de datos o dependencia interna no disponible' },
    };
  }
}
const registerOperation = paths['/internal/devices/register']?.post;
if (registerOperation) {
  registerOperation.responses = {
    ...(registerOperation.responses as Record<string, unknown>),
    '201': { description: 'Dispositivo PENDING y credencial ACTIVE creados atómicamente' },
  };
}
const challengeOperation = paths['/internal/devices/{deviceId}/challenge']?.post;
if (challengeOperation) {
  challengeOperation.responses = {
    ...(challengeOperation.responses as Record<string, unknown>),
    '201': { description: 'Desafío de enrolamiento emitido' },
  };
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
