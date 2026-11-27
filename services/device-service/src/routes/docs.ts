import type { FastifyPluginAsync } from 'fastify';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import type { OpenAPIV3 } from 'openapi-types';

const document = {
  openapi: '3.0.3',
  info: { title: 'PICHU Device Service', version: '0.1.0' },
  paths: {
    '/health': { get: { summary: 'Estado del servicio' } },
    '/health/ready': { get: { summary: 'Disponibilidad (MongoDB, índices, migración, nonces)' } },
    '/devices/{deviceId}': {
      get: { summary: 'Consultar dispositivo (Gateway HMAC y correo verificado)' },
    },
    '/internal/devices/register': {
      post: { summary: 'Registrar dispositivo y su credencial Ed25519 (HMAC)' },
    },
  },
};

const requestExamples: Record<string, unknown> = {
  '/internal/devices/register': {
    identifier: 'esp32-mazda-3',
    publicKey:
      '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA45MvtrOX7j8UVh74F4GxZAyeEGjeMtA4e/FfWGi+z6Y=\n-----END PUBLIC KEY-----',
    vehicleId: '507f1f77bcf86cd799439011',
    userId: '507f1f77bcf86cd799439012',
  },
};
const paths = document.paths as unknown as Record<string, Record<string, Record<string, unknown>>>;
const deviceTags = [
  { name: 'Health', description: 'Estado del servicio' },
  { name: 'Devices', description: 'Metadatos del dispositivo' },
  { name: 'Internal provisioning', description: 'Registro interno de dispositivos' },
];
(document as unknown as { tags: typeof deviceTags }).tags = deviceTags;
for (const [path, operations] of Object.entries(paths)) {
  const tag = path.startsWith('/health')
    ? 'Health'
    : path.startsWith('/internal/')
      ? 'Internal provisioning'
      : 'Devices';
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

const verificationError = {
  description: 'Correo no verificado',
  content: {
    'application/json': {
      schema: {
        type: 'object',
        required: ['error', 'message', 'requestId'],
        properties: {
          error: { type: 'string', enum: ['EMAIL_NOT_VERIFIED'] },
          message: { type: 'string' },
          requestId: { type: 'string' },
        },
      },
      example: {
        error: 'EMAIL_NOT_VERIFIED',
        message: 'Debes verificar tu correo electrónico para continuar.',
        requestId: 'request-1',
      },
    },
  },
};
for (const path of ['/devices/{deviceId}', '/internal/devices/register']) {
  const operation = paths[path]?.[path.startsWith('/internal/') ? 'post' : 'get'];
  if (operation) {
    operation.responses = {
      ...(operation.responses as Record<string, unknown>),
      '401': { description: 'Autenticación interna requerida' },
      '403': verificationError,
      '503': { description: 'Base de datos o Identity no disponibles' },
    };
  }
}
const registerOperation = paths['/internal/devices/register']?.post;
if (registerOperation) {
  registerOperation.responses = {
    ...(registerOperation.responses as Record<string, unknown>),
    '201': { description: 'Dispositivo PENDING y credencial ACTIVE creados atómicamente' },
    '400': { description: 'Datos o clave pública SPKI Ed25519 inválidos' },
    '409': { description: 'Identificador o clave ya registrados (incluidos revocados)' },
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
