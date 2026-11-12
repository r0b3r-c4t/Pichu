import type { FastifyInstance } from 'fastify';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';

export const gatewayOpenApiOptions = {
  mode: 'dynamic' as const,
  openapi: {
    openapi: '3.0.3' as const,
    info: { title: 'PICHU API Gateway', version: '0.1.0' },
    tags: [
      { name: 'Health', description: 'Estado del Gateway' },
      { name: 'Identity', description: 'Autenticación y recuperación' },
      { name: 'Vehicles', description: 'Operaciones públicas de vehículos' },
      { name: 'Invitations', description: 'Invitaciones y membresías' },
      { name: 'Devices', description: 'Dispositivos del usuario verificado' },
    ],
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http' as const, scheme: 'bearer' as const, bearerFormat: 'JWT' },
        refreshCookie: {
          type: 'apiKey' as const,
          in: 'cookie' as const,
          name: 'pichu_refresh_token',
        },
      },
    },
  },
};

export const gatewaySwaggerUiOptions = {
  routePrefix: '/docs',
  uiConfig: {
    docExpansion: 'list' as const,
    deepLinking: true,
    tryItOutEnabled: true,
    withCredentials: true,
  },
};

export function registerDocs(fastify: FastifyInstance): void {
  void fastify.register(swagger, gatewayOpenApiOptions);
  void fastify.register(swaggerUi, { ...gatewaySwaggerUiOptions });
}
