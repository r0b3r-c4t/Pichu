import type { FastifyPluginAsync } from 'fastify';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import type { OpenAPIV3 } from 'openapi-types';
import { z } from 'zod';
import {
  deviceDetailSchema,
  deviceStatusSchema,
  internalInvitationCreateRequestSchema,
  internalInvitationRevokeRequestSchema,
  internalMemberLeaveRequestSchema,
  internalMemberPermissionsUpdateRequestSchema,
  internalMemberReactivateRequestSchema,
  internalMemberTransitionRequestSchema,
  internalVehicleArchiveRequestSchema,
  internalVehicleCreateRequestSchema,
  internalVehicleDeviceChallengeRequestSchema,
  internalVehicleDeviceLinkCompletionRequestSchema,
  internalVehicleDeviceMetadataUpdateRequestSchema,
  internalVehicleDeviceRegistrationRequestSchema,
  internalVehicleDeviceRevokeRequestSchema,
  internalVehicleUpdateRequestSchema,
  invitationAcceptRequestSchema,
  invitationAdminViewSchema,
  invitationStatusSchema,
  memberViewSchema,
  membershipSchema,
  membershipStatusSchema,
  receivedInvitationViewSchema,
  vehicleDeviceChallengeResponseSchema,
  vehicleDeviceLinkResponseSchema,
  vehicleDeviceMetadataUpdateResponseSchema,
  vehicleDeviceRegistrationResponseSchema,
  vehicleDeviceRevokeResponseSchema,
} from '@pichu/contracts';
import {
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
    '/vehicles/{vehicleId}/invitations': {
      post: { summary: 'Crear invitación (propietario o delegado autorizado)' },
      get: { summary: 'Listar invitaciones emitidas del vehículo (paginación keyset)' },
    },
    '/vehicles/{vehicleId}/invitations/{invitationId}': {
      delete: { summary: 'Revocar invitación pendiente' },
    },
    '/invitations': { get: { summary: 'Listar invitaciones recibidas por el usuario' } },
    '/invitations/{invitationId}/accept': { post: { summary: 'Aceptar invitación' } },
    '/vehicles/{vehicleId}/members': {
      get: { summary: 'Listar miembros del vehículo (solo propietario canónico)' },
    },
    '/vehicles/{vehicleId}/members/leave': {
      post: { summary: 'Abandonar voluntariamente el vehículo (membresía MEMBER propia)' },
    },
    '/vehicles/{vehicleId}/members/{membershipId}': {
      patch: { summary: 'Reemplazar permisos base de un miembro (solo propietario canónico)' },
      delete: { summary: 'Revocar membresía (solo propietario canónico, idempotente)' },
    },
    '/vehicles/{vehicleId}/members/{membershipId}/suspend': {
      post: { summary: 'Suspender membresía (solo propietario canónico)' },
    },
    '/vehicles/{vehicleId}/members/{membershipId}/reactivate': {
      post: { summary: 'Reactivar membresía suspendida (solo propietario canónico)' },
    },
    '/vehicles/{vehicleId}/devices': {
      post: { summary: 'Registrar dispositivo PENDING para el vehículo' },
      get: { summary: 'Listar dispositivos autorizados del vehículo con paginación keyset' },
    },
    '/vehicles/{vehicleId}/devices/{deviceId}': {
      get: { summary: 'Consultar detalle de dispositivo en el ámbito del vehículo' },
      patch: { summary: 'Actualizar metadatos descriptivos del dispositivo' },
    },
    '/devices/{deviceId}': {
      get: { summary: 'Consultar detalle de dispositivo por identificador' },
    },
    '/vehicles/{vehicleId}/devices/{deviceId}/challenge': {
      post: { summary: 'Emitir desafío criptográfico de enrolamiento' },
    },
    '/vehicles/{vehicleId}/devices/{deviceId}/link': {
      post: { summary: 'Completar vinculación de dispositivo mediante firma Ed25519 canónica' },
    },
    '/vehicles/{vehicleId}/devices/{deviceId}/revoke': {
      post: { summary: 'Revocar dispositivo irreversiblemente' },
    },
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
};

const paths = document.paths as unknown as Record<string, Record<string, Record<string, unknown>>>;
const vehicleTags = [
  { name: 'Health', description: 'Estado y disponibilidad del servicio' },
  { name: 'Vehicles', description: 'Vehículos y acceso aislado por recurso' },
  { name: 'Invitations', description: 'Invitaciones' },
  { name: 'Members', description: 'Administración de membresías' },
  { name: 'Devices', description: 'Registro, enrolamiento, consulta y revocación de dispositivos' },
];
(document as unknown as { tags: typeof vehicleTags }).tags = vehicleTags;
for (const [path, operations] of Object.entries(paths)) {
  const tag = path.startsWith('/health')
    ? 'Health'
    : path.includes('invitations')
      ? 'Invitations'
      : path.includes('/members')
        ? 'Members'
        : path.includes('/devices')
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
const actorUserIdExample = '507f1f77bcf86cd799439011';
const invitationExample = {
  invitationId: '507f1f77bcf86cd799439013',
  vehicleId: vehicleExample.id,
  inviterUserId: actorUserIdExample,
  inviteeUserId: '507f1f77bcf86cd799439014',
  permissions: ['vehicle:read'],
  status: 'PENDING',
  expiresAt: '2026-12-03T12:00:00.000Z',
  createdAt: '2026-11-26T12:00:00.000Z',
  acceptedAt: null,
  revokedAt: null,
  revokeReason: null,
};
const membershipExample = {
  membershipId: '507f1f77bcf86cd799439016',
  vehicleId: vehicleExample.id,
  userId: '507f1f77bcf86cd799439014',
  role: 'MEMBER',
  permissions: ['vehicle:read'],
  status: 'ACTIVE',
};
const memberExample = {
  ...membershipExample,
  createdAt: '2026-11-26T12:00:00.000Z',
  suspendedAt: null,
  revokedAt: null,
};
const pageSchema = z.strictObject({ nextCursor: z.string().nullable() });
const invitationNotFound = domainError(
  'Inexistent, foreign, or invisible invitation (uniform)',
  'NOT_FOUND',
  'Invitation not found',
);
const membershipNotFound = domainError(
  'Vehicle or membership not visible, inexistent, or from another vehicle (uniform)',
  'NOT_FOUND',
  'Membership not found',
);
const insufficientPermissions = domainError(
  'Caller can read the vehicle but lacks the required authority',
  'FORBIDDEN',
  'Insufficient permissions to invite members',
);
function stateConflict(description: string, text: string) {
  return domainError(description, 'CONFLICT', text);
}
const membershipConflict = stateConflict(
  'OWNER membership, incompatible membership state, archived vehicle, or concurrent change',
  'Cannot suspend membership in status REVOKED',
);

const userIdQuery = {
  name: 'userId',
  in: 'query',
  required: true,
  description: 'Identidad derivada del JWT verificado por el Gateway y firmada con HMAC v2',
  schema: { type: 'string', pattern: '^[a-f0-9]{24}$' },
};
const pageQuery = [
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
      'Cursor keyset opaco (base64url) ligado a actor, recurso, tipo de listado y filtros. ' +
      'No está cifrado ni firmado y nunca concede acceso.',
    schema: { type: 'string', maxLength: 256, pattern: '^[A-Za-z0-9_-]+$' },
  },
];
function statusQuery(values: readonly string[], description: string) {
  return {
    name: 'status',
    in: 'query',
    required: false,
    description,
    schema: { type: 'string', enum: [...values] },
  };
}

paths['/vehicles/{vehicleId}/invitations'].post.requestBody = jsonRequestBody(
  internalInvitationCreateRequestSchema,
  requestExamples['/vehicles/{vehicleId}/invitations'],
);
paths['/vehicles/{vehicleId}/invitations'].post.description =
  'Orden: autenticación, autorización sobre el vehículo, validación de permisos delegados, ' +
  'consulta de existencia en Identity y revalidación transaccional. Un MEMBER con ' +
  'vehicle:manage o invitation:create sólo delega vehicle:read, device:read o module:read que ' +
  'posea directamente. Una invitación pendiente vigente duplicada es 409 y nunca se sobrescribe.';
paths['/vehicles/{vehicleId}/invitations'].post.responses = {
  201: result(
    'Invitation created',
    z.strictObject({
      invitationId: z.string(),
      status: invitationStatusSchema,
      message,
      data: invitationAdminViewSchema,
      requestId,
    }),
    {
      invitationId: invitationExample.invitationId,
      status: 'PENDING',
      message: 'Invitation created',
      data: invitationExample,
      requestId: 'request-1',
    },
  ),
  400: vehicleValidationError,
  401: error,
  403: insufficientPermissions,
  404: domainError('Vehicle not visible, or invitee not found', 'NOT_FOUND', 'Vehicle not found'),
  409: stateConflict(
    'Owner invitee, active/suspended membership, or pending invitation already exists',
    'A pending invitation already exists for this user',
  ),
  503: error,
  504: error,
};
paths['/vehicles/{vehicleId}/invitations'].get.parameters = [
  ...(paths['/vehicles/{vehicleId}/invitations'].get.parameters as unknown[]),
  userIdQuery,
  ...pageQuery,
  statusQuery(invitationStatusSchema.options, 'Estado efectivo; sin filtro se listan todos'),
];
paths['/vehicles/{vehicleId}/invitations'].get.responses = {
  200: result(
    'Issued invitations (owner: all; delegate: own current membership), createdAt ASC, _id ASC',
    z.strictObject({
      invitations: z.array(invitationAdminViewSchema),
      page: pageSchema,
      requestId,
    }),
    { invitations: [invitationExample], page: { nextCursor: null }, requestId: 'request-1' },
  ),
  400: vehicleValidationError,
  401: error,
  403: domainError(
    'Caller can read the vehicle but lacks invitation authority',
    'FORBIDDEN',
    'Insufficient permissions to list invitations',
  ),
  404: vehicleNotFound,
};
paths['/invitations'].get.parameters = [
  userIdQuery,
  ...pageQuery,
  statusQuery(invitationStatusSchema.options, 'Estado efectivo; por defecto PENDING vigentes'),
];
paths['/invitations'].get.responses = {
  200: result(
    "Caller's received invitations, createdAt ASC, _id ASC",
    z.strictObject({
      invitations: z.array(receivedInvitationViewSchema),
      page: pageSchema,
      requestId,
    }),
    {
      invitations: [
        {
          invitationId: invitationExample.invitationId,
          vehicleId: vehicleExample.id,
          vehicleName: vehicleExample.name,
          permissions: ['vehicle:read'],
          status: 'PENDING',
          expiresAt: invitationExample.expiresAt,
          createdAt: invitationExample.createdAt,
        },
      ],
      page: { nextCursor: null },
      requestId: 'request-1',
    },
  ),
  400: vehicleValidationError,
  401: error,
};
paths['/invitations/{invitationId}/accept'].post.requestBody = jsonRequestBody(
  invitationAcceptRequestSchema,
  requestExamples['/invitations/{invitationId}/accept'],
);
paths['/invitations/{invitationId}/accept'].post.responses = {
  200: result(
    'Invitation accepted; a new MEMBER membership without inherited grants is created',
    z.strictObject({
      accepted: z.literal(true),
      vehicleId: z.string(),
      message,
      data: membershipSchema,
      requestId,
    }),
    {
      accepted: true,
      vehicleId: vehicleExample.id,
      message: 'Invitation accepted',
      data: membershipExample,
      requestId: 'request-1',
    },
  ),
  400: vehicleValidationError,
  401: error,
  404: invitationNotFound,
  409: stateConflict(
    'Own invitation not pending, expired (persisted EXPIRED), issuer authority lost ' +
      '(persisted REVOKED issuer_authority_lost), or incompatible membership',
    'Invitation is no longer pending',
  ),
  500: error,
};
paths['/vehicles/{vehicleId}/invitations/{invitationId}'].delete.requestBody = jsonRequestBody(
  internalInvitationRevokeRequestSchema,
  { userId: actorUserIdExample, reason: 'Wrong recipient' },
);
paths['/vehicles/{vehicleId}/invitations/{invitationId}'].delete.responses = {
  200: result(
    'Invitation revoked, or already revoked (original record, unchanged)',
    z.strictObject({
      invitationId: z.string(),
      status: z.literal('REVOKED'),
      message,
      data: invitationAdminViewSchema,
      requestId,
    }),
    {
      invitationId: invitationExample.invitationId,
      status: 'REVOKED',
      message: 'Invitation revoked',
      data: {
        ...invitationExample,
        status: 'REVOKED',
        revokedAt: '2026-11-26T13:00:00.000Z',
        revokeReason: 'Wrong recipient',
      },
      requestId: 'request-1',
    },
  ),
  400: vehicleValidationError,
  401: error,
  403: insufficientPermissions,
  404: invitationNotFound,
  409: stateConflict('Invitation accepted or expired', 'Invitation already expired'),
};
paths['/vehicles/{vehicleId}/members'].get.parameters = [
  ...(paths['/vehicles/{vehicleId}/members'].get.parameters as unknown[]),
  userIdQuery,
  ...pageQuery,
  statusQuery(
    membershipStatusSchema.options,
    'Por defecto ACTIVE y SUSPENDED; REVOKED requiere filtro explícito',
  ),
];
paths['/vehicles/{vehicleId}/members'].get.responses = {
  200: result(
    'Vehicle members, createdAt ASC, _id ASC',
    z.strictObject({ members: z.array(memberViewSchema), page: pageSchema, requestId }),
    { members: [memberExample], page: { nextCursor: null }, requestId: 'request-1' },
  ),
  400: vehicleValidationError,
  401: error,
  403: vehicleOwnerOnly,
  404: vehicleNotFound,
};
const memberMutationSchema = z.strictObject({
  membershipId: z.string(),
  status: membershipStatusSchema,
  message,
  data: memberViewSchema,
  requestId,
});
function memberMutationResponses(description: string, text: string, data: unknown) {
  return {
    200: result(description, memberMutationSchema, {
      membershipId: memberExample.membershipId,
      status: (data as { status: string }).status,
      message: text,
      data,
      requestId: 'request-1',
    }),
    400: vehicleValidationError,
    401: error,
    403: vehicleOwnerOnly,
    404: membershipNotFound,
    409: membershipConflict,
  };
}
const memberPath = '/vehicles/{vehicleId}/members/{membershipId}';
paths[memberPath].patch.requestBody = jsonRequestBody(
  internalMemberPermissionsUpdateRequestSchema,
  { userId: actorUserIdExample, permissions: ['vehicle:read', 'device:read'] },
);
paths[memberPath].patch.description =
  'Reemplaza el conjunto completo de permisos base (vacío permitido) de una membresía MEMBER ' +
  'ACTIVE o SUSPENDED. No modifica rol, identidad, estado ni auditoría. Las AccessGrants son ' +
  'independientes y no se revocan implícitamente; las invitaciones pendientes emitidas por el ' +
  'miembro que el nuevo conjunto ya no autoriza se revocan en la misma transacción.';
paths[memberPath].patch.responses = memberMutationResponses(
  'Permissions replaced (or unchanged)',
  'Member permissions updated',
  { ...memberExample, permissions: ['vehicle:read', 'device:read'] },
);
paths[memberPath].delete.requestBody = jsonRequestBody(internalMemberTransitionRequestSchema, {
  userId: actorUserIdExample,
  reason: 'No longer drives the car',
});
paths[memberPath].delete.responses = memberMutationResponses(
  'Membership revoked with its grants and pending issued invitations; repeating returns the ' +
    'original revocation unchanged',
  'Member revoked',
  { ...memberExample, status: 'REVOKED', revokedAt: '2026-11-26T13:00:00.000Z' },
);
paths[`${memberPath}/suspend`].post.requestBody = jsonRequestBody(
  internalMemberTransitionRequestSchema,
  { userId: actorUserIdExample, reason: 'Temporary' },
);
paths[`${memberPath}/suspend`].post.responses = memberMutationResponses(
  'Membership suspended; its active AccessGrants and pending issued invitations are revoked',
  'Member suspended',
  { ...memberExample, status: 'SUSPENDED', suspendedAt: '2026-11-26T13:00:00.000Z' },
);
paths[`${memberPath}/reactivate`].post.requestBody = jsonRequestBody(
  internalMemberReactivateRequestSchema,
  { userId: actorUserIdExample },
);
paths[`${memberPath}/reactivate`].post.responses = memberMutationResponses(
  'Membership reactivated with its current base permissions only (no grants or invitations)',
  'Member reactivated',
  memberExample,
);
paths['/vehicles/{vehicleId}/members/leave'].post.requestBody = jsonRequestBody(
  internalMemberLeaveRequestSchema,
  { userId: '507f1f77bcf86cd799439014', membershipId: memberExample.membershipId },
);
paths['/vehicles/{vehicleId}/members/leave'].post.responses = {
  200: result(
    'Own MEMBER membership revoked (member_left), or the targeted one was already revoked',
    z.strictObject({
      membershipId: z.string(),
      status: z.literal('REVOKED'),
      message,
      data: membershipSchema,
      requestId,
    }),
    {
      membershipId: memberExample.membershipId,
      status: 'REVOKED',
      message: 'Left vehicle',
      data: { ...membershipExample, status: 'REVOKED' },
      requestId: 'request-1',
    },
  ),
  400: vehicleValidationError,
  401: error,
  404: membershipNotFound,
  409: stateConflict(
    'The canonical owner cannot leave',
    'The vehicle owner cannot leave the vehicle',
  ),
};
const deviceDetailExample = {
  deviceId: '507f1f77bcf86cd799439015',
  vehicleId: vehicleExample.id,
  identifier: 'esp32-sunroof-01',
  status: 'PENDING' as const,
  operational: false,
  credential: {
    credentialId: '507f1f77bcf86cd799439017',
    keyId: 'dk_AAAAAAAAAAAAAAAAAAAAAA',
    algorithm: 'Ed25519' as const,
    fingerprint: `sha256:${'a'.repeat(64)}`,
    status: 'ACTIVE' as const,
    usable: true,
    activatedAt: '2026-11-26T12:00:00.000Z',
    expiresAt: null,
    revokedAt: null,
  },
  connectivity: { lastSeenAt: null },
  metadata: {
    name: 'Sunroof Node',
    manufacturer: 'Espressif',
    hardwareModel: 'ESP32-S3',
    hardwareRevision: 'rev-1.0',
    firmwareVersion: '1.0.0',
    serialNumber: 'SN-001',
  },
  createdAt: '2026-11-26T12:00:00.000Z',
  updatedAt: '2026-11-26T12:00:00.000Z',
  linkedAt: null,
  revokedAt: null,
  revocationReason: null,
};
const deviceChallengeExample = {
  protocol: 'pichu-device-link-v1' as const,
  challengeId: '507f1f77bcf86cd799439018',
  deviceId: deviceDetailExample.deviceId,
  vehicleId: vehicleExample.id,
  credentialId: deviceDetailExample.credential.credentialId,
  requestedByUserId: actorUserIdExample,
  challenge: 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8',
  expiresAt: '2026-11-26T12:05:00.000Z',
};
const deviceNotFound = domainError(
  'Inexistent, foreign, or invisible vehicle or device (uniform)',
  'NOT_FOUND',
  'Device not found',
);
const deviceForbidden = domainError(
  'Caller can legitimately see the vehicle or device but lacks the required authority',
  'FORBIDDEN',
  'Insufficient permissions for this device',
);
const deviceConflict = stateConflict(
  'Duplicate identifier/key, expired/used challenge, unusable credential, or terminal REVOKED state',
  'Device cannot complete the requested transition',
);
const upstreamUnavailable = domainError(
  'Upstream Device or Vehicle database unavailable',
  'SERVICE_UNAVAILABLE',
  'Device service unavailable',
);
const upstreamTimeout = domainError(
  'Upstream Device call exceeded internal deadline',
  'GATEWAY_TIMEOUT',
  'Device service timed out',
);

paths['/vehicles/{vehicleId}/devices'].post.requestBody = jsonRequestBody(
  internalVehicleDeviceRegistrationRequestSchema,
  {
    userId: actorUserIdExample,
    identifier: 'esp32-sunroof-01',
    publicKey:
      '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=\n-----END PUBLIC KEY-----',
    metadata: { name: 'Sunroof Node', manufacturer: 'Espressif' },
  },
);
paths['/vehicles/{vehicleId}/devices'].post.responses = {
  201: result('Device registered as PENDING', vehicleDeviceRegistrationResponseSchema, {
    deviceId: deviceDetailExample.deviceId,
    status: 'PENDING',
    message: 'Device registration accepted',
    data: deviceDetailExample,
    requestId: 'request-1',
  }),
  400: vehicleValidationError,
  401: error,
  403: deviceForbidden,
  404: vehicleNotFound,
  409: deviceConflict,
  503: upstreamUnavailable,
  504: upstreamTimeout,
};

paths['/vehicles/{vehicleId}/devices'].get.parameters = [
  ...(paths['/vehicles/{vehicleId}/devices'].get.parameters as unknown[]),
  userIdQuery,
  ...pageQuery,
  statusQuery(deviceStatusSchema.options, 'Filtro opcional de estado de vinculación'),
];
paths['/vehicles/{vehicleId}/devices'].get.responses = {
  200: result(
    'Authorized vehicle devices ordered by createdAt ASC, _id ASC',
    z.strictObject({
      devices: z.array(deviceDetailSchema),
      page: pageSchema,
      requestId,
    }),
    {
      devices: [{ ...deviceDetailExample, status: 'ACTIVE', operational: true }],
      page: { nextCursor: null },
      requestId: 'request-1',
    },
  ),
  400: vehicleValidationError,
  401: error,
  403: deviceForbidden,
  404: vehicleNotFound,
  503: upstreamUnavailable,
  504: upstreamTimeout,
};

paths['/vehicles/{vehicleId}/devices/{deviceId}'].get.parameters = [
  ...(paths['/vehicles/{vehicleId}/devices/{deviceId}'].get.parameters as unknown[]),
  userIdQuery,
];
paths['/vehicles/{vehicleId}/devices/{deviceId}'].get.responses = {
  200: result('Authorized vehicle device detail', deviceDetailSchema.extend({ requestId }), {
    ...deviceDetailExample,
    status: 'ACTIVE',
    operational: true,
    linkedAt: '2026-11-26T12:02:00.000Z',
    requestId: 'request-1',
  }),
  400: vehicleValidationError,
  401: error,
  404: deviceNotFound,
  503: upstreamUnavailable,
  504: upstreamTimeout,
};

paths['/devices/{deviceId}'].get.parameters = [
  ...(paths['/devices/{deviceId}'].get.parameters as unknown[]),
  userIdQuery,
];
paths['/devices/{deviceId}'].get.responses = {
  200: result('Authorized device detail', deviceDetailSchema.extend({ requestId }), {
    ...deviceDetailExample,
    status: 'ACTIVE',
    operational: true,
    linkedAt: '2026-11-26T12:02:00.000Z',
    requestId: 'request-1',
  }),
  400: vehicleValidationError,
  401: error,
  404: deviceNotFound,
  503: upstreamUnavailable,
  504: upstreamTimeout,
};

paths['/vehicles/{vehicleId}/devices/{deviceId}'].patch.requestBody = jsonRequestBody(
  internalVehicleDeviceMetadataUpdateRequestSchema,
  { userId: actorUserIdExample, firmwareVersion: '1.1.0', serialNumber: null },
);
paths['/vehicles/{vehicleId}/devices/{deviceId}'].patch.responses = {
  200: result('Device metadata updated', vehicleDeviceMetadataUpdateResponseSchema, {
    deviceId: deviceDetailExample.deviceId,
    status: 'ACTIVE',
    message: 'Device metadata updated',
    data: {
      ...deviceDetailExample,
      status: 'ACTIVE',
      operational: true,
      metadata: { ...deviceDetailExample.metadata, firmwareVersion: '1.1.0', serialNumber: null },
    },
    requestId: 'request-1',
  }),
  400: vehicleValidationError,
  401: error,
  403: deviceForbidden,
  404: deviceNotFound,
  409: deviceConflict,
  503: upstreamUnavailable,
  504: upstreamTimeout,
};

paths['/vehicles/{vehicleId}/devices/{deviceId}/challenge'].post.requestBody = jsonRequestBody(
  internalVehicleDeviceChallengeRequestSchema,
  { userId: actorUserIdExample },
);
paths['/vehicles/{vehicleId}/devices/{deviceId}/challenge'].post.responses = {
  201: result('Single-use challenge issued', vehicleDeviceChallengeResponseSchema, {
    challengeId: deviceChallengeExample.challengeId,
    status: 'PENDING',
    message: 'Device enrollment challenge issued',
    data: deviceChallengeExample,
    requestId: 'request-1',
  }),
  400: vehicleValidationError,
  401: error,
  403: deviceForbidden,
  404: deviceNotFound,
  409: deviceConflict,
  503: upstreamUnavailable,
  504: upstreamTimeout,
};

paths['/vehicles/{vehicleId}/devices/{deviceId}/link'].post.requestBody = jsonRequestBody(
  internalVehicleDeviceLinkCompletionRequestSchema,
  {
    userId: actorUserIdExample,
    challengeId: deviceChallengeExample.challengeId,
    challenge: deviceChallengeExample.challenge,
    signature:
      'pobMhCedEBz-1oaWKnuirWj96o5UNkmbADvBNgNkBiI-x3RD1u0PzJ-TVXsE1P0h4udxA0izS_3vUtn4DeYpDw',
  },
);
paths['/vehicles/{vehicleId}/devices/{deviceId}/link'].post.responses = {
  200: result(
    'Device linked after canonical Ed25519 proof verification',
    vehicleDeviceLinkResponseSchema,
    {
      deviceId: deviceDetailExample.deviceId,
      status: 'ACTIVE',
      message: 'Device linked',
      data: {
        ...deviceDetailExample,
        status: 'ACTIVE',
        operational: true,
        linkedAt: '2026-11-26T12:02:00.000Z',
      },
      requestId: 'request-1',
    },
  ),
  400: vehicleValidationError,
  401: error,
  403: deviceForbidden,
  404: deviceNotFound,
  409: deviceConflict,
  503: upstreamUnavailable,
  504: upstreamTimeout,
};

paths['/vehicles/{vehicleId}/devices/{deviceId}/revoke'].post.requestBody = jsonRequestBody(
  internalVehicleDeviceRevokeRequestSchema,
  { userId: actorUserIdExample, reason: 'ADMINISTRATIVE' },
);
paths['/vehicles/{vehicleId}/devices/{deviceId}/revoke'].post.responses = {
  200: result(
    'Device irreversibly revoked (or idempotent repeat)',
    vehicleDeviceRevokeResponseSchema,
    {
      deviceId: deviceDetailExample.deviceId,
      status: 'REVOKED',
      message: 'Device revoked',
      data: {
        ...deviceDetailExample,
        status: 'REVOKED',
        operational: false,
        revokedAt: '2026-11-26T12:10:00.000Z',
        revocationReason: 'ADMINISTRATIVE',
      },
      requestId: 'request-1',
    },
  ),
  400: vehicleValidationError,
  401: error,
  403: deviceForbidden,
  404: deviceNotFound,
  409: deviceConflict,
  503: upstreamUnavailable,
  504: upstreamTimeout,
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
