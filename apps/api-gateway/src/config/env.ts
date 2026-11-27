import { z } from 'zod';

const httpUrlSchema = z.url().refine((value) => {
  const url = new URL(value);
  return url.protocol === 'http:' || url.protocol === 'https:';
}, 'Service URL must use HTTP or HTTPS');

export const gatewayEnvSchema = z.strictObject({
  HOST: z.string().trim().min(1).default('0.0.0.0'),
  PORT: z.coerce.number().int().min(1).max(65_535).default(3000),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  INTERNAL_AUTH_ENVIRONMENT: z
    .enum(['development', 'test', 'staging', 'production'])
    .default('development'),
  INTERNAL_AUTH_KEYRING_JSON: z.string().trim().min(2),
  JWT_SECRET: z.string().min(32),
  JWT_ISSUER: z.string().trim().min(1),
  JWT_AUDIENCE: z.string().trim().min(1),
  VEHICLE_SERVICE_URL: httpUrlSchema.default('http://127.0.0.1:3002'),
  DEVICE_SERVICE_URL: httpUrlSchema.default('http://127.0.0.1:3003'),
  IDENTITY_SERVICE_URL: httpUrlSchema.default('http://127.0.0.1:3001'),
  PROXY_TIMEOUT_MS: z.coerce.number().int().min(100).max(30_000).default(5_000),
  TLS_CA_PATH: z.string().trim().min(1).optional(),
  CORS_ORIGINS: z.string().trim().min(1).default('http://localhost:3000'),
  MAX_PAYLOAD_BYTES: z.coerce.number().int().min(1_024).max(10_485_760).default(1_048_576),
  RATE_LIMIT_MAX: z.coerce.number().int().min(1).max(10_000).default(100),
  RATE_LIMIT_WINDOW_SECONDS: z.coerce.number().int().min(1).max(86_400).default(60),
  SENSITIVE_RATE_LIMIT_MAX: z.coerce.number().int().min(1).max(10_000).default(20),
  /** Invitation issuance per authenticated user (instance-local, on top of the global limit). */
  INVITATION_RATE_LIMIT_MAX: z.coerce.number().int().min(1).max(1_000).default(10),
  INVITATION_RATE_LIMIT_WINDOW_SECONDS: z.coerce.number().int().min(1).max(86_400).default(60),
  /** Complementary invitation issuance limit per client IP within the same window. */
  INVITATION_IP_RATE_LIMIT_MAX: z.coerce.number().int().min(1).max(10_000).default(30),
});

export type GatewayEnv = z.infer<typeof gatewayEnvSchema>;

export class GatewayConfigError extends Error {
  constructor(
    public readonly issues: Array<{
      path: string;
      message: string;
    }> = [],
  ) {
    super(
      `Gateway configuration is invalid: ${issues
        .map((issue) => `${issue.path}: ${issue.message}`)
        .join('; ')}`,
    );

    this.name = 'GatewayConfigError';
  }
}

export function loadGatewayEnv(source: NodeJS.ProcessEnv = process.env): GatewayEnv {
  const input =
    source === process.env
      ? Object.fromEntries(Object.keys(gatewayEnvSchema.shape).map((key) => [key, source[key]]))
      : source;
  const result = gatewayEnvSchema.safeParse(input);
  if (!result.success) {
    throw new GatewayConfigError(
      result.error.issues.map((issue) => ({
        path: issue.path.join('.'),
        message: issue.message,
      })),
    );
  }
  if (result.success && result.data.NODE_ENV === 'production') {
    for (const key of [
      'IDENTITY_SERVICE_URL',
      'VEHICLE_SERVICE_URL',
      'DEVICE_SERVICE_URL',
    ] as const) {
      if (!result.data[key].startsWith('https://'))
        throw new GatewayConfigError([
          { path: key, message: 'Production service URLs must use HTTPS' },
        ]);
    }
    if (!result.data.TLS_CA_PATH)
      throw new GatewayConfigError([
        { path: 'TLS_CA_PATH', message: 'Production TLS CA is required' },
      ]);
  }
  return result.data;
}

export function configuredCorsOrigins(env: GatewayEnv): Set<string> {
  return new Set(
    env.CORS_ORIGINS.split(',')
      .map((origin) => origin.trim())
      .filter(Boolean),
  );
}
