import { z } from 'zod';

const httpUrlSchema = z.url().refine((value) => {
  const url = new URL(value);
  return url.protocol === 'http:' || url.protocol === 'https:';
}, 'Service URL must use HTTP or HTTPS');

export const gatewayEnvSchema = z.strictObject({
  HOST: z.string().trim().min(1).default('0.0.0.0'),
  PORT: z.coerce.number().int().min(1).max(65_535).default(3000),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  INTERNAL_SERVICE_SECRET: z.string().min(32),
  JWT_SECRET: z.string().min(32),
  JWT_ISSUER: z.string().trim().min(1),
  JWT_AUDIENCE: z.string().trim().min(1),
  VEHICLE_SERVICE_URL: httpUrlSchema.default('http://127.0.0.1:3002'),
  DEVICE_SERVICE_URL: httpUrlSchema.default('http://127.0.0.1:3003'),
  IDENTITY_SERVICE_URL: httpUrlSchema.default('http://127.0.0.1:3001'),
  PROXY_TIMEOUT_MS: z.coerce.number().int().min(100).max(30_000).default(5_000),
  CORS_ORIGINS: z.string().trim().min(1).default('http://localhost:3000'),
  MAX_PAYLOAD_BYTES: z.coerce.number().int().min(1_024).max(10_485_760).default(1_048_576),
  RATE_LIMIT_MAX: z.coerce.number().int().min(1).max(10_000).default(100),
  RATE_LIMIT_WINDOW_SECONDS: z.coerce.number().int().min(1).max(86_400).default(60),
  SENSITIVE_RATE_LIMIT_MAX: z.coerce.number().int().min(1).max(10_000).default(20),
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
  return result.data;
}

export function configuredCorsOrigins(env: GatewayEnv): Set<string> {
  return new Set(
    env.CORS_ORIGINS.split(',')
      .map((origin) => origin.trim())
      .filter(Boolean),
  );
}
