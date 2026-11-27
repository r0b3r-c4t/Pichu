import { z } from 'zod';
import {
  internalCallerNameSchema,
  internalEnvironmentSchema,
  internalKeyIdSchema,
} from '@pichu/contracts';
import { decodeBytes32, validateKeyring, type Keyring } from '@pichu/internal-auth';

const FORBIDDEN_DATABASE_NAMES = new Set([
  'admin',
  'local',
  'config',
  'identity_db',
  'identity_test_db',
  'vehicle_db',
  'vehicle_test_db',
  'automation_db',
  'automation_test_db',
]);

const ALLOWED_TEST_DATABASE_PATTERN = /^(?:test|device_db|device_test_db|device_[a-z0-9_-]+)$/;

function isHttpOrHttpsUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return (
      (parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.hostname.length > 0
    );
  } catch {
    return false;
  }
}

function parseMongoDatabaseUrl(value: string): URL | undefined {
  if (!value.startsWith('mongodb://') && !value.startsWith('mongodb+srv://')) return undefined;
  try {
    const parsed = new URL(value);
    return parsed.hostname ? parsed : undefined;
  } catch {
    return undefined;
  }
}

const envSchema = z
  .object({
    HOST: z.string().trim().min(1).default('0.0.0.0'),
    PORT: z.coerce.number().int().min(1).max(65535).default(3003),
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    DATABASE_URL: z.string().trim().min(1),
    IDENTITY_SERVICE_URL: z
      .string()
      .trim()
      .refine(isHttpOrHttpsUrl, { message: 'Service URL must be a valid HTTP or HTTPS URL' })
      .default('http://127.0.0.1:3001'),
    INTERNAL_AUTH_ENVIRONMENT: internalEnvironmentSchema.default('development'),
    INTERNAL_AUTH_KEYRING_JSON: z.string().trim().min(2),
    INTERNAL_AUTH_BODY_LIMIT: z.coerce.number().int().min(1).max(1_048_576).default(1_048_576),
    TLS_CERT_PATH: z.string().trim().min(1).optional(),
    TLS_KEY_PATH: z.string().trim().min(1).optional(),
    TLS_CA_PATH: z.string().trim().min(1).optional(),
  })
  .superRefine((env, context) => {
    const mongoUrl = parseMongoDatabaseUrl(env.DATABASE_URL);
    if (!mongoUrl) {
      context.addIssue({
        code: 'custom',
        path: ['DATABASE_URL'],
        message: 'DATABASE_URL must be a valid mongodb:// or mongodb+srv:// URI',
      });
      return;
    }

    const dbName = decodeURIComponent(mongoUrl.pathname.replace(/^\/+/, ''));
    const explicitDbName = mongoUrl.searchParams.get('dbName');
    if (explicitDbName !== null && explicitDbName !== dbName) {
      context.addIssue({
        code: 'custom',
        path: ['DATABASE_URL'],
        message: 'DATABASE_URL must not specify a conflicting dbName query parameter',
      });
    }
    if (FORBIDDEN_DATABASE_NAMES.has(dbName)) {
      context.addIssue({
        code: 'custom',
        path: ['DATABASE_URL'],
        message: 'DATABASE_URL cannot target another service or administrative database',
      });
      return;
    }

    const isTestMode =
      env.NODE_ENV === 'test' ||
      (env.NODE_ENV !== 'production' && env.INTERNAL_AUTH_ENVIRONMENT === 'test');
    if (isTestMode) {
      if (!ALLOWED_TEST_DATABASE_PATTERN.test(dbName)) {
        context.addIssue({
          code: 'custom',
          path: ['DATABASE_URL'],
          message:
            'Test DATABASE_URL must target device_db, device_test_db, test, or an isolated device_* database',
        });
      }
    } else if (dbName !== 'device_db') {
      context.addIssue({
        code: 'custom',
        path: ['DATABASE_URL'],
        message: 'DATABASE_URL must target device_db outside explicit test mode',
      });
    }

    if (env.NODE_ENV === 'production') {
      if (!mongoUrl.username || !mongoUrl.password) {
        context.addIssue({
          code: 'custom',
          path: ['DATABASE_URL'],
          message: 'Production DATABASE_URL must include explicit authentication credentials',
        });
      }
      if (env.INTERNAL_AUTH_ENVIRONMENT !== 'production') {
        context.addIssue({
          code: 'custom',
          path: ['INTERNAL_AUTH_ENVIRONMENT'],
          message: 'INTERNAL_AUTH_ENVIRONMENT must be production when NODE_ENV is production',
        });
      }
      if (!env.IDENTITY_SERVICE_URL.startsWith('https://')) {
        context.addIssue({
          code: 'custom',
          path: ['IDENTITY_SERVICE_URL'],
          message: 'IDENTITY_SERVICE_URL must use HTTPS in production',
        });
      }
    }
  });

export type DeviceEnv = z.infer<typeof envSchema>;
export function loadEnv(source: NodeJS.ProcessEnv = process.env): DeviceEnv {
  const env = envSchema.parse(source);
  if (
    env.NODE_ENV === 'production' &&
    (!env.TLS_CERT_PATH || !env.TLS_KEY_PATH || !env.TLS_CA_PATH)
  )
    throw new Error('Production TLS configuration is incomplete');
  return env;
}

const keyringEntrySchema = z.strictObject({
  environment: internalEnvironmentSchema,
  sender: internalCallerNameSchema,
  audience: internalCallerNameSchema,
  keyId: internalKeyIdSchema,
  secretBase64Url: z.string(),
  notBefore: z.number().int().nonnegative().safe(),
  notAfter: z.number().int().nonnegative().safe(),
  state: z.enum(['active', 'previous', 'revoked']),
});

export function parseInternalKeyring(env: DeviceEnv): Keyring {
  try {
    const entries = z.array(keyringEntrySchema).parse(JSON.parse(env.INTERNAL_AUTH_KEYRING_JSON));
    if (entries.some((entry) => entry.environment !== env.INTERNAL_AUTH_ENVIRONMENT)) {
      throw new Error('Keyring environment mismatch');
    }
    const keyring: Keyring = entries.map((entry) => ({
      environment: entry.environment,
      sender: entry.sender,
      audience: entry.audience,
      keyId: entry.keyId,
      secret: decodeBytes32(entry.secretBase64Url),
      notBefore: entry.notBefore,
      notAfter: entry.notAfter,
      state: entry.state,
    }));
    validateKeyring(keyring);
    return keyring;
  } catch {
    throw new Error('Invalid internal authentication configuration');
  }
}
