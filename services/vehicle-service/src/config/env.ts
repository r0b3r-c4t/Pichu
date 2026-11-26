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
  'device_db',
  'device_test_db',
  'automation_db',
  'automation_test_db',
]);

const ALLOWED_TEST_DATABASE_PATTERN = /^(?:test|vehicle_db|vehicle_test_db|vehicle_[a-z0-9_-]+)$/;

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
  if (!value.startsWith('mongodb://') && !value.startsWith('mongodb+srv://')) {
    return undefined;
  }
  try {
    const parsed = new URL(value);
    if (!parsed.hostname) {
      return undefined;
    }
    return parsed;
  } catch {
    return undefined;
  }
}

const httpServiceUrlSchema = z.string().trim().refine(isHttpOrHttpsUrl, {
  message: 'Service URL must be a valid HTTP or HTTPS URL',
});

const envSchema = z
  .object({
    HOST: z.string().trim().min(1).default('0.0.0.0'),
    PORT: z.coerce.number().int().min(1).max(65_535).default(3002),
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    DATABASE_URL: z.string().trim().min(1),
    IDENTITY_SERVICE_URL: httpServiceUrlSchema.default('http://127.0.0.1:3001'),
    DEVICE_SERVICE_URL: httpServiceUrlSchema.default('http://127.0.0.1:3003'),
    INTERNAL_AUTH_ENVIRONMENT: internalEnvironmentSchema.default('development'),
    INTERNAL_AUTH_KEYRING_JSON: z.string().trim().min(2),
    INTERNAL_AUTH_BODY_LIMIT: z.coerce.number().int().min(1).max(1_048_576).default(1_048_576),
    INVITATION_TTL_SECONDS: z.coerce
      .number()
      .int()
      .min(60)
      .max(30 * 86_400)
      .default(7 * 86_400),
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
    const explicitDbNameParam = mongoUrl.searchParams.get('dbName');
    if (explicitDbNameParam !== null && explicitDbNameParam !== dbName) {
      context.addIssue({
        code: 'custom',
        path: ['DATABASE_URL'],
        message: 'DATABASE_URL must not specify a conflicting dbName query parameter',
      });
    }

    if (
      FORBIDDEN_DATABASE_NAMES.has(dbName) ||
      (explicitDbNameParam !== null && FORBIDDEN_DATABASE_NAMES.has(explicitDbNameParam))
    ) {
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
      if (dbName !== '' && !ALLOWED_TEST_DATABASE_PATTERN.test(dbName)) {
        context.addIssue({
          code: 'custom',
          path: ['DATABASE_URL'],
          message:
            'Test DATABASE_URL must target vehicle_db, vehicle_test_db, test, or an isolated vehicle_* database',
        });
      }
    } else if (dbName !== 'vehicle_db') {
      context.addIssue({
        code: 'custom',
        path: ['DATABASE_URL'],
        message: 'DATABASE_URL must target vehicle_db outside explicit test mode',
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

      for (const field of ['IDENTITY_SERVICE_URL', 'DEVICE_SERVICE_URL'] as const) {
        if (!env[field].startsWith('https://')) {
          context.addIssue({
            code: 'custom',
            path: [field],
            message: `${field} must use HTTPS in production`,
          });
        }
      }
    }
  });

export type VehicleEnv = z.infer<typeof envSchema>;

export function loadEnv(source: NodeJS.ProcessEnv = process.env): VehicleEnv {
  const env = envSchema.parse(source);
  if (
    env.NODE_ENV === 'production' &&
    (!env.TLS_CERT_PATH || !env.TLS_KEY_PATH || !env.TLS_CA_PATH)
  ) {
    throw new Error('Production TLS configuration is incomplete');
  }
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

export function parseInternalKeyring(env: VehicleEnv): Keyring {
  let raw: unknown;
  try {
    raw = JSON.parse(env.INTERNAL_AUTH_KEYRING_JSON);
  } catch {
    throw new Error('Invalid internal authentication configuration');
  }

  const parsed = z.array(keyringEntrySchema).safeParse(raw);
  if (
    !parsed.success ||
    parsed.data.some((entry) => entry.environment !== env.INTERNAL_AUTH_ENVIRONMENT)
  ) {
    throw new Error('Invalid internal authentication configuration');
  }

  try {
    const keyring: Keyring = parsed.data.map((entry) => ({
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
