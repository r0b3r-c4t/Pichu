import { z } from 'zod';
import { decodeBytes32, validateKeyring, type Keyring } from '@pichu/internal-auth';
const envSchema = z.object({
  HOST: z.string().trim().min(1).default('0.0.0.0'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3002),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  DATABASE_URL: z.string().url(),
  IDENTITY_SERVICE_URL: z.string().url().default('http://127.0.0.1:3001'),
  DEVICE_SERVICE_URL: z.string().url().default('http://127.0.0.1:3003'),
  INTERNAL_AUTH_ENVIRONMENT: z
    .enum(['development', 'test', 'staging', 'production'])
    .default('development'),
  INTERNAL_AUTH_KEYRING_JSON: z.string().trim().min(2),
  INTERNAL_AUTH_BODY_LIMIT: z.coerce.number().int().min(1).max(1_048_576).default(1_048_576),
  TLS_CERT_PATH: z.string().trim().min(1).optional(),
  TLS_KEY_PATH: z.string().trim().min(1).optional(),
  TLS_CA_PATH: z.string().trim().min(1).optional(),
});
export type VehicleEnv = z.infer<typeof envSchema>;
export function loadEnv(source: NodeJS.ProcessEnv = process.env): VehicleEnv {
  const env = envSchema.parse(source);
  if (
    env.NODE_ENV === 'production' &&
    (!env.TLS_CERT_PATH || !env.TLS_KEY_PATH || !env.TLS_CA_PATH)
  )
    throw new Error('Production TLS configuration is incomplete');
  return env;
}

export function parseInternalKeyring(env: VehicleEnv): Keyring {
  try {
    const entries = z
      .array(
        z.strictObject({
          environment: z.enum(['development', 'test', 'staging', 'production']),
          sender: z.string(),
          audience: z.string(),
          keyId: z.string(),
          secretBase64Url: z.string(),
          notBefore: z.number().int().nonnegative(),
          notAfter: z.number().int().nonnegative(),
          state: z.enum(['active', 'previous', 'revoked']),
        }),
      )
      .parse(JSON.parse(env.INTERNAL_AUTH_KEYRING_JSON));
    const keyring: Keyring = entries.map((entry) => ({
      ...entry,
      secret: decodeBytes32(entry.secretBase64Url),
    })) as Keyring;
    validateKeyring(keyring);
    return keyring;
  } catch {
    throw new Error('Invalid internal authentication configuration');
  }
}
