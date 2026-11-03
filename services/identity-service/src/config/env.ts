import { z } from 'zod';

const environmentSchema = z
  .object({
    HOST: z.string().trim().min(1),
    PORT: z.coerce.number().int().min(1).max(65_535),
    DOCUMENTATION_URL: z.string().url(),
    RESEND_API_KEY: z.string().trim().min(1),
    RESEND_FROM_EMAIL: z.string().email(),
    RESEND_FROM_NAME: z.string().trim().min(1),
    EMAIL_VERIFICATION_URL: z.string().url(),
    EMAIL_VERIFICATION_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(86_400),
    PASSWORD_RESET_URL: z.string().url(),
    PASSWORD_RESET_TOKEN_TTL_SECONDS: z.coerce.number().int().min(300).max(86_400),
    NODE_ENV: z.enum(['development', 'test', 'production']),
    JWT_SECRET: z.string().refine((value) => Buffer.byteLength(value, 'utf8') >= 32, {
      message: 'JWT_SECRET must contain at least 32 bytes',
    }),
    JWT_ISSUER: z.string().trim().min(1),
    JWT_AUDIENCE: z.string().trim().min(1),
    ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(3_600),
    REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().int().min(300).max(2_592_000),
    AUTH_COOKIE_ORIGIN: z.string().url(),
    DATABASE_URL: z
      .string()
      .url()
      .refine((value) => value.startsWith('mongodb://') || value.startsWith('mongodb+srv://'), {
        message: 'DATABASE_URL must use mongodb:// or mongodb+srv://',
      })
      .refine((value) => {
        try {
          const url = new URL(value);
          return (
            url.pathname === '/identity_db' &&
            url.hostname.length > 0 &&
            url.searchParams.get('authSource') === 'identity_db' &&
            decodeURIComponent(url.username) === 'identity_user' &&
            url.password.length > 0
          );
        } catch {
          return false;
        }
      }, 'DATABASE_URL must target identity_db using identity_user and authSource=identity_db'),
  })
  .superRefine((environment, context) => {
    for (const [field, value] of [
      ['EMAIL_VERIFICATION_URL', environment.EMAIL_VERIFICATION_URL],
      ['PASSWORD_RESET_URL', environment.PASSWORD_RESET_URL],
    ] as const) {
      const targetUrl = new URL(value);
      const hostname = targetUrl.hostname.replace(/^\[|\]$/g, '');
      const isLocalhost = ['localhost', '127.0.0.1', '::1'].includes(hostname);
      const isHttps = targetUrl.protocol === 'https:';
      const isDevelopmentHttp =
        targetUrl.protocol === 'http:' && isLocalhost && environment.NODE_ENV !== 'production';

      if (!isHttps && !isDevelopmentHttp) {
        context.addIssue({
          code: 'custom',
          path: [field],
          message: `${field} must use HTTPS, except HTTP localhost URLs outside production`,
        });
      }
    }

    const cookieOrigin = new URL(environment.AUTH_COOKIE_ORIGIN);
    if (cookieOrigin.protocol !== 'http:' && cookieOrigin.protocol !== 'https:') {
      context.addIssue({
        code: 'custom',
        path: ['AUTH_COOKIE_ORIGIN'],
        message: 'AUTH_COOKIE_ORIGIN must use HTTP or HTTPS',
      });
    }
    if (environment.NODE_ENV === 'production' && cookieOrigin.protocol !== 'https:') {
      context.addIssue({
        code: 'custom',
        path: ['AUTH_COOKIE_ORIGIN'],
        message: 'AUTH_COOKIE_ORIGIN must use HTTPS in production',
      });
    }
  });

export type Environment = z.infer<typeof environmentSchema>;

export function parseEnvironment(input: NodeJS.ProcessEnv): Environment {
  return environmentSchema.parse(input);
}

export function loadEnvironment(): Environment {
  return parseEnvironment(process.env);
}
