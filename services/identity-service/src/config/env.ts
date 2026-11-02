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
    NODE_ENV: z.enum(['development', 'test', 'production']),
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
    const verificationUrl = new URL(environment.EMAIL_VERIFICATION_URL);
    const hostname = verificationUrl.hostname.replace(/^\[|\]$/g, '');
    const isLocalhost = ['localhost', '127.0.0.1', '::1'].includes(hostname);
    const isHttps = verificationUrl.protocol === 'https:';
    const isDevelopmentHttp = verificationUrl.protocol === 'http:' && isLocalhost && environment.NODE_ENV !== 'production';

    if (!isHttps && !isDevelopmentHttp) {
      context.addIssue({
        code: 'custom',
        path: ['EMAIL_VERIFICATION_URL'],
        message: 'EMAIL_VERIFICATION_URL must use HTTPS, except HTTP localhost URLs outside production',
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
