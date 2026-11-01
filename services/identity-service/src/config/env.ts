import { z } from 'zod';

const environmentSchema = z.object({
  HOST: z.string().trim().min(1),
  PORT: z.coerce.number().int().min(1).max(65_535),
  DOCUMENTATION_URL: z.string().url(),
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
});

export type Environment = z.infer<typeof environmentSchema>;

export function parseEnvironment(input: NodeJS.ProcessEnv): Environment {
  return environmentSchema.parse(input);
}

export function loadEnvironment(): Environment {
  return parseEnvironment(process.env);
}
