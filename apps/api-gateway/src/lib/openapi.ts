import { z } from 'zod';

export function jsonSchema(schema: z.ZodType): Record<string, unknown> {
  const generated = z.toJSONSchema(schema, { target: 'draft-7' }) as Record<string, unknown>;
  delete generated.$schema;
  return generated;
}
