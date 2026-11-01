import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import prettier from 'eslint-config-prettier';

export default tseslint.config(
  {
    ignores: ['**/node_modules/**', '**/dist/**', '**/.next/**', '**/out/**', '**/coverage/**'],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['apps/api-gateway/**/*.ts', 'services/**/*.ts', 'packages/contracts/**/*.ts'],
    languageOptions: {
      globals: {
        process: 'readonly',
      },
    },
  },
  prettier,
);
