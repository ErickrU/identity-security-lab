import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['chapters/**/*.test.ts', 'small-idp/**/*.test.ts'],
    exclude: ['**/node_modules/**', '**/cdk.out/**'],
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
