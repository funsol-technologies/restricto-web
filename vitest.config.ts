import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: { include: ['tests/**/*.test.{ts,tsx}'], environment: 'node', testTimeout: 20000 },
});
