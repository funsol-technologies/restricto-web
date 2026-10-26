import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: { alias: { '@funsol/restricto-web': new URL('./src/index.ts', import.meta.url).pathname } },
  test: { include: ['tests/**/*.test.{ts,tsx}'], environment: 'node', testTimeout: 20000 },
});
