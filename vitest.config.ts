import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: { include: ['test/**/*.test.ts'], testTimeout: 20000, pool: 'forks' },
  resolve: { alias: { '@core': '/src/core', '@server': '/src/server' } }
});
