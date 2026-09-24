/// <reference types="vitest/config" />
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { serverApiPlugin } from './src/server/plugin';

export default defineConfig({
  plugins: [react(), serverApiPlugin()],
  server: {
    host: '127.0.0.1',
    port: 5370,
    strictPort: true,
  },
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    testTimeout: 20000,
  },
});
