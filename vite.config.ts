import { defineConfig } from 'vite';
import machoApi from './src/server/plugin.ts';

export default defineConfig({
  plugins: [machoApi()],
  server: {
    host: '127.0.0.1',
    port: 5370,
    strictPort: true
  }
});
