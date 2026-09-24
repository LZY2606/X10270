import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { createApiMiddleware } from './src/server/api';
import { openStore } from './src/server/store';
import { ensureCasePackSeeded } from './src/server/casepack';

function apiPlugin(): Plugin {
  return {
    name: 'macho-api',
    configureServer(server) {
      const store = openStore('data/app.db');
      ensureCasePackSeeded(store);
      server.middlewares.use('/api', createApiMiddleware(store));
    },
  };
}

export default defineConfig({
  plugins: [react(), apiPlugin()],
  server: { host: '127.0.0.1', port: 5370, strictPort: true },
});
