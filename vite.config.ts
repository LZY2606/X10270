import { defineConfig, type Plugin } from 'vite';
import { createApiMiddleware } from './src/server/api';

function machoApiPlugin(): Plugin {
  return {
    name: 'macho-review-api',
    configureServer(server) {
      server.middlewares.use('/api', createApiMiddleware());
    },
  };
}

export default defineConfig({
  plugins: [machoApiPlugin()],
  server: { strictPort: true },
});
