import { defineConfig } from 'vite';
import { Store } from './src/server/store';
import { seedCasePack } from './src/cases/casepack';
import { createApiMiddleware } from './src/server/api';

export default defineConfig({
  plugins: [
    {
      name: 'macho-review-api',
      configureServer(server) {
        const store = new Store(process.env.MACHO_DB ?? 'data/review.db');
        seedCasePack(store);
        server.middlewares.use('/api', createApiMiddleware(store));
      },
    },
  ],
});
