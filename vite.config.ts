import { defineConfig } from 'vitest/config'
import { createApiApp } from './src/server/api'

export default defineConfig({
  plugins: [
    {
      name: 'macho-review-api',
      configureServer(server) {
        const app = createApiApp({
          dbPath: process.env.MACHO_DB ?? 'data/app.db',
          seed: true,
        })
        server.middlewares.use('/api', app)
      },
    },
  ],
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
  },
})
