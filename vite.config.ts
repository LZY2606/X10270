import { defineConfig } from 'vite';

export default defineConfig({
  root: '.',
  publicDir: false,
  build: {
    outDir: 'dist/client',
    rollupOptions: { input: 'index.html' }
  },
  server: { strictPort: true }
});
