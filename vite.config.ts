import { defineConfig } from 'vite';
import { machoApiPlugin } from './server/plugin';

export default defineConfig({
  plugins: [machoApiPlugin()],
  server: { strictPort: true },
});
