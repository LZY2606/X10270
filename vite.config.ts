import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { createApiPlugin } from "./src/server/plugin";

export default defineConfig({
  plugins: [react(), createApiPlugin() as Plugin],
  server: {
    host: "127.0.0.1",
    port: 5370,
    strictPort: true,
  },
  preview: {
    host: "127.0.0.1",
    port: 5370,
    strictPort: true,
  },
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    globals: false,
    testTimeout: 20000,
    hookTimeout: 20000,
  },
});
