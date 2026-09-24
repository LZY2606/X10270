import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// The HTTP API is served by the same Node process (scripts/dev-server.ts)
// which starts Vite in middleware mode. This config is also used by vitest.
export default defineConfig({
  plugins: [react()],
  root: ".",
  server: { host: "127.0.0.1", port: 5370, strictPort: true },
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    globals: false,
  },
});
