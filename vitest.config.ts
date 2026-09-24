import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { apiPlugin } from "./src/server/vite-plugin-api.ts";

export default defineConfig({
  plugins: [react(), apiPlugin()],
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 15000,
    hookTimeout: 15000,
  },
});
