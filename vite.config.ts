import { defineConfig } from "vite";

export default defineConfig({
  root: ".",
  appType: "custom",
  server: { middlewareMode: true },
  build: { outDir: "dist/client" }
});
