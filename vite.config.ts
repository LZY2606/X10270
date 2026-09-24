import { defineConfig } from "vite";

export default defineConfig({
  root: "src/web",
  publicDir: false,
  build: { outDir: "../../dist-web", emptyOutDir: true },
  server: { middlewareMode: true }
});
