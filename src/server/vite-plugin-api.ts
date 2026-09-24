/** Vite 插件：把服务端 API 以中间件方式挂进同一个 dev server（业务规则不只在浏览器）。 */

import type { Plugin } from "vite";
import { handleApi, exportBundle } from "./api.js";
import { getRuntime } from "./runtime.js";
import type { ExportBundle } from "./store.js";

export function apiPlugin(): Plugin {
  return {
    name: "macho-testimony-api",
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        try {
          const url = new URL(req.url ?? "/", "http://127.0.0.1:5370");
          if (url.pathname === "/api/export" && req.method === "GET") {
            const rt = getRuntime();
            const bundle = exportBundle(rt.service);
            res.writeHead(200, {
              "content-type": "application/json; charset=utf-8",
              "content-disposition": 'attachment; filename="macho-testimony-archive.json"',
            });
            res.end(JSON.stringify(bundle));
            return;
          }
          if (url.pathname === "/api/reimport" && req.method === "POST") {
            const chunks: Buffer[] = [];
            for await (const c of req) chunks.push(c as Buffer);
            const bundle = JSON.parse(Buffer.concat(chunks).toString("utf8")) as ExportBundle;
            const rt = getRuntime();
            rt.resetDatabase(bundle);
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify({ ok: true, sessions: rt.store.listSessions().length }));
            return;
          }
          if (url.pathname === "/api/reset" && req.method === "POST") {
            const rt = getRuntime();
            rt.resetDatabase();
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify({ ok: true }));
            return;
          }
          const rt = getRuntime();
          const handled = await handleApi(req, res, url, rt);
          if (!handled) next();
        } catch (err) {
          res.writeHead(500, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "internal", message: (err as Error).message }));
        }
      });
    },
  };
}
