/** 独立 Node 服务器入口（npm run build && npm start）。 */

import { createServer } from "node:http";
import { handleApi, exportBundle } from "./api.js";
import { getRuntime } from "./runtime.js";

const port = Number(process.env.PORT ?? 5370);
const rt = getRuntime();

createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://127.0.0.1:${port}`);
  if (url.pathname === "/api/export") {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(exportBundle(rt.service)));
    return;
  }
  const handled = await handleApi(req, res, url, rt);
  if (!handled) {
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not-found" }));
  }
}).listen(port, "127.0.0.1", () => {
  console.log(`API server http://127.0.0.1:${port}`);
});
