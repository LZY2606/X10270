/** HTTP 路由（不依赖框架，Vite 中间件与独立 Node 服务器共用）。 */

import type { ServerResponse, IncomingMessage } from "node:http";
import { SessionService } from "./session-service.js";
import { seedCasePack, casePackMeta } from "./seed.js";
import type { ExportBundle } from "./store.js";

export interface ApiDeps {
  service: SessionService;
  /** 删除本地数据库后重建（测试导出/删除/再导入的极端工作流） */
  resetDatabase: (bundle?: ExportBundle) => void;
}

interface JsonReq {
  method: string;
  body: any;
  query: URLSearchParams;
}

function send(res: ServerResponse, status: number, data: unknown): void {
  const json = JSON.stringify(data);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(json);
}

export async function handleApi(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  deps: ApiDeps,
): Promise<boolean> {
  const { service } = deps;
  if (!url.pathname.startsWith("/api/")) return false;
  const read = async (): Promise<JsonReq> => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const raw = Buffer.concat(chunks).toString("utf8");
    return {
      method: req.method ?? "GET",
      body: raw ? JSON.parse(raw) : {},
      query: url.searchParams,
    };
  };

  try {
    if (url.pathname === "/api/casepack" && req.method === "GET") {
      send(res, 200, casePackMeta());
      return true;
    }
    if (url.pathname === "/api/sessions" && req.method === "GET") {
      const sessions = service.store.listSessions();
      const seeded = seedCasePack(service);
      const seededById = new Map(seeded.map((s) => [s.sessionId, s]));
      send(res, 200, sessions.map((s) => ({ ...s, scenario: seededById.get(s.id) ?? null })));
      return true;
    }
    if (url.pathname === "/api/sessions" && req.method === "POST") {
      const { body } = await read();
      const title = typeof body?.title === "string" && body.title.trim() ? body.title : "未命名会话";
      const session = service.createSession(title);
      send(res, 201, session);
      return true;
    }

    const m = url.pathname.match(/^\/api\/sessions\/([^/]+)(?:\/(.*))?$/);
    if (!m) {
      send(res, 404, { error: "not-found" });
      return true;
    }
    const sessionId = m[1]!;
    const action = m[2] ?? "";

    if (req.method === "GET" && action === "") {
      const branch = url.searchParams.get("branch") ?? "main";
      const seqParam = url.searchParams.get("seq");
      const view = seqParam === null
        ? service.currentView(sessionId, branch)
        : service.viewAt(sessionId, Number(seqParam), branch);
      send(res, 200, {
        session: service.store.getSession(sessionId),
        branches: distinctBranches(service, sessionId),
        view: serializeView(view),
      });
      return true;
    }

    if (req.method === "GET" && action === "events") {
      send(res, 200, service.store.listAllEvents(sessionId));
      return true;
    }

    if (req.method === "GET" && action === "materials") {
      send(res, 200, service.store.listMaterials(sessionId));
      return true;
    }

    const { body } = await read();

    if (req.method === "POST" && action === "import") {
      const bytes = Buffer.from(body.base64 ?? "", "base64");
      if (!bytes.length) {
        send(res, 422, { error: "incomplete-input", message: "材料为空：禁止以空值伪装成功", location: { field: "base64" } });
        return true;
      }
      const imported = service.importMaterial({
        sessionId,
        branchId: body.branchId ?? "main",
        kind: body.kind ?? "macho-fat64",
        bytes,
        sourceLabel: body.sourceLabel ?? "upload",
        basis: body.basis ?? {},
      });
      const derivation = service.derive(sessionId, body.branchId ?? "main");
      send(res, 201, { material: imported.material, event: imported.event, derivation });
      return true;
    }
    if (req.method === "POST" && action === "derive") {
      send(res, 200, service.derive(sessionId, body.branchId ?? "main"));
      return true;
    }
    if (req.method === "POST" && action === "policy") {
      const row = service.revisePolicy(sessionId, body.changes ?? {}, body.branchId ?? "main");
      const derivation = service.derive(sessionId, body.branchId ?? "main");
      send(res, 200, { event: row, derivation });
      return true;
    }
    if (req.method === "POST" && action === "amend") {
      const bytes = Buffer.from(body.base64 ?? "", "base64");
      if (!bytes.length) {
        send(res, 422, { error: "incomplete-input", message: "修订材料为空", location: { field: "base64" } });
        return true;
      }
      const result = service.amendSource({
        sessionId,
        branchId: body.branchId ?? "main",
        bytes,
        sourceLabel: body.sourceLabel ?? "amendment",
        basis: body.basis ?? {},
      });
      send(res, 200, result);
      return true;
    }
    if (req.method === "POST" && action === "decide") {
      if (!["accept", "reject", "adjust"].includes(body.value)) {
        send(res, 422, { error: "incomplete-input", message: "决定值必须为 accept/reject/adjust", location: { field: "value" } });
        return true;
      }
      const row = service.decide({
        sessionId,
        branchId: body.branchId ?? "main",
        value: body.value,
        target: String(body.target ?? ""),
        note: String(body.note ?? ""),
      });
      send(res, 200, row);
      return true;
    }
    if (req.method === "POST" && action === "branch") {
      const row = service.branch(sessionId, String(body.branchId), body.fromSeq);
      send(res, 201, row);
      return true;
    }
    if (req.method === "POST" && action === "recover") {
      const recovered = service.store.recoverHalfWrites();
      send(res, 200, { recoveredTransactions: recovered });
      return true;
    }
    if (req.method === "POST" && action === "inject-halfwrite") {
      const tx = service.store.injectHalfWrite(body.detail ?? "manual");
      send(res, 200, { tx });
      return true;
    }

    send(res, 404, { error: "not-found", action });
    return true;
  } catch (err) {
    send(res, 500, { error: "internal", message: (err as Error).message });
    return true;
  }
}

function distinctBranches(service: SessionService, sessionId: string): string[] {
  return [...new Set(service.store.listAllEvents(sessionId).map((e) => e.branch_id))];
}

function serializeView(view: Awaited<ReturnType<SessionService["currentView"]>>) {
  return {
    ...view,
    material: view.material
      ? { ...view.material, rawLength: Buffer.from(view.material.raw_base64, "base64").length }
      : null,
  };
}

export function exportBundle(service: SessionService): ExportBundle {
  return service.store.exportAll();
}
