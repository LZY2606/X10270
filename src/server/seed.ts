/** 首次启动播种：将离线案例包的 11 个场景导入为带样例会话，直接进入审阅页。 */

import { buildCasePack } from "../domain/casepack.js";
import { SessionService } from "./session-service.js";
import type { SessionRow } from "./store.js";

export interface SeededScenario {
  scenarioId: string;
  sessionId: string;
  title: string;
  phase: string;
  changedSource: string;
  basis: string;
}

export function seedCasePack(service: SessionService, force = false): SeededScenario[] {
  const existing = service.store.listSessions();
  const out: SeededScenario[] = [];
  const cp = buildCasePack();
  for (const scn of cp.scenarios) {
    const title = `[${scn.phase}] ${scn.title}`;
    let session = existing.find((s) => s.title === title);
    if (!session) {
      session = service.createSession(title);
      service.importMaterial({
        sessionId: session.id,
        kind: "macho-fat64",
        bytes: scn.bytes,
        sourceLabel: `casepack://${cp.id}/${scn.id}`,
        basis: {
          scenarioId: scn.id,
          phase: scn.phase,
          changedSource: scn.changedSource,
          basis: scn.basis,
          expectations: scn.expectations,
        },
      });
      service.derive(session.id);
      // 参数修订场景：直接在该会话上留下 v2 事件与重新派生（历史保留 v1 结论）
      if (scn.phase === "revision") {
        service.revisePolicy(session.id, { unknownBlobIsError: true });
        service.derive(session.id);
      }
      // 冲突人工决定：在多架构同名会话上留下两次互斥决定（分支承载）
      if (scn.phase === "decision") {
        service.decide({
          sessionId: session.id, value: "accept", target: "slice:0",
          note: "人工决定 A：选择 arm64（subtype=0）",
        });
        service.branch(session.id, "alt-arm64e");
        // alt 分支材料：复用主分支材料
        service.importMaterial({
          sessionId: session.id, branchId: "alt-arm64e", kind: "macho-fat64",
          bytes: scn.bytes, sourceLabel: `casepack://${cp.id}/${scn.id}#branch`,
          basis: { scenarioId: scn.id, phase: scn.phase, branched: true },
        });
        service.derive(session.id, "alt-arm64e");
        service.decide({
          sessionId: session.id, branchId: "alt-arm64e", value: "accept", target: "slice:1",
          note: "冲突人工决定 B：选择 arm64e（subtype=2）",
        });
      }
    }
    out.push({
      scenarioId: scn.id,
      sessionId: session.id,
      title,
      phase: scn.phase,
      changedSource: scn.changedSource,
      basis: scn.basis,
    });
  }
  return out;
}

export function casePackMeta() {
  const cp = buildCasePack();
  return { id: cp.id, title: cp.title, narrative: cp.narrative };
}
