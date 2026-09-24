import { parseFat, FatModel } from "../domain/macho.js";
import { runRules, coverageBands, CoverageBand } from "../domain/rules.js";
import { DEFAULT_PARAMS, Finding, RuleParams, ResultKind } from "../domain/types.js";
import { digestOf, stableId } from "../domain/ids.js";
import { EventRow, Store } from "./store.js";

export interface FindingWithId extends Finding { id: string }

export interface ReviewSnapshot {
  eventId: string;
  materialId: string;
  paramVersion: string;
  resultKind: ResultKind;
  findings: FindingWithId[];
}

export interface DecisionRecord {
  eventId: string; seq: number; branch: string;
  findingId: string; action: "accept" | "reject" | "adjust";
  note: string; paramVersion: string;
}

export interface TimelineEntry {
  seq: number; id: string; branch: string; kind: string; summary: string;
}

export interface ReviewState {
  seq: number;
  headSeq: number;
  params: RuleParams;
  materials: { id: string; name: string; lineage: string; digest: string; importedSeq: number }[];
  currentMaterialId: string | null;
  model: FatModel | null;
  review: ReviewSnapshot | null;
  bands: CoverageBand[];
  decisions: DecisionRecord[];
  timeline: TimelineEntry[];
  branches: string[];
  counterexamples: CounterexampleRecord[];
}

export interface CounterexampleRecord {
  eventId: string; seq: number; name: string; source: string;
  expectRule: string; expectStatus: string; adopted: boolean;
  impactContained: boolean; firedRules: string[];
}

function withFindingIds(findings: Finding[]): FindingWithId[] {
  return findings.map((f) => ({
    ...f,
    id: stableId("finding", f.ruleId, f.status, f.affected,
      f.evidence.map((e) => [e.objectId, e.offset.raw, e.bytesHex])),
  }));
}

export class ReviewSession {
  private params: RuleParams;

  constructor(private store: Store) {
    this.params = { ...DEFAULT_PARAMS };
    // 恢复最近一次的参数版本
    const lastParamEvent = [...this.store.events()].reverse().find((e) => e.kind === "param-revision");
    if (lastParamEvent) this.params = lastParamEvent.payload.params as RuleParams;
  }

  get currentParams(): RuleParams { return this.params; }

  importMachO(name: string, hex: string, lineage = "import"): { materialId: string; review: ReviewSnapshot } {
    const bytes = Buffer.from(hex, "hex");
    const digest = digestOf([hex]);
    const materialId = stableId("mat", name, digest);
    const model = parseFat(new Uint8Array(bytes));
    const importEvent = this.store.appendEvent("main", "import", {
      name, lineage, digest: model.fileDigest, fileLength: model.fileLength,
      diagnostics: model.diagnostics,
    }, model.fileDigest, this.params.version, []);
    this.store.addMaterial(
      { id: materialId, kind: "macho-fat", name, lineage, rawHex: hex, digest: model.fileDigest },
      importEvent.seq,
    );
    const review = this.runReview(materialId, model, new Uint8Array(bytes), [importEvent.id]);
    return { materialId, review };
  }

  private runReview(materialId: string, model: FatModel, bytes: Uint8Array, parents: string[]): ReviewSnapshot {
    const out = runRules(model, bytes, this.params);
    const findings = withFindingIds(out.findings);
    const event = this.store.appendEvent("main", "review", {
      materialId, resultKind: out.resultKind, findings,
    }, model.fileDigest, this.params.version, parents);
    return { eventId: event.id, materialId, paramVersion: this.params.version, resultKind: out.resultKind, findings };
  }

  reviseParams(next: RuleParams, note: string): void {
    const event = this.store.appendEvent("main", "param-revision", { params: next, note },
      digestOf([next]), next.version, []);
    this.params = { ...next };
    const current = this.currentMaterial();
    if (current) {
      const bytes = new Uint8Array(Buffer.from(current.rawHex, "hex"));
      this.runReview(current.id, parseFat(bytes), bytes, [event.id]);
    }
  }

  /** 只影响局部依赖的源数据改动：记录受影响对象清单 */
  sourceChange(name: string, hex: string, lineage: string): { materialId: string; changedObjects: string[] } {
    const before = this.currentMaterial();
    const beforeModel = before ? parseFat(new Uint8Array(Buffer.from(before.rawHex, "hex"))) : null;
    const { materialId, review } = this.importMachOLineage(name, hex, lineage);
    const afterMat = this.store.material(materialId)!;
    const afterModel = parseFat(new Uint8Array(Buffer.from(afterMat.rawHex, "hex")));
    const changedObjects: string[] = [];
    if (beforeModel) {
      const beforeIds = new Set(beforeModel.slices.flatMap((s) => [s.id, ...s.commands.map((c) => c.id)]));
      for (const s of afterModel.slices) {
        if (!beforeIds.has(s.id)) changedObjects.push(s.id);
        for (const c of s.commands) if (!beforeIds.has(c.id)) changedObjects.push(c.id);
      }
    }
    this.store.appendEvent("main", "source-change", {
      materialId, changedObjects, reviewEventId: review.eventId,
      note: "局部源数据改动，仅列出的对象身份发生变化",
    }, afterModel.fileDigest, this.params.version, []);
    return { materialId, changedObjects };
  }

  private importMachOLineage(name: string, hex: string, lineage: string) {
    return this.importMachO(name, hex, lineage);
  }

  decide(branch: string, findingId: string, action: "accept" | "reject" | "adjust", note: string): EventRow {
    return this.store.appendEvent(branch, "decision", { findingId, action, note },
      digestOf([findingId, action, note]), this.params.version, []);
  }

  recordCounterexample(rec: Omit<CounterexampleRecord, "eventId" | "seq">): void {
    this.store.appendEvent("main", "counterexample", rec,
      digestOf([rec.name, rec.source]), this.params.version, []);
  }

  private currentMaterial() {
    const state = this.materialsAt(this.store.headSeq());
    return state.length > 0 ? state[state.length - 1]! : null;
  }

  private materialsAt(seq: number) {
    return this.store.materials().filter((m) => m.importedSeq <= seq);
  }

  /** 折叠事件 ≤ seq：恢复当时的依赖版本与可见结论（不用最新计算覆盖历史） */
  stateAt(seq?: number): ReviewState {
    const head = this.store.headSeq();
    const at = seq ?? head;
    const events = this.store.events(at);
    let params = { ...DEFAULT_PARAMS };
    let review: ReviewSnapshot | null = null;
    let currentMaterialId: string | null = null;
    const decisions: DecisionRecord[] = [];
    const counterexamples: CounterexampleRecord[] = [];
    const timeline: TimelineEntry[] = [];
    const branches = new Set<string>();

    for (const e of events) {
      branches.add(e.branch);
      timeline.push({ seq: e.seq, id: e.id, branch: e.branch, kind: e.kind, summary: summarize(e) });
      if (e.kind === "param-revision") params = e.payload.params as RuleParams;
      if (e.kind === "import") currentMaterialId = this.materialsAt(e.seq).at(-1)?.id ?? currentMaterialId;
      if (e.kind === "source-change") currentMaterialId = e.payload.materialId as string;
      if (e.kind === "review") {
        review = {
          eventId: e.id,
          materialId: e.payload.materialId as string,
          paramVersion: e.paramVersion,
          resultKind: e.payload.resultKind as ResultKind,
          findings: e.payload.findings as FindingWithId[],
        };
      }
      if (e.kind === "decision") {
        decisions.push({
          eventId: e.id, seq: e.seq, branch: e.branch,
          findingId: e.payload.findingId as string,
          action: e.payload.action as DecisionRecord["action"],
          note: (e.payload.note as string) ?? "", paramVersion: e.paramVersion,
        });
      }
      if (e.kind === "counterexample") {
        counterexamples.push({
          eventId: e.id, seq: e.seq,
          name: e.payload.name as string, source: e.payload.source as string,
          expectRule: e.payload.expectRule as string, expectStatus: e.payload.expectStatus as string,
          adopted: e.payload.adopted as boolean, impactContained: e.payload.impactContained as boolean,
          firedRules: e.payload.firedRules as string[],
        });
      }
    }

    const materials = this.materialsAt(at).map((m) => ({
      id: m.id, name: m.name, lineage: m.lineage, digest: m.digest, importedSeq: m.importedSeq,
    }));
    if (!currentMaterialId && materials.length > 0) currentMaterialId = materials.at(-1)!.id;
    const matRow = currentMaterialId ? this.store.material(currentMaterialId) : null;
    let model: FatModel | null = null;
    let bands: CoverageBand[] = [];
    if (matRow) {
      const bytes = new Uint8Array(Buffer.from(matRow.rawHex, "hex"));
      model = parseFat(bytes);
      bands = coverageBands(model);
    }
    return {
      seq: at, headSeq: head, params, materials, currentMaterialId, model, review, bands,
      decisions, timeline, branches: [...branches].sort(), counterexamples,
    };
  }
}

function summarize(e: EventRow): string {
  const p = e.payload as Record<string, unknown>;
  switch (e.kind) {
    case "import": return `导入 ${p.name}（digest ${String(p.digest).slice(0, 12)}…）`;
    case "review": return `复核 ${p.resultKind}，${(p.findings as unknown[]).length} 条判定`;
    case "param-revision": return `参数修订 → ${e.paramVersion}：${p.note ?? ""}`;
    case "source-change": return `源数据改动，影响 ${(p.changedObjects as unknown[]).length} 个对象`;
    case "decision": return `[${e.branch}] ${p.action} ${String(p.findingId).slice(0, 18)}… ${p.note ?? ""}`;
    case "counterexample": return `反例 ${p.name}（${p.adopted ? "采纳" : "未采纳"}，影响${p.impactContained ? "已" : "未"}限制）`;
    default: return e.kind;
  }
}
