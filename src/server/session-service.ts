/**
 * 会话编排服务（服务端，可被测试直接调用）：
 * 导入材料 → 派生（解析+策略选择）→ 参数修订 → 源数据改动 → 人工决定 → 分支/时间旅行。
 * 每个派生结果携带 inputDigest / policyVersion / parentEventId；
 * 历史事件重放恢复“当时”的依赖版本与可见结论，不用最新结果覆盖历史。
 */

import { createHash } from "node:crypto";
import { parseContainer } from "../domain/parser.js";
import type {
  ArchPolicy, DecisionValue, DerivationResult,
  ParseResult, SessionEvent,
} from "../domain/model.js";
import { SessionStore, type EventRow, type MaterialRow } from "./store.js";

export const DEFAULT_POLICY: ArchPolicy = {
  id: "policy-target-arch",
  version: 1,
  preferredCpuType: 0x0100000c, // arm64
  preferredCpuSubtype: 0,
  unknownBlobIsError: false,
  scanBudgetBytes: 2_000_000,
};

export function digestBase64(base64: string): string {
  return createHash("sha256").update(Buffer.from(base64, "base64")).digest("hex");
}

interface PolicyAt {
  policy: ArchPolicy;
  policyEventId: string | null;
}

function policyAt(events: EventRow[]): PolicyAt {
  let policy = { ...DEFAULT_POLICY };
  let policyEventId: string | null = null;
  for (const e of events) {
    if (e.type === "session-created") {
      policy = { ...DEFAULT_POLICY };
      policyEventId = e.id;
    } else if (e.type === "parameter-revised") {
      const p = JSON.parse(e.payload) as Partial<ArchPolicy> & { version?: number };
      policy = { ...policy, ...p, version: p.version ?? policy.version + 1 };
      policyEventId = e.id;
    }
  }
  return { policy, policyEventId };
}

/** 选择目标架构：匹配候选全部保留，无法唯一决定不自动选择。 */
function selectArch(parse: ParseResult, policy: ArchPolicy): DerivationResult["selection"] {
  const candidates = parse.slices.filter(
    (s) =>
      s.descriptor.cputype === policy.preferredCpuType &&
      (policy.preferredCpuSubtype === 0 || s.descriptor.cpusubtype === policy.preferredCpuSubtype),
  );
  const noDup = !parse.findings.some(
    (f) => f.code === "ARCH_DUPLICATE" && candidates.some((c) => f.affected.includes(c.id)),
  );
  if (candidates.length === 1) {
    return { matchedSliceId: candidates[0]!.id, candidates: candidates.map((c) => c.id), decided: true, reason: "唯一策略匹配" };
  }
  if (candidates.length > 1 && noDup) {
    return { matchedSliceId: null, candidates: candidates.map((c) => c.id), decided: false, reason: "多个子类型匹配，保留候选" };
  }
  if (candidates.length > 1) {
    return { matchedSliceId: null, candidates: candidates.map((c) => c.id), decided: false, reason: "多架构同名（ARCH_DUPLICATE），无法唯一决定，全部合法候选保留" };
  }
  return { matchedSliceId: null, candidates: [], decided: false, reason: "无匹配目标架构" };
}

export interface ComputedView {
  /** 当前事件时刻所依据的材料 */
  material: MaterialRow | null;
  derivation: DerivationResult | null;
  /** 截止时刻事件链（机器可读判断依据） */
  events: SessionEvent[];
  decision: { value: DecisionValue; target: string; note: string } | null;
  policy: ArchPolicy;
}

function toSessionEvent(e: EventRow): SessionEvent {
  return {
    id: e.id,
    sessionId: e.session_id,
    branchId: e.branch_id,
    seq: e.seq,
    type: e.type as SessionEvent["type"],
    at: e.at,
    payload: JSON.parse(e.payload),
    inputDigest: e.input_digest ?? undefined,
    policyVersion: e.policy_version ?? undefined,
    parentEventId: e.parent_event_id,
  };
}

export class SessionService {
  constructor(readonly store: SessionStore) {}

  createSession(title: string) {
    return this.store.createSession(title);
  }

  importMaterial(input: {
    sessionId: string;
    branchId?: string;
    kind: string;
    bytes: Buffer;
    sourceLabel: string;
    basis: Record<string, unknown>;
    supersedes?: string | null;
  }): { material: MaterialRow; event: EventRow } {
    const base64 = input.bytes.toString("base64");
    const inputDigest = digestBase64(base64);
    return this.store.addMaterial({
      sessionId: input.sessionId,
      branchId: input.branchId,
      kind: input.kind,
      rawBase64: base64,
      sourceLabel: input.sourceLabel,
      basis: JSON.stringify({ unit: "byte", ...input.basis }),
      inputDigest,
      supersedes: input.supersedes ?? null,
    });
  }

  /** 派生：从分支上最新材料计算，记录输入摘要/参数版本/父依赖。 */
  derive(sessionId: string, branchId = "main"): DerivationResult {
    const events = this.store.listEvents(sessionId, branchId);
    const materials = this.store.listMaterials(sessionId).filter((m) => m.branch_id === branchId);
    const material = materials[materials.length - 1] ?? null;
    const parentEvent = events[events.length - 1] ?? null;
    const { policy } = policyAt(events);

    if (!material) {
      throw new Error("输入不完整：分支上不存在材料，无法派生（禁止用默认值伪装成功）");
    }
    const bytes = Buffer.from(material.raw_base64, "base64");
    const parse = parseContainer(bytes, {
      scanBudgetBytes: policy.scanBudgetBytes,
      unknownBlobIsError: policy.unknownBlobIsError,
    });
    const selection = selectArch(parse, policy);
    const derived: DerivationResult = {
      id: `der_${material.id}_v${policy.version}`,
      parentEventId: parentEvent?.id ?? null,
      inputDigest: material.input_digest,
      policyVersion: policy.version,
      computedAt: new Date().toISOString(),
      parse,
      selection,
      findings: parse.findings,
      resultClass: parse.resultClass,
    };
    this.store.withTransaction("derive", (commit) => {
      this.store.insertEvent({
        sessionId, branchId, type: "derivation-computed",
        payload: {
          derivationId: derived.id,
          resultClass: derived.resultClass,
          materialId: material.id,
          findingCodes: parse.findings.map((f) => ({
            id: f.id, code: f.code, severity: f.severity, affected: f.affected,
            location: f.location ?? null, evidence: f.evidence ?? null,
          })),
          selection,
          sliceIds: parse.slices.map((s) => s.id),
        },
        inputDigest: material.input_digest,
        policyVersion: policy.version,
        parentEventId: parentEvent?.id ?? null,
      });
      commit("");
    });
    return derived;
  }

  revisePolicy(sessionId: string, changes: Partial<ArchPolicy>, branchId = "main"): EventRow {
    const events = this.store.listEvents(sessionId, branchId);
    const { policy } = policyAt(events);
    const parent = events[events.length - 1] ?? null;
    const next: ArchPolicy = { ...policy, ...changes, version: policy.version + 1 };
    let row!: EventRow;
    this.store.withTransaction("revise-policy", (commit) => {
      row = this.store.insertEvent({
        sessionId, branchId, type: "parameter-revised",
        payload: { from: stripPolicy(policy), to: stripPolicy(next), changes },
        policyVersion: next.version,
        parentEventId: parent?.id ?? null,
      });
      commit("");
    });
    return row;
  }

  /** 局部源数据改动：导入新材料（不可变），以 supersedes 指向上一版，再派生。 */
  amendSource(input: {
    sessionId: string;
    branchId?: string;
    bytes: Buffer;
    sourceLabel: string;
    basis: Record<string, unknown>;
  }): { material: MaterialRow; event: EventRow; derivation: DerivationResult } {
    const branchId = input.branchId ?? "main";
    const previous = this.store
      .listMaterials(input.sessionId)
      .filter((m) => m.branch_id === branchId)
      .at(-1);
    const imported = this.importMaterial({
      sessionId: input.sessionId,
      branchId,
      kind: "macho-fat-amendment",
      bytes: input.bytes,
      sourceLabel: input.sourceLabel,
      basis: input.basis,
      supersedes: previous?.id ?? null,
    });
    const derivation = this.derive(input.sessionId, branchId);
    return { material: imported.material, event: imported.event, derivation };
  }

  decide(input: {
    sessionId: string;
    branchId?: string;
    value: DecisionValue;
    target: string;
    note: string;
  }): EventRow {
    const branchId = input.branchId ?? "main";
    const events = this.store.listEvents(input.sessionId, branchId);
    const parent = events[events.length - 1] ?? null;
    const { policy } = policyAt(events);
    let row!: EventRow;
    this.store.withTransaction("decision", (commit) => {
      row = this.store.insertEvent({
        sessionId: input.sessionId, branchId,
        type: "decision",
        payload: { value: input.value, target: input.target, note: input.note },
        policyVersion: policy.version,
        parentEventId: parent?.id ?? null,
      });
      commit("");
    });
    return row;
  }

  /** 从源分支某事件点拉出分支；分叉点之后的事件不复制。 */
  branch(sessionId: string, newBranchId: string, fromSeq?: number): EventRow {
    const sourceEvents = this.store.listEvents(sessionId, "main");
    const cutoff = fromSeq ?? sourceEvents[sourceEvents.length - 1]?.seq ?? 0;
    const kept = sourceEvents.filter((e) => e.seq <= cutoff);
    const parent = kept[kept.length - 1] ?? null;
    let row!: EventRow;
    this.store.withTransaction("branch", (commit) => {
      // 复制分叉点前材料归属到新分支（材料不可变，保留原 id，不复制行：视图按链回溯）
      row = this.store.insertEvent({
        sessionId, branchId: newBranchId, seq: 0,
        type: "branch-created",
        payload: { fromBranch: "main", fromSeq: cutoff },
        parentEventId: parent?.id ?? null,
      });
      commit("");
    });
    return row;
  }

  /** 时间旅行：回到分支上 seq 时刻，依据当时材料/策略重放，得到当时可见结论。 */
  viewAt(sessionId: string, seq: number, branchId = "main"): ComputedView {
    const events = this.store
      .listAllEvents(sessionId)
      .filter((e) => e.branch_id === branchId || (branchId !== "main" && e.type === "session-created"))
      .filter((e) => e.seq <= seq)
      .sort((a, b) => a.seq - b.seq || (a.branch_id === branchId ? -1 : 1));
    const { policy } = policyAt(events);
    let material: MaterialRow | null = null;
    let derivation: DerivationResult | null = null;
    let decision: ComputedView["decision"] = null;
    for (const e of events) {
      if (e.type === "material-imported") {
        const p = JSON.parse(e.payload) as { materialId: string };
        material = this.store.getMaterial(p.materialId);
      } else if (e.type === "derivation-computed") {
        const p = JSON.parse(e.payload) as {
          materialId: string;
          derivationId: string;
          resultClass: DerivationResult["resultClass"];
          selection: DerivationResult["selection"];
        };
        const mat = this.store.getMaterial(p.materialId);
        if (mat) {
          const bytes = Buffer.from(mat.raw_base64, "base64");
          const parse = parseContainer(bytes, {
            scanBudgetBytes: policy.scanBudgetBytes,
            unknownBlobIsError: policy.unknownBlobIsError,
          });
          derivation = {
            id: p.derivationId ?? "",
            parentEventId: e.parent_event_id,
            inputDigest: e.input_digest ?? mat.input_digest,
            policyVersion: e.policy_version ?? 1,
            computedAt: e.at,
            parse,
            selection: p.selection ?? selectArchPublic(parse, policy),
            findings: parse.findings,
            resultClass: (p.resultClass as DerivationResult["resultClass"]) ?? parse.resultClass,
          };
        }
      } else if (e.type === "decision") {
        const p = JSON.parse(e.payload) as { value: DecisionValue; target: string; note: string };
        decision = p;
      }
    }
    return { material, derivation, events: events.map(toSessionEvent), decision, policy };
  }

  currentView(sessionId: string, branchId = "main"): ComputedView {
    const max = this.store.listEvents(sessionId, branchId).at(-1)?.seq ?? 0;
    return this.viewAt(sessionId, max, branchId);
  }
}

function selectArchPublic(parse: ParseResult, policy: ArchPolicy) {
  const candidates = parse.slices.filter(
    (s) =>
      s.descriptor.cputype === policy.preferredCpuType &&
      (policy.preferredCpuSubtype === 0 || s.descriptor.cpusubtype === policy.preferredCpuSubtype),
  );
  return {
    matchedSliceId: candidates.length === 1 ? candidates[0]!.id : null,
    candidates: candidates.map((c) => c.id),
    decided: candidates.length === 1,
    reason: candidates.length === 1 ? "唯一策略匹配" : "无法唯一决定，候选保留",
  };
}

function stripPolicy(p: ArchPolicy): Record<string, unknown> {
  return { ...p };
}
