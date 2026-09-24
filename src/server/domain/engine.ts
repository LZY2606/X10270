// 事件溯源引擎：所有输入/计算/决定都是不可变事件；投影按事件序列重建。
// 回到任意旧事件 = 在该 seq 上做投影，不会用最新结果覆盖历史。
import { contentId, canonical, sha256Hex } from '../../shared/id.js';
import type {
  AnalysisRun, Decision, DomainEvent, EventType, Finding,
  Material, ParamVersion,
} from '../../shared/types.js';
import { analyze, DEFAULT_RULES } from './rules.js';

export interface ProjectMeta { projectId: string; name: string; createdAt: string }

export interface State {
  meta: ProjectMeta;
  events: DomainEvent[];
  materials: Map<string, Material>;
  paramVersions: Map<string, ParamVersion>;
  runs: Map<string, AnalysisRun>;
  branchHeads: Map<string, number>; // branch -> head seq
  branchParents: Map<string, { parent: string; parentSeq: number }>;
  cursor: Map<string, number>; // branch -> TIMELINE_CHECKOUT 指向的 seq
}

export function emptyState(meta: ProjectMeta): State {
  return {
    meta,
    events: [],
    materials: new Map(),
    paramVersions: new Map(),
    runs: new Map(),
    branchHeads: new Map([['main', 0]]),
    branchParents: new Map([['main', { parent: 'main', parentSeq: 0 }]]),
    cursor: new Map(),
  };
}

function evtId(type: EventType, branch: string, seq: number, payload: unknown): string {
  return contentId('evt', { type, branch, seq, payload });
}

export function makeEvent(state: State, branch: string, type: EventType, payload: Record<string, unknown>, at?: string): DomainEvent {
  const head = state.branchHeads.get(branch) ?? branchEventSeqs(state, branch).length;
  const seq = (state.events.reduce((m, e) => Math.max(m, e.seq), 0)) + 1;
  const ev: DomainEvent = {
    eventId: evtId(type, branch, seq, payload),
    seq,
    branch,
    at: at ?? new Date(0).toISOString(),
    type,
    payload,
  };
  void head;
  return ev;
}

function append(state: State, evs: DomainEvent[]): void {
  for (const ev of evs) {
    state.events.push(ev);
    state.branchHeads.set(ev.branch, ev.seq);
    switch (ev.type) {
      case 'MATERIAL_IMPORTED':
        state.materials.set((ev.payload.material as Material).materialId, ev.payload.material as Material);
        break;
      case 'PARAMS_SET':
        state.paramVersions.set((ev.payload.params as ParamVersion).paramVersionId, ev.payload.params as ParamVersion);
        break;
      case 'ANALYSIS_RUN_RECORDED':
        state.runs.set((ev.payload.run as AnalysisRun).runId, ev.payload.run as AnalysisRun);
        break;
      case 'BRANCH_CREATED':
        state.branchHeads.set(ev.payload.name as string, ev.seq);
        state.branchParents.set(ev.payload.name as string, { parent: ev.payload.parent as string, parentSeq: ev.payload.parentSeq as number });
        break;
      case 'TIMELINE_CHECKOUT':
        state.cursor.set(ev.branch, ev.payload.seq as number);
        break;
    }
  }
}

export function replay(events: DomainEvent[], meta: ProjectMeta): State {
  const state = emptyState(meta);
  const ordered = [...events].sort((a, b) => a.seq - b.seq);
  append(state, ordered);
  return state;
}

export function branchEventSeqs(state: State, branch: string): DomainEvent[] {
  if (!state.branchParents.has(branch)) return [];
  const { parent, parentSeq } = state.branchParents.get(branch)!;
  const parentEvs = branch === parent ? [] : branchEventSeqs(state, parent).filter((e) => e.seq <= parentSeq);
  const own = state.events.filter((e) => e.branch === branch);
  return [...parentEvs, ...own].sort((a, b) => a.seq - b.seq);
}

export class ProjectEngine {
  state: State;
  constructor(state: State) { this.state = state; }

  events(branch = 'main'): DomainEvent[] { return branchEventSeqs(this.state, branch); }

  currentParams(branch = 'main'): ParamVersion {
    const evs = this.events(branch);
    let cur: ParamVersion | null = null;
    for (const e of evs) if (e.type === 'PARAMS_SET') cur = e.payload.params as ParamVersion;
    if (cur) return cur;
    const seed: ParamVersion = {
      paramVersionId: contentId('params', { version: 1, rules: DEFAULT_RULES }),
      version: 1, rules: { ...DEFAULT_RULES }, createdAtSeq: 0, note: '初始规则',
    };
    return seed;
  }

  importMaterial(input: { kind: Material['kind']; name: string; bytes?: Buffer; text?: string; provenance?: Material['provenance']; at?: string }): DomainEvent[] {
    const branch = 'main';
    const data = input.bytes ?? (input.text !== undefined ? Buffer.from(input.text, 'utf8') : Buffer.alloc(0));
    const sha = sha256Hex(data);
    const existing = [...this.state.materials.values()].find((m) => m.sha256 === sha && m.kind === input.kind);
    if (existing) return []; // 等价输入幂等：不产生新事件
    const seq = this.state.events.length + 1;
    const material: Material = {
      materialId: contentId('mat', { kind: input.kind, sha256: sha, name: input.name }),
      kind: input.kind,
      name: input.name,
      byteSize: data.length,
      sha256: sha,
      importedAtSeq: seq,
      ...(input.bytes ? { rawBase64: data.toString('base64') } : { rawText: input.text ?? '' }),
      ...(input.provenance ? { provenance: input.provenance } : {}),
    };
    const ev = makeEvent(this.state, branch, 'MATERIAL_IMPORTED', { material }, input.at);
    append(this.state, [ev]);
    return [ev];
  }

  setParams(patch: Partial<ParamVersion['rules']>, note: string, at?: string): DomainEvent[] {
    const branch = 'main';
    const base = this.currentParams(branch);
    const rules = { ...base.rules, ...patch };
    const version = base.version + 1;
    const params: ParamVersion = {
      paramVersionId: contentId('params', { version, rules }),
      version,
      rules,
      createdAtSeq: this.state.events.length + 1,
      note,
    };
    if (params.paramVersionId === base.paramVersionId) return [];
    const ev = makeEvent(this.state, branch, 'PARAMS_SET', { params }, at);
    append(this.state, [ev]);
    return [ev];
  }

  runAnalysis(materialId: string, at?: string, branch = 'main'): DomainEvent[] {
    const material = this.state.materials.get(materialId);
    if (!material) throw new Error('material 不存在: ' + materialId);
    const params = this.currentParams(branch);
    const seq = this.state.events.length + 1;
    const parentRunIds = this.events(branch)
      .filter((e) => e.type === 'ANALYSIS_RUN_RECORDED')
      .map((e) => (e.payload.run as AnalysisRun).runId);
    const bytes = material.kind === 'universal-binary'
      ? Buffer.from(material.rawBase64 ?? '', 'base64')
      : Buffer.alloc(0);
    const run = analyze(bytes, materialId, params, parentRunIds, seq);
    if (this.state.runs.has(run.runId)) return []; // 等价输入+参数 => 幂等
    const evs: DomainEvent[] = [];
    const runEv = makeEvent(this.state, branch, 'ANALYSIS_RUN_RECORDED', {
      run: stripDocument(run), inputDigest: run.inputDigest, paramVersionId: run.paramVersionId,
    }, at);
    evs.push(runEv);
    append(this.state, evs);
    return evs;
  }

  makeDecision(findingId: string, action: Decision['action'], rationale: string, opts?: { params?: Record<string, unknown>; at?: string }): DomainEvent[] {
    const branch = 'main';
    const prior = this.findingsMap(branch);
    const finding = prior.get(findingId);
    if (!finding) throw new Error('finding 不存在: ' + findingId);
    const decision: Decision = {
      decisionId: contentId('dec', { findingId, action, rationale, atSeq: this.state.events.length + 1 }),
      findingId, action, rationale, atSeq: this.state.events.length + 1,
      ...(opts?.params ? { params: opts.params } : {}),
    };
    const evs = [makeEvent(this.state, branch, 'DECISION_MADE', { decision }, opts?.at)];
    // 互相冲突的人工决定：同一 finding 上 accept 与 reject 并存 => SEM-01，保留全部候选
    const history = this.decisionsFor(findingId).concat(decision);
    const accepts = history.filter((d) => d.action === 'accept');
    const rejects = history.filter((d) => d.action === 'reject');
    if (accepts.length > 0 && rejects.length > 0) {
      const conflict: Finding = {
        findingId: contentId('find', { sem: 'SEM-01', findingId, n: history.length }),
        ruleId: 'SEM-01',
        category: 'semantic',
        severity: 'violation',
        status: 'open',
        message: `finding ${findingId} 存在互相冲突的人工决定（accept ×${accepts.length} / reject ×${rejects.length}），语义无解，保留全部合法候选`,
        subjects: [findingId],
        evidence: [],
        candidates: history.map((d) => ({ label: d.action, detail: `${d.decisionId}: ${d.rationale}` })),
        params: { paramVersionId: finding.params.paramVersionId },
      };
      evs.push(makeEvent(this.state, branch, 'FINDING_RAISED', { finding: conflict, subjectFindingId: findingId }, opts?.at));
    }
    append(this.state, evs);
    return evs;
  }

  createBranch(name: string, at?: string): DomainEvent[] {
    if (this.state.branchParents.has(name)) return [];
    const parentSeq = this.state.events.reduce((m, e) => Math.max(m, e.seq), 0);
    const ev = makeEvent(this.state, 'main', 'BRANCH_CREATED', { name, parent: 'main', parentSeq }, at);
    append(this.state, [ev]);
    return [ev];
  }

  checkout(branch: string, seq: number, at?: string): DomainEvent[] {
    const ev = makeEvent(this.state, branch, 'TIMELINE_CHECKOUT', { seq }, at);
    append(this.state, [ev]);
    return [ev];
  }

  decisionsFor(findingId: string): Decision[] {
    return this.state.events
      .filter((e) => e.type === 'DECISION_MADE' && (e.payload.decision as Decision).findingId === findingId)
      .map((e) => e.payload.decision as Decision);
  }

  findingsMap(branch: string): Map<string, Finding> {
    const m = new Map<string, Finding>();
    for (const e of this.events(branch)) {
      if (e.type === 'ANALYSIS_RUN_RECORDED') {
        for (const f of (e.payload.run as AnalysisRun).findings) m.set(f.findingId, f);
      }
      if (e.type === 'FINDING_RAISED') {
        const f = e.payload.finding as Finding;
        m.set(f.findingId, f);
      }
    }
    return m;
  }
}

function stripDocument(run: AnalysisRun): AnalysisRun {
  // 文档派生量较大：事件里保存运行骨架与 findings，文档在投影时由材料重新派生。
  return { ...run, document: null };
}

export function canonicalEvents(events: DomainEvent[]): string {
  return sha256Hex(canonical(events.map((e) => ({ eventId: e.eventId, seq: e.seq, type: e.type, branch: e.branch }))));
}
