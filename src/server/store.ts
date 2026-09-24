// SQLite 事件存储：不可变材料 + 可修改决定分层。
// 所有多表写入均在事务内完成；崩溃/截断导入不会留下半写状态。
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { parseFat, sha256, DEFAULT_BUDGET, type ParseBudget } from './macho.js';
import { buildMaterials, type KeyedMaterial } from './materials.js';
import { evaluate, DEFAULT_PARAMS, RULE_VERSION, type RuleParams } from './rules.js';
import type {
  Archive, DomainEvent, Finding, Material, ReviewState, RunOutcome, Diagnostic,
} from '../shared/types.js';

export interface StoreOptions {
  dbPath: string;
  budget?: ParseBudget;
}

interface AppendInput {
  branch: string;
  type: DomainEvent['type'];
  paramVersion: number;
  payload: Record<string, unknown>;
  parents: string[];
  ruleVersion?: string;
}

export class Store {
  db: DatabaseSync;
  budget: ParseBudget;

  constructor(opts: StoreOptions) {
    if (opts.dbPath !== ':memory:') mkdirSync(dirname(opts.dbPath), { recursive: true });
    this.db = new DatabaseSync(opts.dbPath);
    this.db.exec('PRAGMA journal_mode=WAL');
    this.budget = opts.budget ?? DEFAULT_BUDGET;
    this.migrate();
  }

  close() {
    try { this.db.close(); } catch { /* already closed */ }
  }

  private migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
      CREATE TABLE IF NOT EXISTS events(
        id TEXT PRIMARY KEY, seq INTEGER UNIQUE, branch TEXT NOT NULL, type TEXT NOT NULL,
        rule_version TEXT NOT NULL, param_version INTEGER NOT NULL,
        parents TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS materials(
        id TEXT NOT NULL, key TEXT NOT NULL, kind TEXT NOT NULL,
        slice_id TEXT, name TEXT NOT NULL, raw TEXT NOT NULL,
        meta TEXT NOT NULL, digest TEXT NOT NULL, seq INTEGER NOT NULL,
        PRIMARY KEY(id, seq)
      );
      CREATE TABLE IF NOT EXISTS branches(name TEXT PRIMARY KEY, head TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS idx_mat_key_seq ON materials(key, seq);
      CREATE INDEX IF NOT EXISTS idx_ev_branch ON events(branch, seq);
    `);
  }

  private nowIso() { return new Date().toISOString(); }

  private nextSeq(): number {
    const row = this.db.prepare('SELECT COALESCE(MAX(seq),0) AS m FROM events').get() as { m: number };
    return row.m + 1;
  }

  private appendEventTx(input: AppendInput): DomainEvent {
    const seq = this.nextSeq();
    const ev: DomainEvent = {
      id: `evt:${seq}`,
      seq,
      branch: input.branch,
      type: input.type,
      ruleVersion: input.ruleVersion ?? RULE_VERSION,
      paramVersion: input.paramVersion,
      parents: input.parents,
      payload: input.payload,
      createdAt: this.nowIso(),
    };
    this.db.prepare(
      `INSERT INTO events(id,seq,branch,type,rule_version,param_version,parents,payload,created_at)
       VALUES(?,?,?,?,?,?,?,?,?)`,
    ).run(
      ev.id, ev.seq, ev.branch, ev.type, ev.ruleVersion, ev.paramVersion,
      JSON.stringify(ev.parents), JSON.stringify(ev.payload), ev.createdAt,
    );
    this.db.prepare('INSERT OR REPLACE INTO branches(name,head) VALUES(?,?)').run(
      input.branch, ev.id,
    );
    return ev;
  }

  private insertMaterial(m: KeyedMaterial, seq: number) {
    // INSERT OR IGNORE：同一内容材料跨修订共享同一身份
    this.db.prepare(
      `INSERT OR IGNORE INTO materials(id,key,kind,slice_id,name,raw,meta,digest,seq)
       VALUES(?,?,?,?,?,?,?,?,?)`,
    ).run(
      m.id, m.key, m.kind, m.sliceId ?? null, m.name, m.rawB64,
      JSON.stringify(m.meta), m.digest, seq,
    );
  }

  private headOf(branch: string): string | undefined {
    const row = this.db.prepare('SELECT head FROM branches WHERE name=?').get(branch) as
      | { head: string } | undefined;
    return row?.head;
  }

  /** 运行规则并追加 rule_run 事件（调用方需在事务中）。 */
  private runRulesTx(
    parsed: NonNullable<ReturnType<typeof parseFat>['parsed']>,
    keyed: { materials: KeyedMaterial[]; idByKey: Record<string, string> },
    params: RuleParams,
    branch: string,
    paramVersion: number,
    parents: string[],
    inputDigest: string,
    parseOutcome: RunOutcome,
    diagnostics: Diagnostic[],
  ): DomainEvent {
    let outcome: RunOutcome = parseOutcome;
    let status = 'ok';
    let findings: Finding[] = [];
    if (parseOutcome === 'ok') {
      const run = evaluate(parsed, keyed.idByKey, params);
      status = run.status;
      findings = run.findings;
      if (findings.some((x) => x.rule === 'arch.policy' && x.status === 'violation')) {
        outcome = 'semantic_unsolvable';
      }
    }
    return this.appendEventTx({
      branch,
      type: 'rule_run',
      paramVersion,
      parents,
      payload: {
        inputDigest,
        ruleVersion: RULE_VERSION,
        outcome,
        status,
        diagnostics,
        findings,
      },
    });
  }

  private paramsAt(seq: number): { version: number; params: RuleParams } {
    const rows = this.db
      .prepare('SELECT param_version, payload FROM events WHERE type=? AND seq<=? ORDER BY seq')
      .all('param_revision', seq) as { param_version: number; payload: string }[];
    let params: RuleParams = { ...DEFAULT_PARAMS };
    let version = 1;
    for (const r of rows) {
      const p = JSON.parse(r.payload) as { delta: Partial<RuleParams> };
      params = { ...params, ...p.delta };
      version = r.param_version;
    }
    const first = this.db.prepare('SELECT MIN(seq) AS m FROM events').get() as { m: number | null };
    if (first.m === null) version = 1;
    else if (rows.length === 0) {
      const ir = this.db
        .prepare('SELECT param_version FROM events WHERE seq<=? ORDER BY seq DESC LIMIT 1')
        .get(seq) as { param_version: number } | undefined;
      version = ir?.param_version ?? 1;
    }
    return { version, params };
  }

  private lastRuleRun(seq: number): DomainEvent | undefined {
    const row = this.db
      .prepare("SELECT * FROM events WHERE type='rule_run' AND seq<=? ORDER BY seq DESC LIMIT 1")
      .get(seq) as Record<string, string | number> | undefined;
    return row ? rowToEvent(row) : undefined;
  }

  /** 导入 universal Mach-O：一次事务写入 import + 材料 + rule_run。 */
  importFile(input: {
    branch?: string; name: string; bytes: Uint8Array; scenarioId?: string;
    params?: RuleParams;
  }): { ok: true; event: DomainEvent } | { ok: false; code: string; message: string } {
    const branch = input.branch ?? 'main';
    try {
      const result = this.db.exec('BEGIN');
      void result;
      const res = parseFat(input.bytes, this.budget);
      const pv = this.paramsAt(this.nextSeq() - 1);
      const params = input.params ?? pv.params;
      const paramVersion = pv.version;
      const importEv = this.appendEventTx({
        branch,
        type: 'import',
        paramVersion,
        parents: this.headOf(branch) ? [this.headOf(branch)!] : [],
        payload: {
          name: input.name,
          scenarioId: input.scenarioId ?? null,
          fileSizeBytes: input.bytes.length,
          digest: sha256(input.bytes),
          endianness: res.parsed?.endianness ?? null,
          nfatArch: res.parsed?.slices.length ?? null,
          params,
          basis: 'file',
          unit: 'byte',
        },
      });
      let keyed: { materials: KeyedMaterial[]; idByKey: Record<string, string> } = {
        materials: [],
        idByKey: {},
      };
      if (res.parsed) {
        keyed = buildMaterials(res.parsed);
        for (const m of keyed.materials) this.insertMaterial(m, importEv.seq);
      }
      this.runRulesTx(
        res.parsed ?? (null as never),
        keyed,
        params,
        branch,
        paramVersion,
        [importEv.id],
        sha256(input.bytes),
        res.outcome,
        res.diagnostics as Diagnostic[],
      );
      this.db.exec('COMMIT');
      return { ok: true, event: importEv };
    } catch (err) {
      try { this.db.exec('ROLLBACK'); } catch { /* no transaction */ }
      return { ok: false, code: 'import.failed', message: (err as Error).message };
    }
  }

  private paramDeltaCount(): number {
    return (
      this.db.prepare("SELECT COUNT(*) AS c FROM events WHERE type='param_revision'").get() as {
        c: number;
      }
    ).c;
  }

  /** 参数修订：派生层重新核验，材料字节不动。 */
  reviseParams(branch: string, delta: Partial<RuleParams>, note: string): DomainEvent {
    this.db.exec('BEGIN');
    try {
      const pv = this.paramsAt(this.nextSeq() - 1);
      const nextVersion = pv.version + 1;
      const ev = this.appendEventTx({
        branch,
        type: 'param_revision',
        paramVersion: nextVersion,
        parents: [this.headOf(branch)!],
        payload: { delta, note, fromVersion: pv.version, toVersion: nextVersion },
      });
      const latestImport = this.latestInput(branch);
      if (latestImport) {
        const res = parseFat(latestImport.bytes, this.budget);
        if (res.parsed) {
          const keyed = buildMaterials(res.parsed);
          for (const m of keyed.materials) this.insertMaterial(m, ev.seq);
          this.runRulesTx(
            res.parsed,
            keyed,
            { ...pv.params, ...delta },
            branch,
            nextVersion,
            [ev.id],
            latestImport.digest,
            res.outcome,
            res.diagnostics as Diagnostic[],
          );
        }
      }
      this.db.exec('COMMIT');
      return ev;
    } catch (err) {
      try { this.db.exec('ROLLBACK'); } catch { /* noop */ }
      throw err;
    }
  }

  private latestInput(branch: string): { bytes: Uint8Array; digest: string } | undefined {
    const row = this.db
      .prepare(
        `SELECT payload FROM events
         WHERE type IN ('import','source_amendment') AND branch=?
         ORDER BY seq DESC LIMIT 1`,
      )
      .get(branch) as { payload: string } | undefined;
    if (!row) return undefined;
    const payload = JSON.parse(row.payload) as { digest: string };
    const mat = this.db
      .prepare('SELECT raw FROM materials WHERE key=? ORDER BY seq DESC LIMIT 1')
      .get('file_digest') as { raw: string } | undefined;
    if (!mat) return undefined;
    return { bytes: Buffer.from(mat.raw, 'base64'), digest: payload.digest };
  }

  /** 局部源数据改动：只替换一个直接来源（单个 slice 重建后的整文件），
   *  未变化的内容材料身份保持不变。 */
  amendSource(branch: string, input: {
    bytes: Uint8Array; changedSlice: string; note: string;
  }): DomainEvent {
    this.db.exec('BEGIN');
    try {
      const pv = this.paramsAt(this.nextSeq() - 1);
      const res = parseFat(input.bytes, this.budget);
      const digest = sha256(input.bytes);
      const ev = this.appendEventTx({
        branch,
        type: 'source_amendment',
        paramVersion: pv.version,
        parents: [this.headOf(branch)!],
        payload: {
          note: input.note,
          changedSlice: input.changedSlice,
          digest,
          fileSizeBytes: input.bytes.length,
          impactScope: [input.changedSlice],
        },
      });
      if (res.parsed) {
        const keyed = buildMaterials(res.parsed);
        for (const m of keyed.materials) this.insertMaterial(m, ev.seq);
        this.runRulesTx(
          res.parsed,
          keyed,
          pv.params,
          branch,
          pv.version,
          [ev.id],
          digest,
          res.outcome,
          res.diagnostics as Diagnostic[],
        );
      } else {
        this.runRulesTx(
          null as never,
          { materials: [], idByKey: {} },
          pv.params,
          branch,
          pv.version,
          [ev.id],
          digest,
          res.outcome,
          res.diagnostics as Diagnostic[],
        );
      }
      this.db.exec('COMMIT');
      return ev;
    } catch (err) {
      try { this.db.exec('ROLLBACK'); } catch { /* noop */ }
      throw err;
    }
  }

  /** 人工决定：接受 / 否定 / 参数调整建议。冲突决定以不同分支保存，不互相覆盖。 */
  decide(branch: string, input: {
    findingId: string; decision: 'accept' | 'reject' | 'adjust'; note: string;
  }): DomainEvent {
    const head = this.headOf(branch);
    if (!head) throw new Error(`分支 ${branch} 不存在`);
    this.db.exec('BEGIN');
    try {
      const pv = this.paramsAt(this.nextSeq() - 1);
      const ev = this.appendEventTx({
        branch,
        type: 'decision',
        paramVersion: pv.version,
        parents: [head],
        payload: input,
      });
      this.db.exec('COMMIT');
      return ev;
    } catch (err) {
      try { this.db.exec('ROLLBACK'); } catch { /* noop */ }
      throw err;
    }
  }

  /** 从父分支创建分支，用于保存互相冲突的人工决定。 */
  forkBranch(name: string, fromBranch: string): void {
    const head = this.headOf(fromBranch);
    if (!head) throw new Error(`分支 ${fromBranch} 不存在`);
    const exists = this.headOf(name);
    if (exists) throw new Error(`分支 ${name} 已存在`);
    this.db.prepare('INSERT INTO branches(name,head) VALUES(?,?)').run(name, head);
  }

  /** 回到任意旧事件：恢复当时的材料集合、参数版本、规则版本与可见结论。 */
  stateAsOf(branch: string, eventId?: string | null): ReviewState {
    const evRows = this.db
      .prepare('SELECT * FROM events WHERE branch=? ORDER BY seq')
      .all(branch) as Record<string, string | number>[];
    const events = evRows.map(rowToEvent);
    if (events.length === 0) {
      return emptyState(branch, this.budget);
    }
    const targetId = eventId ?? events[events.length - 1].id;
    const target = events.find((e) => e.id === targetId) ?? events[events.length - 1];
    const upto = events.filter((e) => e.seq <= target.seq);
    const { version, params } = this.paramsAt(target.seq);
    const ruleRun = this.lastRuleRun(target.seq)!;
    const rp = ruleRun.payload as {
      outcome: RunOutcome;
      status: string;
      diagnostics: Diagnostic[];
      findings: Finding[];
      ruleVersion: string;
    };

    const matRows = this.db
      .prepare('SELECT * FROM materials WHERE seq<=? ORDER BY key, seq')
      .all(ruleRun.seq) as Record<string, string | number>[];
    const latestByKey = new Map<string, (typeof matRows)[number]>();
    for (const r of matRows) {
      // 只保留该次规则运行所依赖导入/amend 事件之后引入、且 key 最新的材料
      latestByKey.set(r.key as string, r);
    }
    const materials: Material[] = [...latestByKey.values()].map((r) => ({
      id: r.id as string,
      kind: r.kind as Material['kind'],
      sliceId: (r.slice_id as string | null) ?? undefined,
      name: r.name as string,
      raw: r.raw as string,
      meta: JSON.parse(r.meta as string),
      digest: r.digest as string,
      seq: r.seq as number,
    }));

    const branchRows = this.db.prepare('SELECT name, head FROM branches ORDER BY name').all() as {
      name: string; head: string;
    }[];

    return {
      outcome: rp.outcome,
      diagnostics: rp.diagnostics,
      materials,
      findings: rp.findings,
      events,
      branches: branchRows,
      head: events[events.length - 1].id,
      paramVersion: version,
      ruleVersion: rp.ruleVersion,
      params: params as unknown as Record<string, unknown>,
      asOf: target.id,
    };
  }

  exportArchive(): Archive {
    const events = (
      this.db.prepare('SELECT * FROM events ORDER BY seq').all() as Record<string, string | number>[]
    ).map(rowToEvent);
    const matRows = this.db
      .prepare('SELECT * FROM materials ORDER BY key, seq')
      .all() as Record<string, string | number>[];
    const materials: Material[] = matRows.map((r) => ({
      id: r.id as string,
      kind: r.kind as Material['kind'],
      sliceId: (r.slice_id as string | null) ?? undefined,
      name: r.name as string,
      raw: r.raw as string,
      meta: JSON.parse(r.meta as string),
      digest: r.digest as string,
      seq: r.seq as number,
    }));
    const branches = this.db.prepare('SELECT name, head FROM branches ORDER BY name').all() as {
      name: string; head: string;
    }[];
    const meta = Object.fromEntries(
      (this.db.prepare('SELECT k, v FROM meta').all() as { k: string; v: string }[]).map((r) => [
        r.k,
        r.v,
      ]),
    );
    return {
      format: 'macho-slice-testimony/1',
      exportedAt: new Date().toISOString(),
      meta,
      materials,
      events,
      branches,
    };
  }

  /** 导入档案：全量校验后在单个事务内写入；档案损坏不会产生半写数据库。 */
  importArchive(archive: unknown, opts: { mode: 'merge' | 'replace' } = { mode: 'merge' }):
    | { ok: true; events: number }
    | { ok: false; code: string; message: string } {
    const checked = validateArchive(archive);
    if (!checked.ok) return checked;
    const a = checked.archive;
    this.db.exec('BEGIN');
    try {
      if (opts.mode === 'replace') {
        this.db.exec('DELETE FROM events; DELETE FROM materials; DELETE FROM branches; DELETE FROM meta;');
      }
      for (const ev of a.events) {
        this.db.prepare(
          `INSERT OR REPLACE INTO events(id,seq,branch,type,rule_version,param_version,parents,payload,created_at)
           VALUES(?,?,?,?,?,?,?,?,?)`,
        ).run(
          ev.id, ev.seq, ev.branch, ev.type, ev.ruleVersion, ev.paramVersion,
          JSON.stringify(ev.parents), JSON.stringify(ev.payload), ev.createdAt,
        );
      }
      for (const m of a.materials) {
        this.db.prepare(
          `INSERT OR REPLACE INTO materials(id,key,kind,slice_id,name,raw,meta,digest,seq)
           VALUES(?,?,?,?,?,?,?,?,?)`,
        ).run(
          m.id,
          keyFromId(m.id, m.kind, m.name),
          m.kind, m.sliceId ?? null, m.name, m.raw,
          JSON.stringify(m.meta), m.digest, m.seq,
        );
      }
      for (const b of a.branches) {
        this.db.prepare('INSERT OR REPLACE INTO branches(name,head) VALUES(?,?)').run(
          b.name, b.head,
        );
      }
      for (const [k, v] of Object.entries(a.meta)) {
        this.db.prepare('INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)').run(k, v);
      }
      this.db.exec('COMMIT');
      return { ok: true, events: a.events.length };
    } catch (err) {
      try { this.db.exec('ROLLBACK'); } catch { /* noop */ }
      return { ok: false, code: 'archive.write_failed', message: (err as Error).message };
    }
  }

  reset(): void {
    this.db.exec(
      'DELETE FROM events; DELETE FROM materials; DELETE FROM branches; DELETE FROM meta;',
    );
  }

  /** 测试用：在事务中途故意失败，验证半写恢复（回滚后无残留）。 */
  crashMidImport(input: { name: string; bytes: Uint8Array }): void {
    this.db.exec('BEGIN');
    const res = parseFat(input.bytes, this.budget);
    this.appendEventTx({
      branch: 'main',
      type: 'import',
      paramVersion: 1,
      parents: [],
      payload: { name: input.name, digest: sha256(input.bytes), partial: true },
    });
    if (res.parsed) {
      const keyed = buildMaterials(res.parsed);
      for (const m of keyed.materials.slice(0, 2)) this.insertMaterial(m, this.nextSeq() - 1);
    }
    this.db.exec('ROLLBACK');
  }
}

export function validateArchive(x: unknown):
  | { ok: true; archive: Archive }
  | { ok: false; code: string; message: string } {
  if (typeof x !== 'object' || x === null) {
    return { ok: false, code: 'archive.shape', message: '档案不是对象' };
  }
  const a = x as Partial<Archive>;
  if (a.format !== 'macho-slice-testimony/1') {
    return { ok: false, code: 'archive.format', message: `不支持的档案格式标识: ${String(a.format)}` };
  }
  if (!Array.isArray(a.events) || !Array.isArray(a.materials) || !Array.isArray(a.branches)) {
    return { ok: false, code: 'archive.shape', message: '缺少 events/materials/branches 数组' };
  }
  for (const ev of a.events) {
    if (typeof ev.id !== 'string' || typeof ev.seq !== 'number' || !ev.type || !ev.ruleVersion) {
      return { ok: false, code: 'archive.event', message: `事件 ${String((ev as { id?: unknown }).id)} 字段不完整` };
    }
    const parentsOk = Array.isArray(ev.parents) && ev.parents.every((p) => typeof p === 'string');
    if (!parentsOk) {
      return { ok: false, code: 'archive.event', message: `事件 ${ev.id} 父级依赖无效` };
    }
  }
  const seqs = a.events.map((e) => e.seq);
  if (new Set(seqs).size !== seqs.length) {
    return { ok: false, code: 'archive.order', message: '事件序号不唯一，无法保证稳定顺序' };
  }
  let prev = 0;
  for (const s of [...seqs].sort((x, y) => x - y)) {
    if (s !== prev + 1) {
      return { ok: false, code: 'archive.order', message: `事件序号在 ${prev} 后断裂（得到 ${s}）` };
    }
    prev = s;
  }
  for (const m of a.materials) {
    if (typeof m.id !== 'string' || typeof m.raw !== 'string') {
      return { ok: false, code: 'archive.material', message: '材料缺少 id 或原始字节' };
    }
    let recomputed: string;
    try {
      recomputed = createHash('sha256').update(Buffer.from(m.raw, 'base64')).digest('hex');
    } catch {
      return { ok: false, code: 'archive.material', message: `材料 ${m.id} 的原始表示不是合法 base64` };
    }
    if (recomputed !== m.digest) {
      return {
        ok: false,
        code: 'archive.material_digest',
        message: `材料 ${m.id} 摘要与原始字节不一致（材料可能被截断或篡改）`,
      };
    }
  }
  return { ok: true, archive: a as Archive };
}

function keyFromId(id: string, kind: string, name: string): string {
  // 档案中的 id 已含稳定键；解析回 key，失败时回退到名字派生。
  const parts = id.split(':');
  if (parts.length >= 3 && parts[0] === 'mat') {
    const tail = parts.slice(1, -1).join(':');
    if (kind === 'load_command') {
      return name.startsWith('mach_header') ? tail.replace(/^command:/, 'mach_header:') : tail;
    }
    return tail;
  }
  return `name:${name}`;
}

function rowToEvent(r: Record<string, string | number>): DomainEvent {
  return {
    id: r.id as string,
    seq: r.seq as number,
    branch: r.branch as string,
    type: r.type as DomainEvent['type'],
    ruleVersion: r.rule_version as string,
    paramVersion: r.param_version as number,
    parents: JSON.parse(r.parents as string) as string[],
    payload: JSON.parse(r.payload as string) as Record<string, unknown>,
    createdAt: r.created_at as string,
  };
}

function emptyState(branch: string, budget: ParseBudget): ReviewState {
  return {
    outcome: 'ok',
    diagnostics: [],
    materials: [],
    findings: [],
    events: [],
    branches: [{ name: branch, head: '' }],
    head: '',
    paramVersion: 1,
    ruleVersion: RULE_VERSION,
    params: DEFAULT_PARAMS as unknown as Record<string, unknown>,
    asOf: '',
  };
}
