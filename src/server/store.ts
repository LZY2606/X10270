/**
 * SQLite 事件溯源存储。
 * - 不可变材料（materials）与可修改决定（events）分层；
 * - 所有计算结果记录输入摘要(inputDigest)、参数版本(policyVersion)、父依赖(parentEventId)；
 * - 写入使用两阶段提交（tx_staging），半写崩溃后 recoverHalfWrites() 回滚未确认事务；
 * - 导出为单个 JSON 档案，再导入保持身份、分支与决定历史。
 */

import { DatabaseSync } from "node:sqlite";
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, renameSync } from "node:fs";
import { dirname } from "node:path";

export interface MaterialRow {
  id: string;
  session_id: string;
  branch_id: string;
  kind: string;
  /** 原始表示：base64 字节，不丢任何原始信息 */
  raw_base64: string;
  source_label: string;
  /** 来源坐标/单位基准（JSON） */
  basis: string;
  input_digest: string;
  seq: number;
  created_at: string;
  supersedes_material_id: string | null;
}

export interface EventRow {
  id: string;
  session_id: string;
  branch_id: string;
  seq: number;
  type: string;
  at: string;
  payload: string;
  input_digest: string | null;
  policy_version: number | null;
  parent_event_id: string | null;
}

export interface SessionRow {
  id: string;
  title: string;
  created_at: string;
}

export interface ExportBundle {
  format: "macho-testimony-archive/v1";
  exportedAt: string;
  sessions: Array<{
    session: SessionRow;
    materials: MaterialRow[];
    events: EventRow[];
  }>;
}

const SCHEMA = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS materials (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  branch_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  raw_base64 TEXT NOT NULL,
  source_label TEXT NOT NULL,
  basis TEXT NOT NULL,
  input_digest TEXT NOT NULL,
  seq INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  supersedes_material_id TEXT NULL
);
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  branch_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  type TEXT NOT NULL,
  at TEXT NOT NULL,
  payload TEXT NOT NULL,
  input_digest TEXT NULL,
  policy_version INTEGER NULL,
  parent_event_id TEXT NULL,
  UNIQUE(session_id, branch_id, seq)
);
-- 半写恢复：BEGIN 后登记，COMMIT 成功前崩溃 => 恢复时视为未提交
CREATE TABLE IF NOT EXISTS tx_staging (
  tx_id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, branch_id, seq);
CREATE INDEX IF NOT EXISTS idx_materials_session ON materials(session_id, seq);
`;

export class SessionStore {
  readonly db: DatabaseSync;

  constructor(pathOrDb: string | DatabaseSync) {
    if (typeof pathOrDb === "string") {
      const dir = dirname(pathOrDb);
      if (dir && !existsSync(dir)) mkdirSync(dir, { recursive: true });
      this.db = new DatabaseSync(pathOrDb);
    } else {
      this.db = pathOrDb;
    }
    this.db.exec(SCHEMA);
  }

  close(): void {
    this.db.close();
  }

  /** 模拟崩溃后的半写状态：留下一个未确认 staging（测试直接调用）。 */
  injectHalfWrite(detail = "injected crash"): string {
    const txId = `tx_${randomUUID()}`;
    this.db
      .prepare("INSERT INTO tx_staging(tx_id, started_at, detail) VALUES(?,?,?)")
      .run(txId, new Date().toISOString(), detail);
    return txId;
  }

  /** 恢复：存在未确认 staging 即丢弃 WAL 中未提交内容（SQLite 自动），并清除登记。 */
  recoverHalfWrites(): string[] {
    const stale = this.db.prepare("SELECT tx_id FROM tx_staging").all() as Array<{ tx_id: string }>;
    // ROLLBACK 任何潜在未完成事务；已提交事务的 staging 已在 commit 时删除
    try {
      this.db.exec("ROLLBACK");
    } catch {
      // 无活动事务，忽略
    }
    const del = this.db.prepare("DELETE FROM tx_staging WHERE tx_id = ?");
    for (const s of stale) del.run(s.tx_id);
    return stale.map((s) => s.tx_id);
  }

  private begin(detail: string): string {
    const txId = `tx_${randomUUID()}`;
    this.db.exec("BEGIN IMMEDIATE");
    this.db
      .prepare("INSERT INTO tx_staging(tx_id, started_at, detail) VALUES(?,?,?)")
      .run(txId, new Date().toISOString(), detail);
    return txId;
  }
  private commit(txId: string): void {
    this.db.prepare("DELETE FROM tx_staging WHERE tx_id = ?").run(txId);
    this.db.exec("COMMIT");
  }

  createSession(title: string): SessionRow {
    const tx = this.begin("create-session");
    const id = `sess_${randomUUID()}`;
    const at = new Date().toISOString();
    this.db.prepare("INSERT INTO sessions(id,title,created_at) VALUES(?,?,?)").run(id, title, at);
    this.db
      .prepare(
        `INSERT INTO events(id,session_id,branch_id,seq,type,at,payload,input_digest,policy_version,parent_event_id)
         VALUES(?,?,?,?,?,?,?,?,?,?)`,
      )
      .run(id, id, "main", 0, "session-created", at, JSON.stringify({ title }), null, null, null);
    this.commit(tx);
    return { id, title, created_at: at };
  }

  listSessions(): SessionRow[] {
    return this.db.prepare("SELECT * FROM sessions ORDER BY created_at").all() as unknown as SessionRow[];
  }

  getSession(id: string): SessionRow | null {
    return (this.db.prepare("SELECT * FROM sessions WHERE id=?").get(id) as SessionRow | undefined) ?? null;
  }

  private nextSeq(sessionId: string, branchId: string): number {
    const row = this.db
      .prepare("SELECT COALESCE(MAX(seq),0) AS m FROM events WHERE session_id=? AND branch_id=?")
      .get(sessionId, branchId) as { m: number };
    return row.m + 1;
  }
  private nextMaterialSeq(sessionId: string): number {
    const row = this.db
      .prepare("SELECT COALESCE(MAX(seq),0) AS m FROM materials WHERE session_id=?")
      .get(sessionId) as { m: number };
    return row.m + 1;
  }

  addMaterial(input: {
    sessionId: string;
    branchId?: string;
    kind: string;
    rawBase64: string;
    sourceLabel: string;
    basis: string;
    inputDigest: string;
    supersedes?: string | null;
  }): { material: MaterialRow; event: EventRow } {
    const tx = this.begin("add-material");
    const branch = input.branchId ?? "main";
    const matId = `mat_${randomUUID()}`;
    const seq = this.nextMaterialSeq(input.sessionId);
    const at = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO materials(id,session_id,branch_id,kind,raw_base64,source_label,basis,input_digest,seq,created_at,supersedes_material_id)
         VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
      )
      .run(
        matId, input.sessionId, branch, input.kind, input.rawBase64, input.sourceLabel,
        input.basis, input.inputDigest, seq, at, input.supersedes ?? null,
      );
    const event = this.insertEvent({
      sessionId: input.sessionId,
      branchId: branch,
      type: "material-imported",
      payload: {
        materialId: matId,
        kind: input.kind,
        sourceLabel: input.sourceLabel,
        basis: JSON.parse(input.basis),
        supersedes: input.supersedes ?? null,
        seq,
      },
      inputDigest: input.inputDigest,
    });
    this.commit(tx);
    return {
      material: {
        id: matId, session_id: input.sessionId, branch_id: branch, kind: input.kind,
        raw_base64: input.rawBase64, source_label: input.sourceLabel, basis: input.basis,
        input_digest: input.inputDigest, seq, created_at: at,
        supersedes_material_id: input.supersedes ?? null,
      },
      event,
    };
  }

  insertEvent(input: {
    sessionId: string;
    branchId: string;
    type: string;
    payload: Record<string, unknown>;
    inputDigest?: string | null;
    policyVersion?: number | null;
    parentEventId?: string | null;
    id?: string;
    at?: string;
    seq?: number;
  }): EventRow {
    const id = input.id ?? `evt_${randomUUID()}`;
    const seq = input.seq ?? this.nextSeq(input.sessionId, input.branchId);
    const at = input.at ?? new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO events(id,session_id,branch_id,seq,type,at,payload,input_digest,policy_version,parent_event_id)
         VALUES(?,?,?,?,?,?,?,?,?,?)`,
      )
      .run(
        id, input.sessionId, input.branchId, seq, input.type, at,
        JSON.stringify(input.payload), input.inputDigest ?? null, input.policyVersion ?? null,
        input.parentEventId ?? null,
      );
    return {
      id, session_id: input.sessionId, branch_id: input.branchId, seq, type: input.type, at,
      payload: JSON.stringify(input.payload), input_digest: input.inputDigest ?? null,
      policy_version: input.policyVersion ?? null, parent_event_id: input.parentEventId ?? null,
    };
  }

  /** 在单个可恢复事务内追加事件（用于 derivation/decision/branch）。 */
  withTransaction<T>(detail: string, fn: (commit: (txId: string) => void) => T): T {
    const tx = this.begin(detail);
    const result = fn(() => this.commit(tx));
    return result;
  }

  listEvents(sessionId: string, branchId = "main"): EventRow[] {
    return this.db
      .prepare("SELECT * FROM events WHERE session_id=? AND branch_id=? ORDER BY seq")
      .all(sessionId, branchId) as unknown as EventRow[];
  }

  listAllEvents(sessionId: string): EventRow[] {
    return this.db
      .prepare("SELECT * FROM events WHERE session_id=? ORDER BY branch_id, seq")
      .all(sessionId) as unknown as EventRow[];
  }

  listMaterials(sessionId: string): MaterialRow[] {
    return this.db
      .prepare("SELECT * FROM materials WHERE session_id=? ORDER BY seq")
      .all(sessionId) as unknown as MaterialRow[];
  }

  getMaterial(id: string): MaterialRow | null {
    return (this.db.prepare("SELECT * FROM materials WHERE id=?").get(id) as MaterialRow | undefined) ?? null;
  }

  exportAll(): ExportBundle {
    const sessions = this.listSessions();
    return {
      format: "macho-testimony-archive/v1",
      exportedAt: new Date().toISOString(),
      sessions: sessions.map((s) => ({
        session: s,
        materials: this.listMaterials(s.id),
        events: this.listAllEvents(s.id),
      })),
    };
  }

  /** 导入档案：身份、顺序、来源关系全部按原值恢复（先写临时文件再原子替换）。 */
  importBundleAt(bundle: ExportBundle, dbPath: string): void {
    if (bundle.format !== "macho-testimony-archive/v1") {
      throw new Error(`不支持的档案格式：${String(bundle.format)}`);
    }
    const tmp = `${dbPath}.import-${process.pid}-${Date.now()}`;
    const fresh = new SessionStore(tmp);
    fresh.withTransaction("import-bundle", (commit) => {
      for (const part of bundle.sessions) {
        fresh.db.prepare("INSERT INTO sessions(id,title,created_at) VALUES(?,?,?)")
          .run(part.session.id, part.session.title, part.session.created_at);
        for (const m of part.materials) {
          fresh.db
            .prepare(
              `INSERT INTO materials(id,session_id,branch_id,kind,raw_base64,source_label,basis,input_digest,seq,created_at,supersedes_material_id)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
            )
            .run(m.id, m.session_id, m.branch_id, m.kind, m.raw_base64, m.source_label,
              m.basis, m.input_digest, m.seq, m.created_at, m.supersedes_material_id);
        }
        for (const e of part.events) {
          fresh.db
            .prepare(
              `INSERT INTO events(id,session_id,branch_id,seq,type,at,payload,input_digest,policy_version,parent_event_id)
               VALUES(?,?,?,?,?,?,?,?,?,?)`,
            )
            .run(e.id, e.session_id, e.branch_id, e.seq, e.type, e.at, e.payload,
              e.input_digest, e.policy_version, e.parent_event_id);
        }
      }
      commit("");
    });
    fresh.close();
    renameSync(tmp, dbPath);
  }
}

export { randomUUID };
