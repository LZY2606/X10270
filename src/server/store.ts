import { DatabaseSync } from "node:sqlite";
import { randomUUID } from "node:crypto";
import { digestOf, sha256Hex } from "../domain/ids.js";

export interface MaterialRow {
  id: string; kind: string; name: string; lineage: string;
  rawHex: string; digest: string; importedSeq: number;
}

export interface EventRow {
  id: string; seq: number; branch: string; kind: string;
  payload: Record<string, unknown>; inputDigest: string;
  paramVersion: string; parents: string[];
}

export interface ExportDoc {
  format: "macho-review-export/v1";
  materials: MaterialRow[];
  events: EventRow[];
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS materials (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL, lineage TEXT NOT NULL,
  raw_hex TEXT NOT NULL, digest TEXT NOT NULL, imported_seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, seq INTEGER NOT NULL, branch TEXT NOT NULL, kind TEXT NOT NULL,
  payload TEXT NOT NULL, input_digest TEXT NOT NULL, param_version TEXT NOT NULL,
  parents TEXT NOT NULL, write_token TEXT
);
CREATE TABLE IF NOT EXISTS pending_writes (token TEXT PRIMARY KEY);
CREATE INDEX IF NOT EXISTS idx_events_seq ON events(seq);
`;

export class Store {
  private db: DatabaseSync;

  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec(SCHEMA);
    this.recover();
  }

  close(): void { this.db.close(); }

  /** 半写恢复：未确认（两阶段提交的第二阶段未完成）的写入整体回滚 */
  private recover(): void {
    const pending = this.db.prepare("SELECT token FROM pending_writes").all() as { token: string }[];
    for (const { token } of pending) {
      this.db.prepare("DELETE FROM events WHERE write_token = ?").run(token);
      this.db.prepare("DELETE FROM pending_writes WHERE token = ?").run(token);
    }
  }

  headSeq(): number {
    const row = this.db.prepare("SELECT COALESCE(MAX(seq), 0) AS s FROM events").get() as { s: number };
    return row.s;
  }

  addMaterial(m: Omit<MaterialRow, "importedSeq">, importedSeq: number): void {
    this.db.prepare(
      "INSERT OR IGNORE INTO materials (id, kind, name, lineage, raw_hex, digest, imported_seq) VALUES (?,?,?,?,?,?,?)",
    ).run(m.id, m.kind, m.name, m.lineage, m.rawHex, m.digest, importedSeq);
  }

  materials(): MaterialRow[] {
    const rows = this.db.prepare(
      "SELECT id, kind, name, lineage, raw_hex, digest, imported_seq FROM materials ORDER BY imported_seq, id",
    ).all() as Record<string, unknown>[];
    return rows.map((r) => ({
      id: r.id as string, kind: r.kind as string, name: r.name as string,
      lineage: r.lineage as string, rawHex: r.raw_hex as string,
      digest: r.digest as string, importedSeq: r.imported_seq as number,
    }));
  }

  material(id: string): MaterialRow | null {
    return this.materials().find((m) => m.id === id) ?? null;
  }

  /** 两阶段写入：第一阶段落事件+待确认标记，第二阶段确认。崩溃于中间 → 下次打开回滚。 */
  appendEvent(
    branch: string, kind: string, payload: Record<string, unknown>,
    inputDigest: string, paramVersion: string, parents: string[],
  ): EventRow {
    const seq = this.headSeq() + 1;
    const id = `evt_${digestOf([branch, kind, payload, inputDigest, paramVersion, parents, seq]).slice(0, 20)}`;
    const token = randomUUID();
    this.appendEventPhase1({ id, seq, branch, kind, payload, inputDigest, paramVersion, parents }, token);
    this.appendEventPhase2(token);
    return { id, seq, branch, kind, payload, inputDigest, paramVersion, parents };
  }

  appendEventPhase1(e: EventRow, token: string): void {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("INSERT INTO pending_writes (token) VALUES (?)").run(token);
      this.db.prepare(
        "INSERT INTO events (id, seq, branch, kind, payload, input_digest, param_version, parents, write_token) VALUES (?,?,?,?,?,?,?,?,?)",
      ).run(e.id, e.seq, e.branch, e.kind, JSON.stringify(e.payload), e.inputDigest, e.paramVersion,
        JSON.stringify(e.parents), token);
      this.db.exec("COMMIT");
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  appendEventPhase2(token: string): void {
    this.db.prepare("DELETE FROM pending_writes WHERE token = ?").run(token);
  }

  events(asOfSeq?: number): EventRow[] {
    const limit = asOfSeq ?? Number.MAX_SAFE_INTEGER;
    const rows = this.db.prepare(
      "SELECT id, seq, branch, kind, payload, input_digest, param_version, parents FROM events WHERE seq <= ? ORDER BY seq, id",
    ).all(limit) as Record<string, unknown>[];
    return rows.map((r) => ({
      id: r.id as string, seq: r.seq as number, branch: r.branch as string, kind: r.kind as string,
      payload: JSON.parse(r.payload as string) as Record<string, unknown>,
      inputDigest: r.input_digest as string, paramVersion: r.param_version as string,
      parents: JSON.parse(r.parents as string) as string[],
    }));
  }

  /** 导出：完整材料 + 事件，身份/顺序/来源关系全部保留 */
  export(): ExportDoc {
    return { format: "macho-review-export/v1", materials: this.materials(), events: this.events() };
  }

  /** 导入：幂等；校验材料摘要；身份与顺序原样保留 */
  import(doc: ExportDoc): { materialsAdded: number; eventsAdded: number; rejected: string[] } {
    if (doc.format !== "macho-review-export/v1") throw new Error(`不支持的导出格式: ${doc.format}`);
    const rejected: string[] = [];
    let materialsAdded = 0;
    let eventsAdded = 0;
    for (const m of doc.materials) {
      const actual = sha256Hex(Buffer.from(m.rawHex, "hex"));
      if (actual !== m.digest) {
        rejected.push(`material ${m.id} 摘要不匹配，拒绝导入`);
        continue;
      }
      const before = this.materials().length;
      this.addMaterial(m, m.importedSeq);
      if (this.materials().length > before) materialsAdded++;
    }
    const existing = new Set(this.events().map((e) => e.id));
    for (const e of [...doc.events].sort((a, b) => a.seq - b.seq || a.id.localeCompare(b.id))) {
      if (existing.has(e.id)) continue;
      this.db.prepare(
        "INSERT INTO events (id, seq, branch, kind, payload, input_digest, param_version, parents, write_token) VALUES (?,?,?,?,?,?,?,?,NULL)",
      ).run(e.id, e.seq, e.branch, e.kind, JSON.stringify(e.payload), e.inputDigest, e.paramVersion,
        JSON.stringify(e.parents));
      eventsAdded++;
    }
    return { materialsAdded, eventsAdded, rejected };
  }
}
