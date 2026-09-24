// SQLite storage. Business persistence is intentionally placed behind a small
// repository API so tests can exercise server/storage rules directly (no
// browser-only logic).
//
// Half-write recovery:
//   An `import_marker` row is written *before* a bundle's event rows and only
//   cleared after the commit succeeds. If the process dies mid-import, the
//   marker survives; openStore() detects it and rolls the partial bundle back
//   deterministically on the next open.

import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export interface EventRow {
  id: string;
  seq: number;
  session_id: string;
  branch: string;
  at: string;
  actor: string;
  type: string;
  payload: string;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  created_at TEXT NOT NULL,
  narrative TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  seq INTEGER NOT NULL,
  session_id TEXT NOT NULL,
  branch TEXT NOT NULL,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  type TEXT NOT NULL,
  payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, branch, seq);
CREATE TABLE IF NOT EXISTS kv (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS import_marker (
  bundle_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  started_at TEXT NOT NULL,
  event_ids TEXT NOT NULL
);
`;

export interface RecoveryReport {
  recovered: boolean;
  rolledBackBundleIds: string[];
}

export function openStore(path: string): { db: DatabaseSync; recovery: RecoveryReport } {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec(SCHEMA);
  const recovery = recoverHalfWrites(db);
  return { db, recovery };
}

function recoverHalfWrites(db: DatabaseSync): RecoveryReport {
  const markers = db.prepare('SELECT bundle_id, session_id, event_ids FROM import_marker').all() as {
    bundle_id: string;
    session_id: string;
    event_ids: string;
  }[];
  const rolledBackBundleIds: string[] = [];
  for (const marker of markers) {
    const eventIds = JSON.parse(marker.event_ids) as string[];
    const tx = db.prepare('BEGIN IMMEDIATE');
    tx.run();
    const delEvent = db.prepare('DELETE FROM events WHERE id = ?');
    for (const id of eventIds) delEvent.run(id);
    db.prepare('DELETE FROM sessions WHERE id = ? AND id NOT IN (SELECT DISTINCT session_id FROM events)').run(
      marker.session_id,
    );
    db.prepare('DELETE FROM import_marker WHERE bundle_id = ?').run(marker.bundle_id);
    db.exec('COMMIT');
    rolledBackBundleIds.push(marker.bundle_id);
  }
  return { recovered: rolledBackBundleIds.length > 0, rolledBackBundleIds };
}

export class Store {
  readonly db: DatabaseSync;

  constructor(path: string) {
    this.db = openStore(path).db;
  }

  listSessions(): { id: string; title: string; created_at: string; narrative: string }[] {
    const rows = this.db
      .prepare('SELECT id, title, created_at, narrative FROM sessions ORDER BY created_at, id')
      .all() as { id: string; title: string; created_at: string; narrative: string }[];
    return rows;
  }

  getEvents(sessionId: string): EventRow[] {
    return this.db
      .prepare('SELECT * FROM events WHERE session_id = ? ORDER BY seq, id')
      .all(sessionId) as EventRow[];
  }

  getBranchEvents(sessionId: string, branch: string): EventRow[] {
    return this.db
      .prepare('SELECT * FROM events WHERE session_id = ? AND branch = ? ORDER BY seq, id')
      .all(sessionId, branch) as EventRow[];
  }

  nextSeq(sessionId: string, branch: string): number {
    const row = this.db
      .prepare('SELECT COALESCE(MAX(seq), 0) AS m FROM events WHERE session_id = ? AND branch = ?')
      .get(sessionId, branch) as { m: number };
    return row.m + 1;
  }

  insertSession(id: string, title: string, createdAt: string, narrative: string): void {
    this.db
      .prepare('INSERT OR IGNORE INTO sessions(id, title, created_at, narrative) VALUES(?,?,?,?)')
      .run(id, title, createdAt, narrative);
  }

  insertEvent(row: Omit<EventRow, 'session_id'> & { session_id?: string; sessionId?: string }, sessionId?: string): void {
    const sid = row.session_id ?? row.sessionId ?? sessionId!;
    this.db
      .prepare(
        'INSERT INTO events(id, seq, session_id, branch, at, actor, type, payload) VALUES(?,?,?,?,?,?,?,?)',
      )
      .run(row.id, row.seq, sid, row.branch, row.at, row.actor, row.type, row.payload);
  }

  putKv(k: string, v: string): void {
    this.db.prepare('INSERT OR REPLACE INTO kv(k,v) VALUES(?,?)').run(k, v);
  }

  getKv(k: string): string | null {
    const row = this.db.prepare('SELECT v FROM kv WHERE k = ?').get(k) as { v: string } | undefined;
    return row?.v ?? null;
  }

  deleteSession(sessionId: string): void {
    const tx = this.db.prepare('BEGIN');
    tx.run();
    this.db.prepare('DELETE FROM events WHERE session_id = ?').run(sessionId);
    this.db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
    this.db.exec('COMMIT');
  }

  resetAll(): void {
    this.db.exec('BEGIN; DELETE FROM events; DELETE FROM sessions; DELETE FROM kv; DELETE FROM import_marker; COMMIT;');
  }

  /**
   * Crash-safe bundle import. Pass `crashAfterEventRows` from tests to simulate
   * a half-written transaction; the marker remains and a later open rolls back.
   */
  importBundle(
    bundleId: string,
    session: { id: string; title: string; createdAt: string; narrative: string },
    rows: EventRow[],
    opts: {
      crashAfterEventRows?: number;
      leaveMarker?: boolean;
      crashBeforeClear?: boolean;
    } = {},
  ): { committed: boolean } {
    // Phase 1: session + marker are durable before any event rows exist.
    this.db.exec('BEGIN IMMEDIATE');
    this.insertSession(session.id, session.title, session.createdAt, session.narrative);
    this.db
      .prepare('INSERT OR REPLACE INTO import_marker(bundle_id, session_id, started_at, event_ids) VALUES(?,?,?,?)')
      .run(bundleId, session.id, new Date().toISOString(), JSON.stringify(rows.map((r) => r.id)));
    this.db.exec('COMMIT');

    // Phase 2: event rows are written individually (autocommit), so an abrupt
    // crash leaves a prefix of rows plus a live marker.
    let inserted = 0;
    for (const row of rows) {
      this.insertEvent(row);
      inserted += 1;
      if (opts.crashAfterEventRows !== undefined && inserted >= opts.crashAfterEventRows) {
        return { committed: false };
      }
    }
    if (opts.crashBeforeClear) return { committed: false };
    if (opts.leaveMarker) return { committed: true };

    // Phase 3: clear marker only after every row is durable.
    this.db.exec('BEGIN IMMEDIATE');
    this.db.prepare('DELETE FROM import_marker WHERE bundle_id = ?').run(bundleId);
    this.db.exec('COMMIT');
    return { committed: true };
  }

  close(): void {
    this.db.close();
  }
}
